"""Batched writer: events insert + sessions upsert in one transaction.

When an :class:`Enricher` is given, events are enriched on the way in (local GeoIP/ASN
lookups, cached reputation, tagging rules) and session-scope rules run on the upserted
counters. Nothing here calls the network.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from datetime import UTC, date
from typing import Any

from sqlalchemy import (
    ARRAY,
    ColumnElement,
    Text,
    bindparam,
    func,
    insert,
    literal_column,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import Event
from suckerpot_db.models import EventRow, IpReputationRow, SessionRow, TechniqueDailyRow

from ingest.abuse import identity
from ingest.aggregate import SessionDelta, compute_session_deltas
from ingest.bruteforce import TAG as BRUTE_TAG
from ingest.diskguard import DiskGuard
from ingest.enrichment.enricher import Enricher
from ingest.floods.fold import (
    QUERY_CANCELED,
    WRITER_LIMIT,
    FloodFold,
    SkipLog,
    fold_buckets,
    restore_folded,
    stored_until,
)
from ingest.indicator_store import store_indicators
from ingest.scanners import event_is_benign_safe, stays_benign

log = logging.getLogger(__name__)

RETRACT_LOG_INTERVAL_S = 60.0
RETRACT_SLICE = 1000  # retract_benign refuses more sessions than this per call

_UNION_TAGS: ColumnElement[Any] = literal_column(
    "ARRAY(SELECT DISTINCT unnest(sessions.tags || excluded.tags) ORDER BY 1)"
)
_UNION_TECHNIQUES: ColumnElement[Any] = literal_column(
    "ARRAY(SELECT DISTINCT unnest(sessions.techniques || excluded.techniques) ORDER BY 1 LIMIT 64)"
)
_T = SessionRow.__table__.c
# What the writer reads back of every session it upserted (RETURNING), and again for a row that
# restore_folded_sessions gave back.
_UPSERTED = (
    _T.session_id, _T.sensor, _T.event_count, _T.login_attempts, _T.login_success, _T.commands,
    _T.downloads, _T.http_requests, _T.known_scanner, _T.abuse_score, _T.tags, _T.benign,
    _T.scanner_name, _T.src_ip, _T.started_at, _T.ended_at, _T.last_event_at,
)  # fmt: skip
# True for a row the upsert inserted, false for one it updated.
_INSERTED: ColumnElement[Any] = literal_column("(xmax = 0)").label("inserted")
RESTORE_TIMEOUT_MS = 2000


def strip_nul(value: Any) -> Any:
    """PostgreSQL jsonb rejects U+0000: remove it from every string (keys and values)."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {strip_nul(k): strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_nul(v) for v in value]
    return value


def event_to_row(ev: Event) -> dict[str, Any]:
    return {
        "ts": ev.ts,
        "sensor": str(ev.sensor),
        "session_id": ev.session_id,
        "type": str(ev.type),
        "src_ip": str(ev.src_ip),
        "src_port": ev.src_port,
        "dst_port": ev.dst_port,
        "data": strip_nul(ev.data),
    }


def delta_to_row(d: SessionDelta) -> dict[str, Any]:
    return {
        "session_id": d.session_id,
        "sensor": d.sensor,
        "src_ip": d.src_ip,
        "src_port": d.src_port,
        "dst_port": d.dst_port,
        "started_at": d.started_at,
        "ended_at": d.ended_at,
        "last_event_at": d.last_event_at,
        "event_count": d.event_count,
        "login_attempts": d.login_attempts,
        "login_success": d.login_success,
        "commands": d.commands,
        "downloads": d.downloads,
        "http_requests": d.http_requests,
        "country": d.country,
        "city": d.city,
        "asn": d.asn,
        "org": d.org,
        "abuse_score": d.abuse_score,
        "known_scanner": d.known_scanner,
        "tags": sorted(d.tags),
        "client_tool": d.client_tool,
        "techniques": sorted(d.techniques),
        "benign": d.benign,
        "scanner_name": d.scanner_name,
    }


async def _cached_reputation(
    session: AsyncSession, ips: Sequence[str]
) -> dict[str, tuple[int | None, bool | None]]:
    """abuse_score and GreyNoise noise flag already known for these addresses."""
    stmt = select(
        func.host(IpReputationRow.ip), IpReputationRow.abuse_score, IpReputationRow.gn_noise
    ).where(IpReputationRow.ip.in_(ips))
    return {ip: (score, noise) for ip, score, noise in (await session.execute(stmt)).all()}


async def _demoted_sessions(session: AsyncSession, ids: Sequence[str]) -> frozenset[str]:
    """Sessions that exist and are already not benign (a scanner that did more earlier)."""
    stmt = select(SessionRow.session_id).where(SessionRow.session_id.in_(ids), ~SessionRow.benign)
    return frozenset((await session.scalars(stmt)).all())


def _enrich_rows(
    events: Sequence[Event],
    rows: list[dict[str, Any]],
    deltas: list[SessionDelta],
    enricher: Enricher,
    reputation: dict[str, tuple[int | None, bool | None]],
    demoted: frozenset[str] = frozenset(),
) -> None:
    by_session = {d.session_id: d for d in deltas}
    safe: list[bool] = []
    for ev, row in zip(events, rows, strict=True):
        ip = str(ev.src_ip)
        geo = enricher.geo.lookup(ip)
        score, noise = reputation.get(ip, (None, None))
        tags = enricher.rules.tag_event(str(ev.type), str(ev.sensor), row["data"])
        if str(ev.type) == "login_attempt" and enricher.brute.record(ip, str(ev.sensor), ev.ts):
            tags = sorted({*tags, BRUTE_TAG})
        techniques: list[str] = []
        if enricher.attack is not None:
            techniques = enricher.attack.for_event(str(ev.type), str(ev.sensor), row["data"], tags)
        row["techniques"] = techniques or None
        row.update(
            country=geo.country, city=geo.city, asn=geo.asn, org=geo.org,
            abuse_score=score, known_scanner=noise, tags=tags,
        )  # fmt: skip
        d = by_session[ev.session_id]
        # Only the network can name a scanner (a user-agent is attacker-controlled), and only
        # a session that did nothing but look around stays benign (see ingest/scanners.py).
        scanner = enricher.scanners.match(asn=geo.asn, org=geo.org)
        if scanner is not None:
            d.scanner_name = d.scanner_name or scanner
        ok = event_is_benign_safe(str(ev.type), row["data"], tags)
        safe.append(ok)
        if not ok:
            d.non_benign = True
        d.tags.update(tags)
        d.techniques.update(techniques)
        if d.country is None and geo.country is not None:
            d.country, d.city, d.asn, d.org = geo.country, geo.city, geo.asn, geo.org
        d.abuse_score = score if score is not None else d.abuse_score
        d.known_scanner = noise if noise is not None else d.known_scanner
    # The session verdict comes first, then every event follows it (new rows only). A session
    # already non-benign in the database never turns benign again.
    for d in deltas:
        d.benign = d.scanner_name is not None and not d.non_benign and d.session_id not in demoted
    for row, ev, ok in zip(rows, events, safe, strict=True):
        row["benign"] = by_session[ev.session_id].benign and ok


async def write_batch(
    factory: async_sessionmaker[AsyncSession],
    events: Sequence[Event],
    enricher: Enricher | None = None,
    guard: DiskGuard | None = None,
) -> None:
    """Insert events and upsert sessions atomically. Raises on failure (nothing is committed)."""
    if not events:
        return
    deltas = compute_session_deltas(events)
    rows = [event_to_row(e) for e in events]
    degraded = guard is not None and await guard.is_degraded()
    prior: dict[str, set[str]] = {}
    async with factory() as session, session.begin():
        if enricher is not None:
            ips = sorted({str(e.src_ip) for e in events})
            reputation = await _cached_reputation(session, ips)
            demoted = await _demoted_sessions(session, [d.session_id for d in deltas])
            _enrich_rows(events, rows, deltas, enricher, reputation, demoted)
            if enricher.attack is not None:
                prior = await _prior_techniques(session, [d.session_id for d in deltas])
        if degraded and guard is not None:
            guard.degrade_rows(rows)  # after tagging, which needs the full payload
        await session.execute(insert(EventRow), rows)
        await identity.record(session, events)
        stmt = pg_insert(SessionRow)
        ex = stmt.excluded
        t = SessionRow.__table__
        upsert = stmt.on_conflict_do_update(
            index_elements=[t.c.session_id],
            # A flood group (kind 'burst') is never updated by an event: a forged or stale
            # session id that lands on one changes nothing (the consumer drops burst- ids).
            where=t.c.kind == "session",
            set_={
                "event_count": t.c.event_count + ex.event_count,
                "login_attempts": t.c.login_attempts + ex.login_attempts,
                "login_success": t.c.login_success | ex.login_success,
                "commands": t.c.commands + ex.commands,
                "downloads": t.c.downloads + ex.downloads,
                "http_requests": t.c.http_requests + ex.http_requests,
                "started_at": func.least(t.c.started_at, ex.started_at),
                "last_event_at": func.greatest(t.c.last_event_at, ex.last_event_at),
                # greatest() ignores NULLs in PostgreSQL.
                "ended_at": func.greatest(t.c.ended_at, ex.ended_at),
                "country": func.coalesce(t.c.country, ex.country),
                "city": func.coalesce(t.c.city, ex.city),
                "asn": func.coalesce(t.c.asn, ex.asn),
                "org": func.coalesce(t.c.org, ex.org),
                "abuse_score": func.coalesce(ex.abuse_score, t.c.abuse_score),
                "known_scanner": func.coalesce(ex.known_scanner, t.c.known_scanner),
                "tags": _UNION_TAGS,
                "client_tool": func.coalesce(ex.client_tool, t.c.client_tool),
                "techniques": _UNION_TECHNIQUES,
                "benign": t.c.benign & ex.benign,
                "scanner_name": func.coalesce(t.c.scanner_name, ex.scanner_name),
            },
        ).returning(*_UPSERTED, _INSERTED)
        result = await session.execute(upsert, [delta_to_row(d) for d in deltas])
        if enricher is not None:
            upserted = await _restore_folded(session, events, result.all())
            await _apply_session_rules(session, enricher, upserted)
            if enricher.attack is not None:
                await record_technique_daily(session, events, rows, deltas, prior)
            if enricher.indicators is not None and not degraded:
                await store_indicators(session, events, enricher.indicators, enricher.link_cap)
            # Last, so the advisory lock the fold takes is held only until the commit.
            if enricher.fold is not None:
                await _fold_closed(session, enricher.fold, events, upserted)


_skips = 0
_skips_logged = -RETRACT_LOG_INTERVAL_S


def _retract_skipped(sqlstate: str) -> None:
    """One WARNING per minute at most, with the number of skips since the last one."""
    global _skips, _skips_logged
    _skips += 1
    now = time.monotonic()
    if now - _skips_logged >= RETRACT_LOG_INTERVAL_S:
        log.warning(
            "retract_benign skipped %d time(s) in the last minute (SQLSTATE %s)", _skips, sqlstate
        )
        _skips, _skips_logged = 0, now


async def _retract_benign(session: AsyncSession, ids: list[str]) -> None:
    """Clear the benign flag of earlier events, in a savepoint.

    Ingest cannot UPDATE events: this SECURITY DEFINER function is its one way in. A missed
    retraction only leaves a flag set on old rows, so a failure here (a timeout on a compressed
    chunk, say) is logged and never fails the batch.
    """
    try:
        async with session.begin_nested():
            await session.execute(
                text("SELECT retract_benign(:ids)").bindparams(bindparam("ids", type_=ARRAY(Text))),
                {"ids": ids},
            )
    except DBAPIError as exc:
        if exc.connection_invalidated:
            raise
        sqlstate = str(getattr(exc.orig, "sqlstate", None) or "unknown")
        _retract_skipped(sqlstate)


_fold_skips = SkipLog("session fold")
_restore_skips = SkipLog("folded session restore")


def _sqlstate(exc: DBAPIError) -> str:
    return str(getattr(exc.orig, "sqlstate", None) or "unknown")


async def _restore_folded(
    session: AsyncSession, events: Sequence[Event], upserted: Sequence[Any]
) -> list[Any]:
    """Give a folded connection that got a late event its row back, in a savepoint.

    A row the upsert just inserted for a session whose ``connect`` is not in this batch continues
    a connection seen before; when that connection was folded, ``restore_folded_sessions`` adds its
    earlier events back to the row and takes it out of its group, so it is counted once and none of
    its events is lost from view. Such rows are read again, so the session rules and the fold see
    the whole connection. A failure here (a timeout, a lock held too long) is logged once a minute
    at most and never fails the batch: the row keeps the late events only.
    """
    opened = {ev.session_id for ev in events if str(ev.type) == "connect"}
    ids = [r.session_id for r in upserted if r.inserted and r.session_id not in opened]
    if not ids:
        return list(upserted)
    try:
        async with session.begin_nested():
            restored = await restore_folded(session, ids, timeout_ms=RESTORE_TIMEOUT_MS)
    except DBAPIError as exc:
        if exc.connection_invalidated:
            raise
        _restore_skips.skipped(_sqlstate(exc))
        return list(upserted)
    if not restored:
        return list(upserted)
    fresh = {
        r.session_id: r
        for r in await session.execute(select(*_UPSERTED).where(_T.session_id.in_(restored)))
    }
    return [fresh.get(r.session_id, r) for r in upserted]


async def _fold_closed(
    session: AsyncSession, fold: FloodFold, events: Sequence[Event], upserted: Sequence[Any]
) -> None:
    """Merge the plain connections of a flooding source, in a savepoint.

    Counts the batch's connections in the gate, then asks the database to fold the buckets (source,
    sensor, hour) of the closed, plain-looking sessions this batch touched whose source the gate
    calls hot, each bucket at most once a minute. The function folds every plain, closed connection
    of such a bucket, whichever batch it came from, and re-counts the hour itself; a connection
    with no disconnect is idle against the newest event of this batch, not the clock. Folding is
    housekeeping: the call is capped at ``fold.timeout_ms``, a failure is logged (once a minute at
    most) and never fails the batch, and after a timeout the writer stops folding for a while (the
    sweep worker catches up), so events are acknowledged as before and never wait on it.
    """
    demo = fold.record(events)
    if fold.paused():
        return
    buckets = fold.buckets(upserted, demo)
    if not buckets:
        return
    fold.mark_asked(buckets)
    try:
        async with session.begin_nested():
            folded = await fold_buckets(
                session,
                buckets,
                fold.settings,
                fold.plain_tags,
                limit=WRITER_LIMIT,
                as_of=stored_until(events),
                timeout_ms=fold.timeout_ms,
            )
    except DBAPIError as exc:
        if exc.connection_invalidated:
            raise
        if _sqlstate(exc) == QUERY_CANCELED:
            fold.timed_out()
        _fold_skips.skipped(_sqlstate(exc))
        return
    fold.succeeded()
    fold.calls += 1
    fold.folded += folded


async def _apply_session_rules(
    session: AsyncSession, enricher: Enricher, rows: Sequence[Any]
) -> None:
    """Evaluate session-scope rules on the upserted counters and add any new tags."""
    updates: list[dict[str, Any]] = []
    demote: list[str] = []
    retract: list[str] = []
    for r in rows:
        facts = {
            "session.sensor": r.sensor,
            "session.event_count": r.event_count,
            "session.login_attempts": r.login_attempts,
            "session.login_success": r.login_success,
            "session.commands": r.commands,
            "session.downloads": r.downloads,
            "session.http_requests": r.http_requests,
            "session.known_scanner": r.known_scanner,
            "session.abuse_score": r.abuse_score,
            "session.tags": list(r.tags or []),
        }
        new = set(enricher.rules.tag_session(facts)) - set(r.tags or [])
        if new:
            techniques = enricher.attack.for_tags(sorted(new)) if enricher.attack else []
            updates.append({"sid": r.session_id, "t": sorted(new), "x": sorted(techniques)})
        # A research scanner that signed in, ran a command, downloaded or sent an exploit is not
        # one any more, whatever its user-agent or network says.
        if r.benign and not stays_benign(
            commands=r.commands,
            downloads=r.downloads,
            login_attempts=r.login_attempts,
            login_success=r.login_success,
            tags={*(r.tags or []), *new},
        ):
            demote.append(r.session_id)
        # A session named as a scanner that is not benign (now, or since an earlier batch): its
        # earlier events must not keep the flag.
        if r.scanner_name is not None and (not r.benign or r.session_id in demote):
            retract.append(r.session_id)
    for i in range(0, len(retract), RETRACT_SLICE):
        await _retract_benign(session, retract[i : i + RETRACT_SLICE])
    if demote:
        await session.execute(
            text("UPDATE sessions SET benign = false WHERE session_id = ANY(:ids)").bindparams(
                bindparam("ids", type_=ARRAY(Text))
            ),
            {"ids": demote},
        )
    if updates:
        await session.execute(
            text(
                "UPDATE sessions SET tags = ARRAY(SELECT DISTINCT unnest(tags || :t) ORDER BY 1), "
                "techniques = ARRAY(SELECT DISTINCT unnest(techniques || :x) ORDER BY 1 LIMIT 64) "
                "WHERE session_id = :sid"
            ).bindparams(bindparam("t", type_=ARRAY(Text)), bindparam("x", type_=ARRAY(Text))),
            updates,
        )


async def _prior_techniques(
    session: AsyncSession, session_ids: Sequence[str]
) -> dict[str, set[str]]:
    """Techniques the sessions already carry, to count each session once per technique."""
    stmt = select(SessionRow.session_id, SessionRow.techniques).where(
        SessionRow.session_id.in_(list(session_ids))
    )
    return {sid: set(techs or []) for sid, techs in (await session.execute(stmt)).all()}


async def record_technique_daily(
    session: AsyncSession,
    events: Sequence[Event],
    rows: Sequence[dict[str, Any]],
    deltas: Sequence[SessionDelta],
    prior: dict[str, set[str]],
) -> None:
    """Add the batch to ``technique_daily`` in a savepoint: a failure here never costs events.

    ``events`` counts every event that shows a technique; ``sessions`` counts a session once,
    when it first shows the technique; ``sources`` counts the addresses of those sessions within
    the batch (an upper bound across batches, as a returning address is counted again).
    """
    cells: dict[tuple[date, str, str], list[Any]] = {}
    first_day: dict[tuple[str, str], date] = {}
    for ev, row in zip(events, rows, strict=True):
        techs = row.get("techniques") or []
        day = ev.ts.astimezone(UTC).date()
        for tid in techs:
            cell = cells.setdefault((day, tid, str(ev.sensor)), [0, set(), set()])
            cell[0] += 1
            first_day.setdefault((ev.session_id, tid), day)
    ip_of = {d.session_id: d.src_ip for d in deltas}
    sensor_of = {d.session_id: d.sensor for d in deltas}
    for (sid, tid), day in first_day.items():
        if tid in prior.get(sid, set()):
            continue
        cell = cells.setdefault((day, tid, sensor_of[sid]), [0, set(), set()])
        cell[1].add(sid)
        cell[2].add(ip_of[sid])
    if not cells:
        return
    values = [
        {
            "day": day, "technique": tid, "sensor": sensor,
            "sessions": len(c[1]), "events": c[0], "sources": len(c[2]),
        }
        for (day, tid, sensor), c in sorted(cells.items())
    ]  # fmt: skip
    stmt = pg_insert(TechniqueDailyRow)
    ex = stmt.excluded
    t = TechniqueDailyRow.__table__
    stmt = stmt.on_conflict_do_update(
        index_elements=[t.c.day, t.c.technique, t.c.sensor],
        set_={
            "sessions": t.c.sessions + ex.sessions,
            "events": t.c.events + ex.events,
            "sources": t.c.sources + ex.sources,
        },
    )
    try:
        async with session.begin_nested():
            await session.execute(stmt, values)
    except SQLAlchemyError as exc:
        log.warning("technique counters failed (%s)", type(exc).__name__)
