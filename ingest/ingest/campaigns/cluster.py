"""One clustering cycle: unclustered sessions in, campaigns and links out.

Everything here is bounded: at most ``batch`` sessions per cycle, at most 64 commands and 256
login attempts read per session, at most 16 keys per session, ``merge_budget`` merges. The
whole cycle runs in one transaction; the role's ``statement_timeout`` caps every statement.
Nothing touches the network.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ARRAY, Integer, Text, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.event_bounds import bounded_slices, events_ts_range

from ingest.attack.mapping import AttackMap
from ingest.campaigns.keys import (
    MIN_CREDLIST_ATTEMPTS,
    PAYLOAD_TAGS,
    Key,
    cap_keys,
    credlist_key,
    exploit_key,
    is_benign_host,
    script_key,
)
from ingest.campaigns.naming import campaign_name, severity_of, stages_of
from ingest.campaigns.plan import Cand, build_plan, net_of

log = logging.getLogger(__name__)

CHUNK = 200
MOVE_BATCH = 2000
MAX_KEYS_PER_CAMPAIGN = 1000
MAX_COMMANDS = 64
MAX_LOGINS = 256
CAP_COUNTRIES = 64
CAP_ASNS = 64
CAP_SENSORS = 16
CAP_TECHNIQUES = 64
CAP_TAGS = 64
CAP_FAMILIES = 16
TEXT_ARRAY = ARRAY(Text)
INT_ARRAY = ARRAY(Integer)


@dataclass(frozen=True, slots=True)
class ClusterConfig:
    min_sources: int = 2
    link_cap: int = 500
    batch: int = 2000
    merge_budget: int = 50
    quiet_minutes: int = 10
    keyless_hours: int = 24
    keyed_days: int = 30
    active_days: int = 7


@dataclass(slots=True)
class CycleStats:
    examined: int = 0
    joined: int = 0
    created: int = 0
    merged: int = 0
    deferred: int = 0


@dataclass(slots=True)
class Content:
    """Keys derived from a session's own events (stable once the session is quiet)."""

    keys: set[Key] = field(default_factory=set)
    demo: bool = False


class ContentCache(OrderedDict[str, Content]):
    """Small LRU of content keys: finished sessions do not change."""

    def __init__(self, size: int = 10_000) -> None:
        super().__init__()
        self.size = size

    def put(self, sid: str, value: Content) -> None:
        self[sid] = value
        self.move_to_end(sid)
        while len(self) > self.size:
            self.popitem(last=False)


def _chunks[T](items: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _union(*groups: Iterable[Any], cap: int) -> list[Any]:
    return sorted({x for g in groups for x in g})[:cap]


# ---- reading ---------------------------------------------------------------------------------


#: A session can only carry a clustering key if it did one of these things.
_KEYABLE = "(commands >= 2 OR downloads > 0 OR login_attempts >= :logins OR tags && :payload)"
PER_IP_CAP = 25


def _cand(r: Any) -> Cand:
    return Cand(
        session_id=r.session_id,
        sensor=r.sensor,
        src_ip=r.ip,
        country=r.country,
        asn=r.asn,
        tags=list(r.tags or []),
        techniques=list(r.techniques or []),
        started_at=r.started_at,
        last_event_at=r.last_event_at,
        commands=r.commands,
        downloads=r.downloads,
        login_attempts=r.login_attempts,
    )


async def _load_candidates(s: AsyncSession, cfg: ClusterConfig, now: datetime) -> list[Cand]:
    """Half the budget from the newest sessions, half from the oldest, at most ``PER_IP_CAP``
    per source address: neither a flood of new sessions nor one noisy address starves the rest."""
    params = {
        "quiet": now - timedelta(minutes=cfg.quiet_minutes),
        "logins": MIN_CREDLIST_ATTEMPTS,
        "payload": list(PAYLOAD_TAGS),
    }
    out: dict[str, Cand] = {}
    per_ip: dict[str, int] = {}
    for order, share in (("DESC", cfg.batch - cfg.batch // 2), ("ASC", cfg.batch // 2)):
        rows = await s.execute(
            text(
                "SELECT session_id, sensor, host(src_ip) AS ip, country, asn, tags, techniques, "
                "started_at, last_event_at, commands, downloads, login_attempts FROM sessions "
                "WHERE clustered_at IS NULL AND NOT benign AND last_event_at < :quiet "
                f"AND {_KEYABLE} ORDER BY last_event_at {order} LIMIT :n"
            ).bindparams(bindparam("payload", type_=TEXT_ARRAY)),
            {**params, "n": share},
        )
        for r in rows:
            if r.session_id in out or per_ip.get(r.ip, 0) >= PER_IP_CAP:
                continue
            per_ip[r.ip] = per_ip.get(r.ip, 0) + 1
            out[r.session_id] = _cand(r)
    return list(out.values())


async def _content_keys(
    s: AsyncSession, cands: Sequence[Cand], cache: ContentCache
) -> dict[str, Content]:
    out: dict[str, Content] = {}
    missing = []
    for c in cands:
        hit = cache.get(c.session_id)
        if hit is not None:
            out[c.session_id] = hit
        else:
            missing.append(c)
    by_id = {c.session_id: c for c in missing}
    # Old and new sessions are queried in separate slices so each statement carries a narrow
    # ``ts`` range and compressed chunks outside it are never opened.
    for chunk in bounded_slices(
        missing, lambda c: (c.started_at, c.last_event_at), max_items=CHUNK
    ):
        ids = [c.session_id for c in chunk]
        lo, hi = events_ts_range((c.started_at, c.last_event_at) for c in chunk) or (
            chunk[0].started_at,
            chunk[0].last_event_at,
        )
        bounds = {"lo": lo, "hi": hi}
        fresh = {sid: Content() for sid in ids}
        commands: dict[str, list[str]] = {}
        for r in await s.execute(
            text(
                "SELECT session_id, input FROM ("
                " SELECT session_id, left(data->>'input', 1024) AS input,"
                "  row_number() OVER (PARTITION BY session_id ORDER BY ts, id) AS rn"
                " FROM events WHERE session_id = ANY(:ids) AND ts >= :lo AND ts <= :hi"
                " AND type = 'command') x "
                "WHERE rn <= :cap AND input IS NOT NULL ORDER BY session_id, rn"
            ).bindparams(bindparam("ids", type_=TEXT_ARRAY)),
            {"ids": ids, "cap": MAX_COMMANDS, **bounds},
        ):
            commands.setdefault(r.session_id, []).append(r.input)
        for sid, lines in commands.items():
            key = script_key(lines)
            if key is not None:
                fresh[sid].keys.add(key)
        exploits: dict[str, int] = {}
        for r in await s.execute(
            text(
                "SELECT session_id, type, left(coalesce(data->>'method', ''), 16) AS method, "
                "left(coalesce(data->>'path', data->>'url', ''), 512) AS path, "
                "left(coalesce(data->>'query', ''), 256) AS query, "
                "left(coalesce(data->>'body_preview', data->>'input', ''), 512) AS body "
                "FROM events WHERE session_id = ANY(:ids) AND ts >= :lo AND ts <= :hi "
                "AND type IN ('http_request', 'command') "
                "AND tags && :payload ORDER BY ts LIMIT 2000"
            ).bindparams(
                bindparam("ids", type_=TEXT_ARRAY), bindparam("payload", type_=TEXT_ARRAY)
            ),
            {"ids": ids, "payload": list(PAYLOAD_TAGS), **bounds},
        ):
            if exploits.get(r.session_id, 0) >= 3:
                continue
            path = r.path + ("?" + r.query if r.query else "")
            fresh[r.session_id].keys.add(exploit_key(r.type, r.method, path, r.body))
            exploits[r.session_id] = exploits.get(r.session_id, 0) + 1
        heavy = [c.session_id for c in chunk if c.login_attempts >= MIN_CREDLIST_ATTEMPTS]
        if heavy:
            pairs: dict[str, list[tuple[str, str]]] = {}
            for r in await s.execute(
                text(
                    "SELECT session_id, left(coalesce(data->>'username', ''), 64) AS u, "
                    "left(coalesce(data->>'password', ''), 64) AS p FROM events "
                    "WHERE session_id = ANY(:ids) AND ts >= :lo AND ts <= :hi "
                    "AND type = 'login_attempt' "
                    "ORDER BY session_id, ts LIMIT :cap"
                ).bindparams(bindparam("ids", type_=TEXT_ARRAY)),
                {"ids": heavy, "cap": MAX_LOGINS * len(heavy), **bounds},
            ):
                bucket = pairs.setdefault(r.session_id, [])
                if len(bucket) < MAX_LOGINS:
                    bucket.append((r.u, r.p))
            for sid, items in pairs.items():
                key = credlist_key(items)
                if key is not None:
                    fresh[sid].keys.add(key)
        for r in await s.execute(
            text(
                "SELECT DISTINCT ON (session_id) session_id, (data->>'demo') = 'true' AS demo "
                "FROM events WHERE session_id = ANY(:ids) AND ts >= :lo AND ts <= :hi "
                "ORDER BY session_id, ts"
            ).bindparams(bindparam("ids", type_=TEXT_ARRAY)),
            {"ids": ids, **bounds},
        ):
            fresh[r.session_id].demo = bool(r.demo)
        for sid, content in fresh.items():
            if sid in by_id:
                cache.put(sid, content)
                out[sid] = content
    return out


async def _indicator_keys(
    s: AsyncSession, ids: Sequence[str], since: datetime
) -> dict[str, set[Key]]:
    out: dict[str, set[Key]] = {}
    for chunk in _chunks(list(ids), 500):
        rows = await s.execute(
            text(
                "SELECT l.session_id, i.type, i.value, i.role, i.host, i.trusted, f.family "
                "FROM indicator_sessions l JOIN indicators i ON i.id = l.indicator_id "
                "LEFT JOIN LATERAL (SELECT family FROM indicator_intel "
                " WHERE indicator_id = i.id AND family IS NOT NULL "
                " ORDER BY checked_at DESC LIMIT 1) f ON true "
                "WHERE l.seen_at >= :since AND l.session_id = ANY(:ids)"
            ).bindparams(bindparam("ids", type_=TEXT_ARRAY)),
            {"ids": list(chunk), "since": since},
        )
        for r in rows:
            keys = out.setdefault(r.session_id, set())
            if r.role == "download_host":
                host = (r.host if r.type == "url" else r.value) or ""
                if r.type in ("url", "domain", "ip") and host and not is_benign_host(host):
                    keys.add(("payload_host", host))
            # Only a digest a sensor computed is evidence; a hash that is just text in a command
            # (or a family label hanging off one) would let anyone forge a link.
            if r.type == "hash" and r.trusted:
                keys.add(("hash", r.value))
                if r.family:
                    keys.add(("family", r.family))
    return out


async def _stored_keys(
    s: AsyncSession, keys: Iterable[Key]
) -> tuple[dict[Key, int], dict[Key, int]]:
    """(key -> campaign id, key -> distinct sources recorded) for the stored keys."""
    wanted = sorted(set(keys))
    out: dict[Key, int] = {}
    sources: dict[Key, int] = {}
    for chunk in _chunks(wanted, 500):
        rows = await s.execute(
            text(
                "SELECT k.kind, k.value, k.campaign_id, k.sources FROM campaign_keys k "
                "JOIN unnest(:kinds, :values) AS u(kind, value) "
                "ON u.kind = k.kind AND u.value = k.value WHERE k.campaign_id IS NOT NULL"
            ).bindparams(
                bindparam("kinds", type_=TEXT_ARRAY), bindparam("values", type_=TEXT_ARRAY)
            ),
            {"kinds": [k for k, _ in chunk], "values": [v for _, v in chunk]},
        )
        for r in rows:
            out[(r.kind, r.value)] = r.campaign_id
            sources[(r.kind, r.value)] = r.sources
    return out, sources


async def _live_campaigns(
    s: AsyncSession, ids: Iterable[int]
) -> tuple[dict[int, int], dict[int, tuple[datetime, int]]]:
    """Resolve campaign ids through ``merged_into``: (id -> live id, live id -> order)."""
    resolve: dict[int, int] = {}
    order: dict[int, tuple[datetime, int]] = {}
    frontier = set(ids)
    seen: set[int] = set()
    for _ in range(6):
        frontier -= seen
        if not frontier:
            break
        seen |= frontier
        rows = (
            await s.execute(
                text(
                    "SELECT id, status, merged_into, first_seen FROM campaigns WHERE id = ANY(:ids)"
                ).bindparams(bindparam("ids", type_=ARRAY(Integer))),
                {"ids": sorted(frontier)},
            )
        ).all()
        frontier = set()
        for r in rows:
            if r.status == "merged" and r.merged_into is not None:
                resolve[r.id] = r.merged_into
                frontier.add(r.merged_into)
            else:
                resolve[r.id] = r.id
                order[r.id] = (r.first_seen, r.id)
    for cid in list(resolve):
        hops = 0
        while resolve.get(resolve[cid], resolve[cid]) != resolve[cid] and hops < 6:
            resolve[cid] = resolve[resolve[cid]]
            hops += 1
    return resolve, order


# ---- campaign state --------------------------------------------------------------------------


@dataclass(slots=True)
class State:
    id: int
    first_seen: datetime
    last_seen: datetime
    sessions: int
    sources: int
    countries: list[str]
    asns: list[int]
    sensors: list[str]
    techniques: list[str]
    tags: list[str]
    families: list[str]
    rep_session_id: str | None
    demo: bool
    commands: int = 0
    logins: int = 0

    def add(self, cands: Sequence[Cand], families: Iterable[str]) -> None:
        self.first_seen = min([self.first_seen, *(c.started_at for c in cands)])
        self.last_seen = max([self.last_seen, *(c.last_event_at for c in cands)])
        self.sessions += len(cands)
        self.countries = _union(
            self.countries, (c.country for c in cands if c.country), cap=CAP_COUNTRIES
        )
        self.asns = _union(self.asns, (c.asn for c in cands if c.asn is not None), cap=CAP_ASNS)
        self.sensors = _union(self.sensors, (c.sensor for c in cands), cap=CAP_SENSORS)
        self.techniques = _union(
            self.techniques, *(c.techniques for c in cands), cap=CAP_TECHNIQUES
        )
        self.tags = _union(self.tags, *(c.tags for c in cands), cap=CAP_TAGS)
        self.families = _union(self.families, families, cap=CAP_FAMILIES)
        self.commands += sum(c.commands for c in cands)
        self.logins += sum(c.login_attempts for c in cands)
        self.demo = self.demo and all(c.demo for c in cands)
        if self.rep_session_id is None and cands:
            best = max(
                cands,
                key=lambda c: (c.commands, c.downloads, len(c.techniques), c.session_id),
            )
            self.rep_session_id = best.session_id

    def absorb(self, other: State) -> None:
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        self.sessions += other.sessions
        self.sources += other.sources
        self.countries = _union(self.countries, other.countries, cap=CAP_COUNTRIES)
        self.asns = _union(self.asns, other.asns, cap=CAP_ASNS)
        self.sensors = _union(self.sensors, other.sensors, cap=CAP_SENSORS)
        self.techniques = _union(self.techniques, other.techniques, cap=CAP_TECHNIQUES)
        self.tags = _union(self.tags, other.tags, cap=CAP_TAGS)
        self.families = _union(self.families, other.families, cap=CAP_FAMILIES)
        self.commands += other.commands
        self.logins += other.logins
        self.demo = self.demo and other.demo


def _new_state(cands: Sequence[Cand], families: Iterable[str]) -> State:
    state = State(
        id=0, first_seen=cands[0].started_at, last_seen=cands[0].last_event_at, sessions=0,
        sources=0, countries=[], asns=[], sensors=[], techniques=[], tags=[], families=[],
        rep_session_id=None, demo=True,
    )  # fmt: skip
    state.add(cands, families)
    return state


async def _load_state(s: AsyncSession, cid: int) -> State:
    r = (
        await s.execute(
            text(
                "SELECT id, first_seen, last_seen, sessions, sources, countries, asns, sensors, "
                "techniques, tags, families, rep_session_id, demo FROM campaigns WHERE id = :id"
            ),
            {"id": cid},
        )
    ).one()
    return State(
        id=r.id, first_seen=r.first_seen, last_seen=r.last_seen, sessions=r.sessions,
        sources=r.sources, countries=list(r.countries), asns=list(r.asns),
        sensors=list(r.sensors), techniques=list(r.techniques), tags=list(r.tags),
        families=list(r.families), rep_session_id=r.rep_session_id, demo=r.demo,
    )  # fmt: skip


async def _write_state(
    s: AsyncSession,
    st: State,
    stages_by_technique: dict[str, str],
    cfg: ClusterConfig,
    now: datetime,
) -> None:
    active = st.last_seen >= now - timedelta(days=cfg.active_days)
    await s.execute(
        text(
            "UPDATE campaigns SET name = :name, first_seen = :fs, last_seen = :ls, "
            "sessions = :n, sources = greatest(:src, (SELECT count(DISTINCT src_ip) "
            "FROM campaign_sessions WHERE campaign_id = :id)), countries = :c, asns = :a, "
            "sensors = :se, techniques = :t, stages = :st, tags = :tg, families = :f, "
            "severity = :sev, rep_session_id = :rep, demo = :demo, status = :status, "
            "updated_at = now() WHERE id = :id"
        ).bindparams(
            bindparam("c", type_=TEXT_ARRAY),
            bindparam("a", type_=INT_ARRAY),
            bindparam("se", type_=TEXT_ARRAY),
            bindparam("t", type_=TEXT_ARRAY),
            bindparam("st", type_=TEXT_ARRAY),
            bindparam("tg", type_=TEXT_ARRAY),
            bindparam("f", type_=TEXT_ARRAY),
        ),
        {
            "id": st.id,
            "name": campaign_name(st.families, st.tags, st.sensors, st.id),
            "fs": st.first_seen, "ls": st.last_seen, "n": st.sessions, "src": st.sources,
            "c": st.countries, "a": st.asns, "se": st.sensors, "t": st.techniques,
            "st": stages_of(st.techniques, stages_by_technique), "tg": st.tags,
            "f": st.families, "sev": severity_of(st.tags, st.commands, st.logins),
            "rep": st.rep_session_id, "demo": st.demo,
            "status": "active" if active else "quiet",
        },
    )  # fmt: skip


# ---- the cycle -------------------------------------------------------------------------------


async def run_cycle(
    factory: async_sessionmaker[AsyncSession],
    attack: AttackMap | None,
    cfg: ClusterConfig,
    cache: ContentCache,
    now: datetime | None = None,
) -> CycleStats:
    now = now or datetime.now(UTC)
    stages_by_technique = (
        {t.id: t.stage for t in attack.techniques.values()} if attack is not None else {}
    )
    stats = CycleStats()
    async with factory() as s, s.begin():
        cands = await _load_candidates(s, cfg, now)
        stats.examined = len(cands)
        if cands:
            content = await _content_keys(s, cands, cache)
            ind = await _indicator_keys(
                s, [c.session_id for c in cands], now - timedelta(days=cfg.keyed_days)
            )
            for c in cands:
                c.demo = content[c.session_id].demo
                c.keys = cap_keys((*content[c.session_id].keys, *ind.get(c.session_id, ())))
            await _cluster(s, cands, cfg, now, stages_by_technique, stats)
        # Housekeeping: sessions that cannot carry a key are done at once, and so are the ones
        # that never matched anything.
        await s.execute(
            text(
                "UPDATE sessions SET clustered_at = :now WHERE session_id IN ("
                "SELECT session_id FROM sessions WHERE clustered_at IS NULL "
                f"AND last_event_at < :quiet AND NOT {_KEYABLE} "
                "ORDER BY last_event_at LIMIT :n)"
            ).bindparams(bindparam("payload", type_=TEXT_ARRAY)),
            {
                "now": now,
                "quiet": now - timedelta(minutes=cfg.quiet_minutes),
                "logins": MIN_CREDLIST_ATTEMPTS,
                "payload": list(PAYLOAD_TAGS),
                "n": cfg.batch * 5,
            },
        )
        await s.execute(
            text("UPDATE sessions SET clustered_at = :now WHERE session_id = ANY(:ids)").bindparams(
                bindparam("ids", type_=TEXT_ARRAY)
            ),
            {
                "now": now,
                "ids": [
                    c.session_id
                    for c in cands
                    if not c.keys and c.last_event_at < now - timedelta(hours=cfg.keyless_hours)
                ],
            },
        )
        await s.execute(
            text(
                "UPDATE sessions SET clustered_at = :now WHERE session_id IN ("
                "SELECT session_id FROM sessions WHERE clustered_at IS NULL "
                "AND last_event_at < :old ORDER BY last_event_at LIMIT :n)"
            ),
            {"now": now, "old": now - timedelta(days=cfg.keyed_days), "n": cfg.batch},
        )
        await s.execute(
            text(
                "UPDATE campaigns SET status = 'quiet', updated_at = now() "
                "WHERE status = 'active' AND last_seen < :cut"
            ),
            {"cut": now - timedelta(days=cfg.active_days)},
        )
    return stats


async def _cluster(
    s: AsyncSession,
    cands: list[Cand],
    cfg: ClusterConfig,
    now: datetime,
    stages_by_technique: dict[str, str],
    stats: CycleStats,
) -> None:
    keyed = [c for c in cands if c.keys]
    stored, stored_sources = await _stored_keys(s, (k for c in keyed for k in c.keys))
    resolve, order = await _live_campaigns(s, set(stored.values()))
    key_campaign = {k: resolve[cid] for k, cid in stored.items() if cid in resolve}
    plan = build_plan(keyed, key_campaign, order, cfg.min_sources, cfg.merge_budget, stored_sources)
    guarded = await _guard_active(s)
    stats.deferred = plan.deferred
    by_id = {c.session_id: c for c in keyed}

    states: dict[int, State] = {}

    async def state_of(cid: int) -> State:
        if cid not in states:
            states[cid] = await _load_state(s, cid)
        return states[cid]

    for loser, winner in plan.merges:
        low, win = await state_of(loser), await state_of(winner)
        win.absorb(low)
        states.pop(loser, None)  # the loser row is final: status 'merged', never rewritten
        await _move_campaign(s, loser, winner, cfg.link_cap)
        stats.merged += 1

    assigned: dict[int, list[Cand]] = {}
    new_ids: set[int] = set()
    persist: dict[int, set[Key]] = {c: set(k) for c, k in plan.persist.items()}
    for sid, cid in plan.joins.items():
        assigned.setdefault(cid, []).append(by_id[sid])
        await state_of(cid)
    stats.joined = len(plan.joins)

    for group in plan.groups:
        members = [by_id[sid] for sid in group]
        row = await s.execute(
            text(
                "INSERT INTO campaigns (name, first_seen, last_seen) VALUES ('pending', :fs, :ls) "
                "RETURNING id"
            ),
            {
                "fs": min(m.started_at for m in members),
                "ls": max(m.last_event_at for m in members),
            },
        )
        cid = row.scalar_one()
        st = _new_state(members, {v for m in members for k, v in m.keys if k == "family"})
        st.id = cid
        states[cid] = st
        assigned[cid] = members
        persist[cid] = plan.group_keys[len(new_ids)]
        new_ids.add(cid)
        stats.created += 1

    for cid, members in assigned.items():
        st = states[cid]
        if cid not in new_ids:
            st.add(members, {v for m in members for k, v in m.keys if k == "family"})
        await _link_sessions(s, cid, members, cfg.link_cap)
        if not guarded:
            await _upsert_keys(s, cid, members, persist.get(cid, set()))
        await s.execute(
            text(
                "UPDATE sessions SET campaign_id = :cid, clustered_at = :now "
                "WHERE session_id = ANY(:ids)"
            ).bindparams(bindparam("ids", type_=TEXT_ARRAY)),
            {"cid": cid, "now": now, "ids": [m.session_id for m in members]},
        )
    for st in states.values():
        await _write_state(s, st, stages_by_technique, cfg, now)


async def _move_campaign(s: AsyncSession, loser: int, winner: int, link_cap: int) -> None:
    await s.execute(
        text("UPDATE campaign_keys SET campaign_id = :w WHERE campaign_id = :l"),
        {"w": winner, "l": loser},
    )
    # Bounded: the sessions beyond this batch keep pointing at the loser, and readers follow
    # ``merged_into`` to the winner.
    await s.execute(
        text(
            "UPDATE sessions SET campaign_id = :w WHERE session_id IN ("
            "SELECT session_id FROM sessions WHERE campaign_id = :l LIMIT :n)"
        ),
        {"w": winner, "l": loser, "n": MOVE_BATCH},
    )
    have = (
        await s.execute(
            text("SELECT count(*) FROM campaign_sessions WHERE campaign_id = :w"), {"w": winner}
        )
    ).scalar_one()
    await s.execute(
        text(
            "INSERT INTO campaign_sessions (campaign_id, session_id, src_ip, sensor, seen_at) "
            "SELECT :w, session_id, src_ip, sensor, seen_at FROM campaign_sessions "
            "WHERE campaign_id = :l ORDER BY seen_at DESC LIMIT :room ON CONFLICT DO NOTHING"
        ),
        {"w": winner, "l": loser, "room": max(0, link_cap - have)},
    )
    # The loser keeps its own links (the ingest role cannot delete them); retention prunes them.
    await s.execute(
        text(
            "UPDATE campaigns SET status = 'merged', merged_into = :w, updated_at = now() "
            "WHERE id = :l"
        ),
        {"w": winner, "l": loser},
    )


async def _link_sessions(s: AsyncSession, cid: int, members: Sequence[Cand], cap: int) -> None:
    have = (
        await s.execute(
            text("SELECT count(*) FROM campaign_sessions WHERE campaign_id = :id"), {"id": cid}
        )
    ).scalar_one()
    room = max(0, cap - have)
    if not room:
        return
    newest = sorted(members, key=lambda m: (m.last_event_at, m.session_id), reverse=True)[:room]
    await s.execute(
        text(
            "INSERT INTO campaign_sessions (campaign_id, session_id, src_ip, sensor, seen_at) "
            "VALUES (:cid, :sid, CAST(:ip AS inet), :sensor, :seen) ON CONFLICT DO NOTHING"
        ),
        [
            {"cid": cid, "sid": m.session_id, "ip": m.src_ip, "sensor": m.sensor,
             "seen": m.last_event_at}
            for m in newest
        ],
    )  # fmt: skip


async def _guard_active(s: AsyncSession) -> bool:
    """True while the disk guard is active: no new keys are stored then."""
    row = await s.execute(
        text("SELECT (value ->> 'active')::boolean FROM system_status WHERE key = 'disk_guard'")
    )
    return bool(row.scalar_one_or_none())


async def _upsert_keys(
    s: AsyncSession, cid: int, members: Sequence[Cand], allowed: set[Key]
) -> None:
    """Store the keys the plan allows (matched or strong), then trim to the per-campaign cap."""
    per_key: dict[Key, list[Cand]] = {}
    for m in members:
        for k in m.keys & allowed:
            per_key.setdefault(k, []).append(m)
    if not per_key:
        return
    await s.execute(
        text(
            "INSERT INTO campaign_keys (kind, value, campaign_id, sources, first_seen, last_seen) "
            "VALUES (:kind, :value, :cid, :src, :fs, :ls) "
            "ON CONFLICT (kind, value) DO UPDATE SET campaign_id = excluded.campaign_id, "
            "sources = greatest(campaign_keys.sources, excluded.sources), "
            "first_seen = least(campaign_keys.first_seen, excluded.first_seen), "
            "last_seen = greatest(campaign_keys.last_seen, excluded.last_seen)"
        ),
        [
            {
                "kind": kind, "value": value, "cid": cid,
                "src": len({net_of(m.src_ip) for m in ms}),
                "fs": min(m.started_at for m in ms),
                "ls": max(m.last_event_at for m in ms),
            }
            for (kind, value), ms in sorted(per_key.items())
        ],
    )  # fmt: skip
    await s.execute(
        text(
            "DELETE FROM campaign_keys WHERE campaign_id = :c AND (kind, value) IN ("
            "SELECT kind, value FROM campaign_keys WHERE campaign_id = :c "
            "ORDER BY sources DESC, last_seen DESC, kind, value OFFSET :cap)"
        ),
        {"c": cid, "cap": MAX_KEYS_PER_CAMPAIGN},
    )
