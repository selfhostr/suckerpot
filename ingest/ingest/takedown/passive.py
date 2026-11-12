"""Passive signals and the state update (design M27 sections 4.5 and 5). Database only.

* ``sightings``: did our own sensors see a reported attacking address again?
* ``samples``: did a sample first seen after the report point to a reported C2?
* ``update_states``: run ``state.decide`` for the targets whose checks changed.

A check row is written when the answer changes (and a ``seen`` answer is refreshed once a day),
so the table does not grow by one row per worker cycle.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.session_counts import sql_sessions_count

from ingest.takedown.state import (
    Check,
    ChildView,
    Decision,
    TargetView,
    decide,
)

Factory = async_sessionmaker[AsyncSession]
SIGHTING_WINDOW: Final = timedelta(hours=72)
REFRESH_SEEN: Final = timedelta(hours=24)
STATE_BATCH: Final = 300
CHECKS_PER_TARGET: Final = 200

SIGHTINGS = f"""
SELECT t.id,
  (SELECT {sql_sessions_count("s")} FROM sessions s
    WHERE s.src_ip = CAST(t.value AS inet) AND NOT s.benign AND s.scanner_name IS NULL
      AND s.started_at > t.reported_at AND s.started_at > :since) AS n,
  (SELECT c.outcome FROM takedown_checks c
    WHERE c.target_id = t.id AND c.method = 'sightings'
    ORDER BY c.checked_at DESC LIMIT 1) AS last_outcome,
  (SELECT c.checked_at FROM takedown_checks c
    WHERE c.target_id = t.id AND c.method = 'sightings'
    ORDER BY c.checked_at DESC LIMIT 1) AS last_at
FROM takedown_targets t
WHERE t.role = 'attack_source' AND t.kind = 'ip' AND t.tracking AND NOT t.demo
  AND t.track_until > :now
"""  # noqa: S608 - constant fragments only

SAMPLES = """
SELECT t.id,
  EXISTS (SELECT 1 FROM sample_links l JOIN samples sm ON sm.sha256 = l.sha256
          WHERE l.kind = CASE WHEN t.kind = 'ip' THEN 'c2_ip' ELSE 'c2_domain' END
            AND l.value = t.value AND sm.first_seen > t.reported_at) AS hit,
  (SELECT c.outcome FROM takedown_checks c
    WHERE c.target_id = t.id AND c.method = 'samples'
    ORDER BY c.checked_at DESC LIMIT 1) AS last_outcome
FROM takedown_targets t
WHERE t.role = 'c2' AND t.kind IN ('ip', 'domain') AND t.tracking AND NOT t.demo
  AND t.track_until > :now
"""

INSERT_CHECK = (
    "INSERT INTO takedown_checks (target_id, checked_at, method, outcome, detail) "
    "VALUES (:t, :now, :m, :o, CAST(:d AS jsonb))"
)


async def _write(
    factory: Factory, rows: list[tuple[int, str, str, dict[str, Any]]], now: datetime
) -> None:
    if not rows:
        return
    async with factory() as session, session.begin():
        for tid, method, outcome, detail in rows:
            await session.execute(
                text(INSERT_CHECK),
                {"t": tid, "now": now, "m": method, "o": outcome, "d": json.dumps(detail)},
            )


async def sightings(factory: Factory, now: datetime) -> int:
    async with factory() as session:
        found = (
            await session.execute(text(SIGHTINGS), {"now": now, "since": now - SIGHTING_WINDOW})
        ).all()
    out: list[tuple[int, str, str, dict[str, Any]]] = []
    for r in found:
        outcome = "seen" if r.n > 0 else "not_seen"
        changed = r.last_outcome != outcome
        stale = outcome == "seen" and r.last_at is not None and now - r.last_at >= REFRESH_SEEN
        if changed or stale:
            out.append((r.id, "sightings", outcome, {"sessions": int(r.n)}))
    await _write(factory, out, now)
    return len(out)


async def sample_signals(factory: Factory, now: datetime) -> int:
    async with factory() as session:
        found = (await session.execute(text(SAMPLES), {"now": now})).all()
    out: list[tuple[int, str, str, dict[str, Any]]] = []
    for r in found:
        outcome = "new_sample" if r.hit else "none"
        if r.last_outcome != outcome and not (r.last_outcome is None and outcome == "none"):
            out.append((r.id, "samples", outcome, {}))
    await _write(factory, out, now)
    return len(out)


CANDIDATES = """
SELECT t.id, t.kind, t.role, t.reported_at, t.http_eligible, t.state, t.state_since,
       t.baseline_sha256, t.last_up_at, t.first_down_at, t.resurrections, t.down_before_report
FROM takedown_targets t
WHERE t.tracking AND NOT t.demo
  AND (t.role = 'payload_host' OR t.role = 'attack_source'
       OR t.state_updated_at IS NULL
       OR EXISTS (SELECT 1 FROM takedown_checks c
                  WHERE c.target_id = t.id AND c.checked_at > t.state_updated_at))
ORDER BY CASE t.role WHEN 'payload_url' THEN 0 WHEN 'c2' THEN 1 WHEN 'attack_source' THEN 2
                     ELSE 3 END, t.id
LIMIT :n
"""


async def update_states(factory: Factory, now: datetime, quiet_days: int) -> int:
    """Recompute the state of targets with new checks (hosts and attacking addresses always: their
    state depends on children and on the clock). Returns how many rows changed."""
    async with factory() as session:
        targets = (await session.execute(text(CANDIDATES), {"n": STATE_BATCH})).all()
    changed = 0
    for t in targets:
        async with factory() as session, session.begin():
            checks = await _checks(session, t.id)
            children = await _children(session, t.id) if t.role == "payload_host" else []
            view = TargetView(
                kind=t.kind,
                role=t.role,
                reported_at=t.reported_at,
                http_eligible=t.http_eligible,
                state=t.state,
                state_since=t.state_since,
                baseline_sha256=t.baseline_sha256,
                last_up_at=t.last_up_at,
                first_down_at=t.first_down_at,
                resurrections=t.resurrections,
                down_before_report=t.down_before_report,
            )
            d = decide(view, checks, now, children=children, quiet_days=quiet_days)
            if await _store(session, t.id, view, d, now):
                changed += 1
    return changed


async def _checks(session: AsyncSession, tid: int) -> list[Check]:
    rows = (
        await session.execute(
            text(
                "SELECT checked_at, method, outcome, sha256 FROM takedown_checks "
                "WHERE target_id = :t ORDER BY checked_at DESC, id DESC LIMIT :n"
            ),
            {"t": tid, "n": CHECKS_PER_TARGET},
        )
    ).all()
    return [Check(r.checked_at, r.method, r.outcome, r.sha256) for r in reversed(rows)]


async def _children(session: AsyncSession, tid: int) -> list[ChildView]:
    rows = (
        await session.execute(
            text(
                "SELECT state, last_up_at, first_down_at FROM takedown_targets "
                "WHERE parent_id = :t AND tracking"
            ),
            {"t": tid},
        )
    ).all()
    return [ChildView(r.state, r.last_up_at, r.first_down_at) for r in rows]


async def _store(
    session: AsyncSession, tid: int, view: TargetView, d: Decision, now: datetime
) -> bool:
    await session.execute(
        text(
            """
            UPDATE takedown_targets SET state = :s, state_source = COALESCE(:src, state_source),
                state_since = :since,
                state_updated_at = :now, last_up_at = :up, first_down_at = :down,
                resurrections = :res, down_before_report = :dbr
            WHERE id = :i
            """
        ),
        {
            "s": d.state, "src": d.source, "since": d.state_since, "now": now,
            "up": d.last_up_at, "down": d.first_down_at, "res": d.resurrections,
            "dbr": d.down_before_report, "i": tid,
        },
    )  # fmt: skip
    return d.state != view.state
