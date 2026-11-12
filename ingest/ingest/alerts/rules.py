"""The alert rules: which events become candidates for an alert.

Each collector reads a bounded batch newer than the rule's cursor and returns the candidates plus
the new cursor. The first time a rule runs its cursor starts at "now" (or at the newest row), so
enabling a rule never replays history. Sessions from the documentation address ranges (the demo
generator's) never alert: real traffic cannot come from them.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.session_counts import sql_sessions_count

from ingest.alerts.messages import Candidate

BATCH = 50
NOT_DOCUMENTATION = (
    "NOT (s.src_ip <<= '192.0.2.0/24'::inet OR s.src_ip <<= '198.51.100.0/24'::inet "
    "OR s.src_ip <<= '203.0.113.0/24'::inet)"
)

Cursor = dict[str, Any]
Collector = Callable[[AsyncSession, Cursor | None], Awaitable[tuple[list[Candidate], Cursor]]]


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _ts(cursor: Cursor | None, now: datetime) -> datetime:
    raw = (cursor or {}).get("ts")
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return now


async def _db_now(session: AsyncSession) -> datetime:
    now: datetime = (await session.execute(text("SELECT now()"))).scalar_one()
    return now


async def new_campaigns(
    session: AsyncSession, cursor: Cursor | None
) -> tuple[list[Candidate], Cursor]:
    if cursor is None or not isinstance(cursor.get("last_id"), int):
        newest = (
            await session.execute(text("SELECT COALESCE(max(id), 0) FROM campaigns"))
        ).scalar_one()
        return [], {"last_id": int(newest)}
    rows = (
        (
            await session.execute(
                text(
                    """
                SELECT id, name, severity, sessions, sources, countries, sensors, techniques
                FROM campaigns
                WHERE id > :cur AND NOT demo AND status <> 'merged'
                ORDER BY id LIMIT :n
                """
                ),
                {"cur": cursor["last_id"], "n": BATCH},
            )
        )
        .mappings()
        .all()
    )
    out = [
        Candidate("new_campaign", f"campaign:{r['id']}", str(r["severity"]), dict(r)) for r in rows
    ]
    last = int(rows[-1]["id"]) if rows else cursor["last_id"]
    return out, {"last_id": last}


async def new_download_hosts(
    session: AsyncSession, cursor: Cursor | None
) -> tuple[list[Candidate], Cursor]:
    if cursor is None or not isinstance(cursor.get("last_id"), int):
        newest = (
            await session.execute(text("SELECT COALESCE(max(id), 0) FROM indicators"))
        ).scalar_one()
        return [], {"last_id": int(newest)}
    rows = (
        (
            await session.execute(
                text(
                    """
                SELECT i.id, COALESCE(i.host, i.value) AS host, i.sightings, i.sensors,
                       (SELECT ii.family FROM indicator_intel ii
                         WHERE ii.indicator_id = i.id AND ii.family IS NOT NULL LIMIT 1) AS family
                FROM indicators i
                WHERE i.id > :cur AND i.role = 'download_host' AND NOT i.demo
                ORDER BY i.id LIMIT :n
                """
                ),
                {"cur": cursor["last_id"], "n": BATCH},
            )
        )
        .mappings()
        .all()
    )
    out = [
        Candidate("new_download_host", f"host:{str(r['host'])[:100]}", "warning", dict(r))
        for r in rows
    ]
    last = int(rows[-1]["id"]) if rows else cursor["last_id"]
    return out, {"last_id": last}


async def malware_drops(
    session: AsyncSession, cursor: Cursor | None
) -> tuple[list[Candidate], Cursor]:
    now = await _db_now(session)
    since = _ts(cursor, now)
    if cursor is None:
        return [], {"ts": _iso(now)}
    rows = (
        (
            await session.execute(
                text(
                    f"""
                SELECT s.session_id, s.sensor, host(s.src_ip) AS src_ip, s.country, s.org,
                       s.tags, s.last_event_at
                FROM sessions s
                WHERE s.last_event_at > :since AND 'malware-drop' = ANY(s.tags)
                  AND NOT s.benign AND {NOT_DOCUMENTATION}
                ORDER BY s.last_event_at LIMIT :n
                """  # noqa: S608 - constant fragments only
                ),
                {"since": since, "n": BATCH},
            )
        )
        .mappings()
        .all()
    )
    out = [
        Candidate("malware_drop", f"session:{r['session_id']}"[:128], "severe", dict(r))
        for r in rows
    ]
    nxt = rows[-1]["last_event_at"] if len(rows) == BATCH else now
    return out, {"ts": _iso(nxt)}


async def watched_cves(
    session: AsyncSession, cursor: Cursor | None
) -> tuple[list[Candidate], Cursor]:
    now = await _db_now(session)
    since = _ts(cursor, now)
    if cursor is None:
        return [], {"ts": _iso(now)}
    rows = (
        (
            await session.execute(
                text(
                    f"""
                SELECT c.cve_id, c.title, c.in_kev, {sql_sessions_count("s")} AS sessions
                FROM watched_cves w
                JOIN cve c ON c.cve_id = w.cve_id AND cardinality(c.tags) > 0
                JOIN sessions s ON s.tags && c.tags
                WHERE s.last_event_at > :since AND s.last_event_at <= :now
                  AND NOT s.benign AND {NOT_DOCUMENTATION}
                GROUP BY c.cve_id, c.title, c.in_kev
                ORDER BY c.cve_id LIMIT :n
                """  # noqa: S608 - constant fragments only
                ),
                {"since": since, "now": now, "n": BATCH},
            )
        )
        .mappings()
        .all()
    )
    day = now.astimezone(UTC).date().isoformat()
    out = [
        Candidate(
            "watched_cve_seen",
            f"cve:{r['cve_id']}:{day}",
            "severe" if r["in_kev"] else "warning",
            dict(r),
        )
        for r in rows
    ]
    return out, {"ts": _iso(now)}


COLLECTORS: dict[str, Collector] = {
    "new_campaign": new_campaigns,
    "new_download_host": new_download_hosts,
    "malware_drop": malware_drops,
    "watched_cve_seen": watched_cves,
}
