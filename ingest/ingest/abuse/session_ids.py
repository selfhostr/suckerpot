"""The internal ids a report must never carry: the sessions that stand behind its subjects.

The draft builder collects them while it reads the evidence (``Collector.session_ids``): the
sessions of an attacking address, and for a payload host the attacker sessions that fetched
from it (``indicator_sessions``). A later check cannot replay that read, so this is a superset
built from the stored evidence: every session of a source address that was active since
``LOOKBACK`` before the report's window (``ABUSE_LOOKBACK_DAYS`` is at most 90), and for a
payload host every session that named it. It is capped, newest first. A check that uses it still
may not clear an evidence code the build set (see ``ingest.abuse.reguard``).
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_reporting import Evidence

LOOKBACK = timedelta(days=90)
MAX_SESSION_IDS = 5000


async def internal_session_ids(session: AsyncSession, evidence: Evidence) -> set[str]:
    """Session ids that stand behind the subjects of ``evidence`` (never their values in a log)."""
    since = evidence.window_start - LOOKBACK
    ids: set[str] = set()
    ips = [s.value for s in evidence.subjects if s.type == "ip"]
    if ips:
        found = await session.execute(
            text(
                "SELECT session_id FROM sessions "
                "WHERE src_ip = ANY(CAST(CAST(:ips AS text[]) AS inet[])) "
                "AND last_event_at >= :since ORDER BY last_event_at DESC LIMIT :n"
            ),
            {"ips": ips, "since": since, "n": MAX_SESSION_IDS},
        )
        ids.update(r.session_id for r in found)
    if evidence.kind == "payload_host":
        hosts = [s.value for s in evidence.subjects]
        found = await session.execute(
            text(
                "SELECT x.session_id FROM indicators i "
                "JOIN indicator_sessions x ON x.indicator_id = i.id "
                "WHERE i.role = 'download_host' AND i.host = ANY(:hosts) AND x.seen_at >= :since "
                "GROUP BY x.session_id ORDER BY max(x.seen_at) DESC LIMIT :n"
            ),
            {"hosts": hosts, "since": since, "n": MAX_SESSION_IDS},
        )
        ids.update(r.session_id for r in found)
    return ids
