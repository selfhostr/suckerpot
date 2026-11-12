"""Which sources, payload hosts and C2 servers deserve a report (design M22, section 3.1).

Only these queries decide what is selected; nothing is looked up for an address that did not
pass them. Research scanners, benign sessions, private and reserved ranges, the never-block list
and every self term are excluded here, before any contact lookup.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.blocklist_values import is_never_host, valid_domain
from suckerpot_db.network_names import host_of_target
from suckerpot_db.session_counts import sql_sessions_count
from suckerpot_reporting import SelfTerms
from suckerpot_reporting.normalize import is_documentation, is_forbidden_range

from .config import AbuseSettings

Kind = Literal["attack_source", "payload_host", "c2"]
Origin = Literal["real", "demo"]


@dataclass(frozen=True)
class Seed:
    kind: Kind
    type: Literal["ip", "domain"]
    value: str
    first_ts: datetime
    last_ts: datetime
    sessions: int
    events: int
    asn: int | None = None
    country: str | None = None
    demo: bool = False


def origin_of_ip(value: str, terms: SelfTerms | None, *, include_demo: bool) -> Origin | None:
    """``real`` for a reportable public address, ``demo`` for a documentation address (when
    demo reports are on), None for anything that must never be reported."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if is_documentation(addr):
        return "demo" if include_demo else None
    if is_forbidden_range(addr) or is_never_host(str(addr)):
        return None
    if terms is not None and terms.is_self(addr) is not None:
        return None
    return "real"


def origin_of_domain(value: str, terms: SelfTerms | None) -> Origin | None:
    host = valid_domain(value)
    if host is None or is_never_host(host):
        return None
    if terms is not None:
        for term in terms.names:
            if host == term.value or host.endswith("." + term.value):
                return None
    return "real"


NETWORK_WINDOW_DAYS = 30


async def network_covered(session: AsyncSession) -> set[str]:
    """Hosts the SuckerPot network reported or got taken down in the last 30 days (M29 dedupe).

    The window runs on the report or takedown date, never on the last sighting.

    Empty unless this node is a member: the network sends one strong report per target, so the
    local workflow must not send a second, weaker one to the same desk. A merely ``confirmed``
    target is not covered: the hub may never report it, so the local candidate stays. Network
    kinds ``ip``, ``domain``, ``c2_ip`` and ``c2_domain`` name hosts; a ``c2``
    value may carry ``:port``.
    """
    rows = await session.execute(
        text(
            """
            SELECT t.value FROM network_targets t
            JOIN network_membership m ON m.id = 1 AND m.state = 'member'
            WHERE t.state IN ('reported', 'taken_down') AND t.value IS NOT NULL
              AND t.kind IN ('ip', 'domain', 'c2_ip', 'c2_domain')
              AND t.reported_day IS NOT NULL
              AND coalesce(t.taken_down_day, t.reported_day)
                  >= (now() AT TIME ZONE 'UTC')::date - CAST(:days AS integer)
            """
        ),
        {"days": NETWORK_WINDOW_DAYS},
    )
    out: set[str] = set()
    for (value,) in rows:
        out.add(host_of_target(str(value)))
    return out


async def without_network(session: AsyncSession, seeds: list[Seed]) -> list[Seed]:
    covered = await network_covered(session)
    return [s for s in seeds if s.value.lower() not in covered] if covered else seeds


def _bounds(settings: AbuseSettings, now: datetime) -> dict[str, Any]:
    return {
        "since": now - timedelta(days=settings.lookback_days),
        "settled": now - timedelta(minutes=settings.settle_min),
    }


async def attack_sources(
    session: AsyncSession, settings: AbuseSettings, now: datetime, limit: int = 500
) -> list[Seed]:
    sql = text(
        f"""
        WITH s AS (
            SELECT src_ip, asn, country, started_at, last_event_at, event_count,
                   login_attempts, login_success, commands, downloads, connections,
                   (tags && CAST(:severe AS text[])
                    OR EXISTS (SELECT 1 FROM unnest(tags) AS t WHERE t LIKE 'cve-%')) AS severe
            FROM sessions
            WHERE NOT benign AND scanner_name IS NULL
              AND last_event_at >= :since AND last_event_at < :settled
        )
        SELECT host(src_ip) AS ip, max(asn) AS asn, max(country) AS country,
               min(started_at) AS first_ts, max(last_event_at) AS last_ts,
               {sql_sessions_count()} AS sessions, sum(event_count)::int AS events
        FROM s GROUP BY src_ip
        HAVING sum(login_attempts) >= :min_logins
            OR bool_or(login_success AND commands > 0)
            OR sum(downloads) > 0
            OR bool_or(severe)
        ORDER BY sum(event_count) DESC LIMIT :lim
        """  # noqa: S608 - constant fragments only
    )
    rows = (
        await session.execute(
            sql,
            {
                **_bounds(settings, now),
                "severe": list(settings.severe_tags),
                "min_logins": settings.min_login_attempts,
                "lim": limit,
            },
        )
    ).all()
    return await without_network(
        session,
        [
            Seed(
                "attack_source",
                "ip",
                r.ip,
                r.first_ts,
                r.last_ts,
                r.sessions,
                r.events,
                r.asn,
                r.country,
            )
            for r in rows
        ],
    )


async def payload_hosts(
    session: AsyncSession, settings: AbuseSettings, now: datetime, limit: int = 300
) -> list[Seed]:
    rows = (
        await session.execute(
            text(
                """
                SELECT i.host AS host, i.type AS type, min(i.first_seen) AS first_ts,
                       max(i.last_seen) AS last_ts, count(DISTINCT x.session_id) AS sessions,
                       sum(i.sightings)::int AS events
                FROM indicators i
                JOIN indicator_sessions x ON x.indicator_id = i.id
                JOIN sessions s ON s.session_id = x.session_id
                WHERE i.role = 'download_host' AND i.host IS NOT NULL
                  AND NOT s.benign AND s.scanner_name IS NULL
                  AND i.last_seen >= :since AND i.last_seen < :settled
                  AND (NOT i.demo OR CAST(:demo AS boolean))
                GROUP BY i.host, i.type
                ORDER BY sum(i.sightings) DESC LIMIT :lim
                """
            ),
            {**_bounds(settings, now), "demo": settings.include_demo, "lim": limit},
        )
    ).all()
    out: list[Seed] = []
    for r in rows:
        kind = _host_type(r.host)
        if kind is not None:
            out.append(
                Seed("payload_host", kind, r.host, r.first_ts, r.last_ts, r.sessions, r.events)
            )
    return await without_network(session, out)


async def c2_subjects(
    session: AsyncSession, settings: AbuseSettings, now: datetime, limit: int = 300
) -> list[Seed]:
    rows = (
        await session.execute(
            text(
                """
                SELECT address, kind, min(first_seen) AS first_ts, max(checked_at) AS last_ts
                FROM indicator_contacts
                WHERE confidence = 'high' AND checked_at >= :since AND checked_at < :settled
                GROUP BY address, kind ORDER BY max(checked_at) DESC LIMIT :lim
                """
            ),
            {**_bounds(settings, now), "lim": limit},
        )
    ).all()
    out: dict[str, Seed] = {}
    for r in rows:
        kind = _host_type(r.address)
        if kind is not None:
            out[r.address] = Seed("c2", kind, r.address, r.first_ts, r.last_ts, 0, 0)
    # C2 addresses read from analysed samples (high confidence only).
    links = (
        await session.execute(
            text(
                """
                SELECT l.value AS address, min(sm.first_seen) AS first_ts,
                       max(sm.last_seen) AS last_ts
                FROM sample_links l JOIN samples sm ON sm.sha256 = l.sha256
                WHERE l.kind IN ('c2_ip', 'c2_domain') AND l.confidence = 'high'
                  AND sm.last_seen >= :since AND sm.last_seen < :settled
                GROUP BY l.value ORDER BY max(sm.last_seen) DESC LIMIT :lim
                """
            ),
            {**_bounds(settings, now), "lim": limit},
        )
    ).all()
    for r in links:
        kind = _host_type(r.address)
        if kind is not None and r.address not in out:
            out[r.address] = Seed("c2", kind, r.address, r.first_ts, r.last_ts, 0, 0)
    return (await without_network(session, list(out.values())))[:limit]


def _host_type(value: str) -> Literal["ip", "domain"] | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "domain" if valid_domain(value) else None
    return "ip"
