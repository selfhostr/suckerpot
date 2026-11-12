"""Collects the numbers of one week for the weekly report.

The week runs Monday 00:00 to the next Monday 00:00 in the site time zone. Only real traffic is
counted: research scanners (``benign``) and the documentation address ranges used by the demo
generator are left out. The summary holds no IP address and only defanged indicators, so it is
safe to show, print and forward.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.session_counts import sql_sessions_count

from ingest.alerts.text import clean_text, defang

REAL = (
    "NOT s.benign AND NOT (s.src_ip <<= '192.0.2.0/24'::inet "
    "OR s.src_ip <<= '198.51.100.0/24'::inet OR s.src_ip <<= '203.0.113.0/24'::inet)"
)

# How a sensor is named in prose and in the printed report (same names as the web registry).
SENSOR_LABEL = {
    "ssh": "SSH",
    "telnet": "Telnet",
    "web": "Web",
    "rdp": "RDP",
    "smb": "SMB",
    "redis": "Redis",
    "docker": "Docker",
    "mysql": "MySQL",
    "mssql": "MSSQL",
    "adb": "ADB",
    "sip": "SIP",
    "synology": "Synology NAS",
}


def sensor_label(sensor: object) -> str:
    """The display name of a sensor; an unknown value is cleaned and kept as is."""
    key = str(sensor)
    return SENSOR_LABEL.get(key, clean_text(key, 20))


SENSOR_ADVICE = {
    "ssh": "SSH was the most targeted service: allow it only from a VPN, no password logins.",
    "telnet": "Telnet was the most targeted service: make sure no device of yours still offers it.",
    "rdp": "RDP was the most targeted service: never expose it, use a VPN or a gateway.",
    "web": "Web attacks led: keep web software patched and put a firewall in front.",
    "smb": "SMB was the most targeted service: block file sharing at the perimeter.",
    "redis": "Redis was the most targeted service: bind it to localhost and require a password.",
    "docker": "The Docker API was the most targeted service: never expose it, protect it with TLS.",
    "mysql": "MySQL was the most targeted service: keep databases off the internet.",
    "mssql": "SQL Server was the most targeted service: keep databases off the internet.",
    "adb": "Android Debug Bridge was the most targeted service: disable it on connected devices.",
    "sip": "SIP was the most targeted service: restrict your phone system to known providers.",
    "synology": "Synology NAS was the most targeted: patch DSM and keep it off the internet.",
}


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError, ValueError:
        return ZoneInfo("UTC")


def previous_week(now: datetime, tz: ZoneInfo) -> date:
    """Monday of the last complete week, as seen in the site time zone."""
    local = now.astimezone(tz)
    this_monday = local.date() - timedelta(days=local.weekday())
    return this_monday - timedelta(days=7)


def due(now: datetime, tz: ZoneInfo) -> bool:
    """True from Monday 06:00 local time (and every later day of the week)."""
    local = now.astimezone(tz)
    return local.weekday() > 0 or local.hour >= 6


def window(week_start: date, tz: ZoneInfo) -> tuple[datetime, datetime]:
    start = datetime(week_start.year, week_start.month, week_start.day, tzinfo=tz)
    end_day = week_start + timedelta(days=7)
    end = datetime(end_day.year, end_day.month, end_day.day, tzinfo=tz)
    return start.astimezone(UTC), end.astimezone(UTC)


def _pct(now: int, before: int) -> int | None:
    if before <= 0:
        return None
    return round((now - before) * 100 / before)


async def collect(session: AsyncSession, week_start: date, tz_name: str) -> dict[str, Any]:
    tz = zone(tz_name)
    start, end = window(week_start, tz)
    prev_start = start - timedelta(days=7)
    p = {"s": start, "e": end}
    await session.execute(text("SET LOCAL statement_timeout = '60s'"))
    totals = (
        (
            await session.execute(
                text(
                    f"""
                SELECT {sql_sessions_count("s")} AS sessions,
                       count(DISTINCT s.src_ip) AS sources,
                       {sql_sessions_count("s", "s.commands > 0")} AS with_commands,
                       {sql_sessions_count("s", "'malware-drop' = ANY(s.tags)")} AS malware
                FROM sessions s WHERE s.started_at >= :s AND s.started_at < :e AND {REAL}
                """  # noqa: S608 - constant fragments only
                ),
                p,
            )
        )
        .mappings()
        .one()
    )
    before = (
        await session.execute(
            text(
                f"SELECT {sql_sessions_count('s')} FROM sessions s "  # noqa: S608
                f"WHERE s.started_at >= :s AND s.started_at < :e AND {REAL}"
            ),
            {"s": prev_start, "e": start},
        )
    ).scalar_one()
    by_sensor = [
        {"sensor": r.sensor, "sessions": r.n}
        for r in (
            await session.execute(
                text(
                    f"""
                    SELECT s.sensor, {sql_sessions_count("s")} AS n FROM sessions s
                    WHERE s.started_at >= :s AND s.started_at < :e AND {REAL}
                    GROUP BY s.sensor ORDER BY n DESC, s.sensor LIMIT 12
                    """  # noqa: S608
                ),
                p,
            )
        ).all()
    ]
    countries = [
        {"country": clean_text(r.country, 8), "sessions": r.n}
        for r in (
            await session.execute(
                text(
                    f"""
                    SELECT s.country, {sql_sessions_count("s")} AS n FROM sessions s
                    WHERE s.started_at >= :s AND s.started_at < :e AND {REAL}
                      AND s.country IS NOT NULL
                    GROUP BY s.country ORDER BY n DESC, s.country LIMIT 5
                    """  # noqa: S608
                ),
                p,
            )
        ).all()
    ]
    tags = [
        {"tag": clean_text(r.tag, 40), "sessions": r.n}
        for r in (
            await session.execute(
                text(
                    f"""
                    SELECT t AS tag, {sql_sessions_count("s")} AS n
                    FROM sessions s, unnest(s.tags) AS t
                    WHERE s.started_at >= :s AND s.started_at < :e AND {REAL}
                    GROUP BY t ORDER BY n DESC, t LIMIT 8
                    """  # noqa: S608
                ),
                p,
            )
        ).all()
    ]
    campaigns = [
        {
            "id": r.id,
            "name": clean_text(r.name, 80),
            "severity": r.severity,
            "sessions": r.sessions,
            "sources": r.sources,
        }
        for r in (
            await session.execute(
                text(
                    """
                    SELECT id, name, severity, sessions, sources FROM campaigns
                    WHERE first_seen >= :s AND first_seen < :e AND NOT demo AND status <> 'merged'
                    ORDER BY sessions DESC, id LIMIT 10
                    """
                ),
                p,
            )
        ).all()
    ]
    hosts = [
        {"host": defang(str(r.host), 100), "sightings": r.sightings}
        for r in (
            await session.execute(
                text(
                    """
                    SELECT COALESCE(host, value) AS host, max(sightings) AS sightings
                    FROM indicators
                    WHERE role = 'download_host' AND NOT demo
                      AND first_seen >= :s AND first_seen < :e
                    GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10
                    """
                ),
                p,
            )
        ).all()
    ]
    cves = [
        {"cve_id": clean_text(r.cve_id, 24), "sessions": r.n}
        for r in (
            await session.execute(
                text(
                    f"""
                    SELECT c.cve_id, {sql_sessions_count("s")} AS n
                    FROM watched_cves w
                    JOIN cve c ON c.cve_id = w.cve_id AND cardinality(c.tags) > 0
                    JOIN sessions s ON s.tags && c.tags
                    WHERE s.started_at >= :s AND s.started_at < :e AND {REAL}
                    GROUP BY c.cve_id ORDER BY n DESC, c.cve_id LIMIT 10
                    """  # noqa: S608
                ),
                p,
            )
        ).all()
    ]
    return summarize(
        week_start=week_start,
        tz_name=tz.key or "UTC",
        sessions=int(totals["sessions"]),
        sources=int(totals["sources"]),
        with_commands=int(totals["with_commands"]),
        malware=int(totals["malware"]),
        previous=int(before),
        by_sensor=by_sensor,
        countries=countries,
        tags=tags,
        campaigns=campaigns,
        hosts=hosts,
        cves=cves,
    )


def summarize(
    *,
    week_start: date,
    tz_name: str,
    sessions: int,
    sources: int,
    with_commands: int,
    malware: int,
    previous: int,
    by_sensor: list[dict[str, Any]],
    countries: list[dict[str, Any]],
    tags: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    hosts: list[dict[str, Any]],
    cves: list[dict[str, Any]],
) -> dict[str, Any]:
    """Pure: the numbers become the summary with its headline and next actions."""
    change = _pct(sessions, previous)
    trend = (
        "about the same as the week before"
        if change is None or abs(change) < 5
        else f"{'up' if change > 0 else 'down'} {abs(change)}% on the week before"
    )
    top = by_sensor[0]["sensor"] if by_sensor else None
    if sessions == 0:
        headline = "A quiet week: no attack sessions were recorded."
    else:
        headline = f"{sessions:,} attack sessions from {sources:,} addresses, {trend}" + (
            f", mostly against {sensor_label(top)}." if top else "."
        )
    actions: list[str] = []
    if hosts:
        actions.append(
            f"Block the {len(hosts)} new malware download "
            f"host{'s' if len(hosts) != 1 else ''} listed below on your web proxy or DNS filter."
        )
    if campaigns:
        actions.append(
            f"Review the {len(campaigns)} new campaign{'s' if len(campaigns) != 1 else ''} and "
            "check that your own services do not expose the same weakness."
        )
    for cve in cves[:3]:
        actions.append(
            f"Patch or mitigate {cve['cve_id']} on your own systems: it was tried "
            f"{cve['sessions']:,} times against the honeypot."
        )
    if malware:
        actions.append(
            f"{malware:,} sessions dropped malware. Make sure servers cannot download "
            "files from the internet unless they need to."
        )
    if top in SENSOR_ADVICE:
        actions.append(SENSOR_ADVICE[top])
    if not actions:
        actions.append("Nothing unusual this week. Keep systems patched and exposure minimal.")
    return {
        "week_start": week_start.isoformat(),
        "week_end": (week_start + timedelta(days=6)).isoformat(),
        "timezone": tz_name,
        "headline": headline,
        "totals": {
            "sessions": sessions,
            "sources": sources,
            "with_commands": with_commands,
            "malware": malware,
            "previous_sessions": previous,
            "change_pct": change,
        },
        "by_sensor": by_sensor,
        "countries": countries,
        "tags": tags,
        "campaigns": campaigns,
        "download_hosts": hosts,
        "watched_cves": cves,
        "actions": actions,
    }


def alert_facts(summary: dict[str, Any]) -> list[list[str]]:
    t = summary["totals"]
    change = t["change_pct"]
    return [
        ["Sessions", f"{t['sessions']:,}" + (f" ({change:+d}%)" if change is not None else "")],
        ["Sources", f"{t['sources']:,}"],
        ["New campaigns", str(len(summary["campaigns"]))],
        ["New download hosts", str(len(summary["download_hosts"]))],
        ["Malware sessions", f"{t['malware']:,}"],
    ]
