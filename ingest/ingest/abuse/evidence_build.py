"""Turns selected subjects into ``Subject`` evidence (design M22, section 4).

Evidence is an allow-list: fields are copied one by one into the typed model and every free-text
value goes through ``redact`` first. There is no path that copies a raw event. Sensor names,
session ids, passwords, headers other than the user agent and any sensor output never get here.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.sample_kinds import benign_web_sample
from suckerpot_reporting import (
    Activity,
    RedactionContext,
    RedactionStats,
    SampleRef,
    redact,
)
from suckerpot_reporting.evidence import (
    MAX_ACTIVITIES_CSV,
    MAX_TEXT_LEN,
    MAX_UA_LEN,
    MAX_USERNAME_LEN,
    MAX_USERNAMES,
)

from .candidates import Seed, origin_of_ip
from .config import AbuseSettings
from .ports import protocol_of

EVENT_LIMIT = 3000
COMMAND_CAP = 60


@dataclass
class _Login:
    ts: datetime
    common: dict[str, Any]
    count: int = 0
    users: list[str] = field(default_factory=list)


class Collector:
    """Accumulates the redaction counters and the session ids seen while building one report."""

    def __init__(self) -> None:
        self.stats = RedactionStats()
        self.session_ids: set[str] = set()
        self.extra_addresses: set[str] = set()

    def add(self, stats: RedactionStats) -> None:
        self.stats = self.stats + stats


def _line(value: object, ctx: RedactionContext, col: Collector, limit: int) -> str | None:
    """Redacted single-line text, or None when nothing is left."""
    if not isinstance(value, str) or not value.strip():
        return None
    red = redact(value, ctx, max_len=limit, single_line=True)
    col.add(red.stats)
    return red.text[:limit] or None


def _url_host_address(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _is_severe(tags: list[str], severe: tuple[str, ...]) -> bool:
    return any(t in severe or t.startswith("cve-") for t in tags)


async def source_activities(
    session: AsyncSession,
    seed: Seed,
    start: datetime,
    end: datetime,
    ctx: RedactionContext,
    col: Collector,
    settings: AbuseSettings,
) -> list[Activity]:
    rows = (
        await session.execute(
            text(
                """
                SELECT ts, sensor, session_id, type, src_port, dst_port, data, tags
                FROM events
                WHERE src_ip = CAST(:ip AS inet) AND ts >= :start AND ts <= :end
                  AND type IN ('login_attempt', 'command', 'download_attempt', 'http_request')
                  AND NOT coalesce(benign, false)
                ORDER BY ts LIMIT :lim
                """
            ),
            {"ip": seed.value, "start": start, "end": end, "lim": EVENT_LIMIT},
        )
    ).all()
    acts: list[Activity] = []
    logins: OrderedDict[tuple[int, str, datetime], _Login] = OrderedDict()
    logged_in: set[str] = set()
    announced: set[str] = set()
    commands = 0
    for r in rows:
        col.session_ids.add(r.session_id)
        data = r.data if isinstance(r.data, dict) else {}
        common: dict[str, Any] = {
            "src_ip": seed.value,
            "src_port": r.src_port,
            "dst_port": settings.ports.public_port(r.sensor, r.dst_port),
            "protocol": protocol_of(r.sensor),
            "service": settings.ports.service_of(r.sensor, r.dst_port),
        }
        if r.type == "login_attempt":
            if data.get("success") is True:
                logged_in.add(r.session_id)
                continue
            bucket = (
                settings.ports.public_port(r.sensor, r.dst_port),
                r.sensor,
                r.ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0),
            )
            entry = logins.setdefault(bucket, _Login(r.ts, common))
            entry.count += 1
            name = _line(data.get("username"), ctx, col, MAX_USERNAME_LEN)
            if name and name not in entry.users and len(entry.users) < MAX_USERNAMES:
                entry.users.append(name)
        elif r.type == "command":
            if commands >= COMMAND_CAP:
                continue
            body = _line(data.get("input"), ctx, col, MAX_TEXT_LEN)
            if body is None:
                continue
            commands += 1
            first_after_login = r.session_id in logged_in and r.session_id not in announced
            announced.add(r.session_id)
            acts.append(
                Activity(
                    ts=r.ts,
                    text=body,
                    action=("login_then_commands" if first_after_login else "command"),
                    **common,
                )
            )
        elif r.type == "download_attempt":
            url = data.get("url")
            if isinstance(url, str) and (addr := _url_host_address(url)) is not None:
                # Only a reportable public address joins the allow-list; the deny set wins.
                if (
                    addr not in col.extra_addresses
                    and origin_of_ip(addr, ctx.terms, include_demo=False) == "real"
                ):
                    col.extra_addresses.add(addr)
                    ctx = _with_address(ctx, addr)
            body = _line(url, ctx, col, MAX_TEXT_LEN)
            if body is not None:
                acts.append(Activity(ts=r.ts, text=body, action="download", **common))
        elif r.type == "http_request" and _is_severe(list(r.tags or []), settings.severe_tags):
            method = data.get("method") if isinstance(data.get("method"), str) else "GET"
            path = str(data.get("path") or "/")
            query = str(data.get("query") or "")
            line = _line(
                f"{method} {path}" + (f"?{query}" if query else ""), ctx, col, MAX_TEXT_LEN
            )
            if line is None:
                continue
            ua = _line(data.get("user_agent"), ctx, col, MAX_UA_LEN)
            acts.append(
                Activity(ts=r.ts, text=line, user_agent=ua, action="exploit_attempt", **common)
            )
    for entry in logins.values():
        acts.append(
            Activity(
                ts=entry.ts,
                action="failed_logins",
                count=entry.count,
                usernames=tuple(entry.users),
                **entry.common,
            )
        )
    acts.sort(key=lambda a: a.ts)
    return acts[:MAX_ACTIVITIES_CSV]


def _with_address(ctx: RedactionContext, addr: str) -> RedactionContext:
    return RedactionContext(
        terms=ctx.terms,
        allowed_addresses=ctx.allowed_addresses | {addr},
        allowed_hosts=ctx.allowed_hosts,
        internal_ids=ctx.internal_ids,
    )


async def payload_activities(
    session: AsyncSession,
    seed: Seed,
    start: datetime,
    end: datetime,
    ctx: RedactionContext,
    col: Collector,
    settings: AbuseSettings,
) -> list[Activity]:
    rows = (
        await session.execute(
            text(
                """
                SELECT x.seen_at AS ts, host(x.src_ip) AS ip, s.src_port, s.dst_port, s.sensor,
                       s.session_id, i.value AS url
                FROM indicators i
                JOIN indicator_sessions x ON x.indicator_id = i.id
                JOIN sessions s ON s.session_id = x.session_id
                WHERE i.role = 'download_host' AND i.host = :host
                  AND x.seen_at >= :start AND x.seen_at <= :end AND NOT s.benign
                ORDER BY x.seen_at LIMIT 200
                """
            ),
            {"host": seed.value, "start": start, "end": end},
        )
    ).all()
    acts: list[Activity] = []
    for r in rows:
        col.session_ids.add(r.session_id)
        body = _line(r.url, ctx, col, MAX_TEXT_LEN)
        if body is None:
            continue
        acts.append(
            Activity(
                ts=r.ts,
                src_ip=r.ip,
                src_port=r.src_port,
                dst_port=settings.ports.public_port(r.sensor, r.dst_port),
                protocol=protocol_of(r.sensor),
                service=settings.ports.service_of(r.sensor, r.dst_port),
                action="download",
                text=body,
            )
        )
    return acts


def window_start(
    seed: Seed,
    now: datetime,
    settings: AbuseSettings,
    prior_end: datetime | None,
    draft_start: datetime | None,
) -> datetime:
    """Evidence starts at the end of the last sent report, or the look-back, whichever is later;
    an open draft keeps its own start so it accumulates."""
    base = now - timedelta(days=settings.lookback_days)
    if draft_start is not None:
        base = min(base, draft_start)
    if prior_end is not None:
        base = max(base, prior_end)
    return base


def _clip(value: object, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


async def sample_refs(session: AsyncSession, seed: Seed) -> tuple[SampleRef, ...]:
    """Hashes of payloads the collector fetched from a payload host (plain web pages excluded),
    or analysed samples that name a C2 address. Metadata only; the files themselves never reach a
    report."""
    if seed.kind == "payload_host":
        sql = f"""
            SELECT DISTINCT s.sha256, s.sha1, s.md5, s.tlsh, s.size, s.kind, s.arch, s.family,
                   s.first_seen
            FROM fetch_targets t
            JOIN sample_sources ss ON ss.target_id = t.id
            JOIN samples s ON s.sha256 = ss.sha256
            WHERE t.host = :v AND t.status = 'fetched' AND NOT {benign_web_sample("s")}
            LIMIT 20
        """  # noqa: S608  (constant fragment only)
    elif seed.kind == "c2":
        sql = """
            SELECT DISTINCT s.sha256, s.sha1, s.md5, s.tlsh, s.size, s.kind, s.arch, s.family,
                   s.first_seen
            FROM sample_links l JOIN samples s ON s.sha256 = l.sha256
            WHERE l.value = :v AND l.kind IN ('c2_ip', 'c2_domain') AND l.confidence = 'high'
            LIMIT 20
        """
    else:
        return ()
    out: list[SampleRef] = []
    for r in (await session.execute(text(sql), {"v": seed.value})).all():
        try:
            out.append(
                SampleRef(
                    sha256=r.sha256, sha1=r.sha1, md5=r.md5, tlsh=_clip(r.tlsh, 72), size=r.size,
                    kind=_clip(r.kind, 32), arch=_clip(r.arch, 32), family=_clip(r.family, 64),
                    first_seen=r.first_seen,
                )
            )  # fmt: skip
        except ValueError:
            continue  # a malformed row is left out, never repaired
    return tuple(out)
