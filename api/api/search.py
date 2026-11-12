"""Global search for the header box and the Ctrl/Cmd+K palette (M19).

``GET /api/v1/search?q=`` looks for one thing across five groups: IP addresses, file hashes,
domains and URLs, CVE ids and campaigns. It is built from indexed lookups only:

* IPs: an exact match, or a dotted prefix such as ``203.0.113.`` turned into an address range,
  both on ``ix_sessions_src_ip_sensor_started_at`` (its first column is the address). The hit
  count is the number of connections: a flood group of one hour counts its ``connections``. The
  range scan reads at most ``IP_SCAN_ROWS`` index entries in address order, so on a very wide
  prefix (a /8) the hits come from the lowest addresses of the range, then are ordered by
  recency among those.
* Hashes and domains/URLs: a left-anchored ``LIKE`` on ``ix_indicators_value_prefix``.
* CVEs: the primary key, for a complete id (``CVE-2026-109618``).
* Campaigns: a left-anchored ``LIKE`` on ``ix_campaigns_name_prefix``, or the numeric id.

The input is capped at ``MAX_QUERY`` characters, every group returns at most ``GROUP_LIMIT``
hits, and only the groups a query can plausibly match are queried. The statement timeout is
short, so one slow lookup never ties up the pool. Indicators are returned defanged, like
everywhere else in the API. Results include research-scanner sessions on purpose: a search for a
known address must find it.
"""

from __future__ import annotations

import re
import time
from collections import deque
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import ColumnElement, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import CampaignRow, CveRow, IndicatorRow, SessionRow
from suckerpot_db.session_counts import sessions_count

from api.deps import DbSession
from api.indicators import defang

router = APIRouter(tags=["search"])

MAX_QUERY = 128
RATE_PER_SECOND = 10  # searches per signed-in session (or client address) per second
RATE_TRACKED = 10_000  # callers remembered at once
MIN_QUERY = 2
GROUP_LIMIT = 5
IP_SCAN_ROWS = 2000
STATEMENT_TIMEOUT_MS = 3000

SearchKind = Literal["ip", "hash", "domain", "cve", "campaign"]

_HEX = re.compile(r"^[0-9a-f]{8,128}$")
_CVE = re.compile(r"^cve-\d{4}-\d{4,7}$")
_IPV4_PREFIX = re.compile(r"^\d{1,3}(\.\d{1,3}){0,2}\.$|^\d{1,3}(\.\d{1,3}){1,2}\.\d{3}$")
_HOSTLIKE = re.compile(r"^[a-z0-9][a-z0-9._:/?=&%~#@+,-]*$")


class SearchHit(BaseModel):
    kind: SearchKind
    #: What the web UI links with: the address, the CVE id, or the indicator or campaign id.
    value: str
    #: The headline. Indicators are defanged.
    label: str
    detail: str | None = None
    count: int | None = None
    last_seen: datetime | None = None
    benign: bool = False


class SearchGroup(BaseModel):
    kind: SearchKind
    hits: list[SearchHit]
    #: More than ``GROUP_LIMIT`` matches exist.
    more: bool = False


class SearchResponse(BaseModel):
    q: str
    groups: list[SearchGroup]


def normalise(raw: str) -> str:
    """Trim, drop control characters and undo defanging so pasted indicators still match."""
    cleaned = "".join(ch for ch in raw if ch.isprintable()).strip()[:MAX_QUERY]
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if cleaned.lower().startswith(("hxxp://", "hxxps://")):
        cleaned = "http" + cleaned[4:]
    return cleaned


def like_prefix(value: str) -> str:
    """A LIKE pattern matching values that start with ``value`` (wildcards escaped)."""
    return value.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%"


def ip_bounds(q: str) -> tuple[IPv4Address | IPv6Address, IPv4Address | IPv6Address] | None:
    """The address range an IP query stands for, or None when it is not one.

    A complete address is a range of one. ``203.0.113.`` (or ``203.0.113`` with a full last
    octet) is the whole /24, ``203.0.`` the /16, ``203.`` the /8. A partial last octet such as
    ``203.0.11`` is ambiguous and returns None.
    """
    try:
        addr = ip_address(q)
    except ValueError:
        addr = None
    if addr is not None:
        return addr, addr
    if not _IPV4_PREFIX.match(q):
        return None
    parts = [int(p) for p in q.rstrip(".").split(".")]
    if len(parts) > 3 or any(p > 255 for p in parts):
        return None
    pad = 4 - len(parts)
    low = IPv4Address(bytes(parts + [0] * pad))
    high = IPv4Address(bytes(parts + [255] * pad))
    return low, high


def plan(q: str) -> list[SearchKind]:
    """Which groups a (normalised) query can match, most specific first."""
    low = q.lower()
    kinds: list[SearchKind] = []
    if ip_bounds(q) is not None:
        kinds.append("ip")
    if _CVE.match(low):
        kinds.append("cve")
    if _HEX.match(low):
        kinds.append("hash")
    if (
        ("." in low or "/" in low or low.startswith("http"))
        and _HOSTLIKE.match(low)
        and ip_bounds(q) is None
    ):
        kinds.append("domain")
    if "." not in low and "/" not in low and "hash" not in kinds:
        kinds.append("campaign")
    return kinds


async def _ips(db: AsyncSession, q: str) -> SearchGroup:
    bounds = ip_bounds(q)
    if bounds is None:
        return SearchGroup(kind="ip", hits=[])
    low, high = bounds
    s = SessionRow
    if low == high:
        stmt = (
            select(
                s.src_ip.label("ip"),
                sessions_count().label("n"),
                func.max(s.last_event_at).label("last_seen"),
                func.max(s.country).label("country"),
                func.max(s.org).label("org"),
                func.bool_and(s.benign).label("benign"),
            )
            .where(s.src_ip == str(low))
            .group_by(s.src_ip)
        )
    else:
        inner = (
            select(s.src_ip, s.last_event_at, s.country, s.org, s.benign, s.connections)
            .where(s.src_ip >= str(low), s.src_ip <= str(high))
            .order_by(s.src_ip)
            .limit(IP_SCAN_ROWS)
            .subquery("scan")
        )
        stmt = (
            select(
                inner.c.src_ip.label("ip"),
                sessions_count(connections=inner.c.connections).label("n"),
                func.max(inner.c.last_event_at).label("last_seen"),
                func.max(inner.c.country).label("country"),
                func.max(inner.c.org).label("org"),
                func.bool_and(inner.c.benign).label("benign"),
            )
            .group_by(inner.c.src_ip)
            .order_by(func.max(inner.c.last_event_at).desc())
            .limit(GROUP_LIMIT + 1)
        )
    rows = (await db.execute(stmt)).all()
    hits = [
        SearchHit(
            kind="ip",
            value=str(r.ip),
            label=str(r.ip),
            detail=" · ".join(x for x in (r.country, r.org) if x) or None,
            count=r.n,
            last_seen=r.last_seen,
            benign=bool(r.benign),
        )
        for r in rows[:GROUP_LIMIT]
    ]
    return SearchGroup(kind="ip", hits=hits, more=len(rows) > GROUP_LIMIT)


async def _indicators(db: AsyncSession, q: str, kind: SearchKind) -> SearchGroup:
    i = IndicatorRow
    low = q.lower()
    if kind == "hash":
        types: tuple[str, ...] = ("hash",)
    elif low.startswith("http") or "/" in low:
        types = ("url",)
    else:
        types = ("domain", "ip")
    stmt = (
        select(i.id, i.type, i.value, i.sightings, i.last_seen, i.role)
        .where(i.value.like(like_prefix(low), escape="\\"), i.type.in_(types))
        .order_by(i.last_seen.desc())
        .limit(GROUP_LIMIT + 1)
    )
    rows = (await db.execute(stmt)).all()
    role_words = {
        "download_host": "Serves downloads",
        "contacted_host": "Contacted by a payload",
        "hash": "File hash",
    }
    hits = [
        SearchHit(
            kind=kind,
            value=str(r.id),
            label=defang(r.type, r.value)[:160],
            detail=role_words.get(r.role),
            count=r.sightings,
            last_seen=r.last_seen,
        )
        for r in rows[:GROUP_LIMIT]
    ]
    return SearchGroup(kind=kind, hits=hits, more=len(rows) > GROUP_LIMIT)


async def _cves(db: AsyncSession, q: str) -> SearchGroup:
    c = CveRow
    stmt = select(c.cve_id, c.title, c.cvss_score, c.in_kev, c.published_at).where(
        c.cve_id == q.upper()
    )
    rows = (await db.execute(stmt)).all()
    hits = [
        SearchHit(
            kind="cve",
            value=r.cve_id,
            label=r.cve_id,
            detail=r.title[:140] if r.title else None,
            last_seen=r.published_at,
        )
        for r in rows[:GROUP_LIMIT]
    ]
    return SearchGroup(kind="cve", hits=hits)


async def _campaigns(db: AsyncSession, q: str) -> SearchGroup:
    c = CampaignRow
    cond: ColumnElement[bool] = func.lower(c.name).like(like_prefix(q.lower()), escape="\\")
    if q.isdigit() and len(q) <= 12:
        cond = cond | (c.id == int(q))
    stmt = (
        select(c.id, c.name, c.sessions, c.sources, c.last_seen, c.status)
        .where(cond, c.status != "merged")
        .order_by(c.last_seen.desc(), c.id.desc())
        .limit(GROUP_LIMIT + 1)
    )
    rows = (await db.execute(stmt)).all()
    hits = [
        SearchHit(
            kind="campaign",
            value=str(r.id),
            label=r.name[:160],
            detail=f"{r.sources:,} sources, {r.status}",
            count=r.sessions,
            last_seen=r.last_seen,
        )
        for r in rows[:GROUP_LIMIT]
    ]
    return SearchGroup(kind="campaign", hits=hits, more=len(rows) > GROUP_LIMIT)


def _check_rate(request: Request) -> None:
    """At most ``RATE_PER_SECOND`` searches a second per session: 429 beyond that."""
    token = request.app.state.auth.session_token(request.scope)
    key = token or (request.client.host if request.client else "")
    table: dict[str, deque[float]] | None = getattr(request.app.state, "search_hits", None)
    if table is None:
        table = {}
        request.app.state.search_hits = table
    now = time.monotonic()
    if key not in table and len(table) >= RATE_TRACKED:
        for k in [k for k, v in table.items() if not v or now - v[-1] > 1.0]:
            del table[k]
    hits = table.setdefault(key, deque())
    while hits and now - hits[0] > 1.0:
        hits.popleft()
    if len(hits) >= RATE_PER_SECOND:
        raise HTTPException(
            status_code=429, detail="Too many searches", headers={"Retry-After": "1"}
        )
    hits.append(now)


@router.get("/search", response_model=SearchResponse)
async def search(
    request: Request, db: DbSession, q: Annotated[str, Query(min_length=1, max_length=512)]
) -> SearchResponse:
    """Find an IP, hash, domain, CVE or campaign. Up to five hits per group, indexed lookups."""
    _check_rate(request)
    term = normalise(q)
    if len(term) < MIN_QUERY:
        return SearchResponse(q=term, groups=[])
    await db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))
    groups: list[SearchGroup] = []
    for kind in plan(term):
        if kind == "ip":
            group = await _ips(db, term)
        elif kind == "cve":
            group = await _cves(db, term)
        elif kind == "campaign":
            group = await _campaigns(db, term)
        else:
            group = await _indicators(db, term, kind)
        if group.hits:
            groups.append(group)
    return SearchResponse(q=term, groups=groups)


__all__ = ["ip_bounds", "like_prefix", "normalise", "plan", "router", "search"]
