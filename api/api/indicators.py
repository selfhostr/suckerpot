"""Indicators and infrastructure endpoints (read-only, passive).

Indicators are URLs, hosts and file hashes that ingest extracted from recorded events, with the
threat-intelligence answers ingest cached for them. Nothing here contacts an indicator or an intel
API: the API has no internet access and only reads tables.

* ``GET /indicators``                keyset-paginated list with filters
* ``GET /indicators/export``         owner-triggered CSV or STIX 2.1 download (bounded)
* ``GET /indicators/{id}``           one indicator with intel answers, sessions and source IPs
* ``GET /infrastructure/graph``      bounded graph: source IPs, indicators and malware families

Every value is returned both raw and defanged. The web UI shows only the defanged form and never
renders an indicator as a link.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

router = APIRouter(tags=["indicators"])
audit = logging.getLogger("api.audit")

MAX_LIMIT = 200
MAX_EXPORT = 5000
MAX_GRAPH_NODES = 300
GRAPH_INDICATORS = 60
GRAPH_FAMILIES = 40
GRAPH_SOURCES = MAX_GRAPH_NODES - GRAPH_INDICATORS - GRAPH_FAMILIES
GRAPH_EDGE_ROWS = 20_000
DETAIL_SESSIONS = 50
DETAIL_SOURCES = 50
DETAIL_RELATED = 20
MAX_WINDOW_HOURS = 24 * 90

IndicatorType = Literal["url", "domain", "ip", "hash"]
IndicatorRole = Literal["download_host", "contacted_host", "hash"]
ExportFormat = Literal["csv", "stix"]

Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
# Links shown to the owner must point at the intel providers only.
_LINK_PREFIXES = (
    "https://urlhaus.abuse.ch/",
    "https://threatfox.abuse.ch/",
    "https://www.virustotal.com/",
)
_NOT_CHECKED = "not-checked"
_STIX_NS = uuid.UUID("5f2b4c1e-8f0a-4d51-9f0e-7a63a0c9d001")


class IntelOut(BaseModel):
    source: Literal["urlhaus", "threatfox", "virustotal"]
    known: bool
    family: str | None
    threat_type: str | None
    tags: list[str]
    first_seen_ext: datetime | None
    reference: str | None
    checked_at: datetime


class IndicatorOut(BaseModel):
    id: int
    type: IndicatorType
    value: str
    defanged: str
    role: IndicatorRole
    host: str | None
    first_seen: datetime
    last_seen: datetime
    sightings: int
    sensors: list[str]
    sessions: int
    ips: int
    checked: bool  # at least one intel provider answered
    known: bool | None  # None until checked
    family: str | None
    sources: list[str]  # providers that answered


class IndicatorPage(BaseModel):
    items: list[IndicatorOut]
    next_cursor: str | None


class SessionLink(BaseModel):
    session_id: str
    sensor: str
    src_ip: str
    seen_at: datetime
    country: str | None
    tags: list[str]


class SourceIp(BaseModel):
    ip: str
    sessions: int
    first_seen: datetime
    last_seen: datetime
    country: str | None
    asn: int | None
    org: str | None


class RelatedIndicator(BaseModel):
    id: int
    type: IndicatorType
    defanged: str
    role: IndicatorRole
    sessions: int


class IndicatorDetail(BaseModel):
    indicator: IndicatorOut
    intel: list[IntelOut]
    not_checked: bool  # reserved or private value: never sent to an intel API
    sessions: list[SessionLink]
    source_ips: list[SourceIp]
    related: list[RelatedIndicator]
    links_truncated: bool


class GraphNode(BaseModel):
    id: str
    kind: Literal["source", "indicator", "family"]
    label: str
    weight: int
    type: IndicatorType | None = None
    role: IndicatorRole | None = None
    known: bool | None = None
    country: str | None = None
    indicator_id: int | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    weight: int


class GraphSummary(BaseModel):
    sources: int  # distinct source IPs linked to an indicator in the window
    indicators: int
    families: int
    shared_hosts: int  # download hosts used by at least two source IPs
    sources_on_shared_hosts: int
    top_host: str | None  # defanged
    top_host_sources: int


class InfrastructureGraph(BaseModel):
    window_hours: int
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    summary: GraphSummary
    truncated: bool


def defang(kind: str, value: str) -> str:
    """Make a value unclickable and unresolvable: ``hxxp://files[.]badhost[.]ru/a.sh``."""
    if kind == "hash":
        return value
    out = value
    if kind == "url":
        scheme, sep, rest = value.partition("://")
        if not sep:
            return value.replace(".", "[.]")
        scheme = scheme.replace("http", "hxxp").replace("ftp", "fxp").replace("ldap", "ldxp")
        cut = len(rest)
        for ch in "/?#":
            i = rest.find(ch)
            if 0 <= i < cut:
                cut = i
        authority = rest[:cut]
        if authority.startswith("["):  # an IPv6 host: defang its colons, keep the port's
            end = authority.find("]") + 1 or len(authority)
            authority = authority[:end].replace(":", "[:]") + authority[end:]
        return f"{scheme}://{authority.replace('.', '[.]')}{rest[cut:]}"
    return out.replace(".", "[.]").replace(":", "[:]")


def safe_reference(url: str | None) -> str | None:
    return url if url is not None and url.startswith(_LINK_PREFIXES) else None


_FROM = """
FROM indicators i
LEFT JOIN LATERAL (
    SELECT bool_or(x.known) AS known,
           (array_agg(x.family ORDER BY x.known DESC, x.source)
                FILTER (WHERE x.family IS NOT NULL))[1] AS family,
           array_agg(x.source ORDER BY x.source) AS sources
    FROM indicator_intel x
    WHERE x.indicator_id = i.id AND NOT ('not-checked' = ANY (x.tags))
) k ON true
LEFT JOIN LATERAL (
    SELECT count(*) AS sessions, count(DISTINCT s.src_ip) AS ips
    FROM indicator_sessions s WHERE s.indicator_id = i.id
) l ON true
"""
_COLUMNS = """
i.id, i.type, i.value, i.role, i.host, i.first_seen, i.last_seen, i.sightings, i.sensors,
k.known, k.family, k.sources, l.sessions, l.ips
"""


def _filters(
    type_: str | None,
    role: str | None,
    known: bool | None,
    family: str | None,
    since: datetime | None,
    q: str | None,
) -> tuple[list[str], dict[str, Any]]:
    where: list[str] = []
    params: dict[str, Any] = {}
    if type_:
        where.append("i.type = :type")
        params["type"] = type_
    if role:
        where.append("i.role = :role")
        params["role"] = role
    if known is True:
        where.append("k.known IS TRUE")
    elif known is False:
        where.append("COALESCE(k.known, false) = false")
    if family:
        where.append(
            "EXISTS (SELECT 1 FROM indicator_intel f WHERE f.indicator_id = i.id "
            "AND lower(f.family) = :family)"
        )
        params["family"] = family.lower()
    if since is not None:
        where.append("i.last_seen >= :since")
        params["since"] = since
    if q:
        where.append("strpos(i.value, :q) > 0")
        params["q"] = q.lower()
    return where, params


def _indicator(r: Any) -> IndicatorOut:
    sources = list(r.sources or [])
    return IndicatorOut(
        id=r.id,
        type=r.type,
        value=r.value,
        defanged=defang(r.type, r.value),
        role=r.role,
        host=r.host,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
        sightings=r.sightings,
        sensors=list(r.sensors or []),
        sessions=r.sessions or 0,
        ips=r.ips or 0,
        checked=bool(sources),
        known=bool(r.known) if sources else None,
        family=r.family,
        sources=sources,
    )


def _parse_cursor(cursor: str) -> tuple[datetime, int]:
    values = decode_cursor(cursor)
    try:
        ts, iid = values
        if not isinstance(ts, str) or not isinstance(iid, int) or not 0 <= iid < 2**63:
            raise TypeError
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC), iid
    except (ValueError, TypeError, OverflowError) as exc:
        raise InvalidCursorError("malformed cursor") from exc


TypeFilter = Annotated[IndicatorType | None, Query()]
RoleFilter = Annotated[IndicatorRole | None, Query()]
FamilyFilter = Annotated[str | None, Query(max_length=64, pattern=r"^[A-Za-z0-9 ._:+/()#@,-]+$")]
SearchFilter = Annotated[str | None, Query(max_length=128)]
HoursFilter = Annotated[int | None, Query(ge=1, le=MAX_WINDOW_HOURS)]


def _window(since: datetime | None, hours: int | None) -> datetime | None:
    """The later of ``since`` and "``hours`` ago" (the graph's window), or None for all time."""
    if hours is None:
        return since
    start = datetime.now(UTC) - timedelta(hours=hours)
    return max(start, since) if since is not None else start


@router.get("/indicators", response_model=IndicatorPage)
async def list_indicators(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Limit = 50,
    type: TypeFilter = None,
    role: RoleFilter = None,
    known: bool | None = None,
    family: FamilyFilter = None,
    since: datetime | None = None,
    hours: HoursFilter = None,
    q: SearchFilter = None,
) -> IndicatorPage:
    where, params = _filters(type, role, known, family, _window(since, hours), q)
    if cursor is not None:
        try:
            c_ts, c_id = _parse_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        where.append("(i.last_seen, i.id) < (:c_ts, :c_id)")
        params.update(c_ts=c_ts, c_id=c_id)
    sql = (
        f"SELECT {_COLUMNS} {_FROM} "
        + (f"WHERE {' AND '.join(where)} " if where else "")
        + "ORDER BY i.last_seen DESC, i.id DESC LIMIT :lim"
    )
    rows = (await db.execute(text(sql), {**params, "lim": limit + 1})).all()
    page, more = rows[:limit], len(rows) > limit
    next_cursor = encode_cursor([page[-1].last_seen.isoformat(), page[-1].id]) if more else None
    return IndicatorPage(items=[_indicator(r) for r in page], next_cursor=next_cursor)


def _csv_cell(value: Any) -> str:
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def render_csv(items: list[IndicatorOut]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(
        ["type", "value", "defanged", "role", "first_seen", "last_seen", "sightings", "sensors",
         "known", "family", "intel_sources"]
    )  # fmt: skip
    for i in items:
        w.writerow(
            [
                _csv_cell(v)
                for v in (
                    i.type, i.value, i.defanged, i.role, i.first_seen.isoformat(),
                    i.last_seen.isoformat(), i.sightings, " ".join(i.sensors),
                    "" if i.known is None else str(i.known).lower(), i.family or "",
                    " ".join(i.sources),
                )
            ]
        )  # fmt: skip
    return out.getvalue()


def _stix_pattern(item: IndicatorOut) -> str:
    esc = item.value.replace("\\", "\\\\").replace("'", "\\'")
    if item.type == "url":
        return f"[url:value = '{esc}']"
    if item.type == "domain":
        return f"[domain-name:value = '{esc}']"
    if item.type == "ip":
        return f"[{'ipv6-addr' if ':' in item.value else 'ipv4-addr'}:value = '{esc}']"
    algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(item.value), "SHA-256")
    return f"[file:hashes.'{algo}' = '{esc}']"


def _stamp(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def render_stix(items: list[IndicatorOut], now: datetime) -> dict[str, Any]:
    """A STIX 2.1 bundle with one ``indicator`` object per row (deterministic ids)."""
    objects: list[dict[str, Any]] = []
    for i in items:
        obj: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(_STIX_NS, f'{i.type}:{i.value}')}",
            "created": _stamp(i.first_seen),
            "modified": _stamp(i.last_seen),
            "name": i.defanged[:200],
            "description": (
                f"Seen {i.sightings} time(s) by a honeypot ({i.role.replace('_', ' ')}). "
                "Observed passively; nobody contacted this indicator."
            ),
            "indicator_types": ["malicious-activity" if i.known else "anomalous-activity"],
            "pattern": _stix_pattern(i),
            "pattern_type": "stix",
            "valid_from": _stamp(i.first_seen),
        }
        if i.family:
            obj["labels"] = [i.family[:64]]
        objects.append(obj)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


@router.get("/indicators/export")
async def export_indicators(
    db: DbSession,
    format: ExportFormat = "csv",
    type: TypeFilter = None,
    role: RoleFilter = None,
    known: bool | None = None,
    family: FamilyFilter = None,
    since: datetime | None = None,
    hours: HoursFilter = None,
    q: SearchFilter = None,
) -> Response:
    where, params = _filters(type, role, known, family, _window(since, hours), q)
    sql = (
        f"SELECT {_COLUMNS} {_FROM} "
        + (f"WHERE {' AND '.join(where)} " if where else "")
        + "ORDER BY i.last_seen DESC, i.id DESC LIMIT :lim"
    )
    rows = (await db.execute(text(sql), {**params, "lim": MAX_EXPORT})).all()
    items = [_indicator(r) for r in rows]
    now = datetime.now(UTC)
    audit.info("indicator export format=%s rows=%d", format, len(items))
    stamp = now.strftime("%Y%m%d")
    if format == "stix":
        body = json.dumps(render_stix(items, now), separators=(",", ":"))
        media, name = "application/stix+json;version=2.1", f"indicators-{stamp}.json"
    else:
        body, media, name = render_csv(items), "text/csv; charset=utf-8", f"indicators-{stamp}.csv"
    return Response(
        body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/indicators/{indicator_id}", response_model=IndicatorDetail)
async def get_indicator(
    indicator_id: Annotated[int, Path(ge=1, le=2**62)], db: DbSession
) -> IndicatorDetail:
    return await _detail(db, indicator_id)


async def _detail(db: AsyncSession, indicator_id: int) -> IndicatorDetail:
    row = (
        await db.execute(text(f"SELECT {_COLUMNS} {_FROM} WHERE i.id = :id"), {"id": indicator_id})
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    intel_rows = (
        await db.execute(
            text(
                "SELECT source, known, family, threat_type, tags, first_seen_ext, reference, "
                "checked_at FROM indicator_intel WHERE indicator_id = :id ORDER BY source"
            ),
            {"id": indicator_id},
        )
    ).all()
    real = [r for r in intel_rows if _NOT_CHECKED not in (r.tags or [])]
    intel = [
        IntelOut(
            source=r.source,
            known=r.known,
            family=r.family,
            threat_type=r.threat_type,
            tags=list(r.tags or []),
            first_seen_ext=r.first_seen_ext,
            reference=safe_reference(r.reference),
            checked_at=r.checked_at,
        )
        for r in real
    ]
    sessions = (
        await db.execute(
            text(
                """
                SELECT l.session_id, l.sensor, host(l.src_ip) AS src_ip, l.seen_at,
                       s.country, s.tags
                FROM indicator_sessions l LEFT JOIN sessions s ON s.session_id = l.session_id
                WHERE l.indicator_id = :id
                ORDER BY l.seen_at DESC, l.session_id LIMIT :n
                """
            ),
            {"id": indicator_id, "n": DETAIL_SESSIONS},
        )
    ).all()
    # session-rows-ok: counts indicator_sessions links, and a flood group never has one
    sources = (
        await db.execute(
            text(
                """
                SELECT host(l.src_ip) AS ip, count(*) AS sessions, min(l.seen_at) AS first_seen,
                       max(l.seen_at) AS last_seen,
                       (SELECT max(s.country) FROM sessions s WHERE s.src_ip = l.src_ip) AS country,
                       (SELECT max(s.asn) FROM sessions s WHERE s.src_ip = l.src_ip) AS asn,
                       (SELECT max(s.org) FROM sessions s WHERE s.src_ip = l.src_ip) AS org
                FROM indicator_sessions l WHERE l.indicator_id = :id
                GROUP BY l.src_ip ORDER BY max(l.seen_at) DESC, l.src_ip LIMIT :n
                """
            ),
            {"id": indicator_id, "n": DETAIL_SOURCES},
        )
    ).all()
    related = (
        await db.execute(
            text(
                """
                SELECT o.id, o.type, o.value, o.role, count(*) AS sessions
                FROM indicator_sessions a
                JOIN indicator_sessions b
                  ON b.session_id = a.session_id AND b.indicator_id <> a.indicator_id
                JOIN indicators o ON o.id = b.indicator_id
                WHERE a.indicator_id = :id
                GROUP BY o.id ORDER BY count(*) DESC, o.id LIMIT :n
                """
            ),
            {"id": indicator_id, "n": DETAIL_RELATED},
        )
    ).all()
    out = _indicator(row)
    return IndicatorDetail(
        indicator=out,
        intel=intel,
        not_checked=len(real) < len(intel_rows) and not real,
        sessions=[
            SessionLink(
                session_id=r.session_id,
                sensor=r.sensor,
                src_ip=r.src_ip,
                seen_at=r.seen_at,
                country=r.country,
                tags=list(r.tags or []),
            )
            for r in sessions
        ],
        source_ips=[
            SourceIp(
                ip=r.ip,
                sessions=r.sessions,
                first_seen=r.first_seen,
                last_seen=r.last_seen,
                country=r.country,
                asn=r.asn,
                org=r.org,
            )
            for r in sources
        ],
        related=[
            RelatedIndicator(
                id=r.id,
                type=r.type,
                defanged=defang(r.type, r.value),
                role=r.role,
                sessions=r.sessions,
            )
            for r in related
        ],
        links_truncated=out.sessions > len(sessions),
    )


@router.get("/infrastructure/graph", response_model=InfrastructureGraph)
async def infrastructure_graph(
    db: DbSession,
    hours: Annotated[int, Query(ge=1, le=MAX_WINDOW_HOURS)] = 168,
    role: RoleFilter = None,
) -> InfrastructureGraph:
    """Source IPs, indicators (hosts and hashes) and malware families for a time window.

    At most 300 nodes: 60 indicators (most distinct source IPs first), 40 families and the
    busiest source IPs for the rest. ``truncated`` says when something was left out.
    """
    since = datetime.now(UTC) - timedelta(hours=hours)
    role_sql = "AND i.role = :role" if role else ""
    params: dict[str, Any] = {"since": since, "role": role}
    top = (
        await db.execute(
            text(
                f"""
                SELECT i.id, i.type, i.value, i.role, count(DISTINCT s.src_ip) AS ips,
                       count(*) AS sessions, k.known, k.family
                FROM indicator_sessions s
                JOIN indicators i ON i.id = s.indicator_id
                LEFT JOIN LATERAL (
                    SELECT bool_or(x.known) AS known,
                           (array_agg(x.family ORDER BY x.known DESC, x.source)
                                FILTER (WHERE x.family IS NOT NULL))[1] AS family
                    FROM indicator_intel x
                    WHERE x.indicator_id = i.id AND NOT ('not-checked' = ANY (x.tags))
                ) k ON true
                WHERE s.seen_at >= :since AND i.type <> 'url' {role_sql}
                GROUP BY i.id, k.known, k.family
                ORDER BY ips DESC, sessions DESC, i.id
                LIMIT :n
                """  # noqa: S608 - fixed fragment, values are bound
            ),
            {**params, "n": GRAPH_INDICATORS + 1},
        )
    ).all()
    truncated = len(top) > GRAPH_INDICATORS
    top = top[:GRAPH_INDICATORS]
    ids = [r.id for r in top]
    edge_rows = (
        (
            await db.execute(
                text(
                    """
                    SELECT indicator_id, host(src_ip) AS ip, count(*) AS sessions
                    FROM indicator_sessions
                    WHERE indicator_id = ANY (:ids) AND seen_at >= :since
                    GROUP BY indicator_id, src_ip LIMIT :lim
                    """
                ),
                {"ids": ids, "since": since, "lim": GRAPH_EDGE_ROWS},
            )
        ).all()
        if ids
        else []
    )
    # Keep the source IPs that link the most selected indicators, then the most sessions.
    degree: dict[str, tuple[int, int]] = {}
    for e in edge_rows:
        d, s = degree.get(e.ip, (0, 0))
        degree[e.ip] = (d + 1, s + e.sessions)
    ranked = sorted(degree, key=lambda ip: (-degree[ip][0], -degree[ip][1], ip))
    keep = set(ranked[:GRAPH_SOURCES])
    truncated = truncated or len(ranked) > len(keep)
    geo = {}
    if keep:
        geo = {
            r.ip: r.country
            for r in (
                await db.execute(
                    text(
                        "SELECT host(src_ip) AS ip, max(country) AS country FROM sessions "
                        "WHERE src_ip = ANY (CAST(:ips AS inet[])) GROUP BY src_ip"
                    ),
                    {"ips": sorted(keep)},
                )
            ).all()
        }

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    families: dict[str, int] = {}
    for r in top:
        nodes.append(
            GraphNode(
                id=f"i:{r.id}",
                kind="indicator",
                label=defang(r.type, r.value),
                weight=r.ips,
                type=r.type,
                role=r.role,
                known=bool(r.known) if r.known is not None else None,
                indicator_id=r.id,
            )
        )
        if r.family:
            families[r.family] = families.get(r.family, 0) + r.ips
    fam_keep = sorted(families, key=lambda f: (-families[f], f))[:GRAPH_FAMILIES]
    truncated = truncated or len(families) > len(fam_keep)
    for f in fam_keep:
        nodes.append(GraphNode(id=f"f:{f.lower()}", kind="family", label=f, weight=families[f]))
    for r in top:
        if r.family in fam_keep:
            edges.append(
                GraphEdge(source=f"i:{r.id}", target=f"f:{r.family.lower()}", weight=r.ips)
            )
    for ip in sorted(keep, key=lambda x: (-degree[x][0], -degree[x][1], x)):
        nodes.append(
            GraphNode(
                id=f"s:{ip}", kind="source", label=ip, weight=degree[ip][1], country=geo.get(ip)
            )
        )
    for e in edge_rows:
        if e.ip in keep:
            edges.append(
                GraphEdge(source=f"s:{e.ip}", target=f"i:{e.indicator_id}", weight=e.sessions)
            )
    return InfrastructureGraph(
        window_hours=hours,
        nodes=nodes,
        edges=edges,
        summary=await _summary(db, since),
        truncated=truncated,
    )


async def _summary(db: AsyncSession, since: datetime) -> GraphSummary:
    totals = (
        await db.execute(
            text(
                """
                SELECT count(DISTINCT s.src_ip) AS sources, count(DISTINCT s.indicator_id) AS n,
                       (SELECT count(DISTINCT lower(x.family)) FROM indicator_intel x
                        WHERE x.family IS NOT NULL AND x.indicator_id IN (
                            SELECT indicator_id FROM indicator_sessions WHERE seen_at >= :since
                        )) AS families
                FROM indicator_sessions s JOIN indicators i ON i.id = s.indicator_id
                WHERE s.seen_at >= :since AND i.type <> 'url'
                """
            ),
            {"since": since},
        )
    ).one()
    shared = (
        await db.execute(
            text(
                """
                WITH h AS (
                    SELECT s.indicator_id, i.type, i.value, count(DISTINCT s.src_ip) AS ips
                    FROM indicator_sessions s JOIN indicators i ON i.id = s.indicator_id
                    WHERE s.seen_at >= :since AND i.role = 'download_host'
                      AND i.type IN ('domain', 'ip')
                    GROUP BY s.indicator_id, i.type, i.value HAVING count(DISTINCT s.src_ip) >= 2
                )
                SELECT (SELECT count(*) FROM h) AS hosts,
                       (SELECT count(DISTINCT src_ip) FROM indicator_sessions
                        WHERE seen_at >= :since
                          AND indicator_id IN (SELECT indicator_id FROM h)) AS sources,
                       (SELECT type FROM h ORDER BY ips DESC, indicator_id LIMIT 1) AS top_type,
                       (SELECT value FROM h ORDER BY ips DESC, indicator_id LIMIT 1) AS top_value,
                       (SELECT ips FROM h ORDER BY ips DESC, indicator_id LIMIT 1) AS top_ips
                """
            ),
            {"since": since},
        )
    ).one()
    return GraphSummary(
        sources=totals.sources or 0,
        indicators=totals.n or 0,
        families=totals.families or 0,
        shared_hosts=shared.hosts or 0,
        sources_on_shared_hosts=shared.sources or 0,
        top_host=defang(shared.top_type, shared.top_value) if shared.top_value else None,
        top_host_sources=shared.top_ips or 0,
    )
