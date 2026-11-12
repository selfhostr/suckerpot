# ruff: noqa: S608
"""CVE watch endpoints (read-only): recent vulnerabilities ranked by relevance to our services.

The data is public vulnerability information mirrored by ingest (CISA KEV, NVD, GitHub
advisories). ``seen`` counts come from our own sessions: a CVE lists the tags our rules give to
sessions that exploit it, and we count the sessions that carry one of them.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi import Path as PathParam
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.session_counts import sql_sessions_count

from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.session_floods import SQL_LAST_SEEN

router = APIRouter(tags=["cves"])

MAX_LIMIT = 100
DESCRIPTION_IN_LIST = 400
CVE_ID = r"^CVE-[0-9]{4}-[0-9]{4,10}$"
CVE_ID_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,10}")
SAFE_URL_RE = re.compile(r"https?://[\x21-\x7e]+")

Relevance = Literal["high", "medium", "none", "relevant"]
Severity = Literal["critical", "high", "medium", "low", "none"]
Sort = Literal["rank", "published"]

# Published date, falling back to the KEV addition date and then to when we first saw the CVE.
_PUB = "COALESCE(c.published_at, c.kev_added_at::timestamp AT TIME ZONE 'UTC', c.first_seen_at)"
_SEEN = (
    "CASE WHEN cardinality(c.tags) = 0 THEN 0 ELSE "
    f"(SELECT {sql_sessions_count('s')} FROM sessions s WHERE s.tags && c.tags) END"
)
_ITEM_COLS = f"""
    c.cve_id, c.title, left(c.description, {DESCRIPTION_IN_LIST}) AS description, c.vendor,
    c.product, c.published_at, c.modified_at, c.cvss_score::float AS cvss_score,
    c.cvss_severity, c.in_kev, c.kev_added_at, c.kev_due_date, c.kev_ransomware, c.relevance,
    c.matched_services, c.tags, c.sources, c.rank_score, {_PUB} AS pub, {_SEEN} AS seen_sessions
"""


class CveItem(BaseModel):
    cve_id: str
    title: str | None
    description: str | None
    vendor: str | None
    product: str | None
    published_at: datetime | None
    modified_at: datetime | None
    cvss_score: float | None
    cvss_severity: str | None
    in_kev: bool
    kev_added_at: date | None
    kev_due_date: date | None
    kev_ransomware: bool | None
    relevance: str
    matched_services: list[str]
    tags: list[str]
    sources: list[str]
    seen_sessions: int


class CvePage(BaseModel):
    items: list[CveItem]
    next_cursor: str | None
    total: int


class TagTraffic(BaseModel):
    tag: str
    sessions: int


class Traffic(BaseModel):
    sessions: int
    ips: int
    first_seen: datetime | None
    last_seen: datetime | None
    by_tag: list[TagTraffic]


class CveDetail(BaseModel):
    item: CveItem
    description_full: str | None
    cwes: list[str]
    ghsa_ids: list[str]
    refs: list[str]
    cpes: list[str]
    kev_action: str | None
    traffic: Traffic


class SourceState(BaseModel):
    source: str
    last_run_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    items_last_run: int


class CveSync(BaseModel):
    sources: list[SourceState]
    total: int
    relevant: int
    kev: int
    nvd_key_configured: bool
    github_key_configured: bool


def _item(r: Any) -> CveItem:
    return CveItem(
        **{k: getattr(r, k) for k in CveItem.model_fields if k != "seen_sessions"},
        seen_sessions=int(r.seen_sessions),
    )


def _like(needle: str) -> str:
    escaped = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _filters(
    relevance: Relevance | None,
    kev: bool | None,
    severity: Severity | None,
    since: datetime | None,
    q: str | None,
) -> tuple[list[str], dict[str, Any]]:
    where: list[str] = []
    params: dict[str, Any] = {}
    if relevance == "relevant":
        where.append("c.relevance IN ('high', 'medium')")
    elif relevance:
        where.append("c.relevance = :relevance")
        params["relevance"] = relevance
    if kev is not None:
        where.append("c.in_kev = :kev")
        params["kev"] = kev
    if severity == "none":
        where.append("c.cvss_severity IS NULL")
    elif severity:
        where.append("c.cvss_severity = :severity")
        params["severity"] = severity.upper()
    if since is not None:
        where.append(f"{_PUB} >= :since")
        params["since"] = since
    if q:
        where.append(
            "(c.cve_id ILIKE :q OR c.title ILIKE :q OR c.vendor ILIKE :q OR c.product ILIKE :q "
            "OR c.description ILIKE :q)"
        )
        params["q"] = _like(q)
    return where, params


def _parse_cursor(cursor: str, sort: Sort) -> tuple[Any, str]:
    values = decode_cursor(cursor)
    try:
        key, cve_id = values
        if not isinstance(cve_id, str) or not isinstance(key, str | int):
            raise TypeError
        if not CVE_ID_RE.fullmatch(cve_id):
            raise ValueError
        if sort == "rank":
            rank = int(key)
            if not -(2**31) <= rank < 2**31:
                raise ValueError
            return rank, cve_id
        parsed = datetime.fromisoformat(str(key))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed, cve_id
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc


@router.get("/cves", response_model=CvePage)
async def list_cves(
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 25,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    relevance: Relevance | None = None,
    kev: bool | None = None,
    severity: Severity | None = None,
    since: datetime | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    sort: Sort = "rank",
) -> CvePage:
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    where, params = _filters(relevance, kev, severity, since, q)
    count_sql = "SELECT count(*) FROM cve c" + (" WHERE " + " AND ".join(where) if where else "")
    total = int(await db.scalar(text(count_sql), params) or 0)

    page_where = list(where)
    page_params = dict(params)
    if cursor:
        try:
            key, last_id = _parse_cursor(cursor, sort)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=422, detail="Invalid cursor") from exc
        col = "c.rank_score" if sort == "rank" else _PUB
        page_where.append(f"({col}, c.cve_id) < (:ckey, :cid)")
        page_params.update({"ckey": key, "cid": last_id})
    order = "c.rank_score DESC, c.cve_id DESC" if sort == "rank" else "pub DESC, c.cve_id DESC"
    sql = (
        f"SELECT {_ITEM_COLS} FROM cve c"
        + (" WHERE " + " AND ".join(page_where) if page_where else "")
        + f" ORDER BY {order} LIMIT :lim"
    )
    rows = (await db.execute(text(sql), {**page_params, "lim": limit + 1})).all()
    more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if more and rows:
        last = rows[-1]
        key_value = last.rank_score if sort == "rank" else last.pub.isoformat()
        next_cursor = encode_cursor([key_value, last.cve_id])
    return CvePage(items=[_item(r) for r in rows], next_cursor=next_cursor, total=total)


@router.get("/cves/sync", response_model=CveSync)
async def cve_sync(db: DbSession) -> CveSync:
    states = (
        await db.execute(
            text(
                "SELECT source, last_run_at, last_success_at, last_error, items_last_run "
                "FROM cve_sync_state ORDER BY source"
            )
        )
    ).all()
    known = {r.source: r for r in states}
    sources = [
        SourceState(
            source=name,
            last_run_at=getattr(known.get(name), "last_run_at", None),
            last_success_at=getattr(known.get(name), "last_success_at", None),
            last_error=getattr(known.get(name), "last_error", None),
            items_last_run=getattr(known.get(name), "items_last_run", 0),
        )
        for name in ("kev", "nvd", "github")
    ]
    counts = (
        await db.execute(
            text(
                "SELECT count(*) AS total, count(*) FILTER (WHERE relevance <> 'none') AS relevant,"
                " count(*) FILTER (WHERE in_kev) AS kev FROM cve"
            )
        )
    ).one()
    return CveSync(
        sources=sources,
        total=counts.total,
        relevant=counts.relevant,
        kev=counts.kev,
        nvd_key_configured=await _key_configured(db, "nvd"),
        github_key_configured=await _key_configured(db, "github"),
    )


async def _key_configured(db: AsyncSession, provider: str) -> bool:
    row = (
        await db.execute(
            text(
                "SELECT (detail ->> 'configured') = 'true' AS ok FROM enrichment_status "
                "WHERE name = :n"
            ),
            {"n": provider},
        )
    ).first()
    return bool(row and row.ok)


@router.get("/cves/{cve_id}", response_model=CveDetail)
async def cve_detail(
    db: DbSession, cve_id: Annotated[str, PathParam(pattern=CVE_ID, max_length=30)]
) -> CveDetail:
    sql = f"""
        SELECT {_ITEM_COLS}, c.description AS description_full, c.cwes, c.ghsa_ids, c.refs,
               c.cpes, c.kev_action
        FROM cve c WHERE c.cve_id = :id
    """
    row = (await db.execute(text(sql), {"id": cve_id})).first()
    if row is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    traffic = Traffic(sessions=0, ips=0, first_seen=None, last_seen=None, by_tag=[])
    if row.tags:
        agg = (
            await db.execute(
                text(
                    f"SELECT {sql_sessions_count()} AS sessions, count(DISTINCT src_ip) AS ips, "
                    f"min(started_at) AS first_seen, {SQL_LAST_SEEN} AS last_seen "
                    "FROM sessions WHERE tags && CAST(:tags AS text[])"
                ),
                {"tags": row.tags},
            )
        ).one()
        per_tag = (
            await db.execute(
                text(
                    f"SELECT t AS tag, {sql_sessions_count()} AS sessions "
                    "FROM sessions, unnest(tags) AS t "
                    "WHERE t = ANY(CAST(:tags AS text[])) GROUP BY t ORDER BY sessions DESC, t"
                ),
                {"tags": row.tags},
            )
        ).all()
        traffic = Traffic(
            sessions=agg.sessions,
            ips=agg.ips,
            first_seen=agg.first_seen,
            last_seen=agg.last_seen,
            by_tag=[TagTraffic(tag=r.tag, sessions=r.sessions) for r in per_tag],
        )
    return CveDetail(
        item=_item(row),
        description_full=row.description_full,
        cwes=row.cwes,
        ghsa_ids=row.ghsa_ids,
        refs=[r for r in row.refs if SAFE_URL_RE.fullmatch(r)],
        cpes=row.cpes,
        kev_action=row.kev_action,
        traffic=traffic,
    )
