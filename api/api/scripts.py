"""Script library endpoints (M17): the command sequences attackers ran, explained line by line.

Reads ``scripts``, ``script_sessions`` and ``script_explanations`` (written by ingest). The
explanation comes from the annotation base. Read only. Every list is keyset-paginated.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import ARRAY, Text, bindparam, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import SessionRow

from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.schemas import SessionOut

router = APIRouter(tags=["scripts"])

MAX_LIMIT = 200
NEW_DAYS = 7
PREVIEW_LINES = 3
RISKS = ("info", "notice", "warning", "severe")

Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
SensorName = Annotated[str, Query(pattern=r"^[a-z0-9_-]{1,32}$")]
TechniqueId = Annotated[str, Query(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
Sort = Literal["recent", "common", "newest"]
ScriptId = Annotated[int, Path(ge=1, le=2**62)]


class ScriptItem(BaseModel):
    id: int
    fingerprint: str
    summary: str | None
    preview: list[str]
    line_count: int
    first_seen: datetime
    last_seen: datetime
    sessions: int
    sources: int
    sensors: list[str]
    techniques: list[str]
    campaign_id: int | None
    campaign_name: str | None
    risk: Literal["info", "notice", "warning", "severe"] | None
    is_new: bool


class ScriptPage(BaseModel):
    items: list[ScriptItem]
    next_cursor: str | None


class ScriptsSummary(BaseModel):
    total: int
    new_this_week: int
    seen_today: int
    with_campaign: int
    top_id: int | None
    top_summary: str | None
    top_sessions: int | None


class ExplainedLine(BaseModel):
    n: int
    text: str
    raw: str | None
    explanation: str
    risk: Literal["info", "notice", "warning", "severe"] | None
    technique: str | None
    technique_name: str | None
    rule: str | None


class TechniqueRef(BaseModel):
    id: str
    name: str
    tactic: str | None
    url: str | None


class CampaignRef(BaseModel):
    id: int
    name: str
    status: str


class ScriptDetail(BaseModel):
    item: ScriptItem
    lines: list[ExplainedLine]
    unexplained: int
    techniques_detail: list[TechniqueRef]
    campaign: CampaignRef | None
    demo: bool


class SessionsPage(BaseModel):
    items: list[SessionOut]
    next_cursor: str | None


# ---- helpers ---------------------------------------------------------------------------------
def _risk(value: int | None) -> str | None:
    return None if value is None or not 0 <= value < len(RISKS) else RISKS[value]


def _item(r: Any, now: datetime) -> ScriptItem:
    preview = (r.preview or "").splitlines()[:PREVIEW_LINES]
    return ScriptItem(
        id=r.id,
        fingerprint=r.fingerprint,
        summary=r.summary,
        preview=preview,
        line_count=r.line_count,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
        sessions=r.sessions,
        sources=r.sources,
        sensors=list(r.sensors or []),
        techniques=list(r.techniques or []),
        campaign_id=r.campaign_id,
        campaign_name=r.campaign_name,
        risk=_risk(r.risk),  # type: ignore[arg-type]
        is_new=r.first_seen > now - timedelta(days=NEW_DAYS),
    )


_SELECT = """
SELECT s.id, encode(s.fingerprint, 'hex') AS fingerprint, s.line_count, s.first_seen,
       s.last_seen, s.sessions, s.sources, s.sensors, s.techniques, s.campaign_id,
       c.name AS campaign_name, s.demo, left(s.sample_text, 600) AS preview, e.summary,
       (SELECT max(CASE l ->> 'risk' WHEN 'severe' THEN 3 WHEN 'warning' THEN 2
                                     WHEN 'notice' THEN 1 WHEN 'info' THEN 0 END)
          FROM jsonb_array_elements(e.lines) AS l) AS risk
FROM scripts s
LEFT JOIN script_explanations e ON e.script_id = s.id AND e.source = 'annotations'
LEFT JOIN campaigns c ON c.id = s.campaign_id
"""
_SORT_COLUMN = {"recent": "s.last_seen", "common": "s.sessions", "newest": "s.first_seen"}


def _parse_cursor(cursor: str, sort: str) -> tuple[Any, int]:
    values = decode_cursor(cursor)
    try:
        value, script_id = values
        if not isinstance(script_id, int) or not 0 <= script_id < 2**63:
            raise TypeError
        if sort == "common":
            if not isinstance(value, int) or not 0 <= value < 2**63:
                raise TypeError
            return value, script_id
        if not isinstance(value, str):
            raise TypeError
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC), script_id
    except (ValueError, TypeError, OverflowError) as exc:
        raise InvalidCursorError("malformed cursor") from exc


# ---- routes ----------------------------------------------------------------------------------
@router.get("/scripts/summary", response_model=ScriptsSummary)
async def scripts_summary(db: DbSession) -> ScriptsSummary:
    row = (
        await db.execute(
            text(
                """
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE first_seen > now() - make_interval(days => :d))
                           AS new_week,
                       count(*) FILTER (WHERE last_seen > now() - interval '24 hours') AS today,
                       count(*) FILTER (WHERE campaign_id IS NOT NULL) AS campaigns
                FROM scripts
                """
            ),
            {"d": NEW_DAYS},
        )
    ).one()
    top = (
        await db.execute(
            text(
                """
                SELECT s.id, s.sessions, e.summary FROM scripts s
                LEFT JOIN script_explanations e ON e.script_id = s.id AND e.source = 'annotations'
                ORDER BY s.sessions DESC, s.id DESC LIMIT 1
                """
            )
        )
    ).first()
    return ScriptsSummary(
        total=row.total,
        new_this_week=row.new_week,
        seen_today=row.today,
        with_campaign=row.campaigns,
        top_id=top.id if top else None,
        top_summary=top.summary if top else None,
        top_sessions=top.sessions if top else None,
    )


@router.get("/scripts", response_model=ScriptPage)
async def list_scripts(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Limit = 50,
    sort: Sort = "recent",
    sensor: Annotated[list[SensorName] | None, Query(max_length=16)] = None,
    technique: TechniqueId | None = None,
    campaign_id: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
    days: Annotated[int | None, Query(ge=1, le=3650)] = None,
    new: bool = False,
    min_sources: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ScriptPage:
    where: list[str] = []
    params: dict[str, Any] = {"lim": limit + 1}
    if sensor:
        where.append("s.sensors && :sensors")
        params["sensors"] = sensor
    if technique:
        where.append(":tech = ANY(s.techniques)")
        params["tech"] = technique
    if campaign_id is not None:
        where.append("s.campaign_id = :cid")
        params["cid"] = campaign_id
    if q:
        where.append("strpos(lower(s.sample_text), :q) > 0")
        params["q"] = q.lower()
    if days is not None:
        where.append("s.last_seen > now() - make_interval(days => :days)")
        params["days"] = days
    if new:
        where.append("s.first_seen > now() - make_interval(days => :newdays)")
        params["newdays"] = NEW_DAYS
    if min_sources:
        where.append("s.sources >= :minsrc")
        params["minsrc"] = min_sources
    column = _SORT_COLUMN[sort]
    if cursor is not None:
        try:
            value, last_id = _parse_cursor(cursor, sort)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        where.append(f"({column}, s.id) < (:cv, :cid_last)")
        params.update(cv=value, cid_last=last_id)
    sql = _SELECT + (" WHERE " + " AND ".join(where) if where else "")
    sql += f" ORDER BY {column} DESC, s.id DESC LIMIT :lim"
    stmt = text(sql)
    if sensor:
        stmt = stmt.bindparams(bindparam("sensors", type_=ARRAY(Text)))
    rows = (await db.execute(stmt, params)).all()
    page, more = rows[:limit], len(rows) > limit
    now = datetime.now(UTC)
    next_cursor = None
    if more and page:
        last = page[-1]
        key = {"recent": last.last_seen, "newest": last.first_seen, "common": last.sessions}[sort]
        next_cursor = encode_cursor([key if isinstance(key, int) else key.isoformat(), last.id])
    return ScriptPage(items=[_item(r, now) for r in page], next_cursor=next_cursor)


async def _technique_refs(db: AsyncSession, ids: list[str]) -> list[TechniqueRef]:
    if not ids:
        return []
    known = {
        r.id: r
        for r in await db.execute(
            text(
                "SELECT id, name, tactic, url FROM attack_techniques WHERE id = ANY(:ids)"
            ).bindparams(bindparam("ids", type_=ARRAY(Text))),
            {"ids": ids},
        )
    }
    return [
        TechniqueRef(
            id=i,
            name=known[i].name if i in known else i,
            tactic=known[i].tactic if i in known else None,
            url=known[i].url if i in known else None,
        )
        for i in ids
    ]


@router.get("/scripts/{script_id}", response_model=ScriptDetail)
async def get_script(script_id: ScriptId, db: DbSession) -> ScriptDetail:
    return await _detail(db, script_id)


async def _detail(db: AsyncSession, script_id: int) -> ScriptDetail:
    row = (await db.execute(text(_SELECT + " WHERE s.id = :i"), {"i": script_id})).first()
    if row is None:
        raise HTTPException(status_code=404, detail="script not found")
    sample = (
        await db.execute(
            text("SELECT sample_text, demo FROM scripts WHERE id = :i"), {"i": script_id}
        )
    ).one()
    raws = sample.sample_text.splitlines()
    expl = {
        r.source: r
        for r in await db.execute(
            text("SELECT source, lines FROM script_explanations WHERE script_id = :i"),
            {"i": script_id},
        )
    }
    techniques = list(row.techniques or [])
    refs = await _technique_refs(db, techniques)
    names = {t.id: t.name for t in refs}
    lines: list[ExplainedLine] = []
    unexplained = 0
    base = expl.get("annotations")
    for item in base.lines if base is not None else []:
        n = int(item.get("n", len(lines) + 1))
        risk = item.get("risk")
        technique = item.get("technique")
        if risk is None:
            unexplained += 1
        lines.append(
            ExplainedLine(
                n=n,
                text=str(item.get("text", ""))[:600],
                raw=raws[n - 1][:600] if 1 <= n <= len(raws) else None,
                explanation=str(item.get("explanation", ""))[:300],
                risk=risk if risk in RISKS else None,
                technique=technique if isinstance(technique, str) else None,
                technique_name=names.get(technique) if isinstance(technique, str) else None,
                rule=item.get("rule") if isinstance(item.get("rule"), str) else None,
            )
        )
    campaign = None
    if row.campaign_id is not None:
        c = (
            await db.execute(
                text("SELECT id, name, status FROM campaigns WHERE id = :i"), {"i": row.campaign_id}
            )
        ).first()
        if c is not None:
            campaign = CampaignRef(id=c.id, name=c.name, status=c.status)
    return ScriptDetail(
        item=_item(row, datetime.now(UTC)),
        lines=lines,
        unexplained=unexplained,
        techniques_detail=refs,
        campaign=campaign,
        demo=sample.demo,
    )


@router.get("/scripts/{script_id}/sessions", response_model=SessionsPage)
async def script_sessions(
    script_id: ScriptId,
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Limit = 25,
) -> SessionsPage:
    where = ""
    params: dict[str, Any] = {"i": script_id, "lim": limit + 1}
    if cursor is not None:
        try:
            values = decode_cursor(cursor)
            ts, sid = values
            if not isinstance(ts, str) or not isinstance(sid, str):
                raise TypeError
            parsed = datetime.fromisoformat(ts)
            if parsed.tzinfo is None:
                raise ValueError
            params.update(ts=parsed.astimezone(UTC), sid=sid)
        except (InvalidCursorError, ValueError, TypeError, OverflowError) as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        where = "AND (l.seen_at, l.session_id) < (:ts, :sid)"
    rows = (
        await db.execute(
            text(
                f"""
                SELECT l.seen_at, l.session_id FROM script_sessions l
                WHERE l.script_id = :i {where}
                ORDER BY l.seen_at DESC, l.session_id DESC LIMIT :lim
                """  # noqa: S608 - fixed fragment
            ),
            params,
        )
    ).all()
    page, more = rows[:limit], len(rows) > limit
    ids = [r.session_id for r in page]
    found = {
        s.session_id: s
        for s in await db.scalars(select(SessionRow).where(SessionRow.session_id.in_(ids)))
    }
    items = [SessionOut.model_validate(found[i], from_attributes=True) for i in ids if i in found]
    next_cursor = (
        encode_cursor([page[-1].seen_at.isoformat(), page[-1].session_id]) if more else None
    )
    return SessionsPage(items=items, next_cursor=next_cursor)
