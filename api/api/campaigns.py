"""Campaign endpoints (M15): the grouped, story-level view of attacks.

A campaign is a group of sessions that share a script, a payload host, a file hash, a malware
family, an exploit or a credential list (ingest clusters them). Everything here is read-only and
bounded: lists are keyset-paged, the story shows at most 12 lines of one representative session,
and the timeline covers at most 30 days.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, select, tuple_
from suckerpot_db.event_bounds import session_events_select
from suckerpot_db.models import (
    AttackTechniqueRow,
    CampaignKeyRow,
    CampaignRow,
    CampaignSessionRow,
    EventRow,
    SessionRow,
)

from api.attack import STAGE_LABELS, STAGE_RANK, plain_phrase
from api.cursor import (
    InvalidCursorError,
    decode_cursor,
    encode_cursor,
    parse_session_cursor,
    session_cursor,
)
from api.deps import DbSession
from api.routes import _session_out
from api.schemas import SessionPage
from api.sensors import SensorFilter

router = APIRouter(tags=["campaigns"])

MAX_LIMIT = 200
MAX_DAYS = 365
MAX_TIMELINE_DAYS = 30
EXCERPT_LINES = 12
INDICATOR_LIMIT = 100
#: A key counts as evidence only when this many distinct sources showed it (ingest's rule).
MIN_SOURCES = max(2, int(os.environ.get("CAMPAIGN_MIN_SOURCES", "2") or 2))
LINE_CHARS = 200

CampaignId = Annotated[int, Path(ge=1, le=2**62)]
Status = Literal["active", "quiet", "merged"]
Severity = Literal["info", "notice", "warning", "severe"]
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
Cursor = Annotated[str | None, Query(max_length=512)]
TechniqueFilter = Annotated[str, Query(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
_ESCAPE = re.compile(r"[\x00-\x1f\x7f]")


class CampaignOut(BaseModel):
    id: int
    name: str
    status: Status
    merged_into: int | None
    first_seen: datetime
    last_seen: datetime
    sessions: int
    sources: int
    countries: list[str]
    asns: list[int]
    sensors: list[str]
    techniques: list[str]
    stages: list[str]
    tags: list[str]
    families: list[str]
    severity: Severity
    rep_session_id: str | None
    demo: bool


class CampaignPage(BaseModel):
    items: list[CampaignOut]
    next_cursor: str | None


class StoryTechnique(BaseModel):
    id: str
    name: str
    url: str
    plain: str


class StoryStage(BaseModel):
    stage: str
    label: str
    summary: str
    techniques: list[StoryTechnique]


class ExcerptLine(BaseModel):
    kind: Literal["login", "command", "request", "download"]
    text: str


class Excerpt(BaseModel):
    session_id: str
    sensor: str
    lines: list[ExcerptLine]


class StoryCounts(BaseModel):
    sessions: int
    sources: int
    countries: int
    networks: int
    sensors: int
    days_active: int


class CampaignStory(BaseModel):
    campaign_id: int
    headline: str
    stages: list[StoryStage]
    excerpt: Excerpt | None
    counts: StoryCounts
    what_to_do: list[str]


class TimelinePoint(BaseModel):
    ts: datetime
    sessions: int


class Timeline(BaseModel):
    since: datetime
    until: datetime
    bucket_seconds: int
    linked: int  # sessions the points are made of (links are bounded, counters are not)
    points: list[TimelinePoint]


class IndicatorOut(BaseModel):
    kind: Literal["script", "payload_host", "hash", "family", "exploit", "credlist"]
    value: str
    defanged: str
    sources: int
    #: "low" when fewer sources than the clustering rule needs: do not block on this alone.
    confidence: Literal["normal", "low"]
    first_seen: datetime
    last_seen: datetime


class IndicatorList(BaseModel):
    items: list[IndicatorOut]


def _defang(kind: str, value: str) -> str:
    if kind != "payload_host":
        return value
    return value.replace(".", "[.]")


def _out(row: CampaignRow) -> CampaignOut:
    return CampaignOut(
        id=row.id,
        name=row.name,
        status=row.status,  # type: ignore[arg-type]
        merged_into=row.merged_into,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        sessions=row.sessions,
        sources=row.sources,
        countries=list(row.countries),
        asns=list(row.asns),
        sensors=list(row.sensors),
        techniques=list(row.techniques),
        stages=list(row.stages),
        tags=list(row.tags),
        families=list(row.families),
        severity=row.severity,  # type: ignore[arg-type]
        rep_session_id=row.rep_session_id,
        demo=row.demo,
    )


def _cursor(last_seen: datetime, campaign_id: int) -> str:
    return encode_cursor([last_seen.isoformat(), campaign_id])


def _parse_cursor(cursor: str) -> tuple[datetime, int]:
    values = decode_cursor(cursor)
    try:
        ts, cid = values
        if not isinstance(ts, str) or not isinstance(cid, int):
            raise TypeError
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC), cid
    except (ValueError, TypeError, OverflowError) as exc:
        raise InvalidCursorError("malformed cursor") from exc


async def _get(db: DbSession, campaign_id: int) -> CampaignRow:
    row = await db.get(CampaignRow, campaign_id)
    if row is None:
        raise HTTPException(status_code=404, detail="campaign not found")
    return row


@router.get("/campaigns", response_model=CampaignPage)
async def list_campaigns(
    db: DbSession,
    limit: Limit = 50,
    cursor: Cursor = None,
    status: Status | None = None,
    sensor: SensorFilter = None,
    technique: TechniqueFilter | None = None,
    family: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    hours: Annotated[int | None, Query(ge=1, le=MAX_DAYS * 24)] = None,
    days: Annotated[int | None, Query(ge=1, le=MAX_DAYS)] = None,
    q: Annotated[str | None, Query(max_length=64)] = None,
    include_benign: bool = False,  # accepted for symmetry: research scanners are never clustered
) -> CampaignPage:
    """Campaigns, most recently active first. Merged ones are listed only on request."""
    stmt = select(CampaignRow)
    stmt = stmt.where(CampaignRow.status == status if status else CampaignRow.status != "merged")
    if sensor is not None:
        stmt = stmt.where(CampaignRow.sensors.overlap(sensor))
    if technique is not None:
        stmt = stmt.where(CampaignRow.techniques.contains([technique]))
    if family is not None:
        stmt = stmt.where(CampaignRow.families.contains([family.lower()]))
    window = timedelta(hours=hours) if hours else timedelta(days=days) if days else None
    if window is not None:
        stmt = stmt.where(CampaignRow.last_seen >= datetime.now(UTC) - window)
    if q:
        stmt = stmt.where(func.strpos(func.lower(CampaignRow.name), q.lower()) > 0)
    if cursor is not None:
        try:
            c_ts, c_id = _parse_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(tuple_(CampaignRow.last_seen, CampaignRow.id) < (c_ts, c_id))
    stmt = stmt.order_by(CampaignRow.last_seen.desc(), CampaignRow.id.desc()).limit(limit + 1)
    rows = list((await db.scalars(stmt)).all())
    page, more = rows[:limit], len(rows) > limit
    return CampaignPage(
        items=[_out(r) for r in page],
        next_cursor=_cursor(page[-1].last_seen, page[-1].id) if more else None,
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut)
async def get_campaign(db: DbSession, campaign_id: CampaignId) -> CampaignOut:
    return _out(await _get(db, campaign_id))


def _join(phrases: list[str]) -> str:
    if len(phrases) <= 1:
        return "".join(phrases)
    shown = phrases[:3]
    rest = len(phrases) - len(shown)
    if rest:
        return ", ".join(shown) + f" and {rest} more"
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def _sequence(items: list[str]) -> str:
    """ "a, b, then c": commas, and one final "then"."""
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + ", then " + items[-1] if len(items) > 2 else " then ".join(items)


def _line(text: Any) -> str:
    return _ESCAPE.sub(" ", str(text))[:LINE_CHARS]


def _excerpt_line(ev: EventRow) -> ExcerptLine | None:
    data = ev.data or {}
    if ev.type == "command" and data.get("input"):
        return ExcerptLine(kind="command", text=_line(data["input"]))
    if ev.type == "http_request":
        target = f"{data.get('method', '')} {data.get('path', '')}".strip()
        return ExcerptLine(kind="request", text=_line(target)) if target else None
    if ev.type == "download_attempt" and data.get("url"):
        return ExcerptLine(kind="download", text=_line(data["url"]))
    if ev.type == "login_attempt" and data.get("username") is not None:
        return ExcerptLine(kind="login", text=_line(f"login as {data['username']}"))
    return None


async def _excerpt(db: DbSession, sid: str | None) -> Excerpt | None:
    if not sid:
        return None
    session_row = await db.get(SessionRow, sid)
    if session_row is None:
        return None
    events = (
        await db.scalars(
            session_events_select(session_row)
            .where(EventRow.type != "connect")
            .order_by(EventRow.ts, EventRow.id)
            .limit(EXCERPT_LINES * 4)
        )
    ).all()
    if not events:
        return None
    lines: list[ExcerptLine] = []
    for ev in events:
        line = _excerpt_line(ev)
        if line is None:
            continue
        # Fold a run of login attempts into the first one: the commands are the story.
        if line.kind == "login" and lines and lines[-1].kind == "login":
            continue
        lines.append(line)
        if len(lines) >= EXCERPT_LINES:
            break
    return Excerpt(session_id=sid, sensor=events[0].sensor, lines=lines) if lines else None


def _what_to_do(row: CampaignRow, hosts: list[str]) -> list[str]:
    techniques, tags = set(row.techniques), set(row.tags)
    out: list[str] = []
    if hosts:
        out.append(
            f"Block {_join(hosts[:2])} at your proxy or firewall, "
            "and look for past connections to it."
        )
    if techniques & {"T1110", "T1110.001", "T1110.003", "T1110.004", "T1078"}:
        out.append("Turn off password logins on anything exposed, use keys or MFA, and rate-limit.")
    if techniques & {"T1190", "T1210", "T1505.003"} or tags & {"php2shell", "sql-rce"}:
        out.append("Patch public-facing services and check they are not exposed by mistake.")
    if techniques & {"T1496"} or "crypto-miner" in tags:
        out.append("Alert on sudden CPU use and on connections to mining pools.")
    if techniques & {"T1105"}:
        out.append("Stop servers from downloading and running files from the internet.")
    if techniques & {"T1053.003", "T1098.004", "T1136.001"}:
        out.append("Check cron jobs, authorized SSH keys and local accounts on exposed machines.")
    if not out:
        out.append("Nothing to block yet: keep watching and check your exposure page.")
    return out[:4]


@router.get("/campaigns/{campaign_id}/story", response_model=CampaignStory)
async def campaign_story(db: DbSession, campaign_id: CampaignId) -> CampaignStory:
    """The campaign told as stages in plain English, with a few lines from one real session."""
    row = await _get(db, campaign_id)
    catalogue = {
        t.id: t
        for t in (
            await db.scalars(
                select(AttackTechniqueRow).where(AttackTechniqueRow.id.in_(list(row.techniques)))
            )
        ).all()
    }
    by_stage: dict[str, list[StoryTechnique]] = {}
    for tid in row.techniques:
        t = catalogue.get(tid)
        if t is None:
            continue
        by_stage.setdefault(t.stage, []).append(
            StoryTechnique(id=t.id, name=t.name, url=t.url, plain=plain_phrase(t.id, t.name))
        )
    stages = []
    for stage in sorted(by_stage, key=lambda s: STAGE_RANK.get(s, 99)):
        # A parent technique adds nothing next to its own sub-technique.
        present = {x.id for x in by_stage[stage]}
        items = sorted(
            (x for x in by_stage[stage] if not any(o.startswith(x.id + ".") for o in present)),
            key=lambda x: x.id,
        )
        summary = "They " + _join([x.plain for x in items]) + "."
        stages.append(
            StoryStage(
                stage=stage,
                label=STAGE_LABELS.get(stage, stage),
                summary=summary,
                techniques=items,
            )
        )
    host_rows = (
        await db.scalars(
            select(CampaignKeyRow.value)
            .where(
                CampaignKeyRow.campaign_id == campaign_id,
                CampaignKeyRow.kind == "payload_host",
                CampaignKeyRow.sources >= MIN_SOURCES,
            )
            .order_by(CampaignKeyRow.sources.desc(), CampaignKeyRow.last_seen.desc())
            .limit(3)
        )
    ).all()
    hosts = [_defang("payload_host", h) for h in host_rows]
    labels = _sequence([s.label.lower() for s in stages])
    headline = (
        f"{row.sessions:,} sessions from {row.sources:,} "
        f"{'address' if row.sources == 1 else 'addresses'} followed the same playbook"
        + (f": {labels}." if labels else ".")
    )
    span = max(1, (row.last_seen.date() - row.first_seen.date()).days + 1)
    return CampaignStory(
        campaign_id=campaign_id,
        headline=headline,
        stages=stages,
        excerpt=await _excerpt(db, row.rep_session_id),
        counts=StoryCounts(
            sessions=row.sessions,
            sources=row.sources,
            countries=len(row.countries),
            networks=len(row.asns),
            sensors=len(row.sensors),
            days_active=span,
        ),
        what_to_do=_what_to_do(row, hosts),
    )


@router.get("/campaigns/{campaign_id}/timeline", response_model=Timeline)
async def campaign_timeline(
    db: DbSession,
    campaign_id: CampaignId,
    days: Annotated[int, Query(ge=1, le=MAX_TIMELINE_DAYS)] = 7,
) -> Timeline:
    """Sessions per hour from the campaign's links, for the last ``days`` days (at most 30)."""
    await _get(db, campaign_id)
    until = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    since = until - timedelta(days=days)
    hour = func.date_trunc("hour", CampaignSessionRow.seen_at).label("hour")
    rows = (
        await db.execute(
            select(hour, func.count().label("n"))
            .where(
                CampaignSessionRow.campaign_id == campaign_id,
                CampaignSessionRow.seen_at >= since,
                CampaignSessionRow.seen_at < until,
            )
            .group_by(hour)
            .order_by(hour)
        )
    ).all()
    return Timeline(
        since=since,
        until=until,
        bucket_seconds=3600,
        linked=sum(int(r.n) for r in rows),
        points=[TimelinePoint(ts=r.hour, sessions=int(r.n)) for r in rows],
    )


@router.get("/campaigns/{campaign_id}/sessions", response_model=SessionPage)
async def campaign_sessions(
    db: DbSession, campaign_id: CampaignId, limit: Limit = 50, cursor: Cursor = None
) -> SessionPage:
    await _get(db, campaign_id)
    # Sessions not yet re-pointed after a merge still carry the id of the absorbed campaign.
    absorbed = select(CampaignRow.id).where(CampaignRow.merged_into == campaign_id)
    stmt = select(SessionRow).where(
        or_(SessionRow.campaign_id == campaign_id, SessionRow.campaign_id.in_(absorbed))
    )
    if cursor is not None:
        try:
            c_ts, c_id = parse_session_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(tuple_(SessionRow.started_at, SessionRow.session_id) < (c_ts, c_id))
    stmt = stmt.order_by(SessionRow.started_at.desc(), SessionRow.session_id.desc()).limit(
        limit + 1
    )
    rows = list((await db.scalars(stmt)).all())
    page, more = rows[:limit], len(rows) > limit
    return SessionPage(
        items=[_session_out(r) for r in page],
        next_cursor=session_cursor(page[-1].started_at, page[-1].session_id) if more else None,
    )


@router.get("/campaigns/{campaign_id}/indicators", response_model=IndicatorList)
async def campaign_indicators(db: DbSession, campaign_id: CampaignId) -> IndicatorList:
    """The keys that tie the campaign together: payload hosts, hashes, families, fingerprints."""
    await _get(db, campaign_id)
    rows = (
        await db.scalars(
            select(CampaignKeyRow)
            .where(CampaignKeyRow.campaign_id == campaign_id)
            .order_by(
                CampaignKeyRow.kind,
                CampaignKeyRow.sources.desc(),
                CampaignKeyRow.last_seen.desc(),
                CampaignKeyRow.value,
            )
            .limit(INDICATOR_LIMIT)
        )
    ).all()
    return IndicatorList(
        items=[
            IndicatorOut(
                kind=r.kind,  # type: ignore[arg-type]
                value=r.value,
                defanged=_defang(r.kind, r.value),
                sources=r.sources,
                confidence="normal" if r.sources >= MIN_SOURCES else "low",
                first_seen=r.first_seen,
                last_seen=r.last_seen,
            )
            for r in rows
        ]
    )
