"""Trends endpoints: values never seen before and tag volumes over time (read-only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import AwareDatetime, BaseModel
from sqlalchemy import Select, Text, func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import EventRow, SessionRow
from suckerpot_db.session_counts import sessions_count

from api import analytics_queries as q
from api.analytics_queries import Window, WindowError
from api.analytics_schemas import BucketName
from api.benign import IncludeBenign, visible_events, visible_sessions
from api.deps import DbSession

router = APIRouter()

NewField = Literal["username", "password", "command", "url", "asn", "user_agent"]
LOOKBACK = timedelta(days=90)
TOP_TAGS = 8


class NewValueItem(BaseModel):
    value: str
    count: int
    first_seen: datetime


class NewValues(BaseModel):
    field: NewField
    items: list[NewValueItem]


class TagPoint(BaseModel):
    ts: datetime
    tags: dict[str, int]


class TagSeries(BaseModel):
    bucket: BucketName
    since: datetime
    until: datetime
    series: list[str]
    points: list[TagPoint]


# --------------------------------------------------------------------------- new values


async def new_values(
    db: AsyncSession,
    field: str,
    since: datetime,
    until: datetime,
    limit: int,
    *,
    min_count: int = 1,
    include_benign: bool = True,
) -> list[NewValueItem]:
    """Values seen in ``[since, until)`` and never in the 90 days before ``since``."""
    lookback_start = since - LOOKBACK
    if field == "asn":
        value = SessionRow.asn.cast(Text)
        sess_ok = visible_sessions(include_benign)
        cur_inner = select(
            value.label("value"),
            SessionRow.started_at.label("ts"),
            SessionRow.connections.label("w"),
        ).where(SessionRow.started_at >= since, SessionRow.started_at < until, *sess_ok)
        prev_inner = select(value.label("value")).where(
            SessionRow.started_at >= lookback_start, SessionRow.started_at < since, *sess_ok
        )
    else:
        expr, types = q._event_value(field)
        ev_ok = visible_events(include_benign)
        cur_inner = select(
            expr.label("value"), EventRow.ts.label("ts"), literal_column("1").label("w")
        ).where(EventRow.ts >= since, EventRow.ts < until, EventRow.type.in_(types), *ev_ok)
        prev_inner = select(expr.label("value")).where(
            EventRow.ts >= lookback_start, EventRow.ts < since, EventRow.type.in_(types), *ev_ok
        )
    cur = cur_inner.subquery("cur")
    prev = prev_inner.subquery("prev")
    # The number of sessions or events: a flood group weighs its connections.
    n = sessions_count(connections=cur.c.w)
    stmt = (
        select(cur.c.value, n.label("n"), func.min(cur.c.ts).label("first_seen"))
        .where(
            cur.c.value.is_not(None),
            cur.c.value != literal_column("''"),
            ~cur.c.value.in_(select(prev.c.value).where(prev.c.value.is_not(None))),
        )
        .group_by(cur.c.value)
        .having(n >= min_count)
        .order_by(n.desc(), cur.c.value)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [NewValueItem(value=str(r.value), count=r.n, first_seen=r.first_seen) for r in rows]


@router.get("/trends/new", response_model=NewValues)
async def trends_new(
    db: DbSession,
    field: NewField,
    days: Annotated[int, Query(ge=1, le=30)] = 7,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    include_benign: IncludeBenign = False,
) -> NewValues:
    until = datetime.now(UTC) + timedelta(minutes=1)
    since = until - timedelta(days=days)
    items = await new_values(db, field, since, until, limit, include_benign=include_benign)
    return NewValues(field=field, items=items)


# --------------------------------------------------------------------------- tags over time


def _tag_stmt(bucket: str, window: Window, include_benign: bool = True) -> Select[Any]:
    interval, step = q.BUCKET_SQL[bucket]
    sub = (
        select(
            func.time_bucket(literal_column(interval), SessionRow.started_at).label("b"),
            func.unnest(SessionRow.tags).label("tag"),
            SessionRow.connections.label("w"),
        )
        .where(
            SessionRow.started_at >= q.floor_to_bucket(window.since, step),
            SessionRow.started_at < window.until,
            *visible_sessions(include_benign),
        )
        .subquery("t")
    )
    n = sessions_count(connections=sub.c.w)
    return select(sub.c.b, sub.c.tag, n.label("n")).group_by(sub.c.b, sub.c.tag)


@router.get("/trends/tags", response_model=TagSeries)
async def trends_tags(
    db: DbSession,
    bucket: BucketName = "1d",
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    include_benign: IncludeBenign = False,
) -> TagSeries:
    try:
        window = q.resolve_window(since, until, default=timedelta(days=7))
        q.check_point_count(window, bucket)
    except WindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    step = q.BUCKET_SQL[bucket][1]
    starts = q.bucket_starts(window, step)
    cells: dict[datetime, dict[str, int]] = {s: {} for s in starts}
    totals: dict[str, int] = {}
    for b, tag, n in (await db.execute(_tag_stmt(bucket, window, include_benign))).all():
        slot = cells.get(b.astimezone(UTC))
        if slot is None:
            continue
        slot[tag] = slot.get(tag, 0) + n
        totals[tag] = totals.get(tag, 0) + n
    top = [t for t, _ in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_TAGS]]
    has_other = len(totals) > len(top)
    series = [*top, "other"] if has_other else top
    points = []
    for s in starts:
        counts = cells[s]
        row = {t: counts.get(t, 0) for t in top}
        if has_other:
            row["other"] = sum(v for t, v in counts.items() if t not in top)
        points.append(TagPoint(ts=s, tags=row))
    return TagSeries(
        bucket=bucket, since=window.since, until=window.until, series=series, points=points
    )
