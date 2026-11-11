"""Analytics SQL (SQLAlchemy Core, bound parameters, TimescaleDB ``time_bucket``).

Free-form attacker strings (usernames, commands, URLs...) are truncated in SQL with
``left(..., 256)`` so a hostile payload can never bloat a response. The only literal SQL
fragments (bucket intervals, the truncation length) come from fixed constants, never from input.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from sqlalchemy import (
    ColumnElement,
    Select,
    Text,
    and_,
    case,
    distinct,
    extract,
    func,
    literal_column,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.event_bounds import SLACK
from suckerpot_db.models import EventRow, SessionRow

from api.analytics_schemas import (
    AsnItem,
    Attacker,
    DayCount,
    HeatmapCell,
    SensorBreakdown,
    TimeseriesPoint,
    TopItem,
    ValueCount,
)
from api.benign import visible_events, visible_sessions
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.sensors import SENSORS

MAX_WINDOW = timedelta(days=30)
DEFAULT_WINDOW = timedelta(hours=24)
MAX_POINTS = 500
MAX_VALUE_LEN = 256

# Fixed SQL fragments, keyed by the validated enum value.
BUCKET_SQL = {
    "5m": ("interval '5 minutes'", timedelta(minutes=5)),
    "1h": ("interval '1 hour'", timedelta(hours=1)),
    "1d": ("interval '1 day'", timedelta(days=1)),
}


class WindowError(ValueError):
    """Raised for an invalid time window (mapped to HTTP 422)."""


@dataclass(frozen=True)
class Window:
    since: datetime
    until: datetime


def resolve_window(
    since: datetime | None,
    until: datetime | None,
    *,
    default: timedelta = DEFAULT_WINDOW,
    now: datetime | None = None,
) -> Window:
    """Normalise to UTC, apply defaults and enforce ``0 < until - since <= 30 d``."""
    try:
        end = until.astimezone(UTC) if until is not None else (now or datetime.now(UTC))
        start = since.astimezone(UTC) if since is not None else end - default
        span = end - start
    except (OverflowError, ValueError) as exc:
        raise WindowError("timestamp out of range") from exc
    if span <= timedelta(0):
        raise WindowError("since must be before until")
    if span > MAX_WINDOW:
        raise WindowError("window too large (max 30 days)")
    return Window(start, end)


def floor_to_bucket(ts: datetime, step: timedelta) -> datetime:
    seconds = int(step.total_seconds())
    return datetime.fromtimestamp(int(ts.timestamp()) // seconds * seconds, UTC)


def bucket_starts(window: Window, step: timedelta) -> list[datetime]:
    out: list[datetime] = []
    cur = floor_to_bucket(window.since, step)
    while cur < window.until:
        out.append(cur)
        cur += step
        if len(out) > MAX_POINTS * 100:  # hard stop, callers check MAX_POINTS themselves
            break
    return out


def check_point_count(window: Window, bucket: str) -> None:
    step = BUCKET_SQL[bucket][1]
    n = int((window.until - floor_to_bucket(window.since, step)) / step) + 1
    if n > MAX_POINTS:
        raise WindowError(f"too many points (max {MAX_POINTS}): use a larger bucket")


def _trunc(expr: Any) -> ColumnElement[Any]:
    return func.left(expr, literal_column(str(MAX_VALUE_LEN)))


# --------------------------------------------------------------------------- timeseries


def _bucket_stmt(
    ts_col: Any,
    sensor_col: Any,
    bucket: str,
    window: Window,
    sensor: Sequence[str] | None,
    visible: Sequence[ColumnElement[bool]] = (),
) -> Select[Any]:
    interval, step = BUCKET_SQL[bucket]
    b = func.time_bucket(literal_column(interval), ts_col)
    stmt = (
        select(b.label("b"), sensor_col.label("sensor"), func.count().label("n"))
        .where(ts_col >= floor_to_bucket(window.since, step), ts_col < window.until)
        .group_by(b, sensor_col)
    )
    if sensor is not None:
        stmt = stmt.where(sensor_col.in_(sensor))
    return stmt.where(*visible)


def events_bucket_stmt(
    bucket: str, window: Window, sensor: Sequence[str] | None, include_benign: bool = True
) -> Select[Any]:
    return _bucket_stmt(
        EventRow.ts, EventRow.sensor, bucket, window, sensor, visible_events(include_benign)
    )


def sessions_bucket_stmt(
    bucket: str, window: Window, sensor: Sequence[str] | None, include_benign: bool = True
) -> Select[Any]:
    return _bucket_stmt(
        SessionRow.started_at,
        SessionRow.sensor,
        bucket,
        window,
        sensor,
        visible_sessions(include_benign),
    )


async def timeseries(
    db: AsyncSession,
    bucket: str,
    window: Window,
    sensor: Sequence[str] | None,
    include_benign: bool = True,
) -> list[TimeseriesPoint]:
    starts = bucket_starts(window, BUCKET_SQL[bucket][1])
    ev: dict[datetime, dict[str, int]] = {s: {} for s in starts}
    se: dict[datetime, dict[str, int]] = {s: {} for s in starts}
    for stmt, acc in (
        (events_bucket_stmt(bucket, window, sensor, include_benign), ev),
        (sessions_bucket_stmt(bucket, window, sensor, include_benign), se),
    ):
        for b, name, n in (await db.execute(stmt)).all():
            slot = acc.get(b.astimezone(UTC))
            if slot is not None and name in SENSORS:
                slot[name] = n
    return [
        TimeseriesPoint(ts=s, events=SensorBreakdown(**ev[s]), sessions=SensorBreakdown(**se[s]))
        for s in starts
    ]


# --------------------------------------------------------------------------- top

SESSION_FIELDS = ("country", "asn", "org", "tag", "src_ip")


def _event_value(field: str) -> tuple[ColumnElement[Any], tuple[str, ...]]:
    """Value expression and event types for a field extracted from the JSONB payload."""
    data = EventRow.data
    if field == "username":
        return _trunc(data["username"].astext), ("login_attempt",)
    if field == "password":
        return _trunc(data["password"].astext), ("login_attempt",)
    if field == "command":
        return _trunc(data["input"].astext), ("command",)
    if field == "user_agent":
        return _trunc(data["user_agent"].astext), ("http_request",)
    if field == "url":
        expr = case(
            (EventRow.type == "http_request", data["path"].astext),
            else_=data["url"].astext,
        )
        return _trunc(expr), ("http_request", "download_attempt")
    raise ValueError(field)


def _session_value(field: str) -> Any:
    if field == "country":
        return SessionRow.country
    if field == "asn":
        return SessionRow.asn.cast(Text)
    if field == "org":
        return _trunc(SessionRow.org)
    if field == "src_ip":
        return func.host(SessionRow.src_ip)
    if field == "tag":
        return func.unnest(SessionRow.tags)
    raise ValueError(field)


def top_stmt(
    field: str,
    window: Window,
    sensor: Sequence[str] | None,
    limit: int,
    *,
    src_ip: str | None = None,
    include_benign: bool = True,
) -> Select[Any]:
    """Top values of ``field``.

    Geo, ASN, tag and IP fields count *sessions*; payload fields count *events*.
    Built as an inner (value, ts) subquery plus an outer GROUP BY, so no bound parameter
    appears in both SELECT and GROUP BY.
    """
    if field in SESSION_FIELDS:
        inner = select(
            _session_value(field).label("value"), SessionRow.started_at.label("ts")
        ).where(
            SessionRow.started_at >= window.since,
            SessionRow.started_at < window.until,
            *visible_sessions(include_benign),
        )
        if sensor is not None:
            inner = inner.where(SessionRow.sensor.in_(sensor))
        if src_ip is not None:
            inner = inner.where(SessionRow.src_ip == src_ip)
    else:
        expr, types = _event_value(field)
        inner = select(expr.label("value"), EventRow.ts.label("ts")).where(
            EventRow.ts >= window.since,
            EventRow.ts < window.until,
            EventRow.type.in_(types),
            *visible_events(include_benign),
        )
        if sensor is not None:
            inner = inner.where(EventRow.sensor.in_(sensor))
        if src_ip is not None:
            inner = inner.where(EventRow.src_ip == src_ip)
    sub = inner.subquery("v")
    n = func.count()
    return (
        select(
            sub.c.value,
            n.label("n"),
            func.min(sub.c.ts).label("first_seen"),
            func.max(sub.c.ts).label("last_seen"),
            func.sum(n).over().label("total"),
        )
        .where(sub.c.value.is_not(None))
        .group_by(sub.c.value)
        .order_by(n.desc(), sub.c.value)
        .limit(limit)
    )


async def top(
    db: AsyncSession,
    field: str,
    window: Window,
    sensor: Sequence[str] | None,
    limit: int,
    *,
    src_ip: str | None = None,
    include_benign: bool = True,
) -> tuple[int, list[TopItem]]:
    """Return ``(total, items)``; ``total`` covers all values, not just the page."""
    stmt = top_stmt(field, window, sensor, limit, src_ip=src_ip, include_benign=include_benign)
    rows = (await db.execute(stmt)).all()
    total = int(rows[0].total) if rows else 0
    items = [
        TopItem(
            value=str(r.value),
            count=r.n,
            share=round(r.n / total, 4),
            first_seen=r.first_seen,
            last_seen=r.last_seen,
        )
        for r in rows
    ]
    return total, items


async def top_values(db: AsyncSession, field: str, ip: str, limit: int = 10) -> list[ValueCount]:
    """Most frequent values for one attacker over the last 30 days."""
    now = datetime.now(UTC)
    window = Window(now - MAX_WINDOW, now + timedelta(minutes=1))
    _, items = await top(db, field, window, None, limit, src_ip=ip)
    return [ValueCount(value=i.value, count=i.count) for i in items]


# --------------------------------------------------------------------------- heatmap


def heatmap_stmt(
    window: Window, sensor: Sequence[str] | None, include_benign: bool = True
) -> Select[int, int, int]:
    local = func.timezone(literal_column("'UTC'"), EventRow.ts)
    dow = (extract("isodow", local) - 1).label("dow")
    hour = extract("hour", local).label("hour")
    stmt = (
        select(dow, hour, func.count().label("n"))
        .where(EventRow.ts >= window.since, EventRow.ts < window.until)
        .where(*visible_events(include_benign))
        .group_by(dow, hour)
    )
    if sensor is not None:
        stmt = stmt.where(EventRow.sensor.in_(sensor))
    return stmt


async def heatmap(
    db: AsyncSession, window: Window, sensor: Sequence[str] | None, include_benign: bool = True
) -> list[HeatmapCell]:
    result = await db.execute(heatmap_stmt(window, sensor, include_benign))
    counts = {(int(r.dow), int(r.hour)): r.n for r in result}
    return [
        HeatmapCell(dow=d, hour=h, events=counts.get((d, h), 0))
        for d in range(7)
        for h in range(24)
    ]


# --------------------------------------------------------------------------- attackers

SORTS = ("last_seen", "sessions", "events", "first_seen")


def _sort_keys() -> dict[str, ColumnElement[Any]]:
    s = SessionRow
    return {
        "first_seen": func.min(s.started_at),
        "last_seen": func.max(s.last_event_at),
        "sessions": func.count(),
        "events": func.coalesce(func.sum(s.event_count), 0),
    }


def attackers_stmt(
    *,
    sort: str,
    order: str,
    limit: int,
    country: str | None = None,
    asn: int | None = None,
    sensor: Sequence[str] | None = None,
    tag: str | None = None,
    q: str | None = None,
    after: tuple[datetime | int, str] | None = None,
    ip: str | None = None,
    include_benign: bool = True,
) -> Select[Any]:
    s = SessionRow
    keys = _sort_keys()
    stmt = select(
        s.src_ip.label("ip"),
        keys["first_seen"].label("first_seen"),
        keys["last_seen"].label("last_seen"),
        keys["sessions"].label("sessions"),
        keys["events"].label("events"),
        func.array_agg(distinct(s.sensor)).label("sensors"),
        func.coalesce(func.sum(s.login_attempts), 0).label("login_attempts"),
        func.count().filter(s.login_success).label("login_success"),
        func.coalesce(func.sum(s.commands), 0).label("commands"),
        func.coalesce(func.sum(s.downloads), 0).label("downloads"),
        func.max(s.country).label("country"),
        func.max(s.city).label("city"),
        func.max(s.asn).label("asn"),
        func.max(s.org).label("org"),
        func.max(s.abuse_score).label("abuse_score"),
        func.bool_or(s.known_scanner).label("known_scanner"),
    ).group_by(s.src_ip)
    stmt = stmt.where(*visible_sessions(include_benign))
    if ip is not None:
        stmt = stmt.where(s.src_ip == ip)
    if country is not None:
        stmt = stmt.where(s.country == country.upper())
    if asn is not None:
        stmt = stmt.where(s.asn == asn)
    if q:
        escaped = q.lower().replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        stmt = stmt.where(func.host(s.src_ip).like(escaped + "%", escape="\\"))
    if sensor is not None:
        stmt = stmt.having(func.bool_or(s.sensor.in_(sensor)))
    if tag is not None:
        stmt = stmt.having(func.bool_or(s.tags.contains([tag])))
    key = keys[sort]
    desc = order == "desc"
    if after is not None:
        value, c_ip = after
        if desc:
            cond = or_(key < value, and_(key == value, s.src_ip < c_ip))
        else:
            cond = or_(key > value, and_(key == value, s.src_ip > c_ip))
        stmt = stmt.having(cond)
    if desc:
        stmt = stmt.order_by(key.desc(), s.src_ip.desc())
    else:
        stmt = stmt.order_by(key.asc(), s.src_ip.asc())
    return stmt.limit(limit)


def attacker_cursor(sort: str, order: str, value: datetime | int, ip: str) -> str:
    v: str | int = value.isoformat() if isinstance(value, datetime) else value
    return encode_cursor([sort, order, v, ip])


def parse_attacker_cursor(cursor: str, sort: str, order: str) -> tuple[datetime | int, str]:
    values = decode_cursor(cursor)
    try:
        c_sort, c_order, value, ip = values
        if c_sort != sort or c_order != order or not isinstance(ip, str):
            raise TypeError
        ip = str(ip_address(ip))
        if sort in ("last_seen", "first_seen"):
            if not isinstance(value, str):
                raise TypeError
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                raise TypeError
            return parsed.astimezone(UTC), ip
        if not isinstance(value, int) or not 0 <= value <= 2**62:
            raise TypeError
        return value, ip
    except (ValueError, TypeError, OverflowError) as exc:
        raise InvalidCursorError("malformed cursor") from exc


async def _tags_for(db: AsyncSession, ips: list[str]) -> dict[str, list[str]]:
    if not ips:
        return {}
    inner = select(
        func.host(SessionRow.src_ip).label("ip"), func.unnest(SessionRow.tags).label("tag")
    ).where(SessionRow.src_ip.in_(ips))
    sub = inner.subquery("t")
    stmt = select(sub.c.ip, func.array_agg(distinct(sub.c.tag))).group_by(sub.c.ip)
    return {str(ip): sorted(tags) for ip, tags in (await db.execute(stmt)).all()}


async def _to_attackers(db: AsyncSession, rows: list[Any]) -> list[Attacker]:
    tags = await _tags_for(db, [str(r.ip) for r in rows])
    return [
        Attacker(
            ip=str(r.ip),
            first_seen=r.first_seen,
            last_seen=r.last_seen,
            sessions=r.sessions,
            events=r.events,
            sensors=sorted(r.sensors),
            login_attempts=r.login_attempts,
            login_success=r.login_success,
            commands=r.commands,
            downloads=r.downloads,
            country=r.country,
            city=r.city,
            asn=r.asn,
            org=r.org,
            abuse_score=r.abuse_score,
            known_scanner=r.known_scanner,
            tags=tags.get(str(r.ip), []),
        )
        for r in rows
    ]


async def list_attackers(
    db: AsyncSession,
    *,
    sort: str,
    order: str,
    limit: int,
    cursor: str | None,
    country: str | None,
    asn: int | None,
    sensor: Sequence[str] | None,
    tag: str | None,
    q: str | None,
    include_benign: bool = True,
) -> tuple[list[Attacker], str | None]:
    after = parse_attacker_cursor(cursor, sort, order) if cursor is not None else None
    stmt = attackers_stmt(
        sort=sort,
        order=order,
        limit=limit + 1,
        country=country,
        asn=asn,
        sensor=sensor,
        tag=tag,
        q=q,
        after=after,
        include_benign=include_benign,
    )
    rows = list((await db.execute(stmt)).all())
    page, more = rows[:limit], len(rows) > limit
    items = await _to_attackers(db, page)
    next_cursor = None
    if more:
        last = page[-1]
        next_cursor = attacker_cursor(sort, order, getattr(last, sort), str(last.ip))
    return items, next_cursor


async def get_attacker(db: AsyncSession, ip: str) -> Attacker | None:
    stmt = attackers_stmt(sort="last_seen", order="desc", limit=1, ip=ip)
    rows = list((await db.execute(stmt)).all())
    return (await _to_attackers(db, rows))[0] if rows else None


async def recent_sessions(db: AsyncSession, ip: str, limit: int = 20) -> list[SessionRow]:
    stmt = (
        select(SessionRow)
        .where(SessionRow.src_ip == ip)
        .order_by(SessionRow.started_at.desc(), SessionRow.session_id.desc())
        .limit(limit)
    )
    return list((await db.scalars(stmt)).all())


async def ip_timeline(db: AsyncSession, ip: str, days: int = 30) -> list[DayCount]:
    """Events per UTC day for the last ``days`` days (zero-filled, oldest first)."""
    first = datetime.now(UTC).date() - timedelta(days=days - 1)
    start = datetime(first.year, first.month, first.day, tzinfo=UTC)
    day = func.date(func.timezone(literal_column("'UTC'"), EventRow.ts)).label("day")
    sub = select(day).where(EventRow.src_ip == ip, EventRow.ts >= start).subquery("d")
    stmt = select(sub.c.day, func.count()).group_by(sub.c.day)
    counts: dict[date, int] = {d: n for d, n in (await db.execute(stmt)).all()}
    days_list = [first + timedelta(days=i) for i in range(days)]
    return [DayCount(day=d.isoformat(), events=counts.get(d, 0)) for d in days_list]


# --------------------------------------------------------------------------- asns

ASN_SORTS = ("sessions", "ips", "events")


def asns_stmt(
    sort: str, limit: int, since: datetime | None, include_benign: bool = True
) -> Select[Any]:
    s = SessionRow
    cols: dict[str, ColumnElement[Any]] = {
        "sessions": func.count(),
        "ips": func.count(distinct(s.src_ip)),
        "events": func.coalesce(func.sum(s.event_count), 0),
    }
    stmt = (
        select(
            s.asn.label("asn"),
            func.max(s.org).label("org"),
            func.max(s.country).label("country"),
            cols["ips"].label("ips"),
            cols["sessions"].label("sessions"),
            cols["events"].label("events"),
            func.max(s.last_event_at).label("last_seen"),
        )
        .where(s.asn.is_not(None), *visible_sessions(include_benign))
        .group_by(s.asn)
        .order_by(cols[sort].desc(), s.asn)
        .limit(limit)
    )
    if since is not None:
        stmt = stmt.where(s.started_at >= since)
    return stmt


async def list_asns(
    db: AsyncSession, sort: str, limit: int, since: datetime | None, include_benign: bool = True
) -> list[AsnItem]:
    rows = (await db.execute(asns_stmt(sort, limit, since, include_benign))).all()
    return [
        AsnItem(
            asn=r.asn,
            org=r.org,
            country=r.country,
            ips=r.ips,
            sessions=r.sessions,
            events=r.events,
            last_seen=r.last_seen,
        )
        for r in rows
    ]


# --------------------------------------------------------------------------- session filters

EVENT_VALUE_FIELDS = ("username", "password", "command", "url")


def session_has_value(field: str, value: str) -> ColumnElement[bool]:
    """EXISTS clause: the session has an event whose ``field`` equals ``value``.

    Uses the same (truncated) expression as ``/stats/top``, so a value returned there matches here.
    """
    expr, types = _event_value(field)
    return (
        select(literal_column("1"))
        .where(
            EventRow.session_id == SessionRow.session_id,
            # The session's own time range lets TimescaleDB skip chunks it cannot be in.
            EventRow.ts >= SessionRow.started_at,
            EventRow.ts <= SessionRow.last_event_at + SLACK,
            EventRow.type.in_(types),
            expr == value,
        )
        .exists()
    )
