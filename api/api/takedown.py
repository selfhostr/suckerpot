"""Takedown tracking (M27, ``docs/design/m27.md`` sections 5, 6 and 11): what happened to the
targets that were reported, how fast, and which providers act.

Read-only for both roles, except the two admin actions on one target: ask for an early re-check
(it only moves a due date; the collector and ingest do the work) and stop tracking. The API never
contacts a target. Statistics are counted by ``suckerpot_db.takedown_stats`` (right-censored: a
target not yet observed for the whole window is left out of the rate), then merged with the
monthly roll-up for months whose targets were already pruned.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.takedown_stats import (
    TAKEDOWN_ROLES,
    Fact,
    counted,
    curve,
    median_ttd,
    percent,
    still_up_after_tracking,
    ttd_seconds,
    window_counts,
)

from api import audit as audit_db
from api.abuse_core import error, include_demo
from api.auth import Principal, current_principal
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

TargetId = Annotated[int, Path(ge=1, le=2**62)]  # a bigger number is not a bigint

router = APIRouter(tags=["takedown"])

MAX_FACTS = 200_000
RECHECK_MIN_GAP = timedelta(hours=1)
TIMELINE_MAX = 200
CHILDREN_MAX = 100
ROLE_OF_KIND = {"url": "payload_url", "host": "payload_host"}
State = Literal["up", "down", "changed", "unknown"]
Role = Literal["attack_source", "payload_host", "payload_url", "c2"]
Kind = Literal["url", "ip", "domain"]
Channel = Literal["mail", "urlhaus", "threatfox"]
_LIKE = re.compile(r"([%_\\])")


# ---- shapes ----------------------------------------------------------------------------------


class Section(BaseModel):
    tracked: int = 0
    eligible_48h: int = 0
    down_48h: int = 0
    eligible_7d: int = 0
    down_7d: int = 0
    eligible_30d: int = 0
    down_30d: int = 0
    ttd_p50_s: int | None = None
    ttd_n: int = 0
    still_up_30d: int = 0


class AttackSources(BaseModel):
    tracked: int = 0
    quiet: int = 0
    active: int = 0


class C2Section(BaseModel):
    tracked: int = 0
    still_used: int = 0


class ReportTotals(BaseModel):
    sent: int = 0
    answered: int | None = None  # None while the reply tracking (M26) is not available
    first_reply_p50_s: int | None = None


class Summary(BaseModel):
    since: datetime
    until: datetime
    urls: Section
    hosts: Section
    attack_sources: AttackSources
    c2: C2Section
    reports: ReportTotals


class CurvePoint(BaseModel):
    hours: int
    eligible: int
    down: int
    percent: float | None = None


class CurveSeries(BaseModel):
    kind: Literal["url", "host"]
    points: list[CurvePoint]


class Curve(BaseModel):
    since: datetime
    until: datetime
    series: list[CurveSeries]


class ProviderOut(BaseModel):
    provider_key: str
    name: str | None = None
    asn: int | None = None
    country: str | None = None
    targets: int = 0
    eligible_48h: int = 0
    down_48h: int = 0
    percent_48h: float | None = None
    eligible_30d: int = 0
    down_30d: int = 0
    percent_30d: float | None = None
    ttd_p50_s: int | None = None
    ttd_n: int = 0
    still_up: int = 0
    reports_sent: int = 0
    reports_answered: int | None = None
    percent_answered: float | None = None
    first_reply_p50_s: int | None = None


class Providers(BaseModel):
    items: list[ProviderOut]


class TargetOut(BaseModel):
    id: int
    kind: str
    role: str
    value: str
    parent_id: int | None = None
    provider_key: str
    provider_name: str | None = None
    asn: int | None = None
    country: str | None = None
    reported_at: datetime
    channels: list[str]
    state: str
    state_source: str | None = None
    state_since: datetime | None = None
    tracking: bool
    track_until: datetime
    http_eligible: bool
    demo: bool
    down_before_report: bool
    last_up_at: datetime | None = None
    first_down_at: datetime | None = None
    ttd_s: int | None = None
    resurrections: int = 0
    last_check_at: datetime | None = None


class TargetPage(BaseModel):
    items: list[TargetOut]
    next_cursor: str | None = None


class CheckOut(BaseModel):
    id: int
    checked_at: datetime
    method: str
    outcome: str
    http_status: int | None = None
    sha256: str | None = None
    bytes: int | None = None
    duration_ms: int | None = None
    detail: dict[str, Any] = {}


class Bounds(BaseModel):
    seconds: int | None = None  # upper bound: first confirmed down minus the report time
    down_after: datetime | None = None  # the last time it was seen up
    down_before: datetime | None = None  # the first confirmed down


class Links(BaseModel):
    reports: list[str] = []  # report public ids


class TargetDetail(BaseModel):
    target: TargetOut
    children: list[TargetOut]
    links: Links
    checks: list[CheckOut]
    ttd: Bounds
    baseline_sha256: str | None = None
    last_sha256: str | None = None


class Rechecked(BaseModel):
    id: int
    http: bool
    listing: bool


class Stopped(BaseModel):
    id: int
    tracking: bool = False


# ---- helpers ---------------------------------------------------------------------------------


def _actor(principal: Principal | None) -> str:
    return principal.username if principal else "anonymous"


def _client_ip(request: Request) -> str | None:
    return request.app.state.auth.client_ip(request)  # type: ignore[no-any-return]


def _window(since: datetime | None, until: datetime | None) -> tuple[datetime, datetime]:
    end = until or datetime.now(UTC)
    start = since or end - timedelta(days=90)
    return start, end


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def make_fact(row: Any, now: datetime) -> Fact:
    stopped = row.stopped_at or row.track_until
    observed = min(now, row.track_until, stopped)
    return Fact(
        role=row.role,
        provider_key=row.provider_key,
        reported_at=row.reported_at,
        observed_until=max(observed, row.reported_at),
        first_down_at=row.first_down_at,
        down_before_report=row.down_before_report,
        demo=row.demo,
        tracked_to_end=row.stopped_at is None and row.track_until <= now,
    )


FACT_COLUMNS = (
    "role, kind, provider_key, provider_name, asn, country, reported_at, first_down_at, "
    "down_before_report, demo, track_until, stopped_at, state, channels"
)


async def load_rows(
    db: AsyncSession,
    since: datetime,
    until: datetime,
    *,
    kind: str | None = None,
    channel: str | None = None,
    provider: str | None = None,
) -> list[Any]:
    where = ["reported_at >= :since", "reported_at < :until", "(NOT demo OR :demo)"]
    params: dict[str, Any] = {
        "since": since, "until": until, "demo": include_demo(), "n": MAX_FACTS,
    }  # fmt: skip
    if kind:
        where.append("kind = :kind")
        params["kind"] = kind
    if channel:
        where.append(":channel = ANY(channels)")
        params["channel"] = channel
    if provider:
        where.append("provider_key = :provider")
        params["provider"] = provider
    sql = f"SELECT {FACT_COLUMNS} FROM takedown_targets WHERE {' AND '.join(where)} LIMIT :n"  # noqa: S608
    return list((await db.execute(text(sql), params)).all())


def section(facts: list[Fact]) -> Section:
    out = Section(tracked=sum(1 for f in facts if counted(f)))
    for label, hours in (("48h", 48), ("7d", 168), ("30d", 720)):
        eligible, down = window_counts(facts, hours)
        setattr(out, f"eligible_{label}", eligible)
        setattr(out, f"down_{label}", down)
    out.ttd_p50_s, out.ttd_n = median_ttd(facts)
    out.still_up_30d = still_up_after_tracking(facts)
    return out


async def history(
    db: AsyncSession, since: datetime, until: datetime, before: datetime | None
) -> list[Any]:
    """Roll-up rows of months that end before the oldest live target (their targets are gone)."""
    if before is None:
        return []
    try:
        async with db.begin_nested():
            return list(
                (
                    await db.execute(
                        text(
                            "SELECT * FROM outcome_rollup_monthly WHERE month >= :s AND month < :u "
                            "AND (month + interval '1 month') <= :b"
                        ),
                        {
                            "s": since.date().replace(day=1), "u": until.date(),
                            "b": before.date(),
                        },
                    )
                ).all()
            )  # fmt: skip
    except DBAPIError:
        return []


async def oldest_target(db: AsyncSession) -> datetime | None:
    value = await db.scalar(text("SELECT min(reported_at) FROM takedown_targets WHERE NOT demo"))
    return _utc(value)


async def outcomes_available(db: AsyncSession) -> bool:
    try:
        async with db.begin_nested():
            return bool(
                await db.scalar(
                    text("SELECT to_regclass('public.abuse_report_outcomes') IS NOT NULL")
                )
            )
    except DBAPIError:
        return False


def _median(values: list[float]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return int(ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2)


async def report_rows(
    db: AsyncSession, since: datetime, until: datetime, with_outcomes: bool
) -> list[Any]:
    """One row per report that put a target under tracking (provider, role, outcome, reply time)."""
    extra = (
        ", COALESCE(o.manual_outcome, o.auto_outcome) AS outcome, "
        "EXTRACT(epoch FROM (o.first_reply_at - r.sent_at)) AS first_reply_s"
        if with_outcomes
        else ", NULL AS outcome, NULL AS first_reply_s"
    )
    join = "LEFT JOIN abuse_report_outcomes o ON o.report_id = r.id" if with_outcomes else ""
    sql = (
        f"SELECT DISTINCT ON (l.report_id, t.provider_key) l.report_id, t.provider_key, "  # noqa: S608
        f"t.role, r.sent_at{extra} FROM takedown_target_links l "
        "JOIN takedown_targets t ON t.id = l.target_id JOIN abuse_reports r ON r.id = l.report_id "
        f"{join} WHERE l.report_id IS NOT NULL AND (NOT t.demo OR :demo) "
        "AND r.sent_at >= :since AND r.sent_at < :until ORDER BY l.report_id, t.provider_key"
    )
    params = {"since": since, "until": until, "demo": include_demo()}
    try:
        async with db.begin_nested():
            return list((await db.execute(text(sql), params)).all())
    except DBAPIError:
        if not with_outcomes:
            return []
        return await report_rows(db, since, until, False)


ANSWERED = {"auto_ack", "ticket_opened", "resolved", "rejected", "human_reply"}


# ---- statistics ------------------------------------------------------------------------------


@router.get("/takedown/summary", response_model=Summary)
async def summary(
    db: DbSession,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    kind: Annotated[Kind | None, Query()] = None,
    channel: Annotated[Channel | None, Query()] = None,
) -> Summary:
    start, end = _window(_utc(since), _utc(until))
    now = datetime.now(UTC)
    rows = await load_rows(db, start, end, kind=kind, channel=channel)
    facts = [make_fact(r, now) for r in rows]
    urls = section([f for f in facts if f.role == "payload_url"])
    hosts = section([f for f in facts if f.role == "payload_host"])
    oldest = await oldest_target(db)
    for r in await history(db, start, end, oldest):
        if channel and r.channel != channel:
            continue
        target = urls if r.kind == "payload_url" else hosts if r.kind == "payload_host" else None
        if target is None:
            continue
        target.tracked += r.targets
        for label in ("48h", "7d", "30d"):
            setattr(
                target,
                f"eligible_{label}",
                getattr(target, f"eligible_{label}") + getattr(r, f"targets_eligible_{label}"),
            )
            setattr(
                target,
                f"down_{label}",
                getattr(target, f"down_{label}") + getattr(r, f"targets_down_{label}"),
            )
    sources = [r for r in rows if r.role == "attack_source" and not r.demo]
    c2 = [r for r in rows if r.role == "c2" and not r.demo]
    outcomes = await outcomes_available(db)
    reports = await report_rows(db, start, end, outcomes)
    answered = [r for r in reports if r.outcome in ANSWERED]
    return Summary(
        since=start,
        until=end,
        urls=urls,
        hosts=hosts,
        attack_sources=AttackSources(
            tracked=len(sources),
            quiet=sum(1 for r in sources if r.state == "down"),
            active=sum(1 for r in sources if r.state == "up"),
        ),
        c2=C2Section(tracked=len(c2), still_used=sum(1 for r in c2 if r.state == "up")),
        reports=ReportTotals(
            sent=len(reports),
            answered=len(answered) if outcomes else None,
            first_reply_p50_s=_median(
                [float(r.first_reply_s) for r in reports if r.first_reply_s is not None]
            ),
        ),
    )


@router.get("/takedown/curve", response_model=Curve)
async def takedown_curve(
    db: DbSession,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    channel: Annotated[Channel | None, Query()] = None,
) -> Curve:
    start, end = _window(_utc(since), _utc(until))
    now = datetime.now(UTC)
    rows = await load_rows(db, start, end, channel=channel)
    facts = [make_fact(r, now) for r in rows]
    series = []
    for name, role in ROLE_OF_KIND.items():
        points = curve([f for f in facts if f.role == role])
        series.append(
            CurveSeries(kind=name, points=[CurvePoint(**p) for p in points])  # type: ignore[arg-type]
        )
    return Curve(since=start, until=end, series=series)


SORTS = {
    "targets": lambda p: (-p.targets, p.provider_key),
    "down_48h": lambda p: (-(p.percent_48h if p.percent_48h is not None else -1), p.provider_key),
    "ttd": lambda p: (p.ttd_p50_s if p.ttd_p50_s is not None else 10**12, p.provider_key),
    "reports": lambda p: (-p.reports_sent, p.provider_key),
}


@router.get("/takedown/providers", response_model=Providers)
async def providers(
    db: DbSession,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    kind: Annotated[Kind | None, Query()] = None,
    channel: Annotated[Channel | None, Query()] = None,
    sort: Annotated[Literal["targets", "down_48h", "ttd", "reports"], Query()] = "targets",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Providers:
    start, end = _window(_utc(since), _utc(until))
    now = datetime.now(UTC)
    rows = await load_rows(db, start, end, kind=kind, channel=channel)
    by: dict[str, list[Any]] = defaultdict(list)
    for r in rows:
        if r.role in TAKEDOWN_ROLES:
            by[r.provider_key].append(r)
    out: dict[str, ProviderOut] = {}
    for key, group in by.items():
        facts = [make_fact(r, now) for r in group]
        p = ProviderOut(provider_key=key, targets=sum(1 for f in facts if counted(f)))
        p.name = next((r.provider_name for r in group if r.provider_name), None)
        p.asn = next((r.asn for r in group if r.asn is not None), None)
        p.country = next((r.country for r in group if r.country), None)
        p.eligible_48h, p.down_48h = window_counts(facts, 48)
        p.eligible_30d, p.down_30d = window_counts(facts, 720)
        p.ttd_p50_s, p.ttd_n = median_ttd(facts)
        p.still_up = still_up_after_tracking(facts)
        out[key] = p
    oldest = await oldest_target(db)
    for r in await history(db, start, end, oldest):
        if (channel and r.channel != channel) or r.kind not in TAKEDOWN_ROLES:
            continue
        p = out.setdefault(
            r.provider_key,
            ProviderOut(provider_key=r.provider_key, asn=r.asn, country=r.country),
        )
        p.targets += r.targets
        p.eligible_48h += r.targets_eligible_48h
        p.down_48h += r.targets_down_48h
        p.eligible_30d += r.targets_eligible_30d
        p.down_30d += r.targets_down_30d
    outcomes = await outcomes_available(db)
    sent: dict[str, int] = defaultdict(int)
    answered: dict[str, int] = defaultdict(int)
    replies: dict[str, list[float]] = defaultdict(list)
    for rep in await report_rows(db, start, end, outcomes):
        sent[rep.provider_key] += 1
        if rep.outcome in ANSWERED:
            answered[rep.provider_key] += 1
        if rep.first_reply_s is not None:
            replies[rep.provider_key].append(float(rep.first_reply_s))
    for key, p in out.items():
        p.percent_48h = percent(p.down_48h, p.eligible_48h)
        p.percent_30d = percent(p.down_30d, p.eligible_30d)
        p.reports_sent = sent.get(key, 0)
        if outcomes:
            p.reports_answered = answered.get(key, 0)
            p.percent_answered = percent(p.reports_answered, p.reports_sent)
        p.first_reply_p50_s = _median(replies.get(key, []))
    ordered = sorted(out.values(), key=SORTS[sort])
    return Providers(items=ordered[:limit])


# ---- targets ---------------------------------------------------------------------------------

TARGET_SELECT = (
    "SELECT t.*, (SELECT max(c.checked_at) FROM takedown_checks c WHERE c.target_id = t.id) "
    "AS last_check_at FROM takedown_targets t"
)


def to_out(row: Any) -> TargetOut:
    ttd = None if row.down_before_report else ttd_seconds_of(row)
    return TargetOut(
        id=row.id, kind=row.kind, role=row.role, value=row.value, parent_id=row.parent_id,
        provider_key=row.provider_key, provider_name=row.provider_name, asn=row.asn,
        country=row.country, reported_at=row.reported_at, channels=list(row.channels),
        state=row.state, state_source=row.state_source, state_since=row.state_since,
        tracking=row.tracking, track_until=row.track_until, http_eligible=row.http_eligible,
        demo=row.demo, down_before_report=row.down_before_report, last_up_at=row.last_up_at,
        first_down_at=row.first_down_at, ttd_s=ttd, resurrections=row.resurrections,
        last_check_at=row.last_check_at,
    )  # fmt: skip


def ttd_seconds_of(row: Any) -> int | None:
    if row.first_down_at is None or row.role not in TAKEDOWN_ROLES:
        return None
    fact = Fact(
        role=row.role, provider_key=row.provider_key, reported_at=row.reported_at,
        observed_until=row.first_down_at, first_down_at=row.first_down_at,
        down_before_report=row.down_before_report, demo=row.demo,
    )  # fmt: skip
    value = ttd_seconds(fact)
    return None if value is None else int(value)


def like(value: str) -> str:
    return "%" + _LIKE.sub(r"\\\1", value) + "%"


@router.get("/takedown/targets", response_model=TargetPage)
async def list_targets(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    state: Annotated[State | None, Query()] = None,
    kind: Annotated[Kind | None, Query()] = None,
    role: Annotated[Role | None, Query()] = None,
    provider: Annotated[str | None, Query(max_length=64)] = None,
    channel: Annotated[Channel | None, Query()] = None,
    tracking: Annotated[bool | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> TargetPage | JSONResponse:
    where: list[str] = ["(NOT t.demo OR :demo)"]
    params: dict[str, Any] = {"demo": include_demo(), "n": limit + 1}
    for column, value in (("state", state), ("kind", kind), ("role", role)):
        if value is not None:
            where.append(f"t.{column} = :{column}")
            params[column] = value
    if provider:
        where.append("t.provider_key = :provider")
        params["provider"] = provider
    if channel:
        where.append(":channel = ANY(t.channels)")
        params["channel"] = channel
    if tracking is not None:
        where.append("t.tracking = :tracking")
        params["tracking"] = tracking
    if q and q.strip():
        where.append("(t.value ILIKE :q OR t.provider_name ILIKE :q OR t.provider_key ILIKE :q)")
        params["q"] = like(q.strip())
    if cursor:
        try:
            ts, last_id = decode_cursor(cursor)
            where.append("(t.reported_at, t.id) < (:cts, :cid)")
            params["cts"] = datetime.fromisoformat(str(ts))
            params["cid"] = int(last_id)
        except InvalidCursorError, ValueError, TypeError:
            return error(400, "Invalid cursor", "invalid_cursor")
    sql = (
        f"{TARGET_SELECT} WHERE {' AND '.join(where)} "
        "ORDER BY t.reported_at DESC, t.id DESC LIMIT :n"
    )
    rows = list((await db.execute(text(sql), params)).all())
    page = rows[:limit]
    nxt = (
        encode_cursor([page[-1].reported_at.isoformat(), page[-1].id])
        if len(rows) > limit and page
        else None
    )
    return TargetPage(items=[to_out(r) for r in page], next_cursor=nxt)


@router.get("/takedown/targets/{target_id}", response_model=TargetDetail)
async def get_target(target_id: TargetId, db: DbSession) -> TargetDetail | JSONResponse:
    row = (
        await db.execute(
            text(f"{TARGET_SELECT} WHERE t.id = :i AND (NOT t.demo OR :demo)"),
            {"i": target_id, "demo": include_demo()},
        )
    ).first()
    if row is None:
        return error(404, "Target not found", "not_found")
    kids = (
        await db.execute(
            text(f"{TARGET_SELECT} WHERE t.parent_id = :i ORDER BY t.id LIMIT :n"),
            {"i": target_id, "n": CHILDREN_MAX},
        )
    ).all()
    reports = (
        await db.execute(
            text(
                "SELECT r.public_id FROM takedown_target_links l "
                "JOIN abuse_reports r ON r.id = l.report_id WHERE l.target_id = :i "
                "ORDER BY r.sent_at NULLS LAST, r.id"
            ),
            {"i": target_id},
        )
    ).scalars().all()  # fmt: skip
    checks = (
        await db.execute(
            text(
                "SELECT id, checked_at, method, outcome, http_status, sha256, bytes, duration_ms, "
                "detail FROM takedown_checks WHERE target_id = :i "
                "ORDER BY checked_at DESC, id DESC LIMIT :n"
            ),
            {"i": target_id, "n": TIMELINE_MAX},
        )
    ).all()
    out = to_out(row)
    return TargetDetail(
        target=out,
        children=[to_out(k) for k in kids],
        links=Links(reports=[str(p) for p in reports]),
        checks=[CheckOut(**dict(c._mapping)) for c in checks],
        ttd=Bounds(seconds=out.ttd_s, down_after=row.last_up_at, down_before=row.first_down_at),
        baseline_sha256=row.baseline_sha256,
        last_sha256=row.last_sha256,
    )


# ---- admin actions ---------------------------------------------------------------------------


@router.post("/takedown/targets/{target_id}/recheck", response_model=Rechecked)
async def recheck(target_id: TargetId, request: Request, db: DbSession) -> Rechecked | JSONResponse:
    """Bring the next check forward. The collector (HTTP) and ingest (listings) do the checking."""
    row = (
        await db.execute(
            text(
                "SELECT t.id, t.kind, t.demo, t.tracking, t.http_eligible, t.track_until, "
                "(SELECT max(c.checked_at) FROM takedown_checks c WHERE c.target_id = t.id) "
                "AS last_check FROM takedown_targets t WHERE t.id = :i"
            ),
            {"i": target_id},
        )
    ).first()
    if row is None:
        return error(404, "Target not found", "not_found")
    if row.demo:
        return error(409, "Demo targets are never checked.", "demo_target")
    now = datetime.now(UTC)
    if not row.tracking or row.track_until <= now:
        return error(409, "This target is no longer tracked.", "not_tracked")
    if row.last_check is not None and now - row.last_check < RECHECK_MIN_GAP:
        return JSONResponse(
            {"detail": "This target was checked less than an hour ago.", "code": "too_soon"},
            status_code=429,
            headers={"Retry-After": str(int(RECHECK_MIN_GAP.total_seconds()))},
        )
    http = bool(row.http_eligible)
    await db.execute(
        text(
            "UPDATE takedown_targets SET listing_next_at = :now, "
            "http_next_at = CASE WHEN http_eligible THEN :now ELSE http_next_at END WHERE id = :i"
        ),
        {"now": now, "i": target_id},
    )
    principal = await current_principal(request)
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="takedown.recheck",
        ip=_client_ip(request),
        details={"target": target_id, "http": http},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Rechecked(id=target_id, http=http, listing=True)


@router.post("/takedown/targets/{target_id}/stop", response_model=Stopped)
async def stop(target_id: TargetId, request: Request, db: DbSession) -> Stopped | JSONResponse:
    principal = await current_principal(request)
    found = await db.scalar(
        text("SELECT tracking FROM takedown_targets WHERE id = :i"), {"i": target_id}
    )
    if found is None:
        return error(404, "Target not found", "not_found")
    if found:
        await db.execute(
            text(
                "UPDATE takedown_targets SET tracking = false, stopped_at = now(), "
                "stopped_by = :by WHERE id = :i"
            ),
            {"by": _actor(principal)[:120], "i": target_id},
        )
        await audit_db.record(
            db,
            actor=_actor(principal),
            action="takedown.stop",
            ip=_client_ip(request),
            details={"target": target_id},
            actor_id=audit_db.actor_id_of(principal),
        )
        await db.commit()
    return Stopped(id=target_id)
