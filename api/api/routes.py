"""REST endpoints (read-only). All SQL uses SQLAlchemy constructs with bound parameters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request, Response
from pydantic import AfterValidator, AwareDatetime
from sqlalchemy import func, or_, select, text, tuple_
from suckerpot_db.event_bounds import group_events_select, session_events_select
from suckerpot_db.models import (
    CampaignRow,
    EnrichmentQuotaRow,
    EnrichmentStatusRow,
    EventRow,
    ProviderSecretRow,
    ProviderTestRequestRow,
    SessionRow,
)
from suckerpot_db.session_counts import sessions_count

from api.analytics_queries import session_has_value
from api.benign import IncludeBenign, visible_events, visible_sessions
from api.cursor import (
    InvalidCursorError,
    event_cursor,
    parse_event_cursor,
    parse_session_cursor,
    session_cursor,
)
from api.deps import DbSession
from api.live import fetch_recent
from api.network_feed import router as network_feed_router
from api.schemas import (
    EnrichmentSettings,
    EventOut,
    EventPage,
    GeoFile,
    GeoipStatus,
    Health,
    KeyEditing,
    KeyInfo,
    KeyTest,
    RecentEvents,
    ReputationProvider,
    SensorCounts,
    SessionCredentials,
    SessionDetail,
    SessionOut,
    SessionPage,
    StatsSummary,
)
from api.sensors import SensorFilter
from api.session_floods import AT_MAX, AT_MIN, credentials_of, find_group_of
from api.story import STATEMENT_TIMEOUT_MS, Stage, stage_expr

router = APIRouter()
router.include_router(network_feed_router)
health_router = APIRouter()

MAX_LIMIT = 200
SessionId = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]{1,64}$")]
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
Cursor = Annotated[str | None, Query(max_length=512)]
TagFilter = Annotated[str, Query(pattern=r"^[a-z0-9-]{1,32}$")]
CountryFilter = Annotated[str, Query(pattern=r"^[A-Za-z]{2}$")]
AsnFilter = Annotated[int, Query(ge=0, le=4294967295)]
TechniqueFilter = Annotated[str, Query(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
ValueFilter = Annotated[str, Query(min_length=1, max_length=256)]
KindFilter = Annotated[
    Literal["session", "burst"],
    Query(description="Single connections (session) or flood groups (burst)."),
]


def _normalize_ip(value: str) -> str:
    try:
        addr: IPv4Address | IPv6Address = ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc
    return str(addr)


SrcIp = Annotated[str, AfterValidator(_normalize_ip)]


def _utc_or_422(value: datetime) -> datetime:
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="timestamp out of range") from exc


@health_router.get("/healthz", response_model=Health)
async def healthz(session: DbSession, response: Response) -> Health:
    try:
        await session.execute(select(1))
    except Exception:
        response.status_code = 503
        return Health(status="degraded", db="error")
    return Health(status="ok", db="ok")


@router.get("/events/recent", response_model=RecentEvents)
async def recent_events(
    session: DbSession, limit: Limit = 50, include_benign: IncludeBenign = False
) -> RecentEvents:
    """The latest events, newest first (REST equivalent of the WebSocket backfill)."""
    return RecentEvents(items=await fetch_recent(session, limit, include_benign=include_benign))


@router.get("/sessions", response_model=SessionPage)
async def list_sessions(
    session: DbSession,
    limit: Limit = 50,
    cursor: Cursor = None,
    sensor: SensorFilter = None,
    src_ip: Annotated[SrcIp | None, Query()] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    tag: TagFilter | None = None,
    country: CountryFilter | None = None,
    asn: AsnFilter | None = None,
    username: ValueFilter | None = None,
    password: ValueFilter | None = None,
    command: ValueFilter | None = None,
    url: ValueFilter | None = None,
    technique: TechniqueFilter | None = None,
    campaign_id: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    stage: Annotated[Stage | None, Query(description="The deepest step a session reached.")] = None,
    kind: KindFilter | None = None,
    include_benign: IncludeBenign = False,
) -> SessionPage:
    # Asking for one address by name is on purpose: its sessions are shown whatever the switch says.
    stmt = select(SessionRow).where(*visible_sessions(include_benign or src_ip is not None))
    if technique is not None:
        stmt = stmt.where(SessionRow.techniques.contains([technique]))
    if campaign_id is not None:
        absorbed = select(CampaignRow.id).where(CampaignRow.merged_into == campaign_id)
        stmt = stmt.where(
            or_(SessionRow.campaign_id == campaign_id, SessionRow.campaign_id.in_(absorbed))
        )
    if stage is not None:
        stmt = stmt.where(stage_expr() == stage)
    if kind is not None:
        stmt = stmt.where(SessionRow.kind == kind)
    if sensor is not None:
        stmt = stmt.where(SessionRow.sensor.in_(sensor))
    if src_ip is not None:
        stmt = stmt.where(SessionRow.src_ip == src_ip)
    if tag is not None:
        stmt = stmt.where(SessionRow.tags.contains([tag]))
    if country is not None:
        stmt = stmt.where(SessionRow.country == country.upper())
    if asn is not None:
        stmt = stmt.where(SessionRow.asn == asn)
    for name, val in (
        ("username", username),
        ("password", password),
        ("command", command),
        ("url", url),
    ):
        if val is not None:
            stmt = stmt.where(session_has_value(name, val))
    if since is not None:
        stmt = stmt.where(SessionRow.started_at >= _utc_or_422(since))
    if until is not None:
        stmt = stmt.where(SessionRow.started_at < _utc_or_422(until))
    if cursor is not None:
        try:
            c_ts, c_id = parse_session_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(tuple_(SessionRow.started_at, SessionRow.session_id) < (c_ts, c_id))
    stmt = stmt.order_by(SessionRow.started_at.desc(), SessionRow.session_id.desc()).limit(
        limit + 1
    )
    if stage is not None:
        # The stage CASE cannot use an index, so bound the scan like the other computed queries.
        await session.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))
    rows = list((await session.scalars(stmt)).all())
    page, more = rows[:limit], len(rows) > limit
    return SessionPage(
        items=[_session_out(r) for r in page],
        next_cursor=session_cursor(page[-1].started_at, page[-1].session_id) if more else None,
    )


def _session_out(row: SessionRow) -> SessionOut:
    return SessionOut.model_validate(row, from_attributes=True)


@router.get("/sessions/{session_id}", response_model=SessionDetail)
async def get_session_detail(
    session_id: SessionId,
    session: DbSession,
    at: Annotated[
        AwareDatetime | None,
        Query(
            description="When the connection happened. A connection that was folded into a flood "
            "group has no row of its own: its events are looked up at this time (plus or minus "
            "one hour) and the group that holds it is returned, with folded_from set."
        ),
    ] = None,
) -> SessionDetail:
    when = _utc_or_422(at) if at is not None else None
    if when is not None and not AT_MIN <= when <= AT_MAX:
        raise HTTPException(status_code=422, detail="timestamp out of range")
    row = await session.get(SessionRow, session_id)
    if row is not None:
        return SessionDetail.model_validate(row, from_attributes=True)
    if when is not None:
        group = await find_group_of(session, session_id, when)
        if group is not None:
            out = SessionDetail.model_validate(group, from_attributes=True)
            out.folded_from = session_id
            return out
    raise HTTPException(status_code=404, detail="session not found")


@router.get("/sessions/{session_id}/credentials", response_model=SessionCredentials)
async def get_session_credentials(
    session_id: SessionId,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> SessionCredentials:
    """What a session or a flood group tried to log in with: the top usernames, passwords and
    username/password pairs, and how many distinct ones there were."""
    row = await session.get(SessionRow, session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    return await credentials_of(session, row, limit)


@router.get("/sessions/{session_id}/events", response_model=EventPage)
async def list_session_events(
    session_id: SessionId,
    session: DbSession,
    limit: Limit = 100,
    cursor: Cursor = None,
) -> EventPage:
    after: tuple[datetime, int] | None = None
    if cursor is not None:
        try:
            after = parse_event_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
    # The session row bounds ``ts`` so TimescaleDB can skip every other (compressed) chunk.
    row = await session.get(SessionRow, session_id)
    if row is None:
        if cursor is None:
            raise HTTPException(status_code=404, detail="session not found")
        return EventPage(items=[], next_cursor=None)
    # A flood group has no events under its own id: they are those of its source, sensor and
    # port inside its time range, minus the connections that kept a row of their own.
    stmt = group_events_select(row) if row.kind == "burst" else session_events_select(row)
    if after is not None:
        stmt = stmt.where(tuple_(EventRow.ts, EventRow.id) > after)
    stmt = stmt.order_by(EventRow.ts.asc(), EventRow.id.asc()).limit(limit + 1)
    rows = list((await session.scalars(stmt)).all())
    page, more = rows[:limit], len(rows) > limit
    return EventPage(
        items=[EventOut.model_validate(r, from_attributes=True) for r in page],
        next_cursor=event_cursor(page[-1].ts, page[-1].id) if more else None,
    )


@router.get("/stats/summary", response_model=StatsSummary)
async def stats_summary(session: DbSession, include_benign: IncludeBenign = False) -> StatsSummary:
    since = datetime.now(UTC) - timedelta(hours=24)
    ev_ok = visible_events(include_benign)
    se_ok = visible_sessions(include_benign)

    ev_by_sensor = (
        await session.execute(
            select(EventRow.sensor, func.count(EventRow.id))
            .where(EventRow.ts >= since, *ev_ok)
            .group_by(EventRow.sensor)
        )
    ).all()
    downloads = await session.scalar(
        select(func.count(EventRow.id)).where(
            EventRow.ts >= since, EventRow.type == "download_attempt", *ev_ok
        )
    )
    ses_by_sensor = (
        await session.execute(
            select(SessionRow.sensor, sessions_count())
            .where(SessionRow.started_at >= since, *se_ok)
            .group_by(SessionRow.sensor)
        )
    ).all()
    flood = SessionRow.kind == "burst"
    unique_ips, with_cmds, flood_sessions, flood_sources = (
        await session.execute(
            select(
                func.count(func.distinct(SessionRow.src_ip)),
                sessions_count(SessionRow.commands > 0),
                sessions_count(flood),
                func.count(func.distinct(SessionRow.src_ip)).filter(flood),
            ).where(SessionRow.started_at >= since, *se_ok)
        )
    ).one()

    by_sensor: dict[str, SensorCounts] = {}
    for name, n in ev_by_sensor:
        by_sensor.setdefault(name, SensorCounts(events=0, sessions=0)).events = n
    for name, n in ses_by_sensor:
        by_sensor.setdefault(name, SensorCounts(events=0, sessions=0)).sessions = n
    return StatsSummary(
        window_hours=24,
        events=sum(n for _, n in ev_by_sensor),
        sessions=sum(n for _, n in ses_by_sensor),
        unique_ips=unique_ips,
        sessions_with_commands=with_cmds,
        download_attempts=downloads or 0,
        by_sensor=dict(sorted(by_sensor.items())),
        flood_sessions=flood_sessions,
        flood_sources=flood_sources,
    )


DBIP_ATTRIBUTION = "IP geolocation by DB-IP.com (https://db-ip.com), CC BY 4.0"
MAXMIND_ATTRIBUTION = (
    "This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)"
)


@router.get("/settings/enrichment", response_model=EnrichmentSettings)
async def enrichment_settings(session: DbSession, request: Request) -> EnrichmentSettings:
    """Provider status, GeoIP database age and today's quota usage. Never a key."""
    status = {r.name: r for r in (await session.scalars(select(EnrichmentStatusRow))).all()}
    today = datetime.now(UTC).date()
    used = {
        r.provider: r.used
        for r in (
            await session.scalars(select(EnrichmentQuotaRow).where(EnrichmentQuotaRow.day == today))
        ).all()
    }
    now = datetime.now(UTC)

    geo_row = status.get("geoip")
    d = geo_row.detail if geo_row else {}
    provider = str(d.get("provider", "unknown"))
    files: dict[str, GeoFile] = {}
    for kind, info in (d.get("files") or {}).items():
        try:
            updated = datetime.fromisoformat(info["updated_at"])
            files[str(kind)] = GeoFile(
                file=str(info["file"]),
                bytes=int(info["bytes"]),
                updated_at=updated,
                age_days=round((now - updated).total_seconds() / 86400, 1),
            )
        except KeyError, ValueError, TypeError:
            continue
    attribution = {"dbip": DBIP_ATTRIBUTION, "maxmind": MAXMIND_ATTRIBUTION}.get(provider)
    geoip = GeoipStatus(
        provider=provider,
        available=bool(d.get("available", False)),
        files=files,
        last_error=d.get("last_error"),
        refresh_days=d.get("refresh_days"),
        attribution=attribution,
    )

    secrets = {r.provider: r for r in (await session.scalars(select(ProviderSecretRow))).all()}
    tests = {r.provider: r for r in (await session.scalars(select(ProviderTestRequestRow))).all()}

    def key_info(name: str) -> dict[str, Any]:
        det = status[name].detail if name in status else {}
        row = secrets.get(name)
        reported_source = det.get("source")
        error = det.get("secret_error")
        source: str | None
        if row is not None and not error:
            source = "settings"
        elif row is None:  # a key removed a moment ago may still be reported as "settings"
            source = "env" if det.get("env_configured", det.get("configured")) else None
        else:
            source = reported_source
        raw = det.get("test")
        test = None
        if isinstance(raw, dict):
            try:
                checked = datetime.fromisoformat(str(raw["checked_at"]))
            except KeyError, ValueError:
                checked = None
            test = KeyTest(ok=bool(raw.get("ok")), error=raw.get("error"), checked_at=checked)
        req = tests.get(name)
        pending = bool(
            req is not None
            and (test is None or test.checked_at is None or test.checked_at < req.requested_at)
        )
        return {
            "configured": bool(det.get("configured", False)) or row is not None,
            "source": source,
            "last4": row.last4 if row is not None and source == "settings" else None,
            "updated_at": row.updated_at if row is not None and source == "settings" else None,
            "secret_error": error,
            "pending_apply": bool(row is not None and not error and reported_source != "settings"),
            "test": test,
            "test_pending": pending,
            "test_requested_at": req.requested_at if req is not None else None,
        }

    def rep(name: str) -> ReputationProvider:
        det = status[name].detail if name in status else {}
        return ReputationProvider(
            **key_info(name),
            daily_quota=det.get("daily_quota"),
            used_today=used.get(name, 0),
            disabled=det.get("disabled"),
            paused=bool(det.get("paused", False)),
            last_error=det.get("last_error"),
        )

    editing = request.app.state.secret_box is not None
    key_editing = KeyEditing(
        enabled=editing, reason=None if editing else request.app.state.secret_box_reason
    )
    reported = max((r.updated_at for r in status.values()), default=None)
    return EnrichmentSettings(
        geoip=geoip,
        abuseipdb=rep("abuseipdb"),
        greynoise=rep("greynoise"),
        abusech=rep("abusech"),
        virustotal=rep("virustotal"),
        maxmind=KeyInfo(**key_info("maxmind")),
        nvd=KeyInfo(**key_info("nvd")),
        github=KeyInfo(**key_info("github")),
        key_editing=key_editing,
        reported_at=reported,
    )
