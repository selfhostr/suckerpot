"""Your exposure (M16): the services you run, compared with what attackers go after.

The owner types in an inventory of services (name, kind of service, product, version, whether it
is reachable from the internet). The page puts that next to what the honeypot recorded for the
same kind of service: how many attacks, from how many sources, how far they got, and which known
exploited vulnerabilities (CISA KEV and others, as the CVE watch matched them) apply.

The inventory is only compared with data we already hold. Nothing is scanned, resolved or
contacted; the entries are free text that is stored, shown and never interpreted. Reading is open
to both roles; every change needs an admin and is audited.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from suckerpot_db.models import InventoryServiceRow as Inv
from suckerpot_db.session_counts import sql_sessions_count

from api import audit, guidance
from api.audit import actor_id_of
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.reauth import error, guard
from api.sensors import SENSOR_LABELS, SENSORS, SensorName
from api.session_floods import SQL_LAST_SEEN

router = APIRouter(tags=["exposure"])

Exposure = Literal["internet", "vpn", "internal"]
Verdict = Literal["internet_targeted", "internet_quiet", "private_targeted", "private_quiet"]
DEFAULT_LIMIT = 100
MAX_LIMIT = 200
MAX_ITEMS = 200
CONTROL = {chr(c) for c in range(32)} | {chr(127)}


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if CONTROL & set(value):
        raise ValueError("control characters are not allowed")
    return value or None


class InventoryOut(BaseModel):
    id: int
    name: str
    service: SensorName
    product: str | None
    version: str | None
    exposure: Exposure
    notes: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class InventoryPage(BaseModel):
    items: list[InventoryOut]
    next_cursor: str | None


class InventoryBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    service: SensorName
    product: str | None = Field(default=None, max_length=64)
    version: str | None = Field(default=None, max_length=32)
    exposure: Exposure = "internal"
    notes: str | None = Field(default=None, max_length=512)

    @field_validator("name", "product", "version", "notes")
    @classmethod
    def _plain(cls, v: str | None) -> str | None:
        return _clean(v)

    @field_validator("name")
    @classmethod
    def _named(cls, v: str | None) -> str | None:
        if not v:
            raise ValueError("a name is required")
        return v


class InventoryPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    service: SensorName | None = None
    product: str | None = Field(default=None, max_length=64)
    version: str | None = Field(default=None, max_length=32)
    exposure: Exposure | None = None
    notes: str | None = Field(default=None, max_length=512)

    @field_validator("name", "product", "version", "notes")
    @classmethod
    def _plain(cls, v: str | None) -> str | None:
        return _clean(v)


def _out(row: Inv) -> InventoryOut:
    return InventoryOut(
        id=row.id,
        name=row.name,
        service=row.service,  # type: ignore[arg-type]
        product=row.product,
        version=row.version,
        exposure=row.exposure,  # type: ignore[arg-type]
        notes=row.notes,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _service(request: Request) -> Any:
    return request.app.state.auth


@router.get("/defend/inventory", response_model=InventoryPage)
async def list_inventory(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> InventoryPage:
    stmt = select(Inv).order_by(Inv.id).limit(limit + 1)
    if cursor:
        try:
            (last_id,) = decode_cursor(cursor)
            if not isinstance(last_id, int):
                raise ValueError
        except (InvalidCursorError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(Inv.id > last_id)
    rows = list((await db.execute(stmt)).scalars())
    page = rows[:limit]
    more = len(rows) > limit and bool(page)
    return InventoryPage(
        items=[_out(r) for r in page], next_cursor=encode_cursor([page[-1].id]) if more else None
    )


@router.post("/defend/inventory", status_code=201, response_model=InventoryOut)
async def add_service(body: InventoryBody, request: Request, db: DbSession) -> Response:
    principal, refused = await guard(request, None, "inventory")
    if refused is not None or principal is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    count = (await db.execute(select(func.count()).select_from(Inv))).scalar() or 0
    if count >= MAX_ITEMS:
        return error(409, "The inventory is full. Remove an entry first.", "limit_reached")
    row = Inv(
        name=body.name,
        service=body.service,
        product=body.product,
        version=body.version,
        exposure=body.exposure,
        notes=body.notes,
        created_by=principal.username,
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db, actor=principal.username, action="inventory.add", target=row.name[:120],
        ip=_service(request).client_ip(request),
        details={"service": row.service, "exposure": row.exposure},
        actor_id=actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    await db.refresh(row)
    return JSONResponse(_out(row).model_dump(mode="json"), status_code=201)


@router.patch("/defend/inventory/{item_id}", response_model=InventoryOut)
async def change_service(
    item_id: Annotated[int, Path(ge=1, le=2**53)],
    body: InventoryPatch,
    request: Request,
    db: DbSession,
) -> Response:
    principal, refused = await guard(request, None, "inventory")
    if refused is not None or principal is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row = await db.get(Inv, item_id)
    if row is None:
        return error(404, "That entry does not exist.", "not_found")
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        return error(422, "Nothing to change.", "empty_patch")
    for key, value in changes.items():
        if key in ("name", "service", "exposure") and value is None:
            return error(422, f"{key} cannot be empty.", "invalid")
        setattr(row, key, value)
    row.updated_at = datetime.now(UTC)
    await audit.record(
        db, actor=principal.username, action="inventory.change", target=row.name[:120],
        ip=_service(request).client_ip(request), details={"fields": sorted(changes)},
        actor_id=actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    await db.refresh(row)
    return JSONResponse(_out(row).model_dump(mode="json"))


@router.delete("/defend/inventory/{item_id}", status_code=204)
async def remove_service(
    item_id: Annotated[int, Path(ge=1, le=2**53)], request: Request, db: DbSession
) -> Response:
    principal, refused = await guard(request, None, "inventory")
    if refused is not None or principal is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row = await db.get(Inv, item_id)
    if row is None:
        return error(404, "That entry does not exist.", "not_found")
    name = row.name[:120]
    await db.delete(row)
    await audit.record(
        db, actor=principal.username, action="inventory.remove", target=name,
        ip=_service(request).client_ip(request), actor_id=actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    return Response(status_code=204)


# -- the comparison ---------------------------------------------------------------------------


class Attacks(BaseModel):
    sessions: int
    sources: int
    deep_sessions: int  # sessions that ran commands or tried to download something
    previous_sessions: int
    last_attack_at: datetime | None


class TagCount(BaseModel):
    tag: str
    sessions: int


class CveRef(BaseModel):
    cve_id: str
    title: str | None
    cvss_score: float | None
    in_kev: bool


class ExposedService(BaseModel):
    item: InventoryOut
    label: str
    verdict: Verdict
    attacks: Attacks
    top_tags: list[TagCount]
    cves: list[CveRef]
    checks: list[str]


class Unlisted(BaseModel):
    service: SensorName
    label: str
    sessions: int
    sources: int
    checks: list[str]


class ExposureReport(BaseModel):
    days: int
    generated_at: datetime
    services: list[ExposedService]
    unlisted: list[Unlisted]


async def _attack_counts(
    db: Any, since: datetime, until: datetime
) -> dict[str, tuple[int, int, int, datetime | None]]:
    rows = (
        await db.execute(
            text(
                f"""
                SELECT sensor, {sql_sessions_count()} AS sessions,
                       count(DISTINCT src_ip) AS sources,
                       {sql_sessions_count("", "(commands > 0 OR downloads > 0)")} AS deep,
                       {SQL_LAST_SEEN} AS last_at
                FROM sessions
                WHERE started_at >= :since AND started_at < :until AND NOT benign
                GROUP BY sensor
                """  # noqa: S608 (constants only)
            ),
            {"since": since, "until": until},
        )
    ).all()
    return {r.sensor: (int(r.sessions), int(r.sources), int(r.deep), r.last_at) for r in rows}


async def _top_tags(db: Any, since: datetime) -> dict[str, list[TagCount]]:
    rows = (
        await db.execute(
            text(
                f"""
                SELECT sensor, t AS tag, {sql_sessions_count()} AS n
                FROM sessions CROSS JOIN LATERAL unnest(tags) AS t
                WHERE started_at >= :since AND NOT benign
                GROUP BY sensor, t
                """  # noqa: S608 (constants only)
            ),
            {"since": since},
        )
    ).all()
    grouped: dict[str, list[TagCount]] = {}
    for r in sorted(rows, key=lambda r: (-r.n, r.tag)):
        bucket = grouped.setdefault(r.sensor, [])
        if len(bucket) < 5:
            bucket.append(TagCount(tag=r.tag, sessions=int(r.n)))
    return grouped


async def _cves(db: Any, service: str) -> list[CveRef]:
    try:
        async with db.begin_nested():
            rows = (
                await db.execute(
                    text(
                        """
                        SELECT cve_id, title, cvss_score, in_kev FROM cve
                        WHERE :svc = ANY(matched_services) AND relevance <> 'none'
                        ORDER BY in_kev DESC, rank_score DESC, cve_id DESC LIMIT 3
                        """
                    ),
                    {"svc": service},
                )
            ).all()
    except DBAPIError:
        return []
    return [
        CveRef(
            cve_id=r.cve_id,
            title=r.title,
            cvss_score=float(r.cvss_score) if r.cvss_score is not None else None,
            in_kev=bool(r.in_kev),
        )
        for r in rows
    ]


@router.get("/defend/exposure", response_model=ExposureReport)
async def exposure_report(
    db: DbSession, days: Annotated[int, Query(ge=1, le=90)] = 30
) -> ExposureReport:
    """Each inventory entry next to the attacks on the same kind of service."""
    now = datetime.now(UTC)
    since = now - timedelta(days=days)
    current = await _attack_counts(db, since, now + timedelta(minutes=1))
    previous = await _attack_counts(db, since - timedelta(days=days), since)
    tags = await _top_tags(db, since)
    items = list((await db.execute(select(Inv).order_by(Inv.id).limit(MAX_ITEMS))).scalars())
    cve_cache: dict[str, list[CveRef]] = {}
    services: list[ExposedService] = []
    for row in items:
        sessions, sources, deep, last = current.get(row.service, (0, 0, 0, None))
        if row.service not in cve_cache:
            cve_cache[row.service] = await _cves(db, row.service)
        public = row.exposure == "internet"
        verdict: Verdict = (
            ("internet_targeted" if sessions else "internet_quiet")
            if public
            else ("private_targeted" if sessions else "private_quiet")
        )
        services.append(
            ExposedService(
                item=_out(row),
                label=SENSOR_LABELS.get(row.service, row.service),
                verdict=verdict,
                attacks=Attacks(
                    sessions=sessions,
                    sources=sources,
                    deep_sessions=deep,
                    previous_sessions=previous.get(row.service, (0, 0, 0, None))[0],
                    last_attack_at=last,
                ),
                top_tags=tags.get(row.service, []),
                cves=cve_cache[row.service],
                checks=guidance.SERVICE_CHECKS.get(row.service, []),
            )
        )
    listed = {r.service for r in items}
    unlisted = [
        Unlisted(
            service=s,  # type: ignore[arg-type]
            label=SENSOR_LABELS.get(s, s),
            sessions=current[s][0],
            sources=current[s][1],
            checks=guidance.SERVICE_CHECKS.get(s, []),
        )
        for s in SENSORS
        if s in current and s not in listed
    ]
    unlisted.sort(key=lambda u: (-u.sessions, u.service))
    return ExposureReport(days=days, generated_at=now, services=services, unlisted=unlisted)


__all__ = ["router"]
