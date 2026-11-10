"""System settings for the Settings page: sensor status, retention, disk guard, database size.

Read-only. Every block degrades to ``null`` / empty when its source (TimescaleDB job views,
``system_status`` rows) is unavailable, so a partially migrated database never breaks the page.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import EventRow

from api.deps import DbSession
from api.sensors import SENSORS, latest_event_per_sensor

router = APIRouter()

ACTIVE_WITHIN = timedelta(minutes=15)
QUIET_WITHIN = timedelta(hours=24)
AGGREGATES = ["events_hourly", "events_daily_tags", "events_daily_country", "events_daily_ip"]

SensorState = Literal["active", "quiet", "silent"]


class SensorStatus(BaseModel):
    sensor: str
    last_event_at: datetime | None
    events_last_hour: int
    status: SensorState


class Retention(BaseModel):
    raw_days: int | None
    compression_after_days: int | None
    # Timestamp of the oldest raw event still stored: shorter than ``raw_days`` when the disk
    # guard dropped old chunks or the store is young. ``None`` when empty or unavailable.
    oldest_event_at: datetime | None
    aggregates: list[str]


class DatabaseSize(BaseModel):
    size_bytes: int | None
    max_bytes: int | None


class SystemSettings(BaseModel):
    sensors: list[SensorStatus]
    retention: Retention
    disk_guard: dict[str, Any] | None
    ingest_disk: dict[str, Any] | None
    database: DatabaseSize


def sensor_state(last: datetime | None, now: datetime) -> SensorState:
    if last is None:
        return "silent"
    age = now - last
    if age < ACTIVE_WITHIN:
        return "active"
    if age < QUIET_WITHIN:
        return "quiet"
    return "silent"


async def _scalar(db: AsyncSession, sql: str, **params: object) -> Any:
    """Run a scalar query in a savepoint; ``None`` when it fails (missing view or grant)."""
    try:
        async with db.begin_nested():
            return (await db.execute(text(sql), params)).scalar()
    except DBAPIError:
        return None


async def _job_days(db: AsyncSession, proc: str, key: str) -> int | None:
    seconds = await _scalar(
        db,
        "SELECT extract(epoch FROM (config ->> :k)::interval) "
        "FROM timescaledb_information.jobs "
        "WHERE proc_name = :p AND hypertable_name = 'events' LIMIT 1",
        k=key,
        p=proc,
    )
    return round(float(seconds) / 86400) if seconds is not None else None


async def oldest_event_at(db: AsyncSession) -> datetime | None:
    """Oldest stored raw event without scanning ``events``.

    The chunk catalogue gives the oldest chunk's time range; the exact minimum is then read
    inside that one chunk only (chunk exclusion). Falls back to the chunk start, and to ``None``
    when the catalogue is unreadable or the table is empty.
    """
    try:
        async with db.begin_nested():
            chunk = (
                await db.execute(
                    text(
                        "SELECT range_start, range_end FROM timescaledb_information.chunks "
                        "WHERE hypertable_name = 'events' ORDER BY range_start LIMIT 1"
                    )
                )
            ).first()
    except DBAPIError:
        return None
    if chunk is None:
        return None
    start, end = chunk
    exact = await _scalar(
        db,
        "SELECT ts FROM events WHERE ts >= :s AND ts < :e ORDER BY ts LIMIT 1",
        s=start,
        e=end,
    )
    found = exact if isinstance(exact, datetime) else start
    return found if isinstance(found, datetime) else None


async def _status(db: AsyncSession, key: str) -> dict[str, Any] | None:
    value = await _scalar(db, "SELECT value FROM system_status WHERE key = :k", k=key)
    return value if isinstance(value, dict) else None


@router.get("/settings/system", response_model=SystemSettings)
async def system_settings(db: DbSession) -> SystemSettings:
    now = datetime.now(UTC)
    last_seen = await latest_event_per_sensor(db, now - QUIET_WITHIN - timedelta(days=6))
    # Only the last hour is counted, a small bounded group-by.
    counts = dict(
        (
            await db.execute(
                select(EventRow.sensor, func.count())
                .where(EventRow.ts >= now - timedelta(hours=1))
                .group_by(EventRow.sensor)
            )
        )
        .tuples()
        .all()
    )
    seen = {name: (last, counts.get(name, 0)) for name, last in last_seen.items()}
    sensors = [
        SensorStatus(
            sensor=s,
            last_event_at=seen.get(s, (None, 0))[0],
            events_last_hour=seen.get(s, (None, 0))[1],
            status=sensor_state(seen.get(s, (None, 0))[0], now),
        )
        for s in SENSORS
    ]
    guard = await _status(db, "disk_guard")
    size = await _scalar(db, "SELECT pg_database_size(current_database())")
    max_bytes = guard.get("max_bytes") if guard else None
    return SystemSettings(
        sensors=sensors,
        retention=Retention(
            raw_days=await _job_days(db, "policy_retention", "drop_after"),
            compression_after_days=await _job_days(db, "policy_compression", "compress_after"),
            oldest_event_at=await oldest_event_at(db),
            aggregates=AGGREGATES,
        ),
        disk_guard=guard,
        ingest_disk=await _status(db, "ingest_disk"),
        database=DatabaseSize(
            size_bytes=int(size) if size is not None else None,
            max_bytes=int(max_bytes) if isinstance(max_bytes, int | float) else None,
        ),
    )
