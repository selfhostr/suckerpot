"""System settings: unit (state thresholds, validation) and integration (real TimescaleDB)."""

import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Self, cast

import httpx
import pytest
from analytics_seed import api_engine, owner_engine, small_dataset
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import create_session_factory

from api.main import create_app
from api.settings import oldest_event_at, sensor_state

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(seconds=1), "active"),
        (timedelta(minutes=14, seconds=59), "active"),
        (timedelta(minutes=15), "quiet"),
        (timedelta(hours=23, minutes=59), "quiet"),
        (timedelta(hours=24), "silent"),
        (timedelta(days=30), "silent"),
    ],
)
def test_sensor_state_thresholds(age: timedelta, expected: str) -> None:
    assert sensor_state(NOW - age, NOW) == expected


def test_sensor_state_never_seen() -> None:
    assert sensor_state(None, NOW) == "silent"


class _Result:
    def __init__(self, row: tuple[datetime, datetime] | None = None, value: object = None) -> None:
        self._row, self._value = row, value

    def first(self) -> tuple[datetime, datetime] | None:
        return self._row

    def scalar(self) -> object:
        return self._value


class _FakeDb:
    """Answers the chunk catalogue query, then the in-chunk minimum; either may fail."""

    def __init__(self, *results: _Result | Exception) -> None:
        self._results = list(results)

    def begin_nested(self) -> Self:
        return self

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def execute(self, *_: object) -> _Result:
        item = self._results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _fake(*results: _Result | Exception) -> AsyncSession:
    return cast(AsyncSession, _FakeDb(*results))


CHUNK = (NOW - timedelta(days=7), NOW)


async def test_oldest_event_exact_minimum_in_oldest_chunk() -> None:
    first = NOW - timedelta(days=3)
    assert await oldest_event_at(_fake(_Result(CHUNK), _Result(value=first))) == first


async def test_oldest_event_falls_back_to_chunk_start() -> None:
    assert await oldest_event_at(_fake(_Result(CHUNK), _Result(value=None))) == CHUNK[0]


async def test_oldest_event_null_when_no_chunks() -> None:
    assert await oldest_event_at(_fake(_Result(None))) is None


async def test_oldest_event_null_when_catalogue_unreadable() -> None:
    err = DBAPIError("SELECT 1", None, Exception("permission denied"))
    assert await oldest_event_at(_fake(err)) is None


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    # Anchored to now, not the hour boundary: the API counts a trailing hour.
    base = datetime.now(UTC).replace(microsecond=0)
    async with owner_engine() as owner:
        await small_dataset(base).write(owner)
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO system_status (key, value) VALUES "
                    "('disk_guard', CAST(:g AS jsonb)), ('ingest_disk', CAST(:i AS jsonb)) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                ),
                {
                    "g": json.dumps({"state": "ok", "max_bytes": 5_000_000_000}),
                    "i": json.dumps({"free_bytes": 1}),
                },
            )
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set")
async def test_system_settings(client: httpx.AsyncClient) -> None:
    r = await client.get("/settings/system")
    assert r.status_code == 200, r.text
    body = r.json()
    by = {s["sensor"]: s for s in body["sensors"]}
    assert list(by) == [
        "ssh",
        "telnet",
        "web",
        "rdp",
        "redis",
        "docker",
        "mysql",
        "adb",
        "mssql",
        "smb",
        "sip",
        "synology",
    ]
    assert by["sip"]["status"] == "silent" and by["redis"]["events_last_hour"] == 0
    assert by["ssh"]["status"] == "quiet" or by["ssh"]["status"] == "active"
    assert by["ssh"]["events_last_hour"] == 8
    assert by["web"]["events_last_hour"] == 4
    assert by["telnet"]["status"] == "quiet" or by["telnet"]["status"] == "silent"
    assert by["rdp"] == {
        "sensor": "rdp",
        "last_event_at": None,
        "events_last_hour": 0,
        "status": "silent",
    }
    assert body["retention"]["raw_days"] == 90
    assert body["retention"]["compression_after_days"] == 7
    assert "events_hourly" in body["retention"]["aggregates"]
    oldest = datetime.fromisoformat(body["retention"]["oldest_event_at"])
    assert oldest <= datetime.now(UTC)
    assert body["disk_guard"]["state"] == "ok"
    assert body["ingest_disk"] == {"free_bytes": 1}
    assert body["database"]["size_bytes"] > 0
    assert body["database"]["max_bytes"] == 5_000_000_000
