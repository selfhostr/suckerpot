"""Disk guard against a real TimescaleDB: the size-limiting job and ingest degradation."""

import json
import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from suckerpot_db import database_url_from_env

from ingest.diskguard import DiskGuard
from ingest.writer import write_batch

from .db_fixtures import _migrate, refresh_aggregate
from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

VIEWS = ("events_hourly", "events_daily_tags", "events_daily_country", "events_daily_ip")


@pytest.fixture
async def auto(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    eng = create_async_engine(database_url_from_env(), isolation_level="AUTOCOMMIT")
    async with eng.connect() as conn:
        await _clean(conn)
        yield conn
        await _clean(conn)
    await eng.dispose()


async def _clean(conn: AsyncConnection) -> None:
    await conn.execute(text("TRUNCATE events, sessions, system_status, maintenance_log"))
    for view in VIEWS:
        await refresh_aggregate(
            conn, view, "now() - INTERVAL '400 days'", "now() + INTERVAL '2 days'", force="true"
        )


# Enough data in the old chunks that dropping some of them clears the 80 percent mark with room to
# spare: the fixed size of the schema (catalog, empty tables) grows with every migration.
OLD_ROWS = 150


async def _fill(conn: AsyncConnection, days: range, rows: int = 60) -> None:
    for day in days:
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,"
                " data, country, tags) SELECT now() - make_interval(days => :d, mins => g),"
                " 'ssh', 's' || :d || '-' || g, 'command', '198.51.100.9', 40000, 22,"
                " jsonb_build_object('input', (SELECT string_agg(md5(random()::text || x), '')"
                " FROM generate_series(1, 1500) x)), 'CH', '{recon}' FROM generate_series(1, :n) g"
            ),
            {"d": day, "n": rows},
        )


async def _size(conn: AsyncConnection) -> int:
    return int(
        (await conn.execute(text("SELECT pg_database_size(current_database())"))).scalar_one()
    )


async def _job_id(conn: AsyncConnection) -> int:
    return int(
        (
            await conn.execute(
                text(
                    "SELECT job_id FROM timescaledb_information.jobs"
                    " WHERE proc_name = 'suckerpot_disk_guard'"
                )
            )
        ).scalar_one()
    )


async def _set_ceiling(conn: AsyncConnection, max_bytes: int) -> int:
    job = await _job_id(conn)
    await conn.execute(
        text("SELECT alter_job(:j, config => jsonb_build_object('max_bytes', CAST(:b AS bigint)))"),
        {"j": job, "b": max_bytes},
    )
    return job


async def _hourly_total(conn: AsyncConnection) -> int:
    return int(
        (
            await conn.execute(text("SELECT coalesce(sum(events), 0) FROM events_hourly"))
        ).scalar_one()
    )


async def test_job_is_created_with_the_configured_ceiling(auto: AsyncConnection) -> None:
    config = (
        await auto.execute(
            text(
                "SELECT config, schedule_interval::text FROM timescaledb_information.jobs"
                " WHERE proc_name = 'suckerpot_disk_guard'"
            )
        )
    ).one()
    assert config[0] == {"max_bytes": 10 * 1024**3} and config[1] == "00:05:00"
    try:
        _migrate({"DB_MAX_SIZE_MB": "512"})
        _migrate({"DB_MAX_SIZE_MB": "512"})
        rows = (
            await auto.execute(
                text(
                    "SELECT config FROM timescaledb_information.jobs WHERE proc_name = 'suckerpot_disk_guard'"
                )
            )
        ).all()
        assert [r[0] for r in rows] == [{"max_bytes": 512 * 1024 * 1024}]
    finally:
        _migrate()


async def test_below_ninety_percent_nothing_is_dropped(auto: AsyncConnection) -> None:
    await _fill(auto, range(5, 9))
    size = await _size(auto)
    job = await _set_ceiling(auto, size * 2)
    before = (await auto.execute(text("SELECT count(*) FROM events"))).scalar_one()
    await auto.execute(text("CALL run_job(:j)"), {"j": job})
    assert (await auto.execute(text("SELECT count(*) FROM events"))).scalar_one() == before
    assert (await auto.execute(text("SELECT count(*) FROM maintenance_log"))).scalar_one() == 0
    status = (
        await auto.execute(text("SELECT value FROM system_status WHERE key = 'disk_guard'"))
    ).scalar_one()
    assert status["state"] == "ok" and status["active"] is False and status["percent"] < 90


async def test_above_ninety_percent_drops_oldest_chunks_until_below_eighty(
    auto: AsyncConnection,
) -> None:
    await _fill(
        auto, range(5, 13), rows=OLD_ROWS
    )  # eight chunks, all older than the protected 4 days
    await _fill(auto, range(0, 2), rows=10)  # recent chunks: never dropped
    for view in VIEWS:
        await refresh_aggregate(
            auto, view, "now() - INTERVAL '30 days'", "now() + INTERVAL '2 days'"
        )
    aggregated = await _hourly_total(auto)
    assert aggregated == 8 * OLD_ROWS + 2 * 10
    size = await _size(auto)
    ceiling = int(size / 0.93)
    job = await _set_ceiling(auto, ceiling)

    await auto.execute(text("CALL run_job(:j)"), {"j": job})

    after = await _size(auto)
    assert after < 0.8 * ceiling
    raw = (await auto.execute(text("SELECT count(*) FROM events"))).scalar_one()
    assert 20 <= raw < 8 * OLD_ROWS + 20  # old chunks gone, the recent ones kept
    # Oldest first: what is left of the old data is the newest part.
    oldest_left = (
        await auto.execute(
            text("SELECT max(ts) - min(ts) FROM events WHERE ts < now() - INTERVAL '4 days'")
        )
    ).scalar_one()
    assert oldest_left is None or oldest_left.days < 8
    newest_dropped_ok = (
        await auto.execute(text("SELECT count(*) FROM events WHERE ts > now() - INTERVAL '3 days'"))
    ).scalar_one()
    assert newest_dropped_ok == 20
    # Aggregates are untouched, even after a refresh over the whole range.
    assert await _hourly_total(auto) == aggregated
    log = (await auto.execute(text("SELECT action, detail FROM maintenance_log"))).one()
    assert log[0] == "disk_guard_drop_chunks"
    assert log[1]["state"] == "trimmed" and log[1]["chunks_dropped"] >= 1
    assert log[1]["size_before"] > log[1]["size_after"]
    status = (
        await auto.execute(text("SELECT value FROM system_status WHERE key = 'disk_guard'"))
    ).scalar_one()
    assert status["state"] == "trimmed" and status["active"] is True
    assert status["last_trim_chunks"] == log[1]["chunks_dropped"]

    # A later run under the threshold reports ok but remembers the last trim.
    await auto.execute(text("CALL run_job(:j)"), {"j": job})
    status = (
        await auto.execute(text("SELECT value FROM system_status WHERE key = 'disk_guard'"))
    ).scalar_one()
    assert status["state"] == "ok" and status["last_trim_chunks"] == log[1]["chunks_dropped"]
    assert (await auto.execute(text("SELECT count(*) FROM maintenance_log"))).scalar_one() == 1


async def test_recent_chunks_are_never_dropped_even_when_critical(auto: AsyncConnection) -> None:
    await _fill(auto, range(0, 3))
    size = await _size(auto)
    job = await _set_ceiling(auto, size // 2)  # hopeless: 200%
    before = (await auto.execute(text("SELECT count(*) FROM events"))).scalar_one()
    await auto.execute(text("CALL run_job(:j)"), {"j": job})
    assert (await auto.execute(text("SELECT count(*) FROM events"))).scalar_one() == before
    status = (
        await auto.execute(text("SELECT value FROM system_status WHERE key = 'disk_guard'"))
    ).scalar_one()
    assert status["state"] == "critical" and status["active"] is True


async def test_api_reads_status_and_log_but_cannot_write(auto: AsyncConnection) -> None:
    for table in ("system_status", "maintenance_log"):
        for role, priv, expected in (
            (os.environ.get("POSTGRES_API_USER", "suckerpot_api"), "SELECT", True),
            (os.environ.get("POSTGRES_API_USER", "suckerpot_api"), "INSERT", False),
            (os.environ.get("POSTGRES_API_USER", "suckerpot_api"), "UPDATE", False),
            (os.environ.get("POSTGRES_API_USER", "suckerpot_api"), "DELETE", False),
        ):
            got = (
                await auto.execute(
                    text("SELECT has_table_privilege(:r, :t, :p)"),
                    {"r": role, "t": table, "p": priv},
                )
            ).scalar_one()
            assert got is expected, (table, role, priv)
    ingest = os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest")
    for priv, expected in (("INSERT", True), ("UPDATE", True), ("DELETE", False)):
        got = (
            await auto.execute(
                text("SELECT has_table_privilege(:r, 'system_status', :p)"),
                {"r": ingest, "p": priv},
            )
        ).scalar_one()
        assert got is expected
    assert (
        await auto.execute(
            text("SELECT has_table_privilege(:r, 'maintenance_log', 'INSERT')"), {"r": ingest}
        )
    ).scalar_one() is False


async def test_ingest_degrades_payloads_near_the_ceiling(
    auto: AsyncConnection, factory: async_sessionmaker[AsyncSession]
) -> None:
    size = await _size(auto)
    published: list[dict[str, object]] = []

    async def sink(detail: dict[str, object]) -> None:
        published.append(detail)

    big = "A" * 5000
    events = [
        make_event("command", sid="s-cmd", data={"input": big, "cwd": "/root"}),
        make_event("http_request", sid="s-http", data={"path": "/" + big, "method": "GET"}),
        make_event("login_attempt", sid="s-login", data={"username": big, "password": "x"}),
    ]
    # Ceiling just under the current size: 100%+ of it is used.
    guard = DiskGuard(factory, int(size / 0.99), on_status=sink)
    await write_batch(factory, events, None, guard)
    rows = {
        r[0]: r[1]
        for r in await auto.execute(text("SELECT session_id, data FROM events ORDER BY session_id"))
    }
    assert guard.degraded and guard.degraded_writes == 2
    assert len(rows["s-cmd"]["input"]) == 256 and rows["s-cmd"]["_truncated"] is True
    assert len(rows["s-http"]["path"]) == 256 and rows["s-http"]["method"] == "GET"
    assert len(rows["s-login"]["username"]) == 5000  # other types are never touched
    assert published and published[0]["degraded"] is True

    # Plenty of room: full payloads again.
    roomy = DiskGuard(factory, size * 10)
    await write_batch(
        factory, [make_event("command", sid="s-full", data={"input": big})], None, roomy
    )
    full = (
        await auto.execute(text("SELECT data FROM events WHERE session_id = 's-full'"))
    ).scalar_one()
    assert len(full["input"]) == 5000 and not roomy.degraded and roomy.degraded_writes == 0
    assert json.dumps(full)  # still valid json
