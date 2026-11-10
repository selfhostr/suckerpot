"""Retention against a real TimescaleDB: policies, aggregates, compression, maintenance, roles.

Needs POSTGRES_HOST (owner credentials) like the other integration tests.
"""

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from suckerpot_db import database_url_from_env
from suckerpot_db.retention import AGGREGATES, RetentionError, backfill

from .db_fixtures import _migrate, _role_url, refresh_aggregate

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

CAGG_NAMES = ("events_hourly", "events_daily_tags", "events_daily_country", "events_daily_ip")
ROLLUPS = (*CAGG_NAMES, "sessions_daily")


@pytest.fixture
async def auto(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """Owner connection in autocommit mode (refresh and run_job cannot run in a transaction)."""
    eng = create_async_engine(database_url_from_env(), isolation_level="AUTOCOMMIT")
    async with eng.connect() as conn:
        await _reset_aggregates(conn)
        yield conn
        await _reset_aggregates(conn)
    await eng.dispose()


async def _reset_aggregates(conn: AsyncConnection) -> None:
    await conn.execute(text("TRUNCATE events, sessions, sessions_daily, ip_reputation"))
    for view in CAGG_NAMES:
        await refresh_aggregate(
            conn, view, "now() - INTERVAL '400 days'", "now() + INTERVAL '2 days'", force="true"
        )


async def _backfill(conn: AsyncConnection) -> None:
    await conn.run_sync(lambda c: backfill(c, 90))


async def _insert_event(
    conn: AsyncConnection,
    age_days: float,
    *,
    sensor: str = "ssh",
    etype: str = "login_attempt",
    ip: str = "198.51.100.7",
    country: str | None = "CH",
    tags: tuple[str, ...] = (),
    session: str = "s1",
) -> None:
    await conn.execute(
        text(
            "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data,"
            " country, asn, tags) VALUES (now() - make_interval(secs => :s), :sensor, :sid, :t,"
            " CAST(:ip AS inet), 40000, 22, '{}', :c, 64496, CAST(:tags AS text[]))"
        ),
        {
            "s": age_days * 86400,
            "sensor": sensor,
            "sid": session,
            "t": etype,
            "ip": ip,
            "c": country,
            "tags": list(tags),
        },
    )


async def _jobs(conn: AsyncConnection) -> list[dict[str, Any]]:
    rows = await conn.execute(
        text(
            "SELECT job_id, proc_name, hypertable_name, config, schedule_interval::text AS every"
            " FROM timescaledb_information.jobs WHERE proc_name NOT LIKE 'policy_telemetry%'"
        )
    )
    return [dict(r._mapping) for r in rows]


def _by_proc(jobs: list[dict[str, Any]], proc: str) -> list[dict[str, Any]]:
    return [j for j in jobs if j["proc_name"] == proc]


# ---- policies -------------------------------------------------------------------------------


async def test_policies_exist_with_configured_values(auto: AsyncConnection) -> None:
    jobs = await _jobs(auto)
    (retention,) = [
        j for j in _by_proc(jobs, "policy_retention") if j["hypertable_name"] == "events"
    ]
    assert retention["config"]["drop_after"] == "90 days"
    (compression,) = _by_proc(jobs, "policy_compression")
    assert compression["hypertable_name"] == "events"
    assert compression["config"]["compress_after"] == "7 days"
    refresh = _by_proc(jobs, "policy_refresh_continuous_aggregate")
    assert len(refresh) == len(AGGREGATES)
    for job in refresh:
        assert job["config"]["start_offset"] == "3 days"
        assert job["config"]["end_offset"] == "01:00:00"
        assert job["every"] == "01:00:00"
    (maintenance,) = _by_proc(jobs, "suckerpot_maintenance")
    assert maintenance["config"] == {"retention_days": 90}


async def test_policies_follow_retention_days_and_stay_unique(auto: AsyncConnection) -> None:
    try:
        _migrate({"RETENTION_DAYS": "30"})
        _migrate({"RETENTION_DAYS": "30"})  # idempotent: no duplicate jobs
        jobs = await _jobs(auto)
        (retention,) = [
            j for j in _by_proc(jobs, "policy_retention") if j["hypertable_name"] == "events"
        ]
        assert retention["config"]["drop_after"] == "30 days"
        assert len(_by_proc(jobs, "policy_compression")) == 1
        assert len(_by_proc(jobs, "policy_refresh_continuous_aggregate")) == len(AGGREGATES)
        (maintenance,) = _by_proc(jobs, "suckerpot_maintenance")
        assert maintenance["config"] == {"retention_days": 30}
    finally:
        _migrate()
    (retention,) = [
        j
        for j in _by_proc(await _jobs(auto), "policy_retention")
        if j["hypertable_name"] == "events"
    ]
    assert retention["config"]["drop_after"] == "90 days"


@pytest.mark.parametrize("value", ["6", "abc"])
def test_invalid_retention_days_refuses_migration(value: str) -> None:
    with pytest.raises(RetentionError, match="RETENTION_DAYS"):
        _migrate({"RETENTION_DAYS": value})


# ---- aggregates -----------------------------------------------------------------------------


async def test_aggregates_survive_dropping_raw_chunks(auto: AsyncConnection) -> None:
    await _insert_event(auto, 20, tags=("recon", "scanner"), session="old1")
    await _insert_event(auto, 20, tags=("recon", "scanner"), session="old2")
    await _insert_event(auto, 20, sensor="telnet", etype="command", country="NL", session="old3")
    await _insert_event(auto, 0.01, tags=("recon",), session="new1")
    await _backfill(auto)

    async def snapshot() -> dict[str, list[Any]]:
        out: dict[str, list[Any]] = {}
        for view, order in (
            ("events_hourly", "bucket, sensor, type"),
            ("events_daily_tags", "bucket, sensor, tags"),
            ("events_daily_country", "bucket, sensor, country"),
            ("events_daily_ip", "bucket, sensor, src_ip"),
        ):
            rows = await auto.execute(text(f"SELECT * FROM {view} ORDER BY {order}"))  # noqa: S608
            out[view] = [tuple(r) for r in rows]
        return out

    before = await snapshot()
    assert sum(r[3] for r in before["events_hourly"]) == 4
    assert sum(r[3] for r in before["events_daily_country"]) == 4
    tagged = {tuple(r[2]): r[3] for r in before["events_daily_tags"]}
    assert tagged == {("recon", "scanner"): 2, ("recon",): 1}
    ip_rows = [r for r in before["events_daily_ip"] if r[1] == "ssh"]
    assert sum(r[3] for r in ip_rows) == 3 and sum(r[4] for r in ip_rows) == 3

    # Drop the raw chunks of the old events (what the retention policy does) and refresh again.
    dropped = await auto.execute(
        text("SELECT count(*) FROM drop_chunks('events', older_than => now() - INTERVAL '10 days')")
    )
    assert dropped.scalar_one() >= 1
    raw_old = await auto.execute(
        text("SELECT count(*) FROM events WHERE ts < now() - INTERVAL '10 days'")
    )
    assert raw_old.scalar_one() == 0
    await _backfill(auto)
    assert await snapshot() == before


async def test_retention_policy_job_drops_old_chunks(auto: AsyncConnection) -> None:
    await _insert_event(auto, 120, session="ancient")
    await _insert_event(auto, 1, session="recent")
    await _backfill(auto)  # the ancient event is outside the window, as in production
    job_id = (
        await auto.execute(
            text(
                "SELECT job_id FROM timescaledb_information.jobs"
                " WHERE proc_name = 'policy_retention' AND hypertable_name = 'events'"
            )
        )
    ).scalar_one()
    await auto.execute(text("CALL run_job(:j)"), {"j": job_id})
    remaining = (await auto.execute(text("SELECT session_id FROM events"))).scalars().all()
    assert remaining == ["recent"]


# ---- compression ----------------------------------------------------------------------------


async def test_compression_policy_compresses_old_chunks_and_data_stays_readable(
    auto: AsyncConnection,
) -> None:
    for i in range(20):
        await _insert_event(auto, 10 + i / 100, session=f"c{i}")
    await _insert_event(auto, 0.5, session="fresh")
    job_id = (
        await auto.execute(
            text(
                "SELECT job_id FROM timescaledb_information.jobs"
                " WHERE proc_name = 'policy_compression'"
            )
        )
    ).scalar_one()
    await auto.execute(text("CALL run_job(:j)"), {"j": job_id})
    compressed = (
        await auto.execute(
            text(
                "SELECT count(*) FILTER (WHERE is_compressed), count(*) FILTER (WHERE NOT is_compressed)"
                " FROM timescaledb_information.chunks WHERE hypertable_name = 'events'"
            )
        )
    ).one()
    assert compressed[0] >= 1 and compressed[1] >= 1
    settings = (
        await auto.execute(
            text(
                "SELECT segmentby, orderby FROM timescaledb_information.hypertable_compression_settings"
                " WHERE hypertable = CAST('events' AS regclass)"
            )
        )
    ).one()
    assert tuple(settings) == ("sensor", "ts DESC")
    assert (await auto.execute(text("SELECT count(*) FROM events"))).scalar_one() == 21

    # Late events keep landing in compressed chunks, written by the ingest role.
    ingest = create_async_engine(_role_url("INGEST"))
    async with ingest.begin() as conn:
        await _insert_event(conn, 10.001, session="late")
    await ingest.dispose()
    assert (await auto.execute(text("SELECT count(*) FROM events"))).scalar_one() == 22


# ---- maintenance job ------------------------------------------------------------------------


async def test_maintenance_rolls_up_and_deletes_old_sessions(auto: AsyncConnection) -> None:
    insert = text(
        "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,"
        " last_event_at, event_count, login_attempts, login_success, commands, downloads,"
        " http_requests) VALUES (:id, :sensor, CAST(:ip AS inet), 1, 22,"
        " date_trunc('day', now() - make_interval(days => :age), 'UTC') + INTERVAL '3 hours',"
        " now(), :ev, :logins, :ok, :cmds, :dl, 0)"
    )
    rows = [
        ("a", "ssh", "198.51.100.1", 120, 10, 5, True, 2, 1),
        ("b", "ssh", "198.51.100.2", 120, 4, 3, False, 0, 0),
        ("c", "telnet", "198.51.100.1", 120, 2, 1, False, 0, 0),
        ("d", "ssh", "198.51.100.1", 5, 7, 2, False, 0, 0),
    ]
    for id_, sensor, ip, age, ev, logins, ok, cmds, dl in rows:
        await auto.execute(
            insert,
            {"id": id_, "sensor": sensor, "ip": ip, "age": age, "ev": ev, "logins": logins,
             "ok": ok, "cmds": cmds, "dl": dl},
        )  # fmt: skip
    await auto.execute(
        text(
            "INSERT INTO ip_reputation (ip, abuse_score, abuse_checked_at, updated_at) VALUES"
            " ('198.51.100.1', 10, now() - INTERVAL '3 days', now() - INTERVAL '3 days'),"
            " ('198.51.100.2', 20, now() - INTERVAL '1 hour', now() - INTERVAL '1 hour')"
        )
    )
    await auto.execute(
        text(
            "INSERT INTO enrichment_quota (provider, day, used) VALUES"
            " ('abuseipdb', current_date - 90, 5), ('abuseipdb', current_date, 1)"
        )
    )
    job_id = (
        await auto.execute(
            text(
                "SELECT job_id FROM timescaledb_information.jobs"
                " WHERE proc_name = 'suckerpot_maintenance'"
            )
        )
    ).scalar_one()
    for _ in range(2):  # the second run must change nothing
        await auto.execute(text("CALL run_job(:j)"), {"j": job_id})
        left = (await auto.execute(text("SELECT session_id FROM sessions"))).scalars().all()
        assert left == ["d"]
        daily = (
            await auto.execute(
                text(
                    "SELECT sensor, sessions, events, login_attempts, logins_succeeded, commands,"
                    " downloads, unique_ips FROM sessions_daily ORDER BY sensor"
                )
            )
        ).all()
        assert [tuple(r) for r in daily] == [
            ("ssh", 2, 14, 8, 1, 2, 1, 2),
            ("telnet", 1, 2, 1, 0, 0, 0, 1),
        ]
        ips = (await auto.execute(text("SELECT host(ip) FROM ip_reputation"))).scalars().all()
        assert ips == ["198.51.100.2"]
        quota = (await auto.execute(text("SELECT used FROM enrichment_quota"))).scalars().all()
        assert quota == [1]


# ---- roles ----------------------------------------------------------------------------------


async def test_api_role_reads_aggregates_but_cannot_write(auto: AsyncConnection) -> None:
    await _insert_event(auto, 2, tags=("recon",))
    await _backfill(auto)
    api = create_async_engine(_role_url("API"))
    try:
        async with api.connect() as conn:
            for view in CAGG_NAMES:
                rows = await conn.execute(text(f"SELECT count(*) FROM {view}"))  # noqa: S608
                assert rows.scalar_one() >= 1
            await conn.execute(text("SELECT count(*) FROM sessions_daily"))
        api_user = os.environ.get("POSTGRES_API_USER", "suckerpot_api")
        ingest_user = os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest")
        for view in ROLLUPS:
            for role, privilege, expected in (
                (api_user, "SELECT", True),
                (api_user, "INSERT", False),
                (api_user, "UPDATE", False),
                (api_user, "DELETE", False),
                (ingest_user, "INSERT", False),
                (ingest_user, "DELETE", False),
            ):
                granted = await auto.execute(
                    text("SELECT has_table_privilege(:r, :t, :p)"),
                    {"r": role, "t": view, "p": privilege},
                )
                assert granted.scalar_one() is expected, (role, view, privilege)
    finally:
        await api.dispose()
