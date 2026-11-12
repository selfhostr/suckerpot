"""Production path: a database at 0025 (M28, the deployed head) with data goes to head and back.

The M26 and M27 migrations (0026, 0027) were not deployed when this was written; M29 (0028) adds
the network tables on top, and ``test_upgrade_from_0027_integration`` covers today's deployed
head. This replays what the ``migrate`` service does on an existing install (upgrade, roles,
retention jobs), then the rollback, and checks that nothing that existed at 0025 is lost or left
dangling either way.
"""

import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.retention import apply_retention
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": "collector-test-password",
    "POSTGRES_ANALYZER_PASSWORD": "analyzer-test-password",
}
PRODUCTION = "0025"
# 0026, 0027 (M26, M27), 0028 (M29 network), 0029 (M30 feed); see the 0027 test as well
HEAD = "0033"
M26_M27_TABLES = (
    "report_imap",
    "report_imap_state",
    "report_imap_requests",
    "abuse_replies",
    "abuse_reply_imports",
    "abuse_report_outcomes",
    "takedown_targets",
    "takedown_checks",
    "takedown_target_links",
    "abusech_submission",
    "abusech_submissions",
    "outcome_rollup_monthly",
)
NEW_COLUMNS = (
    ("abuse_reports", "reply_token"),
    ("abuse_send_requests", "message_id"),
    ("abuse_recipients", "reply_domains"),
    ("report_settings", "reference_style"),
)
NEW_REPORT = (
    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo, window_start, "
    "window_end, evidence, content_sha256, guard_ok, status) VALUES (gen_random_uuid(), "
    "gen_random_uuid(), (SELECT min(id) FROM abuse_recipients), :kind, false, now(), now(), "
    "'{}', 'x', true, :status)"
)
# What must survive both directions: (label, query returning one comparable value).
SNAPSHOT = (
    ("events", "SELECT count(*) FROM events WHERE session_id LIKE 'prod-0025-%'"),
    ("sessions", "SELECT count(*) FROM sessions WHERE session_id LIKE 'prod-0025-%'"),
    ("recipients", "SELECT count(*) FROM abuse_recipients"),
    ("reports", "SELECT string_agg(kind || ':' || status, ',' ORDER BY id) FROM abuse_reports"),
    ("send_requests", "SELECT count(*) FROM abuse_send_requests"),
    ("settings", "SELECT reply_contact FROM report_settings WHERE id = 1"),
    ("setup", "SELECT steps::text || coalesce(finished_by, '') FROM setup_progress WHERE id = 1"),
)


def _alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


async def _jobs() -> None:
    """The retention jobs, as the migrate entrypoint schedules them (autocommit)."""
    engine = create_async_engine(database_url_from_env(ENV), isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as conn:
            await conn.run_sync(lambda c: apply_retention(c, ENV))
    finally:
        await engine.dispose()


async def _roles_and_jobs() -> None:
    """What the migrate entrypoint does after ``alembic upgrade head``: roles, then the jobs.

    Only valid at head: the role script grants columns that 0026 adds. At 0025 the deployed
    0025 image applies its own roles, so the test only schedules the jobs there.
    """
    engine = create_async_engine(database_url_from_env(ENV))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: apply_roles(c, ENV))
    finally:
        await engine.dispose()
    await _jobs()


async def _scalar(engine: AsyncEngine, sql: str, params: dict[str, str] | None = None) -> object:
    async with engine.connect() as conn:
        return await conn.scalar(text(sql), params or {})


async def _snapshot(engine: AsyncEngine) -> dict[str, object]:
    return {label: await _scalar(engine, sql) for label, sql in SNAPSHOT}


async def _has_table(engine: AsyncEngine, name: str) -> bool:
    return bool(
        await _scalar(engine, "SELECT to_regclass(:n) IS NOT NULL", {"n": f"public.{name}"})
    )


async def _has_column(engine: AsyncEngine, table: str, column: str) -> bool:
    return bool(
        await _scalar(
            engine,
            "SELECT count(*) = 1 FROM information_schema.columns WHERE table_schema = 'public' "
            "AND table_name = :t AND column_name = :c",
            {"t": table, "c": column},
        )
    )


async def _dangling_jobs(engine: AsyncEngine) -> list[str]:
    """Jobs whose procedure no longer exists (they would fail on every run)."""
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT proc_name FROM timescaledb_information.jobs "
                "WHERE proc_schema = 'public' AND to_regproc('public.' || proc_name) IS NULL"
            )
        )
        return [r[0] for r in rows]


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    # Destructive: it downgrades the database it is pointed at. Only a throwaway project.
    if "-it-" not in os.environ.get("COMPOSE_PROJECT_NAME", ""):
        pytest.skip("destructive test: needs a throwaway COMPOSE_PROJECT_NAME containing '-it-'")
    _alembic("upgrade", "head")
    engine = create_async_engine(database_url_from_env(ENV))
    yield engine
    await engine.dispose()
    # Leave the database at head with roles and jobs, as the other tests expect it.
    _alembic("upgrade", "head")
    await _roles_and_jobs()


async def _seed_production_data(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_send_requests"))
        await conn.execute(text("DELETE FROM abuse_reports"))
        await conn.execute(text("TRUNCATE abuse_recipients CASCADE"))
        await conn.execute(text("DELETE FROM events WHERE session_id LIKE 'prod-0025-%'"))
        await conn.execute(text("DELETE FROM sessions WHERE session_id LIKE 'prod-0025-%'"))
        for i in range(3):
            sid = f"prod-0025-{i}"
            await conn.execute(
                text(
                    "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                    "started_at, last_event_at) VALUES (:s, 'ssh', '192.0.2.10', 40000, 22, "
                    "now() - interval '1 hour', now())"
                ),
                {"s": sid},
            )
            await conn.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,"
                    " data) VALUES (now() - interval '1 hour', 'ssh', :s, 'connect', "
                    "'192.0.2.10', 40000, 22, '{}'::jsonb)"
                ),
                {"s": sid},
            )
        await conn.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, source) "
                "VALUES ('abuse@example.net', 'rdap')"
            )
        )
        for kind, status in (("c2", "reviewed"), ("payload_host", "draft")):
            await conn.execute(text(NEW_REPORT), {"kind": kind, "status": status})
        # The owner counts as ingest for the guard: an automatic send, queued before the send.
        await conn.execute(
            text(
                "INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by) "
                "SELECT id, 'send', true, 'auto' FROM abuse_reports WHERE kind = 'c2'"
            )
        )
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'sent', sent_at = now() - interval '3 days', "
                "sent_by = 'admin', sent_via = 'manual' WHERE kind = 'c2'"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO report_settings (id, reply_contact) "
                "VALUES (1, 'reports@example.org') "
                "ON CONFLICT (id) DO UPDATE SET reply_contact = EXCLUDED.reply_contact"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO setup_progress (id, steps, finished_at, finished_by) "
                """VALUES (1, '{"welcome": "done", "vpn": "skipped"}', now(), 'admin') """
                "ON CONFLICT (id) DO UPDATE SET steps = EXCLUDED.steps, "
                "finished_at = EXCLUDED.finished_at, finished_by = EXCLUDED.finished_by"
            )
        )


async def test_production_0025_upgrades_to_head_and_rolls_back(owner: AsyncEngine) -> None:
    # 1. Production as deployed: 0025 with its retention jobs, data in.
    _alembic("downgrade", PRODUCTION)
    await _jobs()
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == PRODUCTION
    for table in M26_M27_TABLES:
        assert not await _has_table(owner, table), table
    await _seed_production_data(owner)
    before = await _snapshot(owner)
    assert before["events"] == 3 and before["reports"] == "c2:sent,payload_host:draft"

    # 2. The update: upgrade head, then roles and jobs again.
    _alembic("upgrade", "head")
    await _roles_and_jobs()
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == HEAD
    assert await _snapshot(owner) == before
    for table in M26_M27_TABLES:
        assert await _has_table(owner, table), table
    for table, column in NEW_COLUMNS:
        assert await _has_column(owner, table, column), f"{table}.{column}"
    async with owner.connect() as conn:
        tokens = [r[0] for r in await conn.execute(text("SELECT reply_token FROM abuse_reports"))]
    assert len(tokens) == 2 and len(set(tokens)) == 2  # existing reports got distinct tokens
    async with owner.connect() as conn:
        procs = {
            r[0]
            for r in await conn.execute(text("SELECT proc_name FROM timescaledb_information.jobs"))
        }
    assert {"suckerpot_abuse_prune", "suckerpot_takedown_prune"} <= procs
    assert await _dangling_jobs(owner) == []
    # Both sides' grants are in place: M28 setup progress and M27 targets for the API role.
    api = create_async_engine(
        database_url_from_env(
            {
                **ENV,
                "POSTGRES_USER": ENV["POSTGRES_API_USER"],
                "POSTGRES_PASSWORD": ENV["POSTGRES_API_PASSWORD"],
            }
        )
    )
    try:
        assert await _scalar(api, "SELECT finished_by FROM setup_progress") == "admin"
        assert await _scalar(api, "SELECT count(*) FROM takedown_targets") is not None
        assert await _scalar(api, "SELECT count(*) FROM abuse_report_outcomes") is not None
    finally:
        await api.dispose()

    # 3. The rollback: back to 0025 with nothing from 0025 lost and no job left behind.
    _alembic("downgrade", PRODUCTION)
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == PRODUCTION
    assert await _snapshot(owner) == before
    for table in M26_M27_TABLES:
        assert not await _has_table(owner, table), table
    for table, column in NEW_COLUMNS:
        assert not await _has_column(owner, table, column), f"{table}.{column}"
    assert await _dangling_jobs(owner) == []
    # Rescheduling the jobs after the rollback still succeeds.
    await _jobs()
    assert await _snapshot(owner) == before
