"""Production path: a database at 0027 (M26/M27, the deployed head) with data goes to head and back.

The M29 node migration (0028, the opt-in network) is deployed; 0029 adds the M30 feed tables.
This replays what the
``migrate`` service does on an existing install (upgrade, roles, retention jobs), then the
rollback, and checks that nothing that existed at 0027 is lost or left dangling either way, and
that the network tables arrive with their least-privilege grants.
"""

import os
import subprocess
import sys
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.retention import NETWORK_PRUNE_PROC, apply_retention
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration

DB_DIR = os.environ.get("DB_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": "collector-test-password",
    "POSTGRES_ANALYZER_PASSWORD": "analyzer-test-password",
}
PRODUCTION = "0027"
HEAD = "0031"
NETWORK_TABLES = ("network_membership", "network_submissions", "network_targets", "network_summary")
NEW_REPORT = (
    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo, window_start, "
    "window_end, evidence, content_sha256, guard_ok, status) VALUES (gen_random_uuid(), "
    "gen_random_uuid(), (SELECT min(id) FROM abuse_recipients), :kind, false, now(), now(), "
    "'{}', 'x', true, :status)"
)
# What must survive both directions: (label, query returning one comparable value).
SNAPSHOT = (
    ("events", "SELECT count(*) FROM events WHERE session_id LIKE 'prod-0027-%'"),
    ("sessions", "SELECT count(*) FROM sessions WHERE session_id LIKE 'prod-0027-%'"),
    ("recipients", "SELECT count(*) FROM abuse_recipients"),
    ("reports", "SELECT string_agg(kind || ':' || status, ',' ORDER BY id) FROM abuse_reports"),
    ("tokens", "SELECT count(DISTINCT reply_token) FROM abuse_reports"),
    ("outcomes", "SELECT string_agg(auto_outcome, ',' ORDER BY report_id) "
                 "FROM abuse_report_outcomes"),
    ("submissions", "SELECT string_agg(platform || ':' || value, ',' ORDER BY id) "
                    "FROM abusech_submissions"),
    ("settings", "SELECT reply_contact FROM report_settings WHERE id = 1"),
    ("setup", "SELECT steps::text || coalesce(finished_by, '') FROM setup_progress WHERE id = 1"),
)  # fmt: skip


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
    """What the migrate entrypoint does after ``alembic upgrade head``: roles, then the jobs."""
    engine = create_async_engine(database_url_from_env(ENV))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: apply_roles(c, ENV))
    finally:
        await engine.dispose()
    await _jobs()


def _role_engine(user_key: str, password_key: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env(
            {**ENV, "POSTGRES_USER": ENV[user_key], "POSTGRES_PASSWORD": ENV[password_key]}
        )
    )


async def _scalar(engine: AsyncEngine, sql: str, params: dict[str, str] | None = None) -> object:
    async with engine.connect() as conn:
        return await conn.scalar(text(sql), params or {})


async def _refused(engine: AsyncEngine, sql: str) -> bool:
    """True when the role may not run ``sql`` (insufficient privilege)."""
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql))
    except DBAPIError as exc:
        return "permission denied" in str(exc.orig).lower()
    return False


async def _snapshot(engine: AsyncEngine) -> dict[str, object]:
    return {label: await _scalar(engine, sql) for label, sql in SNAPSHOT}


async def _has_table(engine: AsyncEngine, name: str) -> bool:
    return bool(
        await _scalar(engine, "SELECT to_regclass(:n) IS NOT NULL", {"n": f"public.{name}"})
    )


async def _job_procs(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT proc_name FROM timescaledb_information.jobs"))
        return {r[0] for r in rows}


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
        # TRUNCATE ... CASCADE also empties what hangs off them (replies, outcomes, links).
        await conn.execute(text("TRUNCATE abuse_recipients, abusech_submissions CASCADE"))
        await conn.execute(text("DELETE FROM events WHERE session_id LIKE 'prod-0027-%'"))
        await conn.execute(text("DELETE FROM sessions WHERE session_id LIKE 'prod-0027-%'"))
        for i in range(3):
            sid = f"prod-0027-{i}"
            await conn.execute(
                text(
                    "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                    "started_at, last_event_at) VALUES (:s, 'ssh', '192.0.2.20', 40000, 22, "
                    "now() - interval '1 hour', now())"
                ),
                {"s": sid},
            )
            await conn.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,"
                    " data) VALUES (now() - interval '1 hour', 'ssh', :s, 'connect', "
                    "'192.0.2.20', 40000, 22, '{}'::jsonb)"
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
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'sent', sent_at = now() - interval '3 days', "
                "sent_by = 'admin', sent_via = 'manual' WHERE kind = 'c2'"
            )
        )
        # M26: an outcome on the sent report. M27: one abuse.ch candidate.
        await conn.execute(
            text(
                "INSERT INTO abuse_report_outcomes (report_id, auto_outcome) "
                "SELECT id, 'resolved' FROM abuse_reports WHERE kind = 'c2'"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO abusech_submissions (platform, ioc_type, value, threat, lookup) "
                "VALUES ('urlhaus', 'url', 'http://198.51.100.7/bins/x.sh', "
                "'malware_download', 'unknown')"
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
                """VALUES (1, '{"welcome": "done", "network": "skipped"}', now(), 'admin') """
                "ON CONFLICT (id) DO UPDATE SET steps = EXCLUDED.steps, "
                "finished_at = EXCLUDED.finished_at, finished_by = EXCLUDED.finished_by"
            )
        )


async def _check_network_grants() -> None:
    """Least privilege on the new tables, for the roles the update (re)applies."""
    api = _role_engine("POSTGRES_API_USER", "POSTGRES_API_PASSWORD")
    ingest = _role_engine("POSTGRES_INGEST_USER", "POSTGRES_INGEST_PASSWORD")
    try:
        # The API reads the membership without the private key, and writes the owner's wish only.
        assert await _scalar(api, "SELECT desired || ':' || state FROM network_membership") == (
            "off:off"
        )
        assert await _refused(api, "SELECT privkey_enc FROM network_membership")
        assert await _refused(api, "UPDATE network_membership SET state = 'member'")
        assert await _refused(api, "DELETE FROM network_membership")
        for table in ("network_submissions", "network_targets", "network_summary"):
            assert await _scalar(api, f"SELECT count(*) FROM {table}") == 0  # noqa: S608
            assert await _refused(api, f"DELETE FROM {table}")  # noqa: S608
        # Ingest runs the worker: it reads the key column, but cannot add a membership row.
        assert await _scalar(ingest, "SELECT count(privkey_enc) FROM network_membership") == 0
        assert await _refused(ingest, "INSERT INTO network_membership (id) VALUES (2)")
        # The M26/M27 grants are still in place next to the new ones.
        assert await _scalar(api, "SELECT count(*) FROM takedown_targets") is not None
        assert await _scalar(api, "SELECT finished_by FROM setup_progress") == "admin"
    finally:
        await api.dispose()
        await ingest.dispose()


async def test_production_0027_upgrades_to_head_and_rolls_back(owner: AsyncEngine) -> None:
    # 1. Production as deployed: 0027 with its retention jobs, data in.
    _alembic("downgrade", PRODUCTION)
    await _jobs()
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == PRODUCTION
    for table in NETWORK_TABLES:
        assert not await _has_table(owner, table), table
    assert NETWORK_PRUNE_PROC not in await _job_procs(owner)
    await _seed_production_data(owner)
    before = await _snapshot(owner)
    assert before["events"] == 3 and before["reports"] == "c2:sent,payload_host:draft"
    assert before["outcomes"] == "resolved" and before["tokens"] == 2

    # 2. The update: upgrade head, then roles and jobs again.
    _alembic("upgrade", "head")
    await _roles_and_jobs()
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == HEAD
    assert await _snapshot(owner) == before
    for table in NETWORK_TABLES:
        assert await _has_table(owner, table), table
    assert await _scalar(owner, "SELECT count(*) FROM network_membership") == 1
    procs = await _job_procs(owner)
    assert {"suckerpot_abuse_prune", "suckerpot_takedown_prune", NETWORK_PRUNE_PROC} <= procs
    assert await _dangling_jobs(owner) == []
    await _check_network_grants()

    # 3. The rollback: back to 0027 with nothing from 0027 lost and no job left behind.
    _alembic("downgrade", PRODUCTION)
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == PRODUCTION
    assert await _snapshot(owner) == before
    for table in NETWORK_TABLES:
        assert not await _has_table(owner, table), table
    assert await _dangling_jobs(owner) == []
    assert NETWORK_PRUNE_PROC not in await _job_procs(owner)
    # Rescheduling the jobs after the rollback still succeeds and skips the network job.
    await _jobs()
    assert await _snapshot(owner) == before
    assert NETWORK_PRUNE_PROC not in await _job_procs(owner)

    # 4. Updating again after a rollback works the same way.
    _alembic("upgrade", "head")
    await _roles_and_jobs()
    assert await _snapshot(owner) == before
    assert await _scalar(owner, "SELECT count(*) FROM network_membership") == 1
