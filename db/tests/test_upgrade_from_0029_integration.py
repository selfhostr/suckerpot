"""M32 participant migration: 0029 goes to 0030 and back (throwaway database only).

Checks that existing rows keep their values (the new ``origin`` defaults to ``local``), that the
prune job still exists, and the least-privilege grants of the new table and column.
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
PRODUCTION = "0029"
HEAD = "0031"


def _alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


async def _jobs() -> None:
    engine = create_async_engine(database_url_from_env(ENV), isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as conn:
            await conn.run_sync(lambda c: apply_retention(c, ENV))
    finally:
        await engine.dispose()


async def _roles_and_jobs() -> None:
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
    _alembic("upgrade", "head")
    await _roles_and_jobs()


async def _columns(engine: AsyncEngine, table: str) -> set[str]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = :t"),
            {"t": table},
        )
        return {r[0] for r in rows}


async def _check_grants(owner: AsyncEngine) -> None:
    api = _role_engine("POSTGRES_API_USER", "POSTGRES_API_PASSWORD")
    ingest = _role_engine("POSTGRES_INGEST_USER", "POSTGRES_INGEST_PASSWORD")
    try:
        async with ingest.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, depth, status, first_seen, "
                    "next_attempt_at, origin) VALUES ('http://files.example.org/a', 'http', "
                    "'files.example.org', 0, 'pending', now(), now(), 'network_verify')"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO network_verify_tasks (hub_id, url, host, state, received_at, "
                    "lease_until) VALUES ('v_1', 'http://files.example.org/a', "
                    "'files.example.org', 'queued', now(), now() + interval '6 hours')"
                )
            )
        assert await _scalar(api, "SELECT count(*) FROM network_verify_tasks") == 1
        assert await _refused(api, "UPDATE network_verify_tasks SET state = 'done'")
        assert await _refused(api, "DELETE FROM network_verify_tasks")
        # Ingest queues verification fetches only: it cannot rewrite their results.
        assert await _refused(ingest, "UPDATE fetch_targets SET status = 'fetched'")
        assert await _refused(
            api, "INSERT INTO fetch_targets (url) VALUES ('http://x.example.org')"
        )
        # The API still cannot write events or sessions.
        assert await _refused(api, "DELETE FROM events")
        assert await _refused(api, "UPDATE sessions SET src_port = 1")
        async with ingest.begin() as conn:
            await conn.execute(text("DELETE FROM network_verify_tasks"))
        async with owner.begin() as conn:
            await conn.execute(text("DELETE FROM fetch_targets WHERE origin = 'network_verify'"))
    finally:
        await api.dispose()
        await ingest.dispose()


async def test_production_0029_upgrades_to_head_and_rolls_back(owner: AsyncEngine) -> None:
    _alembic("downgrade", PRODUCTION)
    await _jobs()
    assert "origin" not in await _columns(owner, "fetch_targets")
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO fetch_targets (url, scheme, host, depth, status, first_seen) "
                "VALUES ('http://old.example.org/x', 'http', 'old.example.org', 0, 'fetched', "
                "now())"
            )
        )

    _alembic("upgrade", "head")
    await _roles_and_jobs()
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == HEAD
    assert "left_day" in await _columns(owner, "network_membership")
    assert (
        await _scalar(
            owner, "SELECT origin FROM fetch_targets WHERE url = 'http://old.example.org/x'"
        )
        == "local"
    )
    assert await _has_table(owner, "network_verify_tasks")
    assert NETWORK_PRUNE_PROC in await _job_procs(owner)
    assert await _dangling_jobs(owner) == []
    await _check_grants(owner)

    # The prune procedure removes reported tasks after 30 days and keeps the others.
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO network_verify_tasks (hub_id, url, host, state, received_at, "
                "lease_until, reported_at) VALUES "
                "('v_old', 'http://a.example.org/', 'a.example.org', 'reported', now(), now(), "
                "now() - interval '31 days'), "
                "('v_new', 'http://b.example.org/', 'b.example.org', 'reported', now(), now(), "
                "now() - interval '2 days'), "
                "('v_open', 'http://c.example.org/', 'c.example.org', 'queued', now(), now(), NULL)"
            )
        )
        await conn.execute(text("CALL suckerpot_network_prune(0, '{}'::jsonb)"))
    assert (
        await _scalar(
            owner, "SELECT string_agg(hub_id, ',' ORDER BY hub_id) FROM network_verify_tasks"
        )
        == "v_new,v_open"
    )

    _alembic("downgrade", PRODUCTION)
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == PRODUCTION
    assert not await _has_table(owner, "network_verify_tasks")
    assert "origin" not in await _columns(owner, "fetch_targets")
    assert await _dangling_jobs(owner) == []
    await _jobs()
    async with owner.begin() as conn:  # the 0028 procedure body still runs
        await conn.execute(text("CALL suckerpot_network_prune(0, '{}'::jsonb)"))
    assert (
        await _scalar(
            owner, "SELECT count(*) FROM fetch_targets WHERE url = 'http://old.example.org/x'"
        )
        == 1
    )
