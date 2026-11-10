"""Production path: a database at 0028 (M29 network, the deployed head) goes to 0029 and back.

Replays what the ``migrate`` service does on an existing install (upgrade, roles, jobs), then
the rollback. Checks that the 0028 data and the events/sessions survive both ways, that no job
is left dangling, and that the M30 feed tables arrive with their least-privilege grants.
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
PRODUCTION = "0028"
HEAD = "0031"
FEED_TABLES = ("network_feed_state", "network_feed_entries")
SNAPSHOT = (
    ("events", "SELECT count(*) FROM events WHERE session_id LIKE 'prod-0028-%'"),
    ("sessions", "SELECT count(*) FROM sessions WHERE session_id LIKE 'prod-0028-%'"),
    ("membership", "SELECT desired || ':' || state || ':' || pseudonym FROM network_membership"),
    ("targets", "SELECT string_agg(hub_id || ':' || value, ',' ORDER BY hub_id) "
                "FROM network_targets"),
    ("summary", "SELECT data::text FROM network_summary WHERE id = 1"),
    ("submissions", "SELECT string_agg(batch_id || ':' || status, ',' ORDER BY day) "
                    "FROM network_submissions"),
)  # fmt: skip


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
        await conn.execute(text("DELETE FROM events WHERE session_id LIKE 'prod-0028-%'"))
        await conn.execute(text("DELETE FROM sessions WHERE session_id LIKE 'prod-0028-%'"))
        for table in ("network_submissions", "network_targets", "network_summary"):
            await conn.execute(text(f"DELETE FROM {table}"))  # noqa: S608
        for i in range(3):
            sid = f"prod-0028-{i}"
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
                "UPDATE network_membership SET desired = 'member', state = 'member', "
                "pseudonym = 'quiet-node'"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO network_targets (hub_id, kind, value, state, nodes, first_day, "
                "last_day) VALUES ('t_000000000001', 'ip', '198.51.100.7', 'confirmed', 2, "
                "current_date, current_date)"
            )
        )
        await conn.execute(text("INSERT INTO network_summary (id, data) VALUES (1, '{\"n\": 3}')"))
        await conn.execute(
            text(
                "INSERT INTO network_submissions (day, batch_id, status) "
                "VALUES (current_date, 'b0028', 'sent')"
            )
        )


async def _check_feed_grants() -> None:
    """Least privilege on the feed tables, for the roles the update (re)applies."""
    api = _role_engine("POSTGRES_API_USER", "POSTGRES_API_PASSWORD")
    ingest = _role_engine("POSTGRES_INGEST_USER", "POSTGRES_INGEST_PASSWORD")
    try:
        # Ingest (the feed worker) writes state and entries, then removes them.
        async with ingest.begin() as conn:
            await conn.execute(text("INSERT INTO network_feed_state (id, serial) VALUES (1, 7)"))
            await conn.execute(
                text(
                    "INSERT INTO network_feed_entries (list, value, family, tier, categories) "
                    "VALUES ('inbound', '203.0.113.9', 4, 'high', ARRAY['scanner'])"
                )
            )
            await conn.execute(text("UPDATE network_feed_entries SET seen_here = true"))
        # The API reads both and writes neither.
        assert await _scalar(api, "SELECT serial FROM network_feed_state") == 7
        assert await _scalar(api, "SELECT value FROM network_feed_entries") == "203.0.113.9"
        for table in FEED_TABLES:
            assert await _refused(api, f"DELETE FROM {table}")  # noqa: S608
        assert await _refused(api, "UPDATE network_feed_state SET serial = 1")
        assert await _refused(
            api, "INSERT INTO network_feed_entries (list, value) VALUES ('a','b')"
        )
        async with ingest.begin() as conn:
            await conn.execute(text("DELETE FROM network_feed_entries"))
            await conn.execute(text("DELETE FROM network_feed_state"))
        # The M29 grants are still in place next to the new ones.
        assert await _refused(api, "SELECT privkey_enc FROM network_membership")
        assert await _scalar(api, "SELECT count(*) FROM network_targets") == 1
    finally:
        await api.dispose()
        await ingest.dispose()


async def test_production_0028_upgrades_to_head_and_rolls_back(owner: AsyncEngine) -> None:
    # 1. Production as deployed: 0028 with its network job, data in.
    _alembic("downgrade", PRODUCTION)
    await _jobs()
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == PRODUCTION
    for table in FEED_TABLES:
        assert not await _has_table(owner, table), table
    await _seed_production_data(owner)
    before = await _snapshot(owner)
    assert before["events"] == 3 and before["targets"] == "t_000000000001:198.51.100.7"

    # 2. The update: upgrade head, then roles and jobs again.
    _alembic("upgrade", "head")
    await _roles_and_jobs()
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == HEAD
    assert await _snapshot(owner) == before
    for table in FEED_TABLES:
        assert await _has_table(owner, table), table
    assert await _scalar(owner, "SELECT count(*) FROM network_feed_state") == 0
    assert NETWORK_PRUNE_PROC in await _job_procs(owner)
    assert await _dangling_jobs(owner) == []
    await _check_feed_grants()

    # 3. The rollback: back to 0028 with nothing from 0028 lost and no job left behind.
    _alembic("downgrade", PRODUCTION)
    assert await _scalar(owner, "SELECT version_num FROM alembic_version") == PRODUCTION
    assert await _snapshot(owner) == before
    for table in FEED_TABLES:
        assert not await _has_table(owner, table), table
    assert await _dangling_jobs(owner) == []
    assert NETWORK_PRUNE_PROC in await _job_procs(owner)
    await _jobs()
    assert await _snapshot(owner) == before

    # 4. Updating again after a rollback works the same way.
    _alembic("upgrade", "head")
    await _roles_and_jobs()
    assert await _snapshot(owner) == before
    assert await _has_table(owner, "network_feed_entries")
