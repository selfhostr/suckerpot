"""M21 schema: the chain goes down and up, and the new roles hold exactly their grants."""

import os
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration
# ruff: noqa: S608  (test SQL is built from constants)

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
TABLES = ("fetch_targets", "fetch_attempts", "samples", "sample_analysis", "sample_sources",
          "sample_links")  # fmt: skip
SHA = "a" * 64
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": "collector-test-password",
    "POSTGRES_ANALYZER_PASSWORD": "analyzer-test-password",
}


def _alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


async def _roles(env: Mapping[str, str]) -> None:
    engine = create_async_engine(database_url_from_env(env))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: apply_roles(c, env))
    finally:
        await engine.dispose()


def _as(user: str, password: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env({**ENV, "POSTGRES_USER": user, "POSTGRES_PASSWORD": password})
    )


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    await _roles(ENV)
    await _roles(ENV)  # idempotent
    engine = create_async_engine(database_url_from_env(ENV))
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join(TABLES)} CASCADE"))
    yield engine
    await engine.dispose()


async def _can(engine: AsyncEngine, sql: str, params: dict[str, object] | None = None) -> bool:
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params or {})
    except DBAPIError as exc:
        assert getattr(exc.orig, "sqlstate", None) == "42501", exc  # insufficient_privilege
        return False
    return True


async def _allowed(engine: AsyncEngine, sql: str, params: dict[str, object] | None = None) -> bool:
    """True when the statement is allowed, False when row level security refuses it."""
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params or {})
    except DBAPIError as exc:
        assert getattr(exc.orig, "sqlstate", None) == "42501", exc
        return False
    return True


async def test_down_and_up_again(owner: AsyncEngine) -> None:
    async def exists(table: str) -> bool:
        async with owner.connect() as conn:
            return bool(await conn.scalar(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table}))

    assert all([await exists(t) for t in TABLES])
    _alembic("downgrade", "0017")
    assert not any([await exists(t) for t in TABLES])
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "0017"
    _alembic("upgrade", "head")
    assert all([await exists(t) for t in TABLES])
    await _roles(ENV)


async def test_the_c2_role_is_accepted(owner: AsyncEngine) -> None:
    sql = (
        "INSERT INTO indicators (type, value, role, first_seen, last_seen) "
        "VALUES ('ip', '203.0.113.9', :role, now(), now()) ON CONFLICT DO NOTHING"
    )
    async with owner.begin() as conn:
        await conn.execute(text(sql), {"role": "c2"})
    with pytest.raises(DBAPIError):
        async with owner.begin() as conn:
            await conn.execute(text(sql), {"role": "nope"})


async def test_collector_and_analyzer_grants(owner: AsyncEngine) -> None:
    ins = (
        "INSERT INTO fetch_targets (url, scheme, host, first_seen) "
        "VALUES (:u, 'http', '203.0.113.9', now())"
    )
    collector = _as("suckerpot_collector", ENV["POSTGRES_COLLECTOR_PASSWORD"])
    analyzer = _as("suckerpot_analyzer", ENV["POSTGRES_ANALYZER_PASSWORD"])
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    ingest = _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"])
    try:
        # Collector: writes targets, attempts, samples and sources; reads indicators.
        assert await _can(collector, ins, {"u": "http://203.0.113.9/a.sh"})
        assert await _can(
            collector,
            "INSERT INTO fetch_attempts (target_id, started_at, outcome) "
            "SELECT id, now(), 'ok' FROM fetch_targets",
        )
        assert await _can(
            collector,
            "INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen) "
            f"VALUES ('{SHA}', 'x', 'y', 10, now(), now())",
        )
        assert await _can(
            collector,
            f"INSERT INTO sample_sources VALUES ('{SHA}', (SELECT min(id) FROM fetch_targets), "
            "now(), now())",
        )
        assert await _can(collector, "UPDATE samples SET last_seen = now()")
        assert await _can(collector, "SELECT count(*) FROM indicators")
        assert await _can(collector, "DELETE FROM fetch_attempts")
        assert not await _can(collector, "DELETE FROM samples")
        assert not await _can(collector, "DELETE FROM fetch_targets")
        assert not await _can(collector, "UPDATE indicators SET sightings = 2")
        # Row level security: only its own status and quota rows.
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO enrichment_status (name) VALUES ('egress'), ('collector') "
                    "ON CONFLICT DO NOTHING"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO enrichment_quota (provider, day, used) VALUES "
                    "('abuseipdb', current_date, 5), ('collector', current_date, 1) "
                    "ON CONFLICT DO NOTHING"
                )
            )
        upsert = (
            "INSERT INTO enrichment_status (name, detail) VALUES (:n, '{}') "
            "ON CONFLICT (name) DO UPDATE SET detail = EXCLUDED.detail"
        )
        assert await _can(collector, upsert, {"n": "collector"})
        assert await _can(collector, upsert, {"n": "egress_collector"})
        assert not await _allowed(collector, upsert, {"n": "egress"})
        assert not await _allowed(collector, upsert, {"n": "ingest_x"})
        async with collector.connect() as conn:
            names = {r[0] for r in await conn.execute(text("SELECT name FROM enrichment_status"))}
            assert names == {"collector", "egress_collector"}
            await conn.execute(text("UPDATE enrichment_quota SET used = 99"))
            await conn.rollback()
        async with owner.connect() as conn:
            rows = {
                r[0]: r[1]
                for r in await conn.execute(text("SELECT provider, used FROM enrichment_quota"))
            }
            assert rows["abuseipdb"] == 5
            assert (
                await conn.scalar(
                    text("SELECT detail->>'x' FROM enrichment_status WHERE name = 'egress'")
                )
                is None
            )
        # Ingest and API are unaffected: they see every row.
        for eng in (ingest, api):
            async with eng.connect() as conn:
                assert await conn.scalar(text("SELECT count(*) FROM enrichment_status")) >= 3
                assert await conn.scalar(text("SELECT count(*) FROM enrichment_quota")) >= 2
        assert await _can(ingest, upsert, {"n": "egress"})
        assert not await _can(api, upsert, {"n": "egress"})
        assert not await _can(collector, "SELECT count(*) FROM sample_analysis")
        assert await _can(collector, "SELECT count(*) FROM sample_links")  # read only
        assert not await _can(collector, "UPDATE sample_links SET source = 'web_asset'")
        assert not await _can(collector, "SELECT count(*) FROM events")
        assert not await _can(collector, "SELECT count(*) FROM users")

        # Analyzer: findings and next-stage URLs; no attempts, no events, no deletes.
        assert await _can(analyzer, "UPDATE samples SET analysis_status = 'done'")
        assert not await _can(analyzer, "SELECT count(*) FROM enrichment_status")
        assert not await _can(analyzer, "SELECT count(*) FROM enrichment_quota")
        assert await _can(
            analyzer, "UPDATE indicators SET last_seen = now(), sightings = sightings + 1"
        )
        assert not await _can(analyzer, "UPDATE indicators SET value = 'x'")
        assert not await _can(analyzer, "UPDATE indicators SET role = 'c2', host = 'x'")
        assert await _can(
            analyzer,
            f"INSERT INTO sample_analysis (sha256, analyzed_at) VALUES ('{SHA}', now())",
        )
        assert await _can(analyzer, ins, {"u": "http://203.0.113.9/b.sh"})
        assert await _can(
            analyzer,
            f"INSERT INTO sample_links (sha256, kind, value, source, confidence) "
            f"VALUES ('{SHA}', 'next_url', 'http://203.0.113.9/b.sh', 'script', 'high')",
        )
        assert await _can(
            analyzer,
            "INSERT INTO indicators (type, value, role, first_seen, last_seen) "
            "VALUES ('ip', '198.51.100.4', 'c2', now(), now())",
        )
        assert not await _can(analyzer, "UPDATE fetch_targets SET status = 'fetched'")
        # 0033: it may only put a target refused as web_parent back in the queue, nothing else.
        revive = "SELECT suckerpot_revive_web_target(:t, now())"
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, first_seen, status, last_error) "
                    "VALUES ('http://203.0.113.9/w.css', 'http', '203.0.113.9', now(), "
                    "'refused', 'web_parent'), ('http://203.0.113.9/r.sh', 'http', "
                    "'203.0.113.9', now(), 'refused', 'private_address')"
                )
            )
            found = await conn.execute(text("SELECT url, id FROM fetch_targets"))
            ids: dict[str, int] = {str(u): int(i) for u, i in found.tuples().all()}
        for url in ("http://203.0.113.9/w.css", "http://203.0.113.9/r.sh"):
            assert await _can(analyzer, revive, {"t": ids[url]})
        async with owner.connect() as conn:
            found = await conn.execute(text("SELECT url, status FROM fetch_targets"))
            after: dict[str, str] = {str(u): str(st) for u, st in found.tuples().all()}
        assert after["http://203.0.113.9/w.css"] == "pending"
        assert after["http://203.0.113.9/r.sh"] == "refused"  # any other refusal stays
        for other in (collector, api, ingest):
            assert not await _can(other, revive, {"t": ids["http://203.0.113.9/w.css"]})
        assert not await _can(analyzer, "SELECT count(*) FROM fetch_attempts")
        assert not await _can(analyzer, "DELETE FROM sample_analysis")
        assert not await _can(analyzer, "SELECT count(*) FROM events")
        assert not await _can(analyzer, "SELECT count(*) FROM provider_secrets")

        # API: read-only on every new table. Ingest (M22 drafts): reads the four payload tables
        # and nothing else.
        for table in TABLES:
            assert await _can(api, f"SELECT count(*) FROM {table}")
            readable = table in ("fetch_targets", "samples", "sample_links", "sample_sources")
            assert await _can(ingest, f"SELECT count(*) FROM {table}") == readable, table
        assert not await _can(api, ins, {"u": "http://203.0.113.9/c.sh"})
        assert not await _can(api, "UPDATE samples SET family = 'x'")
        assert not await _can(api, "DELETE FROM samples")
        assert not await _can(
            api,
            f"INSERT INTO sample_analysis (sha256, analyzed_at) VALUES ('{SHA}', now())",
        )
    finally:
        for engine in (collector, analyzer, api, ingest):
            await engine.dispose()


async def test_roles_are_skipped_without_their_password(owner: AsyncEngine) -> None:
    env = {k: v for k, v in ENV.items() if "COLLECTOR_PASSWORD" not in k}
    await _roles(env)  # must not raise, and must leave the existing roles alone
