"""Fixtures. Integration tests need a throwaway PostgreSQL named by HUB_TEST_DATABASE_URL.

HUB_TEST_DATABASE_URL is the OWNER url (``postgresql+asyncpg://user:pw@host/db``). The schema is
dropped and rebuilt at the start of the session, so it must point at a disposable database.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from suckerpot_netproto import sign

from hub.config import Settings
from hub.context import AppContext
from hub.main import create_app
from hub.roles import API_ROLE, WORKER_ROLE, apply_roles

from .helpers import FakeClock, NodeClient

HUB_DIR = Path(__file__).resolve().parent.parent
OWNER_URL = os.environ.get("HUB_TEST_DATABASE_URL", "")
API_PASSWORD = "hubtest-api-password-0002"
WORKER_PASSWORD = "hubtest-worker-password-0003"
TABLES = (
    "hub_audit, never_list, network_summary, network_daily, node_stats_weekly, recipient_log, "
    "reports, takedown_votes, target_contributors, targets, observations, batches, nonces, "
    "enrol_challenges, nodes, worker_state, payload_links, target_hosts, feed_entries, feed_runs, "
    "feed_daily, feed_allow, feed_auto_ranges, delist_challenges, delist_requests, "
    "abusech_submissions, node_roles, verify_tasks, verify_attestations, verify_daily, "
    "observatory_daily"
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if OWNER_URL:
        return
    skip = pytest.mark.skip(reason="HUB_TEST_DATABASE_URL is not set")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


def _url_for(role: str, password: str) -> str:
    return (
        make_url(OWNER_URL)
        .set(username=role, password=password)
        .render_as_string(hide_password=False)
    )


async def _reset_schema() -> None:
    engine = create_async_engine(OWNER_URL)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
    finally:
        await engine.dispose()


async def _roles() -> None:
    engine = create_async_engine(OWNER_URL)
    env = {"HUB_API_DB_PASSWORD": API_PASSWORD, "HUB_WORKER_DB_PASSWORD": WORKER_PASSWORD}
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: apply_roles(c, env))
    finally:
        await engine.dispose()


def _build_schema() -> None:
    asyncio.run(_reset_schema())
    env = {**os.environ, "HUB_MIGRATE_DATABASE_URL": OWNER_URL}
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", "-c", str(HUB_DIR / "alembic.ini"), "upgrade", "head"],
        check=True,
        cwd=HUB_DIR,
        env=env,
    )
    asyncio.run(_roles())


def pytest_collection_finish(session: pytest.Session) -> None:
    """Rebuild the throwaway schema once, before any event loop runs."""
    if OWNER_URL and any("integration" in item.keywords for item in session.items):
        _build_schema()


@pytest_asyncio.fixture(autouse=True)
async def clean(request: pytest.FixtureRequest) -> AsyncIterator[None]:
    if "integration" not in request.keywords or not OWNER_URL:
        yield
        return
    engine = create_async_engine(OWNER_URL)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {TABLES} RESTART IDENTITY CASCADE"))
    await engine.dispose()
    yield


@dataclass
class Env:
    client: NodeClient
    http: httpx.AsyncClient
    clock: FakeClock
    ctx: AppContext
    worker: async_sessionmaker[AsyncSession]
    owner: AsyncEngine
    settings: Settings
    hub_key: str

    def node(self) -> NodeClient:
        return NodeClient(self.http, self.clock, self.hub_key)

    async def enrolled(self, count: int = 1, **kw: Any) -> list[NodeClient]:
        out = []
        for _ in range(count):
            node = self.node()
            reply = await node.enrol(**kw)
            assert reply.status == 200, reply.json
            out.append(node)
        return out


def make_settings(**over: Any) -> Settings:
    base: dict[str, Any] = {
        "allow_documentation": True,
        "pow_difficulty": 6,
        "unsigned_per_min": 1000,
        "unsigned_per_day": 100000,
        "auth_failures_per_min": 1000,
        "challenges_per_prefix": 1000,
        "signed_per_hour": 1000,
    }
    return Settings(**{**base, **over})


@pytest_asyncio.fixture
async def env_factory(tmp_path: Path) -> AsyncIterator[Any]:
    """Build an Env with custom settings. Teardown disposes every engine."""
    made: list[tuple[AsyncEngine, AsyncEngine, httpx.AsyncClient]] = []

    async def build(**over: Any) -> Env:
        settings = make_settings(
            database_url=_url_for(API_ROLE, API_PASSWORD),
            worker_database_url=_url_for(WORKER_ROLE, WORKER_PASSWORD),
            **over,
        )
        clock = FakeClock()
        hub_private = sign.generate_private_key()
        api_engine = create_async_engine(settings.database_url)
        worker_engine = create_async_engine(settings.worker_database_url)
        owner = create_async_engine(OWNER_URL)
        app = create_app(settings, engine=api_engine, hub_private=hub_private, clock=clock)
        http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("203.0.113.77", 4567)),
            base_url="http://hub.test",
        )
        made.extend([(api_engine, worker_engine, http)])
        made.append((owner, owner, http))
        hub_key = sign.node_key(sign.public_key_of(hub_private))
        return Env(
            client=NodeClient(http, clock, hub_key),
            http=http,
            clock=clock,
            ctx=app.state.ctx,
            worker=async_sessionmaker(worker_engine, expire_on_commit=False),
            owner=owner,
            settings=settings,
            hub_key=hub_key,
        )

    yield build
    for a, b, http in made:
        await http.aclose()
        await a.dispose()
        await b.dispose()


@pytest_asyncio.fixture
async def env(env_factory: Any) -> Env:
    built: Env = await env_factory()
    return built


@pytest.fixture
def feed_dir(tmp_path: Path) -> Path:
    """Where a test's feed files are published (not created until the first publish)."""
    return tmp_path / "feeds"


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    """A fresh minisign secret key file for the feed signer."""
    from suckerpot_netproto.feeds import minisign

    path = tmp_path / "feed.key"
    path.write_text(minisign.serialize_secret_key(minisign.generate_keypair()), encoding="ascii")
    return path
