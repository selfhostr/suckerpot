"""The trap pack state against a real TimescaleDB, as the ingest role: save, read, gate G (M37)."""

from __future__ import annotations

import os
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.trappacks import SqlGateSource, SqlTrapStore, TrapState

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

FIRST = datetime(2026, 11, 20, 1, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE trap_state"))


async def test_state_round_trip_and_gate(factory: async_sessionmaker[AsyncSession]) -> None:
    store = SqlTrapStore(factory)
    gate = SqlGateSource(factory)
    assert await store.state() is None
    assert await gate.gated_tags(date(2026, 11, 21)) == frozenset()
    state = TrapState(
        key_id="0807060504030201",
        seq=1_790_000_000,
        sha256="a" * 64,
        etag='"t1"',
        source="remote",
        packs=1,
        rejected=[["bad-pack", "schema"]],
        first_seen={"p@1": {"cves": ["CVE-2026-55501"], "first_at": FIRST.isoformat()}},
        accepted_at=FIRST,
        last_check_at=FIRST,
        last_ok_at=FIRST,
    )
    await store.save(state)
    got = await store.state()
    assert got is not None and got.seq == 1_790_000_000 and got.rejected == [["bad-pack", "schema"]]
    assert got.first_seen == state.first_seen and got.source == "remote"
    assert await gate.gated_tags(date(2026, 11, 21)) == frozenset({"cve-2026-55501"})
    assert await gate.gated_tags(date(2026, 11, 23)) == frozenset()
    got.error_code, got.seq = "rollback", 1_790_000_000
    await store.save(got)
    again = await store.state()
    assert again is not None and again.error_code == "rollback"


async def test_the_ingest_role_cannot_delete_the_state(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await SqlTrapStore(factory).save(TrapState(seq=1))
    async with factory() as session:
        with pytest.raises(Exception):  # noqa: B017  (permission denied)
            await session.execute(text("DELETE FROM trap_state"))


async def test_the_state_checks_its_bounds(factory: async_sessionmaker[AsyncSession]) -> None:
    store = SqlTrapStore(factory)
    with pytest.raises(Exception):  # noqa: B017  (check constraint)
        await store.save(TrapState(seq=-1))
    with pytest.raises(Exception):  # noqa: B017
        await store.save(TrapState(source="elsewhere"))
