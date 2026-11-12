"""Flood groups against a real TimescaleDB: the writer folds a connection when it closes, a broken
function never costs a batch, and the sweep backfills history, resumes after a restart, waits for
the advisory lock and chains an hour to the group before it."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_common import Event
from suckerpot_db.locks import SESSION_FOLD

from ingest import writer
from ingest.enrichment import GeoResolver
from ingest.enrichment.enricher import Enricher
from ingest.features import FeatureSettings
from ingest.floods import FloodFold, FoldSettings, FoldWorker, load_plain_tags
from ingest.floods.worker import STATUS_KEY
from ingest.tagging import load_rules
from ingest.writer import write_batch

from .db_fixtures import ROLE_ENV
from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

Factory = async_sessionmaker[AsyncSession]
RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
PLAIN = load_plain_tags(RULES_DIR)
SETTINGS = FoldSettings(min_connections=5)
IP = "203.0.113.70"
T0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)  # the start of a UTC hour
SIGNATURE = (
    "fold_session_buckets(inet[], text[], timestamptz[], integer, text[], interval, integer)"
)
PASSWORD = {
    "method": "rdp-nla-off",
    "success": False,
    "username": "administrator",
    "flags": ["weak_password_match"],
}


@pytest.fixture(autouse=True)
def _fresh_fold_log() -> None:
    """One WARNING a minute is process-wide state: start every test with none logged."""
    writer._fold_skips.skips, writer._fold_skips._logged = 0, -1e9


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


def enricher(tmp_path: Path, fold: FloodFold | None) -> Enricher:
    return Enricher(GeoResolver(tmp_path, fake_for_private=True), load_rules(RULES_DIR), fold=fold)


def new_fold() -> FloodFold:
    return FloodFold.build(SETTINGS, PLAIN)


def rdp(
    kind: str, sid: str, offset: float, data: dict[str, Any] | None = None, ip: str = IP
) -> Event:
    return make_event(kind, sid=sid, offset_s=offset, ip=ip, sensor="rdp", data=data, base=T0)


def connection(n: int, ip: str = IP) -> list[Event]:
    """One whole RDP connection that guessed a password: connect, one login, disconnect."""
    at = 10.0 * n
    return [
        rdp("connect", f"c{n}", at, ip=ip),
        rdp("login_attempt", f"c{n}", at + 1, PASSWORD, ip=ip),
        rdp("disconnect", f"c{n}", at + 2, ip=ip),
    ]


async def shape(engine: AsyncEngine) -> list[tuple[str, str, int]]:
    got = await rows(
        engine, "SELECT session_id, kind, connections FROM sessions ORDER BY session_id"
    )
    return [(r.session_id, r.kind, r.connections) for r in got]


async def totals(engine: AsyncEngine) -> tuple[int, int, int]:
    """Connections, login attempts and events: what folding must never change."""
    (r,) = await rows(
        engine,
        "SELECT coalesce(sum(connections), 0) AS n, coalesce(sum(login_attempts), 0) AS l, "
        "coalesce(sum(event_count), 0) AS e FROM sessions",
    )
    return int(r.n), int(r.l), int(r.e)


# ---- the writer -------------------------------------------------------------------------------


async def test_a_connection_spread_over_three_batches_folds_at_its_disconnect(
    engine: AsyncEngine, factory: Factory, tmp_path: Path
) -> None:
    fold = new_fold()
    enr = enricher(tmp_path, fold)
    for n in range(4):  # four whole connections: the source is not flooding yet
        await write_batch(factory, connection(n), enr)
    assert await totals(engine) == (4, 4, 12)
    assert {k for _, k, _ in await shape(engine)} == {"session"}

    await write_batch(factory, [rdp("connect", "c4", 40)], enr)  # the fifth connect: hot now
    await write_batch(factory, [rdp("login_attempt", "c4", 41, PASSWORD)], enr)
    assert {k for _, k, _ in await shape(engine)} == {"session"}  # still open: nothing folds
    assert await totals(engine) == (5, 5, 14)

    await write_batch(factory, [rdp("disconnect", "c4", 42)], enr)  # it closes: the hour folds
    (group,) = await rows(engine, "SELECT * FROM sessions")
    assert group.kind == "burst" and group.session_id.startswith("burst-")
    assert (group.connections, group.login_attempts, group.event_count) == (5, 5, 15)
    assert (group.src_port, group.dst_port, group.sensor) == (0, 2222, "rdp")
    assert group.tags == ["rdp-cleartext", "weak-credentials"]
    assert group.started_at == T0 and group.ended_at == T0 + timedelta(seconds=42)
    assert str(group.src_ip) == IP and group.campaign_id is None
    # events are never touched, and the sums are what they were
    assert (await rows(engine, "SELECT count(*) AS n FROM events"))[0].n == 15
    assert await totals(engine) == (5, 5, 15)
    assert (fold.calls, fold.folded) == (1, 5)


async def test_later_connections_of_the_hour_join_the_group(
    engine: AsyncEngine, factory: Factory, tmp_path: Path
) -> None:
    enr = enricher(tmp_path, new_fold())
    for n in range(8):
        await write_batch(factory, connection(n), enr)
    (group,) = await rows(engine, "SELECT * FROM sessions")
    assert group.kind == "burst" and group.connections == 8
    assert (group.login_attempts, group.event_count) == (8, 24)


async def test_a_connection_that_did_something_keeps_its_row(
    engine: AsyncEngine, factory: Factory, tmp_path: Path
) -> None:
    enr = enricher(tmp_path, new_fold())
    await write_batch(
        factory,
        [
            rdp("connect", "typed", 5),
            rdp("login_attempt", "typed", 6, {"success": True}),
            rdp("command", "typed", 7, {"input": "whoami"}),
            rdp("disconnect", "typed", 8),
        ],
        enr,
    )
    for n in range(6):
        await write_batch(factory, connection(n + 10), enr)
    got = {sid: (kind, n) for sid, kind, n in await shape(engine)}
    assert got["typed"] == ("session", 1)
    assert sorted(k for k, _ in got.values()) == ["burst", "session"]
    assert await totals(engine) == (7, 7, 22)


async def test_a_demo_hour_never_folds(
    engine: AsyncEngine, factory: Factory, tmp_path: Path
) -> None:
    enr = enricher(tmp_path, new_fold())
    await write_batch(
        factory, [rdp("connect", "d0", 0, {"demo": True}), rdp("disconnect", "d0", 1)], enr
    )
    for n in range(1, 8):  # the database function sees the demo event of the hour
        await write_batch(factory, connection(n), enr)
    assert {k for _, k, _ in await shape(engine)} == {"session"}
    assert (await totals(engine))[0] == 8


async def test_without_a_fold_every_connection_keeps_its_row(
    engine: AsyncEngine, factory: Factory, tmp_path: Path
) -> None:
    enr = enricher(tmp_path, None)  # SESSION_FOLD_ENABLED=false
    for n in range(8):
        await write_batch(factory, connection(n), enr)
    assert {k for _, k, _ in await shape(engine)} == {"session"}
    assert (await totals(engine))[0] == 8


async def test_a_broken_function_does_not_fail_the_batch(
    engine: AsyncEngine, factory: Factory, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The ingest role loses its right to call the function: the savepoint absorbs the error."""
    role = ROLE_ENV["POSTGRES_INGEST_USER"]
    assert role.isidentifier()
    fold = new_fold()
    enr = enricher(tmp_path, fold)
    async with engine.begin() as conn:
        await conn.execute(text(f"REVOKE EXECUTE ON FUNCTION {SIGNATURE} FROM {role}"))
    try:
        with caplog.at_level("WARNING"):
            for n in range(7):
                await write_batch(factory, connection(n), enr)  # never raises
        skipped = [r for r in caplog.records if "session fold skipped" in r.message]
        assert len(skipped) == 1  # three failed calls, one line a minute
        assert {k for _, k, _ in await shape(engine)} == {"session"}
        assert await totals(engine) == (7, 7, 21)
        assert (await rows(engine, "SELECT count(*) AS n FROM events"))[0].n == 21
        assert (fold.calls, fold.folded) == (0, 0)
    finally:
        async with engine.begin() as conn:
            await conn.execute(text(f"GRANT EXECUTE ON FUNCTION {SIGNATURE} TO {role}"))
    await write_batch(factory, connection(7), enr)  # and it recovers: the whole hour folds
    (group,) = await rows(engine, "SELECT kind, connections FROM sessions")
    assert (group.kind, group.connections) == ("burst", 8)


async def test_an_event_cannot_reach_a_group(
    engine: AsyncEngine, factory: Factory, tmp_path: Path
) -> None:
    """The consumer drops a burst- id; behind it the check constraint refuses the row, so the
    batch fails whole and the group keeps its numbers (the upsert's WHERE is a third wall)."""
    enr = enricher(tmp_path, new_fold())
    for n in range(6):
        await write_batch(factory, connection(n), enr)
    before = await rows(engine, "SELECT * FROM sessions")
    assert [r.kind for r in before] == ["burst"]
    with pytest.raises(IntegrityError):
        await write_batch(factory, [rdp("command", before[0].session_id, 90, {"input": "id"})], enr)
    assert await rows(engine, "SELECT * FROM sessions") == before
    assert (await rows(engine, "SELECT count(*) AS n FROM events"))[0].n == 18


# ---- the sweep --------------------------------------------------------------------------------

NOW = datetime.now(UTC)  # fixed for the module: the worker's clock
HOUR = NOW.replace(minute=0, second=0, microsecond=0)
TOP = HOUR - timedelta(hours=3)  # where the recent pass starts and the backfill begins


def worker(factory: Factory, **kw: Any) -> FoldWorker:
    args: dict[str, Any] = {
        "fold": SETTINGS, "plain_tags": PLAIN, "clock": lambda: NOW, "busy_pause_s": 0.0,
        "step": timedelta(hours=6),
    }  # fmt: skip
    return FoldWorker(FeatureSettings(), factory, **{**args, **kw})


async def seed(
    engine: AsyncEngine,
    count: int,
    ip: str,
    started: datetime,
    prefix: str,
    *,
    ended: bool = True,
    last: datetime | None = None,
    commands: int = 0,
) -> None:
    """``count`` plain RDP connections of ``ip`` from ``started`` on, one every 7 seconds."""
    async with engine.begin() as conn:
        for n in range(count):
            at = started + timedelta(seconds=7 * n)
            await conn.execute(
                text(
                    """
                    INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port,
                        started_at, ended_at, last_event_at, event_count, login_attempts,
                        login_success, commands, tags)
                    VALUES (:sid, 'rdp', CAST(:ip AS inet), 40000, 3389, :t, :ended, :last, 3, 1,
                        false, :commands, '{}')
                    """
                ),
                {
                    "sid": f"{prefix}-{n}", "ip": ip, "t": at, "commands": commands,
                    "ended": at + timedelta(seconds=2) if ended else None,
                    "last": last or at + timedelta(seconds=2),
                },
            )  # fmt: skip


async def seed_history(engine: AsyncEngine) -> None:
    """From the newest hour back: a recent flood with one connection still open, a flood at the
    start of the first backfill window, a flood with one connection that typed a command, a flood
    at the very start of the history, and a source that stayed below the threshold."""
    recent = HOUR - timedelta(hours=1)
    await seed(engine, 7, "203.0.113.71", recent + timedelta(minutes=10), "recent")
    await seed(  # opened an hour ago and still talking: not closed
        engine, 1, "203.0.113.71", recent + timedelta(minutes=20), "open", ended=False,
        last=NOW - timedelta(minutes=1),
    )  # fmt: skip
    await seed(engine, 6, "203.0.113.71", TOP - timedelta(hours=3) + timedelta(minutes=10), "noon")
    gone = HOUR - timedelta(hours=12)
    await seed(engine, 7, "198.51.100.5", gone + timedelta(minutes=5), "mixed")
    await seed(engine, 1, "198.51.100.5", gone + timedelta(minutes=9), "typed", commands=2)
    oldest = HOUR - timedelta(hours=16)
    await seed(engine, 6, "203.0.113.71", oldest + timedelta(minutes=10), "late")
    await seed(engine, 3, "192.0.2.9", oldest + timedelta(minutes=20), "few")


async def groups(engine: AsyncEngine) -> dict[str, int]:
    got = await rows(engine, "SELECT session_id, connections FROM sessions WHERE kind = 'burst'")
    return {r.session_id: r.connections for r in got}


async def saved(engine: AsyncEngine) -> dict[str, Any]:
    (r,) = await rows(engine, "SELECT value FROM system_status WHERE key = :k", k=STATUS_KEY)
    value: dict[str, Any] = r.value
    return value


async def test_the_sweep_backfills_history_and_resumes_after_a_restart(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_history(engine)
    before = await totals(engine)
    assert before == (31, 31, 93)

    # First process: the recent pass and one backfill window, then it dies on the next window.
    first = worker(factory)
    real = first._sweep
    windows: list[tuple[datetime, datetime]] = []

    async def dying(lo: datetime, hi: datetime, deadline: float) -> tuple[int, bool]:
        windows.append((lo, hi))
        if len(windows) == 3:
            raise RuntimeError("the process died")
        return await real(lo, hi, deadline)

    first._sweep = dying  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="died"):
        await first.run_once()
    assert windows[0] == (TOP, HOUR + timedelta(hours=1))  # the recent pass: 3 h and the current
    assert windows[1] == (TOP - timedelta(hours=6), TOP)  # the first backfill window
    assert await saved(engine) == {
        "cursor": (TOP - timedelta(hours=6)).isoformat(),
        "done": False,
        "folded": 6,
        "recent_folded": 7,
    }
    assert sorted((await groups(engine)).values()) == [6, 7]  # the recent flood and the first one
    assert await totals(engine) == before

    # Second process: it reads the cursor and carries on where the first stopped.
    second = worker(factory)
    real2 = second._sweep
    seen: list[tuple[datetime, datetime]] = []

    async def spy(lo: datetime, hi: datetime, deadline: float) -> tuple[int, bool]:
        seen.append((lo, hi))
        return await real2(lo, hi, deadline)

    second._sweep = spy  # type: ignore[method-assign]
    await second.run_once()
    assert seen[1] == (TOP - timedelta(hours=12), TOP - timedelta(hours=6))  # not the first again
    assert seen[-1][0] == HOUR - timedelta(hours=16)  # the hour of the oldest session: the floor
    state = await saved(engine)
    assert state["done"] is True and state["cursor"] == (HOUR - timedelta(hours=16)).isoformat()
    assert (state["folded"], state["recent_folded"]) == (6 + 7 + 6, 7)

    assert sorted((await groups(engine)).values()) == [6, 6, 7, 7]
    got = {sid: (kind, n) for sid, kind, n in await shape(engine)}
    # a connection that typed a command, an open one and a source below the threshold stay
    assert got["typed-0"] == ("session", 1) and got["open-0"] == ("session", 1)
    assert [got[f"few-{n}"] for n in range(3)] == [("session", 1)] * 3
    assert await totals(engine) == before  # not one connection, password or event lost

    # a finished backfill is not walked again: the cursor and the totals stay
    third = worker(factory)
    await third.run_once()
    assert third.state.done and await saved(engine) == state


async def test_the_sweep_waits_for_the_advisory_lock_and_keeps_its_place(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed(engine, 7, "203.0.113.72", HOUR - timedelta(hours=1, minutes=-10), "busy")
    await seed(engine, 6, "203.0.113.72", HOUR - timedelta(hours=5, minutes=-10), "older")
    w = worker(factory)
    async with engine.connect() as holder:
        await holder.execute(text("SELECT pg_advisory_lock(:k)"), {"k": SESSION_FOLD})
        try:
            await w.run_once()  # a 0 from the function here would be a lie: it must not move on
            assert w.busy >= 5 and w.calls == 0
            assert await groups(engine) == {}
            state = await saved(engine)
            assert state["cursor"] == TOP.isoformat() and state["done"] is False
        finally:
            await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": SESSION_FOLD})
            await holder.commit()
    await w.run_once()
    assert sorted((await groups(engine)).values()) == [6, 7]
    assert (await saved(engine))["done"] is True and w.calls >= 2


async def test_an_hour_below_the_threshold_joins_the_group_of_the_hour_before(
    engine: AsyncEngine, factory: Factory
) -> None:
    """One call never chains into the next hour: the sweep calls again, and pages on."""
    ip = "203.0.113.73"
    await seed(engine, 6, ip, HOUR - timedelta(hours=2, minutes=-10), "first")
    await seed(engine, 2, ip, HOUR - timedelta(hours=1, minutes=-10), "second")  # 2 < 5
    await seed(engine, 2, "198.51.100.9", HOUR - timedelta(hours=1, minutes=-15), "alone")
    await worker(factory).run_once()
    got = {sid: (kind, n) for sid, kind, n in await shape(engine)}
    assert sorted(v for v in got.values() if v[0] == "burst") == [("burst", 2), ("burst", 6)]
    assert [got[f"alone-{n}"] for n in range(2)] == [("session", 1)] * 2  # no group before it
    assert await totals(engine) == (10, 10, 30)


async def test_the_sweep_folds_connections_that_never_disconnected(
    engine: AsyncEngine, factory: Factory
) -> None:
    """No disconnect: a connection counts as closed after SESSION_FOLD_IDLE_MIN of silence."""
    await seed(
        engine, 6, "203.0.113.74", HOUR - timedelta(hours=1, minutes=-20), "idle", ended=False
    )
    await seed(engine, 6, "203.0.113.75", NOW - timedelta(minutes=2), "young", ended=False)
    await worker(factory).run_once()
    got = {sid: kind for sid, kind, _ in await shape(engine)}
    assert sorted((await groups(engine)).values()) == [6]
    assert all(got[f"young-{n}"] == "session" for n in range(6))  # two minutes is not closed


async def test_a_disabled_sweep_folds_nothing(engine: AsyncEngine, factory: Factory) -> None:
    await seed(engine, 7, "203.0.113.76", HOUR - timedelta(hours=1, minutes=-20), "off")
    w = FoldWorker(FeatureSettings(), factory, fold=FoldSettings(enabled=False), plain_tags=PLAIN)
    assert not w.enabled
    await w.run(None)  # returns at once when disabled
    assert await groups(engine) == {}
