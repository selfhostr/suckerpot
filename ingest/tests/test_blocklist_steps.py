"""The blocklist cycle runs step by step: a failed step is named, nothing is written after it."""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.exc import DBAPIError, StatementError

from ingest.blocklist import worker as blocklist
from ingest.blocklist.worker import (
    BlocklistStepError,
    BlocklistWorker,
    describe_error,
    ip_candidates,
)
from ingest.features import FeatureSettings

NOW = datetime(2026, 11, 1, tzinfo=UTC)
SQL = "SELECT host(src_ip) FROM events WHERE src_ip = ANY($1)"
PARAMS = {"ips": ["203.0.113.9"]}


class QueryCanceledError(Exception):
    """Stands for asyncpg's error of the same name."""


def timeout_error() -> DBAPIError:
    """What SQLAlchemy raises on a statement timeout with asyncpg: driver error as the cause."""
    driver = QueryCanceledError("canceling statement due to statement timeout")
    try:
        try:
            raise driver
        except QueryCanceledError as e:
            raise RuntimeError(f"{type(e)}: {e}") from e  # SQLAlchemy's adapted error
    except RuntimeError as adapted:
        return DBAPIError(SQL, PARAMS, adapted)


def test_a_database_error_is_described_without_the_statement_or_its_values() -> None:
    err = timeout_error()
    assert "203.0.113.9" in str(err) and "SELECT" in str(err)  # what must never be logged
    got = describe_error(err)
    assert got == "QueryCanceledError: canceling statement due to statement timeout"


def test_any_other_error_is_described_by_its_class_only() -> None:
    assert describe_error(ValueError("203.0.113.9")) == "ValueError"
    assert describe_error(StatementError("bad", SQL, PARAMS, None)) == "StatementError"


def test_the_step_error_names_the_step() -> None:
    err = BlocklistStepError("ip-demo", timeout_error())
    assert err.step == "ip-demo"
    assert err.summary == (
        "step ip-demo: QueryCanceledError: canceling statement due to statement timeout"
    )
    assert "203.0.113.9" not in str(err)


class FakeSession:
    def __init__(self, log: list[str]) -> None:
        self.log = log

    async def execute(self, stmt: Any, params: Any = None) -> None:
        self.log.append(str(stmt))

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[None]:
        self.log.append("BEGIN")
        yield
        self.log.append("END")


def fake_factory(log: list[str]) -> Any:
    @asynccontextmanager
    async def factory() -> AsyncIterator[FakeSession]:
        yield FakeSession(log)

    return factory


ROW = {
    "ip": "203.0.113.9", "sessions": 3, "sensors": 1, "first_seen": NOW, "last_seen": NOW,
    "login_attempts": 0, "login_success": False, "commands": 4, "downloads": 1,
    "max_abuse": None, "known_scanner": False, "benign": False, "campaigns": [],
}  # fmt: skip


def patch_reads(monkeypatch: pytest.MonkeyPatch, calls: list[str], fail: str = "") -> None:
    def fake(name: str, value: Any) -> Any:
        async def read(db: Any, *args: Any) -> Any:
            calls.append(name)
            if name == fail:
                raise timeout_error()
            return value

        return read

    monkeypatch.setattr(blocklist, "_ip_rows", fake("ip-sessions", [ROW]))
    monkeypatch.setattr(blocklist, "_ip_tags", fake("ip-tags", {}))
    monkeypatch.setattr(blocklist, "_demo_ips", fake("ip-demo", set()))
    monkeypatch.setattr(blocklist, "_indicator_candidates", fake("indicators", []))
    monkeypatch.setattr(blocklist, "_contact_candidates", fake("contacts", []))
    monkeypatch.setattr(blocklist, "_network_confirmed", fake("network", set()))
    monkeypatch.setattr(blocklist, "_overrides", fake("overrides", []))
    monkeypatch.setattr(blocklist, "write_entries", fake("write", 0))


async def test_each_step_has_its_own_transaction_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    sql: list[str] = []
    patch_reads(monkeypatch, calls)
    w = BlocklistWorker(FeatureSettings(blocklist_enabled=True), fake_factory(sql))
    await w.run_once()
    steps = ["ip-sessions", "ip-tags", "ip-demo", "indicators", "contacts", "network"]
    assert calls == [*steps, "overrides", "write"]
    assert sql.count("BEGIN") == sql.count("END") == len(calls)
    assert sql.count("SET LOCAL statement_timeout = '30s'") == len(calls)
    assert w.entries == 1 and w.last_run_at is not None


@pytest.mark.parametrize("step", ["ip-sessions", "ip-tags", "ip-demo", "indicators", "network"])
async def test_a_failed_step_is_named_and_nothing_is_written(
    monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    calls: list[str] = []
    patch_reads(monkeypatch, calls, fail=step)
    w = BlocklistWorker(FeatureSettings(blocklist_enabled=True), fake_factory([]))
    with pytest.raises(BlocklistStepError) as info:
        await w.run_once()
    assert info.value.step == step
    assert calls[-1] == step and "write" not in calls
    assert w.last_run_at is None


async def test_the_cycle_log_and_status_carry_the_step_and_the_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[str] = []
    patch_reads(monkeypatch, calls, fail="ip-demo")
    w = BlocklistWorker(FeatureSettings(blocklist_enabled=True), fake_factory([]))
    w.interval_s = 60
    w.start_delay_s = 0
    caplog.set_level(logging.WARNING, logger="ingest.features")
    task = asyncio.create_task(w.run())
    for _ in range(100):
        if w.last_error:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    want = "step ip-demo: QueryCanceledError: canceling statement due to statement timeout"
    assert w.last_error == want
    assert f"blocklist cycle failed ({want})" in caplog.text
    assert "203.0.113.9" not in caplog.text and "SELECT" not in caplog.text


def test_the_demo_flag_comes_from_the_demo_step() -> None:
    other = {**ROW, "ip": "198.51.100.4"}
    got = {c.value: c for c in ip_candidates([ROW, other], {}, {"198.51.100.4"})}
    assert got["198.51.100.4"].demo is True
    assert got["203.0.113.9"].demo is False
    assert got["203.0.113.9"].score > 0


async def test_the_first_cycle_waits_after_the_start_and_the_status_is_published_first() -> None:
    w = BlocklistWorker(FeatureSettings(blocklist_enabled=True), fake_factory([]))
    assert w.start_delay_s >= 120  # a few minutes: not while the stack starts
    w.start_delay_s = 0.2
    cycles: list[float] = []
    seen: list[dict[str, Any]] = []

    async def run_once() -> None:
        cycles.append(asyncio.get_running_loop().time())

    async def publish(status: dict[str, Any]) -> None:
        seen.append(status)

    w.run_once = run_once  # type: ignore[method-assign]
    started = asyncio.get_running_loop().time()
    task = asyncio.create_task(w.run(publish))
    await asyncio.sleep(0.1)
    assert cycles == [] and len(seen) == 1  # waiting, but the status is already out
    await asyncio.sleep(0.3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(cycles) == 1 and cycles[0] - started >= 0.2
