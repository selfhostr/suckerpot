"""The worker acts on a change made from the terminal without a restart (slow 1 GB nodes)."""

from __future__ import annotations

import asyncio

import pytest

from ingest.network import worker as worker_mod

from .helpers import FakeGate, MemoryStore
from .test_participant import make


async def _paused(
    store: MemoryStore, monkeypatch: pytest.MonkeyPatch, gate_open: bool = True
) -> bool:
    """True when pause() ended before its interval (100 s here)."""
    monkeypatch.setattr(worker_mod, "WAKE_POLL_S", 0.01)
    w, _ = make(store)
    if not gate_open:
        w._gate = FakeGate(False)  # type: ignore[assignment]
    w.interval_s = 100.0
    try:
        await asyncio.wait_for(w.pause(), timeout=1.0)
    except TimeoutError:
        return False
    return True


async def test_a_new_country_of_a_member_ends_the_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemoryStore(
        desired="member", state="member", pseudonym="amber-falcon-42", country="CH",
        synced_pseudonym="amber-falcon-42", synced_country=None, synced_show_country=False,
    )  # fmt: skip
    assert await _paused(store, monkeypatch)


async def test_a_leave_ends_the_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    assert await _paused(MemoryStore(desired="leave", state="member"), monkeypatch)


async def test_nothing_to_send_keeps_the_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemoryStore(
        desired="member", state="member", pseudonym="amber-falcon-42",
        synced_pseudonym="amber-falcon-42", synced_country=None, synced_show_country=False,
    )  # fmt: skip
    assert not await _paused(store, monkeypatch)


def test_the_fold_timeout_is_configurable() -> None:
    from ingest.floods.config import FoldSettings
    from ingest.floods.fold import FloodFold

    s = FoldSettings.from_env({"SESSION_FOLD_TIMEOUT_MS": "8000"})
    assert FloodFold.build(s, frozenset()).timeout_ms == 8000
    assert FoldSettings.from_env({}).writer_timeout_ms == 2000
    with pytest.raises(ValueError, match="between 500 and 30000"):
        FoldSettings.from_env({"SESSION_FOLD_TIMEOUT_MS": "5"})


async def test_a_gate_open_again_ends_the_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    """Right after a restart hubproxy is not up: egress_closed. Once the gate is open, the worker
    tries at once instead of letting the error stand for a whole interval."""
    synced = {
        "desired": "member", "state": "member", "pseudonym": "amber-falcon-42",
        "synced_pseudonym": "amber-falcon-42", "synced_country": None, "synced_show_country": False,
        "last_error_code": "egress_closed",
    }  # fmt: skip
    assert await _paused(MemoryStore(**synced), monkeypatch)
    assert not await _paused(MemoryStore(**synced), monkeypatch, gate_open=False)
