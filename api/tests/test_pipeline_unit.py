"""``GET /settings/pipeline``: the three statuses and the stall threshold."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from api.settings import DEFAULT_STALL_SECONDS, pipeline_health, pipeline_settings, stall_seconds

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def test_unknown_without_a_heartbeat() -> None:
    h = pipeline_health(None, None, None, 0, NOW, 300)
    assert h.status == "unknown"
    assert h.stalled_for_seconds == 0
    assert h.last_ok_at is None


def test_ok_with_a_fresh_heartbeat() -> None:
    h = pipeline_health(NOW - timedelta(seconds=40), None, None, 2, NOW, 300)
    assert (h.status, h.stalled_for_seconds, h.parked_events) == ("ok", 0, 2)


def test_stalled_when_the_heartbeat_is_old() -> None:
    h = pipeline_health(NOW - timedelta(hours=11), None, None, 0, NOW, 300)
    assert h.status == "stalled"
    assert h.stalled_for_seconds == 11 * 3600


def test_stalled_when_the_failure_streak_is_old() -> None:
    h = pipeline_health(
        NOW - timedelta(seconds=20),
        NOW - timedelta(seconds=400),
        "57014 QueryCanceledError on events:ssh",
        0,
        NOW,
        300,
    )
    assert h.status == "stalled"
    assert h.stalled_for_seconds == 20
    assert h.last_error == "57014 QueryCanceledError on events:ssh"


def test_a_short_failure_streak_is_still_ok() -> None:
    h = pipeline_health(NOW - timedelta(seconds=20), NOW - timedelta(seconds=100), "x", 0, NOW, 300)
    assert h.status == "ok"


def test_stall_seconds_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PIPELINE_STALL_SECONDS", raising=False)
    assert stall_seconds() == DEFAULT_STALL_SECONDS
    monkeypatch.setenv("PIPELINE_STALL_SECONDS", "60")
    assert stall_seconds() == 60
    for bad in ("0", "-5", "soon"):
        monkeypatch.setenv("PIPELINE_STALL_SECONDS", bad)
        assert stall_seconds() == DEFAULT_STALL_SECONDS


class _Result:
    def __init__(self, row: Any) -> None:
        self._row = row

    def first(self) -> Any:
        return self._row


class _Nested:
    async def __aenter__(self) -> None: ...

    async def __aexit__(self, *_a: Any) -> None: ...


class _Db:
    def __init__(self, row: Any) -> None:
        self.row = row

    def begin_nested(self) -> _Nested:
        return _Nested()

    async def execute(self, *_a: Any) -> _Result:
        return _Result(self.row)


async def test_endpoint_reads_the_row() -> None:
    row = (datetime.now(UTC) - timedelta(hours=1), None, None, 3)
    h = await pipeline_settings(_Db(row))  # type: ignore[arg-type]
    assert h.status == "stalled"
    assert h.parked_events == 3


async def test_endpoint_unknown_without_a_row() -> None:
    h = await pipeline_settings(_Db(None))  # type: ignore[arg-type]
    assert h.status == "unknown"
