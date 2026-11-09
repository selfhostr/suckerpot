from typing import Any

import pytest
from suckerpot_common import Event

from ingest.config import Settings
from ingest.consumer import Consumer, parse_messages, preview
from ingest.healthcheck import is_healthy
from ingest.writer import strip_nul

from .helpers import make_event


def test_strip_nul_recursive() -> None:
    assert strip_nul({"a\x00": ["x\x00y", 1, {"k": "\x00"}]}) == {"a": ["xy", 1, {"k": ""}]}


def test_parse_messages_skips_bad() -> None:
    good_fields: dict[Any, Any] = Event.to_stream_fields(make_event("connect"))
    msgs = [(b"1-0", good_fields), (b"2-0", {b"v": b"1", b"event": b"{not json"}), (b"3-0", {})]
    good, bad, mismatched = parse_messages(msgs)
    assert [m for m, _ in good] == [b"1-0"]
    assert bad == [b"2-0", b"3-0"] and mismatched == 0


def test_preview_truncates() -> None:
    assert preview({"a": "x" * 1000}).endswith("...<truncated>")
    assert len(preview({"a": "x" * 1000})) < 300


def test_healthcheck_logic() -> None:
    assert is_healthy(1.0)
    assert not is_healthy(31.0)
    assert not is_healthy(None)


class FakeRedis:
    def __init__(self) -> None:
        self.acked: list[Any] = []
        self.trimmed: dict[str, Any] = {}

    async def xtrim(self, stream: str, **kwargs: Any) -> int:
        self.trimmed = kwargs
        return 0

    async def xack(self, stream: str, group: str, *ids: Any) -> int:
        self.acked.extend(ids)
        return len(ids)


async def test_process_acks_bad_and_does_not_ack_on_db_failure(monkeypatch: Any) -> None:
    calls: list[int] = []

    async def fake_write(_factory: Any, events: Any) -> None:
        calls.append(len(events))

    monkeypatch.setattr("ingest.consumer.write_batch", fake_write)
    redis = FakeRedis()
    c = Consumer(Settings.from_env({}), redis, None)  # type: ignore[arg-type]
    good_fields: dict[Any, Any] = Event.to_stream_fields(make_event("connect"))
    await c.process("events:ssh", [(b"1-0", good_fields), (b"2-0", {b"v": b"9"})])
    assert calls == [1]
    assert sorted(redis.acked) == [b"1-0", b"2-0"]

    async def failing_write(_factory: Any, _events: Any) -> None:
        raise OSError("db down")

    monkeypatch.setattr("ingest.consumer.write_batch", failing_write)
    redis.acked.clear()
    with pytest.raises(OSError):
        await c.process("events:ssh", [(b"3-0", good_fields)])
    assert redis.acked == []


def test_skipped_retractions_log_one_warning_a_minute(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import ingest.writer as w

    clock = {"t": 1000.0}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    monkeypatch.setattr(w, "_skips", 0)
    monkeypatch.setattr(w, "_skips_logged", -w.RETRACT_LOG_INTERVAL_S)
    with caplog.at_level("WARNING"):
        for _ in range(5):
            w._retract_skipped("57014")
            clock["t"] += 5
        assert len(caplog.records) == 1  # the first skip logs, the next four are counted
        clock["t"] += 60
        w._retract_skipped("57014")
    msgs = [r.getMessage() for r in caplog.records]
    assert len(msgs) == 2
    assert "skipped 1 time(s)" in msgs[0] and "skipped 5 time(s)" in msgs[1]
