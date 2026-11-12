import contextlib
import logging
from pathlib import Path
from typing import Any

import pytest
from redis.exceptions import ResponseError
from sqlalchemy.exc import DBAPIError, StatementError

from ingest.config import Settings
from ingest.consumer import (
    MAX_ATTEMPTS,
    MAX_CONSECUTIVE_PARKS,
    Consumer,
    _db_message,
    classify_failure,
    parse_messages,
)

from .helpers import make_event


class FakeRedis:
    def __init__(self, batches: list[list[Any]] | None = None, trim_error: bool = False) -> None:
        self.acked: list[Any] = []
        self.trimmed: list[dict[str, Any]] = []
        self.batches = batches or []
        self.trim_error = trim_error
        self.reads = 0
        self.groups_created = 0
        self.read_errors: list[Exception] = []
        self.parked: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        self.streams: list[list[Any]] = []

    async def xadd(self, stream: str, fields: dict[str, Any], **kwargs: Any) -> str:
        self.parked.append((stream, fields, kwargs))
        return "1-0"

    async def xgroup_create(self, *args: Any, **kwargs: Any) -> None:
        self.groups_created += 1

    async def xack(self, stream: str, group: str, *ids: Any) -> int:
        self.acked.extend(ids)
        return len(ids)

    async def xtrim(self, stream: str, **kwargs: Any) -> int:
        if self.trim_error:
            raise ResponseError("NOPERM")
        self.trimmed.append(kwargs)
        return 0

    async def xreadgroup(self, *args: Any, **kwargs: Any) -> Any:
        self.reads += 1
        if self.read_errors:
            raise self.read_errors.pop(0)
        if self.streams:
            return self.streams.pop(0)
        if self.batches:
            return [[b"events:ssh", self.batches.pop(0)]]
        return []


@pytest.fixture(autouse=True)
def _no_retry_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ingest.consumer.RETRY_PAUSE_S", 0.0)


def fields() -> dict[Any, Any]:
    return dict(make_event("connect").to_stream_fields())


def consumer(redis: FakeRedis, tmp_path: Path) -> Consumer:
    s = Settings.from_env({"INGEST_HEARTBEAT_PATH": str(tmp_path / "hb")})
    return Consumer(s, redis, None)  # type: ignore[arg-type]


async def test_trim_uses_last_acked_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def ok(_f: Any, _e: Any) -> None: ...

    monkeypatch.setattr("ingest.consumer.write_batch", ok)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    await c.process("events:ssh", [(b"9-0", fields()), (b"10-1", fields()), (b"10-0", {})])
    assert r.trimmed == [{"minid": "10-1", "approximate": True}]


async def test_trim_failure_is_not_fatal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def ok(_f: Any, _e: Any) -> None: ...

    monkeypatch.setattr("ingest.consumer.write_batch", ok)
    r = FakeRedis(trim_error=True)
    await consumer(r, tmp_path).process("events:ssh", [(b"1-0", fields())])
    assert r.acked == [b"1-0"]


def burst_fields(sid: str, **kw: Any) -> dict[Any, Any]:
    return dict(make_event("connect", sid=sid, **kw).to_stream_fields())


async def test_reserved_session_ids_are_dropped_counted_and_acknowledged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A flood group id (burst-...) is the database's: an event that names one is forged."""
    written: list[list[str]] = []

    async def record(_f: Any, events: Any, *_a: Any) -> None:
        written.append([e.session_id for e in events])

    monkeypatch.setattr("ingest.consumer.write_batch", record)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    messages = [
        (b"1-0", burst_fields("burst-0123456789abcdef01234567")),
        (b"2-0", burst_fields("real-1")),
        (b"3-0", burst_fields("burst-")),  # the bare prefix is reserved too
        (b"4-0", burst_fields("xburst-1")),  # only a prefix is reserved
    ]
    with caplog.at_level("WARNING"):
        await c.process("events:ssh", messages)
    assert written == [["real-1", "xburst-1"]]
    assert sorted(r.acked) == [b"1-0", b"2-0", b"3-0", b"4-0"]  # the forged ones are acked too
    assert c.sensor_mismatches == 2
    assert any("forged sensor or session id" in rec.message for rec in caplog.records)


def test_parse_messages_drops_reserved_ids_like_a_sensor_mismatch() -> None:
    msgs = [
        (b"1-0", burst_fields("burst-a")),
        (b"2-0", burst_fields("burst-b", sensor="web")),  # both wrong: counted once
        (b"3-0", burst_fields("ok")),
    ]
    good, bad, mismatched = parse_messages(msgs, "ssh")
    assert [m for m, _ in good] == [b"3-0"]
    assert bad == [b"1-0", b"2-0"] and mismatched == 2
    good, bad, mismatched = parse_messages(msgs)  # no stream to compare with: still dropped
    assert [m for m, _ in good] == [b"3-0"] and mismatched == 2


async def test_a_reserved_id_in_a_bisected_batch_is_dropped_too(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    written: list[list[str]] = []

    async def record(_f: Any, events: Any, *_a: Any) -> None:
        written.append([e.session_id for e in events])

    monkeypatch.setattr("ingest.consumer.write_batch", record)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    acked = await c._isolate(
        "events:ssh", [(b"1-0", burst_fields("burst-x")), (b"2-0", burst_fields("fine"))]
    )
    assert sorted(acked) == [b"1-0", b"2-0"] and written == [["fine"]]
    assert c.sensor_mismatches == 1


async def test_dead_letter_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A data error that escapes the per-event handling still counts toward dead-lettering.
    async def boom(_self: Any, _stream: Any, _messages: Any) -> list[Any]:
        raise DBAPIError("stmt", {}, _Orig("22P02"))

    monkeypatch.setattr(Consumer, "_process_live", boom)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    for _ in range(MAX_ATTEMPTS):
        with pytest.raises(DBAPIError):
            await c.process("events:ssh", [(b"1-0", fields())])
    assert r.acked == []
    await c.process("events:ssh", [(b"1-0", fields())])  # 6th delivery: dead-lettered, not written
    assert r.acked == [b"1-0"]
    assert ("events:ssh", b"1-0") not in c.attempts


@pytest.mark.parametrize("sqlstate", [None, "XX000", "40P01", "42501", "57014", "53300", "08006"])
async def test_only_data_errors_count_per_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sqlstate: str | None
) -> None:
    async def boom(_self: Any, _stream: Any, _messages: Any) -> list[Any]:
        raise DBAPIError("stmt", {}, _Orig(sqlstate))

    monkeypatch.setattr(Consumer, "_process_live", boom)
    c = consumer(FakeRedis(), tmp_path)
    c.s = Settings.from_env({"INGEST_MAX_BATCH_FAILURES": "100"})  # keep bisection out of it
    for _ in range(MAX_ATTEMPTS + 3):
        with pytest.raises(DBAPIError):
            await c.process("events:ssh", [(b"1-0", fields())])
    assert c.attempts == {}


@pytest.mark.parametrize(
    ("sqlstate", "kind"),
    [
        ("22P02", "data"),
        ("23505", "data"),
        ("57014", "other"),
        ("40P01", "other"),
        ("40001", "other"),
        ("42501", "other"),
        ("42P01", "other"),
        ("53100", "other"),
        ("XX000", "other"),
        ("08006", "outage"),
        ("57P01", "outage"),
        ("57P03", "outage"),
        ("53300", "outage"),
        (None, "outage"),
    ],
)
def test_classification(sqlstate: str | None, kind: str) -> None:
    assert classify_failure(DBAPIError("stmt", {}, _Orig(sqlstate))) == kind


def test_classification_of_non_database_errors() -> None:
    assert classify_failure(OSError("reset")) == "outage"
    assert classify_failure(ResponseError("LOADING")) == "outage"
    assert classify_failure(StatementError("bind", "stmt", {}, ValueError("x"))) == "data"
    invalidated = DBAPIError("stmt", {}, _Orig("57014"), connection_invalidated=True)
    assert classify_failure(invalidated) == "outage"


async def test_a_timeout_counts_against_the_stream_not_the_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def timeout(_f: Any, _e: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig("57014"))

    monkeypatch.setattr("ingest.consumer.write_batch", timeout)
    c = consumer(FakeRedis(), tmp_path)
    for n in range(1, 4):
        with pytest.raises(DBAPIError):
            await c.process("events:ssh", [(b"1-0", fields())])
        assert c.failures == {"events:ssh": n}
    assert c.attempts == {}


async def test_a_poisonous_event_is_parked_after_repeated_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    poison = make_event("command", sid="poison")
    written: list[list[str]] = []

    async def write(_f: Any, events: list[Any], *_a: Any) -> None:
        if any(e.session_id == "poison" for e in events):
            raise DBAPIError("stmt", {}, _Orig("57014"))
        written.append([e.session_id for e in events])

    monkeypatch.setattr("ingest.consumer.write_batch", write)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    batch = [
        (f"{i}-0".encode(), dict(make_event("connect", sid=f"s{i}").to_stream_fields()))
        for i in range(1, 6)
    ]
    batch.insert(2, (b"3-5", dict(poison.to_stream_fields())))
    for _ in range(c.s.max_batch_failures):
        with pytest.raises(DBAPIError):
            await c.process("events:ssh", batch)
    assert r.acked == []
    await c.process("events:ssh", batch)  # bisects
    assert sorted(r.acked) == sorted(m[0] for m in batch)
    assert sorted(x for w in written for x in w) == ["s1", "s2", "s3", "s4", "s5"]
    assert len(r.parked) == 1
    stream, parked_fields, kwargs = r.parked[0]
    assert stream == "events:parked"
    assert parked_fields["origin_stream"] == "events:ssh"
    assert parked_fields["origin_id"] == "3-5"
    assert parked_fields["error"] == "57014"
    assert kwargs == {"maxlen": 500, "approximate": True}
    assert c.parked == 1
    assert c.failures.get("events:ssh", 0) == 0


async def test_a_parked_entry_is_small_and_marked_truncated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    big = make_event("command", sid="big", data={"cmd": "x" * 15000})

    async def write(_f: Any, events: list[Any], *_a: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig("57014"))

    monkeypatch.setattr("ingest.consumer.write_batch", write)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    await c._park("events:ssh", b"1-0", big, DBAPIError("s", {}, _Orig("57014")))
    _, entry, kwargs = r.parked[0]
    assert set(entry) == {
        "sensor", "session_id", "src_ip", "type", "ts", "origin_stream", "origin_id",
        "error", "data", "truncated",
    }  # fmt: skip
    assert len(entry["data"].encode()) <= 2048
    assert entry["truncated"] == "1"
    assert "event" not in entry
    assert kwargs["maxlen"] == 500
    small = make_event("command", sid="small", data={"cmd": "ls"})
    await c._park("events:ssh", b"2-0", small, DBAPIError("s", {}, _Orig("57014")))
    assert r.parked[1][1]["truncated"] == "0"


async def test_a_single_failure_is_retried_before_parking(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = {"n": 0}

    async def write(_f: Any, events: list[Any], *_a: Any) -> None:
        calls["n"] += 1
        if len(events) == 1 and calls["n"] <= 1:
            raise DBAPIError("stmt", {}, _Orig("57014"))

    monkeypatch.setattr("ingest.consumer.write_batch", write)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    c.failures["events:ssh"] = c.s.max_batch_failures
    await c.process("events:ssh", [(b"1-0", fields())])
    assert r.parked == [] and r.acked == [b"1-0"]


async def test_at_most_a_few_events_are_parked_per_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def write(_f: Any, events: list[Any], *_a: Any) -> None:
        if any(e.session_id.startswith("bad") for e in events):
            raise DBAPIError("stmt", {}, _Orig("57014"))

    monkeypatch.setattr("ingest.consumer.write_batch", write)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    batch = [(b"1-0", dict(make_event("connect", sid="good").to_stream_fields()))]
    batch += [
        (f"{i}-0".encode(), dict(make_event("connect", sid=f"bad{i}").to_stream_fields()))
        for i in range(2, 8)
    ]
    c.failures["events:ssh"] = c.s.max_batch_failures
    with pytest.raises(DBAPIError):
        await c.process("events:ssh", batch)
    assert len(r.parked) == MAX_CONSECUTIVE_PARKS
    assert b"1-0" in r.acked  # the stored event stays acknowledged
    assert len(r.acked) == 1 + MAX_CONSECUTIVE_PARKS  # the others stay pending
    assert c.failures["events:ssh"] == 1  # reset, then counted once for the raised error


async def test_nogroup_recreates_the_groups_and_goes_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    r = FakeRedis()
    r.read_errors = [ResponseError("NOGROUP No such key 'events:ssh' or consumer group 'ingest'")]
    c = consumer(r, tmp_path)
    c.reclaim_stale = _noop  # type: ignore[method-assign,assignment]
    c._state = _noop  # type: ignore[method-assign]
    orig = r.xreadgroup

    async def read_then_stop(*a: Any, **k: Any) -> Any:
        res = await orig(*a, **k)
        if r.reads >= 2:
            c.stop.set()
        return res

    r.xreadgroup = read_then_stop  # type: ignore[method-assign]
    with caplog.at_level(logging.WARNING):
        await c.run()
    assert r.groups_created == 2 * len(c.s.streams)  # at startup, then again after NOGROUP
    assert any("recreated" in rec.getMessage() for rec in caplog.records)


async def test_an_unexpected_exception_backs_the_stream_off_and_the_loop_survives(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def write(_f: Any, events: list[Any], *_a: Any) -> None:
        raise ValueError("bug")

    monkeypatch.setattr("ingest.consumer.write_batch", write)
    r = FakeRedis()
    r.streams = [[("events:ssh", [(b"1-0", fields())])]]
    c = consumer(r, tmp_path)
    c.ensure_groups = _noop  # type: ignore[method-assign]
    c.reclaim_stale = _noop  # type: ignore[method-assign,assignment]
    c._state = _noop  # type: ignore[method-assign]
    orig = r.xreadgroup

    async def read_then_stop(*a: Any, **k: Any) -> Any:
        res = await orig(*a, **k)
        if not res:
            c.stop.set()
        return res

    r.xreadgroup = read_then_stop  # type: ignore[method-assign]
    await c.run()
    assert "events:ssh" in c.unhealthy and c.failures["events:ssh"] == 1


async def test_a_whole_batch_that_fails_is_never_parked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Every write fails: a systemic fault (permissions, schema), not a bad event.
    async def always(_f: Any, _e: Any, *_a: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig("42501"))

    monkeypatch.setattr("ingest.consumer.write_batch", always)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    batch = [(b"1-0", fields()), (b"2-0", fields())]
    for _ in range(c.s.max_batch_failures + 3):
        with pytest.raises(DBAPIError):
            await c.process("events:ssh", batch)
    assert r.acked == [] and r.parked == []


async def test_parking_single_events_stops_after_a_run_of_parks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def always(_f: Any, _e: Any, *_a: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig("42501"))

    monkeypatch.setattr("ingest.consumer.write_batch", always)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    for i in range(1, 12):
        for _ in range(c.s.max_batch_failures + 1):
            with contextlib.suppress(DBAPIError):
                await c.process("events:ssh", [(f"{i}-0".encode(), fields())])
    assert len(r.parked) == MAX_CONSECUTIVE_PARKS


async def test_an_outage_during_bisection_is_retried_not_parked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = {"n": 0}

    async def write(_f: Any, _e: Any, *_a: Any) -> None:
        calls["n"] += 1
        raise DBAPIError("stmt", {}, _Orig("57014" if calls["n"] <= 5 else None))

    monkeypatch.setattr("ingest.consumer.write_batch", write)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    batch = [(b"1-0", fields()), (b"2-0", fields())]
    for _ in range(5):
        with pytest.raises(DBAPIError):
            await c.process("events:ssh", batch)
    with pytest.raises(DBAPIError):
        await c.process("events:ssh", batch)
    assert r.parked == [] and r.acked == []


async def test_one_failing_stream_does_not_stop_the_others(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def write(_f: Any, events: list[Any], *_a: Any) -> None:
        if events[0].sensor == "ssh":
            raise DBAPIError("stmt", {}, _Orig("57014", "canceling statement due to timeout"))

    monkeypatch.setattr("ingest.consumer.write_batch", write)
    web = dict(make_event("connect", sensor="web").to_stream_fields())
    ssh = dict(make_event("connect", sensor="ssh").to_stream_fields())
    r = FakeRedis()
    r.streams = [[("events:ssh", [(b"1-0", ssh)]), ("events:web", [(b"2-0", web)])]]
    c = consumer(r, tmp_path)
    c.ensure_groups = _noop  # type: ignore[method-assign]
    c.reclaim_stale = _noop  # type: ignore[method-assign,assignment]
    c._state = _noop  # type: ignore[method-assign]
    orig_read = r.xreadgroup

    async def read_then_stop(*a: Any, **k: Any) -> Any:
        res = await orig_read(*a, **k)
        if not res:
            c.stop.set()
        return res

    r.xreadgroup = read_then_stop  # type: ignore[method-assign]
    with caplog.at_level(logging.ERROR):
        await c.run()
    assert r.acked == [b"2-0"]  # web stored in the same loop iteration
    assert "events:ssh" in c.unhealthy
    assert "events:ssh" in c.draining
    msg = next(rec.getMessage() for rec in caplog.records if "batch failed on" in rec.getMessage())
    assert "events:ssh" in msg and "SQLSTATE 57014" in msg
    assert "canceling statement due to timeout" in msg


async def test_failure_message_is_capped_and_free_of_parameters() -> None:
    exc = DBAPIError("INSERT ... [parameters: secret-payload]", {}, _Orig("57014", "x" * 500))
    assert len(_db_message(exc)) == 200
    assert "secret-payload" not in _db_message(exc)
    bind = StatementError("bind secret", "stmt", {"a": "secret"}, ValueError("v"))
    assert _db_message(bind) == "StatementError"


async def test_pipeline_state_is_stamped_only_when_healthy(tmp_path: Path) -> None:
    c = consumer(FakeRedis(), tmp_path)
    updates: list[str] = []

    async def spy(assignments: str, **_p: Any) -> None:
        updates.append(assignments)

    c._state = spy  # type: ignore[method-assign]
    await c._state_ok()
    await c._state_ok()  # within 30 s: not repeated
    assert len(updates) == 1 and "last_ok_at = now()" in updates[0]
    c._last_state = -1e9
    c.unhealthy.add("events:ssh")
    await c._state_ok()
    assert len(updates) == 1


async def test_a_failure_is_recorded_in_pipeline_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cause = type("QueryCanceledError", (Exception,), {})()

    async def timeout(_f: Any, _e: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig("57014", cause=cause))

    monkeypatch.setattr("ingest.consumer.write_batch", timeout)
    c = consumer(FakeRedis(), tmp_path)
    seen: list[tuple[str, dict[str, Any]]] = []

    async def spy(assignments: str, **p: Any) -> None:
        seen.append((assignments, p))

    c._state = spy  # type: ignore[method-assign]
    with pytest.raises(DBAPIError):
        await c.process("events:ssh", [(b"1-0", fields())])
    assert "failing_since = coalesce(failing_since, now())" in seen[0][0]
    assert seen[0][1] == {"e": "57014 QueryCanceledError on events:ssh"}


async def test_outage_errors_do_not_count(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def down(_f: Any, _e: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig(None))

    monkeypatch.setattr("ingest.consumer.write_batch", down)
    c = consumer(FakeRedis(), tmp_path)
    for _ in range(MAX_ATTEMPTS + 2):
        with pytest.raises(DBAPIError):
            await c.process("events:ssh", [(b"1-0", fields())])
    assert c.attempts == {}


async def test_statement_error_single_event_is_data_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def bad(_f: Any, _e: Any) -> None:
        raise StatementError("cannot bind", "stmt", {}, ValueError("x"))

    monkeypatch.setattr("ingest.consumer.write_batch", bad)
    r = FakeRedis()
    await consumer(r, tmp_path).process("events:ssh", [(b"1-0", fields())])
    assert r.acked == [b"1-0"]


async def test_heartbeat_only_after_successful_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = {"n": 0}

    async def flaky(_f: Any, _e: Any) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("db down")

    async def noop(*_a: Any, **_k: Any) -> None: ...

    monkeypatch.setattr("ingest.consumer.write_batch", flaky)
    r = FakeRedis(batches=[[(b"1-0", fields())], [(b"1-0", fields())]])
    c = consumer(r, tmp_path)
    beats: list[int] = []
    at_sleep: list[int] = []

    def spy() -> None:
        beats.append(1)

    async def fake_sleep(_s: float) -> None:
        at_sleep.append(len(beats))

    orig_read = r.xreadgroup

    async def read_then_stop(*a: Any, **k: Any) -> Any:
        res = await orig_read(*a, **k)
        if not res:
            c.stop.set()
        return res

    c.heartbeat = spy  # type: ignore[method-assign]
    c._sleep = fake_sleep  # type: ignore[method-assign,assignment]
    c.ensure_groups = noop  # type: ignore[method-assign]
    c.reclaim_stale = noop  # type: ignore[method-assign,assignment]
    r.xreadgroup = read_then_stop  # type: ignore[method-assign]
    await c.run()
    assert at_sleep == [1]  # only the startup beat existed when the first batch failed
    assert len(beats) >= 3  # startup, committed batch, then the empty read


async def _noop(*_a: Any, **_k: Any) -> None: ...


class _Orig(Exception):
    def __init__(
        self, sqlstate: str | None, message: str = "db error", cause: Exception | None = None
    ) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate
        self.__cause__ = cause
