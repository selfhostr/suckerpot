"""Flood groups, ingest side, pure code: the gate, the settings, the plain-tag list, the choice of
buckets and the sweep's saved state. The database side is in ``test_floods_integration.py``."""

import asyncio
import json
from collections import namedtuple
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy.exc import DBAPIError

from ingest.abuse.config import DEFAULT_SEVERE_TAGS
from ingest.campaigns.cluster import _KEYABLE
from ingest.campaigns.keys import PAYLOAD_TAGS
from ingest.campaigns.naming import SEVERE_TAGS, WARNING_TAGS
from ingest.enrichment.enricher import Enricher
from ingest.features import FeatureSettings
from ingest.floods import FloodFold, FloodGate, FoldSettings, FoldWorker, load_plain_tags
from ingest.floods.fold import MAX_BUCKETS, hour_of, is_demo, looks_plain
from ingest.floods.rules import FILE_NAME, SPRAY_TAGS, parse
from ingest.floods.worker import FoldState
from ingest.scanners import ATTACK_TAGS, BENIGN_TAGS
from ingest.tagging import RuleError, load_rules
from ingest.writer import _fold_closed

from .helpers import make_event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
T0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
PLAIN = frozenset({"credential-stuffing", "weak-credentials", "rdp-cleartext", "scanner"})


# ---- the gate ---------------------------------------------------------------------------------


def test_gate_is_hot_at_the_threshold_and_only_then() -> None:
    gate = FloodGate(threshold=3)
    assert [gate.record("192.0.2.1", "rdp", T0 + timedelta(seconds=n)) for n in range(4)] == [
        False,
        False,
        True,
        True,
    ]
    assert gate.is_hot("192.0.2.1", "rdp", T0 + timedelta(seconds=10))
    assert not gate.is_hot("192.0.2.1", "ssh", T0)  # one key per sensor
    assert not gate.is_hot("192.0.2.2", "rdp", T0)  # and per address


def test_gate_forgets_connections_older_than_the_window() -> None:
    gate = FloodGate(threshold=3, window=timedelta(hours=1))
    for n in range(3):
        gate.record("192.0.2.1", "rdp", T0 + timedelta(minutes=n))
    assert gate.is_hot("192.0.2.1", "rdp", T0 + timedelta(minutes=30))
    assert not gate.is_hot("192.0.2.1", "rdp", T0 + timedelta(hours=2))
    # a source that slows down never gets hot: only the last hour counts
    slow = FloodGate(threshold=3, window=timedelta(hours=1))
    assert not any(
        slow.record("192.0.2.9", "rdp", T0 + timedelta(minutes=40 * n)) for n in range(6)
    )


def test_checking_does_not_count() -> None:
    gate = FloodGate(threshold=2)
    for _ in range(5):
        assert not gate.is_hot("192.0.2.1", "rdp", T0)
    assert len(gate) == 0


def test_gate_is_bounded_and_evicts_the_least_recently_used() -> None:
    gate = FloodGate(threshold=2, max_keys=3)
    for n in range(10):
        gate.record(f"192.0.2.{n}", "rdp", T0)
    assert len(gate) == 3
    gate.record("192.0.2.7", "rdp", T0)  # touched: now the most recent
    gate.record("192.0.2.50", "rdp", T0)
    assert gate.is_hot("192.0.2.7", "rdp", T0)  # still there, with two connections
    assert not gate.is_hot("192.0.2.8", "rdp", T0)  # evicted


def test_gate_keeps_at_most_threshold_timestamps_per_key() -> None:
    gate = FloodGate(threshold=4)
    for n in range(1000):
        gate.record("192.0.2.1", "rdp", T0 + timedelta(milliseconds=n))
    assert len(gate._seen[("192.0.2.1", "rdp")]) == 4


@pytest.mark.parametrize("kw", [{"threshold": 0}, {"max_keys": 0}, {"window": timedelta(0)}])
def test_gate_refuses_nonsense(kw: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        FloodGate(**kw)


# ---- the settings -----------------------------------------------------------------------------


def test_defaults_are_on_20_and_15_minutes() -> None:
    s = FoldSettings.from_env({})
    assert (s.enabled, s.min_connections, s.idle_minutes) == (True, 20, 15)
    assert FoldSettings() == s


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("1", True), ("YES", True), ("false", False), ("0", False), ("off", False)],
)
def test_the_switch(raw: str, expected: bool) -> None:
    assert FoldSettings.from_env({"SESSION_FOLD_ENABLED": raw}).enabled is expected


def test_an_empty_switch_keeps_the_default() -> None:
    assert FoldSettings.from_env({"SESSION_FOLD_ENABLED": " "}).enabled is True


def test_the_threshold_is_between_5_and_10000() -> None:
    assert FoldSettings.from_env({"SESSION_FOLD_MIN": "5"}).min_connections == 5
    assert FoldSettings.from_env({"SESSION_FOLD_MIN": "10000"}).min_connections == 10_000
    for bad in ("4", "10001", "0", "-1", "twenty"):
        with pytest.raises(ValueError, match="SESSION_FOLD_MIN"):
            FoldSettings.from_env({"SESSION_FOLD_MIN": bad})


def test_the_idle_time_is_between_5_and_1440_minutes() -> None:
    assert FoldSettings.from_env({"SESSION_FOLD_IDLE_MIN": "5"}).idle_minutes == 5
    for bad in ("4", "1441", "x"):
        with pytest.raises(ValueError, match="SESSION_FOLD_IDLE_MIN"):
            FoldSettings.from_env({"SESSION_FOLD_IDLE_MIN": bad})


# ---- the plain tags ---------------------------------------------------------------------------


def test_the_shipped_file_lists_the_five_plain_tags() -> None:
    assert load_plain_tags(RULES_DIR) == {
        "credential-stuffing",
        "weak-credentials",
        "rdp-cleartext",
        "scanner",
        "smb-v1-probe",
    }


def test_the_shipped_file_is_not_read_as_tagging_rules() -> None:
    assert (RULES_DIR / FILE_NAME).is_file()
    assert load_rules(RULES_DIR).rules  # no 'rules' list in floods.yaml: it is skipped


def _write(tmp_path: Path, body: str) -> Path:
    (tmp_path / FILE_NAME).write_text(body, encoding="utf-8")
    return tmp_path


def test_a_missing_file_leaves_no_tag_plain(tmp_path: Path) -> None:
    assert load_plain_tags(tmp_path) == frozenset()


@pytest.mark.parametrize(
    "tag",
    [
        "malware-drop", "mirai", "crypto-miner", "php2shell", "container-escape", "sql-rce",
        "redis-rogue-master", "db-ransom", "sip-fraud", "persistence", "c3rb3r", "bluekeep",
        "eternalblue", "synology-exploit", "exploit", "cve-2026-109618", "cve-anything",
    ],
)  # fmt: skip
def test_payload_severe_and_cve_tags_are_refused(tmp_path: Path, tag: str) -> None:
    with pytest.raises(RuleError, match=f"'{tag}' cannot be a plain tag"):
        load_plain_tags(_write(tmp_path, f"plain_tags:\n  - scanner\n  - {tag}\n"))


def test_every_severe_warning_payload_and_attack_tag_is_refused() -> None:
    never = set(SEVERE_TAGS) | set(WARNING_TAGS) | set(PAYLOAD_TAGS) | set(DEFAULT_SEVERE_TAGS)
    never |= ATTACK_TAGS - SPRAY_TAGS
    for tag in sorted(never):
        with pytest.raises(RuleError):
            parse({"plain_tags": [tag]})


def test_an_unknown_tag_is_refused() -> None:
    with pytest.raises(RuleError, match="not a tag of the rules"):
        parse({"plain_tags": ["credential-stufing"]})


def test_every_plain_tag_the_rules_ship_is_a_classified_tag() -> None:
    tags = {r.tag for r in load_rules(RULES_DIR).rules}
    assert tags == BENIGN_TAGS | ATTACK_TAGS  # a new tag must be classified, so refusal sees it


@pytest.mark.parametrize(
    "doc",
    [
        None,
        {},
        {"plain_tags": "scanner"},
        {"plain_tags": [1]},
        {"plain_tags": [""]},
        {"plain_tags": ["scanner", "scanner"]},
        {"plain_tags": ["x" * 65]},
        {"plain_tags": ["scanner"] * 33},
        ["scanner"],
    ],
)
def test_a_broken_file_is_refused(doc: object) -> None:
    with pytest.raises(RuleError):
        parse(doc)


def test_unreadable_yaml_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="cannot read"):
        load_plain_tags(_write(tmp_path, "plain_tags: [unclosed"))


# ---- which buckets are worth a call -----------------------------------------------------------

Row = namedtuple(
    "Row",
    "session_id sensor src_ip started_at ended_at last_event_at login_attempts login_success "
    "commands downloads http_requests tags benign scanner_name",
)


def row(sid: str = "a", ip: str = "192.0.2.1", **kw: Any) -> Row:
    base: dict[str, Any] = {
        "session_id": sid, "sensor": "rdp", "src_ip": ip, "started_at": T0,
        "ended_at": T0 + timedelta(seconds=3), "last_event_at": T0 + timedelta(seconds=3),
        "login_attempts": 1, "login_success": False, "commands": 0, "downloads": 0,
        "http_requests": 0, "tags": [], "benign": False, "scanner_name": None,
    }  # fmt: skip
    base.update(kw)
    return Row(**base)


def hot_fold(ip: str = "192.0.2.1", sensor: str = "rdp", n: int = 5) -> FloodFold:
    fold = FloodFold.build(FoldSettings(min_connections=n), PLAIN)
    for i in range(n):
        fold.gate.record(ip, sensor, T0 - timedelta(seconds=n - i))
    return fold


def test_a_closed_plain_row_of_a_hot_source_is_worth_a_call() -> None:
    fold = hot_fold()
    assert fold.buckets([row()]) == [("192.0.2.1", "rdp", T0)]
    assert fold.buckets([row("a"), row("b"), row("c", started_at=T0 + timedelta(minutes=5))]) == [
        ("192.0.2.1", "rdp", T0)
    ]  # one bucket for the same address, sensor and hour


def test_the_bucket_is_the_hour_the_session_started_in() -> None:
    fold = hot_fold()
    late = T0.replace(minute=59, second=58)
    assert fold.buckets([row(started_at=late, ended_at=late + timedelta(seconds=4))]) == [
        ("192.0.2.1", "rdp", T0)
    ]
    assert hour_of(T0 + timedelta(hours=1, minutes=3)) == T0 + timedelta(hours=1)


@pytest.mark.parametrize(
    "change",
    [
        {"ended_at": None},  # still open: it folds at its disconnect, or when it is idle
        {"benign": True},
        {"scanner_name": "Censys"},
        {"login_success": True},
        {"commands": 1},
        {"downloads": 1},
        {"http_requests": 1},
        {"login_attempts": 20},
        {"tags": ["malware-drop"]},
        {"tags": ["credential-stuffing", "php2shell"]},
    ],
)
def test_a_row_that_did_anything_is_not_worth_a_call(change: dict[str, Any]) -> None:
    assert hot_fold().buckets([row(**change)]) == []


def test_plain_tags_and_attempts_below_twenty_are_fine() -> None:
    assert hot_fold().buckets([row(tags=["credential-stuffing", "scanner"], login_attempts=19)])


def test_a_cold_source_is_not_worth_a_call() -> None:
    fold = FloodFold.build(FoldSettings(min_connections=5), PLAIN)
    for i in range(4):
        fold.gate.record("192.0.2.1", "rdp", T0 + timedelta(seconds=i))
    assert fold.buckets([row()]) == []
    assert hot_fold(sensor="ssh").buckets([row()]) == []  # hot on another sensor only


def test_a_demo_hour_is_not_worth_a_call() -> None:
    fold = hot_fold()
    demo = {("192.0.2.1", "rdp", int(T0.timestamp()))}
    assert fold.buckets([row()], demo) == []
    other_hour = {("192.0.2.1", "rdp", int((T0 + timedelta(hours=1)).timestamp()))}
    assert fold.buckets([row()], other_hour) == [("192.0.2.1", "rdp", T0)]


def test_buckets_of_one_call_are_capped_and_ordered() -> None:
    ips = [f"{net}.{n}" for net in ("192.0.2", "198.51.100", "203.0.113") for n in range(1, 255)]
    fold = FloodFold.build(FoldSettings(min_connections=5), PLAIN)
    for ip in ips:
        for i in range(5):
            fold.gate.record(ip, "rdp", T0 + timedelta(seconds=i))
    got = fold.buckets([row(f"s{i}", ip) for i, ip in enumerate(ips)])
    assert len(ips) > MAX_BUCKETS == len(got)
    assert got == sorted(got, key=lambda b: (b[2], b[0], b[1]))


def test_looks_plain_reads_only_the_row() -> None:
    assert looks_plain(row(tags=None), PLAIN)
    assert not looks_plain(row(tags=["recon"]), PLAIN)  # a tag the list does not name


def test_record_counts_connects_only_and_reports_demo_hours() -> None:
    fold = FloodFold.build(FoldSettings(min_connections=5), PLAIN)
    events = [
        make_event("connect", sid="a", ip="192.0.2.1", sensor="rdp"),
        make_event("login_attempt", sid="a", ip="192.0.2.1", sensor="rdp"),
        make_event("connect", sid="b", ip="192.0.2.2", sensor="rdp", data={"demo": True}),
        make_event("connect", sid="c", ip="192.0.2.3", sensor="rdp", data={"demo": "true"}),
        make_event("connect", sid="d", ip="192.0.2.4", sensor="rdp", data={"demo": False}),
    ]
    demo = fold.record(events)
    assert demo == {
        ("192.0.2.2", "rdp", int(T0.timestamp())),
        ("192.0.2.3", "rdp", int(T0.timestamp())),
    }
    assert len(fold.gate) == 2  # .1 and .4: a demo connect never feeds the gate
    assert is_demo({"demo": True}) and is_demo({"demo": "TRUE"})
    assert not is_demo({}) and not is_demo({"demo": False}) and not is_demo({"demo": 0})


# ---- the writer's call is housekeeping --------------------------------------------------------


class _Boom(DBAPIError):
    """A database error with a chosen ``connection_invalidated``."""

    def __init__(self, invalidated: bool) -> None:
        Exception.__init__(self, "boom")
        self.connection_invalidated = invalidated
        self.orig = type("Orig", (), {"sqlstate": "55P03"})()


class _Nested:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> None:
        return None


class _Session:
    def __init__(self) -> None:
        self.nested = 0

    def begin_nested(self) -> _Nested:
        self.nested += 1
        return _Nested()


async def call(session: _Session, fold: FloodFold, events: list[Any], rows: list[Any]) -> None:
    await _fold_closed(cast(Any, session), fold, events, rows)


async def test_a_failed_fold_never_fails_the_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    fold = hot_fold()

    async def broken(*_a: Any, **_k: Any) -> int:
        raise _Boom(False)

    monkeypatch.setattr("ingest.writer.fold_buckets", broken)
    session = _Session()
    await call(session, fold, [make_event("connect", ip="192.0.2.1", sensor="rdp")], [row()])
    assert session.nested == 1 and fold.calls == 0 and fold.folded == 0


async def test_a_lost_connection_is_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def lost(*_a: Any, **_k: Any) -> int:
        raise _Boom(True)

    monkeypatch.setattr("ingest.writer.fold_buckets", lost)
    with pytest.raises(DBAPIError):
        await call(
            _Session(), hot_fold(), [make_event("connect", ip="192.0.2.1", sensor="rdp")], [row()]
        )


async def test_nothing_to_fold_makes_no_call(monkeypatch: pytest.MonkeyPatch) -> None:
    called = 0

    async def spy(*_a: Any, **_k: Any) -> int:
        nonlocal called
        called += 1
        return 0

    monkeypatch.setattr("ingest.writer.fold_buckets", spy)
    cold = FloodFold.build(FoldSettings(min_connections=5), PLAIN)
    session = _Session()
    await call(session, cold, [make_event("connect", sensor="rdp")], [row()])
    assert called == 0 and session.nested == 0


async def test_a_call_counts_what_it_folded(monkeypatch: pytest.MonkeyPatch) -> None:
    async def folded(*_a: Any, **_k: Any) -> int:
        return 7

    monkeypatch.setattr("ingest.writer.fold_buckets", folded)
    fold = hot_fold()
    await call(_Session(), fold, [make_event("connect", sensor="rdp")], [row()])
    assert (fold.calls, fold.folded) == (1, 7)


def test_the_enricher_has_no_fold_unless_given_one() -> None:
    assert Enricher.__dataclass_fields__["fold"].default is None


# ---- the campaigns never key a group ----------------------------------------------------------


def test_a_group_is_never_keyable_for_campaigns() -> None:
    assert _KEYABLE.startswith("(kind = 'session' AND ")
    assert ":logins" in _KEYABLE and ":payload" in _KEYABLE
    assert _KEYABLE.count("(") == _KEYABLE.count(")")  # safe under a NOT


# ---- the sweep's state ------------------------------------------------------------------------


def test_state_round_trips() -> None:
    state = FoldState(cursor=T0, done=True, folded=12, recent_folded=3)
    assert FoldState.from_json(json.loads(state.to_json())) == state
    assert FoldState.from_json(state.to_json()) == state  # a driver may hand back the text


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "not json",
        [],
        7,
        {"cursor": "yesterday"},
        {"cursor": T0.isoformat(), "folded": "x"},
    ],
)
def test_a_damaged_state_starts_over(raw: object) -> None:
    assert FoldState.from_json(raw) == FoldState()


def test_a_naive_cursor_is_read_as_utc() -> None:
    state = FoldState.from_json({"cursor": "2026-10-24T10:00:00"})
    assert state.cursor == T0


async def test_a_disabled_worker_does_nothing_but_publish() -> None:
    worker = FoldWorker(FeatureSettings(), None, fold=FoldSettings(enabled=False))
    seen: list[dict[str, Any]] = []

    async def publish(detail: dict[str, Any]) -> None:
        seen.append(detail)

    await asyncio.wait_for(worker.run(publish), timeout=2)
    assert seen == [{"session_fold": {"enabled": False, "cycles": 0, "last_error": None}}]


async def test_a_worker_without_a_database_has_nothing_to_do() -> None:
    worker = FoldWorker(FeatureSettings(), None, fold=FoldSettings())
    await worker.run_once()
    assert worker.state == FoldState()
