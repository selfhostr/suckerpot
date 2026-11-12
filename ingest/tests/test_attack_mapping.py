"""ATT&CK catalogue and mapping rules: the shipped files load, and bad files are refused."""

from __future__ import annotations

from pathlib import Path

import pytest

from ingest.attack.mapping import (
    MAX_TECHNIQUES_PER_EVENT,
    AttackError,
    load_attack,
    valid_technique_id,
)
from ingest.tagging import load_rules

RULES = Path(__file__).resolve().parents[1] / "rules"


def write(directory: Path, name: str, body: str) -> None:
    (directory / "attack").mkdir(exist_ok=True)
    (directory / "attack" / name).write_text(body, encoding="utf-8")


CATALOGUE = """
techniques:
  - {id: T1059, name: Command and Scripting Interpreter, tactic: execution, stage: execution}
  - {id: T1105, name: Ingress Tool Transfer, tactic: command-and-control, stage: tool_transfer}
"""


def test_shipped_files_load_and_only_name_known_things() -> None:
    attack = load_attack(RULES)
    assert len(attack.techniques) >= 30
    tags = set(load_rules(RULES).tags)
    # Every tag mapped here is a tag the tagging engine can produce (credential-stuffing is
    # produced by the brute-force tracker, not by a rule file).
    assert set(attack.from_tags) - tags <= {"credential-stuffing"}
    for tid in attack.techniques:
        assert valid_technique_id(tid)
    assert attack.techniques["T1059.004"].url == "https://attack.mitre.org/techniques/T1059/004/"


def test_events_get_techniques_from_rules_and_tags() -> None:
    attack = load_attack(RULES)
    got = attack.for_event("command", "ssh", {"input": "uname -a"}, [])
    assert "T1059.004" in got
    assert "T1082" in got
    got = attack.for_event("http_request", "web", {"path": "/x", "method": "GET"}, ["php2shell"])
    assert {"T1190", "T1505.003"} <= set(got)
    assert attack.for_event("connect", "ssh", {}, []) == []


def test_probe_tags_and_android_fingerprinting_map_to_discovery_techniques() -> None:
    attack = load_attack(RULES)
    assert attack.for_tags(["service-probe"]) == ["T1595"]
    assert attack.for_tags(["iot-shell-probe"]) == ["T1059.004"]
    got = attack.for_event("command", "adb", {"input": "getprop ro.product.model"}, ["recon"])
    assert {"T1059.004", "T1082"} <= set(got)
    # every tag the recon rules produce is mapped, so no probe is invisible in the story
    tags = set(load_rules(RULES).tags)
    assert {"service-probe", "iot-shell-probe"} <= tags
    assert {"service-probe", "iot-shell-probe"} <= set(attack.from_tags)


def test_login_success_adds_valid_accounts() -> None:
    attack = load_attack(RULES)
    ok = attack.for_event("login_attempt", "ssh", {"success": True}, [])
    assert "T1078" in ok
    assert "T1078" not in attack.for_event("login_attempt", "ssh", {"success": False}, [])


def test_an_event_never_carries_more_than_eight_techniques() -> None:
    attack = load_attack(RULES)
    tags = sorted(attack.from_tags)
    assert len(attack.for_event("command", "ssh", {"input": "uname -a"}, tags)) <= (
        MAX_TECHNIQUES_PER_EVENT
    )


@pytest.mark.parametrize("value", ["T1059", "T1059.004", "T0001"])
def test_technique_id_accepts(value: str) -> None:
    assert valid_technique_id(value)


@pytest.mark.parametrize("value", ["", "t1059", "T105", "T1059.04", "T1059.0040", "T10a9", 5, None])
def test_technique_id_refuses(value: object) -> None:
    assert not valid_technique_id(value)


def test_missing_catalogue_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AttackError, match="missing"):
        load_attack(tmp_path)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("techniques: []", "non-empty"),
        ("techniques:\n  - {id: T9, name: x, tactic: impact, stage: objective}", "invalid"),
        (
            "techniques:\n  - {id: T1059, name: x, tactic: execution, stage: recon}",
            "belongs to stage",
        ),
        ("techniques:\n  - {id: T1059, name: x, tactic: weird, stage: nowhere}", "stage"),
        (
            "techniques:\n"
            "  - {id: T1059, name: x, tactic: execution, stage: execution}\n"
            "  - {id: T1059, name: y, tactic: execution, stage: execution}",
            "duplicate",
        ),
    ],
)
def test_bad_catalogues_are_refused(tmp_path: Path, body: str, message: str) -> None:
    write(tmp_path, "techniques.yaml", body)
    with pytest.raises(AttackError, match=message):
        load_attack(tmp_path)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            "rules:\n  - {id: a, technique: T9999, when: {field: type, equals: command}}",
            "catalogue",
        ),
        ("rules:\n  - {id: a, technique: T1059, when: {field: nope, equals: x}}", "not allowed"),
        (
            "rules:\n  - {id: a, technique: T1059, when: {field: session.commands, gte: 1}}",
            "event-scope",
        ),
        ("from_tags:\n  Bad_Tag: [T1059]", "invalid tag"),
        ("from_tags:\n  mirai: [T4242]", "unknown technique"),
        ("from_tags: [1, 2]", "mapping"),
    ],
)
def test_bad_mapping_files_are_refused(tmp_path: Path, body: str, message: str) -> None:
    write(tmp_path, "techniques.yaml", CATALOGUE)
    write(tmp_path, "mapping.yaml", body)
    with pytest.raises(AttackError, match=message):
        load_attack(tmp_path)


def test_duplicate_rule_ids_across_files_are_refused(tmp_path: Path) -> None:
    write(tmp_path, "techniques.yaml", CATALOGUE)
    rule = "rules:\n  - {id: same, technique: T1059, when: {field: type, equals: command}}"
    write(tmp_path, "a.yaml", rule)
    write(tmp_path, "b.yaml", rule)
    with pytest.raises(AttackError, match="duplicate"):
        load_attack(tmp_path)
