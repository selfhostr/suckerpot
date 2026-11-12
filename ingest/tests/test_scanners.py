"""Research scanners (M19): the shipped list, the loader's strictness and the safety net."""

from pathlib import Path
from typing import Any

import pytest

from ingest.scanners import (
    ATTACK_TAGS,
    BENIGN_TAGS,
    SAFE_FLAGS,
    ScannerSet,
    event_is_benign_safe,
    load_scanners,
    stays_benign,
)
from ingest.tagging import RuleError, load_rules

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
SHIPPED = load_scanners(RULES_DIR)


def write_dir(text: str) -> Path:
    import tempfile

    d = Path(tempfile.mkdtemp())
    return write(d, text)


def write(tmp_path: Path, text: str) -> Path:
    (tmp_path / "scanners.yaml").write_text(text, encoding="utf-8")
    return tmp_path


def test_shipped_file_loads_and_is_not_read_as_tagging_rules() -> None:
    assert len(SHIPPED.scanners) >= 5
    assert load_rules(RULES_DIR).rules  # scanners.yaml has no 'rules' list and is skipped


@pytest.mark.parametrize(
    ("asn", "org", "expected"),
    [
        (398324, None, "Censys"),
        (None, "Censys, Inc.", "Censys"),
        (None, "SHODAN Research", "Shodan"),
        (64496, "Example Hosting", None),
        (None, None, None),
    ],
)
def test_match_by_network_only(asn: int | None, org: str | None, expected: str | None) -> None:
    assert SHIPPED.match(asn=asn, org=org) == expected


def test_a_user_agent_is_never_a_way_in() -> None:
    assert "user_agents" not in (RULES_DIR / "scanners.yaml").read_text().replace("never", "")
    with pytest.raises(RuleError):
        load_scanners(write_dir("scanners:\n  - {name: A, user_agents: [censysinspect]}"))


def test_match_cuts_huge_input_first() -> None:
    assert SHIPPED.match(asn=None, org="x" * 100_000 + "censys") is None


def test_empty_set_matches_nothing() -> None:
    assert ScannerSet().match(asn=398324, org="Censys") is None


def test_missing_file_means_no_scanners(tmp_path: Path) -> None:
    assert load_scanners(tmp_path).scanners == ()


@pytest.mark.parametrize(
    "body",
    [
        "scanners: nope",
        "- just a list",
        "scanners:\n  - {name: A}",  # no way to match
        "scanners:\n  - {name: A, user_agents: [x]}",  # a user-agent is not a way in
        "scanners:\n  - {name: A, orgs: [x], extra: 1}",
        "scanners:\n  - {name: '', orgs: [x]}",
        "scanners:\n  - {name: A, asns: [abc]}",
        "scanners:\n  - {name: A, asns: [true]}",
        "scanners:\n  - {name: A, orgs: [x]}\n  - {name: A, orgs: [y]}",
        "scanners:\n  - {name: A, orgs: ['']}",
        "scanners: [unclosed",
    ],
)
def test_broken_file_raises(tmp_path: Path, body: str) -> None:
    with pytest.raises(RuleError):
        load_scanners(write(tmp_path, body))


def test_stays_benign_only_while_the_session_only_looked_around() -> None:
    ok: dict[str, Any] = {
        "commands": 0,
        "downloads": 0,
        "login_attempts": 0,
        "login_success": False,
    }
    assert stays_benign(**ok, tags=["recon", "scanner"])
    for bad in ({"commands": 1}, {"downloads": 1}, {"login_attempts": 1}, {"login_success": True}):
        assert not stays_benign(**{**ok, **bad}, tags=[])
    for tag in ("php2shell", "credential-stuffing", "never-seen-tag"):
        assert not stays_benign(**ok, tags=[tag])


def test_every_rule_tag_is_classified() -> None:
    tags = {r.tag for r in load_rules(RULES_DIR).rules}
    assert BENIGN_TAGS.isdisjoint(ATTACK_TAGS)
    assert tags == BENIGN_TAGS | ATTACK_TAGS, tags ^ (BENIGN_TAGS | ATTACK_TAGS)


@pytest.mark.parametrize(
    ("etype", "data", "tags", "safe"),
    [
        ("connect", {}, [], True),
        (
            "http_request",
            {"method": "GET", "flags": ["recon", "config_leak"]},
            ["env-file-probe"],
            True,
        ),
        ("http_request", {"method": "HEAD"}, [], True),
        # a research scanner that fingerprints a web app or the Docker API stays benign
        ("http_request", {"method": "GET", "flags": ["wordpress"]}, ["service-probe"], True),
        ("http_request", {"method": "GET", "flags": ["recon"]}, ["service-probe"], True),
        ("http_request", {"method": "GET", "flags": ["phpinfo_probe"]}, ["service-probe"], True),
        ("command", {"input": "INFO", "flags": []}, ["service-probe"], False),
        ("command", {"input": "enable"}, ["iot-shell-probe"], False),
        ("scan", {}, ["iot-shell-probe"], False),
        ("http_request", {"method": "POST"}, [], False),  # wp-login, phpunit eval-stdin
        ("http_request", {}, [], False),
        ("http_request", {"method": "GET", "flags": ["shellshock"]}, [], False),
        ("http_request", {"method": "GET", "flags": ["phpunit_rce"]}, [], False),
        ("http_request", {"method": "GET", "flags": ["lfi"]}, [], False),
        ("http_request", {"method": "GET", "flags": "recon"}, [], False),
        ("http_request", {"method": "GET", "flags": [5]}, [], False),
        ("http_request", {"method": "GET"}, ["php2shell"], False),
        ("login_attempt", {}, [], False),
        ("command", {}, [], False),
        ("download_attempt", {}, [], False),
    ],
)
def test_event_is_benign_safe(
    etype: str, data: dict[str, object], tags: list[str], safe: bool
) -> None:
    assert event_is_benign_safe(etype, data, tags) is safe


def test_safe_flags_hold_no_exploit_word() -> None:
    for flag in SAFE_FLAGS:
        assert not any(w in flag for w in ("rce", "exploit", "shell", "inject", "traversal"))
