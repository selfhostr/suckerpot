"""Trap pack authoring (M37): the repository's packs are valid and the shipped bundle is the
compiled form of their YAML sources (`just trap-check`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from suckerpot_common import traps

from tools import trap_packs


def test_repository_packs_are_valid_and_the_bundle_is_up_to_date() -> None:
    data, errors = trap_packs.compile_bundle()
    assert errors == []
    assert trap_packs.WEB_BUNDLE.read_bytes() == data, "run: just trap-build"
    assert trap_packs.cmd_check(argparse.Namespace()) == 0
    ids = [p["id"] for p in json.loads(data)["packs"]]
    assert ids == ["log4j-log4shell", "phpunit-eval-stdin", "router-boaform-gponform"]


def test_ingest_reads_the_same_packs_with_the_same_validator() -> None:
    from datetime import date

    res = traps.load_bundle(trap_packs.WEB_BUNDLE.read_bytes(), today=date(2026, 11, 20))
    assert res.rejected == [] and len(res.packs) == 3
    # The converted packs observe only: nothing claims a CVE, so no tag can make anyone reportable.
    assert not any(p.claims for p in res.packs)


@pytest.fixture
def scratch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(trap_packs, "ROOT", tmp_path)
    monkeypatch.setattr(trap_packs, "PACKS", tmp_path / "traps" / "packs")
    monkeypatch.setattr(trap_packs, "FIXTURES", tmp_path / "traps" / "fixtures")
    (tmp_path / "traps" / "packs").mkdir(parents=True)
    return tmp_path


def test_new_scaffolds_a_pack_that_check_refuses_until_edited(scratch: Path) -> None:
    assert trap_packs.main(["new", "CVE-2026-55501", "acme-edgegate-cve-2026-55501"]) == 0
    src = scratch / "traps" / "packs" / "acme-edgegate-cve-2026-55501.yaml"
    fix = scratch / "traps" / "fixtures" / "acme-edgegate-cve-2026-55501"
    assert src.is_file() and (fix / "expect.json").is_file()
    assert sorted(p.name for p in fix.glob("*.http")) == [
        "benign-1.http",
        "exploit-1.http",
        "probe-1.http",
    ]
    _, errors = trap_packs.load_sources()
    assert errors == ["traps/packs/acme-edgegate-cve-2026-55501.yaml: still has TODO"]
    # Without the TODO markers the scaffold is a valid pack.
    src.write_text(src.read_text().replace("TODO", "Acme"))
    objs, errors = trap_packs.load_sources()
    assert errors == [] and objs[0]["disclosed"].count("-") == 2
    assert trap_packs.main(["new", "CVE-2026-55501", "acme-edgegate-cve-2026-55501"]) == 1
    assert trap_packs.main(["new", "not-a-cve"]) == 2


def test_sources_are_checked(scratch: Path) -> None:
    packs = scratch / "traps" / "packs"
    good = (Path(trap_packs.__file__).resolve().parents[2] / "traps" / "packs").glob("*.yaml")
    text = sorted(good)[0].read_text()
    (packs / "wrong-name.yaml").write_text(text)
    (packs / "broken.yaml").write_text("schema: [unclosed\n")
    (packs / "invalid.yaml").write_text(text.replace("version: 1", "version: 0"))
    _, errors = trap_packs.load_sources()
    joined = "\n".join(errors)
    assert "broken.yaml: YAML" in joined
    assert "invalid.yaml: schema: version" in joined
    assert "wrong-name.yaml: the file name must be the pack id" in joined


def test_flags_with_a_meaning_in_ingest_rules_are_reserved() -> None:
    """Security review M3: every flag the web tagging rules test is set by the sensor's code or
    owned by one bundled pack, so no other pack can make the rules fire."""
    import yaml

    rules = yaml.safe_load((Path(__file__).resolve().parents[1] / "rules" / "web.yaml").read_text())
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("field") == "data.flags" and "has" in node:
                has = node["has"]
                found.update(has if isinstance(has, list) else [has])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(rules)
    owned = dict(traps.PACK_OWNED_FLAGS)
    assert found and found <= traps.WEB_BUILTIN_FLAGS | set(owned), found - traps.WEB_BUILTIN_FLAGS
    assert set(owned) <= found  # the owned flags are the ones the rules use


# -- distribution (M37 P2) ------------------------------------------------------------------------


def test_release_bundle_holds_every_pack_the_kill_list_and_a_higher_seq(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    data, errors = trap_packs.release_bundle(1_790_000_000, now=datetime(2026, 11, 21, tzinfo=UTC))
    assert errors == []
    doc = traps.parse_bundle(data)
    assert doc["seq"] == 1_790_000_000 and doc["issued_at"] == "2026-11-21T00:00:00Z"
    assert doc["disabled"] == []  # traps/disabled.yaml
    assert [p["id"] for p in doc["packs"]] == [
        "log4j-log4shell", "phpunit-eval-stdin", "router-boaform-gponform"
    ]  # fmt: skip
    _, errors = trap_packs.release_bundle(1_790_000_000, previous=data)
    assert errors == ["seq 1790000000 is not above the published seq 1790000000"]
    _, errors = trap_packs.release_bundle(0)
    assert "seq must be a positive integer" in errors
    out = tmp_path / "dist"
    assert trap_packs.main(["release", "--seq", "7", "--out", str(out)]) == 0
    assert traps.parse_bundle((out / "traps.json").read_bytes())["seq"] == 7


def test_kill_list_file_is_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "disabled.yaml"
    monkeypatch.setattr(trap_packs, "DISABLED", path)
    path.write_text("disabled:\n  - {id: log4j-log4shell, reason: flags benign traffic}\n")
    assert trap_packs.load_disabled() == (
        [{"id": "log4j-log4shell", "reason": "flags benign traffic"}],
        [],
    )
    data, errors = trap_packs.release_bundle(9)
    assert errors == [] and traps.parse_bundle(data)["disabled"][0]["id"] == "log4j-log4shell"
    path.write_text("disabled:\n  - {id: x}\n")
    assert trap_packs.load_disabled()[1] == [
        "traps/disabled.yaml: entry 0 needs exactly id and reason"
    ]
    path.write_text("disabled:\n  - {id: Not A Slug, reason: r}\n")
    _, errors = trap_packs.release_bundle(9)
    assert any(e.startswith("bundle:") for e in errors)


def test_sign_verifies_with_the_public_key_and_keygen_never_overwrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from suckerpot_netproto.feeds import minisign
    from suckerpot_netproto.feeds import traps as tb

    key_file = tmp_path / "pack.key"
    assert trap_packs.main(["keygen", "--out", str(key_file)]) == 0
    printed = capsys.readouterr().out
    public = printed.splitlines()[0].removeprefix("TRAP_PACK_KEY=")
    assert oct(key_file.stat().st_mode & 0o777) == "0o600"
    assert minisign.parse_secret_key(key_file.read_text()).public.encoded == public
    assert trap_packs.main(["keygen", "--out", str(key_file)]) == 1

    bundle = tmp_path / "traps.json"
    bundle.write_bytes(trap_packs.release_bundle(11)[0])
    monkeypatch.setenv("TRAP_PACK_SECRET_KEY", key_file.read_text())
    assert trap_packs.main(["sign", str(bundle), "--public", public]) == 0
    sig = (tmp_path / "traps.json.minisig").read_text()
    assert tb.verify_bundle(bundle.read_bytes(), sig, minisign.parse_public_key(public)) == 11
    assert key_file.read_text().splitlines()[1] not in capsys.readouterr().out
    # Signed with a key that is not the committed one: refused, nothing written.
    (tmp_path / "traps.json.minisig").unlink()
    other = minisign.generate_keypair().public.encoded
    assert trap_packs.main(["sign", str(bundle), "--public", other]) == 1
    assert not (tmp_path / "traps.json.minisig").exists()
    monkeypatch.setenv("TRAP_PACK_SECRET_KEY", "")
    assert trap_packs.main(["sign", str(bundle), "--public", public]) == 1


def test_verify_refuses_a_bundle_this_commit_does_not_build(tmp_path: Path) -> None:
    """Security review of #163: publish rebuilds from the checked-out commit before signing."""
    good = tmp_path / "traps.json"
    good.write_bytes(trap_packs.release_bundle(21)[0])
    assert trap_packs.main(["verify", str(good)]) == 0
    doc = json.loads(good.read_bytes())
    doc["issued_at"] = "2030-01-01T00:00:00Z"  # only the time differs: fine
    good.write_bytes(json.dumps(doc).encode())
    assert trap_packs.main(["verify", str(good)]) == 0
    doc["disabled"] = [{"id": "log4j-log4shell", "reason": "x"}]
    bad = tmp_path / "bad.json"
    bad.write_bytes(json.dumps(doc).encode())
    assert trap_packs.main(["verify", str(bad)]) == 1
    doc["disabled"] = []
    doc["packs"][0]["title"] = "changed"
    bad.write_bytes(json.dumps(doc).encode())
    assert trap_packs.main(["verify", str(bad)]) == 1
