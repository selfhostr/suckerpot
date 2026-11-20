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
