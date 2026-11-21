"""Static checks of the trap pack signing workflow (M37 P2, design section 5 and D1)."""

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "trap-packs.yml"


def _load() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    data["triggers"] = data.pop(True, None) or data.get("on")  # PyYAML reads `on:` as True
    return data  # type: ignore[no-any-return]


def test_never_runs_on_pull_requests() -> None:
    """No secret may ever reach code that was not merged: only a push to main or a manual run."""
    triggers = _load()["triggers"]
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" not in WORKFLOW.read_text().replace("!= 'pull_request'", "")
    for name, job in _load()["jobs"].items():
        assert "refs/heads/main" in job["if"] and "!= 'pull_request'" in job["if"], name


def test_the_secret_lives_only_in_the_protected_environment_job() -> None:
    wf = _load()
    assert wf["permissions"] == {}
    jobs = wf["jobs"]
    assert set(jobs) == {"build", "publish"}
    assert jobs["publish"]["environment"] == "trap-packs"
    assert "environment" not in jobs["build"]
    assert jobs["build"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "write"}
    assert jobs["publish"]["needs"] == "build"
    # The pack secret appears in exactly one step, of the publish job.
    users = [
        (name, step.get("name"))
        for name, job in jobs.items()
        for step in job["steps"]
        if "TRAP_PACK_SECRET_KEY" in str(step)
    ]
    assert users == [("publish", "Sign and verify with the committed public key")]
    sign = next(s for s in jobs["publish"]["steps"] if s.get("name", "").startswith("Sign"))
    assert sign["env"] == {"TRAP_PACK_SECRET_KEY": "${{ secrets.TRAP_PACK_SECRET_KEY }}"}
    assert "trap_packs sign" in sign["run"]
    # The secret is only in the environment of the sign command, never while packages install.
    assert "uv sync" not in sign["run"] and "\n" not in sign["run"].strip()
    names = [s.get("name", "") for s in jobs["publish"]["steps"]]
    verify = names.index("Refuse a bundle this commit does not build")
    assert (
        names.index("Install the tool (no secret in this step)")
        < verify
        < names.index(sign["name"])
    )
    assert "trap_packs verify" in jobs["publish"]["steps"][verify]["run"]


def test_actions_are_pinned_and_checkout_keeps_no_credentials() -> None:
    for job in _load()["jobs"].values():
        for step in job["steps"]:
            uses = step.get("uses")
            if uses is None:
                continue
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", uses.split(" ")[0]), uses
            if uses.startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_the_bundle_is_checked_and_attached_to_the_fixed_release() -> None:
    text = WORKFLOW.read_text()
    assert "tools.trap_packs check" in text
    assert "tools.trap_packs release --seq" in text and "--previous" in text
    assert "gh release upload trap-packs" in text
    # The bundle is uploaded before its signature (the hub reads the signature first).
    assert text.index("--clobber dist/traps.json\n") < text.index(
        "--clobber dist/traps.json.minisig"
    )
