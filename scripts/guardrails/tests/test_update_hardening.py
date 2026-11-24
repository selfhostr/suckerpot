"""Hardening of the automatic update: the age floor and the choice of the candidate release."""

import time

import pytest
from conftest import Sandbox
from test_auto_update import (
    ENV,
    names,
    publish,
    result,
    run_auto,
    stage_auto,
    stage_release,
    verify,
    write_exec,
)


def test_a_manifest_cannot_lower_the_minimum_age_below_48_hours(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, auto_min_age_h=0, released_at=int(time.time()) - 3600)
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 4
    assert "waits for 48 h" in proc.stderr
    # A manual update does not check the age.
    assert verify(sandbox, "v0.9.0").returncode == 0


def test_the_local_setting_can_raise_the_minimum_age_never_lower_it(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, released_at=int(time.time()) - 72 * 3600)
    sandbox.write_env(ENV + "AUTO_UPDATE_MIN_AGE_H=96\n")
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 4 and "waits for 96 h" in proc.stderr
    sandbox.write_env(ENV + "AUTO_UPDATE_MIN_AGE_H=1\n")
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 0
    publish(sandbox, released_at=int(time.time()) - 3600)
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 4
    sandbox.write_env(ENV + "AUTO_UPDATE_MIN_AGE_H=banana\n")
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 4 and "ignoring AUTO_UPDATE_MIN_AGE_H" in proc.stderr


def test_the_manifest_can_still_raise_the_minimum_age(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, auto_min_age_h=200, released_at=int(time.time()) - 72 * 3600)
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 4


def test_a_download_problem_is_not_a_verdict(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_RELEASE_RC"] = "9"
    assert run_auto(sandbox).returncode == 1
    assert result(sandbox)["error_code"] == "verification_unavailable"
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions").exists()


def test_a_release_that_fails_verification_is_marked_bad_and_the_next_one_is_tried(
    sandbox: Sandbox,
) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.7.0\nv0.8.0\nv0.9.0\nv0.9.1\n")
    # The newest tag fails; the one before it passes.
    stub = sandbox.root / "scripts" / "verify-release.sh"
    text = stub.read_text().replace(
        'exit "${SHIM_RELEASE_RC:-0}"', '[ "$2" = v0.9.1 ] && exit 6\nexit 0'
    )
    stub.write_text(text)
    assert run_auto(sandbox).returncode == 0
    calls = sandbox.calls()
    assert "verify-release --auto v0.9.1" in calls and "verify-release --auto v0.9.0" in calls
    assert "update --yes --auto v0.9.0 lock_held=1" in calls
    state = sandbox.root / ".suckerpot-state"
    assert (state / "bad-versions").read_text() == "v0.9.1\n"
    assert "v0.9.1 signature_invalid" in (state / "bad-versions.log").read_text()
    assert result(sandbox)["last_result"] == "updated"


def test_at_most_three_candidates_are_tried_and_none_is_older_than_the_installed(
    sandbox: Sandbox,
) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.7.0\nv0.8.0\nv0.8.1\nv0.8.2\nv0.8.3\nv0.8.4\nv0.8.5\n")
    sandbox.env["SHIM_RELEASE_RC"] = "5"
    assert run_auto(sandbox).returncode == 0
    tried = [c for c in sandbox.calls() if c.startswith("verify-release")]
    assert tried == [f"verify-release --auto v0.8.{n}" for n in (5, 4, 3)]
    assert result(sandbox)["error_code"] == "commit_mismatch"
    assert names(sandbox) == []
    bad = (sandbox.root / ".suckerpot-state" / "bad-versions").read_text().split()
    assert bad == ["v0.8.5", "v0.8.4", "v0.8.3"]


def _young(sandbox: Sandbox, *tags: str) -> None:
    """verify-release.sh --auto answers 4 (too young) for TAGS and 0 for the others."""
    stub = sandbox.root / "scripts" / "verify-release.sh"
    checks = "".join(f'[ "$2" = {t} ] && exit 4\n' for t in tags)
    stub.write_text(stub.read_text().replace('exit "${SHIM_RELEASE_RC:-0}"', checks + "exit 0"))


def test_a_young_newest_release_falls_back_to_an_older_eligible_one(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.8.0\nv0.9.0\nv0.9.1\nv0.9.2\n")
    _young(sandbox, "v0.9.2", "v0.9.1")
    assert run_auto(sandbox).returncode == 0
    tried = [c for c in sandbox.calls() if c.startswith("verify-release")]
    assert tried == [f"verify-release --auto v0.9.{n}" for n in (2, 1, 0)]
    assert "update --yes --auto v0.9.0 lock_held=1" in sandbox.calls()
    res = result(sandbox)
    assert res["last_result"] == "updated"
    assert res["to"] == "v0.9.0" and res["waiting"] == "v0.9.2"
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions").exists()


def test_young_releases_do_not_use_up_the_three_tries(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    tags = [f"v0.8.{n}" for n in range(8)]
    sandbox.git_set("tags", "\n".join(tags) + "\n")
    # A burst: the six newest are all too young; v0.8.1 has waited long enough.
    _young(sandbox, *tags[2:])
    assert run_auto(sandbox).returncode == 0
    assert "update --yes --auto v0.8.1 lock_held=1" in sandbox.calls()
    assert result(sandbox)["waiting"] == "v0.8.7"


def test_only_young_releases_refuse_as_too_young_without_marking_them_bad(
    sandbox: Sandbox,
) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.8.0\nv0.9.0\nv0.9.1\n")
    sandbox.env["SHIM_RELEASE_RC"] = "4"
    assert run_auto(sandbox).returncode == 0
    res = result(sandbox)
    assert res["last_result"] == "refused" and res["error_code"] == "too_young"
    assert res["to"] == "v0.9.1"
    assert len([c for c in sandbox.calls() if c.startswith("verify-release")]) == 2
    assert names(sandbox) == []
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions").exists()


def test_at_most_ten_releases_are_checked_per_run(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.8.0\n" + "".join(f"v0.8.{n}\n" for n in range(1, 13)))
    sandbox.env["SHIM_RELEASE_RC"] = "4"
    assert run_auto(sandbox).returncode == 0
    assert len([c for c in sandbox.calls() if c.startswith("verify-release")]) == 10
    assert result(sandbox)["error_code"] == "too_young"
    assert names(sandbox) == []


# ---- what counts as a verdict on the release, and what is only a problem of this machine


def _only_marked(sandbox: Sandbox) -> list[str]:
    bad = sandbox.root / ".suckerpot-state" / "bad-versions"
    return bad.read_text().split() if bad.exists() else []


@pytest.mark.parametrize(("rc", "marked"), [(3, True), (5, True), (6, True)])
def test_only_real_verdicts_mark_a_release_bad(sandbox: Sandbox, rc: int, marked: bool) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.8.0\nv0.9.0\n")
    sandbox.env["SHIM_RELEASE_RC"] = str(rc)
    run_auto(sandbox)
    assert (_only_marked(sandbox) == ["v0.9.0"]) is marked


@pytest.mark.parametrize("rc", [1, 2, 4, 9, 11])
def test_a_missing_verdict_or_a_local_problem_never_marks_a_release(
    sandbox: Sandbox, rc: int
) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.8.0\nv0.9.0\n")
    sandbox.env["SHIM_RELEASE_RC"] = str(rc)
    run_auto(sandbox)
    assert _only_marked(sandbox) == []
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions.log").exists()
    assert len([c for c in sandbox.calls() if c.startswith("verify-release")]) == 1


def test_a_bundle_answering_503_is_a_transient_problem(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    write_exec(
        sandbox.shim / "curl",
        '#!/bin/sh\nfor a; do last=$a; done\ncase "$*" in\n'
        '  *sigstore.json*) : > "$4"; printf 503 ;;\n'
        '  *) cp "$SHIM_DIR/assets/release-manifest.json" "$4"; printf 200 ;;\n'
        "esac\n",
    )
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 9 and "HTTP 503" in proc.stderr


def test_cosign_naming_a_bad_identity_is_a_rejection(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    sandbox.env["SHIM_COSIGN_RC"] = "1"
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 6


@pytest.mark.parametrize(
    "error",
    [
        "Error: getting trusted root: Get https://tuf-repo-cdn.sigstore.dev: dial tcp: i/o timeout",
        "error updating TUF root: no such host",
        "something nobody has seen before",
        "",
    ],
)
def test_cosign_without_a_clear_rejection_is_no_verdict(sandbox: Sandbox, error: str) -> None:
    stage_release(sandbox)
    sandbox.env["SHIM_COSIGN_RC"] = "1"
    sandbox.env["SHIM_COSIGN_ERR"] = error or " "
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 9


@pytest.mark.parametrize("rc", ["125", "126", "127"])
def test_a_verifier_container_that_cannot_start_is_no_verdict(sandbox: Sandbox, rc: str) -> None:
    stage_release(sandbox)
    sandbox.env["SHIM_COSIGN_RC"] = rc
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 9


def test_a_verifier_image_that_cannot_be_pulled_is_no_verdict(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    sandbox.env["SHIM_NO_COSIGN_IMAGE"] = "1"
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 9
    assert not any("verify-blob" in c for c in sandbox.calls())
