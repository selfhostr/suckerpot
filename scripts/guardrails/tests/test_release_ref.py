"""scripts/check-release-ref.sh and the first gate of the release workflow.

A release must come from reviewed code on main: the script runs against a real temporary git
repository, and a static test pins the shape of release.yml.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "check-release-ref.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
}


def _git(repo: Path, *args: str) -> str:
    git = shutil.which("git") or "git"
    env = {"PATH": os.environ["PATH"], "HOME": str(repo), **GIT_ENV}
    out = subprocess.run(  # noqa: S603
        [git, *args], cwd=repo, env=env, capture_output=True, text=True, check=True, timeout=60
    )
    return out.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository whose `main` is also the remote-tracking ref origin/main."""
    # The uv test image ships without git; CI and `just guardrails` containers that have it run these.
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _git(path, "commit", "-q", "--allow-empty", "-m", "first")
    _git(path, "commit", "-q", "--allow-empty", "-m", "second")
    _git(path, "update-ref", "refs/remotes/origin/main", "main")
    return path


def _run(repo: Path, tag: str, commit: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": os.environ["PATH"], "HOME": str(repo), **GIT_ENV}
    return subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT), tag, commit],  # noqa: S607
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_a_tag_on_main_passes(repo: Path) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    proc = _run(repo, "v1.2.3", head)
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


def test_an_older_commit_of_main_passes(repo: Path) -> None:
    first = _git(repo, "rev-parse", "HEAD~1")
    assert _run(repo, "v0.10.0", first).returncode == 0


def test_a_commit_only_on_a_side_branch_fails(repo: Path) -> None:
    _git(repo, "switch", "-q", "-c", "side")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "unreviewed")
    side = _git(repo, "rev-parse", "HEAD")
    proc = _run(repo, "v1.2.3", side)
    assert proc.returncode != 0
    assert "not part of origin/main" in proc.stderr


@pytest.mark.parametrize(
    "tag", ["1.2.3", "v1.2", "v1.2.3-rc1", "v1.2.3.4", "vx.y.z", "v1.2.3\nv9.9.9", "", "v1.2.3 "]
)
def test_a_malformed_tag_fails(repo: Path, tag: str) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    proc = _run(repo, tag, head)
    assert proc.returncode != 0
    assert "vMAJOR.MINOR.PATCH" in proc.stderr


def test_both_failures_are_reported_on_their_own_line(repo: Path) -> None:
    _git(repo, "switch", "-q", "-c", "side")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "unreviewed")
    proc = _run(repo, "latest", _git(repo, "rev-parse", "HEAD"))
    assert proc.returncode != 0
    assert len([line for line in proc.stderr.splitlines() if line.startswith("FAIL")]) == 2


def test_an_unknown_commit_fails(repo: Path) -> None:
    proc = _run(repo, "v1.2.3", "0" * 40)
    assert proc.returncode != 0
    assert "not in this clone" in proc.stderr


def test_a_missing_main_ref_fails(repo: Path) -> None:
    _git(repo, "update-ref", "-d", "refs/remotes/origin/main")
    proc = _run(repo, "v1.2.3", _git(repo, "rev-parse", "HEAD"))
    assert proc.returncode != 0
    assert "origin/main is not available" in proc.stderr


def test_the_script_needs_its_two_arguments(repo: Path) -> None:
    proc = subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT), "v1.2.3"],  # noqa: S607
        cwd=repo,
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2


# --- release.yml -------------------------------------------------------------------------------


def _jobs() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return data["jobs"]  # type: ignore[no-any-return]


def _needs(job: dict[str, Any]) -> set[str]:
    needs = job.get("needs") or []
    return {needs} if isinstance(needs, str) else set(needs)


def _ancestors(jobs: dict[str, Any], name: str) -> set[str]:
    seen: set[str] = set()
    todo = list(_needs(jobs[name]))
    while todo:
        current = todo.pop()
        if current not in seen:
            seen.add(current)
            todo.extend(_needs(jobs[current]))
    return seen


def test_the_check_job_runs_the_script_before_anything_else() -> None:
    jobs = _jobs()
    check = jobs["check"]
    assert not _needs(check)
    runs = "\n".join(step.get("run", "") for step in check["steps"])
    assert 'scripts/check-release-ref.sh "$TAG" "$COMMIT" origin/main' in runs
    checkout = check["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0  # origin/main must be in the clone
    assert "environment" not in check
    perms = check.get("permissions", {})
    assert "id-token" not in perms and perms.get("packages") != "write"


def test_every_other_job_depends_on_the_check_job() -> None:
    jobs = _jobs()
    for name in jobs:
        if name != "check":
            assert "check" in _ancestors(jobs, name), name


def test_jobs_that_sign_or_write_to_the_registry_run_in_the_release_environment() -> None:
    jobs = _jobs()
    guarded = []
    for name, job in jobs.items():
        perms = job.get("permissions", {})
        if perms.get("id-token") == "write" or perms.get("packages") == "write":
            guarded.append(name)
            assert job.get("environment") == "release", name
    assert {"build", "merge", "manifest"} <= set(guarded)
    # The job that publishes the release assets is held to the same gate.
    assert jobs["attach"].get("environment") == "release"
