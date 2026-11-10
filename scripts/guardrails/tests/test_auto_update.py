"""Automatic update (M32): auto-update.sh, verify-release.sh and lib/schedule.sh, on fakes.

Nothing here reaches Docker, git, GitHub or Sigstore: the sandbox of conftest.py puts fake
`docker`, `git`, `curl` and `sleep` first on PATH, and these tests add fakes for `crontab`,
`systemctl` and `loginctl` where needed.
"""

import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import ROOT, Sandbox

OLD = "a" * 40
NEW = "b" * 40
DEFAULTS = "NETWORK_DEFAULTS_VERSION=1\nNETWORK_HUB_URL=https://hub.example.org\n"

ENV = """\
COMPOSE_PROJECT_NAME=demo
SUCKERPOT_VOLUME_PREFIX=demo
SUCKERPOT_INSTALL_MODE=images
SUCKERPOT_VERSION=v0.8.0
AUTO_UPDATE_ENABLED=true
"""

EXTRA = [
    "scripts/auto-update.sh",
    "scripts/verify-release.sh",
    "scripts/lib/schedule.sh",
]


def stage(sb: Sandbox) -> None:
    """Copies the new scripts into the sandbox and sets a typical images install."""
    for rel in EXTRA:
        dest = sb.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest)
    (sb.root / "config").mkdir(exist_ok=True)
    (sb.root / "config" / "network-defaults.env").write_text(DEFAULTS)
    sb.write_env(ENV)
    sb.git_mode("normal")
    sb.git_set("head", OLD)
    sb.git_set("tags", "v0.7.0\nv0.8.0\nv0.9.0\n")
    sb.env["AUTO_UPDATE_JITTER_S"] = "0"


def write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


# ------------------------------------------------------------------ auto-update.sh

STUB_RELEASE = """#!/bin/sh
echo "verify-release $*" >> "$SHIM_LOG"
echo "commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
for n in redis migrate ingest api collector hubproxy demo sensor-ssh sensor-rdp sensor-telnet sensor-web \
  sensor-redis sensor-docker sensor-mysql sensor-mssql sensor-adb sensor-smb sensor-sip sensor-synology; do
  echo "image.$n=sha256:0000000000000000000000000000000000000000000000000000000000000000"
done
exit "${SHIM_RELEASE_RC:-0}"
"""
STUB_IMAGES = """#!/bin/sh
echo "verify-images $*" >> "$SHIM_LOG"
exit "${SHIM_IMAGES_RC:-0}"
"""
STUB_UPDATE = """#!/bin/sh
echo "update $* lock_held=${SELFHOSTR_UPDATE_LOCK_HELD:-}" >> "$SHIM_LOG"
if [ "${SHIM_UPDATE_MOVES_HEAD:-0}" = 1 ]; then
  printf %s "$SHIM_NEW_HEAD" > "$SHIM_DIR/gitstate/head"
  mkdir -p .suckerpot-state
  printf '{\\n  "completed": false,\\n  "from_version": "v0.8.0"\\n}\\n' > .suckerpot-state/last-update.json
fi
if [ "${SHIM_UPDATE_RC:-0}" = 0 ]; then
  printf '{\\n  "completed": true,\\n  "from_version": "v0.8.0"\\n}\\n' > .suckerpot-state/last-update.json
fi
exit "${SHIM_UPDATE_RC:-0}"
"""
STUB_ROLLBACK = """#!/bin/sh
echo "rollback $*" >> "$SHIM_LOG"
exit "${SHIM_ROLLBACK_RC:-0}"
"""


def stage_auto(sb: Sandbox) -> None:
    stage(sb)
    for name, text in {
        "verify-release.sh": STUB_RELEASE,
        "verify-images.sh": STUB_IMAGES,
        "update.sh": STUB_UPDATE,
        "rollback.sh": STUB_ROLLBACK,
    }.items():
        write_exec(sb.root / "scripts" / name, text)
    sb.env["SHIM_NEW_HEAD"] = NEW


def run_auto(sb: Sandbox) -> subprocess.CompletedProcess[str]:
    return sb.run("scripts/auto-update.sh")


def result(sb: Sandbox) -> dict[str, str]:
    data: dict[str, str] = json.loads(
        (sb.root / ".suckerpot-state" / "auto-update.json").read_text()
    )
    return data


def names(sb: Sandbox) -> list[str]:
    return [c.split()[0] for c in sb.calls() if c.split()[0] in {"update", "rollback"}]


def test_a_signed_old_enough_release_is_installed(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    proc = run_auto(sandbox)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = sandbox.calls()
    assert "verify-release --auto v0.9.0" in calls
    assert any(c.startswith("verify-images --expect ") and c.endswith(" v0.9.0") for c in calls)
    assert "update --yes --auto v0.9.0 lock_held=1" in calls
    # Both checks run before the update.
    first_images = next(i for i, c in enumerate(calls) if c.startswith("verify-images"))
    assert first_images < calls.index("update --yes --auto v0.9.0 lock_held=1")
    assert (result(sandbox)["last_result"], result(sandbox)["to"]) == ("updated", "v0.9.0")
    assert result(sandbox)["from"] == "v0.8.0"
    assert "updated" in proc.stdout


def test_it_does_nothing_when_off_or_not_images_mode(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.write_env(ENV.replace("AUTO_UPDATE_ENABLED=true", "AUTO_UPDATE_ENABLED=false"))
    assert run_auto(sandbox).returncode == 0
    sandbox.write_env(ENV.replace("true", "yes"))
    assert run_auto(sandbox).returncode == 0
    assert sandbox.calls() == []
    assert not (sandbox.root / ".suckerpot-state" / "auto-update.json").exists()
    sandbox.write_env(ENV.replace("images", "source"))
    assert run_auto(sandbox).returncode == 0
    assert result(sandbox)["error_code"] == "source_mode"
    assert names(sandbox) == []


def test_it_stops_after_an_unfinished_update(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    state = sandbox.root / ".suckerpot-state"
    state.mkdir()
    (state / "last-update.json").write_text(
        '{\n  "completed": false,\n  "from_version": "v0.8.0"\n}\n'
    )
    assert run_auto(sandbox).returncode == 0
    assert result(sandbox)["error_code"] == "unfinished_update"
    assert names(sandbox) == []


def test_other_majors_and_old_tags_are_never_installed(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.7.0\nv0.8.0\nv1.0.0\nv1.2.3\n")
    assert run_auto(sandbox).returncode == 0
    assert result(sandbox)["error_code"] == "up_to_date"
    assert names(sandbox) == []
    sandbox.git_set("tags", "v0.8.0\nv0.9.0\nv1.0.0\nv0.9.1-rc1\n")
    assert run_auto(sandbox).returncode == 0
    assert "update --yes --auto v0.9.0 lock_held=1" in sandbox.calls()


def test_a_version_marked_bad_is_not_tried_again(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.8.0\nv0.9.0\nv0.9.1\n")
    state = sandbox.root / ".suckerpot-state"
    state.mkdir()
    (state / "bad-versions").write_text("v0.9.1\n")
    assert run_auto(sandbox).returncode == 0
    assert "update --yes --auto v0.9.0 lock_held=1" in sandbox.calls()


@pytest.mark.parametrize(
    ("rc", "code"),
    [
        (3, "not_signed"),
        (4, "too_young"),
        (5, "commit_mismatch"),
        (6, "signature_invalid"),
        (1, "manifest_invalid"),
    ],
)
def test_a_release_that_does_not_verify_is_refused(sandbox: Sandbox, rc: int, code: str) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_RELEASE_RC"] = str(rc)
    assert run_auto(sandbox).returncode == 0
    assert result(sandbox)["last_result"] == "refused"
    assert result(sandbox)["error_code"] == code
    assert names(sandbox) == []
    assert not any(c.startswith("verify-images") for c in sandbox.calls())


def test_images_that_do_not_verify_are_refused_before_any_change(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_IMAGES_RC"] = "1"
    assert run_auto(sandbox).returncode == 0
    assert result(sandbox)["error_code"] == "images_unverified"
    assert names(sandbox) == []


def test_a_failed_update_rolls_back_and_remembers_the_version(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_UPDATE_RC"] = "10"  # update.sh: a regression caused by the release
    sandbox.env["SHIM_UPDATE_MOVES_HEAD"] = "1"
    proc = run_auto(sandbox)
    assert proc.returncode == 1
    assert names(sandbox) == ["update", "rollback"]
    assert "rollback --yes" in sandbox.calls()
    assert (sandbox.root / ".suckerpot-state" / "bad-versions").read_text() == "v0.9.0\n"
    assert result(sandbox)["error_code"] == "update_failed_rolled_back"
    # The next run does not retry that version.
    sandbox.log.write_text("")
    sandbox.git_set("head", OLD)
    (sandbox.root / ".suckerpot-state" / "last-update.json").write_text(
        '{\n  "completed": true,\n}\n'
    )
    assert run_auto(sandbox).returncode == 0
    assert names(sandbox) == []
    assert result(sandbox)["error_code"] == "up_to_date"


def test_a_failed_update_that_is_not_a_regression_is_retried(sandbox: Sandbox) -> None:
    """A failure not caused by the release (for example a node that was already degraded) never
    blacklists the version: it is rolled back and tried again on the next run."""
    stage_auto(sandbox)
    sandbox.env["SHIM_UPDATE_RC"] = "1"
    sandbox.env["SHIM_UPDATE_MOVES_HEAD"] = "1"
    assert run_auto(sandbox).returncode == 1
    assert names(sandbox) == ["update", "rollback"]
    assert result(sandbox)["error_code"] == "update_failed_rolled_back"
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions").exists()
    # The next run tries the same release again.
    sandbox.log.write_text("")
    sandbox.git_set("head", OLD)
    (sandbox.root / ".suckerpot-state" / "last-update.json").write_text(
        '{\n  "completed": true,\n}\n'
    )
    sandbox.env["SHIM_UPDATE_RC"] = "0"
    assert run_auto(sandbox).returncode == 0
    assert names(sandbox) == ["update"]
    assert result(sandbox)["last_result"] == "updated"


def fail_once_more(sb: Sandbox) -> None:
    """One more automatic run whose update fails (not a regression) and is rolled back."""
    sb.log.write_text("")
    sb.git_set("head", OLD)
    (sb.root / ".suckerpot-state" / "last-update.json").write_text('{\n  "completed": true,\n}\n')
    assert run_auto(sb).returncode == 1


def test_repeated_non_regression_failures_blacklist_after_three_attempts(
    sandbox: Sandbox,
) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_UPDATE_RC"] = "1"
    sandbox.env["SHIM_UPDATE_MOVES_HEAD"] = "1"
    state = sandbox.root / ".suckerpot-state"
    assert run_auto(sandbox).returncode == 1
    assert (state / "update-attempts").read_text() == "v0.9.0 1\n"
    assert not (state / "bad-versions").exists()
    fail_once_more(sandbox)
    assert (state / "update-attempts").read_text() == "v0.9.0 2\n"
    assert not (state / "bad-versions").exists()
    fail_once_more(sandbox)
    assert (state / "bad-versions").read_text() == "v0.9.0\n"
    assert "update_failed_repeatedly" in (state / "bad-versions.log").read_text()
    assert not (state / "update-attempts").exists()


def test_the_attempt_cap_is_configurable(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_UPDATE_RC"] = "1"
    sandbox.env["SHIM_UPDATE_MOVES_HEAD"] = "1"
    sandbox.env["AUTO_UPDATE_MAX_ATTEMPTS"] = "1"
    assert run_auto(sandbox).returncode == 1
    assert (sandbox.root / ".suckerpot-state" / "bad-versions").read_text() == "v0.9.0\n"


def test_a_success_resets_the_attempt_counter(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_UPDATE_RC"] = "1"
    sandbox.env["SHIM_UPDATE_MOVES_HEAD"] = "1"
    state = sandbox.root / ".suckerpot-state"
    assert run_auto(sandbox).returncode == 1
    assert (state / "update-attempts").exists()
    sandbox.log.write_text("")
    sandbox.git_set("head", OLD)
    (state / "last-update.json").write_text('{\n  "completed": true,\n}\n')
    sandbox.env["SHIM_UPDATE_RC"] = "0"
    assert run_auto(sandbox).returncode == 0
    assert names(sandbox) == ["update"]
    assert not (state / "update-attempts").exists()


def test_a_failed_rollback_is_reported_and_blocks_later_runs(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_UPDATE_RC"] = "10"
    sandbox.env["SHIM_UPDATE_MOVES_HEAD"] = "1"
    sandbox.env["SHIM_ROLLBACK_RC"] = "1"
    assert run_auto(sandbox).returncode == 1
    assert result(sandbox)["error_code"] == "rollback_failed"
    sandbox.log.write_text("")
    assert run_auto(sandbox).returncode == 0  # the unfinished-update lock holds
    assert result(sandbox)["error_code"] == "unfinished_update"
    assert names(sandbox) == []


def test_an_early_failure_changes_nothing_so_nothing_is_rolled_back(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_UPDATE_RC"] = "1"  # e.g. the backup failed: the code never moved
    assert run_auto(sandbox).returncode == 1
    assert names(sandbox) == ["update"]
    assert result(sandbox)["error_code"] == "update_failed"
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions").exists()


def test_a_second_run_waits_for_the_lock_and_exits_quietly(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    state = sandbox.root / ".suckerpot-state"
    state.mkdir()
    held = subprocess.Popen(  # noqa: S603
        ["flock", str(state / "update.lock"), "sleep", "20"],  # noqa: S607
    )
    try:
        time.sleep(0.5)
        proc = run_auto(sandbox)
        assert proc.returncode == 0
        assert sandbox.calls() == []
    finally:
        held.kill()
        held.wait()


def test_the_log_is_private_and_rotated(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    state = sandbox.root / ".suckerpot-state"
    state.mkdir()
    (state / "auto-update.log").write_text("x" * (1024 * 1024 + 10))
    assert run_auto(sandbox).returncode == 0
    assert (state / "auto-update.log.1").exists()
    log = state / "auto-update.log"
    assert log.stat().st_size < 4096
    assert oct(log.stat().st_mode & 0o777) == "0o600"
    assert oct(state.stat().st_mode & 0o777) == "0o700"


def test_the_sleep_is_a_random_jitter_up_to_half_an_hour(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    del sandbox.env["AUTO_UPDATE_JITTER_S"]
    write_exec(sandbox.shim / "sleep", '#!/bin/sh\necho "sleep $*" >> "$SHIM_LOG"\n')
    assert run_auto(sandbox).returncode == 0
    waited = [int(c.split()[1]) for c in sandbox.calls() if c.startswith("sleep ")]
    assert len(waited) == 1 and 0 <= waited[0] <= 1800


def test_no_sudo_and_no_container_with_the_docker_socket() -> None:
    for rel in ("scripts/auto-update.sh", "scripts/lib/schedule.sh", "scripts/verify-release.sh"):
        code = "\n".join(
            line
            for line in (ROOT / rel).read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "sudo" not in code
        assert "docker.sock" not in code


# ------------------------------------------------------------------ verify-release.sh

CURL_SHIM = r"""#!/bin/sh
# Fake curl: serves $SHIM_DIR/assets/<file name of the URL> or answers 404.
echo "curl $*" >> "$SHIM_LOG"
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;;
    http*) url=$1 ;;
  esac
  shift
done
file="$SHIM_DIR/assets/${url##*/}"
if [ -f "$file" ]; then cp "$file" "$out"; printf 200; else : > "$out"; printf 404; fi
"""

DOCKER_SHIM = r"""#!/bin/sh
case "$*" in
  "image inspect "*|"pull "*) [ -z "${SHIM_NO_COSIGN_IMAGE:-}" ] || exit 1 ;;
  *verify-blob*)
    echo "docker $*" >> "$SHIM_LOG"
    rc=${SHIM_COSIGN_RC:-0}
    if [ "$rc" != 0 ]; then
      echo "${SHIM_COSIGN_ERR:-Error: none of the expected identities matched what was in the certificate}" >&2
    fi
    exit "$rc" ;;
esac
exec "$(dirname "$0")/docker.real" "$@"
"""

GIT_SHIM = r"""#!/bin/sh
case "$*" in
  "show v"*":config/network-defaults.env") echo "git $*" >> "$SHIM_LOG"; cat "$SHIM_DIR/defaults" ;;
  *) exec "$(dirname "$0")/git.real" "$@" ;;
esac
"""


def stage_release(sb: Sandbox) -> None:
    stage(sb)
    for name, text in (("docker", DOCKER_SHIM), ("git", GIT_SHIM)):
        (sb.shim / name).rename(sb.shim / f"{name}.real")
        write_exec(sb.shim / name, text)
    write_exec(sb.shim / "curl", CURL_SHIM)
    (sb.shim / "assets").mkdir()
    (sb.shim / "defaults").write_text(DEFAULTS)
    sb.git_set("tagcommit", NEW)
    publish(sb)


def publish(sb: Sandbox, tag: str = "v0.9.0", **override: Any) -> None:
    manifest: dict[str, object] = {
        "schema": "selfhostr-release/1",
        "version": tag,
        "commit": NEW,
        "images": {"ingest": "sha256:" + "1" * 64, "hubproxy": "sha256:" + "2" * 64},
        "network_defaults_sha256": hashlib.sha256(DEFAULTS.encode()).hexdigest(),
        "auto_min_age_h": 48,
        "major": int(tag[1:].split(".")[0]),
        "released_at": int(time.time()) - 72 * 3600,
    }
    manifest.update(override)
    assets = sb.shim / "assets"
    (assets / "release-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    (assets / "release-manifest.json.sigstore.json").write_text("{}")


def verify(sb: Sandbox, *args: str) -> subprocess.CompletedProcess[str]:
    return sb.run("scripts/verify-release.sh", *args)


def test_a_valid_manifest_verifies_and_prints_the_age(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 0, proc.stderr
    out = dict(line.split("=", 1) for line in proc.stdout.splitlines())
    assert out["version"] == "v0.9.0" and out["commit"] == NEW
    assert 71 <= int(out["age_h"]) <= 73 and out["auto_min_age_h"] == "48" and out["major"] == "0"
    calls = "\n".join(sandbox.calls())
    # Fetched over https from the release of the configured repository, then verified by cosign
    # against the workflow identity of that exact tag.
    assert "--proto =https" in calls
    assert (
        "https://github.com/selfhostr/suckerpot/releases/download/v0.9.0/release-manifest.json"
        in calls
    )
    assert "verify-blob" in calls and "--bundle /m/release-manifest.json.sigstore.json" in calls
    assert r"release\.yml@refs/tags/v0\.9\.0$" in calls
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in calls


def test_a_bad_signature_is_refused_before_the_file_is_trusted(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    sandbox.env["SHIM_COSIGN_RC"] = "1"
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 6
    assert proc.stdout == ""


def test_a_missing_bundle_means_not_signed(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    (sandbox.shim / "assets" / "release-manifest.json.sigstore.json").unlink()
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 3


def test_a_missing_manifest_is_only_tolerated_for_a_release_that_predates_them(
    sandbox: Sandbox,
) -> None:
    stage_release(sandbox)
    (sandbox.shim / "assets" / "release-manifest.json").unlink()
    assert verify(sandbox, "v0.5.0").returncode == 3  # manual, before v0.6.0
    assert verify(sandbox, "v0.9.0").returncode == 1  # manual, should have one
    assert verify(sandbox, "--auto", "v0.5.0").returncode == 3  # automatic: never accepted
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 3


def test_the_commit_must_be_the_commit_of_the_tag(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    sandbox.git_set("tagcommit", "c" * 40)  # the tag was moved after signing
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 5
    assert "signed manifest names" in proc.stderr


@pytest.mark.parametrize(
    "override",
    [
        {"version": "v0.9.1"},
        {"schema": "selfhostr-release/9"},
        {"commit": "not-a-commit"},
        {"major": 1},
        {"network_defaults_sha256": "d" * 64},
        {"images": {"ingest": "sha256:short"}},
        {"images": {}},
        {"released_at": int(time.time()) + 7 * 86400},
        {"auto_min_age_h": 100000},
    ],
)
def test_a_manifest_that_does_not_match_the_tag_is_refused(
    sandbox: Sandbox, override: dict[str, Any]
) -> None:
    stage_release(sandbox)
    publish(sandbox, **override)
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 5


def test_a_young_release_is_refused_only_for_an_automatic_update(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, released_at=int(time.time()) - 3600)
    assert verify(sandbox, "v0.9.0").returncode == 0
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 4
    assert "waits for 48 h" in proc.stderr
    publish(sandbox, released_at=int(time.time()) - 49 * 3600)
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 0


def test_the_transparency_log_time_cannot_be_older_than_the_signed_one(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, released_at=int(time.time()) - 100 * 3600)
    bundle = sandbox.shim / "assets" / "release-manifest.json.sigstore.json"
    bundle.write_text(
        json.dumps({"tlogEntries": [{"integratedTime": str(int(time.time()) - 3600)}]})
    )
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 4


def test_bad_arguments(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    assert verify(sandbox).returncode == 2
    assert verify(sandbox, "latest").returncode == 2
    assert verify(sandbox, "v1.2.3; rm -rf /").returncode == 2


def test_a_fork_checks_its_own_workflow(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    sandbox.write_env(ENV + "SUCKERPOT_IMAGE_PREFIX=ghcr.io/example-org/forked\n")
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 0
    calls = "\n".join(sandbox.calls())
    assert "https://github.com/example-org/forked/releases/download/v0.9.0/" in calls
    assert r"github\.com/example-org/forked/\.github/workflows/release" in calls


# ------------------------------------------------------------------ schedule.sh

CRONTAB_SHIM = r"""#!/bin/sh
# Fake crontab backed by $SHIM_DIR/crontab.data. SHIM_CRONTAB_BROKEN makes it unusable.
echo "crontab $*" >> "$SHIM_LOG"
if [ -n "${SHIM_CRONTAB_BROKEN:-}" ]; then echo "crontab: cannot open the spool" >&2; exit 1; fi
case "$1" in
  -l) if [ -f "$SHIM_DIR/crontab.data" ]; then cat "$SHIM_DIR/crontab.data"; else echo "no crontab for demo" >&2; exit 1; fi ;;
  -r) rm -f "$SHIM_DIR/crontab.data" ;;
  -) cat > "$SHIM_DIR/crontab.data" ;;
esac
"""

SYSTEMCTL_SHIM = '#!/bin/sh\necho "systemctl $*" >> "$SHIM_LOG"\nexit 0\n'
LOGINCTL_SHIM = '#!/bin/sh\necho "${SHIM_LINGER:-yes}"\n'


def stage_schedule(sb: Sandbox) -> None:
    stage(sb)
    write_exec(sb.shim / "crontab", CRONTAB_SHIM)
    write_exec(sb.shim / "systemctl", SYSTEMCTL_SHIM)
    write_exec(sb.shim / "loginctl", LOGINCTL_SHIM)
    sb.env["XDG_CONFIG_HOME"] = str(sb.shim / "config")


def sched(sb: Sandbox, body: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", "-c", f". scripts/lib/schedule.sh; {body}"],  # noqa: S607
        cwd=sb.root,
        env=sb.env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def crontab_text(sb: Sandbox) -> str:
    path = sb.shim / "crontab.data"
    return path.read_text() if path.exists() else ""


def test_install_adds_one_marked_line_and_keeps_the_others(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    (sandbox.shim / "crontab.data").write_text("MAILTO=\n0 1 * * * /usr/bin/backup\n")
    assert sched(sandbox, "schedule_install 4 37").returncode == 0
    text = crontab_text(sandbox)
    assert text.startswith("MAILTO=\n0 1 * * * /usr/bin/backup\n")
    mine = [line for line in text.splitlines() if "selfhostr-auto-update" in line]
    assert len(mine) == 1
    assert re.fullmatch(
        rf"37 4 \* \* \* cd {re.escape(str(sandbox.root))} && bash scripts/auto-update\.sh "
        r"> /dev/null 2>&1 # selfhostr-auto-update demo",
        mine[0],
    )


def test_install_is_idempotent_and_moves_the_time(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    for hm in ("4 37", "4 37", "3 05"):
        assert sched(sandbox, f"schedule_install {hm}").returncode == 0
    lines = [line for line in crontab_text(sandbox).splitlines() if "selfhostr-auto-update" in line]
    assert len(lines) == 1 and lines[0].startswith("5 3 * * *")
    status = sched(sandbox, "schedule_status")
    assert status.returncode == 0 and status.stdout.strip() == "cron 03:05"


def test_remove_only_touches_its_own_line(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    (sandbox.shim / "crontab.data").write_text(
        "0 1 * * * /usr/bin/backup\n"
        "9 9 * * * cd /srv/other && bash scripts/auto-update.sh # selfhostr-auto-update other\n"
    )
    assert sched(sandbox, "schedule_install 4 10; schedule_remove").returncode == 0
    text = crontab_text(sandbox)
    assert "/usr/bin/backup" in text and "selfhostr-auto-update other" in text
    assert "selfhostr-auto-update demo" not in text
    assert sched(sandbox, "schedule_status").returncode == 1
    assert sched(sandbox, "schedule_remove").returncode == 0  # idempotent


def test_remove_with_no_crontab_is_fine_and_status_says_off(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    assert sched(sandbox, "schedule_remove").returncode == 0
    status = sched(sandbox, "schedule_status")
    assert status.returncode == 1 and status.stdout.strip() == "off"


def test_bad_times_are_refused(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    for hm in ("24 0", "4 60", "x 1", "4", "-1 0"):
        assert sched(sandbox, f"schedule_install {hm}").returncode != 0, hm
    assert crontab_text(sandbox) == ""


def test_random_time_is_in_the_night_window(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    for _ in range(30):
        hour, minute = sched(sandbox, "schedule_random_time").stdout.split()
        assert 3 <= int(hour) <= 5 and 0 <= int(minute) <= 59


def test_an_unreadable_crontab_is_never_overwritten(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    sandbox.env["SHIM_CRONTAB_BROKEN"] = "1"
    proc = sched(sandbox, 'schedule_install 4 10; echo "method=${SCHEDULE_METHOD:-}"')
    assert not any(c == "crontab -" for c in sandbox.calls())
    # It fell back to a systemd user timer instead.
    assert "method=systemd" in proc.stdout


def test_systemd_user_timer_fallback_and_removal(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    sandbox.env["SHIM_CRONTAB_BROKEN"] = "1"
    assert sched(sandbox, "schedule_install 5 59").returncode == 0
    units = sandbox.shim / "config" / "systemd" / "user"
    timer = (units / "selfhostr-auto-update-demo.timer").read_text()
    service = (units / "selfhostr-auto-update-demo.service").read_text()
    assert "OnCalendar=*-*-* 05:59:00" in timer
    assert f"WorkingDirectory={sandbox.root}" in service
    assert "ExecStart=/usr/bin/env bash scripts/auto-update.sh" in service
    calls = sandbox.calls()
    assert "systemctl --user enable --now selfhostr-auto-update-demo.timer" in calls
    status = sched(sandbox, "schedule_status")
    assert status.stdout.strip() == "systemd 05:59"
    assert sched(sandbox, "schedule_remove").returncode == 0
    assert not (units / "selfhostr-auto-update-demo.timer").exists()
    assert "systemctl --user disable --now selfhostr-auto-update-demo.timer" in sandbox.calls()
    assert not any(c.startswith("sudo") for c in sandbox.calls())


def test_systemd_fallback_warns_when_lingering_is_off(sandbox: Sandbox) -> None:
    stage_schedule(sandbox)
    sandbox.env["SHIM_CRONTAB_BROKEN"] = "1"
    sandbox.env["SHIM_LINGER"] = "no"
    proc = sched(sandbox, "schedule_install 4 0")
    assert proc.returncode == 0
    assert "lingering is off" in proc.stderr


# ------------------------------------------------------------------ verify-images.sh and hubproxy

TREE_GIT_SHIM = r"""#!/bin/sh
case "$*" in
  "cat-file -e "*":hubproxy/Dockerfile")
    echo "git $*" >> "$SHIM_LOG"
    [ "${SHIM_HUBPROXY_IN_TREE:-1}" = 1 ] ;;
  *) exec "$(dirname "$0")/git.real" "$@" ;;
esac
"""


def stage_images(sb: Sandbox, tags: str) -> None:
    sb.write_env(ENV)
    sb.git_mode("normal")
    sb.git_set("tags", tags)
    (sb.shim / "git").rename(sb.shim / "git.real")
    write_exec(sb.shim / "git", TREE_GIT_SHIM)


def hubproxy_checked(sb: Sandbox) -> bool:
    return any("-hubproxy:" in c for c in sb.docker_calls())


def test_full_mode_rollback_target_without_hubproxy_skips_it(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.5.0\nv0.6.0\n")
    sandbox.env["SHIM_HUBPROXY_IN_TREE"] = "0"
    proc = sandbox.run("scripts/verify-images.sh", "v0.5.0")
    assert proc.returncode == 0, proc.stderr
    assert not hubproxy_checked(sandbox)
    assert "all 18 images" in proc.stdout


def test_a_release_that_ships_hubproxy_must_have_it_verified(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.5.0\nv0.6.0\n")
    proc = sandbox.run("scripts/verify-images.sh", "v0.6.0")
    assert proc.returncode == 0, proc.stderr
    assert hubproxy_checked(sandbox)
    assert "all 19 images" in proc.stdout


def test_an_unknown_tag_falls_back_to_the_version_number(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.1.0\n")
    assert sandbox.run("scripts/verify-images.sh", "v0.6.0").returncode == 0
    assert hubproxy_checked(sandbox)
    sandbox.log.write_text("")
    assert sandbox.run("scripts/verify-images.sh", "v0.5.9").returncode == 0
    assert not hubproxy_checked(sandbox)


def test_a_participant_install_refuses_a_target_without_hubproxy(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.5.0\n")
    sandbox.env["SHIM_HUBPROXY_IN_TREE"] = "0"
    sandbox.write_env(ENV + "SUCKERPOT_STACK_MODE=participant\n")
    proc = sandbox.run("scripts/verify-images.sh", "v0.5.0")
    assert proc.returncode != 0
    assert "needs a release from v0.6.0 on" in proc.stderr
    assert not hubproxy_checked(sandbox)


def test_asking_for_hubproxy_of_a_release_without_it_fails(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.5.0\n")
    sandbox.env["SHIM_HUBPROXY_IN_TREE"] = "0"
    proc = sandbox.run("scripts/verify-images.sh", "--only", "hubproxy", "v0.5.0")
    assert proc.returncode != 0


def expect_file(sb: Sandbox, digest: str, names: str = "redis api") -> Path:
    path = sb.root / "expect.txt"
    path.write_text("".join(f"image.{n}={digest}\n" for n in names.split()))
    return path


def test_images_matching_the_signed_manifest_pass(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.6.0\n")
    path = expect_file(sandbox, "sha256:" + "0" * 64)
    args = ("--only", "redis api", "--expect", str(path), "v0.6.0")
    proc = sandbox.run("scripts/verify-images.sh", *args)
    assert proc.returncode == 0, proc.stderr


def test_an_image_that_differs_from_the_signed_manifest_is_refused(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.6.0\n")
    path = expect_file(sandbox, "sha256:" + "1" * 64)
    args = ("--pull", "--only", "redis api", "--expect", str(path), "v0.6.0")
    proc = sandbox.run("scripts/verify-images.sh", *args)
    assert proc.returncode == 7
    assert "REFUSED redis" in proc.stderr
    assert not any(" pull " in c for c in sandbox.docker_calls())


def test_an_image_missing_from_the_signed_manifest_is_refused(sandbox: Sandbox) -> None:
    stage_images(sandbox, "v0.6.0\n")
    path = expect_file(sandbox, "sha256:" + "0" * 64, "redis")
    args = ("--only", "redis api", "--expect", str(path), "v0.6.0")
    assert sandbox.run("scripts/verify-images.sh", *args).returncode == 7
