"""scripts/update.sh and scripts/rollback.sh, run against fake docker and git (see conftest.py)."""

import re
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from conftest import ROOT, Sandbox

OLD = "a" * 40
NEW = "b" * 40

ENV = """\
COMPOSE_PROJECT_NAME=demo
SUCKERPOT_VOLUME_PREFIX=demo
SUCKERPOT_INSTALL_MODE=images
SUCKERPOT_VERSION=v0.8.0
DASHBOARD_PORT=8443
POSTGRES_PASSWORD=ownerpassword-aaaaaaaaaaaaaaaaaaaa
"""


RELEASE_STUB = """#!/bin/sh
echo "verify-release $*" >> "$SHIM_LOG"
echo "commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
for n in redis migrate ingest api collector hubproxy demo sensor-ssh sensor-rdp sensor-telnet sensor-web \
  sensor-redis sensor-docker sensor-mysql sensor-mssql sensor-adb sensor-smb sensor-sip sensor-synology; do
  echo "image.$n=sha256:0000000000000000000000000000000000000000000000000000000000000000"
done
exit "${SHIM_RELEASE_RC:-0}"
"""


def prepare(sb: Sandbox, mode: str = "images", branch: str = "") -> None:
    stub = sb.root / "scripts" / "verify-release.sh"
    stub.write_text(RELEASE_STUB)
    stub.chmod(0o755)
    sb.write_env(ENV.replace("images", mode))
    sb.git_mode("normal")
    sb.git_set("head", OLD)
    sb.git_set("tagcommit", NEW)
    sb.git_set("describe", "v0.8.0")
    sb.git_set("tags", "v0.8.0\nv0.9.0\nv0.7.0\n")
    sb.git_set("notes", "Adds the setup wizard.")
    sb.git_set("branch", branch)
    sb.env["SHIM_RUNNING_VERSION"] = "v0.9.0"
    sb.env["SHIM_EXISTING_VOLUMES"] = "demo_backups"


def run_update(sb: Sandbox, *args: str, stdin: str = "") -> tuple[int, str]:
    proc = sb.run("scripts/update.sh", *args, stdin=stdin)
    return proc.returncode, proc.stdout + proc.stderr


def test_update_images_mode_full_flow(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    calls = sandbox.calls()
    joined = "\n".join(calls)
    assert "Adds the setup wizard." in out
    # Backup first, then code, then images, then start.
    order = [
        joined.index("backup-service.sh now preupdate"),
        joined.index("git checkout --quiet --detach " + NEW),
        joined.index("cosign"),
        joined.index("docker compose up -d --no-build --pull never --wait --wait-timeout 600"),
    ]
    assert order == sorted(order)
    # Pulled by the digest cosign verified, then tagged; never pulled by tag.
    assert "docker pull --quiet ghcr.io/selfhostr/suckerpot-api@sha256:" in joined
    assert "docker tag ghcr.io/selfhostr/suckerpot-api@sha256:" in joined
    assert "docker compose pull --policy missing" in joined
    assert "docker compose pull\n" not in joined + "\n"
    assert re.search(r"SUCKERPOT_VERSION=v0\.9\.0", (sandbox.root / ".env").read_text())
    assert "# added by just update" in (sandbox.root / ".env").read_text()
    state = sandbox.root / ".suckerpot-state" / "last-update.json"
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.parent.stat().st_mode) == 0o700
    text = state.read_text()
    assert f'"from_ref": "{OLD}"' in text
    assert '"from_version": "v0.8.0"' in text
    assert '"dump": "suckerpot-preupdate-20261101T020000Z.dump"' in text
    assert '"mode": "images"' in text
    assert '"api": "sha256:0123456789abcdef"' in text
    assert "just rollback" in out


def test_update_takes_the_newest_tag_and_asks_to_confirm(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, stdin="n\n")
    assert rc != 0
    assert "target:  v0.9.0" in out
    assert not any("backup-service.sh" in c for c in sandbox.calls())
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_update_to_a_given_version(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.7.0"
    rc, out = run_update(sandbox, "--yes", "v0.7.0")
    assert rc == 0, out
    assert f"git checkout --quiet --detach {NEW}" in sandbox.calls()


def test_update_refuses_an_unknown_or_malformed_version(sandbox: Sandbox) -> None:
    prepare(sandbox)
    assert run_update(sandbox, "--yes", "v9.9.9")[0] != 0
    assert run_update(sandbox, "--yes", "v1.2")[0] != 0
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_update_stops_when_the_backup_fails(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_BACKUP_RC"] = "1"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "nothing was changed" in out
    assert not any(c.startswith("git checkout") for c in sandbox.calls())
    assert (sandbox.root / ".env").read_text().count("v0.8.0") == 1


def test_update_needs_a_healthy_backup_service(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_BACKUP_HEALTH"] = "unhealthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "backup" in out
    assert not any("backup-service.sh now" in c for c in sandbox.calls())


def test_no_backup_needs_the_typed_phrase(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, _ = run_update(sandbox, "--yes", "--no-backup", stdin="yes\n")
    assert rc != 0
    assert not any(c.startswith("git checkout") for c in sandbox.calls())
    rc, out = run_update(sandbox, "--yes", "--no-backup", stdin="no backup\n")
    assert rc == 0, out
    assert '"dump": ""' in (sandbox.root / ".suckerpot-state" / "last-update.json").read_text()


def test_source_mode_refuses_local_changes(sandbox: Sandbox) -> None:
    prepare(sandbox, mode="source")
    sandbox.git_set("dirty", " M docker-compose.yml\n")
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "local changes" in out
    assert not any("backup-service.sh" in c for c in sandbox.calls())


def test_source_mode_on_a_branch_pulls_fast_forward_only(sandbox: Sandbox) -> None:
    prepare(sandbox, mode="source", branch="main")
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.8.0"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "git pull --ff-only --quiet" in sandbox.calls()
    assert "docker compose build" in sandbox.calls()
    assert "docker compose pull" not in sandbox.calls()


def test_failed_start_prints_the_rollback_and_never_rolls_back(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_UP_RC"] = "1"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "just rollback" in out
    assert "suckerpot-preupdate-20261101T020000Z.dump" in out
    calls = "\n".join(sandbox.calls())
    assert "restore" not in calls
    assert calls.count("git checkout") == 1


def test_wrong_running_version_is_a_failure(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.8.0"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "reports version" in out


def test_update_refuses_worktrees_and_missing_names(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.git_mode("linked")
    assert run_update(sandbox, "--yes")[0] != 0
    sandbox.git_mode("normal")
    sandbox.write_env("DASHBOARD_PORT=8443\n")
    assert run_update(sandbox, "--yes")[0] != 0
    sandbox.write_env("COMPOSE_PROJECT_NAME=sp-test\nSUCKERPOT_VOLUME_PREFIX=sp-test\n")
    assert run_update(sandbox, "--yes")[0] != 0
    assert not any("backup-service.sh" in c for c in sandbox.calls())


# ------------------------------------------------------------------- rollback


def calls_of(sb: Sandbox) -> list[str]:
    return sb.calls()


def write_state(
    sb: Sandbox, dump: str = "suckerpot-preupdate-20261101T020000Z.dump", alembic: str | None = None
) -> None:
    state = sb.root / ".suckerpot-state"
    state.mkdir(exist_ok=True)
    (state / "last-update.json").write_text(
        "{\n"
        '  "from_version": "v0.8.0",\n'
        f'  "from_ref": "{OLD}",\n'
        '  "from_branch": "",\n'
        '  "mode": "images",\n'
        f'  "dump": "{dump}",\n'
        + (f'  "alembic_before": "{alembic}",\n' if alembic else "")
        + '  "target": "v0.9.0",\n'
        '  "at": "2026-11-01T02:00:00Z",\n'
        '  "images": {\n  }\n}\n'
    )


def test_rollback_restores_code_images_and_dump(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    # restore-db.sh has its own tests and confirmation; here it is replaced by a recorder.
    (sandbox.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restore-db volume:suckerpot-preupdate-20261101T020000Z.dump" in calls_of(sandbox)
    calls = sandbox.calls()
    joined = "\n".join(calls)
    assert f"git checkout --quiet --detach {OLD}" in calls
    assert "SUCKERPOT_VERSION=v0.8.0" in (sandbox.root / ".env").read_text()
    assert "docker compose pull --policy missing" in calls
    order = [
        joined.index("git checkout"),
        joined.index("cosign"),
        joined.index("docker compose up -d --no-build --pull never --wait --wait-timeout 600"),
    ]
    assert order == sorted(order)
    assert "events received since that dump are lost" in proc.stdout.lower()


def test_rollback_needs_the_typed_word(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    for answer in ("yes\n", "\n", "Rollback\n"):
        proc = sandbox.run("scripts/rollback.sh", stdin=answer)
        assert proc.returncode != 0
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_rollback_without_state_or_dump_does_nothing(sandbox: Sandbox) -> None:
    prepare(sandbox)
    assert sandbox.run("scripts/rollback.sh", stdin="rollback\n").returncode != 0
    write_state(sandbox, dump="")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "no backup" in proc.stderr or "without a backup" in proc.stderr
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_rollback_rejects_a_tampered_dump_name(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox, dump="x;rm -rf /.dump")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert not sandbox.docker_calls()


def test_update_and_rollback_use_only_the_documented_commands(
    parse_env: Callable[[Path], dict[str, str]],
) -> None:
    """The scripts never remove volumes or data, and never run compose with a project override."""
    for rel in ("scripts/update.sh", "scripts/rollback.sh", "scripts/install.sh"):
        code = "\n".join(
            line
            for line in (ROOT / rel).read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "down -v" not in code and "--volumes" not in code
        assert "volume rm" not in code and "volume prune" not in code
        assert "system prune" not in code
        assert not re.search(r"compose\s+(-p|--project-name)\b", code)


def test_update_ignores_stale_exported_values(sandbox: Sandbox) -> None:
    """`just` exports the OLD .env; the update must start the stack with the NEW file."""
    prepare(sandbox)
    sandbox.env["SUCKERPOT_VERSION"] = "v0.8.0"
    sandbox.env["DASHBOARD_PORT"] = "8443"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    up = [c for c in sandbox.calls() if c.startswith("ENV_AT_UP")]
    assert up and all("SUCKERPOT_VERSION=unset" in c and "DASHBOARD_PORT=unset" in c for c in up)
    assert "SUCKERPOT_VERSION=v0.9.0" in (sandbox.root / ".env").read_text()


def test_update_verifies_before_anything_runs_and_fails_closed(sandbox: Sandbox) -> None:
    prepare(sandbox)
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "signatures could not be verified" in out
    assert not any(c.startswith("docker compose up") for c in sandbox.docker_calls())
    sandbox.git_set("head", OLD)
    rc, out = run_update(sandbox, "--yes", "--skip-verify", "--force")
    assert rc == 0, out
    assert "NOT checked" in out


def test_rollback_checks_the_dump_before_changing_anything(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    sandbox.env["SHIM_DUMP_MISSING"] = "1"
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "no longer in the backups volume" in proc.stderr
    assert not any(c.startswith("git checkout") for c in sandbox.calls())
    # Only the read-only schema query may reach compose before the dump is checked.
    changing = [
        c
        for c in sandbox.docker_calls()
        if c.startswith("docker compose") and not c.startswith("docker compose exec -T db sh -c")
    ]
    assert not changing
    assert "SUCKERPOT_VERSION=v0.8.0" in (sandbox.root / ".env").read_text()


def test_rollback_checks_ports_and_ignores_stale_values(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    (sandbox.root / "scripts" / "restore-db.sh").write_text("true\n")
    sandbox.env["SUCKERPOT_VERSION"] = "v0.9.0"
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check-ports: ok" in proc.stdout
    up = [c for c in sandbox.calls() if c.startswith("ENV_AT_UP")]
    assert up and all("SUCKERPOT_VERSION=unset" in c for c in up)
    # A bad port layout in .env stops the rollback before the stack is started.
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0") + "SSH_HOST_PORT=8443\n")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0


def test_rollback_refuses_unverifiable_images(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    (sandbox.root / "scripts" / "restore-db.sh").write_text("true\n")
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "could not be verified" in proc.stderr
    assert not any(c.startswith("docker compose up") for c in sandbox.docker_calls())


def test_rollback_never_lets_docker_create_the_backups_volume(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    sandbox.env["SHIM_EXISTING_VOLUMES"] = ""
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "does not exist" in proc.stderr
    assert not any(c.startswith("docker run") for c in sandbox.docker_calls())


def test_unfinished_update_blocks_a_new_one_unless_forced(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    state = sandbox.root / ".suckerpot-state" / "last-update.json"
    assert '"completed": true' in state.read_text()
    state.write_text(state.read_text().replace('"completed": true', '"completed": false'))
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "never finished" in out
    rc, out = run_update(sandbox, "--yes", "--force")
    assert "never finished" not in out


def test_rollback_releases_the_unfinished_update_lock(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    state = sandbox.root / ".suckerpot-state" / "last-update.json"
    state.write_text(
        state.read_text().replace('"from_version"', '"completed": false,\n  "from_version"')
    )
    (sandbox.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"completed": true' in state.read_text()
    assert '"completed": false' not in state.read_text()


# ------------------------------------------------------------ signed release manifest (M32)


def test_update_checks_the_signed_manifest_before_the_code_changes(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    calls = sandbox.calls()
    assert "verify-release v0.9.0" in calls
    first = next(i for i, c in enumerate(calls) if c.startswith("verify-release"))
    assert first < next(i for i, c in enumerate(calls) if c.startswith("git checkout"))
    assert first < next(i for i, c in enumerate(calls) if "backup-service.sh" in c)


def test_a_bad_manifest_stops_a_manual_update_before_anything_changes(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_RELEASE_RC"] = "6"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "release manifest" in out and "could not be verified" in out
    assert not any(
        "backup-service.sh" in c or c.startswith("git checkout") for c in sandbox.calls()
    )


def test_a_release_without_manifest_warns_manually_and_is_refused_automatically(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_RELEASE_RC"] = "3"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "no signed release manifest" in out
    prepare(sandbox)
    sandbox.env["SHIM_RELEASE_RC"] = "3"
    sandbox.log.write_text("")
    rc, out = run_update(sandbox, "--auto", "v0.9.0")
    assert rc != 0
    assert "refuses it" in out
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_skip_verify_skips_the_manifest_with_a_warning(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_RELEASE_RC"] = "6"
    rc, out = run_update(sandbox, "--yes", "--skip-verify")
    assert rc == 0, out
    assert "manifest was NOT checked" in out
    assert not any(c.startswith("verify-release") for c in sandbox.calls())


def test_source_mode_has_no_manifest_to_check(sandbox: Sandbox) -> None:
    prepare(sandbox, mode="source")
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.8.0"  # a source build reports its describe string
    rc, out = run_update(sandbox, "--yes", "v0.9.0")
    assert rc == 0, out
    assert not any(c.startswith("verify-release") for c in sandbox.calls())


def test_auto_flag_is_strict_and_prompt_free(sandbox: Sandbox) -> None:
    prepare(sandbox)
    for bad in ("--no-backup", "--skip-verify", "--force"):
        rc, out = run_update(sandbox, "--auto", bad, "v0.9.0")
        assert rc == 2 and "cannot be combined" in out
    rc, out = run_update(sandbox, "--auto", "v0.9.0")
    assert rc == 0, out
    assert "verify-release --auto v0.9.0" in sandbox.calls()
    assert "just rollback" not in out


INGEST_SHIM = """#!/bin/sh
case "$*" in
  "compose exec -T ingest printenv SUCKERPOT_RUNNING_VERSION")
    echo "docker $*" >> "$SHIM_LOG"; echo "${SHIM_INGEST_VERSION:-}"; exit 0 ;;
  "compose exec -T ingest python -m ingest.network.cli status --json")
    echo "docker $*" >> "$SHIM_LOG"; exit "${SHIM_NETWORK_CLI_RC:-0}" ;;
esac
exec "$(dirname "$0")/docker.real" "$@"
"""


def participant(sb: Sandbox) -> None:
    """Switches the sandbox to a participant install (no api) with a docker fake that knows ingest."""
    real = sb.shim / "docker"
    real.rename(sb.shim / "docker.real")
    real.write_text(INGEST_SHIM)
    real.chmod(0o755)
    env = sb.root / ".env"
    env.write_text(env.read_text() + "SUCKERPOT_STACK_MODE=participant\n")
    sb.env["SHIM_INGEST_VERSION"] = "v0.9.0"


def test_participant_health_checks_ingest_and_the_network_client(sandbox: Sandbox) -> None:
    prepare(sandbox)
    participant(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    calls = sandbox.calls()
    assert "docker compose exec -T ingest printenv SUCKERPOT_RUNNING_VERSION" in calls
    assert "docker compose exec -T ingest python -m ingest.network.cli status --json" in calls
    assert not any("api printenv" in c for c in calls)
    assert not any(c.startswith("curl") for c in calls)  # no dashboard to ask


def test_participant_update_fails_when_the_network_client_does_not_answer(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    participant(sandbox)
    sandbox.env["SHIM_NETWORK_CLI_RC"] = "1"
    sandbox.env["SHIM_HEALTH_BEFORE"] = "ingest healthy\ndb healthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "ingest healthy\ndb healthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "network client of ingest does not answer" in out


def test_full_mode_health_is_unchanged(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    calls = sandbox.calls()
    assert "docker compose exec -T api printenv SUCKERPOT_RUNNING_VERSION" in calls
    assert not any("ingest.network.cli" in c for c in calls)
    assert any(c.startswith("curl") and "/healthz" in c for c in calls)


def test_a_second_update_cannot_run_while_the_lock_is_held(sandbox: Sandbox) -> None:
    prepare(sandbox)
    state = sandbox.root / ".suckerpot-state"
    state.mkdir(exist_ok=True)
    held = subprocess.Popen(  # noqa: S603
        ["flock", str(state / "update.lock"), "sleep", "20"],  # noqa: S607
    )
    try:
        time.sleep(0.5)
        rc, out = run_update(sandbox, "--yes")
        assert rc != 0
        assert "another update or rollback is running" in out
        assert not any("backup-service.sh" in c for c in sandbox.calls())
    finally:
        held.kill()
        held.wait()


def test_rollback_yes_skips_both_confirmations(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    (sandbox.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')
    proc = sandbox.run("scripts/rollback.sh", "--yes", stdin="")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restore-db --yes volume:suckerpot-preupdate-20261101T020000Z.dump" in sandbox.calls()
    assert sandbox.run("scripts/rollback.sh", "--bogus").returncode == 2


# ------------------------------------------------------------------ health judged against a baseline


def test_a_service_already_unhealthy_does_not_fail_the_update(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api healthy\ndb healthy\ningest unhealthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "api healthy\ndb healthy\ningest unhealthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "ingest was already unhealthy before the update" in out


def test_up_failing_for_an_already_unhealthy_service_is_judged_per_service(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api healthy\ningest unhealthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "api healthy\ningest unhealthy"
    sandbox.env["SHIM_UP_RC"] = "1"
    sandbox.env["SHIM_MIGRATE_STATE"] = "exited 0"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out


def test_up_failing_with_a_failed_migration_is_a_release_fault(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_UP_RC"] = "1"
    sandbox.env["SHIM_MIGRATE_STATE"] = "exited 1"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out
    assert "migrations did not finish cleanly" in out


def test_a_service_that_was_healthy_and_is_not_anymore_fails_the_update(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api healthy\ndb healthy\ningest healthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "api healthy\ndb healthy\ningest unhealthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out
    assert "ingest(unhealthy)" in out


def test_a_healthy_service_that_vanished_is_a_regression(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api healthy\ndb healthy\ningest healthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "api healthy\ndb healthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out
    assert "ingest(not running)" in out


def test_a_service_without_a_healthcheck_counts_as_healthy_before(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api healthy\nworker "
    sandbox.env["SHIM_HEALTH_AFTER"] = "api healthy\nworker unhealthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out


def test_a_starting_service_gets_a_bounded_wait(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api healthy\ningest healthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "api healthy\ningest starting"
    sandbox.env["UPDATE_HEALTH_WAIT_SECONDS"] = "20"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out
    polls = [c for c in sandbox.calls() if c.startswith("docker compose ps --format")]
    # One snapshot before the update, then 20 / 5 + 1 polls after it.
    assert len(polls) == 1 + 5


def test_the_state_file_records_the_alembic_revision_before_the_update(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_ALEMBIC"] = "a1b2c3d4"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    state = (sandbox.root / ".suckerpot-state" / "last-update.json").read_text()
    assert '"alembic_before": "a1b2c3d4"' in state


# ------------------------------------------------------------------ rollback and the database


def rollback_sandbox(sb: Sandbox, alembic_before: str | None, dump: str | None = None) -> None:
    prepare(sb)
    sb.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    if dump is None:
        write_state(sb, alembic=alembic_before)
    else:
        write_state(sb, dump=dump, alembic=alembic_before)
    (sb.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')


def restored(sb: Sandbox) -> bool:
    return any(c.startswith("restore-db") for c in sb.calls())


def test_rollback_keeps_the_database_when_the_schema_did_not_move(sandbox: Sandbox) -> None:
    rollback_sandbox(sandbox, "a1b2c3d4")
    sandbox.env["SHIM_ALEMBIC"] = "a1b2c3d4"
    proc = sandbox.run("scripts/rollback.sh", "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not restored(sandbox)
    assert "no event is lost" in proc.stdout
    assert f"git checkout --quiet --detach {OLD}" in sandbox.calls()
    assert "docker compose pull --policy missing" in sandbox.calls()


def test_rollback_restores_the_database_when_the_schema_moved(sandbox: Sandbox) -> None:
    rollback_sandbox(sandbox, "a1b2c3d4")
    sandbox.env["SHIM_ALEMBIC"] = "e5f6a7b8"
    proc = sandbox.run("scripts/rollback.sh", "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert restored(sandbox)
    assert "the schema changed" in proc.stdout


def test_rollback_restores_when_the_revision_is_unknown(sandbox: Sandbox) -> None:
    rollback_sandbox(sandbox, None)  # a state file from before this field existed
    sandbox.env["SHIM_ALEMBIC"] = "a1b2c3d4"
    assert sandbox.run("scripts/rollback.sh", "--yes").returncode == 0
    assert restored(sandbox)


def test_rollback_restores_when_the_database_cannot_be_read(sandbox: Sandbox) -> None:
    rollback_sandbox(sandbox, "a1b2c3d4")
    sandbox.env["SHIM_ALEMBIC"] = ""
    assert sandbox.run("scripts/rollback.sh", "--yes").returncode == 0
    assert restored(sandbox)


def test_rollback_restore_db_flag_forces_the_restore(sandbox: Sandbox) -> None:
    rollback_sandbox(sandbox, "a1b2c3d4")
    sandbox.env["SHIM_ALEMBIC"] = "a1b2c3d4"
    proc = sandbox.run("scripts/rollback.sh", "--yes", "--restore-db")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert restored(sandbox)


def test_rollback_keep_db_flag_never_restores(sandbox: Sandbox) -> None:
    rollback_sandbox(sandbox, "a1b2c3d4")
    sandbox.env["SHIM_ALEMBIC"] = "e5f6a7b8"
    proc = sandbox.run("scripts/rollback.sh", "--yes", "--keep-db")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not restored(sandbox)


def test_rollback_keep_db_works_without_a_dump(sandbox: Sandbox) -> None:
    rollback_sandbox(sandbox, None, dump="")
    assert sandbox.run("scripts/rollback.sh", "--yes").returncode != 0
    assert sandbox.run("scripts/rollback.sh", "--yes", "--keep-db").returncode == 0


def test_rollback_documents_and_validates_its_flags(sandbox: Sandbox) -> None:
    prepare(sandbox)
    assert sandbox.run("scripts/rollback.sh", "--restore-db=1").returncode == 2
    text = (sandbox.root / "scripts" / "rollback.sh").read_text()
    assert "--restore-db" in text and "--keep-db" in text


def test_image_verification_failure_in_update_exits_1_not_a_release_fault(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    rc, out = run_update(sandbox, "--yes")
    assert rc == 1, out
    assert "signatures could not be verified" in out


def test_dashboard_not_answering_is_a_warning_when_api_was_unhealthy(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_CURL_RC"] = "22"
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api unhealthy\ndb healthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "api unhealthy\ndb healthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "the dashboard does not answer" in out
    assert "api was already unhealthy before the update" in out


def test_dashboard_not_answering_is_a_release_fault_when_api_was_healthy(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_CURL_RC"] = "22"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out


def test_network_client_check_is_a_warning_when_ingest_was_unhealthy(sandbox: Sandbox) -> None:
    prepare(sandbox)
    participant(sandbox)
    sandbox.env["SHIM_NETWORK_CLI_RC"] = "1"
    sandbox.env["SHIM_HEALTH_BEFORE"] = "ingest unhealthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "ingest unhealthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "ingest was already unhealthy before the update" in out


def test_network_client_check_is_a_release_fault_when_ingest_was_healthy(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    participant(sandbox)
    sandbox.env["SHIM_NETWORK_CLI_RC"] = "1"
    sandbox.env["SHIM_HEALTH_BEFORE"] = "ingest healthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "ingest healthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out


def test_the_running_version_check_stays_strict_on_a_degraded_node(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_HEALTH_BEFORE"] = "api unhealthy\ndb healthy"
    sandbox.env["SHIM_HEALTH_AFTER"] = "api unhealthy\ndb healthy"
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.8.0"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 10, out
