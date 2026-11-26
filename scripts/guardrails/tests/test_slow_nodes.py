"""Slow nodes (1 vCPU / 1 GB cloud VMs) and Ctrl-C: scripts/lib/stackop.sh, participant.sh
set-name and set-country without a restart, the update lock, the versions in status.sh."""

import os
import signal
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from conftest import ROOT, Sandbox
from test_install import psb, wrap_docker  # noqa: F401 (psb: the fixture)
from test_node_tui import PROFILE_CASES, node  # noqa: F401 (the fixture)
from test_status import _render

LIB = ROOT / "scripts" / "lib"


def snippet(sb: Sandbox, script: str, **env: str) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        [  # noqa: S607
            "bash",
            "-c",
            f'set -euo pipefail\n. scripts/lib/env.sh\n. "{LIB / "stackop.sh"}"\n{script}',
        ],
        cwd=sb.root,
        env={**sb.env, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )


def test_leftovers_of_an_interrupted_recreate_are_removed(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=suckerpot\nSUCKERPOT_VOLUME_PREFIX=suckerpot\n")
    wrap_docker(
        sandbox,
        '  "ps -a --filter label=com.docker.compose.project=suckerpot --format"*)\n'
        '    printf "1c5075d17d3b_suckerpot-ingest-1 created\\nsuckerpot-ingest-1 running\\n'
        'ab12ab12ab12_suckerpot-db-1 running\\n"; exit 0 ;;',
    )
    proc = snippet(sandbox, "stack_clean_leftovers")
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 0, out
    calls = sandbox.calls()
    assert "docker rm -f 1c5075d17d3b_suckerpot-ingest-1" in calls
    assert not [c for c in calls if c.startswith("docker rm") and "suckerpot-db-1" in c]
    assert "Removed 1 container(s) left by an interrupted restart" in out
    assert "ab12ab12ab12_suckerpot-db-1 is left from an interrupted restart and still runs" in out


def test_ctrl_c_never_cuts_a_restart_in_half(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=suckerpot\nSUCKERPOT_VOLUME_PREFIX=suckerpot\n")
    for keep_going in ("0", "1"):
        done = sandbox.root / f"finished-{keep_going}"
        # The real sleep: the step takes 3 s; Ctrl-C reaches the whole foreground group after 1 s.
        proc = snippet(
            sandbox,
            f"stack_run 'Restarting ingest' bash -c '/usr/bin/sleep 3; touch {done}'; "
            'echo "rc=$? interrupted=$STACK_INTERRUPTED"',
            STACK_EXIT_ON_INTERRUPT="0" if keep_going == "0" else "1",
        )
        time.sleep(1.0)
        os.killpg(proc.pid, signal.SIGINT)
        out, _ = proc.communicate(timeout=60)
        assert done.exists(), out  # the step ran to its end
        assert "Interrupted: the current step finishes first" in out
        assert "Restarting ingest: done in" in out
        if keep_going == "0":
            assert "rc=0 interrupted=1" in out
        else:  # the default: the script stops once the step is over
            assert proc.returncode == 130 and "Stopped after that step" in out
            assert "rc=" not in out


def health_shim(sb: Sandbox, healthy_after: int) -> None:
    """compose ps: ingest unhealthy for the first calls, then healthy (a loaded node)."""
    wrap_docker(
        sb,
        '  "compose ps --format"*)\n'
        '    n=$(cat "$SHIM_DIR/ps-n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$SHIM_DIR/ps-n"\n'
        f'    if [ "$n" -gt {healthy_after} ]; then echo "ingest running healthy"; '
        'else echo "ingest running unhealthy"; fi; exit 0 ;;',
    )


def test_an_unhealthy_check_on_the_way_is_not_the_end(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=suckerpot\nSUCKERPOT_VOLUME_PREFIX=suckerpot\n")
    health_shim(sandbox, 2)
    proc = snippet(sandbox, "stack_wait_healthy 60 ingest && echo healthy")
    out, _ = proc.communicate(timeout=120)
    assert proc.returncode == 0 and "healthy" in out, out
    health_shim(sandbox, 10_000)
    proc = snippet(sandbox, "stack_wait_healthy 1 ingest || echo deadline")
    out, _ = proc.communicate(timeout=120)
    assert "Not healthy after" in out and "ingest(unhealthy)" in out and "deadline" in out


def test_set_country_of_a_member_never_restarts_ingest(
    node: Sandbox,  # noqa: F811
    parse_env: Callable[[Path], dict[str, str]],
) -> None:
    start = len(node.calls())
    proc = node.run("scripts/participant.sh", "set-country", "CH")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "the country is now CH, and the hub has it." in proc.stdout
    calls = node.calls()[start:]
    assert any("cli update --country CH --show-country" in c for c in calls)
    assert not [c for c in calls if c.startswith(("docker compose up", "docker compose restart"))]
    assert parse_env(node.root / ".env")["NETWORK_COUNTRY"] == "CH"


def test_an_ingest_that_runs_but_does_not_answer_changes_nothing(node: Sandbox) -> None:  # noqa: F811
    wrap_docker(
        node,
        '  "compose exec -T ingest python -m ingest.network.cli status --json") exit 1 ;;\n'
        '  "compose ps --status running -q ingest") echo abc123; exit 0 ;;\n' + PROFILE_CASES,
    )
    before = (node.root / ".env").read_text()
    start = len(node.calls())
    proc = node.run(
        "scripts/participant.sh", "set-country", "CH", extra_env={"SUCKERPOT_INGEST_WAIT": "2"}
    )
    assert proc.returncode != 0
    assert "ingest runs but did not answer within 2 s" in proc.stderr
    assert (node.root / ".env").read_text() == before
    assert not [c for c in node.calls()[start:] if c.startswith("docker compose up")]


def test_ctrl_c_before_the_change_is_made_puts_env_back(node: Sandbox) -> None:  # noqa: F811
    # The update command of ingest is slow (a loaded node): Ctrl-C arrives while it runs.
    wrap_docker(
        node,
        '  "compose exec -T ingest python -m ingest.network.cli update --country"*) echo "docker $*" >> "$SHIM_LOG"; /usr/bin/sleep 5; exit 1 ;;\n'
        + PROFILE_CASES,
    )
    before = (node.root / ".env").read_text()
    proc = subprocess.Popen(  # noqa: S603
        ["bash", str(node.root / "scripts/participant.sh"), "set-country", "CH"],  # noqa: S607
        cwd=node.root,
        env=node.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    # Ctrl-C once the update command of ingest runs (the shim records it as it starts).
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not any("update --country" in c for c in node.calls()):
        time.sleep(0.1)
    time.sleep(0.3)
    os.killpg(proc.pid, signal.SIGINT)
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 130, out
    assert "interrupted before the change was made: nothing was changed" in out
    assert (node.root / ".env").read_text() == before


def test_the_random_wait_of_auto_update_comes_before_the_lock() -> None:
    text = (ROOT / "scripts/auto-update.sh").read_text()
    assert text.index('sleep "$pause"') < text.index("flock -n 9")


def test_a_held_lock_says_who_holds_it(sandbox: Sandbox) -> None:
    from test_update import prepare

    prepare(sandbox)
    state = sandbox.root / ".suckerpot-state"
    state.mkdir(exist_ok=True)
    holder = subprocess.Popen(  # noqa: S603
        ["flock", str(state / "update.lock"), "/usr/bin/sleep", "30"]  # noqa: S607
    )
    try:
        time.sleep(0.5)
        (state / "update.lock.info").write_text(
            f"pid={holder.pid} what=auto-update since={int(time.time()) - 120}\n"
        )
        proc = sandbox.run("scripts/update.sh", "--yes")
        assert proc.returncode != 0
        assert "another update or rollback is running: auto-update (pid" in proc.stderr
        assert "for 2 min" in proc.stderr
    finally:
        holder.kill()
        holder.wait()


def test_status_shows_the_version_the_containers_run() -> None:
    rc, out = _render({"version": "v0.15.1", "running": "v0.12.1", "install": "images"})
    assert rc == 1, out
    assert out.splitlines()[0].startswith("SuckerPot v0.12.1 (scripts v0.15.1), participant mode")
    assert (
        "Scripts v0.15.1, images v0.12.1: the update did not finish. Run ./suckerpot.sh update --resume"
        in out
    )
    assert "Fix: ./suckerpot.sh update --resume" in out
    _, same = _render({"version": "v0.15.1", "running": "v0.15.1", "install": "images"})
    assert "images_behind" not in same and "Scripts v0.15.1, images" not in same


def test_status_shows_the_name_and_country_and_the_hub(tmp_path: Path) -> None:
    import json

    from test_status import member_cli

    cli = member_cli(country="CH", show_country=False, profile_synced=False)
    _, out = _render({"cli_raw": json.dumps(cli)})
    assert "Node name: amber-falcon-42; country: CH (hidden); not sent to the hub yet" in out


def test_the_metadata_lookup_is_off_unless_asked(sandbox: Sandbox) -> None:
    proc = snippet(sandbox, f'. "{LIB / "geocheck.sh"}"\ngeo_check CH\necho "$GEO_WHY"')
    out, _ = proc.communicate(timeout=60)
    assert "a cloud server behind NAT such as Oracle Cloud" in out
    assert "--self-address" in out
    assert not [c for c in sandbox.calls() if c.startswith("curl")]


def test_an_interrupted_update_names_the_way_forward_and_resume_finishes_it(
    sandbox: Sandbox,
) -> None:
    from test_update import prepare, run_update

    prepare(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    state = sandbox.root / ".suckerpot-state" / "last-update.json"
    state.write_text(state.read_text().replace('"completed": true', '"completed": false'))
    rc, out = run_update(sandbox, "--yes")
    assert rc == 1
    assert "was interrupted and never finished" in out
    assert "./suckerpot.sh update --resume" in out and "tmux or screen" in out
    rc, out = run_update(sandbox, "--yes", "--resume")
    assert rc == 0, out
    assert "finishing the interrupted update to v0.9.0" in out
    assert '"completed": true' in state.read_text(), out


def test_status_offers_to_finish_an_interrupted_update() -> None:
    rc, out = _render(
        {"version": "v0.15.1", "running": "v0.12.1", "install": "images", "unfinished": "v0.15.1"}
    )
    assert rc == 1, out
    assert "Run ./suckerpot.sh update --resume" in out
    assert "The update to v0.15.1 was interrupted and never finished" in out
    assert "Fix: ./suckerpot.sh update --resume" in out


def test_env_on_the_new_version_with_old_containers_finishes_the_update(
    sandbox: Sandbox,
) -> None:
    """The third node: the update was cut off after .env and the checkout changed, before the
    restart. `update.sh --force v0.9.0` said "Already on v0.9.0" and the node stayed stuck."""
    from test_update import ENV, NEW, prepare, run_update, write_state

    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    sandbox.git_set("head", NEW)
    write_state(sandbox)  # "completed" missing: not finished
    state = sandbox.root / ".suckerpot-state" / "last-update.json"
    state.write_text(state.read_text().replace('"at":', '"completed": false,\n  "at":'))
    sandbox.env["SHIM_INGEST_VERSION"] = "v0.8.0"
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.9.0"  # what the restarted api reports
    rc, out = run_update(sandbox, "--yes", "--force", "v0.9.0")
    assert "Already on" not in out, out
    assert ".env names v0.9.0 but the containers run v0.8.0: finishing the update" in out
    assert rc == 0, out
    assert any(c.startswith("docker compose up") for c in sandbox.calls())
    assert '"completed": true' in state.read_text()
    # The same versions everywhere: "Already on" again.
    sandbox.env["SHIM_INGEST_VERSION"] = "v0.9.0"
    rc, out = run_update(sandbox, "--yes", "v0.9.0")
    assert rc == 0 and "Already on v0.9.0" in out, out


def test_repair_clears_an_unfinished_update_once_the_stack_runs_the_env_version(
    psb: Sandbox,  # noqa: F811
) -> None:
    from test_install import p_real

    rc, out = p_real(psb)
    assert rc == 0, out
    state = psb.root / ".suckerpot-state" / "last-update.json"
    state.parent.mkdir(exist_ok=True)
    state.write_text('{\n  "target": "v0.9.0",\n  "completed": false,\n  "images": {\n  }\n}\n')
    version = next(
        line.split("=", 1)[1]
        for line in (psb.root / ".env").read_text().splitlines()
        if line.startswith("SUCKERPOT_VERSION=")
    )
    psb.env["SHIM_INGEST_VERSION"] = version
    proc = psb.run("scripts/install.sh", "--repair", "--yes")
    assert proc.returncode == 0, proc.stderr
    assert '"completed": true' in state.read_text()
    assert "The update that was cut off is over" in proc.stdout


def test_the_country_check_never_ends_the_script_with_a_sigpipe(sandbox: Sandbox) -> None:
    """Several public addresses (SELF_ADDRESS and the interfaces): `| head -n 1` closed the pipe
    while the list was still written, and pipefail ended set-country silently (exit 141)."""
    proc = snippet(
        sandbox,
        f'. "{LIB / "geocheck.sh"}"\n'
        "geo_own_addresses() { local i; for i in $(seq 1 20000); do echo 8.8.8.8; done; }\n"
        'geo_check CH || true\necho "survived $GEO_ADDR"',
    )
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 0, out
    assert "survived 8.8.8.8" in out


def test_a_closed_gate_the_node_recovered_from_is_not_an_error() -> None:
    import json
    from datetime import timedelta

    from test_status import iso, member_cli

    # The gate was closed 8 min ago (hubproxy still starting), the hub answered 2 min ago.
    cli = member_cli(
        last_error={"code": "egress_closed", "since": iso(timedelta(minutes=8))},
        hub={
            "host": "suckerpot-hub.selfhostr.io",
            "last_contact": iso(timedelta(minutes=2)),
            "signature_ok": True,
        },
    )
    _, out = _render({"cli_raw": json.dumps(cli)})
    assert (
        "Last network error: egress_closed (8 min ago), recovered since (hub contact 2 min ago)."
        in out
    )
    assert "vpn --remove" not in out


def test_a_closed_gate_on_the_direct_path_never_points_to_the_vpn() -> None:
    import json
    from datetime import timedelta

    from test_status import iso, member_cli

    cli = member_cli(
        path="direct",
        last_error={"code": "egress_closed", "since": iso(timedelta(minutes=8))},
        hub={
            "host": "suckerpot-hub.selfhostr.io",
            "last_contact": iso(timedelta(minutes=30)),
            "signature_ok": True,
        },
    )
    _, out = _render({"cli_raw": json.dumps(cli)})
    assert "hubproxy was not up" in out and "vpn --remove" not in out
    _, vpn = _render({"cli_raw": json.dumps({**cli, "path": "vpn"})})
    assert "check the VPN" in vpn
