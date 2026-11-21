"""scripts/status.sh and its renderer scripts/lib/status_render.py (M32, design section 10).

The renderer runs inside the ingest container in real life; here the fake docker runs it with the
interpreter of the tests. The network part is a canned answer of `ingest.network.cli status --json`.
"""

import json
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import ROOT, Sandbox
from test_install import add_participant_files, wrap_docker

SECRET = "s3cr3t-database-password-value-0001"  # noqa: S105

SENSOR_OFF = [
    f"SENSOR_{n}=0"
    for n in ("TELNET", "RDP", "REDIS", "DOCKER", "MYSQL", "ADB", "MSSQL", "SMB", "SIP", "SYNOLOGY")
]


def iso(delta: timedelta) -> str:
    return (datetime.now(UTC) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def member_cli(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "state": "member",
        "pseudonym": "amber-falcon-42",
        "node": "3f9a1c07",
        "standing": "new",
        "counts_from": "2026-11-17",
        "path": "direct",
        "self_address": "learned",
        "hub": {
            "host": "suckerpot-hub.selfhostr.io",
            "last_contact": iso(timedelta(minutes=12)),
            "signature_ok": True,
        },
        "sent": [
            {"day": "2026-11-02", "sources": 412, "links": 9, "files": 0},
            {"day": "2026-11-01", "sources": 398, "links": 7, "files": 0},
        ],
        "reveals_7d": 3,
        "sessions_24h": {"ssh": 1204, "web": 962},
        "warnings": [],
        "errors": [],
    }
    doc.update(overrides)
    return doc


HEALTHY_PS = (
    "sensor-ssh running healthy\nsensor-web running healthy\n"
    "ingest running healthy\ndb running healthy\nredis running healthy\n"
)


class Status:
    """A participant sandbox with a canned `docker compose ps` and network status."""

    def __init__(self, sb: Sandbox) -> None:
        self.sb = sb
        add_participant_files(sb)
        self.set_env()
        self.set_ps(HEALTHY_PS)
        self.set_cli(member_cli())
        wrap_docker(
            sb,
            '  "compose ps --format"*) cat "$SHIM_DIR/ps.txt"; exit 0 ;;\n'
            '  "compose exec -T ingest python -m ingest.network.cli status --json")\n'
            '    echo "docker $*" >> "$SHIM_LOG"; cat "$SHIM_DIR/cli.json"; exit "${SHIM_CLI_RC:-0}" ;;\n'
            '  "compose exec -T ingest python -m ingest.network.cli status --last-batch")\n'
            '    echo \'{"batch": "last"}\'; exit 0 ;;\n'
            '  "compose exec -T ingest python -I -c "*) shift 7; exec '
            + sys.executable
            + ' -I -c "$@" ;;',
        )
        (sb.root / ".suckerpot-state").mkdir()
        # The firewall unit as fwcheck.sh sees it: active, tables unreadable (no root, sudo refuses).
        for name, text in {
            "systemctl": '#!/bin/sh\n[ "$1" = is-active ] && exit "${SHIM_FW_ACTIVE:-0}"\nexit 0\n',
            "sudo": "#!/bin/sh\nexit 1\n",
        }.items():
            (sb.shim / name).write_text(text)
            (sb.shim / name).chmod(0o755)
        self.fw_root = sb.root / "fwroot"
        self.firewall(installed=True)
        self.schedule()

    def firewall(self, *, installed: bool) -> None:
        unit = self.fw_root / "etc/systemd/system/suckerpot-firewall.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        if installed:
            unit.write_text("[Unit]\n")
        else:
            unit.unlink(missing_ok=True)

    def latest(self, tag: str, age: timedelta) -> None:
        stamp = int((datetime.now(UTC) - age).timestamp())
        (self.sb.shim / "gitstate" / "refs").write_text(f"{tag} {stamp}\n")

    def set_env(self, **extra: str) -> None:
        values = {
            "COMPOSE_PROJECT_NAME": "suckerpot",
            "SUCKERPOT_VOLUME_PREFIX": "suckerpot",
            "SUCKERPOT_STACK_MODE": "participant",
            "SUCKERPOT_INSTALL_MODE": "images",
            "SUCKERPOT_VERSION": "v0.6.0",
            "AUTO_UPDATE_ENABLED": "true",
            "POSTGRES_PASSWORD": SECRET,
            "SSH_HOST_PORT": "2222",
            "SENSOR_SSH": "1",
            "SENSOR_WEB": "1",
        }
        values.update(extra)
        lines = [f"{k}={v}" for k, v in values.items()] + SENSOR_OFF
        self.sb.write_env("\n".join(lines) + "\n")

    def set_ps(self, text: str) -> None:
        (self.sb.shim / "ps.txt").write_text(text)

    def set_cli(self, doc: dict[str, Any] | str) -> None:
        text = doc if isinstance(doc, str) else json.dumps(doc)
        (self.sb.shim / "cli.json").write_text(text)

    def schedule(self, hhmm: str = "04:37", *, daily: bool = False) -> None:
        """Every 6 hours (from v0.11.10), or once a day like an older install."""
        hour, minute = hhmm.split(":")
        h = int(hour)
        hours = str(h) if daily else f"{h % 6},{h % 6 + 6},{h % 6 + 12},{h % 6 + 18}"
        (self.sb.shim / "crontab.txt").write_text(
            f"{int(minute)} {hours} * * * cd {self.sb.root} && bash scripts/auto-update.sh"
            " > /dev/null 2>&1 # selfhostr-auto-update suckerpot\n"
        )

    def auto_state(self, **fields: str) -> None:
        (self.sb.root / ".suckerpot-state" / "auto-update.json").write_text(json.dumps(fields))

    def run(self, *args: str, **env: str) -> tuple[int, str, str]:
        proc = self.sb.run(
            "scripts/status.sh", *args, extra_env={"SUCKERPOT_FW_ROOT": str(self.fw_root), **env}
        )
        return proc.returncode, proc.stdout, proc.stderr


@pytest.fixture
def st(sandbox: Sandbox) -> Status:
    return Status(sandbox)


def test_healthy_participant_report(st: Status) -> None:
    st.schedule()
    st.auto_state(
        last_run=iso(timedelta(hours=3)), last_result="ok", **{"from": "v0.6.0", "to": "v0.6.0"}
    )
    rc, out, err = st.run()
    assert rc == 0, out + err
    assert "SuckerPot v0.6.0, participant mode, images" in out
    assert out.splitlines()[0].rstrip().endswith("OK")
    assert "Sensors (2 running, all healthy)" in out
    assert "ssh      router 22 -> 2222" in out
    assert "last 24 h:  1,204 sessions" in out
    assert "router 80, 443" in out
    assert "Member as amber-falcon-42 (Node 3f9a1c07), standing: new" in out
    assert "Counts toward consensus from 2026-11-17" in out
    assert "Hub contact: OK, 12 min ago (suckerpot-hub.selfhostr.io, signature verified)" in out
    assert "Path: direct (no VPN). The hub sees this machine's address." in out
    assert "Own address: learned" in out
    assert "Sent: 2026-11-02  412 sources, 9 links (blinded), 0 files" in out
    assert "2026-11-01  398 sources, 7 links (blinded), 0 files" in out
    assert "Links revealed for verification (7 days): 3" in out
    assert "Automatic: on, every 6 h from 04:37." in out
    assert "already on v0.6.0" in out
    assert "Exit code 0 = OK, 1 = warning, 2 = error." in out


def test_the_report_never_holds_a_secret(st: Status) -> None:
    _, out, err = st.run()
    assert SECRET not in out + err
    _, out, err = st.run("--json")
    assert SECRET not in out + err
    assert SECRET not in "\n".join(c for c in st.sb.calls() if "exec" in c)


def test_json_output_has_the_same_data_and_the_exit_code(st: Status) -> None:
    st.schedule()
    rc, out, _ = st.run("--json")
    assert rc == 0
    doc = json.loads(out)
    assert doc["stack"] == "participant"
    assert doc["exit"] == 0
    assert doc["sensors"] == {"ssh": "healthy", "web": "healthy"}
    assert doc["network"]["pseudonym"] == "amber-falcon-42"
    assert doc["updates"]["schedule"] == "cron 04:37/6h"
    assert doc["warnings"] == []


def test_unhealthy_sensor_is_a_warning(st: Status) -> None:
    st.schedule()
    st.set_ps(HEALTHY_PS.replace("sensor-ssh running healthy", "sensor-ssh running unhealthy"))
    rc, out, _ = st.run()
    assert rc == 1
    assert "WARNING" in out.splitlines()[0]
    assert "not healthy: ssh" in out


def test_ingest_down_is_an_error(st: Status) -> None:
    st.set_ps("sensor-ssh running healthy\ndb running healthy\n")
    rc, out, _ = st.run()
    assert rc == 2
    assert "Ingest is not running" in out
    _, out, _ = st.run("--json")
    assert rc == 2
    assert json.loads(out)["errors"] == ["ingest_down"]


def test_database_down_is_an_error(st: Status) -> None:
    st.set_ps("sensor-ssh running healthy\ningest running healthy\ndb exited\n")
    rc, out, _ = st.run()
    assert rc == 2
    assert "the database is not running" in out


def test_stale_hub_contact_is_a_warning(st: Status) -> None:
    st.schedule()
    cli = member_cli()
    cli["hub"]["last_contact"] = iso(timedelta(hours=30))
    st.set_cli(cli)
    rc, out, _ = st.run()
    assert rc == 1
    assert "30 h ago" in out
    assert "no contact with the hub for more than 26 h" in out


def test_hub_signature_failure_is_an_error(st: Status) -> None:
    st.schedule()
    cli = member_cli(errors=["hub_signature"])
    cli["hub"]["signature_ok"] = False
    st.set_cli(cli)
    rc, out, _ = st.run()
    assert rc == 2
    assert "signature check" in out


@pytest.mark.parametrize(
    "code",
    [
        "consent_outdated",
        "hub_key_differs_from_release",
        "waiting_self_address",
        "submit_paused_self_address",
    ],
)
def test_network_warning_codes_are_warnings(st: Status, code: str) -> None:
    st.schedule()
    st.set_cli(member_cli(warnings=[code]))
    rc, _, _ = st.run()
    assert rc == 1
    assert code in json.loads(st.run("--json")[1])["warnings"]


def test_eligibility_pending_is_shown_and_not_a_warning(st: Status) -> None:
    st.schedule()
    st.set_cli(member_cli(standing="pending"))
    rc, out, _ = st.run()
    assert rc == 0
    assert "standing: pending" in out


def not_member_cli(
    state: str = "not_joined", desired: str = "off", last_error: str | None = None
) -> dict[str, Any]:
    """The shape of ingest v0.11.1 for a node that is not a member: only `network` is nested."""
    return {
        "state": state,
        "pseudonym": "calm-otter-12",
        "hub": {"host": "hub.example.org", "last_contact": None, "signature_ok": True},
        "network": {"membership": {"desired": desired, "last_error": last_error, "state": "off"}},
        "warnings": [],
        "errors": [],
    }


@pytest.mark.parametrize(
    ("code", "text"),
    [
        ("egress_closed", "the path to the hub is closed (egress_closed)"),
        ("hub_unreachable", "the hub cannot be reached (hub_unreachable)"),
        ("something_new", "unexpected problem (something_new)"),
    ],
)
def test_pending_join_with_an_error_is_a_warning(st: Status, code: str, text: str) -> None:
    st.schedule()
    st.set_cli(not_member_cli(desired="member", last_error=code))
    rc, out, _ = st.run()
    assert rc == 1
    assert "Joining as calm-otter-12: not accepted by the hub yet." in out
    assert f"Last problem: {text}. SuckerPot keeps trying by itself." in out
    assert "Not joined" not in out
    assert "join_pending" in json.loads(st.run("--json")[1])["warnings"]


def test_pending_join_without_an_error_is_ok(st: Status) -> None:
    st.schedule()
    st.set_cli(not_member_cli(desired="member"))
    rc, out, _ = st.run()
    assert rc == 0
    assert "Joining as calm-otter-12: not accepted by the hub yet." in out
    assert "The request is in progress." in out
    assert "Last problem" not in out


def test_never_asked_and_left_still_say_not_joined(st: Status) -> None:
    st.schedule()
    for state in ("not_joined", "left"):
        st.set_cli(not_member_cli(state=state, desired="off"))
        rc, out, _ = st.run()
        assert rc == 0
        assert "Not joined. Join: ./scripts/participant.sh join" in out
        assert "Joining" not in out


def test_a_member_is_not_shown_as_joining(st: Status) -> None:
    st.schedule()
    st.set_cli(member_cli())
    rc, out, _ = st.run()
    assert rc == 0
    assert "Member as amber-falcon-42" in out
    assert "Joining" not in out


def test_auto_update_off_is_a_warning_in_participant_mode_only(st: Status) -> None:
    st.set_env(AUTO_UPDATE_ENABLED="false")
    rc, out, _ = st.run()
    assert rc == 1
    assert "Automatic: off" in out
    assert "Needs attention" in out
    assert "Fix: ./scripts/participant.sh auto-update on" in out
    st.set_env(AUTO_UPDATE_ENABLED="false", SUCKERPOT_STACK_MODE="full")
    st.set_cli(member_cli(state="off"))
    rc, out, _ = st.run()
    assert rc == 0, out
    assert "Not joined" in out


def test_a_failed_automatic_update_is_a_warning(st: Status) -> None:
    st.schedule()
    st.auto_state(
        last_run=iso(timedelta(hours=1)),
        last_result="failed",
        error_code="health_check",
        **{"from": "v0.6.0", "to": "v0.6.1"},
    )
    rc, out, _ = st.run()
    assert rc == 1
    assert "failed (health_check), rolled back" in out


def test_a_release_still_too_young_is_not_a_failed_update(st: Status) -> None:
    st.schedule()
    st.auto_state(
        last_run=iso(timedelta(hours=1)),
        last_result="refused",
        error_code="too_young",
        **{"from": "v0.6.0", "to": "v0.6.1"},
    )
    rc, out, _ = st.run()
    assert rc == 0
    assert "did not complete" not in out
    assert "refused (too_young)" in out


def test_any_other_refusal_is_still_a_warning(st: Status) -> None:
    st.schedule()
    st.auto_state(
        last_run=iso(timedelta(hours=1)),
        last_result="refused",
        error_code="digest_mismatch",
        **{"from": "v0.6.0", "to": "v0.6.1"},
    )
    rc, out, _ = st.run()
    assert rc == 1
    assert "did not complete" in out


def test_updated_result_and_systemd_schedule(st: Status) -> None:
    unit_dir = st.sb.root / "home" / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "selfhostr-auto-update-suckerpot.timer").write_text(
        "[Timer]\nOnCalendar=*-*-* 05:12:00\n"
    )
    st.sb.env["XDG_CONFIG_HOME"] = str(st.sb.root / "home" / ".config")
    (st.sb.shim / "crontab.txt").write_text("")
    st.auto_state(
        last_run=iso(timedelta(hours=1)),
        last_result="updated",
        **{"from": "v0.5.0", "to": "v0.6.0"},
    )
    rc, out, _ = st.run()
    assert rc == 0, out
    assert "next window 05:12" in out
    assert "updated v0.5.0 to v0.6.0" in out


def test_a_once_a_day_schedule_from_an_older_release_still_shows(st: Status) -> None:
    st.schedule("05:12", daily=True)
    st.auto_state(last_run=iso(timedelta(hours=1)), last_result="ok", **{"from": "v0.6.0"})
    rc, out, _ = st.run()
    assert rc == 0, out
    assert "Automatic: on, next window 05:12." in out


def test_network_status_failure_is_reported_not_fatal(st: Status) -> None:
    st.schedule()
    st.sb.env["SHIM_CLI_RC"] = "1"
    rc, out, _ = st.run()
    assert rc == 1
    assert "Status unavailable: the network status command failed" in out


def test_garbage_from_the_status_command_is_handled(st: Status) -> None:
    st.schedule()
    st.set_cli("not json at all")
    rc, out, _ = st.run()
    assert rc == 1
    assert "Status unavailable" in out


def test_vpn_path_is_described_honestly(st: Status) -> None:
    st.schedule()
    st.set_cli(member_cli(path="vpn"))
    rc, out, _ = st.run()
    assert rc == 0
    assert "Path: through your VPN" in out


def test_last_batch_prints_only_the_command_output(st: Status) -> None:
    rc, out, _ = st.run("--last-batch")
    assert rc == 0
    assert json.loads(out) == {"batch": "last"}


def test_needs_an_install_and_rejects_unknown_options(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    proc = sandbox.run("scripts/status.sh")
    assert proc.returncode == 2
    assert "not installed" in proc.stderr
    sandbox.write_env("COMPOSE_PROJECT_NAME=suckerpot\n")
    proc = sandbox.run("scripts/status.sh", "--nope")
    assert proc.returncode == 2


def test_status_makes_no_change(st: Status) -> None:
    before = (st.sb.root / ".env").read_text()
    st.run()
    st.run("--json")
    assert (st.sb.root / ".env").read_text() == before
    calls = st.sb.docker_calls()
    assert not any(c.startswith(("docker compose up", "docker compose down")) for c in calls)
    assert not any(" rm " in c or c.startswith("docker volume") for c in calls)


def test_renderer_runs_on_the_standard_library_only() -> None:
    text = (ROOT / "scripts/lib/status_render.py").read_text()
    imports = {
        line.split()[1].split(".")[0]
        for line in text.splitlines()
        if line.startswith(("import ", "from "))
    }
    assert imports <= {"json", "sys", "datetime", "typing"}


def test_a_healthy_participant_has_no_needs_attention_block(st: Status) -> None:
    st.latest("v0.6.0", timedelta(days=30))
    rc, out, _ = st.run()
    assert rc == 0, out
    assert "Needs attention" not in out


def test_missing_firewall_is_a_warning_with_its_command(st: Status) -> None:
    st.firewall(installed=False)
    rc, out, _ = st.run()
    assert rc == 1
    assert "Needs attention" in out
    assert "The host firewall is not installed" in out
    assert "Fix: ./scripts/participant.sh firewall" in out
    assert "Automatic updates are off" not in out


@pytest.mark.parametrize("stack", ["participant", "full"])
def test_an_installed_firewall_that_is_not_active_is_a_warning(st: Status, stack: str) -> None:
    st.set_env(SUCKERPOT_STACK_MODE=stack)
    rc, out, _ = st.run(SHIM_FW_ACTIVE="3")
    assert rc == 1, out
    assert "not loaded" in out
    _, js, _ = st.run("--json", SHIM_FW_ACTIVE="3")
    assert "firewall_not_loaded" in js


def test_a_full_install_does_not_ask_for_the_participant_firewall(st: Status) -> None:
    st.firewall(installed=False)
    st.set_env(SUCKERPOT_STACK_MODE="full")
    _, out, _ = st.run()
    assert "Needs attention" not in out


def test_an_older_release_than_the_newest_known_needs_attention(st: Status) -> None:
    st.latest("v0.6.2", timedelta(days=10))
    rc, out, _ = st.run()
    assert rc == 1
    assert "runs v0.6.0, the newest release is v0.6.2" in out
    assert "Fix: just update" in out


def test_a_release_younger_than_three_days_is_not_outdated(st: Status) -> None:
    st.latest("v0.6.2", timedelta(hours=20))
    rc, out, _ = st.run()
    assert rc == 0, out
    assert "Needs attention" not in out


def test_a_newer_major_version_is_not_offered(st: Status) -> None:
    st.latest("v1.0.0", timedelta(days=30))
    rc, out, _ = st.run()
    assert rc == 0, out


def test_flag_on_without_a_schedule_is_reported_as_off(st: Status) -> None:
    (st.sb.shim / "crontab.txt").write_text("")
    rc, out, _ = st.run()
    assert rc == 1
    assert "Fix: ./scripts/participant.sh auto-update on" in out


def test_source_install_explains_why_updates_are_off(st: Status) -> None:
    st.set_env(AUTO_UPDATE_ENABLED="false", SUCKERPOT_INSTALL_MODE="source")
    rc, out, _ = st.run()
    assert rc == 1
    assert "this install builds from source" in out


def test_json_lists_what_needs_attention(st: Status) -> None:
    st.firewall(installed=False)
    _, out, _ = st.run("--json")
    doc = json.loads(out)
    assert doc["firewall"] == "missing"
    assert doc["needs_attention"] == [
        {
            "problem": "The host firewall is not installed",
            "fix": "./scripts/participant.sh firewall",
        }
    ]
