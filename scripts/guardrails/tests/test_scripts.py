"""Shell guards of M28: sensor switches in check-ports.sh, the all-or-nothing VPN variables and the
idle mode of the vpn entrypoint."""

import re
import shutil
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import Sandbox
from test_install import _real_run, add_participant_files, crontab_text, p_real, wrap_docker

ROOT = Path(__file__).resolve().parents[3]
PATH = "/usr/local/bin:/usr/bin:/bin"


@pytest.fixture
def scripts(tmp_path: Path) -> Path:
    """A copy of the scripts in a folder without a .env, so only the given variables count."""
    dest = tmp_path / "scripts"
    dest.mkdir()
    for name in ("check-ports.sh", "check-vpn-env.sh"):
        shutil.copy(ROOT / "scripts" / name, dest / name)
    return dest


def _run(script: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/bin/sh", str(script)],
        env={"PATH": PATH, **env},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_ports_default_layout_is_ok(scripts: Path) -> None:
    assert _run(scripts / "check-ports.sh").returncode == 0


def test_ports_switch_must_be_zero_or_one(scripts: Path) -> None:
    result = _run(scripts / "check-ports.sh", SENSOR_SSH="2")
    assert result.returncode == 1
    assert "SENSOR_SSH must be 0 or 1" in result.stderr


def test_ports_clash_is_checked_between_enabled_sensors(scripts: Path) -> None:
    result = _run(scripts / "check-ports.sh", SSH_HOST_PORT="2323", TELNET_HOST_PORT="2323")
    assert result.returncode == 1
    assert "both use port 2323" in result.stderr


def test_ports_disabled_sensor_takes_no_part_in_clashes(scripts: Path) -> None:
    result = _run(
        scripts / "check-ports.sh", SENSOR_SSH="0", SSH_HOST_PORT="2323", TELNET_HOST_PORT="2323"
    )
    assert result.returncode == 0, result.stderr


def test_ports_disabled_sensor_takes_no_part_in_the_admin_check(scripts: Path) -> None:
    refused = _run(scripts / "check-ports.sh", ADMIN_SSH_PORT="22")
    assert refused.returncode == 1
    allowed = _run(scripts / "check-ports.sh", ADMIN_SSH_PORT="22", SENSOR_SSH="0")
    assert allowed.returncode == 0, allowed.stderr


@pytest.mark.parametrize("port", ["22", "23", "80", "443", "5555", "5001"])
def test_dashboard_is_refused_on_a_sensor_port_even_when_that_sensor_is_off(
    scripts: Path, port: str
) -> None:
    result = _run(
        scripts / "check-ports.sh",
        DASHBOARD_PORT=port,
        SENSOR_SSH="0",
        SENSOR_TELNET="0",
        SENSOR_WEB="0",
        SENSOR_ADB="0",
        SENSOR_SYNOLOGY="0",
    )
    assert result.returncode == 1
    assert "is a service port" in result.stderr


def test_dashboard_clash_with_an_enabled_sensor_host_port(scripts: Path) -> None:
    result = _run(scripts / "check-ports.sh", DASHBOARD_PORT="9000", SSH_HOST_PORT="9000")
    assert result.returncode == 1


PROFILE = {"COMPOSE_PROFILES": "egress"}
PASSWORDS = {
    "EGRESS_PROXY_PASSWORD": "a" * 24,
    "POSTGRES_COLLECTOR_PASSWORD": "b" * 24,
    "POSTGRES_ANALYZER_PASSWORD": "c" * 24,
}
WG = {
    "VPN_WG_PRIVATE_KEY": "k" * 43 + "=",
    "VPN_WG_ADDRESSES": "198.51.100.2/32",
    "VPN_WG_PEER_PUBLIC_KEY": "p" * 43 + "=",
    "VPN_WG_ENDPOINT_IP": "8.8.4.4",
    "VPN_WG_ENDPOINT_PORT": "51820",
}


def test_vpn_env_all_wireguard_values_empty_is_accepted(scripts: Path) -> None:
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **PASSWORDS)
    assert result.returncode == 0, result.stderr


def test_vpn_env_complete_set_is_accepted(scripts: Path) -> None:
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **PASSWORDS, **WG)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("missing", sorted(WG))
def test_vpn_env_partial_set_is_refused(scripts: Path, missing: str) -> None:
    env = {k: v for k, v in WG.items() if k != missing}
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **PASSWORDS, **env)
    assert result.returncode == 1
    assert missing in result.stderr
    assert WG["VPN_WG_PRIVATE_KEY"] not in result.stderr


def test_vpn_env_idle_install_still_needs_strong_passwords(scripts: Path) -> None:
    weak = {**PASSWORDS, "EGRESS_PROXY_PASSWORD": "short"}
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **weak)
    assert result.returncode == 1


def test_vpn_env_without_the_profile_is_skipped(scripts: Path) -> None:
    assert _run(scripts / "check-vpn-env.sh").returncode == 0


# --- vpn idle mode -------------------------------------------------------------------------


def _fake_gluetun(tmp_path: Path) -> Path:
    fake = tmp_path / "gluetun"
    fake.write_text(f"#!/bin/sh\necho started > {tmp_path}/started\nsleep 30\n", encoding="utf-8")
    fake.chmod(0o755)
    return fake


def _entrypoint(tmp_path: Path, **env: str) -> subprocess.Popen[str]:
    conf = tmp_path / "conf"
    conf.mkdir(exist_ok=True)
    return subprocess.Popen(  # noqa: S603
        ["/bin/sh", str(ROOT / "vpn" / "entrypoint.sh")],
        env={
            "PATH": PATH,
            "VPN_CONFIG_DIR": str(conf),
            "VPN_GLUETUN_BIN": str(_fake_gluetun(tmp_path)),
            "VPN_SNAPSHOT": str(tmp_path / "snapshot"),
            "VPN_IDLE_MARKER": str(tmp_path / "idle"),
            "VPN_IDLE_INTERVAL": "1",
            **env,
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for(path: Path, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if path.exists():
            return True
        time.sleep(0.05)
    return path.exists()


def test_idle_mode_starts_nothing_and_leaves_when_wg_env_appears(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path)
    try:
        assert _wait_for(tmp_path / "idle")
        time.sleep(1.5)
        assert proc.poll() is None  # still waiting
        assert not (tmp_path / "started").exists()  # gluetun never ran
        (tmp_path / "conf" / "wg.env").write_text("x\n", encoding="utf-8")
        assert proc.wait(timeout=10) == 0  # restart path
    finally:
        if proc.poll() is None:
            proc.kill()
    assert not (tmp_path / "idle").exists()
    assert not (tmp_path / "started").exists()
    assert "no VPN configuration yet; waiting" in (proc.stderr.read() if proc.stderr else "")


def test_idle_mode_marker_is_removed_on_termination(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path)
    try:
        assert _wait_for(tmp_path / "idle")
        proc.terminate()
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
    assert not (tmp_path / "idle").exists()


def test_env_values_present_do_not_trigger_idle_mode(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path, WIREGUARD_PRIVATE_KEY="k" * 43 + "=", WIREGUARD_ADDRESSES="")
    try:
        assert _wait_for(tmp_path / "started")
        assert not (tmp_path / "idle").exists()
    finally:
        proc.kill()


COMPOSE_AND_IMAGE_DEFAULTS = {
    "VPN_SERVICE_PROVIDER": "custom",
    "VPN_TYPE": "wireguard",
    "WIREGUARD_IMPLEMENTATION": "userspace",
    "WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL": "25s",
    "WIREGUARD_PRIVATE_KEY": "",
    "WIREGUARD_PUBLIC_KEY": "",
    "WIREGUARD_ADDRESSES": "",
    "WIREGUARD_ENDPOINT_IP": "",
    "WIREGUARD_ENDPOINT_PORT": "",
    "WIREGUARD_MTU": "1400",
    "WIREGUARD_PRIVATE_KEY_SECRETFILE": "/run/secrets/wireguard_private_key",
    "WIREGUARD_PRESHARED_KEY_SECRETFILE": "/run/secrets/wireguard_preshared_key",
    "WIREGUARD_ADDRESSES_SECRETFILE": "/run/secrets/wireguard_addresses",
}


def test_compose_env_and_image_defaults_still_go_idle(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path, **COMPOSE_AND_IMAGE_DEFAULTS)
    try:
        assert _wait_for(tmp_path / "idle")
        time.sleep(1.2)
        assert proc.poll() is None
        assert not (tmp_path / "started").exists()
    finally:
        proc.kill()


def test_compose_env_with_keys_set_is_not_idle(tmp_path: Path) -> None:
    env = {**COMPOSE_AND_IMAGE_DEFAULTS, "WIREGUARD_PRIVATE_KEY": "k" * 43 + "="}
    proc = _entrypoint(tmp_path, **env)
    try:
        assert _wait_for(tmp_path / "started")
        assert not (tmp_path / "idle").exists()
    finally:
        proc.kill()


def test_invalid_uploaded_file_is_not_idle_and_fails_closed(tmp_path: Path) -> None:
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "wg.env").write_text("anything\n", encoding="utf-8")
    proc = _entrypoint(tmp_path)
    assert proc.wait(timeout=10) == 1
    assert not (tmp_path / "idle").exists()
    assert not (tmp_path / "started").exists()


def test_health_script_is_healthy_only_in_idle_mode_or_when_gluetun_is(tmp_path: Path) -> None:
    marker = tmp_path / "idle"
    gluetun = tmp_path / "gluetun-health"
    gluetun.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    gluetun.chmod(0o755)
    env = {"PATH": PATH, "VPN_IDLE_MARKER": str(marker), "VPN_GLUETUN_BIN": str(gluetun)}
    health = ["/bin/sh", str(ROOT / "vpn" / "health.sh")]

    def code() -> int:
        return subprocess.run(health, env=env, capture_output=True, check=False).returncode  # noqa: S603

    assert code() == 1  # no marker: gluetun's own check decides (here: unhealthy)
    marker.write_text("", encoding="utf-8")
    assert code() == 0


# --- participant mode (M32): check-participant.sh, lib helpers, participant.sh -------------------

PARTICIPANT_DIRECT = {
    "SUCKERPOT_STACK_MODE": "participant",
    "COMPOSE_FILE": "docker-compose.yml:docker-compose.participant.yml",
    "COMPOSE_PROFILES": "direct",
    "EGRESS_MODE": "direct",
    "EGRESS_PROXY_URL": "http://hubproxy:8888",
    "EGRESS_CONTROL_URL": "http://hubproxy:8000",
    "HUBPROXY_ALLOW": "hub.example.org:443",
    "EGRESS_PROXY_PASSWORD": "a" * 24,
}
PARTICIPANT_VPN = {
    "SUCKERPOT_STACK_MODE": "participant",
    "COMPOSE_FILE": "docker-compose.yml:docker-compose.lowmem.yml:docker-compose.participant.yml",
    "COMPOSE_PROFILES": "egress",
    "EGRESS_MODE": "vpn",
    "EGRESS_PROXY_URL": "http://vpn:8888",
    "EGRESS_CONTROL_URL": "http://vpn:8000",
    "EGRESS_PROXY_PASSWORD": "a" * 24,
}


@pytest.fixture
def psb(sandbox: Sandbox) -> Sandbox:
    add_participant_files(sandbox)
    return sandbox


@pytest.fixture
def pscripts(tmp_path: Path) -> Path:
    dest = tmp_path / "scripts"
    dest.mkdir()
    shutil.copy(ROOT / "scripts" / "check-participant.sh", dest / "check-participant.sh")
    return dest


def _check(pscripts: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return _run(pscripts / "check-participant.sh", **env)


def test_check_participant_accepts_both_valid_layouts(pscripts: Path) -> None:
    assert _check(pscripts, **PARTICIPANT_DIRECT).returncode == 0
    assert _check(pscripts, **PARTICIPANT_VPN).returncode == 0
    with_feeds = {
        **PARTICIPANT_DIRECT,
        "HUBPROXY_ALLOW": "hub.example.org:443,feeds.example.org:443",
    }
    assert _check(pscripts, **with_feeds).returncode == 0


def test_check_participant_ignores_a_full_install(pscripts: Path) -> None:
    assert _check(pscripts).returncode == 0
    assert _check(pscripts, COMPOSE_PROFILES="egress,dashboard").returncode == 0


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"COMPOSE_FILE": "docker-compose.yml"}, "docker-compose.participant.yml"),
        ({"COMPOSE_PROFILES": "direct,egress"}, "exactly"),
        ({"COMPOSE_PROFILES": "dashboard"}, "exactly"),
        ({"COMPOSE_PROFILES": "egress"}, "EGRESS_MODE"),
        ({"EGRESS_MODE": "vpn"}, "EGRESS_MODE"),
        ({"EGRESS_PROXY_URL": "http://vpn:8888"}, "EGRESS_PROXY_URL"),
        ({"EGRESS_CONTROL_URL": "http://hubproxy:9999"}, "EGRESS_CONTROL_URL"),
        ({"HUBPROXY_ALLOW": ""}, "empty"),
        ({"HUBPROXY_ALLOW": "198.51.100.7:443"}, "address literals"),
        ({"HUBPROXY_ALLOW": "*.example.org:443"}, "malformed"),
        ({"HUBPROXY_ALLOW": "hub.example.org:8443"}, ":443"),
        ({"HUBPROXY_ALLOW": "hub.example.org"}, ":443"),
        ({"HUBPROXY_ALLOW": "hub:443"}, "dot"),
        ({"HUBPROXY_ALLOW": "printer.local:443"}, "local name"),
        ({"HUBPROXY_ALLOW": "Hub.Example.org:443"}, "malformed"),
        (
            {
                "HUBPROXY_ALLOW": "a.example.org:443,b.example.org:443,c.example.org:443,d.example.org:443"
            },
            "more than 3",
        ),
        ({"EGRESS_PROXY_PASSWORD": "short"}, "EGRESS_PROXY_PASSWORD"),
        ({"NETWORK_VERIFIER": "true"}, "needs a VPN"),
    ],
)
def test_check_participant_refuses_bad_direct_layouts(
    pscripts: Path, change: dict[str, str], message: str
) -> None:
    result = _check(pscripts, **{**PARTICIPANT_DIRECT, **change})
    assert result.returncode == 1, result.stderr
    assert message in result.stderr
    assert "a" * 24 not in result.stderr


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"HUBPROXY_ALLOW": "hub.example.org:443"}, "must be empty"),
        ({"EGRESS_PROXY_URL": "http://hubproxy:8888"}, "EGRESS_PROXY_URL"),
        ({"NETWORK_VERIFIER": "true"}, "COLLECTOR_ENABLED"),
    ],
)
def test_check_participant_refuses_bad_vpn_layouts(
    pscripts: Path, change: dict[str, str], message: str
) -> None:
    result = _check(pscripts, **{**PARTICIPANT_VPN, **change})
    assert result.returncode == 1
    assert message in result.stderr


def test_check_participant_accepts_a_verifier_with_vpn_and_collector(pscripts: Path) -> None:
    ok = {**PARTICIPANT_VPN, "NETWORK_VERIFIER": "true", "COLLECTOR_ENABLED": "true"}
    assert _check(pscripts, **ok).returncode == 0


def _bash_lib(sb: Sandbox, body: str) -> subprocess.CompletedProcess[str]:
    (sb.root / "t.sh").write_text('set -euo pipefail\ncd "$(dirname "$0")"\n' + body)
    return sb.run("t.sh")


def test_pseudonym_rules_match_the_hub(psb: Sandbox) -> None:
    body = (
        ". scripts/lib/pseudonym.sh\n"
        'ok() { pseudonym_valid "$1" 2>/dev/null && echo "ok:$1" || echo "no:$1"; }\n'
        'ok "amber-falcon-42"\nok "ab"\nok "Admin"\nok "n o d e"\nok "a_b.c-d"\n'
        'ok "two  spaces"\nok "year 2026 x"\nok "my honeypot"\nok "SelfHostr-Fan"\n'
        'ok "-lead"\nok "trail-"\nok "mail@x"\nok "url://x"\nok "ünï"\n'
        'ok "$(printf "a%.0s" $(seq 1 25))"\nok "$(printf "a%.0s" $(seq 1 24))"\n'
    )
    proc = _bash_lib(psb, body)
    assert proc.returncode == 0, proc.stderr
    results = dict(line.split(":", 1)[::-1] for line in proc.stdout.splitlines())
    good = {name for name, verdict in results.items() if verdict == "ok"}
    assert good == {"amber-falcon-42", "a_b.c-d", "a" * 24}


def test_random_pseudonyms_are_valid_and_vary(psb: Sandbox) -> None:
    body = ". scripts/lib/pseudonym.sh\nfor _ in $(seq 1 40); do pseudonym_random; echo; done\n"
    proc = _bash_lib(psb, body)
    assert proc.returncode == 0, proc.stderr
    names = proc.stdout.split()
    assert len(names) == 40
    assert len(set(names)) > 30
    words = (ROOT / "netproto/suckerpot_netproto/data/pseudonym_words.txt").read_text()
    adjectives, nouns = words.split("[nouns]")
    for name in names:
        adjective, noun, number = name.split("-")
        assert re.fullmatch(r"\d\d", number)
        assert f"\n{adjective}\n" in adjectives
        assert f"\n{noun}\n" in nouns
        assert len(name) <= 24


def test_hubproxy_allow_comes_from_the_shipped_defaults(psb: Sandbox) -> None:
    body = (
        ". scripts/lib/env.sh\nhubproxy_allow 0; echo\nhubproxy_allow 1; echo\n"
        'url_host "https://hub.example.org:8443/v1"; echo\n'
    )
    proc = _bash_lib(psb, body)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == [
        "suckerpot-hub.selfhostr.io:443",
        "suckerpot-hub.selfhostr.io:443,suckerpot-feeds.selfhostr.io:443",
        "hub.example.org",
    ]


def test_wg_parse_conf_is_text_only_and_strict(psb: Sandbox) -> None:
    good = psb.root / "good.conf"
    good.write_text(
        "[Interface]\nPrivateKey = KEY1\nAddress = 198.51.100.2/32, 2001:db8::2/128\nDNS = 198.51.100.1\n"
        "PostUp = touch /tmp/pwned\n[Peer]\nPublicKey = KEY2\nEndpoint = 203.0.113.9:51820\n"
    )
    bad = psb.root / "bad.conf"
    bad.write_text(
        "[Interface]\nPrivateKey = $(touch pwned)\nAddress = 1.1.1.1\n[Peer]\nPublicKey = K\nEndpoint = 203.0.113.9:1\n"
    )
    body = (
        ". scripts/lib/env.sh\n"
        'wg_parse_conf good.conf && echo "$wg_ep_ip $wg_ep_port $wg_addr"\n'
        "wg_parse_conf bad.conf 2>&1 && echo BAD || echo refused\n"
        "wg_parse_conf missing.conf 2>&1 || true\n"
    )
    proc = _bash_lib(psb, body)
    assert proc.returncode == 0, proc.stderr
    assert "203.0.113.9 51820 198.51.100.2/32,2001:db8::2/128" in proc.stdout
    assert "refused" in proc.stdout
    assert "unexpected characters" in proc.stdout
    assert not (psb.root / "pwned").exists()


def test_env_set_allows_the_verify_switches_and_never_the_consent(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\nNETWORK_ENABLED=true\n")
    proc = sandbox.run(
        "scripts/env-set.sh", "set", "NETWORK_VERIFY_REVEALS=false", "NETWORK_VERIFIER=false"
    )
    assert proc.returncode == 0, proc.stderr
    env = parse_env(sandbox.root / ".env")
    assert env["NETWORK_VERIFY_REVEALS"] == "false"
    bad = sandbox.run("scripts/env-set.sh", "set", "NETWORK_VERIFIER=maybe")
    assert bad.returncode != 0
    consent = sandbox.run("scripts/env-set.sh", "set", "NETWORK_CONSENT=v1:sources:2026-01-01")
    assert consent.returncode != 0
    assert "NETWORK_CONSENT" in consent.stderr
    assert "NETWORK_CONSENT" not in parse_env(sandbox.root / ".env")


def test_env_set_can_clear_the_consent_record_but_never_set_it(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    record = "v2:sources,payloads,c2,files,rechecks:2026-11-03"
    sandbox.write_env(f"COMPOSE_PROJECT_NAME=demo\nNETWORK_CONSENT={record}\n")
    refused = sandbox.run("scripts/env-set.sh", "set", "NETWORK_CONSENT=x")
    assert refused.returncode != 0
    assert parse_env(sandbox.root / ".env")["NETWORK_CONSENT"] == record
    cleared = sandbox.run("scripts/env-set.sh", "set", "NETWORK_CONSENT=")
    assert cleared.returncode == 0, cleared.stderr
    assert parse_env(sandbox.root / ".env").get("NETWORK_CONSENT", "") == ""


def test_env_set_auto_update_flag_points_at_the_schedule_command(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\n")
    proc = sandbox.run("scripts/env-set.sh", "set", "AUTO_UPDATE_ENABLED=true")
    assert proc.returncode == 0, proc.stderr
    assert parse_env(sandbox.root / ".env")["AUTO_UPDATE_ENABLED"] == "true"
    assert "participant.sh auto-update" in proc.stdout


def test_env_migrate_adds_the_mode_defaults_without_changing_the_mode(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\nSUCKERPOT_STACK_MODE=participant\n")
    proc = sandbox.run("scripts/env-migrate.sh")
    assert proc.returncode == 0, proc.stderr
    env = parse_env(sandbox.root / ".env")
    assert env["SUCKERPOT_STACK_MODE"] == "participant"
    assert env["AUTO_UPDATE_ENABLED"] == "false"
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\n")
    assert sandbox.run("scripts/env-migrate.sh").returncode == 0
    env = parse_env(sandbox.root / ".env")
    assert env["SUCKERPOT_STACK_MODE"] == "full"


# participant.sh ---------------------------------------------------------------------------------


@pytest.fixture
def installed(psb: Sandbox) -> Sandbox:
    """A sandbox with a finished participant install (fake docker) and a fake ingest CLI."""
    rc, out = p_real(psb)
    assert rc == 0, out
    wrap_docker(
        psb,
        '  "compose exec -T ingest python -m ingest.network.cli leave")\n'
        '    echo "docker $*" >> "$SHIM_LOG"; exit 0 ;;\n'
        '  "compose exec -T ingest python -m ingest.network.cli status --json")\n'
        '    cat "$SHIM_DIR/cli-state.json"; exit 0 ;;',
    )
    (psb.shim / "cli-state.json").write_text('{"state": "off"}')
    return psb


def _calls_after(sb: Sandbox, start: int) -> list[str]:
    return sb.calls()[start:]


def test_auto_update_off_and_on(
    installed: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    assert crontab_text(installed).strip() != ""
    proc = installed.run("scripts/participant.sh", "auto-update", "off")
    assert proc.returncode == 0, proc.stderr
    assert crontab_text(installed).strip() == ""
    assert parse_env(installed.root / ".env")["AUTO_UPDATE_ENABLED"] == "false"
    proc = installed.run("scripts/participant.sh", "auto-update", "on")
    assert proc.returncode == 0, proc.stderr
    first = crontab_text(installed)
    assert len([line for line in first.splitlines() if "selfhostr-auto-update" in line]) == 1
    assert parse_env(installed.root / ".env")["AUTO_UPDATE_ENABLED"] == "true"
    proc = installed.run("scripts/participant.sh", "auto-update", "on")
    assert proc.returncode == 0
    assert crontab_text(installed) == first  # the same time, one line


def test_auto_update_on_needs_signed_images(installed: Sandbox) -> None:
    text = (
        (installed.root / ".env")
        .read_text()
        .replace("SUCKERPOT_INSTALL_MODE=images", "SUCKERPOT_INSTALL_MODE=source")
    )
    installed.write_env(text)
    proc = installed.run("scripts/participant.sh", "auto-update", "on")
    assert proc.returncode != 0
    assert "signed release images" in proc.stderr


def test_auto_update_leaves_other_crontab_lines_alone(installed: Sandbox) -> None:
    path = installed.shim / "crontab.txt"
    path.write_text("0 1 * * * /usr/bin/backup-home\n" + path.read_text())
    assert installed.run("scripts/participant.sh", "auto-update", "off").returncode == 0
    assert path.read_text() == "0 1 * * * /usr/bin/backup-home\n"


def _wg_file(sb: Sandbox, endpoint: str = "8.8.4.4:51820") -> Path:
    conf = sb.root / "wg.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 198.51.100.2/32\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        f"Endpoint = {endpoint}\n"
    )
    return conf


def test_vpn_file_switches_to_the_vpn_path(
    installed: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    start = len(installed.calls())
    proc = installed.run("scripts/participant.sh", "vpn", str(_wg_file(installed)))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = parse_env(installed.root / ".env")
    assert env["COMPOSE_PROFILES"] == "egress"
    assert env["EGRESS_MODE"] == "vpn"
    assert env["EGRESS_PROXY_URL"] == "http://vpn:8888"
    assert env["EGRESS_CONTROL_URL"] == "http://vpn:8000"
    assert env["VPN_WG_ENDPOINT_IP"] == "8.8.4.4"
    assert "HUBPROXY_ALLOW" not in env
    assert stat.S_IMODE((installed.root / ".env").stat().st_mode) == 0o600
    calls = _calls_after(installed, start)
    assert "docker compose --profile direct rm -sf hubproxy" in calls
    assert any(c.startswith("docker compose up") and "--remove-orphans" in c for c in calls)
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" not in proc.stdout + proc.stderr
    assert "goes through your VPN" in proc.stdout


def test_vpn_remove_goes_back_to_direct_and_drops_the_verifier(
    installed: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    assert installed.run("scripts/participant.sh", "vpn", str(_wg_file(installed))).returncode == 0
    text = (installed.root / ".env").read_text() + "NETWORK_VERIFIER=true\nCOLLECTOR_ENABLED=true\n"
    installed.write_env(text)
    start = len(installed.calls())
    proc = installed.run("scripts/participant.sh", "vpn", "--remove")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = parse_env(installed.root / ".env")
    assert env["COMPOSE_PROFILES"] == "direct"
    assert env["EGRESS_MODE"] == "direct"
    assert env["EGRESS_PROXY_URL"] == "http://hubproxy:8888"
    assert env["HUBPROXY_ALLOW"] == "suckerpot-hub.selfhostr.io:443"
    assert env["VPN_WG_PRIVATE_KEY"] == ""
    assert env["NETWORK_VERIFIER"] == "false"
    assert env["COLLECTOR_ENABLED"] == "false"
    assert "docker compose --profile egress rm -sf vpn collector analyzer" in _calls_after(
        installed, start
    )
    assert "The hub now sees this machine's address" in proc.stdout


def test_a_bad_vpn_file_changes_nothing(installed: Sandbox) -> None:
    before = (installed.root / ".env").read_text()
    start = len(installed.calls())
    proc = installed.run(
        "scripts/participant.sh", "vpn", str(_wg_file(installed, "vpn.example.org:51820"))
    )
    assert proc.returncode != 0
    assert "IPv4" in proc.stderr
    assert (installed.root / ".env").read_text() == before
    assert not any(c.startswith("docker compose up") for c in _calls_after(installed, start))


def test_a_vpn_change_that_does_not_start_is_put_back(installed: Sandbox) -> None:
    before = (installed.root / ".env").read_text()
    wrap_docker(installed, '  "compose up"*) exit 1 ;;')
    proc = installed.run("scripts/participant.sh", "vpn", str(_wg_file(installed)))
    assert proc.returncode != 0
    assert ".env was put back" in proc.stderr
    assert (installed.root / ".env").read_text() == before


def test_leave_turns_the_network_off_and_keeps_the_sensors(
    installed: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    start = len(installed.calls())
    proc = installed.run("scripts/participant.sh", "leave")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert parse_env(installed.root / ".env")["NETWORK_ENABLED"] == "false"
    calls = _calls_after(installed, start)
    assert "docker compose exec -T ingest python -m ingest.network.cli leave" in calls
    ups = [c for c in calls if c.startswith("docker compose up")]
    assert len(ups) == 1
    assert ups[0].endswith("--no-deps ingest")  # only ingest restarts
    assert not any(c.startswith("docker compose down") for c in calls)


def test_leave_that_is_not_confirmed_changes_nothing(installed: Sandbox) -> None:
    (installed.shim / "cli-state.json").write_text('{"state": "member"}')
    before = (installed.root / ".env").read_text()
    proc = installed.run("scripts/participant.sh", "leave")
    assert proc.returncode != 0
    assert (installed.root / ".env").read_text() == before


def test_leave_ignores_a_nested_off_state(installed: Sandbox) -> None:
    # The real status holds nested objects with their own "state" (verifier, consent): an "off"
    # there must not count as "the node has left" while the top-level state is still member.
    (installed.shim / "cli-state.json").write_text(
        '{"network": {"verifier": {"enabled": false, "state": "off"}}, "state": "member"}'
    )
    before = (installed.root / ".env").read_text()
    proc = installed.run("scripts/participant.sh", "leave")
    assert proc.returncode != 0
    assert (installed.root / ".env").read_text() == before


def test_leave_accepts_the_top_level_state_next_to_nested_ones(installed: Sandbox) -> None:
    (installed.shim / "cli-state.json").write_text(
        '{"network": {"verifier": {"state": "off"}, "consent": {"state": "valid"}}, "state": "left"}'
    )
    proc = installed.run("scripts/participant.sh", "leave")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_join_shows_the_consent_and_writes_a_fresh_record(
    installed: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    assert installed.run("scripts/participant.sh", "leave").returncode == 0
    old_pseudonym = parse_env(installed.root / ".env")["NETWORK_PSEUDONYM"]
    (installed.shim / "cli-state.json").write_text(
        '{"state": "member", "pseudonym": "Grey Heron 7", "error_code": null}'
    )
    start = len(installed.calls())
    proc = installed.run("scripts/participant.sh", "join", "--yes", "--pseudonym", "Grey Heron 7")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "joined as Grey Heron 7" in proc.stdout
    calls = _calls_after(installed, start)
    assert (
        "docker compose exec -T ingest python -m ingest.network.cli join --pseudonym Grey Heron 7"
        in calls
    )
    assert "SuckerPot participant mode" in proc.stdout
    assert "Pseudonym: Grey Heron 7" in proc.stdout
    env = parse_env(installed.root / ".env")
    assert env["NETWORK_ENABLED"] == "true"
    assert env["NETWORK_PSEUDONYM"] == "'Grey Heron 7'"
    assert env["NETWORK_PSEUDONYM"] != old_pseudonym
    assert env["NETWORK_CONSENT"].startswith(
        "v2:sources,payloads,c2,files,rechecks,verify_reveals:"
    )


def test_join_reports_a_taken_pseudonym_and_suggests_another(installed: Sandbox) -> None:
    # The 2026-11-21 report: the hub refused the name of an earlier install and nothing said so.
    (installed.shim / "cli-state.json").write_text(
        '{"network": {"membership": {"desired": "off", "state": "error"}}, '
        '"state": "error", "pseudonym": "bignoe", "error_code": "pseudonym_taken"}'
    )
    proc = installed.run("scripts/participant.sh", "join", "--yes", "--pseudonym", "bignoe")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "the hub refused the pseudonym 'bignoe'" in proc.stderr
    assert re.search(r"join --pseudonym bignoe-\d\d\n", proc.stderr)


def test_join_still_in_progress_says_so(installed: Sandbox) -> None:
    (installed.shim / "cli-state.json").write_text('{"state": "enrolling", "error_code": null}')
    proc = installed.run(
        "scripts/participant.sh", "join", "--yes", extra_env={"SUCKERPOT_ENROL_WAIT": "0"}
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "still in progress" in proc.stdout


def test_join_declined_changes_nothing(installed: Sandbox) -> None:
    assert installed.run("scripts/participant.sh", "leave").returncode == 0
    before = (installed.root / ".env").read_text()
    answers = installed.root / "answers"
    answers.write_text("n\n")
    proc = installed.run(
        "scripts/participant.sh", "join", extra_env={"SELFHOSTR_TTY": str(answers)}
    )
    assert proc.returncode != 0
    assert (installed.root / ".env").read_text() == before


def test_join_refuses_a_bad_pseudonym(installed: Sandbox) -> None:
    before = (installed.root / ".env").read_text()
    proc = installed.run("scripts/participant.sh", "join", "--yes", "--pseudonym", "root")
    assert proc.returncode != 0
    assert (installed.root / ".env").read_text() == before


def test_uninstall_stops_the_stack_and_only_prints_the_volume_command(installed: Sandbox) -> None:
    start = len(installed.calls())
    proc = installed.run("scripts/participant.sh", "uninstall", "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = _calls_after(installed, start)
    assert "docker compose down" in calls
    assert crontab_text(installed).strip() == ""
    assert not any("volume rm" in c for c in calls)
    assert "docker volume ls -q --filter" in proc.stdout
    assert "xargs docker volume rm" in proc.stdout
    assert "NOT deleted" in proc.stdout


def test_participant_commands_are_refused_on_a_full_install(psb: Sandbox) -> None:
    rc, out = _real_run(psb)
    assert rc == 0, out
    for args in (["leave"], ["join", "--yes"], ["vpn", "--remove"], ["uninstall", "--yes"]):
        proc = psb.run("scripts/participant.sh", *args)
        assert proc.returncode != 0, args
        assert "full install" in proc.stderr


def test_participant_sh_needs_an_install_and_knows_its_commands(psb: Sandbox) -> None:
    proc = psb.run("scripts/participant.sh", "status")
    assert proc.returncode != 0
    assert "nothing is installed" in proc.stderr
    psb.write_env("COMPOSE_PROJECT_NAME=demo\nSUCKERPOT_VOLUME_PREFIX=demo\n")
    proc = psb.run("scripts/participant.sh", "explode")
    assert proc.returncode != 0
    assert "unknown command" in proc.stderr
