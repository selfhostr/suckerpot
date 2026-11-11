"""scripts/install.sh: what it writes, what it refuses, and that it never looks up an address.

Every run happens in the sandbox of conftest.py (fake docker, git, curl, ss on PATH).
"""

import re
import shutil
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox, is_real_docker_untouched

SECRET_NAMES = [
    line.strip()
    for line in (ROOT / "scripts/lib/env.sh")
    .read_text()
    .split("SECRET_VARS=(", 1)[1]
    .split(")", 1)[0]
    .split()
]
PASSWORD = "correct horse battery"  # noqa: S105
ALL_IFACES = "0.0.0.0"  # noqa: S104


def dry_run(
    sb: Sandbox, *extra: str, out: str = "out.env", stdin: str | None = None
) -> tuple[Path, int, str]:
    target = sb.root / out
    proc = sb.run(
        "scripts/install.sh",
        "--yes",
        "--dry-run",
        "--env-out",
        str(target),
        "--sensors",
        "ssh,web",
        "--admin-password-stdin",
        *extra,
        stdin=PASSWORD + "\n" if stdin is None else stdin,
    )
    return target, proc.returncode, proc.stdout + proc.stderr


def test_only_the_fake_docker_is_reachable(sandbox: Sandbox) -> None:
    assert is_real_docker_untouched(sandbox)


def test_secret_list_matches_env_example() -> None:
    example = (ROOT / ".env.example").read_text()
    assert len(SECRET_NAMES) >= 20
    for name in SECRET_NAMES:
        assert re.search(rf"^{name}=", example, re.MULTILINE), name


def test_dry_run_writes_a_complete_env(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(sandbox)
    assert rc == 0, out
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    env = parse_env(target)
    values = []
    for name in SECRET_NAMES:
        assert len(env[name]) >= 24, name
        values.append(env[name])
    assert len(set(values)) == len(values), "secrets must be pairwise different"
    assert len(env["SESSION_SECRET"]) >= 64
    assert "change-me" not in "\n".join(
        line for line in target.read_text().splitlines() if not line.startswith("#")
    )
    assert env["COMPOSE_PROJECT_NAME"] == "suckerpot"
    assert env["SUCKERPOT_VOLUME_PREFIX"] == "suckerpot"
    assert env["SENSOR_SSH"] == "1"
    assert env["SENSOR_WEB"] == "1"
    assert env["SENSOR_TELNET"] == "0"
    assert env["COMPOSE_PROFILES"] == "egress"
    assert env["COOKIE_SECURE"] == "true"
    assert env["DASHBOARD_BIND"] == "127.0.0.1"
    assert re.fullmatch(r"'\$argon2[^']+'", env["ADMIN_PASSWORD_HASH"])
    # The password is never written, and nothing was run.
    assert PASSWORD not in target.read_text()
    assert sandbox.docker_calls() == []
    assert not (sandbox.root / ".env").exists()
    assert not (sandbox.root / "install.log").exists()


def test_dry_run_secrets_differ_between_runs(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    a, rc_a, _ = dry_run(sandbox, out="a.env")
    b, rc_b, _ = dry_run(sandbox, out="b.env")
    assert rc_a == rc_b == 0
    assert parse_env(a)["POSTGRES_PASSWORD"] != parse_env(b)["POSTGRES_PASSWORD"]


def test_https_tunnel_sets_hosts_origins_and_secure_cookie(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(
        sandbox, "--public-host", "dash.example.org", "--project", "demo", "--prefix", "demo-data"
    )
    assert rc == 0, out
    env = parse_env(target)
    assert env["API_ALLOWED_HOSTS"] == "dash.example.org"
    assert env["API_ALLOWED_ORIGINS"] == "https://dash.example.org"
    assert env["COOKIE_SECURE"] == "true"
    assert env["COMPOSE_PROJECT_NAME"] == "demo"
    assert env["SUCKERPOT_VOLUME_PREFIX"] == "demo-data"


def test_wireguard_file_is_parsed_without_printing_keys(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    conf = sandbox.root / "wg.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 198.51.100.2/32\nDNS = 198.51.100.1\n"
        "[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        "Endpoint = 198.51.100.7:51820\nAllowedIPs = 0.0.0.0/0\n"
    )
    target, rc, out = dry_run(sandbox, "--wg-conf", str(conf))
    assert rc == 0, out
    env = parse_env(target)
    assert env["VPN_WG_ENDPOINT_IP"] == "198.51.100.7"
    assert env["VPN_WG_ENDPOINT_PORT"] == "51820"
    assert env["VPN_WG_ADDRESSES"] == "198.51.100.2/32"
    assert env["VPN_WG_PRIVATE_KEY"].startswith("AAAAAAAA")
    assert "AAAAAAAAAAAAAAAA" not in out


def test_wireguard_hostname_endpoint_is_refused(sandbox: Sandbox) -> None:
    conf = sandbox.root / "wg.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = a\nAddress = 198.51.100.2/32\n"
        "[Peer]\nPublicKey = b\nEndpoint = vpn.example.org:51820\n"
    )
    _, rc, out = dry_run(sandbox, "--wg-conf", str(conf))
    assert rc != 0
    assert "IPv4" in out


def test_refuses_when_env_exists(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=suckerpot\n")
    before = (sandbox.root / ".env").read_text()
    target, rc, out = dry_run(sandbox)
    assert rc != 0
    assert "already installed" in out
    assert not target.exists()
    assert (sandbox.root / ".env").read_text() == before


def test_refuses_to_overwrite_an_existing_env_out(sandbox: Sandbox) -> None:
    (sandbox.root / "out.env").write_text("keep\n")
    _, rc, _ = dry_run(sandbox)
    assert rc != 0
    assert (sandbox.root / "out.env").read_text() == "keep\n"


def test_refuses_throwaway_and_bad_names(sandbox: Sandbox) -> None:
    for name in ("sp-it-abc123-1", "sp-test", "sp-ci", "Bad Name", "-lead", "UPPER", "a" * 42):
        for flag in ("--project", "--prefix"):
            args = (flag, name) if flag == "--project" else ("--project", "okname", flag, name)
            target, rc, out = dry_run(sandbox, *args, out=f"n{abs(hash((name, flag)))}.env")
            assert rc != 0, (flag, name, out)
            assert not target.exists()


def test_test_install_mode_accepts_only_the_e2e_name_shape(sandbox: Sandbox) -> None:
    # scripts/e2e/participant.sh installs under sp-it-participant-<random> with this switch set;
    # the switch must never open the door to a live-looking name, and the e2e name is refused
    # without the switch.
    env = {"SELFHOSTR_TEST_INSTALL": "1"}

    def run(name: str, out: str, extra_env: dict[str, str] | None) -> int:
        proc = sandbox.run(
            "scripts/install.sh", "--yes", "--dry-run", "--env-out", str(sandbox.root / out),
            "--sensors", "ssh", "--admin-password-stdin", "--project", name, "--prefix", name,
            stdin=PASSWORD + "\n", extra_env=extra_env,
        )  # fmt: skip
        return proc.returncode

    assert run("sp-it-participant-abcd1234", "ok.env", env) == 0
    assert run("sp-it-participant-abcd1234", "no1.env", None) != 0
    for name in ("suckerpot", "sp-it-abc123-1", "sp-ci", "sp-it-participant-AB"):
        assert run(name, f"no-{abs(hash(name))}.env", env) != 0, name


def test_refuses_a_linked_worktree(sandbox: Sandbox) -> None:
    sandbox.git_mode("linked")
    target, rc, out = dry_run(sandbox)
    assert rc != 0
    assert "worktree" in out
    assert not target.exists()


def test_normal_git_checkout_is_accepted(sandbox: Sandbox) -> None:
    sandbox.git_mode("normal")
    _, rc, out = dry_run(sandbox)
    assert rc == 0, out


def test_refuses_unknown_sensor_and_short_password(sandbox: Sandbox) -> None:
    _, rc, out = dry_run(sandbox, "--sensors", "ssh,nope")
    assert rc != 0
    assert "unknown sensor" in out
    _, rc, out = dry_run(sandbox, stdin="short\n")
    assert rc != 0
    assert "12 characters" in out


def test_dry_run_requires_env_out(sandbox: Sandbox) -> None:
    proc = sandbox.run("scripts/install.sh", "--yes", "--dry-run")
    assert proc.returncode != 0


def test_interactive_answers_come_from_the_terminal(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    answers = sandbox.root / "answers"
    # mode, sensors, access, admin user, password x2, wireguard, public address, network
    answers.write_text("source\nssh,telnet\nl\nowner\n" + PASSWORD + "\n" + PASSWORD + "\n\n\n\n\n")
    target = sandbox.root / "i.env"
    proc = sandbox.run(
        "scripts/install.sh",
        "--dry-run",
        "--env-out",
        str(target),
        extra_env={"SELFHOSTR_TTY": str(answers)},
    )
    assert proc.returncode == 0, proc.stderr
    env = parse_env(target)
    assert env["ADMIN_USERNAME"] == "owner"
    assert env["SENSOR_TELNET"] == "1"
    assert env["SENSOR_WEB"] == "0"
    assert env["SUCKERPOT_INSTALL_MODE"] == "source"
    assert PASSWORD not in proc.stdout + proc.stderr


def _real_run(sb: Sandbox, *extra: str, stdin: str = PASSWORD + "\n") -> tuple[int, str]:
    proc = sb.run(
        "scripts/install.sh",
        "--yes",
        "--images",
        "--version",
        "v0.8.0",
        "--sensors",
        "ssh,web",
        "--admin-password-stdin",
        *extra,
        stdin=stdin,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_full_install_with_fake_docker(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    env_path = sandbox.root / ".env"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    env = parse_env(env_path)
    assert env["SUCKERPOT_INSTALL_MODE"] == "images"
    assert env["SUCKERPOT_VERSION"] == "v0.8.0"
    assert env["ADMIN_PASSWORD_HASH"].startswith("'$argon2")
    calls = "\n".join(sandbox.calls())
    # The password reached the hasher on stdin only.
    assert (sandbox.shim / "hash-stdin").read_text() == PASSWORD + "\n"
    assert PASSWORD not in calls
    assert PASSWORD not in out
    for name in SECRET_NAMES:
        assert env[name] not in calls
        assert env[name] not in out
    assert "docker pull --quiet ghcr.io/selfhostr/suckerpot-api@sha256:" in calls
    assert "--network none" in calls
    assert "docker volume create suckerpot_db-data" in calls
    assert "docker compose pull --policy missing" in calls
    assert "docker compose up -d --no-build --pull never --wait --wait-timeout 600" in calls
    assert "curl -fsS --max-time 5 http://127.0.0.1:8443/healthz" in calls
    log = (sandbox.root / "install.log").read_text()
    assert PASSWORD not in log
    assert all(env[name] not in log for name in SECRET_NAMES)
    # Nothing outside the shims was reached, and no compose call names a stack other than .env's.
    assert " -p " not in calls


def test_full_install_generates_and_prints_the_password_once(sandbox: Sandbox) -> None:
    proc = sandbox.run(
        "scripts/install.sh", "--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh"
    )
    assert proc.returncode == 0, proc.stderr
    printed = re.findall(r"password .*: (\S+)", proc.stdout)
    assert len(printed) == 1
    assert len(printed[0]) >= 20
    assert printed[0] not in "\n".join(sandbox.calls())
    assert (sandbox.shim / "hash-stdin").read_text() == printed[0] + "\n"


def test_install_refuses_existing_volumes_and_adopts_nothing(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_EXISTING_VOLUMES"] = "suckerpot_db-data"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "already exist" in out
    assert not (sandbox.root / ".env").exists()
    assert not any(c.startswith("docker volume create") for c in sandbox.docker_calls())


def test_install_refuses_any_volume_of_the_prefix(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_EXISTING_VOLUMES"] = "suckerpot_backups"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "already exist" in out
    assert not (sandbox.root / ".env").exists()


def test_install_refuses_existing_containers_of_the_project(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_PROJECT_CONTAINERS"] = "0123456789ab"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "Containers of the compose project" in out
    assert not (sandbox.root / ".env").exists()


def test_install_refuses_low_memory_and_low_disk(sandbox: Sandbox) -> None:
    (sandbox.shim / "meminfo").write_text("MemTotal:        1000000 kB\n")
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "2 GiB" in out
    (sandbox.shim / "meminfo").write_text("MemTotal:        8000000 kB\n")
    sandbox.env["SELFHOSTR_FREE_DISK_KB"] = str(5 * 1024 * 1024)
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "15 GiB" in out
    assert not (sandbox.root / ".env").exists()


def test_busy_ssh_port_is_mapped_to_2222_and_admin_port_protected(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    (sandbox.shim / "ss-output").write_text(
        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\n"
    )
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    env = parse_env(sandbox.root / ".env")
    assert env["SSH_HOST_PORT"] == "2222"
    assert env["ADMIN_SSH_PORT"] == "22"
    assert env["SENSOR_SSH"] == "1"


def test_other_busy_port_turns_that_sensor_off(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    (sandbox.shim / "ss-output").write_text("tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n")
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    assert "web sensor is left off" in out
    assert parse_env(sandbox.root / ".env")["SENSOR_WEB"] == "0"


def test_lowmem_overlay_goes_into_compose_file(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = _real_run(sandbox, "--lowmem", "on")
    assert rc != 0 and "docker-compose.lowmem.yml" in out
    (sandbox.root / "docker-compose.lowmem.yml").write_text("services: {}\n")
    rc, out = _real_run(sandbox, "--lowmem", "on")
    assert rc == 0, out
    env = parse_env(sandbox.root / ".env")
    assert env["COMPOSE_FILE"] == "docker-compose.yml:docker-compose.lowmem.yml"


def test_source_mode_builds_here(sandbox: Sandbox) -> None:
    proc = sandbox.run(
        "scripts/install.sh",
        "--yes",
        "--source",
        "--sensors",
        "ssh",
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
    )
    assert proc.returncode == 0, proc.stderr
    calls = "\n".join(sandbox.calls())
    assert "docker build -q -f api/Dockerfile -t suckerpot-install-api ." in calls
    assert "docker compose up -d --build --wait --wait-timeout 900" in calls
    assert "docker compose pull" not in calls


def test_a_failed_start_stops_with_a_named_reason(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_UP_RC"] = "1"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "did not become healthy" in out


def test_script_never_looks_up_a_public_address() -> None:
    forbidden = ("ipify", "icanhazip", "ifconfig.me", "checkip", "ipinfo", "myip", "wget", "nc ")
    for rel in (
        "scripts/install.sh",
        "scripts/update.sh",
        "scripts/rollback.sh",
        "scripts/lib/env.sh",
    ):
        text = (ROOT / rel).read_text()
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for word in forbidden:
            assert word not in code, (rel, word)
        for line in code.splitlines():
            if re.search(r"\bcurl\b", line):
                assert "healthz" in line, (rel, line)
                assert re.search(r"http://(\$hbind|\$bind|127\.0\.0\.1)", line), (rel, line)


def test_images_install_verifies_before_anything_runs(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    calls = sandbox.docker_calls()
    verify = next(i for i, c in enumerate(calls) if "cosign" in c and " verify " in c)
    hasher = next(i for i, c in enumerate(calls) if "api.hashpw" in c)
    up = next(i for i, c in enumerate(calls) if c.startswith("docker compose up"))
    assert verify < hasher < up  # the api image is verified before it hashes the password
    assert "docker compose pull" not in calls
    env = parse_env(sandbox.root / ".env")
    assert env["SUCKERPOT_IMAGE_PREFIX"].startswith("ghcr.io/")
    assert env["UPDATE_CHECK_ENABLED"] == "false"


def test_failed_signature_check_starts_nothing(sandbox: Sandbox) -> None:
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "could not be verified" in out
    assert not any("api.hashpw" in c for c in sandbox.docker_calls())
    assert not any(c.startswith("docker compose up") for c in sandbox.docker_calls())


def test_skip_verify_is_explicit_and_loud(sandbox: Sandbox) -> None:
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    rc, out = _real_run(sandbox, "--skip-verify")
    assert rc == 0, out
    assert "NOT checked" in out


def test_lan_bind_needs_a_tunnel_or_an_explicit_flag(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    _, rc, out = dry_run(sandbox, "--dashboard-bind", ALL_IFACES)
    assert rc != 0
    assert "--allow-lan" in out
    target, rc, out = dry_run(sandbox, "--dashboard-bind", ALL_IFACES, "--allow-lan")
    assert rc == 0, out
    assert parse_env(target)["COOKIE_SECURE"] == "false"
    target, rc, out = dry_run(
        sandbox, "--dashboard-bind", ALL_IFACES, "--public-host", "dash.example.org", out="b.env"
    )
    assert rc == 0, out
    assert parse_env(target)["COOKIE_SECURE"] == "true"


def test_a_failed_install_leaves_no_temporary_env(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_PROJECT_CONTAINERS"] = "0123456789ab"
    _real_run(sandbox)
    assert not list(sandbox.root.glob(".env*.tmp")) and not (sandbox.root / ".env.tmp").exists()


def test_bad_image_prefix_is_refused(sandbox: Sandbox) -> None:
    sandbox.env["SUCKERPOT_IMAGE_PREFIX"] = "evil.example/x/y"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "SUCKERPOT_IMAGE_PREFIX" in out
    assert not any("api.hashpw" in c for c in sandbox.docker_calls())


# --------------------------------------------------------------------- participant mode (M32)

PARTICIPANT_FILES = [
    "scripts/lib/firewall.sh",
    "scripts/host/render-firewall.sh",
    "scripts/host/install-firewall.sh",
    "scripts/host/firewall-participant.nft",
    "scripts/host/firewall.nft",
    "scripts/lib/pseudonym.sh",
    "scripts/lib/schedule.sh",
    "scripts/lib/status_render.py",
    "scripts/status.sh",
    "scripts/participant.sh",
    "scripts/check-participant.sh",
    "docker-compose.participant.yml",
    "config/network-defaults.env",
    "netproto/suckerpot_netproto/data/pseudonym_words.txt",
]

CRONTAB_SHIM = r"""#!/bin/sh
# Fake crontab: a text file in $SHIM_DIR, never the real crontab of the user running the tests.
f="$SHIM_DIR/crontab.txt"
echo "crontab $*" >> "$SHIM_LOG"
case "$1" in
  -l) if [ -f "$f" ]; then cat "$f"; else echo "no crontab for user" >&2; exit 1; fi ;;
  -r) rm -f "$f" ;;
  -) cat > "$f" ;;
  *) exit 2 ;;
esac
"""


def add_participant_files(sb: Sandbox) -> None:
    """Copies the participant scripts into the sandbox and puts a fake crontab on PATH."""
    for rel in PARTICIPANT_FILES:
        dest = sb.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest)
    # Never the real loader: it would run sudo. test_firewall_step.py checks how it is called.
    loader = sb.root / "scripts/host/install-firewall.sh"
    loader.write_text('#!/bin/sh\necho "install-firewall $*" >> "$SHIM_LOG"\n')
    loader.chmod(0o755)
    crontab = sb.shim / "crontab"
    crontab.write_text(CRONTAB_SHIM)
    crontab.chmod(0o755)


def wrap_docker(sb: Sandbox, cases: str) -> None:
    """Puts a wrapper before the fake docker: `cases` is the body of a `case "$*" in` (POSIX sh)."""
    base = sb.shim / "docker-base"
    if not base.exists():
        (sb.shim / "docker").rename(base)
    wrapper = sb.shim / "docker"
    wrapper.write_text(
        '#!/bin/sh\ncase "$*" in\n' + cases + '\n  *) ;;\nesac\nexec "$SHIM_DIR/docker-base" "$@"\n'
    )
    wrapper.chmod(0o755)


def crontab_text(sb: Sandbox) -> str:
    path = sb.shim / "crontab.txt"
    return path.read_text() if path.exists() else ""


@pytest.fixture
def psb(sandbox: Sandbox) -> Sandbox:
    add_participant_files(sandbox)
    return sandbox


def p_dry_run(
    sb: Sandbox, *extra: str, out: str = "out.env", sensors: str = "ssh,web"
) -> tuple[Path, int, str]:
    target = sb.root / out
    proc = sb.run(
        "scripts/install.sh",
        "--participant",
        "--yes",
        "--dry-run",
        "--env-out",
        str(target),
        "--sensors",
        sensors,
        *extra,
    )
    return target, proc.returncode, proc.stdout + proc.stderr


def p_real(sb: Sandbox, *extra: str) -> tuple[int, str]:
    proc = sb.run(
        "scripts/install.sh",
        "--participant",
        "--yes",
        "--version",
        "v0.8.0",
        "--sensors",
        "ssh,web",
        *extra,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_participant_dry_run_writes_the_participant_env(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = p_dry_run(psb)
    assert rc == 0, out
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    env = parse_env(target)
    assert env["SUCKERPOT_STACK_MODE"] == "participant"
    assert env["COMPOSE_PROFILES"] == "direct"
    assert env["COMPOSE_FILE"] == "docker-compose.yml:docker-compose.participant.yml"
    assert env["EGRESS_MODE"] == "direct"
    assert env["EGRESS_PROXY_URL"] == "http://hubproxy:8888"
    assert env["EGRESS_CONTROL_URL"] == "http://hubproxy:8000"
    assert env["HUBPROXY_ALLOW"] == "suckerpot-hub.selfhostr.io:443"
    assert env["NETWORK_ENABLED"] == "true"
    assert re.fullmatch(
        r"v2:sources,payloads,c2,files,rechecks,verify_reveals:\d{4}-\d\d-\d\d",
        env["NETWORK_CONSENT"],
    )
    assert re.fullmatch(r"[a-z]+-[a-z]+-\d\d", env["NETWORK_PSEUDONYM"])
    assert env["SELF_TERMS_AUTO_CONFIRM"] == "true"
    assert env["NETWORK_VERIFY_REVEALS"] == "true"
    assert env["DB_MAX_SIZE_GB"] == "4"
    assert env["AUTO_UPDATE_ENABLED"] == "true"
    assert env["SENSOR_SSH"] == "1"
    assert env["SENSOR_TELNET"] == "0"
    # The hub address and key are not copied: ingest reads the defaults baked into the image.
    assert "NETWORK_HUB_URL" not in env
    assert "NETWORK_HUB_KEY" not in env
    assert "NETWORK_VERIFIER" not in env
    # The base file's required values hold inert placeholders; the dashboard never starts.
    assert re.fullmatch(
        r"'\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9]{22}\$[A-Za-z0-9]{43}'",
        env["ADMIN_PASSWORD_HASH"],
    )
    assert len(env["SESSION_SECRET"]) >= 64
    for name in SECRET_NAMES:
        assert len(env[name]) >= 24, name
    assert psb.docker_calls() == []
    assert "crontab" not in "\n".join(psb.calls())


def test_participant_placeholders_differ_between_runs(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    a, _, _ = p_dry_run(psb, out="a.env")
    b, _, _ = p_dry_run(psb, out="b.env")
    env_a, env_b = parse_env(a), parse_env(b)
    assert env_a["ADMIN_PASSWORD_HASH"] != env_b["ADMIN_PASSWORD_HASH"]
    assert env_a["SESSION_SECRET"] != env_b["SESSION_SECRET"]


def test_participant_prints_the_consent_screen_with_the_vpn_truth(psb: Sandbox) -> None:
    _, rc, out = p_dry_run(psb)
    assert rc == 0, out
    assert "SuckerPot participant mode" in out
    assert "Without a VPN that address" in out
    assert "this machine's own public address" in out
    assert "./scripts/participant.sh vpn <file.conf>" in out
    assert "./scripts/participant.sh leave" in out
    assert "--yes was given" in out
    assert "Never sent: passwords, commands" in out
    assert "Cloudflare" in out
    assert "What you get back today: nothing yet" in out


def test_participant_pseudonym_override_and_none(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = p_dry_run(
        psb, "--pseudonym", "Grey Heron 7", "--country", "ch", "--show-country"
    )
    assert rc == 0, out
    env = parse_env(target)
    assert env["NETWORK_PSEUDONYM"] == "'Grey Heron 7'"
    assert env["NETWORK_COUNTRY"] == "CH"
    assert env["NETWORK_SHOW_COUNTRY"] == "true"
    target, rc, out = p_dry_run(psb, "--no-pseudonym", out="n.env")
    assert rc == 0, out
    env = parse_env(target)
    assert env["NETWORK_PSEUDONYM"] == ""
    assert "Pseudonym: none" in out
    assert "NETWORK_COUNTRY" not in env


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--pseudonym", "admin"], "reserved"),
        (["--pseudonym", "ab"], "3 to 24"),
        (["--pseudonym", "has 1234 run"], "four digits"),
        (["--pseudonym", "my-selfhostr-box"], "project name"),
        (["--pseudonym", "x1", "--no-pseudonym"], "exclude"),
        (["--country", "CHE"], "two-letter"),
        (["--show-country"], "--country"),
        (["--verifier"], "--wg-conf"),
        (["--self-address", "not an address"], "unexpected characters"),
        (["--dashboard-port", "9000"], "need --full"),
        (["--public-host", "dash.example.org"], "need --full"),
        (["--admin-user", "bob"], "need --full"),
        (["--admin-password-stdin"], "need --full"),
        (["--allow-lan"], "need --full"),
        (["--dashboard-bind", "127.0.0.1"], "need --full"),
        (["--full"], "exclude each other"),
    ],
)
def test_participant_refuses_bad_flag_combinations(
    psb: Sandbox, args: list[str], message: str
) -> None:
    target, rc, out = p_dry_run(psb, *args)
    assert rc != 0, out
    assert message in out
    assert not target.exists()


def test_participant_only_flags_need_participant_mode(psb: Sandbox) -> None:
    cases = [
        ["--pseudonym", "x1"],
        ["--no-pseudonym"],
        ["--feeds"],
        ["--no-auto-update"],
        ["--verifier"],
    ]
    for i, args in enumerate(cases):
        target, rc, out = dry_run(psb, *args, out=f"f{i}.env")
        assert rc != 0, (args, out)
        assert "need --participant" in out
        assert not target.exists()


def test_participant_with_a_vpn_file(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    conf = psb.root / "wg.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 198.51.100.2/32\n"
        "[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        "Endpoint = 198.51.100.7:51820\n"
    )
    target, rc, out = p_dry_run(psb, "--wg-conf", str(conf), "--verifier")
    assert rc == 0, out
    env = parse_env(target)
    assert env["COMPOSE_PROFILES"] == "egress"
    assert env["EGRESS_MODE"] == "vpn"
    assert env["EGRESS_PROXY_URL"] == "http://vpn:8888"
    assert env["VPN_WG_ENDPOINT_IP"] == "198.51.100.7"
    assert env["NETWORK_VERIFIER"] == "true"
    assert env["COLLECTOR_ENABLED"] == "true"
    assert env["COLLECTOR_VERIFY_ENABLED"] == "true"
    assert "HUBPROXY_ALLOW" not in env
    assert "All of it leaves through your VPN" in out
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" not in out


def test_participant_feeds_widen_the_allow_list(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = p_dry_run(psb, "--feeds", "--self-address", "203.0.113.9")
    assert rc == 0, out
    env = parse_env(target)
    assert (
        env["HUBPROXY_ALLOW"] == "suckerpot-hub.selfhostr.io:443,suckerpot-feeds.selfhostr.io:443"
    )
    assert env["NETWORK_FEED_ENABLED"] == "true"
    assert env["SELF_ADDRESS"] == "203.0.113.9"
    assert env["INDICATORS_IGNORE"] == "203.0.113.9"


def test_participant_consent_prompt_declined_installs_nothing(psb: Sandbox) -> None:
    answers = psb.root / "answers"
    answers.write_text("n\n")
    proc = psb.run(
        "scripts/install.sh",
        "--participant",
        "--dry-run",
        "--env-out",
        str(psb.root / "o.env"),
        extra_env={"SELFHOSTR_TTY": str(answers)},
    )
    assert proc.returncode == 1
    assert "Join the SuckerPot network as described? [y/N]" in proc.stderr
    assert "Not joined" in proc.stderr
    assert not (psb.root / "o.env").exists()
    assert psb.docker_calls() == []


def test_participant_consent_prompt_accepted_is_the_only_question(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    answers = psb.root / "answers"
    answers.write_text("y\n")
    target = psb.root / "o.env"
    proc = psb.run(
        "scripts/install.sh",
        "--participant",
        "--dry-run",
        "--env-out",
        str(target),
        extra_env={"SELFHOSTR_TTY": str(answers)},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.count("[y/N]") == 1
    assert "--yes was given" not in proc.stdout
    env = parse_env(target)
    assert env["SENSOR_SSH"] == "1"
    assert env["SENSOR_REDIS"] == "1"  # the recommended sensors
    assert env["SENSOR_RDP"] == "0"


def test_participant_install_with_fake_docker(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    env = parse_env(psb.root / ".env")
    assert stat.S_IMODE((psb.root / ".env").stat().st_mode) == 0o600
    calls = "\n".join(psb.calls())
    # Verified before it runs, no api image, no admin hash, no dashboard check.
    assert "api.hashpw" not in calls
    assert "healthz" not in calls
    assert "docker compose up -d --no-build --pull never --wait --wait-timeout 600" in calls
    assert "docker volume create suckerpot_vpn-config" in calls
    assert "docker pull --quiet ghcr.io/selfhostr/suckerpot-ingest@sha256:" in calls
    # Nothing secret leaves the .env, the log or the screen.
    log = (psb.root / "install.log").read_text()
    for name in SECRET_NAMES:
        assert env[name] not in calls
        assert env[name] not in out
        assert env[name] not in log
    assert env["ADMIN_PASSWORD_HASH"] not in out
    # Done screen: the ports, the status command, the schedule.
    assert "SuckerPot is running in participant mode (v0.8.0)." in out
    assert f"Pseudonym: {env['NETWORK_PSEUDONYM']}" in out
    assert "Path: direct (no VPN)" in out
    assert re.search(r"22\s+->\s+22\s+TCP\s+ssh", out)
    assert re.search(r"443\s+->\s+443\s+TCP\s+web", out)
    assert "./scripts/status.sh" in out
    assert "22222" not in out
    assert "8443" not in out
    # Scheduled once, with the marker, at a random time between 03:00 and 05:59.
    cron = [line for line in crontab_text(psb).splitlines() if "selfhostr-auto-update" in line]
    assert len(cron) == 1
    minute, hour = cron[0].split()[:2]
    assert 3 <= int(hour) <= 5
    assert 0 <= int(minute) <= 59
    assert cron[0].endswith("# selfhostr-auto-update suckerpot")
    assert f"daily at 0{hour}:{int(minute):02d} local time" in out


def test_participant_no_auto_update_schedules_nothing(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = p_real(psb, "--no-auto-update")
    assert rc == 0, out
    assert parse_env(psb.root / ".env")["AUTO_UPDATE_ENABLED"] == "false"
    assert crontab_text(psb) == ""
    assert "Automatic updates:      off" in out


def test_participant_source_install_keeps_auto_update_off(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    proc = psb.run("scripts/install.sh", "--participant", "--yes", "--source", "--sensors", "ssh")
    assert proc.returncode == 0, proc.stderr
    assert parse_env(psb.root / ".env")["AUTO_UPDATE_ENABLED"] == "false"
    assert crontab_text(psb) == ""
    calls = "\n".join(psb.calls())
    assert "docker compose up -d --build --wait --wait-timeout 900" in calls
    assert "docker build" not in calls  # nothing to hash: there is no admin account


def test_participant_busy_port_22_maps_ssh_to_2222_without_asking(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    (psb.shim / "ss-output").write_text("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
    rc, out = p_real(psb)
    assert rc == 0, out
    env = parse_env(psb.root / ".env")
    assert env["SSH_HOST_PORT"] == "2222"
    assert env["ADMIN_SSH_PORT"] == "22"
    assert re.search(r"22\s+->\s+2222\s+TCP\s+ssh", out)
    assert "Never forward your admin SSH port (22 on this machine)." in out


def test_participant_low_memory_adds_the_lowmem_overlay_in_order(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    (psb.root / "docker-compose.lowmem.yml").write_text("services: {}\n")
    (psb.shim / "meminfo").write_text("MemTotal:        4000000 kB\n")
    rc, out = p_real(psb)
    assert rc == 0, out
    env = parse_env(psb.root / ".env")
    assert env["COMPOSE_FILE"] == (
        "docker-compose.yml:docker-compose.lowmem.yml:docker-compose.participant.yml"
    )


def test_participant_second_run_changes_nothing(psb: Sandbox) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    before = (psb.root / ".env").read_text()
    ups = [c for c in psb.docker_calls() if c.startswith("docker compose up")]
    rc, out = p_real(psb)
    assert rc == 0, out
    assert "already installed here in participant mode" in out
    assert (psb.root / ".env").read_text() == before
    assert [c for c in psb.docker_calls() if c.startswith("docker compose up")] == ups
    assert len(crontab_text(psb).splitlines()) == 1


def test_participant_repair_runs_the_start_and_schedule_steps_only(psb: Sandbox) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    before = (psb.root / ".env").read_text()
    cron_before = crontab_text(psb)
    start = len(psb.calls())
    proc = psb.run("scripts/install.sh", "--repair", "--yes")
    assert proc.returncode == 0, proc.stderr
    assert "repaired and running in participant mode" in proc.stdout
    assert (psb.root / ".env").read_text() == before
    assert crontab_text(psb) == cron_before  # the same time, not a new one
    new = psb.calls()[start:]
    assert any(c.startswith("docker compose up") for c in new)
    assert not any("api.hashpw" in c for c in new)


def test_repair_needs_an_install(psb: Sandbox) -> None:
    proc = psb.run("scripts/install.sh", "--repair", "--yes")
    assert proc.returncode != 0
    assert "needs an existing install" in proc.stderr


def test_a_full_install_is_never_switched_to_participant(psb: Sandbox) -> None:
    rc, out = _real_run(psb)
    assert rc == 0, out
    before = (psb.root / ".env").read_text()
    proc = psb.run("scripts/install.sh", "--participant", "--yes")
    assert proc.returncode != 0
    assert "would remove the dashboard; not supported" in proc.stderr
    assert (psb.root / ".env").read_text() == before


def test_a_full_install_writes_no_participant_settings(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    env = parse_env(sandbox.root / ".env")
    for name in (
        "SUCKERPOT_STACK_MODE",
        "HUBPROXY_ALLOW",
        "EGRESS_MODE",
        "AUTO_UPDATE_ENABLED",
        "SELF_TERMS_AUTO_CONFIRM",
    ):
        assert name not in env, name
    assert env["COMPOSE_PROFILES"] == "egress"
    assert "COMPOSE_FILE" not in env
    assert "crontab" not in "\n".join(sandbox.calls())


def test_participant_to_full_switch_keeps_the_data_and_the_secrets(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    old = parse_env(psb.root / ".env")
    cron = crontab_text(psb)
    start = len(psb.calls())
    proc = psb.run(
        "scripts/install.sh",
        "--full",
        "--yes",
        "--admin-password-stdin",
        "--admin-user",
        "owner",
        stdin=PASSWORD + "\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    new = parse_env(psb.root / ".env")
    assert new["SUCKERPOT_STACK_MODE"] == "full"
    assert new["COMPOSE_FILE"] == "docker-compose.yml"
    assert new["COMPOSE_PROFILES"] == "egress"
    assert new["EGRESS_MODE"] == "vpn"
    assert new["EGRESS_PROXY_URL"] == "http://vpn:8888"
    assert new["EGRESS_CONTROL_URL"] == "http://vpn:8000"
    assert "HUBPROXY_ALLOW" not in new
    assert new["SELF_TERMS_AUTO_CONFIRM"] == "false"
    assert new["ADMIN_USERNAME"] == "owner"
    assert new["ADMIN_PASSWORD_HASH"] != old["ADMIN_PASSWORD_HASH"]
    assert new["DASHBOARD_BIND"] == "127.0.0.1"
    # Kept: every secret, the volumes, the sensors, the membership and the update choice.
    for name in SECRET_NAMES:
        assert new[name] == old[name], name
    for name in (
        "SUCKERPOT_VOLUME_PREFIX",
        "COMPOSE_PROJECT_NAME",
        "SENSOR_SSH",
        "SENSOR_WEB",
        "NETWORK_ENABLED",
        "NETWORK_CONSENT",
        "NETWORK_PSEUDONYM",
        "AUTO_UPDATE_ENABLED",
    ):
        assert new[name] == old[name], name
    assert crontab_text(psb) == cron
    bak = psb.root / ".env.participant.bak"
    assert bak.read_text().count("SUCKERPOT_STACK_MODE=participant") == 1
    assert stat.S_IMODE(bak.stat().st_mode) == 0o600
    calls = psb.calls()[start:]
    backup = next(i for i, c in enumerate(calls) if "backup-service.sh now preswitch" in c)
    up = next(i for i, c in enumerate(calls) if c.startswith("docker compose up"))
    assert backup < up
    assert "docker compose --profile direct rm -sf hubproxy" in calls
    assert "--remove-orphans" in calls[up]
    assert not any("volume rm" in c for c in calls)
    assert PASSWORD not in "\n".join(calls) + proc.stdout + proc.stderr
    assert "Switched from participant mode to full mode" in proc.stdout
    assert "Dashboard: http://127.0.0.1:8443" in proc.stdout


def test_switch_declining_automatic_updates_removes_the_schedule(psb: Sandbox) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    assert crontab_text(psb).strip() != ""
    answers = psb.root / "answers"
    # access, admin user, password x2, keep automatic updates
    answers.write_text("l\nadmin\n" + PASSWORD + "\n" + PASSWORD + "\nno\n")
    proc = psb.run("scripts/install.sh", "--full", extra_env={"SELFHOSTR_TTY": str(answers)})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert crontab_text(psb).strip() == ""
    assert "AUTO_UPDATE_ENABLED=false" in (psb.root / ".env").read_text()


def test_a_failed_backup_leaves_the_participant_env_as_it_was(psb: Sandbox) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    before = (psb.root / ".env").read_text()
    wrap_docker(psb, '  *"now preswitch") echo "docker $*" >> "$SHIM_LOG"; exit 1 ;;')
    proc = psb.run(
        "scripts/install.sh", "--full", "--yes", "--admin-password-stdin", stdin=PASSWORD + "\n"
    )
    assert proc.returncode != 0
    assert "backup before the switch failed" in proc.stderr
    assert (psb.root / ".env").read_text() == before
    assert not (psb.root / ".env.tmp").exists()


def test_existing_install_refuses_settings_flags(psb: Sandbox) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    for args in (
        ["--sensors", "all"],
        ["--version", "v0.9.0"],
        ["--project", "other"],
        ["--source"],
    ):
        proc = psb.run("scripts/install.sh", "--participant", "--repair", "--yes", *args)
        assert proc.returncode != 0, args
        assert "keeps its settings" in proc.stderr


def test_participant_refuses_a_throwaway_project_name(psb: Sandbox) -> None:
    target, rc, out = p_dry_run(psb, "--project", "sp-test")
    assert rc != 0
    assert "bad project name" in out
    assert not target.exists()


def test_participant_scripts_make_no_http_calls_and_look_up_no_address() -> None:
    for rel in (
        "scripts/participant.sh",
        "scripts/status.sh",
        "scripts/check-participant.sh",
        "scripts/lib/pseudonym.sh",
    ):
        lines = (ROOT / rel).read_text().splitlines()
        code = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
        assert not re.search(r"\b(curl|wget|ipify|icanhazip|ifconfig\.me)\b", code), rel


# --------------------------------------------------------------------- the network question (M33)


def test_full_install_joins_the_network_with_the_explicit_flag(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(sandbox, "--join-network")
    assert rc == 0, out
    env = parse_env(target)
    assert env["NETWORK_ENABLED"] == "true"
    # Full mode agrees to the five required items; early reveals stay a separate choice.
    assert re.fullmatch(
        r"v2:sources,payloads,c2,files,rechecks:\d{4}-\d\d-\d\d", env["NETWORK_CONSENT"]
    )
    assert re.fullmatch(r"[a-z]+-[a-z]+-\d\d", env["NETWORK_PSEUDONYM"])
    # Full mode keeps its rules: the VPN is the only way out, the own address is not auto-confirmed.
    assert "SELF_TERMS_AUTO_CONFIRM" not in env
    assert "NETWORK_VERIFY_REVEALS" not in env
    assert env["COMPOSE_PROFILES"] == "egress"
    assert "EGRESS_MODE" not in env and "HUBPROXY_ALLOW" not in env
    assert "--join-network was given" in out
    assert "your VPN exit address" in out
    assert env["NETWORK_PSEUDONYM"] in out
    assert "Join the SuckerPot network?" not in out  # the flag is the answer: no prompt


def test_yes_alone_never_joins_the_network(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(sandbox)
    assert rc == 0, out
    env = parse_env(target)
    for name in ("NETWORK_CONSENT", "NETWORK_PSEUDONYM", "NETWORK_ENABLED"):
        assert name not in env, name
    assert "--yes does not join it" in out


def test_join_network_and_no_network_exclude_each_other(sandbox: Sandbox) -> None:
    _, rc, out = dry_run(sandbox, "--join-network", "--no-network")
    assert rc != 0 and "exclude each other" in out


def test_join_network_is_a_full_mode_flag(psb: Sandbox) -> None:
    _, rc, out = p_dry_run(psb, "--join-network")
    assert rc != 0 and "--join-network" in out


def test_no_network_declines_and_writes_no_consent(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(sandbox, "--no-network")
    assert rc == 0, out
    env = parse_env(target)
    for name in ("NETWORK_CONSENT", "NETWORK_PSEUDONYM", "NETWORK_ENABLED"):
        assert name not in env, name
    assert "The SuckerPot network" not in out


def _interactive(sandbox: Sandbox, network_answer: str) -> tuple[Path, int, str]:
    answers = sandbox.root / "answers"
    answers.write_text(
        "images\nssh,web\nl\nowner\n" + PASSWORD + "\n" + PASSWORD + "\n\n\n\n" + network_answer
    )
    target = sandbox.root / "i.env"
    proc = sandbox.run(
        "scripts/install.sh",
        "--dry-run",
        "--env-out",
        str(target),
        extra_env={"SELFHOSTR_TTY": str(answers)},
    )
    return target, proc.returncode, proc.stdout + proc.stderr


@pytest.mark.parametrize("answer", ["y\n", "Y\n", "yes\n"])
def test_a_typed_yes_joins_the_network(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]], answer: str
) -> None:
    target, rc, out = _interactive(sandbox, answer)
    assert rc == 0, out
    assert "Join the SuckerPot network? [y/N]" in out
    assert parse_env(target)["NETWORK_CONSENT"].startswith("v2:sources,payloads,c2,files,rechecks:")


@pytest.mark.parametrize("answer", ["\n", "n\n", "N\n", "no\n"])
def test_an_empty_or_no_answer_does_not_join_the_network(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]], answer: str
) -> None:
    target, rc, out = _interactive(sandbox, answer)
    assert rc == 0, out
    env = parse_env(target)
    assert "NETWORK_CONSENT" not in env and "NETWORK_PSEUDONYM" not in env


def test_a_garbled_network_answer_is_refused(sandbox: Sandbox) -> None:
    _, rc, out = _interactive(sandbox, "maybe\n")
    assert rc != 0 and "answer y or n" in out


def test_end_of_input_is_not_a_yes_to_the_network_question(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = _interactive(sandbox, "")
    assert rc != 0 and "no answer to the network question" in out
    assert not target.exists() or "NETWORK_CONSENT" not in parse_env(target)


def test_the_consent_text_is_exact_about_the_vpn_and_the_address(sandbox: Sandbox) -> None:
    _, rc, out = dry_run(sandbox, "--join-network")
    assert rc == 0, out
    assert "nothing is sent at all" in out
    assert "address is confirmed" in out
    assert "Cloudflare" in out
    assert "What you get back today: nothing yet" in out
    assert "experimental preview" in out


def test_a_fresh_install_carries_the_network_default_marker(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(sandbox, "--no-network")
    assert rc == 0, out
    assert parse_env(target)["NETWORK_DEFAULT_PINNED"] == "1"


def test_no_network_is_a_full_mode_flag(psb: Sandbox) -> None:
    _, rc, out = p_dry_run(psb, "--no-network")
    assert rc != 0 and "--no-network" in out


# ------------------------------------------------------------ engine version and DMZ advice

ENGINE_SHIM = """#!/bin/sh
case "$*" in
  "version "*) echo "$SHIM_ENGINE" ;;
  *) exec "$(dirname "$0")/docker.real" "$@" ;;
esac
"""


def set_engine(sb: Sandbox, version: str) -> None:
    if not (sb.shim / "docker.real").exists():
        (sb.shim / "docker").rename(sb.shim / "docker.real")
        (sb.shim / "docker").write_text(ENGINE_SHIM)
        (sb.shim / "docker").chmod(0o755)
    sb.env["SHIM_ENGINE"] = version


@pytest.mark.parametrize(
    ("engine", "warned"), [("24.0.7", True), ("27.5.1", True), ("28.0.0", False), ("29.1.2", False)]
)
def test_engine_older_than_28_gets_a_warning_about_isolation(
    psb: Sandbox, engine: str, warned: bool
) -> None:
    set_engine(psb, engine)
    rc, out = p_real(psb)
    assert rc == 0, out
    assert ("NOT isolated from the host" in out) is warned
    if warned:
        assert "28 or newer is strongly recommended" in out


def test_engine_older_than_24_is_refused(psb: Sandbox) -> None:
    set_engine(psb, "23.0.6")
    rc, out = p_real(psb)
    assert rc != 0
    assert "Docker Engine 24 or newer is required" in out


def test_participant_summary_recommends_forwards_over_a_dmz(psb: Sandbox) -> None:
    set_engine(psb, "28.0.0")
    rc, out = p_real(psb)
    assert rc == 0, out
    assert "does not filter internet traffic to this" in out
    assert "Use port forwards, not your router's DMZ" in out
    assert "admin SSH faces the internet" in out


# --- M35: --lite -----------------------------------------------------------------------------


def _lite_run(sb: Sandbox, *extra: str) -> tuple[int, str]:
    proc = sb.run("scripts/install.sh", "--participant", "--yes", "--version", "v0.8.0", *extra)
    return proc.returncode, proc.stdout + proc.stderr


def _with_overlays(sb: Sandbox, mem_kb: int) -> None:
    (sb.root / "docker-compose.lowmem.yml").write_text("services: {}\n")
    (sb.root / "docker-compose.lite.yml").write_text("services: {}\n")
    (sb.shim / "meminfo").write_text(f"MemTotal:        {mem_kb} kB\n")


def test_participant_lite_stacks_the_overlays_and_picks_four_sensors(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    _with_overlays(psb, 990000)
    rc, out = _lite_run(psb, "--lite")
    assert rc == 0, out
    env = parse_env(psb.root / ".env")
    assert env["COMPOSE_FILE"] == (
        "docker-compose.yml:docker-compose.lowmem.yml:docker-compose.lite.yml"
        ":docker-compose.participant.yml"
    )
    names = ("ssh", "telnet", "web", "redis", "docker", "adb", "rdp")
    on = {s for s in names if env[f"SENSOR_{s.upper()}"] == "1"}
    assert on == {"ssh", "telnet", "web", "redis"}


def test_participant_lite_keeps_an_explicit_sensor_list(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    _with_overlays(psb, 990000)
    rc, out = _lite_run(psb, "--lite", "--sensors", "ssh,adb")
    assert rc == 0, out
    env = parse_env(psb.root / ".env")
    assert env["SENSOR_ADB"] == "1" and env["SENSOR_WEB"] == "0"


def test_lite_refuses_lowmem_off(psb: Sandbox) -> None:
    _with_overlays(psb, 990000)
    rc, out = _lite_run(psb, "--lite", "--lowmem", "off")
    assert rc != 0 and "--lite" in out


def test_lite_refuses_less_than_one_gib(psb: Sandbox) -> None:
    _with_overlays(psb, 500000)
    rc, out = _lite_run(psb, "--lite")
    assert rc != 0 and "1 GiB" in out


def test_lite_is_a_participant_flag(sandbox: Sandbox) -> None:
    proc = sandbox.run("scripts/install.sh", "--yes", "--lite", "--dry-run", "--env-out", "x")
    assert proc.returncode != 0 and "--participant" in proc.stdout + proc.stderr


def test_default_participant_install_still_needs_two_gib(psb: Sandbox) -> None:
    _with_overlays(psb, 990000)
    rc, out = _lite_run(psb, "--sensors", "ssh,web")
    assert rc != 0 and "2 GiB" in out


def _lite_install(psb: Sandbox, swap_kb: int | None = 2000000) -> None:
    _with_overlays(psb, 990000)
    swap = "" if swap_kb is None else f"SwapTotal:       {swap_kb} kB\n"
    (psb.shim / "meminfo").write_text("MemTotal:        990000 kB\n" + swap)
    rc, out = _lite_run(psb, "--lite")
    assert rc == 0, out


def test_lite_node_cannot_switch_to_full(psb: Sandbox) -> None:
    _lite_install(psb)
    before = (psb.root / ".env").read_text()
    proc = psb.run(
        "scripts/install.sh", "--full", "--yes", "--admin-password-stdin", stdin=PASSWORD + "\n"
    )
    assert proc.returncode != 0
    assert "lite node cannot switch to full mode" in proc.stdout + proc.stderr
    assert (psb.root / ".env").read_text() == before


def test_switch_to_full_checks_the_memory(psb: Sandbox) -> None:
    rc, out = p_real(psb)
    assert rc == 0, out
    (psb.shim / "meminfo").write_text("MemTotal:        990000 kB\n")
    proc = psb.run(
        "scripts/install.sh", "--full", "--yes", "--admin-password-stdin", stdin=PASSWORD + "\n"
    )
    assert proc.returncode != 0 and "2 GiB" in proc.stdout + proc.stderr


def test_lite_without_swap_warns(psb: Sandbox) -> None:
    _with_overlays(psb, 990000)
    (psb.shim / "meminfo").write_text("MemTotal:        990000 kB\nSwapTotal:       100000 kB\n")
    rc, out = _lite_run(psb, "--lite")
    assert rc == 0, out
    assert "less than 512 MiB of swap" in out


def test_lite_with_swap_does_not_warn(psb: Sandbox) -> None:
    _with_overlays(psb, 990000)
    (psb.shim / "meminfo").write_text("MemTotal:        990000 kB\nSwapTotal:      1048576 kB\n")
    rc, out = _lite_run(psb, "--lite")
    assert rc == 0, out
    assert "of swap" not in out


def test_admin_ssh_port_defaults_from_sshd_when_22_is_free(
    psb: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    for name, body in (("systemctl", "exit 1\n"), ("sshd", "echo 'port 52022'\n")):
        shim = psb.shim / name
        shim.write_text("#!/bin/sh\n" + body)
        shim.chmod(0o755)
    rc, out = p_real(psb)
    assert rc == 0, out
    assert parse_env(psb.root / ".env")["ADMIN_SSH_PORT"] == "52022"
