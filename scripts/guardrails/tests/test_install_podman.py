"""install.sh on Podman (docs/dev/design/podman.md phase 3, installer UI phase D).

Fakes only: podman, docker-compose, systemctl, sudo and the host scripts that need root are shims
that record their calls. The real runs are described in the pull request that added this file.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import Sandbox
from test_engine import CAPABLE_COMPOSE, CAPABLE_PODMAN
from test_install import add_participant_files

SOCK = "unix:///run/podman/podman.sock"
SYSTEMCTL = r"""#!/bin/sh
echo "systemctl $*" >> "$SHIM_LOG"
case "$*" in
  "is-active --quiet docker.service" | "is-active --quiet docker.socket") exit "${SHIM_DOCKER_ACTIVE:-3}" ;;
  is-active*) exit 3 ;;
esac
exit 0
"""
PODMAN = CAPABLE_PODMAN.replace(
    "esac\nexit 0\n",
    '  *) shift 2; exec env SHIM_LOG=/dev/null "$SHIM_DIR/docker-real" "$@" ;;\nesac\nexit 0\n',
)
SUDO = '#!/bin/sh\necho "sudo $*" >> "$SHIM_LOG"\nexit 0\n'
RECORD = '#!/bin/sh\necho "{name} $*" >> "$SHIM_LOG"\nexit 0\n'


def _podman_host(sb: Sandbox, *, docker: bool = False) -> None:
    """A capable Podman host. Without `docker`, the docker command is gone from PATH."""
    add_participant_files(sb)
    # podman: the capable answers for the host checks, everything else as the fake docker does.
    (sb.shim / "docker-real").write_text((sb.shim / "docker").read_text())
    (sb.shim / "docker-real").chmod(0o755)
    for name, text in (
        ("podman", PODMAN),
        ("docker-compose", CAPABLE_COMPOSE),
        ("systemctl", SYSTEMCTL),
        ("sudo", SUDO),
    ):
        (sb.shim / name).write_text(text)
        (sb.shim / name).chmod(0o755)
    if not docker:
        (sb.shim / "docker").unlink()
        tools = sb.shim.parent / "tools"
        tools.mkdir(exist_ok=True)
        for d in ("/usr/bin", "/bin"):
            for entry in sorted(Path(d).iterdir()) if os.path.isdir(d) else []:
                link = tools / entry.name
                if entry.name in ("docker", "podman", "docker-compose", "sudo", "systemctl"):
                    continue
                if not os.path.lexists(link):
                    link.symlink_to(entry)
        sb.env["PATH"] = f"{sb.shim}:{tools}"
    for rel, name in (
        ("scripts/host/install-stack-unit.sh", "install-stack-unit"),
        ("scripts/ensure-networks.sh", "ensure-networks"),
    ):
        path = sb.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(RECORD.format(name=name))
        path.chmod(0o755)
    conf = sb.shim.parent / "confroot"
    (conf / "etc/containers/containers.conf.d").mkdir(parents=True, exist_ok=True)
    # A packaged Podman: its socket unit exists.
    (conf / "usr/lib/systemd/system").mkdir(parents=True, exist_ok=True)
    (conf / "usr/lib/systemd/system/podman.socket").write_text("[Socket]\n")
    sb.env["SUCKERPOT_CONF_ROOT"] = str(conf)
    sb.env["SUCKERPOT_UNIT_ROOT"] = str(sb.shim.parent / "unitroot")
    sb.env["SUCKERPOT_ENROL_WAIT"] = "0"


def _install(sb: Sandbox, *args: str) -> tuple[int, str]:
    proc = sb.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh,web", *args),
    )
    return proc.returncode, proc.stdout + proc.stderr


def _env(sb: Sandbox) -> dict[str, str]:
    out = {}
    for line in (sb.root / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v
    return out


def test_a_podman_only_host_installs_on_podman_without_a_question(sandbox: Sandbox) -> None:
    _podman_host(sandbox)
    rc, out = _install(sandbox)
    assert rc == 0, out
    env = _env(sandbox)
    assert env["SUCKERPOT_ENGINE"] == "podman"
    assert env["COMPOSE_FILE"].endswith(":docker-compose.participant.yml:docker-compose.podman.yml")
    assert "Choose 1 or 2" not in out
    assert "Podman support is experimental" in out
    calls = sandbox.calls()
    # The firewall (required) and the boot unit come before the start, which goes through the
    # network step; never `docker compose`.
    fw = next(i for i, c in enumerate(calls) if c.startswith("install-firewall "))
    unit = next(i for i, c in enumerate(calls) if c.startswith("install-stack-unit "))
    nets = next(i for i, c in enumerate(calls) if c.startswith("ensure-networks"))
    up = next(i for i, c in enumerate(calls) if c.startswith("docker-compose up -d --no-build"))
    assert fw < unit < nets < up
    assert f"DOCKER_HOST={SOCK}" in calls[up]
    assert not [c for c in calls if c.startswith("docker ")]
    rendered = (sandbox.root / ".suckerpot-state/host-firewall.nft").read_text()
    assert "table bridge suckerpot_bridge" in rendered
    assert "result: ok type=participant version=v0.8.0 engine=podman" in out


def test_podman_refuses_without_sudo_for_the_firewall(sandbox: Sandbox) -> None:
    _podman_host(sandbox)
    (sandbox.shim / "sudo").write_text("#!/bin/sh\nexit 1\n")
    rc, out = _install(sandbox)
    assert rc == 1
    assert "on Podman the host firewall is required" in out
    assert not [c for c in sandbox.calls() if c.startswith("docker-compose up")]


def test_podman_no_firewall_installs_the_unit_without_it(sandbox: Sandbox) -> None:
    _podman_host(sandbox)
    rc, out = _install(sandbox, "--no-firewall")
    assert rc == 0, out
    calls = sandbox.calls()
    assert not [c for c in calls if c.startswith("install-firewall")]
    assert [c for c in calls if c.startswith("install-stack-unit --no-firewall ")]
    assert _env(sandbox)["SUCKERPOT_NO_FIREWALL"] == "1"


def test_old_podman_is_refused_with_the_reason(sandbox: Sandbox) -> None:
    _podman_host(sandbox)
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--version", "v0.8.0"),
        extra_env={"SHIM_PODMAN_INFO": "4.9.3 netavark v2 false"},
    )
    assert proc.returncode == 1
    assert "this host does not meet the Podman requirements: Podman 4.9.3 is too old" in (
        proc.stdout + proc.stderr
    )
    assert not (sandbox.root / ".env").exists()


def test_source_mode_is_refused_on_podman(sandbox: Sandbox) -> None:
    _podman_host(sandbox)
    rc, out = _install(sandbox, "--source")
    assert rc == 1
    assert "--source is not supported on Podman" in out


# ------------------------------------------------------------------ the engine choice (phase D)


def _dry(sb: Sandbox, *args: str, **env: str) -> dict[str, str]:
    out = sb.root / "out.env"
    proc = sb.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--dry-run", "--env-out", str(out), *args),
        extra_env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    values = {}
    for line in out.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            values[k] = v
    return values


def test_both_engines_with_docker_active_use_docker(sandbox: Sandbox) -> None:
    _podman_host(sandbox, docker=True)
    env = _dry(sandbox, SHIM_DOCKER_ACTIVE="0")
    assert env["SUCKERPOT_ENGINE"] == "docker"
    assert "docker-compose.podman.yml" not in env.get("COMPOSE_FILE", "")


def test_both_engines_without_a_terminal_and_docker_off_use_podman(sandbox: Sandbox) -> None:
    """Fedora: docker-compose brings the docker command along; Docker is off, Podman is packaged."""
    _podman_host(sandbox, docker=True)
    env = _dry(sandbox)
    assert env["SUCKERPOT_ENGINE"] == "podman"


def test_a_podman_command_without_its_socket_unit_keeps_docker(sandbox: Sandbox) -> None:
    _podman_host(sandbox, docker=True)
    (Path(sandbox.env["SUCKERPOT_CONF_ROOT"]) / "usr/lib/systemd/system/podman.socket").unlink()
    env = _dry(sandbox)
    assert env["SUCKERPOT_ENGINE"] == "docker"


def _asked(sb: Sandbox, answer: str, **env: str) -> tuple[dict[str, str], str]:
    tty = sb.root / "answers"
    tty.write_text(answer)
    out = sb.root / "out.env"
    proc = sb.run(
        "scripts/install.sh",
        *("--full", "--dry-run", "--env-out", str(out)),
        extra_env={"SELFHOSTR_TTY": str(tty), **env},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    values = {}
    for line in out.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            values[k] = v
    return values, proc.stdout + proc.stderr


@pytest.mark.parametrize(
    ("answer", "engine"), [("2\n", "podman"), ("\n", "podman"), ("1\n", "docker")]
)
def test_both_engines_with_docker_stopped_ask_on_a_terminal(
    sandbox: Sandbox, answer: str, engine: str
) -> None:
    _podman_host(sandbox, docker=True)
    env, out = _asked(sandbox, answer)
    assert "are both installed. Docker is not active." in out
    assert "2  Podman   experimental; the host firewall is required" in out
    assert env["SUCKERPOT_ENGINE"] == engine
    assert ("docker-compose.podman.yml" in env.get("COMPOSE_FILE", "")) == (engine == "podman")


def test_both_engines_with_docker_active_never_ask(sandbox: Sandbox) -> None:
    _podman_host(sandbox, docker=True)
    env, out = _asked(sandbox, "2\n", SHIM_DOCKER_ACTIVE="0")
    assert "Choose 1 or 2" not in out
    assert env["SUCKERPOT_ENGINE"] == "docker"


@pytest.mark.parametrize("engine", ["docker", "podman"])
def test_the_engine_flag_wins(sandbox: Sandbox, engine: str) -> None:
    _podman_host(sandbox, docker=True)
    env = _dry(sandbox, "--engine", engine, SHIM_DOCKER_ACTIVE="0")
    assert env["SUCKERPOT_ENGINE"] == engine


def test_a_bad_engine_flag_is_refused(sandbox: Sandbox) -> None:
    proc = sandbox.run("scripts/install.sh", "--participant", "--yes", "--engine", "lxc")
    assert proc.returncode == 1
    assert "--engine must be docker or podman" in proc.stdout + proc.stderr


def test_a_docker_only_host_never_offers_podman(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    (sandbox.shim / "podman").unlink()
    env = _dry(sandbox)
    assert env["SUCKERPOT_ENGINE"] == "docker"
