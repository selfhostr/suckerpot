"""The host firewall step of the installer and of `participant.sh firewall`.

The loader (install-firewall.sh) is replaced by a stub: no test ever runs sudo, nft or systemctl.
"""

import stat
from pathlib import Path

import pytest
from conftest import Sandbox
from test_install import add_participant_files, p_real

STUB_LOADER = """#!/bin/sh
echo "install-firewall $*" >> "$SHIM_LOG"
exit "${SHIM_FW_RC:-0}"
"""
SYSTEMCTL_STUB = "#!/bin/sh\nexit 1\n"

ENV = """\
COMPOSE_PROJECT_NAME=demo
SUCKERPOT_VOLUME_PREFIX=demo
SUCKERPOT_STACK_MODE=participant
SUCKERPOT_INSTALL_MODE=images
ADMIN_SSH_PORT=2200
DASHBOARD_PORT=8443
"""
FILE = ".suckerpot-state/host-firewall.nft"


@pytest.fixture
def fsb(sandbox: Sandbox) -> Sandbox:
    add_participant_files(sandbox)
    loader = sandbox.root / "scripts/host/install-firewall.sh"
    loader.write_text(STUB_LOADER)
    loader.chmod(0o755)
    sysctl = sandbox.shim / "systemctl"
    sysctl.write_text(SYSTEMCTL_STUB)
    sysctl.chmod(0o755)
    sandbox.write_env(ENV)
    return sandbox


def answer(sb: Sandbox, text: str) -> dict[str, str]:
    path = sb.root / "answers"
    path.write_text(text)
    return {"SELFHOSTR_TTY": str(path)}


def loader_calls(sb: Sandbox) -> list[str]:
    return [c for c in sb.calls() if c.startswith("install-firewall")]


def test_yes_renders_privately_and_installs(fsb: Sandbox) -> None:
    proc = fsb.run("scripts/participant.sh", "firewall", extra_env=answer(fsb, "y\n"))
    assert proc.returncode == 0, proc.stderr
    assert "Admin SSH port used: 2200 (ADMIN_SSH_PORT in .env)" in proc.stdout
    assert "Install the host firewall now?" in proc.stderr
    assert loader_calls(fsb) == [f"install-firewall {FILE}"]
    rendered = fsb.root / FILE
    assert stat.S_IMODE(rendered.stat().st_mode) == 0o600
    assert "2200" in rendered.read_text()


def test_enter_means_yes_and_no_means_commands_to_run_later(fsb: Sandbox) -> None:
    assert (
        fsb.run("scripts/participant.sh", "firewall", extra_env=answer(fsb, "\n")).returncode == 0
    )
    assert len(loader_calls(fsb)) == 1
    fsb.log.write_text("")
    proc = fsb.run("scripts/participant.sh", "firewall", extra_env=answer(fsb, "n\n"))
    assert proc.returncode == 0
    assert loader_calls(fsb) == []
    assert "scripts/host/render-firewall.sh --participant --admin-ssh-port 2200" in proc.stdout
    assert f"scripts/host/install-firewall.sh {FILE}" in proc.stdout
    assert "stops a compromised sensor" in proc.stdout


def test_no_terminal_never_asks_and_never_fails(fsb: Sandbox) -> None:
    proc = fsb.run(
        "scripts/participant.sh", "firewall", extra_env={"SELFHOSTR_TTY": "/nonexistent/tty"}
    )
    assert proc.returncode == 0
    assert loader_calls(fsb) == []
    assert "Install the host firewall now?" not in proc.stderr
    assert f"scripts/host/install-firewall.sh {FILE}" in proc.stdout


@pytest.mark.parametrize("rc", ["3", "4", "5"])
def test_a_loader_failure_prints_the_commands_and_does_not_fail(fsb: Sandbox, rc: str) -> None:
    fsb.env["SHIM_FW_RC"] = rc
    proc = fsb.run("scripts/participant.sh", "firewall", extra_env=answer(fsb, "y\n"))
    assert proc.returncode == 0
    assert f"was not installed (exit {rc})" in proc.stdout
    assert f"scripts/host/install-firewall.sh {FILE}" in proc.stdout


def test_a_full_install_renders_the_full_ruleset_with_its_dashboard_port(fsb: Sandbox) -> None:
    fsb.write_env(ENV.replace("participant", "full").replace("8443", "9443"))
    proc = fsb.run("scripts/participant.sh", "firewall", extra_env=answer(fsb, "n\n"))
    assert proc.returncode == 0, proc.stderr
    assert "--full --admin-ssh-port 2200 --dashboard-port 9443" in proc.stdout
    assert "9443" in (fsb.root / FILE).read_text()


def test_uninstall_goes_to_the_loader(fsb: Sandbox) -> None:
    assert fsb.run("scripts/participant.sh", "firewall", "uninstall").returncode == 0
    assert loader_calls(fsb) == ["install-firewall --uninstall"]


def test_unknown_subcommand_is_a_usage_error(fsb: Sandbox) -> None:
    assert fsb.run("scripts/participant.sh", "firewall", "wipe").returncode != 0


def add_shims(sb: Sandbox, sudo_rc: int, uid: str = "1000") -> None:
    for name, text in {
        "sudo": f"#!/bin/sh\nexit {sudo_rc}\n",
        "id": f"#!/bin/sh\necho {uid}\n",
    }.items():
        path = sb.shim / name
        path.write_text(text)
        path.chmod(0o755)


def test_the_installer_with_yes_installs_when_sudo_needs_no_password(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    loader = sandbox.root / "scripts/host/install-firewall.sh"
    loader.write_text(STUB_LOADER)
    loader.chmod(0o755)
    add_shims(sandbox, 0)
    rc, out = p_real(sandbox)
    assert rc == 0, out
    assert [c for c in sandbox.calls() if c.startswith("install-firewall")] == [
        f"install-firewall {FILE}"
    ]
    assert "The host firewall is loaded" in out


def test_the_installer_with_yes_prints_one_command_when_sudo_asks(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    loader = sandbox.root / "scripts/host/install-firewall.sh"
    loader.write_text(STUB_LOADER)
    loader.chmod(0o755)
    add_shims(sandbox, 1)
    rc, out = p_real(sandbox)
    assert rc == 0, out
    assert not [c for c in sandbox.calls() if c.startswith("install-firewall")]
    assert "    ./scripts/participant.sh firewall" in out


def test_a_failing_loader_never_fails_the_install(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    loader = sandbox.root / "scripts/host/install-firewall.sh"
    loader.write_text(STUB_LOADER)
    loader.chmod(0o755)
    add_shims(sandbox, 0)
    sandbox.env["SHIM_FW_RC"] = "5"
    rc, out = p_real(sandbox)
    assert rc == 0, out
    assert "was not installed (exit 5)" in out


def test_the_installer_with_yes_does_not_load_without_sudo(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    add_shims(sandbox, 1)
    loader = sandbox.root / "scripts/host/install-firewall.sh"
    loader.write_text(STUB_LOADER)
    loader.chmod(0o755)
    rc, out = p_real(sandbox)
    assert rc == 0, out
    assert "Host firewall" in out
    assert "./scripts/participant.sh firewall" in out
    assert not [c for c in sandbox.calls() if c.startswith("install-firewall")]
    # The rendered file (it holds the admin port) is in the untracked state folder.
    assert Path(sandbox.root / FILE).exists()
