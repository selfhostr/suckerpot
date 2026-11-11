"""scripts/move-admin-ssh.sh: moves the admin SSH daemon without ever locking the user out.

The script runs in a scratch root (MOVE_SSH_ROOT) with fake `id`, `sshd`, `systemctl`, `ss`, `ufw`
and `sleep` first on PATH. The fakes keep a tiny model of the machine: a restart makes the
listeners match the files the script wrote, and the Nth call of `sleep` makes a login appear on
the new port. They never touch the real SSH daemon, and every call is recorded in a log.
"""

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import ROOT

SCRIPT = ROOT / "scripts/move-admin-ssh.sh"
MARK = "# move-admin-ssh.sh: managed file."
MARK_FULL = MARK + " Undo with: ./scripts/move-admin-ssh.sh --undo"

ID_SHIM = '#!/bin/sh\necho "id $*" >> "$SHIM_LOG"\necho "${SHIM_UID:-0}"\n'

# Effective ports from the files, like sshd -T: the main file, plus the drop-in folder when the
# main file includes it. No Port line at all means 22.
PORTS_FUNC = r"""
ports() {
  root=${MOVE_SSH_ROOT:-}
  cfg=$root/etc/ssh/sshd_config
  files=$cfg
  grep -Eiq '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$cfg" 2>/dev/null &&
    files="$cfg $(ls "$root"/etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
  p=$(cat $files 2>/dev/null | awk 'tolower($1) == "port" {print $2}' | sort -n | tr '\n' ' ')
  echo "${p:-22}"
}
"""

SSHD_SHIM = (
    '#!/bin/sh\necho "sshd $*" >> "$SHIM_LOG"\n'
    + PORTS_FUNC
    + r"""
case "$1" in
  -t)
    if [ -n "${SHIM_SSHD_T_FAIL:-}" ] && [ -e "$MOVE_SSH_ROOT/etc/ssh/sshd_config.d/10-admin-port.conf" ]; then
      echo "sshd: bad configuration" >&2
      exit 255
    fi ;;
  -T) for p in $(ports); do echo "port $p"; done ;;
esac
exit 0
"""
)

SYSTEMCTL_SHIM = (
    '#!/bin/sh\necho "systemctl $*" >> "$SHIM_LOG"\n'
    + PORTS_FUNC
    + r"""
restart() {
  if [ -n "${SHIM_ALL_FAIL:-}" ]; then : > "$SHIM_DIR/listen"; return 1; fi
  : > "$SHIM_DIR/listen"
  if [ -n "${SHIM_SOCKET:-}" ]; then
    ov="$MOVE_SSH_ROOT/etc/systemd/system/ssh.socket.d/override.conf"
    if [ -e "$ov" ]; then
      sed -n 's/^ListenStream=0\.0\.0\.0:\([0-9]*\)$/\1/p' "$ov" | while read -r p; do echo "$p systemd"; done > "$SHIM_DIR/listen"
    else
      echo "22 systemd" > "$SHIM_DIR/listen"
    fi
  else
    for p in $(ports); do echo "$p sshd"; done > "$SHIM_DIR/listen"
  fi
}
rc=0
case "$1 $2" in
  "cat ssh.service") [ -z "${SHIM_NO_UNIT:-}" ] || rc=1 ;;
  "is-enabled --quiet" | "is-active --quiet")
    { [ "$3" = ssh.socket ] && [ -n "${SHIM_SOCKET:-}" ]; } || rc=1 ;;
  "restart ssh.socket")
    n=$(cat "$SHIM_DIR/sockfails" 2>/dev/null || echo 0)
    if [ "$n" -lt "${SHIM_SOCKET_RESTART_FAILS:-0}" ]; then
      echo $((n + 1)) > "$SHIM_DIR/sockfails"
      rc=1
    else
      restart || rc=1
    fi ;;
  "restart ssh" | "try-restart ssh.service" | "start ssh.socket") restart || rc=1 ;;
  "stop ssh.service") [ -z "${SHIM_ALL_FAIL:-}" ] || rc=1 ;;
  "show ssh.socket")
    while read -r p proc; do [ -n "$p" ] && [ -n "${SHIM_SOCKET:-}" ] && echo "0.0.0.0:$p (Stream)"; done < "$SHIM_DIR/listen" ;;
esac
exit $rc
"""
)

SS_SHIM = r"""#!/bin/sh
echo "ss $*" >> "$SHIM_LOG"
case "$1" in
  -Hltnp)
    while read -r p proc; do
      [ -n "${SHIM_SOCKET:-}" ] && [ "$proc" = sshd ] && proc=systemd
      [ -n "$p" ] && echo "LISTEN 0 128 0.0.0.0:$p 0.0.0.0:* users:((\"$proc\",pid=7,fd=3))"
    done < "$SHIM_DIR/listen"
    cat "$SHIM_DIR/foreign" 2>/dev/null || true ;;
  -Htnp) cat "$SHIM_DIR/established" 2>/dev/null || true ;;
esac
exit 0
"""

SLEEP_SHIM = r"""#!/bin/sh
n=$(cat "$SHIM_DIR/sleeps" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$SHIM_DIR/sleeps"
echo "sleep $*" >> "$SHIM_LOG"
if [ -n "${SHIM_LOGIN_AFTER:-}" ] && [ "$n" -eq "$SHIM_LOGIN_AFTER" ]; then
  echo "ESTAB 0 0 192.0.2.10:$SHIM_LOGIN_PORT 198.51.100.7:50000 users:((\"sshd\",pid=4242,fd=4))" > "$SHIM_DIR/established"
  echo "${SHIM_TITLE:-sshd: alice@pts/0}" > "$SHIM_DIR/title"
fi
exit 0
"""

# Process titles: only pid 4242, the owner of the login connection, is known.
PS_SHIM = r"""#!/bin/sh
echo "ps $*" >> "$SHIM_LOG"
[ "$4" = 4242 ] && cat "$SHIM_DIR/title" 2>/dev/null
exit 0
"""

# Interrupts the script (its parent) at the first sleep, like a Ctrl-C while it waits.
INTERRUPT_SLEEP_SHIM = '#!/bin/sh\nkill -TERM "$PPID"\nexit 0\n'

UFW_SHIM = r"""#!/bin/sh
echo "ufw $*" >> "$SHIM_LOG"
[ "$1" != status ] || { [ -z "${SHIM_UFW:-}" ] || echo "Status: active"; }
exit 0
"""

RECORD_SHIM = '#!/bin/sh\necho "$(basename "$0") $*" >> "$SHIM_LOG"\nexit 1\n'
NETWORK_TOOLS = ["curl", "wget", "dig", "host", "nslookup", "getent", "ip", "hostname", "ifconfig"]

MAIN_DEBIAN = "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\nUsePAM yes\n"


@dataclass
class Box:
    base: Path
    fake_root: Path
    shim: Path
    env: dict[str, str]

    @property
    def cfg(self) -> Path:
        return self.fake_root / "etc/ssh/sshd_config"

    @property
    def dropin(self) -> Path:
        return self.fake_root / "etc/ssh/sshd_config.d/10-admin-port.conf"

    @property
    def override(self) -> Path:
        return self.fake_root / "etc/systemd/system/ssh.socket.d/override.conf"

    def calls(self) -> list[str]:
        log = self.shim / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def listening(self) -> list[str]:
        return sorted((self.shim / "listen").read_text().split()[::2], key=int)

    def run(self, *args: str, stdin: str = "y\n", **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            ["bash", str(SCRIPT), *args],  # noqa: S607
            env={**self.env, **env},
            input=stdin,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )


def out(proc: subprocess.CompletedProcess[str]) -> str:
    return proc.stdout + proc.stderr


@pytest.fixture
def box(tmp_path: Path) -> Box:
    shim = tmp_path / "shim"
    fake_root = tmp_path / "root"
    shim.mkdir()
    (fake_root / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (fake_root / "etc/systemd/system").mkdir(parents=True)
    (fake_root / "etc/ssh/sshd_config").write_text(MAIN_DEBIAN)
    (shim / "listen").write_text("22 sshd\n")
    shims = {
        "id": ID_SHIM,
        "sshd": SSHD_SHIM,
        "systemctl": SYSTEMCTL_SHIM,
        "ss": SS_SHIM,
        "sleep": SLEEP_SHIM,
        "ps": PS_SHIM,
        "ufw": UFW_SHIM,
        **dict.fromkeys(NETWORK_TOOLS, RECORD_SHIM),
    }
    for name, text in shims.items():
        path = shim / name
        path.write_text(text)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    env = {
        "PATH": f"{shim}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "LANG": "C",
        "SHIM_DIR": str(shim),
        "SHIM_LOG": str(shim / "calls.log"),
        "MOVE_SSH_ROOT": str(fake_root),
        "MOVE_SSH_WAIT_SECONDS": "20",
        "SHIM_LOGIN_PORT": "22222",
        "SHIM_LOGIN_AFTER": "1",
        "SUDO_USER": "alice",
    }
    return Box(tmp_path, fake_root, shim, env)


def test_help_needs_no_root(box: Box) -> None:
    proc = box.run("--help", SHIM_UID="1000")
    assert proc.returncode == 0
    assert "move-admin-ssh.sh --undo" in proc.stdout
    assert "22222" in proc.stdout
    assert "honeypot" not in out(proc).lower()


def test_refuses_without_root(box: Box) -> None:
    proc = box.run(SHIM_UID="1000")
    assert proc.returncode == 1
    assert "sudo" in proc.stderr
    assert not box.dropin.exists()
    assert not any(c.startswith(("systemctl restart", "ufw allow")) for c in box.calls())


def test_unknown_arguments_are_errors(box: Box) -> None:
    assert box.run("--force").returncode == 1
    assert box.run("22222", "33333").returncode == 1
    assert box.run("--undo", "22222").returncode == 1


@pytest.mark.parametrize("bad", ["abc", "70000", "1023", "22", "0", "-5x", "2222x"])
def test_refuses_a_bad_port(box: Box, bad: str) -> None:
    proc = box.run(bad)
    assert proc.returncode == 1
    assert "1024 to 65535" in proc.stderr or "unknown option" in proc.stderr
    assert not box.dropin.exists()


@pytest.mark.parametrize(
    "reserved", ["2222", "2375", "3306", "3389", "5000", "5060", "5555", "6379", "8443"]
)
def test_refuses_a_port_suckerpot_uses(box: Box, reserved: str) -> None:
    proc = box.run(reserved)
    assert proc.returncode == 1
    assert "used by SuckerPot" in proc.stderr
    assert not box.dropin.exists()


def test_refuses_a_busy_port(box: Box) -> None:
    (box.shim / "foreign").write_text(
        'LISTEN 0 511 0.0.0.0:48022 0.0.0.0:* users:(("nginx",pid=9,fd=6))\n'
    )
    proc = box.run("48022")
    assert proc.returncode == 1
    assert "already used by another program" in proc.stderr
    assert not box.dropin.exists()


def test_refuses_other_systems(box: Box) -> None:
    proc = box.run(SHIM_NO_UNIT="1")
    assert proc.returncode == 1
    assert "Debian and Ubuntu" in proc.stderr
    assert "docs/vps.md" in proc.stderr


def test_refuses_when_a_tool_is_missing(box: Box) -> None:
    (box.shim / "ss").unlink()
    only = box.base / "only"
    only.mkdir()
    for tool in ("bash", "uname"):
        found = shutil.which(tool, path="/usr/bin:/bin")
        assert found
        (only / tool).symlink_to(found)
    (only / "id").symlink_to(box.shim / "id")
    proc = box.run(PATH=str(only))
    assert proc.returncode == 1
    assert "not found" in proc.stderr


def test_declining_changes_nothing(box: Box) -> None:
    proc = box.run(stdin="n\n")
    assert proc.returncode == 1
    assert "nothing was changed" in proc.stderr
    assert not box.dropin.exists()


def test_sshd_config_path_moves_the_port(box: Box) -> None:
    proc = box.run()
    text = out(proc)
    assert proc.returncode == 0, text
    calls = box.calls()
    check = f"sshd -t -f {box.cfg}"
    assert check in calls
    assert calls.index(check) < calls.index("systemctl restart ssh")
    assert "ssh -p 22222 alice@YOUR-SERVER" in text
    assert "Keep this window open" in text
    assert "./scripts/install.sh --participant" in text
    assert "--undo" in text
    body = box.dropin.read_text().splitlines()
    assert body[0].startswith(MARK)
    assert body[1:] == ["Port 22222"]
    assert box.listening() == ["22222"]
    assert not box.override.exists()


def test_both_ports_are_open_while_waiting(box: Box) -> None:
    # The drop-in as it is at the first poll for the login.
    snap = box.shim / "snap"
    hook = box.shim / "ss"
    hook.write_text(
        hook.read_text().replace(
            "-Htnp)", f'-Htnp) cp "{box.dropin}" "{snap}" 2>/dev/null || true;'
        )
    )
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert snap.read_text().splitlines()[1:] == ["Port 22", "Port 22222"]


def test_socket_activation_path(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1")
    text = out(proc)
    assert proc.returncode == 0, text
    calls = box.calls()
    assert "systemctl restart ssh.socket" in calls
    assert "systemctl restart ssh" not in calls
    assert "systemctl daemon-reload" in calls
    lines = box.override.read_text().splitlines()
    assert lines[0].startswith(MARK)
    assert lines[1:] == [
        "[Socket]",
        "ListenStream=",
        "ListenStream=0.0.0.0:22222",
        "ListenStream=[::]:22222",
    ]
    assert box.listening() == ["22222"]
    assert box.dropin.read_text().splitlines()[1:] == ["Port 22222"]


def test_socket_override_has_both_ports_in_phase_one(box: Box) -> None:
    snap = box.shim / "snap"
    hook = box.shim / "ss"
    hook.write_text(
        hook.read_text().replace(
            "-Htnp)", f'-Htnp) cp "{box.override}" "{snap}" 2>/dev/null || true;'
        )
    )
    proc = box.run(SHIM_SOCKET="1")
    assert proc.returncode == 0, out(proc)
    assert snap.read_text().splitlines()[1:] == [
        "[Socket]",
        "ListenStream=",
        "ListenStream=0.0.0.0:22",
        "ListenStream=[::]:22",
        "ListenStream=0.0.0.0:22222",
        "ListenStream=[::]:22222",
    ]


def test_custom_port_and_yes(box: Box) -> None:
    proc = box.run("48022", "--yes", stdin="", SHIM_LOGIN_PORT="48022")
    assert proc.returncode == 0, out(proc)
    assert box.dropin.read_text().splitlines()[1:] == ["Port 48022"]
    assert "ssh -p 48022 alice@YOUR-SERVER" in out(proc)


def test_ufw_is_opened_when_active(box: Box) -> None:
    proc = box.run(SHIM_UFW="1")
    assert proc.returncode == 0, out(proc)
    assert "ufw allow 22222/tcp" in box.calls()
    assert "firewall panel" in out(proc)


def test_no_ufw_rule_when_inactive(box: Box) -> None:
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert not any(c.startswith("ufw allow") for c in box.calls())
    assert "firewall panel" in out(proc)


def test_timeout_leaves_port_22_only(box: Box) -> None:
    proc = box.run(SHIM_LOGIN_AFTER="")
    text = out(proc)
    assert proc.returncode == 1
    assert "no login on port 22222 was seen" in text
    assert "SSH listens on port 22 again" in text
    assert not box.dropin.exists()
    assert not box.override.exists()
    assert box.listening() == ["22"]
    assert box.cfg.read_text() == MAIN_DEBIAN
    # Port 22 was never closed: the only restarts are "both ports" and "back to 22".
    assert box.calls().count("systemctl restart ssh") == 2


def test_timeout_with_socket_activation(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_LOGIN_AFTER="")
    assert proc.returncode == 1
    assert not box.override.exists()
    assert not box.override.parent.exists()
    assert not box.dropin.exists()
    assert box.listening() == ["22"]


@pytest.mark.parametrize(
    "title",
    [
        "sshd: [accepted]",
        "sshd: alice [priv]",
        "sshd: alice [net]",
        "sshd-session: alice [priv]",
        "sshd-session: [accepted]",
    ],
)
def test_a_pre_login_connection_never_closes_port_22(box: Box, title: str) -> None:
    proc = box.run(SHIM_TITLE=title)
    assert proc.returncode == 1
    assert "no login on port 22222 was seen" in out(proc)
    assert box.listening() == ["22"]
    assert not box.dropin.exists()


@pytest.mark.parametrize(
    "title",
    [
        "sshd: alice@pts/0",
        "sshd: alice@notty",
        "sshd-session: alice@pts/3",
        "sshd-session: alice@notty",
    ],
)
def test_an_authenticated_session_counts(box: Box, title: str) -> None:
    proc = box.run(SHIM_TITLE=title)
    assert proc.returncode == 0, out(proc)
    assert box.listening() == ["22222"]


def test_interrupt_restores_port_22(box: Box) -> None:
    sleeper = box.shim / "sleep"
    sleeper.write_text(INTERRUPT_SLEEP_SHIM)
    proc = box.run()
    assert proc.returncode == 143
    assert not box.dropin.exists()
    assert box.listening() == ["22"]
    assert "Going back to port 22 only" in proc.stdout


def test_sshd_t_failure_restores_everything(box: Box) -> None:
    box.override.parent.mkdir(parents=True)
    own = "[Socket]\nListenStream=\nListenStream=0.0.0.0:22\n"
    box.override.write_text(own)
    proc = box.run(SHIM_SOCKET="1", SHIM_SSHD_T_FAIL="1")
    assert proc.returncode == 1
    assert "refused" in proc.stderr
    assert not box.dropin.exists()
    assert box.override.read_text() == own
    assert not Path(str(box.override) + ".suckerpot.bak").exists()
    assert box.cfg.read_text() == MAIN_DEBIAN
    assert box.listening() == ["22"]


def test_existing_override_is_backed_up_and_restored(box: Box) -> None:
    box.override.parent.mkdir(parents=True)
    original = "[Socket]\nListenStream=\nListenStream=0.0.0.0:22\nListenStream=[::]:22\n"
    box.override.write_text(original)
    proc = box.run(SHIM_SOCKET="1")
    assert proc.returncode == 0, out(proc)
    backup = Path(str(box.override) + ".suckerpot.bak")
    assert backup.read_text() == original
    assert "kept as" in out(proc)
    proc = box.run("--undo", "--yes", SHIM_SOCKET="1")
    assert proc.returncode == 0, out(proc)
    assert box.override.read_text() == original
    assert not backup.exists()


def test_main_config_with_its_own_port_line(box: Box) -> None:
    original = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nUsePAM yes\n"
    box.cfg.write_text(original)
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert Path(str(box.cfg) + ".suckerpot.bak").read_text() == original
    changed = box.cfg.read_text()
    assert "\nPort 22\n" not in changed
    assert "UsePAM yes" in changed
    assert box.listening() == ["22222"]
    proc = box.run("--undo", "--yes")
    assert proc.returncode == 0, out(proc)
    assert box.cfg.read_text() == original
    assert not Path(str(box.cfg) + ".suckerpot.bak").exists()
    assert box.listening() == ["22"]


def test_main_config_without_include(box: Box) -> None:
    original = "Port 22\nPermitRootLogin no\n"
    box.cfg.write_text(original)
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert "Include /etc/ssh/sshd_config.d/*.conf" in box.cfg.read_text()
    assert box.listening() == ["22222"]
    assert Path(str(box.cfg) + ".suckerpot.bak").read_text() == original
    assert box.run("--undo", "--yes").returncode == 0
    assert box.cfg.read_text() == original


def test_existing_backup_is_not_overwritten(box: Box) -> None:
    box.cfg.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    bak = Path(str(box.cfg) + ".suckerpot.bak")
    bak.write_text("the first original\n")
    assert box.run().returncode == 0
    assert bak.read_text() == "the first original\n"


def test_undo_restores_port_22(box: Box) -> None:
    assert box.run().returncode == 0
    assert box.listening() == ["22222"]
    proc = box.run("--undo", "--yes")
    text = out(proc)
    assert proc.returncode == 0, text
    assert box.listening() == ["22"]
    assert not box.dropin.exists()
    assert "firewall rule" in text


def test_undo_without_anything_to_undo(box: Box) -> None:
    proc = box.run("--undo", "--yes")
    assert proc.returncode == 0
    assert "already on port 22" in proc.stdout


def test_second_run_has_nothing_to_do(box: Box) -> None:
    assert box.run().returncode == 0
    before = len(box.calls())
    proc = box.run()
    assert proc.returncode == 0
    assert "Nothing to do" in proc.stdout
    assert not any(c.startswith("systemctl restart") for c in box.calls()[before:])


def test_no_network_lookup_and_no_address(box: Box) -> None:
    proc = box.run()
    assert proc.returncode == 0
    names = {c.split()[0] for c in box.calls()}
    assert not names & set(NETWORK_TOOLS)
    script = SCRIPT.read_text().lower()
    for word in ("curl", "wget", "dig ", "hostname", "ifconfig", "ip addr", "honeypot"):
        assert word not in script


def test_script_is_executable_and_has_a_shebang() -> None:
    assert os.access(SCRIPT, os.X_OK)
    assert SCRIPT.read_text().startswith("#!/usr/bin/env bash\n")
    assert stat.S_IMODE(SCRIPT.stat().st_mode) & stat.S_IXUSR


def test_already_off_port_22_changes_nothing(box: Box) -> None:
    box.cfg.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 2200\n")
    (box.shim / "listen").write_text("2200 sshd\n")
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert "already off port 22" in proc.stdout
    assert "2200" in proc.stdout
    assert "free for the SSH sensor" in proc.stdout
    assert not box.dropin.exists()
    assert box.cfg.read_text().endswith("Port 2200\n")
    assert not any(c.startswith("systemctl restart") for c in box.calls())


def test_port_22_plus_foreign_ports_is_refused(box: Box) -> None:
    box.cfg.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPort 2200\n")
    (box.shim / "listen").write_text("22 sshd\n2200 sshd\n")
    proc = box.run()
    assert proc.returncode == 1
    assert "unusual" in proc.stderr
    assert "By hand" in proc.stderr
    assert not box.dropin.exists()
    assert not any(c.startswith("systemctl restart") for c in box.calls())


def test_files_of_an_interrupted_run_are_reverted_first(box: Box) -> None:
    box.dropin.write_text(f"{MARK_FULL}\nPort 22\nPort 22222\n")
    (box.shim / "listen").write_text("22 sshd\n22222 sshd\n")
    proc = box.run()
    text = out(proc)
    assert proc.returncode == 0, text
    assert "earlier run" in text
    assert box.dropin.read_text().splitlines()[1:] == ["Port 22222"]
    assert box.listening() == ["22222"]


def test_a_systemd_socket_of_another_unit_is_not_ssh(box: Box) -> None:
    # Held by systemd, but ssh.socket does not list 48022: some other unit owns it.
    (box.shim / "foreign").write_text(
        'LISTEN 0 4096 0.0.0.0:48022 0.0.0.0:* users:(("systemd",pid=1,fd=40))\n'
    )
    proc = box.run("48022", SHIM_SOCKET="1")
    assert proc.returncode == 1
    assert "already used by another program" in proc.stderr
    # Without socket activation a systemd owner is never SSH either.
    proc = box.run("48022")
    assert proc.returncode == 1


def test_socket_restart_failure_falls_back_to_stop_and_start(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_SOCKET_RESTART_FAILS="1")
    assert proc.returncode == 0, out(proc)
    calls = box.calls()
    assert "systemctl stop ssh.service" in calls
    assert "systemctl start ssh.socket" in calls
    assert box.listening() == ["22222"]


def test_when_nothing_can_be_restarted_the_user_is_told_what_to_do(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_ALL_FAIL="1")
    assert proc.returncode == 1
    err = proc.stderr
    assert "Do NOT close this session" in err
    assert "sudo systemctl restart ssh\n" in err
    assert "sudo ss -ltnp | grep -E 'sshd|systemd'" in err
    assert not box.dropin.exists()
    assert not box.override.exists()
    # The last attempt went straight at the socket.
    assert box.calls().count("systemctl restart ssh.socket") >= 3
