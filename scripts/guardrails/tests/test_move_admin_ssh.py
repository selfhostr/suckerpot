"""scripts/move-admin-ssh.sh: moves the admin SSH daemon without ever locking the user out.

The script runs in a scratch root (MOVE_SSH_ROOT) with fake `id`, `sshd`, `systemctl`, `ss`, `ps`,
`ufw`, `firewall-cmd` and `sleep` first on PATH. The fakes keep a tiny model of the machine: a
restart makes the listeners match the files the script wrote (and is logged in a history file),
and the Nth call of `sleep` makes a login appear on the target port. They never touch the real SSH
daemon, and every call is recorded in a log.
"""

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import ROOT

SCRIPT = ROOT / "scripts/move-admin-ssh.sh"
MARK = "# move-admin-ssh.sh: managed file. Undo with: ./scripts/move-admin-ssh.sh --undo"

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
d="$MOVE_SSH_ROOT/etc/ssh/sshd_config.d/10-admin-port.conf"
case "$1" in
  -t)
    if [ -n "${SHIM_SSHD_T_FAIL:-}" ] && [ -e "$d" ]; then
      echo "sshd: bad configuration" >&2
      exit 255
    fi
    # Fails only for the final single-port file (no "moving from" line): the second phase.
    if [ -n "${SHIM_SSHD_T_FAIL_PHASE2:-}" ] && [ -e "$d" ] && ! grep -q '^# moving from' "$d"; then
      echo "sshd: bad configuration" >&2
      exit 255
    fi ;;
  -T)
    for p in $(ports); do echo "port $p"; done
    echo "listenaddress ${SHIM_LISTENADDR:-0.0.0.0}" ;;
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
  echo "$(awk '{printf "%s ", $1}' "$SHIM_DIR/listen")" >> "$SHIM_DIR/history"
}
rc=0
case "$1 $2" in
  "cat ssh.service") [ -z "${SHIM_NO_UNIT:-}" ] || rc=1 ;;
  "is-enabled --quiet" | "is-active --quiet")
    case "$3" in
      ssh.socket) [ -n "${SHIM_SOCKET:-}" ] || rc=1 ;;
      firewalld) [ -n "${SHIM_FIREWALLD:-}" ] || rc=1 ;;
      *) rc=1 ;;
    esac ;;
  "restart ssh.socket")
    n=$(cat "$SHIM_DIR/sockfails" 2>/dev/null || echo 0)
    if [ "$n" -lt "${SHIM_SOCKET_RESTART_FAILS:-0}" ]; then
      echo $((n + 1)) > "$SHIM_DIR/sockfails"
      rc=1
    else
      restart || rc=1
    fi ;;
  "start ssh.socket")
    n=$(cat "$SHIM_DIR/startfails" 2>/dev/null || echo 0)
    if [ "$n" -lt "${SHIM_START_FAILS:-0}" ]; then
      echo $((n + 1)) > "$SHIM_DIR/startfails"
      rc=1
    else
      restart || rc=1
    fi ;;
  "restart ssh" | "try-restart ssh.service") restart || rc=1 ;;
  "stop ssh.service") [ -z "${SHIM_ALL_FAIL:-}" ] || rc=1 ;;
  "show ssh.socket")
    while read -r p proc; do [ -n "$p" ] && [ -n "${SHIM_SOCKET:-}" ] && echo "0.0.0.0:$p (Stream)"; done < "$SHIM_DIR/listen"
    [ -z "${SHIM_SHOW_EXTRA:-}" ] || echo "$SHIM_SHOW_EXTRA" ;;
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

# Hangs up the script once the test has closed its pipes and created the "go" file.
HUP_SLEEP_SHIM = r"""#!/bin/sh
echo "sleep $*" >> "$SHIM_LOG"
[ -e "$SHIM_DIR/go" ] || { /bin/sleep 0.2; exit 0; }
kill -HUP "$PPID"
exit 0
"""

UFW_SHIM = r"""#!/bin/sh
echo "ufw $*" >> "$SHIM_LOG"
if [ "$1" = status ] && [ -n "${SHIM_UFW:-}" ]; then
  echo "Status: active"
  echo
  echo "To                         Action      From"
  echo "--                         ------      ----"
  printf '%s\n' "$SHIM_UFW_RULES"
fi
exit 0
"""

FIREWALLD_SHIM = r"""#!/bin/sh
echo "firewall-cmd $*" >> "$SHIM_LOG"
case "$1" in
  --list-services) echo "${SHIM_FW_SERVICES:-}" ;;
  --list-ports) echo "${SHIM_FW_PORTS:-}" ;;
esac
exit 0
"""

RECORD_SHIM = '#!/bin/sh\necho "$(basename "$0") $*" >> "$SHIM_LOG"\nexit 1\n'
NETWORK_TOOLS = ["curl", "wget", "dig", "host", "nslookup", "getent", "ip", "hostname", "ifconfig"]

MAIN_DEBIAN = "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\nUsePAM yes\n"
OPEN_UFW = "22/tcp                     ALLOW       Anywhere\n22/tcp (v6)                ALLOW       Anywhere (v6)"


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

    def restarts(self) -> int:
        return sum(
            1 for c in self.calls() if c.startswith(("systemctl restart", "systemctl start"))
        )

    def history(self) -> list[list[str]]:
        """The listening ports after every restart, in order."""
        path = self.shim / "history"
        return [line.split() for line in path.read_text().splitlines()] if path.exists() else []

    def listening(self) -> list[str]:
        return sorted((self.shim / "listen").read_text().split()[::2], key=int)

    def start_on(self, port: int, own_line: bool = True) -> None:
        """The machine's SSH already runs on this port, set up by the user."""
        line = f"Port {port}\n" if own_line else ""
        self.cfg.write_text(f"Include /etc/ssh/sshd_config.d/*.conf\n{line}UsePAM yes\n")
        (self.shim / "listen").write_text(f"{port} sshd\n")

    def reset_login(self) -> None:
        for name in ("established", "sleeps"):
            (self.shim / name).unlink(missing_ok=True)

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
    (fake_root / "proc/4242").mkdir(parents=True)
    (fake_root / "proc/4242/exe").symlink_to("/usr/sbin/sshd")
    shims = {
        "id": ID_SHIM,
        "sshd": SSHD_SHIM,
        "systemctl": SYSTEMCTL_SHIM,
        "ss": SS_SHIM,
        "sleep": SLEEP_SHIM,
        "ps": PS_SHIM,
        "ufw": UFW_SHIM,
        "firewall-cmd": FIREWALLD_SHIM,
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


def snapshot_hook(box: Box, target: Path, snap: Path) -> None:
    """Copies `target` each time the script polls for a login (the state while it waits)."""
    hook = box.shim / "ss"
    hook.write_text(
        hook.read_text().replace("-Htnp)", f'-Htnp) cp "{target}" "{snap}" 2>/dev/null || true;')
    )


# ---------------------------------------------------------------- arguments and preconditions
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
    assert box.restarts() == 0


def test_a_systemd_socket_of_another_unit_is_not_ssh(box: Box) -> None:
    # Held by systemd, but ssh.socket does not list 48022: some other unit owns it.
    (box.shim / "foreign").write_text(
        'LISTEN 0 4096 0.0.0.0:48022 0.0.0.0:* users:(("systemd",pid=1,fd=40))\n'
    )
    assert box.run("48022", SHIM_SOCKET="1").returncode == 1
    assert box.run("48022").returncode == 1


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
        (only / tool).symlink_to(Path("/usr/bin") / tool)
    (only / "id").symlink_to(box.shim / "id")
    proc = box.run(PATH=str(only))
    assert proc.returncode == 1
    assert "not found" in proc.stderr


def test_declining_changes_nothing(box: Box) -> None:
    proc = box.run(stdin="n\n")
    assert proc.returncode == 1
    assert "nothing was changed" in proc.stderr
    assert not box.dropin.exists()
    assert "from port 22 to port 22222" in proc.stdout


# ---------------------------------------------------------------- the move itself
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
    assert box.dropin.read_text().splitlines() == [MARK, "Port 22222"]
    assert box.listening() == ["22222"]
    assert not box.override.exists()
    assert box.history() == [["22", "22222"], ["22222"]]


def test_both_ports_are_open_while_waiting(box: Box) -> None:
    snap = box.shim / "snap"
    snapshot_hook(box, box.dropin, snap)
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert snap.read_text().splitlines() == [MARK, "# moving from 22", "Port 22", "Port 22222"]


def test_socket_activation_path(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1")
    text = out(proc)
    assert proc.returncode == 0, text
    calls = box.calls()
    assert "systemctl restart ssh.socket" in calls
    assert "systemctl restart ssh" not in calls
    assert "systemctl daemon-reload" in calls
    assert box.override.read_text().splitlines() == [
        MARK,
        "[Socket]",
        "ListenStream=",
        "ListenStream=0.0.0.0:22222",
        "ListenStream=[::]:22222",
        "BindIPv6Only=ipv6-only",
    ]
    assert box.listening() == ["22222"]
    assert box.dropin.read_text().splitlines() == [MARK, "Port 22222"]


def test_socket_override_has_both_ports_in_phase_one(box: Box) -> None:
    snap = box.shim / "snap"
    snapshot_hook(box, box.override, snap)
    proc = box.run(SHIM_SOCKET="1")
    assert proc.returncode == 0, out(proc)
    assert snap.read_text().splitlines()[1:] == [
        "[Socket]",
        "ListenStream=",
        "ListenStream=0.0.0.0:22",
        "ListenStream=[::]:22",
        "ListenStream=0.0.0.0:22222",
        "ListenStream=[::]:22222",
        "BindIPv6Only=ipv6-only",
    ]


def test_custom_port_and_yes(box: Box) -> None:
    proc = box.run("48022", "--yes", stdin="", SHIM_LOGIN_PORT="48022")
    assert proc.returncode == 0, out(proc)
    assert box.dropin.read_text().splitlines() == [MARK, "Port 48022"]
    assert "ssh -p 48022 alice@YOUR-SERVER" in out(proc)


def test_second_run_has_nothing_to_do(box: Box) -> None:
    assert box.run().returncode == 0
    before = len(box.calls())
    proc = box.run()
    assert proc.returncode == 0
    assert "Nothing to do" in proc.stdout
    assert not any(c.startswith("systemctl restart") for c in box.calls()[before:])


def test_rerun_with_another_port_never_opens_22(box: Box) -> None:
    assert box.run().returncode == 0
    box.reset_login()
    proc = box.run("48022", SHIM_LOGIN_PORT="48022")
    assert proc.returncode == 0, out(proc)
    assert "from port 22222 to port 48022" in proc.stdout
    assert box.history() == [["22", "22222"], ["22222"], ["22222", "48022"], ["48022"]]
    assert box.dropin.read_text().splitlines() == [MARK, "Port 48022"]


def test_no_argument_run_off_port_22_changes_nothing(box: Box) -> None:
    box.start_on(2200)
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert "already off port 22" in proc.stdout
    assert "2200" in proc.stdout
    assert "free for the SSH sensor" in proc.stdout
    assert "move-admin-ssh.sh PORT" in proc.stdout
    assert not box.dropin.exists()
    assert box.restarts() == 0


def test_explicit_port_moves_from_a_port_that_is_not_22(box: Box) -> None:
    box.start_on(2200)
    proc = box.run("48022", SHIM_LOGIN_PORT="48022")
    assert proc.returncode == 0, out(proc)
    assert "from port 2200 to port 48022" in proc.stdout
    assert box.listening() == ["48022"]
    assert all("22" not in step for step in box.history())


def test_several_ports_not_set_up_by_the_script_are_refused(box: Box) -> None:
    box.cfg.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPort 2200\n")
    (box.shim / "listen").write_text("22 sshd\n2200 sshd\n")
    proc = box.run()
    assert proc.returncode == 1
    assert "unusual" in proc.stderr
    assert "By hand" in proc.stderr
    assert not box.dropin.exists()
    assert box.restarts() == 0


def test_a_specific_listen_address_is_refused(box: Box) -> None:
    proc = box.run(SHIM_LISTENADDR="192.0.2.7")
    assert proc.returncode == 1
    assert "specific address" in proc.stderr
    assert "192.0.2.7" in proc.stderr
    assert not box.dropin.exists()
    assert box.restarts() == 0
    # Wildcards, with or without a port, are fine.
    assert box.run(SHIM_LISTENADDR="[::]:22").returncode == 0


def test_a_specific_socket_address_is_refused(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_SHOW_EXTRA="192.0.2.7:22 (Stream)")
    assert proc.returncode == 1
    assert "specific address" in proc.stderr
    assert not box.override.exists()
    assert box.restarts() == 0


def test_another_file_that_sets_a_port_is_refused_by_name(box: Box) -> None:
    other = box.fake_root / "etc/ssh/sshd_config.d/50-cloud.conf"
    other.write_text("Port 2200\n")
    proc = box.run()
    assert proc.returncode == 1
    assert str(other) in proc.stderr
    assert not box.dropin.exists()
    assert box.restarts() == 0


# ---------------------------------------------------------------- firewalls
def test_ufw_is_opened_when_ssh_is_open_to_anywhere(box: Box) -> None:
    proc = box.run(SHIM_UFW="1", SHIM_UFW_RULES=OPEN_UFW)
    assert proc.returncode == 0, out(proc)
    assert "ufw allow 22222/tcp" in box.calls()
    assert "firewall panel" in out(proc)


def test_ufw_open_through_the_openssh_profile(box: Box) -> None:
    proc = box.run(SHIM_UFW="1", SHIM_UFW_RULES="OpenSSH                    ALLOW       Anywhere")
    assert proc.returncode == 0, out(proc)
    assert "ufw allow 22222/tcp" in box.calls()


def test_ufw_limited_to_sources_gets_no_rule_but_a_note(box: Box) -> None:
    proc = box.run(
        SHIM_UFW="1", SHIM_UFW_RULES="22/tcp                     ALLOW       203.0.113.5"
    )
    assert proc.returncode == 0, out(proc)
    assert not any(c.startswith("ufw allow") for c in box.calls())
    assert "ufw allow from ADDRESS to any port 22222 proto tcp" in proc.stdout


def test_no_ufw_rule_when_inactive(box: Box) -> None:
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert not any(c.startswith("ufw allow") for c in box.calls())
    assert "firewall panel" in out(proc)


def test_firewalld_is_opened_when_ssh_is_allowed(box: Box) -> None:
    proc = box.run(SHIM_FIREWALLD="1", SHIM_FW_SERVICES="dhcpv6-client ssh")
    assert proc.returncode == 0, out(proc)
    assert "firewall-cmd --permanent --add-port=22222/tcp" in box.calls()


def test_firewalld_without_an_ssh_service_gets_no_rule(box: Box) -> None:
    proc = box.run(SHIM_FIREWALLD="1", SHIM_FW_SERVICES="dhcpv6-client")
    assert proc.returncode == 0, out(proc)
    assert not any("--add-port" in c for c in box.calls())
    assert "same way" in proc.stdout


# ---------------------------------------------------------------- proof of login
def test_timeout_goes_back_to_the_start_port(box: Box) -> None:
    proc = box.run(SHIM_LOGIN_AFTER="")
    text = out(proc)
    assert proc.returncode == 1
    assert "no login on port 22222 was seen" in text
    assert "SSH listens on port 22 again" in text
    assert not box.dropin.exists()
    assert not box.override.exists()
    assert box.listening() == ["22"]
    assert box.cfg.read_text() == MAIN_DEBIAN
    # The old port was never closed: both ports, then back to the start port.
    assert box.history() == [["22", "22222"], ["22"]]


def test_timeout_with_socket_activation(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_LOGIN_AFTER="")
    assert proc.returncode == 1
    assert not box.override.exists()
    assert not box.override.parent.exists()
    assert not box.dropin.exists()
    assert box.listening() == ["22"]


def test_timeout_from_a_port_that_is_not_22_goes_back_there(box: Box) -> None:
    box.start_on(2200)
    proc = box.run("48022", SHIM_LOGIN_AFTER="")
    assert proc.returncode == 1
    assert box.listening() == ["2200"]
    assert not box.dropin.exists() or box.dropin.read_text().splitlines()[1:] == ["Port 2200"]
    assert all(step != ["48022"] for step in box.history())


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
def test_a_pre_login_connection_never_closes_the_old_port(box: Box, title: str) -> None:
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


def test_a_forged_title_on_another_program_does_not_count(box: Box) -> None:
    exe = box.fake_root / "proc/4242/exe"
    exe.unlink()
    exe.symlink_to("/usr/bin/python3")
    proc = box.run()
    assert proc.returncode == 1
    assert box.listening() == ["22"]


def test_the_executable_may_be_sshd_session_or_deleted(box: Box) -> None:
    exe = box.fake_root / "proc/4242/exe"
    exe.unlink()
    exe.symlink_to("/usr/lib/openssh/sshd-session (deleted)")
    assert box.run().returncode == 0


# ---------------------------------------------------------------- undo is a normal move
def test_undo_is_a_two_phase_move_back(box: Box) -> None:
    assert box.run().returncode == 0
    box.reset_login()
    proc = box.run("--undo", "--yes", SHIM_LOGIN_PORT="22")
    text = out(proc)
    assert proc.returncode == 0, text
    assert "from port 22222 to port 22" in text
    assert box.listening() == ["22"]
    assert not box.dropin.exists()
    assert box.cfg.read_text() == MAIN_DEBIAN
    assert box.history()[-2:] == [["22", "22222"], ["22"]]


def test_undo_with_a_foreign_listener_on_22_changes_nothing(box: Box) -> None:
    assert box.run().returncode == 0
    box.reset_login()
    (box.shim / "foreign").write_text(
        'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("docker-proxy",pid=9,fd=4))\n'
    )
    before = box.dropin.read_text()
    restarts = box.restarts()
    proc = box.run("--undo", "--yes", SHIM_LOGIN_PORT="22")
    assert proc.returncode == 1
    assert "most likely the SSH sensor" in proc.stderr
    assert "docker compose down" in proc.stderr
    assert box.dropin.read_text() == before
    assert box.listening() == ["22222"]
    assert box.restarts() == restarts


def test_undo_timeout_names_the_sensor_and_keeps_the_admin_port(box: Box) -> None:
    assert box.run().returncode == 0
    box.reset_login()
    proc = box.run("--undo", "--yes", SHIM_LOGIN_AFTER="")
    assert proc.returncode == 1
    assert "docker compose down" in proc.stderr
    assert box.listening() == ["22222"]
    assert box.dropin.read_text().splitlines() == [MARK, "Port 22222"]


def test_undo_when_already_on_22_has_nothing_to_do(box: Box) -> None:
    proc = box.run("--undo", "--yes")
    assert proc.returncode == 0
    assert "Nothing to do" in proc.stdout
    assert box.restarts() == 0


def test_undo_keeps_edits_made_after_the_move(box: Box) -> None:
    original = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nUsePAM yes\n"
    box.cfg.write_text(original)
    assert box.run().returncode == 0
    backup = Path(str(box.cfg) + ".suckerpot.bak")
    assert backup.read_text() == original
    with box.cfg.open("a") as f:
        f.write("PasswordAuthentication no\n")
    box.reset_login()
    proc = box.run("--undo", "--yes", SHIM_LOGIN_PORT="22")
    assert proc.returncode == 0, out(proc)
    assert box.cfg.read_text() == original + "PasswordAuthentication no\n"
    assert backup.read_text() == original  # a plain safety copy, never copied back
    assert box.listening() == ["22"]


def test_main_config_without_include_is_fixed_and_unfixed(box: Box) -> None:
    original = "Port 22\nPermitRootLogin no\n"
    box.cfg.write_text(original)
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert "Include /etc/ssh/sshd_config.d/*.conf" in box.cfg.read_text()
    assert box.listening() == ["22222"]
    assert Path(str(box.cfg) + ".suckerpot.bak").read_text() == original
    box.reset_login()
    assert box.run("--undo", "--yes", SHIM_LOGIN_PORT="22").returncode == 0
    assert box.cfg.read_text() == original


def test_existing_backup_is_not_overwritten(box: Box) -> None:
    box.cfg.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    bak = Path(str(box.cfg) + ".suckerpot.bak")
    bak.write_text("the first original\n")
    assert box.run().returncode == 0
    assert bak.read_text() == "the first original\n"


def test_existing_override_is_backed_up_and_restored(box: Box) -> None:
    box.override.parent.mkdir(parents=True)
    original = "[Socket]\nListenStream=\nListenStream=0.0.0.0:22\nListenStream=[::]:22\n"
    box.override.write_text(original)
    proc = box.run(SHIM_SOCKET="1")
    assert proc.returncode == 0, out(proc)
    backup = Path(str(box.override) + ".suckerpot.bak")
    assert backup.read_text() == original
    assert "kept as" in out(proc)
    box.reset_login()
    proc = box.run("--undo", "--yes", SHIM_SOCKET="1", SHIM_LOGIN_PORT="22")
    assert proc.returncode == 0, out(proc)
    assert box.override.read_text() == original
    assert not backup.exists()


# ---------------------------------------------------------------- an interrupted run
def test_a_killed_run_goes_back_to_its_recorded_port(box: Box) -> None:
    box.dropin.write_text(f"{MARK}\n# moving from 22222\nPort 22222\nPort 48022\n")
    (box.shim / "listen").write_text("22222 sshd\n48022 sshd\n")
    proc = box.run()
    text = out(proc)
    assert proc.returncode == 0, text
    assert "earlier run" in text
    assert "port 22222 first" in text
    assert box.listening() == ["22222"]
    assert box.history() == [["22222"]]
    assert "Nothing to do" in text


def test_a_killed_run_from_port_22_removes_its_files(box: Box) -> None:
    box.dropin.write_text(f"{MARK}\n# moving from 22\nPort 22\nPort 22222\n")
    (box.shim / "listen").write_text("22 sshd\n22222 sshd\n")
    proc = box.run()
    assert proc.returncode == 0, out(proc)
    assert "earlier run" in proc.stdout
    assert box.listening() == ["22222"]
    assert box.history()[0] == ["22"]


# ---------------------------------------------------------------- every failure ends on the start port
def test_interrupt_restores_the_start_port(box: Box) -> None:
    sleeper = box.shim / "sleep"
    sleeper.write_text(INTERRUPT_SLEEP_SHIM)
    proc = box.run()
    assert proc.returncode == 143
    assert not box.dropin.exists()
    assert box.listening() == ["22"]
    assert "Going back to port 22" in proc.stdout


def test_a_hangup_with_closed_pipes_still_completes_the_revert(box: Box) -> None:
    (box.shim / "sleep").write_text(HUP_SLEEP_SHIM)
    env = {**box.env, "MOVE_SSH_WAIT_SECONDS": "200"}
    proc = subprocess.Popen(  # noqa: S603
        ["bash", str(SCRIPT)],  # noqa: S607
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None
    proc.stdin.write("y\n")
    proc.stdin.close()
    for line in proc.stdout:
        if "Waiting up to" in line:
            break
    proc.stdout.close()
    proc.stderr.close()
    (box.shim / "go").write_text("")
    proc.wait(timeout=30)
    assert proc.returncode in (129, 141)
    assert not box.dropin.exists()
    assert box.cfg.read_text() == MAIN_DEBIAN
    assert box.listening() == ["22"]


def test_sshd_t_failure_in_phase_one_restores_everything(box: Box) -> None:
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


def test_a_failure_in_phase_two_ends_on_the_start_port_with_a_listener(box: Box) -> None:
    proc = box.run(SHIM_SSHD_T_FAIL_PHASE2="1")
    assert proc.returncode == 1
    assert "refused" in proc.stderr
    assert box.listening() == ["22"]
    assert not box.dropin.exists()
    assert box.history() == [["22", "22222"], ["22"]]


def test_socket_restart_failure_falls_back_to_stop_and_start(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_SOCKET_RESTART_FAILS="1")
    assert proc.returncode == 0, out(proc)
    calls = box.calls()
    assert "systemctl stop ssh.service" in calls
    assert "systemctl start ssh.socket" in calls
    assert box.listening() == ["22222"]


def test_a_stop_that_works_followed_by_a_start_that_fails_ends_on_the_start_port(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_SOCKET_RESTART_FAILS="1", SHIM_START_FAILS="1")
    assert proc.returncode == 1
    assert box.listening() == ["22"]
    assert not box.dropin.exists()
    assert not box.override.exists()


def test_when_nothing_can_be_restarted_the_user_is_told_what_to_do(box: Box) -> None:
    proc = box.run(SHIM_SOCKET="1", SHIM_ALL_FAIL="1")
    assert proc.returncode == 1
    err = proc.stderr
    assert "Do NOT close this session" in err
    assert "sudo systemctl restart ssh\n" in err
    assert "sudo ss -ltnp | grep -E 'sshd|systemd'" in err
    assert not box.dropin.exists()
    assert not box.override.exists()
    assert box.calls().count("systemctl restart ssh.socket") >= 3


# ---------------------------------------------------------------- hygiene
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
