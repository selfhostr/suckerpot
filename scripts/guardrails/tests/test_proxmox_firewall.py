"""scripts/host/proxmox-firewall.sh: the Proxmox VE firewall file of the SuckerPot VM.

The script runs against a fake root (SUCKERPOT_PVE_ROOT) with fake `id`, `pve-firewall`, `qm` and
`pvesh` first on PATH. The fakes only record their calls and answer from environment variables;
there is no Proxmox here and nothing under the real /etc/pve is ever read or written.
Every address is from a documentation range.
"""

import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "host" / "proxmox-firewall.sh"
PATH = "/usr/local/bin:/usr/bin:/bin"
VMID = "102"
MARK = "# SuckerPot:"
NIC = "virtio=02:00:00:00:00:01,bridge=vmbr0"
# The private ranges every VM file must drop, in this order (the point of the test).
PRIVATE = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 fc00::/7"  # gitleaks:allow (private ranges are the point of the rule)

ID_SHIM = '#!/bin/sh\necho "id $*" >> "$SHIM_LOG"\necho "${SHIM_UID:-0}"\n'

# `compile` keeps a copy of the VM file as it was when it ran, and fails on demand:
#   SHIM_COMPILE_FAIL=new     fails while the file holds a rule written by the script
#   SHIM_COMPILE_FAIL=always  fails every time
#   SHIM_COMPILE_WARN=1       exits 0 but names the VM file on stderr while it holds such a rule
PVE_FIREWALL_SHIM = r"""#!/bin/sh
echo "pve-firewall $*" >> "$SHIM_LOG"
vmfw="$SUCKERPOT_PVE_ROOT/etc/pve/firewall/102.fw"
case "$1" in
  compile)
    n=$(cat "$SHIM_DIR/compiles" 2>/dev/null || echo 0)
    n=$((n + 1))
    echo "$n" > "$SHIM_DIR/compiles"
    cp "$vmfw" "$SHIM_DIR/compile-$n.fw" 2>/dev/null || : > "$SHIM_DIR/compile-$n.fw"
    new=0
    grep -q 'SuckerPot:' "$vmfw" 2>/dev/null && new=1
    if [ "${SHIM_COMPILE_FAIL:-}" = always ] || { [ "${SHIM_COMPILE_FAIL:-}" = new ] && [ "$new" = 1 ]; }; then
      echo "pve-firewall: syntax error" >&2
      exit 255
    fi
    if [ -n "${SHIM_COMPILE_WARN:-}" ] && [ "$new" = 1 ]; then
      echo "/etc/pve/firewall/102.fw (line 9): unknown option" >&2
    fi
    echo "iptables rules"
    exit 0 ;;
  status) echo "Status: enabled/running" ;;
esac
exit 0
"""

QM_SHIM = r"""#!/bin/sh
echo "qm $*" >> "$SHIM_LOG"
case "$1" in
  config)
    if [ -n "${SHIM_QM_MISSING:-}" ]; then
      echo "Configuration file 'nodes/pve/qemu-server/$2.conf' does not exist" >&2
      exit 2
    fi
    if [ -n "${SHIM_QM_CONFIG:-}" ]; then
      printf '%s\n' "$SHIM_QM_CONFIG"
    else
      printf 'name: vm-test\nnet0: %s,firewall=1\n' "$SHIM_NIC"
    fi ;;
  set) exit "${SHIM_QM_SET_RC:-0}" ;;
esac
exit 0
"""

PVESH_SHIM = r"""#!/bin/sh
echo "pvesh $*" >> "$SHIM_LOG"
[ "${SHIM_PVESH_RC:-0}" = 0 ] || exit "$SHIM_PVESH_RC"
if [ "$1 $2" = "get /cluster/firewall/options" ]; then
  if [ -n "${SHIM_DC_JSON+x}" ]; then
    printf '%s\n' "$SHIM_DC_JSON"
  else
    echo '{"enable":1,"policy_in":"DROP"}'
  fi
fi
exit 0
"""


@dataclass
class Box:
    base: Path
    root: Path
    shim: Path
    env: dict[str, str]

    @property
    def fwdir(self) -> Path:
        return self.root / "etc/pve/firewall"

    @property
    def vmfw(self) -> Path:
        return self.fwdir / f"{VMID}.fw"

    @property
    def bakdir(self) -> Path:
        return self.root / "root/suckerpot-firewall-backups"

    def backups(self) -> list[Path]:
        return sorted(self.bakdir.glob("*")) if self.bakdir.exists() else []

    def calls(self) -> list[str]:
        log = self.shim / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def run(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            ["bash", str(SCRIPT), *args],  # noqa: S607
            env={**self.env, **env},
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def vm(self, *extra: str, **env: str) -> subprocess.CompletedProcess[str]:
        """Run for the example VM with the four required arguments, then `extra`."""
        return self.run(*BASE, *extra, **env)

    def snapshot(self) -> dict[str, bytes]:
        """Every file of the fake root, to prove that a run changed nothing."""
        return {
            str(p.relative_to(self.root)): p.read_bytes()
            for p in sorted(self.root.rglob("*"))
            if p.is_file()
        }


BASE = (
    "--vmid",
    VMID,
    "--gateway",
    "192.0.2.1",
    "--admin-port",
    "2200",
    "--admin-from",
    "198.51.100.0/24",
)
FULL = (
    *BASE,
    "--allow-out",
    "192.0.2.53",
    "--private-port",
    "8443",
    "--private-port",
    "8444",
    "--private-from",
    "192.0.2.10",
    "--private-from-admin",
)
FULL_RULES = [
    "OUT ACCEPT -dest 192.0.2.1",
    "OUT ACCEPT -dest 192.0.2.53",
    *[f"OUT DROP -dest {r}" for r in PRIVATE.split()],
    "IN ACCEPT -source 198.51.100.0/24 -p tcp -dport 2200",
    "IN DROP -p tcp -dport 2200",
    "IN ACCEPT -source 192.0.2.10 -p tcp -dport 8443",
    "IN ACCEPT -source 198.51.100.0/24 -p tcp -dport 8443",
    "IN DROP -p tcp -dport 8443",
    "IN ACCEPT -source 192.0.2.10 -p tcp -dport 8444",
    "IN ACCEPT -source 198.51.100.0/24 -p tcp -dport 8444",
    "IN DROP -p tcp -dport 8444",
]


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def box(tmp_path: Path) -> Box:
    shim = tmp_path / "shim"
    root = tmp_path / "root"
    shim.mkdir()
    (root / "etc/pve/firewall").mkdir(parents=True)
    (root / "etc/pve/.version").write_text("1\n")
    # Neighbours of the VM file that the script must never touch.
    (root / "etc/pve/firewall/cluster.fw").write_text("[OPTIONS]\n\nenable: 0\n")
    (root / "etc/pve/nodes").mkdir()
    (root / "etc/pve/nodes/host.fw").write_text("[OPTIONS]\n\nenable: 1\n")
    for name, text in {
        "id": ID_SHIM,
        "pve-firewall": PVE_FIREWALL_SHIM,
        "qm": QM_SHIM,
        "pvesh": PVESH_SHIM,
    }.items():
        _write_exec(shim / name, text)
    env = {
        "PATH": f"{shim}:{PATH}",
        "HOME": str(tmp_path),
        "LANG": "C",
        "SHIM_DIR": str(shim),
        "SHIM_LOG": str(shim / "calls.log"),
        "SHIM_NIC": NIC,
        "SUCKERPOT_PVE_ROOT": str(root),
    }
    return Box(tmp_path, root, shim, env)


def generated(out: str) -> str:
    """The generated file, as printed between the two headings."""
    start = out.index("== Generated")
    body = out[out.index("\n", start) + 1 : out.index("== Difference")]
    return body.rstrip("\n") + "\n"


def rules(text: str) -> list[str]:
    """The rules of a VM file, without their comments, in order."""
    section = ""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
        elif line and section == "[RULES]":
            out.append(line.split(" #", 1)[0])
    return out


def options(text: str) -> list[str]:
    section = ""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
        elif line and section == "[OPTIONS]":
            out.append(line)
    return out


OLD = f"[OPTIONS]\n\nenable: 1\n\n[RULES]\n\nIN ACCEPT -p tcp -dport 80 {MARK} old\n"
FOREIGN = (
    "[OPTIONS]\n\nenable: 1\nlog_level_in: info\npolicy_in: DROP\n\n"
    "[RULES]\n\nIN ACCEPT -p tcp -dport 9090 # mine\n\n[ALIASES]\n\nlan 192.0.2.0/24\n"
)


# ---------------------------------------------------------------- what it generates
def test_help_needs_no_root_and_no_proxmox(box: Box) -> None:
    proc = box.run("--help", SHIM_UID="1000")
    assert proc.returncode == 0
    assert "--admin-port N" in proc.stdout
    assert "Exit codes" in proc.stdout
    assert "SUCKERPOT_PVE_ROOT is for the tests only" in proc.stdout


def test_a_full_example_in_the_right_order(box: Box) -> None:
    proc = box.vm(*FULL[len(BASE) :])
    assert proc.returncode == 0, proc.stderr
    text = generated(proc.stdout)
    assert options(text) == [
        "enable: 1",
        "policy_in: ACCEPT",
        "policy_out: ACCEPT",
        "macfilter: 1",
    ]
    assert rules(text) == FULL_RULES
    # Every rule says why it is there, and the options come first.
    rule_lines = [ln for ln in text.splitlines() if re.match(r"^(IN|OUT) ", ln)]
    assert len(rule_lines) == len(FULL_RULES)
    assert all(f" {MARK} " in ln for ln in rule_lines)
    assert text.index("[OPTIONS]") < text.index("[RULES]")
    # fe80::/10 must stay reachable (neighbour discovery) and ipfilter must not be set.
    assert "fe80" not in text
    assert "ipfilter" not in text


def test_the_minimal_file_has_no_private_port_rules(box: Box) -> None:
    proc = box.vm()
    assert proc.returncode == 0
    assert rules(generated(proc.stdout)) == [
        "OUT ACCEPT -dest 192.0.2.1",
        *[f"OUT DROP -dest {r}" for r in PRIVATE.split()],
        "IN ACCEPT -source 198.51.100.0/24 -p tcp -dport 2200",
        "IN DROP -p tcp -dport 2200",
    ]


def test_ipv6_addresses_and_repeated_sources(box: Box) -> None:
    proc = box.run(
        *("--vmid", VMID, "--gateway", "2001:db8::1", "--admin-port", "2200"),
        *("--admin-from", "2001:db8:1::/48", "--allow-out", "2001:db8::53"),
        *("--private-port", "8443", "--private-from", "192.0.2.10"),
        *("--private-from", "192.0.2.11", "--private-from", "192.0.2.10"),
    )
    assert proc.returncode == 0, proc.stderr
    got = rules(generated(proc.stdout))
    assert got[0] == "OUT ACCEPT -dest 2001:db8::1"
    assert got[1] == "OUT ACCEPT -dest 2001:db8::53"
    assert "IN ACCEPT -source 2001:db8:1::/48 -p tcp -dport 2200" in got
    # The tunnel host is listed once, in the order it was given.
    assert got[-3:] == [
        "IN ACCEPT -source 192.0.2.10 -p tcp -dport 8443",
        "IN ACCEPT -source 192.0.2.11 -p tcp -dport 8443",
        "IN DROP -p tcp -dport 8443",
    ]


# ---------------------------------------------------------------- arguments
@pytest.mark.parametrize(
    "drop",
    ["--vmid", "--gateway", "--admin-port", "--admin-from"],
)
def test_the_four_required_arguments(box: Box, drop: str) -> None:
    args = list(BASE)
    i = args.index(drop)
    del args[i : i + 2]
    proc = box.run(*args)
    assert proc.returncode == 2
    assert drop in proc.stderr
    assert "required" in proc.stderr


@pytest.mark.parametrize(
    "bad",
    [
        "198.51.100.0/33",
        "198.51.100.0/0",
        "::/0",
        "300.1.1.1",
        "198.51.100.0/24/1",
        "198.51.100.0/",
        "198.51.100.0/024",
        "198.51.100",
        "192.0.2.01",
        "2001:db8::g/64",
        "2001:db8::/129",
        "example.org",
        "198.51.100.0/24 ",
        "$(id)",
    ],
)
def test_a_bad_admin_source_is_refused(box: Box, bad: str) -> None:
    proc = box.run(*BASE[:-1], bad)
    assert proc.returncode == 2
    assert "--admin-from" in proc.stderr
    assert not box.vmfw.exists()


@pytest.mark.parametrize(
    "bad", ["0", "65536", "abc", "022", "-1", "22x", "", "70000", "2200 ", "1e3"]
)
def test_a_bad_port_is_refused(box: Box, bad: str) -> None:
    proc = box.run(*BASE[:5], bad, *BASE[6:])
    assert proc.returncode == 2
    assert "--admin-port" in proc.stderr
    proc = box.vm("--private-port", bad, "--private-from", "192.0.2.10")
    assert proc.returncode == 2
    assert "--private-port" in proc.stderr


@pytest.mark.parametrize("bad", ["12", "abc", "0", "1000000000", "10 2", "-102", "102.0"])
def test_a_bad_vmid_is_refused(box: Box, bad: str) -> None:
    proc = box.run("--vmid", bad, *BASE[2:])
    assert proc.returncode == 2
    assert "--vmid" in proc.stderr


@pytest.mark.parametrize("bad", ["192.0.2.0/24", "192.0.2", "gateway", "::g", "1.2.3.4.5"])
def test_the_gateway_is_one_address(box: Box, bad: str) -> None:
    proc = box.run(*BASE[:3], bad, *BASE[4:])
    assert proc.returncode == 2
    assert "--gateway" in proc.stderr


@pytest.mark.parametrize(
    "ok",
    [
        "::",
        "::1",
        "2001:db8::",
        "2001:db8::1",
        "2001:DB8:0:0:0:0:0:1",
        "1:2:3:4:5:6:7::",
        "::2:3:4:5:6:7:8",
        "::ffff:192.0.2.1",
        "64:ff9b::192.0.2.33",
        "1:2:3:4:5:6:192.0.2.1",
        "fe80::1",
    ],
)
def test_ipv6_forms_that_are_valid(box: Box, ok: str) -> None:
    proc = box.run(*BASE[:3], ok, *BASE[4:])
    assert proc.returncode == 0, proc.stderr
    assert f"-dest {ok}" in proc.stdout


@pytest.mark.parametrize(
    "bad",
    [
        "2001:db8:::1",
        "2001:db8::1::2",
        "2001:db8",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7:8::",
        "12345::",
        "2001:db8::1:",
        ":2001:db8::1",
        "1.2.3.4::",
        "::1.2.3",
        "::ffff:192.0.2.256",
        "fe80::1%eth0",
        "1:2:3:4:5:6:7",
    ],
)
def test_ipv6_forms_that_are_not(box: Box, bad: str) -> None:
    proc = box.run(*BASE[:3], bad, *BASE[4:])
    assert proc.returncode == 2, proc.stdout
    assert "--gateway" in proc.stderr


def test_the_admin_port_cannot_be_a_private_port(box: Box) -> None:
    proc = box.vm("--private-port", "2200", "--private-from", "192.0.2.10")
    assert proc.returncode == 2
    assert "is the admin port" in proc.stderr


@pytest.mark.parametrize("port", ["22", "80", "443", "445", "3389", "5060", "6379"])
def test_a_sensor_port_is_refused(box: Box, port: str) -> None:
    proc = box.vm("--private-port", port, "--private-from", "192.0.2.10")
    assert proc.returncode == 2
    assert "sensor port" in proc.stderr
    proc = box.run(*BASE[:5], port, *BASE[6:])
    assert proc.returncode == 2
    assert "sensor port" in proc.stderr


def test_a_private_port_needs_someone_to_reach_it(box: Box) -> None:
    proc = box.vm("--private-port", "8443")
    assert proc.returncode == 2
    assert "--private-from" in proc.stderr
    proc = box.vm("--private-from", "192.0.2.10")
    assert proc.returncode == 2
    assert "--private-port" in proc.stderr
    assert box.vm("--private-port", "8443", "--private-from-admin").returncode == 0


def test_nothing_is_open_to_everyone(box: Box) -> None:
    for option in ("--allow-out", "--private-from"):
        extra = ["--private-port", "8443"] if option == "--private-from" else []
        proc = box.vm(*extra, option, "0.0.0.0/0")
        assert proc.returncode == 2
        assert "every address" in proc.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["--force"],
        ["--vmid", "103"],
        ["--allow-out"],
        ["--set-nic-firewall"],
    ],
)
def test_other_bad_arguments(box: Box, args: list[str]) -> None:
    proc = box.vm(*args)
    assert proc.returncode == 2
    assert "see --help" in proc.stderr


@pytest.mark.parametrize(
    "extra",
    [
        ["--gateway", "192.0.2.1"],
        ["--admin-port", "2200"],
        ["--apply"],
        ["--replace"],
        ["--set-nic-firewall"],
        ["--private-from-admin"],
    ],
)
def test_undo_takes_only_the_vmid(box: Box, extra: list[str]) -> None:
    proc = box.run("--undo", "--vmid", VMID, *extra)
    assert proc.returncode == 2
    assert "--undo takes only --vmid" in proc.stderr


def test_the_script_asks_for_no_default_admin_port(box: Box) -> None:
    proc = box.run(*[a for a in BASE if a not in ("--admin-port", "2200")])
    assert proc.returncode == 2
    assert "scripts/move-admin-ssh.sh" in proc.stderr


def test_a_python3_that_refuses_a_value_is_listened_to(box: Box) -> None:
    _write_exec(box.shim / "python3", "#!/bin/sh\necho bad\n")
    proc = box.vm()
    assert proc.returncode == 2
    assert "not an IPv4 or IPv6 address" in proc.stderr
    # A python3 that fails to run changes nothing.
    _write_exec(box.shim / "python3", "#!/bin/sh\nexit 1\n")
    assert box.vm().returncode == 0
    _write_exec(box.shim / "python3", "#!/bin/sh\necho ok\n")
    assert box.vm().returncode == 0


# ---------------------------------------------------------------- the dry run
def test_a_dry_run_changes_nothing(box: Box) -> None:
    box.vmfw.write_text(OLD)
    before = box.snapshot()
    proc = box.vm(*FULL[len(BASE) :], SHIM_UID="1000")
    assert proc.returncode == 0, proc.stderr
    assert box.snapshot() == before
    assert not box.bakdir.exists()
    assert not any(c.startswith(("qm set", "pvesh set")) for c in box.calls())
    assert "dry run" in proc.stderr
    # The difference is against the current file.
    assert "(current)" in proc.stdout
    assert "-IN ACCEPT -p tcp -dport 80" in proc.stdout
    assert "+OUT ACCEPT -dest 192.0.2.1" in proc.stdout


def test_a_dry_run_says_when_the_file_is_new(box: Box) -> None:
    proc = box.vm()
    assert proc.returncode == 0
    assert "new file" in proc.stdout
    assert not box.vmfw.exists()


def test_a_dry_run_runs_anywhere(box: Box) -> None:
    for tool in ("pve-firewall", "qm", "pvesh"):
        (box.shim / tool).unlink()
    (box.root / "etc/pve/.version").unlink()
    proc = box.vm(SHIM_UID="1000")
    assert proc.returncode == 0
    assert "not a Proxmox node" in proc.stderr


def test_a_dry_run_shows_what_it_would_drop(box: Box) -> None:
    box.vmfw.write_text(FOREIGN)
    proc = box.vm()
    assert proc.returncode == 0
    assert "not generated by this script" in proc.stdout
    for line in (
        "[OPTIONS] log_level_in: info",
        "[OPTIONS] policy_in: DROP",
        "[RULES] IN ACCEPT -p tcp -dport 9090 # mine",
        "[ALIASES] lan 192.0.2.0/24",
    ):
        assert line in proc.stdout
    assert "--replace" in proc.stdout
    assert box.vmfw.read_text() == FOREIGN


# ---------------------------------------------------------------- --apply
def test_apply_writes_a_new_file_and_checks_it(box: Box) -> None:
    proc = box.vm(*FULL[len(BASE) :], "--apply")
    assert proc.returncode == 0, proc.stderr
    new = box.vmfw.read_text()
    assert new == generated(proc.stdout)
    assert rules(new) == FULL_RULES
    # The check saw the new file, then `pve-firewall status` is printed.
    assert (box.shim / "compile-1.fw").read_text() == new
    assert "Status: enabled/running" in proc.stdout
    # There was no file before: the backup is an empty marker, and nothing is left behind.
    (marker,) = box.backups()
    assert re.fullmatch(rf"{VMID}-\d{{8}}T\d{{6}}Z\.absent", marker.name)
    assert marker.read_text() == ""
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert stat.S_IMODE(box.bakdir.stat().st_mode) == 0o700
    assert sorted(p.name for p in box.fwdir.iterdir()) == ["102.fw", "cluster.fw"]


def test_apply_never_touches_the_datacenter_or_node_firewall(box: Box) -> None:
    cluster = (box.fwdir / "cluster.fw").read_bytes()
    node = (box.root / "etc/pve/nodes/host.fw").read_bytes()
    assert box.vm("--apply", SHIM_DC_JSON="{}").returncode == 0
    assert (box.fwdir / "cluster.fw").read_bytes() == cluster
    assert (box.root / "etc/pve/nodes/host.fw").read_bytes() == node
    assert not any(c.startswith("pvesh set") for c in box.calls())


def test_apply_backs_up_the_current_file(box: Box) -> None:
    box.vmfw.write_text(OLD)
    proc = box.vm("--apply")
    assert proc.returncode == 0, proc.stderr
    (backup,) = box.backups()
    assert re.fullmatch(rf"{VMID}-\d{{8}}T\d{{6}}Z\.fw", backup.name)
    assert backup.read_text() == OLD
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert box.vmfw.read_text() == generated(proc.stdout)
    assert str(backup) in proc.stderr


def test_a_file_the_gui_made_or_an_earlier_run_wrote_is_not_foreign(box: Box) -> None:
    # `enable: 1` alone is what the web UI writes; the rule is one of ours (its comment says so).
    box.vmfw.write_text(OLD)
    assert box.vm("--apply").returncode == 0
    box.vmfw.write_text("[OPTIONS]\n\nenable: 1\n")
    assert box.vm("--apply").returncode == 0


def test_apply_refuses_what_it_did_not_generate(box: Box) -> None:
    box.vmfw.write_text(FOREIGN)
    proc = box.vm("--apply")
    assert proc.returncode == 4
    assert "--replace" in proc.stderr
    assert "[RULES] IN ACCEPT -p tcp -dport 9090 # mine" in proc.stdout
    assert box.vmfw.read_text() == FOREIGN
    assert box.backups() == []
    assert not any(c.endswith("compile") for c in box.calls())


def test_replace_drops_them_after_a_backup(box: Box) -> None:
    box.vmfw.write_text(FOREIGN)
    proc = box.vm("--apply", "--replace")
    assert proc.returncode == 0, proc.stderr
    assert "mine" not in box.vmfw.read_text()
    (backup,) = box.backups()
    assert backup.read_text() == FOREIGN


def test_a_changed_option_value_is_foreign(box: Box) -> None:
    box.vmfw.write_text("[OPTIONS]\n\nenable: 1\npolicy_in: DROP\n")
    assert box.vm("--apply").returncode == 4


def test_apply_when_nothing_changes_writes_nothing(box: Box) -> None:
    first = box.vm("--apply")
    assert first.returncode == 0
    before = box.snapshot()
    proc = box.vm("--apply")
    assert proc.returncode == 0
    assert "already matches" in proc.stderr
    assert box.snapshot() == before


def test_apply_puts_the_old_file_back_when_the_check_fails(box: Box) -> None:
    box.vmfw.write_text(OLD)
    proc = box.vm("--apply", SHIM_COMPILE_FAIL="new")
    assert proc.returncode == 5
    assert "rolled back" in proc.stderr
    assert box.vmfw.read_text() == OLD
    (backup,) = box.backups()
    assert backup.read_text() == OLD
    # The check that failed ran on the new file.
    assert "OUT ACCEPT -dest 192.0.2.1" in (box.shim / "compile-1.fw").read_text()
    assert sorted(p.name for p in box.fwdir.iterdir()) == ["102.fw", "cluster.fw"]


def test_apply_removes_a_new_file_when_the_check_fails(box: Box) -> None:
    proc = box.vm("--apply", SHIM_COMPILE_FAIL="new")
    assert proc.returncode == 5
    assert not box.vmfw.exists()
    assert "syntax error" in proc.stderr


def test_a_complaint_about_the_file_is_a_failed_check(box: Box) -> None:
    box.vmfw.write_text(OLD)
    proc = box.vm("--apply", SHIM_COMPILE_WARN="1")
    assert proc.returncode == 5
    assert box.vmfw.read_text() == OLD


@pytest.mark.parametrize(
    ("missing", "code"),
    [("pve-firewall", 3), ("qm", 3), ("pvesh", 3)],
)
def test_apply_needs_the_proxmox_tools(box: Box, missing: str, code: int) -> None:
    (box.shim / missing).unlink()
    proc = box.vm("--apply")
    assert proc.returncode == code
    assert missing in proc.stderr
    assert not box.vmfw.exists()


def test_apply_needs_a_mounted_etc_pve(box: Box) -> None:
    (box.root / "etc/pve/.version").unlink()
    proc = box.vm("--apply")
    assert proc.returncode == 3
    assert "not mounted" in proc.stderr
    assert not box.vmfw.exists()


def test_apply_needs_root(box: Box) -> None:
    proc = box.vm("--apply", SHIM_UID="1000")
    assert proc.returncode == 4
    assert "root" in proc.stderr
    assert not box.vmfw.exists()
    assert box.backups() == []


def test_apply_needs_the_vm_to_exist(box: Box) -> None:
    proc = box.vm("--apply", SHIM_QM_MISSING="1")
    assert proc.returncode == 4
    assert "not found" in proc.stderr
    assert not box.vmfw.exists()
    # A dry run only warns.
    dry = box.vm(SHIM_QM_MISSING="1")
    assert dry.returncode == 0
    assert "not found" in dry.stderr


# ---------------------------------------------------------------- --undo
def _backup(box: Box, stamp: str, text: str | None) -> Path:
    box.bakdir.mkdir(parents=True, exist_ok=True)
    path = box.bakdir / f"{VMID}-{stamp}.{'absent' if text is None else 'fw'}"
    path.write_text(text or "")
    path.chmod(0o600)
    return path


def test_undo_restores_the_most_recent_backup(box: Box) -> None:
    _backup(box, "20261101T000000Z", "[OPTIONS]\n\nenable: 0\n")
    newest = "[OPTIONS]\n\nenable: 1\nlog_level_in: info\n"
    _backup(box, "20261102T000000Z", newest)
    box.vmfw.write_text("[OPTIONS]\n\nenable: 1\npolicy_in: DROP\n")
    proc = box.run("--undo", "--vmid", VMID)
    assert proc.returncode == 0, proc.stderr
    assert box.vmfw.read_text() == newest
    assert (box.shim / "compile-1.fw").read_text() == newest
    assert "Status: enabled/running" in proc.stdout
    # The file it replaced is kept, apart from the numbered backups.
    (kept,) = box.bakdir.glob("*-before-undo.fw")
    assert kept.read_text() == "[OPTIONS]\n\nenable: 1\npolicy_in: DROP\n"
    assert stat.S_IMODE(kept.stat().st_mode) == 0o600
    # A second --undo does not undo the undo: it still means "the newest numbered backup".
    box.vmfw.write_text("[OPTIONS]\n\nenable: 1\n")
    assert box.run("--undo", "--vmid", VMID).returncode == 0
    assert box.vmfw.read_text() == newest


def test_undo_twice_in_a_row_is_a_no_op(box: Box) -> None:
    _backup(box, "20261102T000000Z", "[OPTIONS]\n\nenable: 1\n")
    box.vmfw.write_text("[OPTIONS]\n\nenable: 0\n")
    assert box.run("--undo", "--vmid", VMID).returncode == 0
    before = box.snapshot()
    proc = box.run("--undo", "--vmid", VMID)
    assert proc.returncode == 0
    assert "nothing to do" in proc.stderr
    assert box.snapshot() == before


def test_undo_after_the_first_apply_removes_the_file(box: Box) -> None:
    assert box.vm("--apply").returncode == 0
    assert box.vmfw.exists()
    proc = box.run("--undo", "--vmid", VMID)
    assert proc.returncode == 0, proc.stderr
    assert not box.vmfw.exists()


def test_undo_after_an_apply_brings_the_old_file_back(box: Box) -> None:
    box.vmfw.write_text(OLD)
    assert box.vm("--apply").returncode == 0
    assert box.vmfw.read_text() != OLD
    assert box.run("--undo", "--vmid", VMID).returncode == 0
    assert box.vmfw.read_text() == OLD


def test_undo_with_no_backup(box: Box) -> None:
    proc = box.run("--undo", "--vmid", VMID)
    assert proc.returncode == 4
    assert "nothing to undo" in proc.stderr
    # Another VM's backup, and a file of another shape, do not count.
    _backup(box, "20261102T000000Z", "[OPTIONS]\n\nenable: 1\n").rename(
        box.bakdir / "103-20261102T000000Z.fw"
    )
    (box.bakdir / f"{VMID}-notes.fw").write_text("x")
    assert box.run("--undo", "--vmid", VMID).returncode == 4


def test_undo_is_rolled_back_when_its_check_fails(box: Box) -> None:
    _backup(box, "20261102T000000Z", "[OPTIONS]\n\nenable: 1\n")
    current = "[OPTIONS]\n\nenable: 0\n"
    box.vmfw.write_text(current)
    proc = box.run("--undo", "--vmid", VMID, SHIM_COMPILE_FAIL="always")
    assert proc.returncode == 5
    assert "rolled back" in proc.stderr
    assert box.vmfw.read_text() == current


def test_undo_needs_root_and_a_node(box: Box) -> None:
    _backup(box, "20261102T000000Z", "[OPTIONS]\n\nenable: 1\n")
    assert box.run("--undo", "--vmid", VMID, SHIM_UID="1000").returncode == 4
    (box.shim / "qm").unlink()
    assert box.run("--undo", "--vmid", VMID).returncode == 3


# ---------------------------------------------------------------- warnings
def test_a_disabled_datacenter_firewall_is_a_warning(box: Box) -> None:
    for state in ("{}", '{"enable":0}'):
        proc = box.vm(SHIM_DC_JSON=state)
        assert proc.returncode == 0
        assert "datacenter firewall is disabled" in proc.stderr
        assert "pvesh set /cluster/firewall/options --enable 1" in proc.stderr
        assert "policy_in" in proc.stderr
        assert "8006" in proc.stderr
        assert "never changes it" in proc.stderr
    on = box.vm(SHIM_DC_JSON='{"enable":1,"policy_in":"DROP"}')
    assert "datacenter firewall" not in on.stderr
    # Applying still works: it only warns.
    assert box.vm("--apply", SHIM_DC_JSON="{}").returncode == 0
    assert not any(c.startswith("pvesh set") for c in box.calls())


def test_an_unreadable_datacenter_setting_is_a_warning(box: Box) -> None:
    proc = box.vm(SHIM_PVESH_RC="1")
    assert proc.returncode == 0
    assert "could not read the datacenter firewall" in proc.stderr


def test_a_nic_without_firewall_gets_the_exact_command(box: Box) -> None:
    config = f"name: vm-test\nnet0: {NIC}\nnet1: virtio=02:00:00:00:00:02,bridge=vmbr1,firewall=0\n"
    config += "net2: virtio=02:00:00:00:00:03,bridge=vmbr2,firewall=1\n"
    proc = box.vm(SHIM_QM_CONFIG=config)
    assert proc.returncode == 0
    assert f"qm set {VMID} --net0 {NIC},firewall=1" in proc.stderr
    assert f"qm set {VMID} --net1 virtio=02:00:00:00:00:02,bridge=vmbr1,firewall=1" in proc.stderr
    assert "--net2" not in proc.stderr
    assert not any(c.startswith("qm set") for c in box.calls())


def test_apply_prints_the_nic_command_but_does_not_run_it(box: Box) -> None:
    proc = box.vm("--apply", SHIM_QM_CONFIG=f"net0: {NIC}")
    assert proc.returncode == 0
    assert f"qm set {VMID} --net0 {NIC},firewall=1" in proc.stderr
    assert not any(c.startswith("qm set") for c in box.calls())


def test_a_nic_with_firewall_has_no_warning(box: Box) -> None:
    proc = box.vm()
    assert "firewall=1 or its rules" not in proc.stderr


def test_set_nic_firewall_runs_qm_set_after_the_file(box: Box) -> None:
    config = f"net0: {NIC},firewall=0,tag=7"
    proc = box.vm("--apply", "--set-nic-firewall", SHIM_QM_CONFIG=config)
    assert proc.returncode == 0, proc.stderr
    calls = box.calls()
    assert f"qm set {VMID} --net0 {NIC},tag=7,firewall=1" in calls
    assert calls.index("pve-firewall compile") < calls.index(
        f"qm set {VMID} --net0 {NIC},tag=7,firewall=1"
    )


def test_a_failed_qm_set_leaves_the_file_and_says_so(box: Box) -> None:
    proc = box.vm(
        "--apply", "--set-nic-firewall", SHIM_QM_CONFIG=f"net0: {NIC}", SHIM_QM_SET_RC="1"
    )
    assert proc.returncode == 5
    assert "do nothing until the NIC has firewall=1" in proc.stderr
    assert box.vmfw.exists()


# ---------------------------------------------------------------- the script itself
def test_the_script_never_writes_the_datacenter_firewall() -> None:
    text = SCRIPT.read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    # It reads the setting through pvesh, and `target` is the only file it writes.
    assert "cluster.fw" not in code
    assert "host.fw" not in code
    # The one `pvesh set` in the script is the advice printed to the owner, never a call.
    writes = [
        ln.strip() for ln in code.splitlines() if re.search(r"pvesh\s+(set|create|delete)", ln)
    ]
    assert writes == ["pvesh set /cluster/firewall/options --enable 1"]
    assert sum("pvesh get /cluster/firewall/options" in ln for ln in code.splitlines()) == 1
    assert "sed -i" not in code
    assert "eval " not in code
    assert text.splitlines()[0] == "#!/usr/bin/env bash"
    assert "set -euo pipefail" in text


def test_the_script_has_no_default_admin_port() -> None:
    # The default of scripts/move-admin-ssh.sh stays out of this script and its docs.
    default = "2" * 5
    assert default not in SCRIPT.read_text()
    for doc in (ROOT / "scripts/host/README.md", ROOT / "docs/deployment.md"):
        assert default not in doc.read_text()


def test_the_sensor_ports_match_the_env_example() -> None:
    env = (ROOT / ".env.example").read_text()
    wanted = {m for m in re.findall(r"^[A-Z_]*HOST_PORT=(\d+)$", env, re.MULTILINE)}
    listed = re.search(r'^SENSOR_PORTS="([0-9 ]+)"', SCRIPT.read_text(), re.MULTILINE)
    assert listed is not None
    assert set(listed.group(1).split()) == wanted
