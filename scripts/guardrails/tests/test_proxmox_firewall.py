"""scripts/host/proxmox-firewall.sh: the Proxmox VE firewall file of the SuckerPot VM.

The script runs against a fake root (SUCKERPOT_PVE_ROOT) with fake `id`, `pve-firewall`, `qm` and
`pvesh` first on PATH. The fakes only record their calls and answer from environment variables;
there is no Proxmox here and nothing under the real /etc/pve is ever read or written.
Every address is from a documentation range.
"""

import ipaddress
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "host" / "proxmox-firewall.sh"
PATH = "/usr/local/bin:/usr/bin:/bin"
VMID = "210"
MARK = "# SuckerPot:"
NIC = "virtio=02:00:00:00:00:01,bridge=vmbr0"
# The private ranges every VM file must drop, in this order (the point of the test).
PRIVATE = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 fc00::/7"  # gitleaks:allow (private ranges are the point of the rule)
# An --allow-out that covers a whole private range (warned about), and ones inside a range (not).
COVERING = "192.168.0.0/16 192.168.0.0/15 10.0.0.0/8 10.0.0.0/7 172.16.0.0/12 100.64.0.0/10 169.254.0.0/16"  # gitleaks:allow (private ranges are the point of the test)
INSIDE = "192.168.0.0/24 10.1.0.0/16 172.16.0.0/16 192.168.0.0/17"  # gitleaks:allow (private ranges are the point of the test)

ID_SHIM = '#!/bin/sh\necho "id $*" >> "$SHIM_LOG"\necho "${SHIM_UID:-0}"\n'

# `compile` keeps a copy of the VM file as it was when it ran, and fails on demand:
#   SHIM_COMPILE_FAIL=new     fails while the file holds a rule written by the script
#   SHIM_COMPILE_FAIL=always  fails every time
#   SHIM_COMPILE_WARN=1       exits 0 but names a file on stderr while the VM file holds such a rule
#                             (SHIM_COMPILE_WARN_NAME: which file, default the VM's own)
PVE_FIREWALL_SHIM = r"""#!/bin/sh
echo "pve-firewall $*" >> "$SHIM_LOG"
vmfw="$SUCKERPOT_PVE_ROOT/etc/pve/firewall/210.fw"
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
      echo "${SHIM_COMPILE_WARN_NAME:-/etc/pve/firewall/210.fw} (line 9): unknown option" >&2
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

    def stack(self) -> list[Path]:
        """The numbered backups, oldest first: the steps --undo goes back through."""
        return [p for p in self.backups() if "before-undo" not in p.name]

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
    "192.0.2.50",
    "--private-from-admin",
)
DHCP = ["OUT DROP -p udp -dport 68", "OUT DROP -p udp -dport 546"]
GATEWAY = [
    "OUT ACCEPT -dest 192.0.2.1 -p udp -dport 53",
    "OUT ACCEPT -dest 192.0.2.1 -p tcp -dport 53",
]
PRIVATE_DROPS = [f"OUT DROP -dest {r}" for r in PRIVATE.split()]
LINK_LOCAL = ["OUT DROP -dest fe80::/10 -p tcp", "OUT DROP -dest fe80::/10 -p udp"]
ADMIN = ["IN ACCEPT -source 198.51.100.0/24 -p tcp -dport 2200", "IN DROP -p tcp -dport 2200"]
FULL_RULES = [
    *DHCP,
    *GATEWAY,
    "OUT ACCEPT -dest 192.0.2.53",
    *PRIVATE_DROPS,
    *LINK_LOCAL,
    *ADMIN,
    "IN ACCEPT -source 192.0.2.50 -p tcp -dport 8443",
    "IN ACCEPT -source 198.51.100.0/24 -p tcp -dport 8443",
    "IN DROP -p tcp -dport 8443",
    "IN ACCEPT -source 192.0.2.50 -p tcp -dport 8444",
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
    # No ipfilter option ever, and no set without --vm-addr.
    assert "ipfilter" not in text
    assert "[IPSET" not in text


def test_the_minimal_file_has_no_private_port_rules(box: Box) -> None:
    proc = box.vm()
    assert proc.returncode == 0
    assert rules(generated(proc.stdout)) == [
        *DHCP,
        *GATEWAY,
        *PRIVATE_DROPS,
        *LINK_LOCAL,
        *ADMIN,
    ]


def test_the_gateway_answers_dns_only_by_default(box: Box) -> None:
    got = rules(generated(box.vm().stdout))
    gateway_rules = [r for r in got if "192.0.2.1" in r]
    assert gateway_rules == GATEWAY
    # No rule opens every port of the gateway.
    assert "OUT ACCEPT -dest 192.0.2.1" not in got


def test_gateway_all_opens_every_port_of_the_gateway(box: Box) -> None:
    proc = box.vm("--gateway-all")
    assert proc.returncode == 0, proc.stderr
    got = rules(generated(proc.stdout))
    assert got == [*DHCP, "OUT ACCEPT -dest 192.0.2.1", *PRIVATE_DROPS, *LINK_LOCAL, *ADMIN]


def test_dhcp_server_replies_are_dropped_before_any_accept(box: Box) -> None:
    for extra in ([], ["--gateway-all", "--allow-out", "192.0.2.53"]):
        got = rules(generated(box.vm(*extra).stdout))
        assert got[:2] == DHCP
        assert not any(r.startswith("OUT ACCEPT") for r in got[:2])


def test_ipv6_link_local_loses_tcp_and_udp_but_not_icmpv6(box: Box) -> None:
    got = rules(generated(box.vm().stdout))
    assert [r for r in got if "fe80" in r] == LINK_LOCAL
    # Both come after the accepts (an IPv6 gateway may be link-local) and the private drops, and
    # no rule drops fe80::/10 whatever the protocol: that would break neighbour discovery.
    assert got.index(LINK_LOCAL[0]) > got.index(PRIVATE_DROPS[-1])
    assert "OUT DROP -dest fe80::/10" not in got


def test_ipv6_addresses_and_repeated_sources(box: Box) -> None:
    proc = box.run(
        *("--vmid", VMID, "--gateway", "2001:db8::1", "--admin-port", "2200"),
        *("--admin-from", "2001:db8:1::/48", "--allow-out", "2001:db8::53"),
        *("--private-port", "8443", "--private-from", "192.0.2.50"),
        *("--private-from", "192.0.2.51", "--private-from", "192.0.2.50"),
    )
    assert proc.returncode == 0, proc.stderr
    got = rules(generated(proc.stdout))
    assert got[2] == "OUT ACCEPT -dest 2001:db8::1 -p udp -dport 53"
    assert "OUT ACCEPT -dest 2001:db8::53" in got
    assert "IN ACCEPT -source 2001:db8:1::/48 -p tcp -dport 2200" in got
    # The tunnel host is listed once, in the order it was given.
    assert got[-3:] == [
        "IN ACCEPT -source 192.0.2.50 -p tcp -dport 8443",
        "IN ACCEPT -source 192.0.2.51 -p tcp -dport 8443",
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
    proc = box.vm("--private-port", bad, "--private-from", "192.0.2.50")
    assert proc.returncode == 2
    assert "--private-port" in proc.stderr


@pytest.mark.parametrize("bad", ["12", "abc", "0", "1000000000", "10 2", "-210", "210.5"])
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
    proc = box.vm("--private-port", "2200", "--private-from", "192.0.2.50")
    assert proc.returncode == 2
    assert "is the admin port" in proc.stderr


@pytest.mark.parametrize("port", ["22", "80", "443", "445", "3389", "5060", "6379"])
def test_a_sensor_port_is_refused(box: Box, port: str) -> None:
    proc = box.vm("--private-port", port, "--private-from", "192.0.2.50")
    assert proc.returncode == 2
    assert "sensor port" in proc.stderr
    proc = box.run(*BASE[:5], port, *BASE[6:])
    assert proc.returncode == 2
    assert "sensor port" in proc.stderr


def test_a_private_port_needs_someone_to_reach_it(box: Box) -> None:
    proc = box.vm("--private-port", "8443")
    assert proc.returncode == 2
    assert "--private-from" in proc.stderr
    proc = box.vm("--private-from", "192.0.2.50")
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
        ["--vmid", "211"],
        ["--allow-out"],
        ["--set-nic-firewall"],
        ["--vm-nic", "net0"],
        ["--vm-addr", "192.0.2.60", "--vm-nic", "eth0"],
        ["--vm-addr", "192.0.2.60", "--vm-nic", "net0", "--vm-nic", "net1"],
        ["--vm-addr", "192.0.2.0/23"],
        ["--vm-addr", "not-an-address"],
        ["--dns"],
        ["--dns", "192.0.2.53/24"],
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
        ["--gateway-all"],
        ["--vm-addr", "192.0.2.60"],
        ["--vm-nic", "net0"],
        ["--dns", "192.0.2.53"],
    ],
)
def test_undo_takes_only_the_vmid(box: Box, extra: list[str]) -> None:
    proc = box.run("--undo", "--vmid", VMID, *extra)
    assert proc.returncode == 2
    assert "--undo takes only --vmid" in proc.stderr


def test_a_source_wider_than_a_16_is_a_warning(box: Box) -> None:
    admin = box.run(*BASE[:-1], "198.51.0.0/15")
    assert admin.returncode == 0, admin.stderr
    assert "--admin-from 198.51.0.0/15 is wider than a /16" in admin.stderr
    tunnel = box.vm("--private-port", "8443", "--private-from", "198.51.0.0/15")
    assert tunnel.returncode == 0, tunnel.stderr
    assert "--private-from 198.51.0.0/15 is wider than a /16" in tunnel.stderr
    # A /16 and narrower are fine, and so is an IPv6 /48.
    assert (
        "wider than"
        not in box.vm("--private-port", "8443", "--private-from", "198.51.0.0/16").stderr
    )
    assert "wider than" not in box.vm().stderr
    assert "wider than" not in box.run(*BASE[:-1], "2001:db8:1::/48").stderr
    v6 = box.run(*BASE[:-1], "2001:db8::/32")
    assert "--admin-from 2001:db8::/32 is wider than a /48" in v6.stderr


@pytest.mark.parametrize("allow", COVERING.split())
def test_an_allow_out_that_covers_a_private_range_is_a_warning(box: Box, allow: str) -> None:
    proc = box.vm("--allow-out", allow)
    assert proc.returncode == 0, proc.stderr
    net = ipaddress.IPv4Network(allow)
    covered = [
        r for r in PRIVATE.split() if ":" not in r and net.supernet_of(ipaddress.IPv4Network(r))
    ]
    assert covered
    assert f"--allow-out {allow} covers the whole private range {covered[0]}" in proc.stderr


@pytest.mark.parametrize("allow", [*INSIDE.split(), "192.0.2.53"])
def test_an_allow_out_inside_a_private_range_is_not(box: Box, allow: str) -> None:
    proc = box.vm("--allow-out", allow)
    assert proc.returncode == 0, proc.stderr
    assert "covers the whole private range" not in proc.stderr
    assert "wider than" not in proc.stderr
    assert f"OUT ACCEPT -dest {allow}" in proc.stdout


def test_an_allow_out_wider_than_a_16_is_a_warning(box: Box) -> None:
    assert (
        "--allow-out 198.0.0.0/8 is wider than a /16" in box.vm("--allow-out", "198.0.0.0/8").stderr
    )


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
    assert "+OUT DROP -p udp -dport 68" in proc.stdout


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
    assert sorted(p.name for p in box.fwdir.iterdir()) == ["210.fw", "cluster.fw"]


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
    # A failed apply pushes nothing on the stack of backups.
    assert box.backups() == []
    # The check that failed ran on the new file.
    assert "OUT ACCEPT -dest 192.0.2.1" in (box.shim / "compile-1.fw").read_text()
    assert sorted(p.name for p in box.fwdir.iterdir()) == ["210.fw", "cluster.fw"]


def test_apply_removes_a_new_file_when_the_check_fails(box: Box) -> None:
    proc = box.vm("--apply", SHIM_COMPILE_FAIL="new")
    assert proc.returncode == 5
    assert not box.vmfw.exists()
    assert box.backups() == []
    assert "syntax error" in proc.stderr


@pytest.mark.parametrize(
    "name",
    ["/etc/pve/firewall/210.fw", "210.fw", "/etc/pve/firewall/210.fw:", "see 210.fw (line 3)"],
)
def test_a_complaint_about_the_file_is_a_failed_check(box: Box, name: str) -> None:
    box.vmfw.write_text(OLD)
    proc = box.vm("--apply", SHIM_COMPILE_WARN="1", SHIM_COMPILE_WARN_NAME=name)
    assert proc.returncode == 5
    assert box.vmfw.read_text() == OLD


@pytest.mark.parametrize(
    "name",
    [
        "/etc/pve/firewall/1210.fw",
        "/etc/pve/firewall/2210.fw",
        "/etc/pve/firewall/x210.fw",
        "/etc/pve/firewall/210.fw.tmp.4242",
        "/etc/pve/firewall/210.fwx",
        "/etc/pve/firewall/210-fw",
    ],
)
def test_a_complaint_about_another_file_is_not(box: Box, name: str) -> None:
    proc = box.vm("--apply", SHIM_COMPILE_WARN="1", SHIM_COMPILE_WARN_NAME=name)
    assert proc.returncode == 0, proc.stderr
    assert box.vmfw.read_text() == generated(proc.stdout)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write to a read-only folder")
@pytest.mark.parametrize("what", ["apply", "undo"])
def test_a_read_only_etc_pve_is_said_plainly(box: Box, what: str) -> None:
    box.vmfw.write_text(OLD)
    _backup(box, "20261104T000000Z", "[OPTIONS]\n\nenable: 1\n")
    before = box.snapshot()
    box.fwdir.chmod(0o555)
    try:
        proc = box.vm("--apply") if what == "apply" else box.run("--undo", "--vmid", VMID)
    finally:
        box.fwdir.chmod(0o755)
    assert proc.returncode == 5
    assert "read-only" in proc.stderr
    assert "quorum" in proc.stderr
    assert "Nothing was changed" in proc.stderr
    # Nothing was written, so nothing is claimed to be restored.
    assert "RESTORE FAILED" not in proc.stderr
    assert "rolled back" not in proc.stderr
    assert "back in place" not in proc.stderr
    assert box.snapshot() == before


# A `cat` that cuts the Nth read of a .fw file short, like a failing disk.
CAT_SHIM = r"""#!/bin/sh
# Only the script's copies count (cat -- FILE): first the one that reads the file to keep, then
# the one that makes the backup.
case "$1 $2" in
  "-- "*.fw)
    n=$(/bin/cat "$SHIM_DIR/cats" 2>/dev/null || echo 0)
    n=$((n + 1))
    echo "$n" > "$SHIM_DIR/cats"
    if [ "$n" = "${SHIM_CAT_CUT_AT:-0}" ]; then
      exec /usr/bin/head -c 3 -- "$2"
    fi ;;
esac
exec /bin/cat "$@"
"""


@pytest.mark.parametrize("cut_at", ["1", "2"])
def test_a_bad_backup_copy_aborts_before_anything_changes(box: Box, cut_at: str) -> None:
    box.vmfw.write_text(OLD)
    _write_exec(box.shim / "cat", CAT_SHIM)
    before = box.snapshot()
    proc = box.vm("--apply", SHIM_CAT_CUT_AT=cut_at)
    assert proc.returncode == 5
    assert "nothing was changed" in proc.stderr
    assert box.snapshot() == before
    assert box.backups() == []
    assert not any(c.endswith("compile") for c in box.calls())


def test_a_backup_folder_that_cannot_be_made_aborts_before_anything_changes(box: Box) -> None:
    box.vmfw.write_text(OLD)
    box.bakdir.parent.mkdir(parents=True)
    box.bakdir.write_text("in the way")
    proc = box.vm("--apply")
    assert proc.returncode == 5
    assert "nothing was changed" in proc.stderr
    assert box.vmfw.read_text() == OLD


def test_the_test_root_is_refused_for_root(box: Box) -> None:
    unshare = shutil.which("unshare")
    if unshare is None or subprocess.run([unshare, "-Ur", "true"], check=False).returncode != 0:  # noqa: S603
        pytest.skip("no user namespace to be root in")
    proc = subprocess.run(  # noqa: S603
        [unshare, "-Ur", "bash", str(SCRIPT), *BASE],
        env=box.env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2
    assert "SUCKERPOT_PVE_ROOT" in proc.stderr
    assert "refused for root" in proc.stderr
    assert "== Generated" not in proc.stdout


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


def test_undo_restores_the_most_recent_backup_and_takes_it_off(box: Box) -> None:
    older = "[OPTIONS]\n\nenable: 0\n"
    newest = "[OPTIONS]\n\nenable: 1\nlog_level_in: info\n"
    _backup(box, "20261103T000000Z", older)
    newer = _backup(box, "20261104T000000Z", newest)
    box.vmfw.write_text("[OPTIONS]\n\nenable: 1\npolicy_in: DROP\n")
    proc = box.run("--undo", "--vmid", VMID)
    assert proc.returncode == 0, proc.stderr
    assert box.vmfw.read_text() == newest
    assert (box.shim / "compile-1.fw").read_text() == newest
    assert "Status: enabled/running" in proc.stdout
    assert not newer.exists()
    # The file it replaced is kept, apart from the numbered backups.
    (kept,) = box.bakdir.glob("*-before-undo.fw")
    assert kept.read_text() == "[OPTIONS]\n\nenable: 1\npolicy_in: DROP\n"
    assert stat.S_IMODE(kept.stat().st_mode) == 0o600
    # Exactly one step per call: the next one goes to the older backup, the one after has none.
    assert box.run("--undo", "--vmid", VMID).returncode == 0
    assert box.vmfw.read_text() == older
    last = box.run("--undo", "--vmid", VMID)
    assert last.returncode == 4
    assert "nothing to undo" in last.stderr
    assert box.vmfw.read_text() == older


def test_two_applies_then_two_undos_go_back_one_step_each(box: Box) -> None:
    first = box.vm("--apply")
    assert first.returncode == 0, first.stderr
    one = box.vmfw.read_text()
    second = box.vm("--gateway-all", "--apply")
    assert second.returncode == 0, second.stderr
    two = box.vmfw.read_text()
    assert one != two
    assert len(box.stack()) == 2
    assert box.run("--undo", "--vmid", VMID).returncode == 0
    assert box.vmfw.read_text() == one
    assert len(box.stack()) == 1
    assert box.run("--undo", "--vmid", VMID).returncode == 0
    assert not box.vmfw.exists()
    assert box.stack() == []
    assert box.run("--undo", "--vmid", VMID).returncode == 4


def test_a_failed_apply_pushes_nothing_on_the_stack(box: Box) -> None:
    assert box.vm("--apply").returncode == 0
    one = box.vmfw.read_text()
    (before,) = box.stack()
    failed = box.vm("--gateway-all", "--apply", SHIM_COMPILE_FAIL="new")
    assert failed.returncode == 5
    assert box.vmfw.read_text() == one
    assert box.stack() == [before]
    # One undo is enough to get back to the state before the one successful apply.
    assert box.run("--undo", "--vmid", VMID).returncode == 0
    assert not box.vmfw.exists()
    assert box.run("--undo", "--vmid", VMID).returncode == 4


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
    _backup(box, "20261104T000000Z", "[OPTIONS]\n\nenable: 1\n").rename(
        box.bakdir / "220-20261104T000000Z.fw"
    )
    (box.bakdir / f"{VMID}-notes.fw").write_text("x")
    assert box.run("--undo", "--vmid", VMID).returncode == 4


def test_undo_is_rolled_back_when_its_check_fails(box: Box) -> None:
    backup = _backup(box, "20261104T000000Z", "[OPTIONS]\n\nenable: 1\n")
    current = "[OPTIONS]\n\nenable: 0\n"
    box.vmfw.write_text(current)
    proc = box.run("--undo", "--vmid", VMID, SHIM_COMPILE_FAIL="always")
    assert proc.returncode == 5
    assert "rolled back" in proc.stderr
    assert box.vmfw.read_text() == current
    # The step was not taken, so its backup stays on the stack.
    assert backup.exists()


def test_undo_needs_root_and_a_node(box: Box) -> None:
    _backup(box, "20261104T000000Z", "[OPTIONS]\n\nenable: 1\n")
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


# ---------------------------------------------------------------- --vm-addr (ipfilter set)
VM_ADDRS = ("--vm-addr", "192.0.2.60", "--vm-addr", "2001:db8::60")


def ipset(text: str, name: str) -> list[str]:
    """The entries of an [IPSET name] section, without their comments."""
    section = ""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
        elif line and section == f"[IPSET {name}]":
            out.append(line.split(" #", 1)[0])
    return out


def test_vm_addr_writes_the_set_and_no_ipfilter_option(box: Box) -> None:
    proc = box.vm(*VM_ADDRS)
    assert proc.returncode == 0, proc.stderr
    text = generated(proc.stdout)
    # The set alone filters its NIC. The option would give every NIC an empty set, and a NIC
    # that later gets firewall=1 would silently lose its IPv4 traffic.
    assert options(text) == [
        "enable: 1",
        "policy_in: ACCEPT",
        "policy_out: ACCEPT",
        "macfilter: 1",
    ]
    assert "ipfilter:" not in text
    assert ipset(text, "ipfilter-net0") == ["192.0.2.60", "2001:db8::60"]
    assert text.index("[RULES]") < text.index("[IPSET ipfilter-net0]")
    # The rules are the same as without it, and each address says why it is there.
    assert rules(text) == [*DHCP, *GATEWAY, *PRIVATE_DROPS, *LINK_LOCAL, *ADMIN]
    assert f"192.0.2.60 {MARK} address or range of the VM" in text
    # The owner is told what a wrong list costs.
    assert "filters net0" in proc.stderr
    assert "only send from 192.0.2.60 2001:db8::60" in proc.stderr


def test_vm_addr_names_the_nic_and_lists_an_address_once(box: Box) -> None:
    config = f"name: vm-test\nnet1: {NIC},firewall=1\n"
    proc = box.vm(*VM_ADDRS, "--vm-addr", "192.0.2.60", "--vm-nic", "net1", SHIM_QM_CONFIG=config)
    assert proc.returncode == 0, proc.stderr
    text = generated(proc.stdout)
    assert ipset(text, "ipfilter-net1") == ["192.0.2.60", "2001:db8::60"]
    assert "ipfilter-net0" not in text


@pytest.mark.parametrize(
    "cidr",
    ["192.0.2.0/24", "192.0.2.64/26", "192.0.2.60/32", "2001:db8:1:2::/64", "2001:db8::60/128"],
)
def test_vm_addr_takes_a_cidr_no_broader_than_a_24_or_a_64(box: Box, cidr: str) -> None:
    proc = box.vm("--vm-addr", cidr)
    assert proc.returncode == 0, proc.stderr
    assert ipset(generated(proc.stdout), "ipfilter-net0") == [cidr]


@pytest.mark.parametrize(
    ("cidr", "limit"),
    [
        ("192.0.2.0/23", "/24"),
        ("192.0.0.0/16", "/24"),
        ("0.0.0.0/0", "/24"),
        ("2001:db8::/48", "/64"),
        ("2001:db8:1:2::/63", "/64"),
        ("::/0", "/64"),
    ],
)
def test_vm_addr_refuses_a_broader_cidr(box: Box, cidr: str, limit: str) -> None:
    proc = box.vm("--vm-addr", cidr)
    assert proc.returncode == 2
    assert f"--vm-addr {cidr} is broader than a {limit}" in proc.stderr
    assert not box.vmfw.exists()


@pytest.mark.parametrize(
    "bad",
    ["192.0.2.0/", "192.0.2.1/33", "2001:db8::/129", "192.0.2.0/024", "192.0.2.0/24/1", "x/64"],
)
def test_vm_addr_validates_a_cidr_strictly(box: Box, bad: str) -> None:
    proc = box.vm("--vm-addr", bad)
    assert proc.returncode == 2
    assert "--vm-addr" in proc.stderr


def test_without_vm_addr_no_set_is_written(box: Box) -> None:
    text = generated(box.vm().stdout)
    assert "ipfilter" not in text
    assert "[IPSET" not in text


def test_apply_writes_the_set_and_a_rerun_with_other_addresses_is_not_foreign(box: Box) -> None:
    assert box.vm(*VM_ADDRS, "--apply").returncode == 0
    assert ipset(box.vmfw.read_text(), "ipfilter-net0") == ["192.0.2.60", "2001:db8::60"]
    # Its own set and rules, with other addresses, are replaced without --replace.
    again = box.vm("--vm-addr", "192.0.2.61", "--apply")
    assert again.returncode == 0, again.stderr
    assert ipset(box.vmfw.read_text(), "ipfilter-net0") == ["192.0.2.61"]


def test_leaving_vm_addr_out_later_takes_the_set_away_like_any_rule_of_ours(box: Box) -> None:
    assert box.vm(*VM_ADDRS, "--apply").returncode == 0
    proc = box.vm("--apply")
    assert proc.returncode == 0, proc.stderr
    assert "[IPSET" not in box.vmfw.read_text()
    # And the diff said so before: the set is shown as removed.
    assert "-[IPSET ipfilter-net0]" in proc.stdout


def test_a_set_of_the_owners_is_foreign(box: Box) -> None:
    box.vmfw.write_text("[OPTIONS]\n\nenable: 1\n\n[IPSET management] # my admins\n\n192.0.2.80\n")
    proc = box.vm()
    assert proc.returncode == 0
    assert "[IPSET MANAGEMENT] 192.0.2.80" in proc.stdout
    assert box.vm("--apply").returncode == 4


def test_another_nic_is_not_a_reason_to_refuse(box: Box) -> None:
    # No ipfilter option, so the other NICs are not given an empty set: nothing to protect.
    config = f"net0: {NIC},firewall=1\nnet1: virtio=02:00:00:00:00:02,bridge=vmbr1,firewall=1\n"
    proc = box.vm(*VM_ADDRS, "--apply", "--set-nic-firewall", SHIM_QM_CONFIG=config)
    assert proc.returncode == 0, proc.stderr
    assert "would cut off" not in proc.stderr
    assert "[IPSET ipfilter-net1]" not in box.vmfw.read_text()


def test_vm_addr_needs_the_nic_to_exist(box: Box) -> None:
    dry = box.vm(*VM_ADDRS, "--vm-nic", "net3")
    assert dry.returncode == 0
    assert "the VM has no net3" in dry.stderr
    proc = box.vm(*VM_ADDRS, "--vm-nic", "net3", "--apply")
    assert proc.returncode == 4
    assert not box.vmfw.exists()


# ---------------------------------------------------------------- --dns
def test_dns_adds_dns_only_rules_before_the_drops(box: Box) -> None:
    proc = box.vm("--dns", "2001:db8::53", "--dns", "fe80::1", "--dns", "192.0.2.53")
    assert proc.returncode == 0, proc.stderr
    got = rules(generated(proc.stdout))
    dns = [
        f"OUT ACCEPT -dest {a} -p {p} -dport 53"
        for a in ("2001:db8::53", "fe80::1", "192.0.2.53")
        for p in ("udp", "tcp")
    ]
    assert got == [*DHCP, *GATEWAY, *dns, *PRIVATE_DROPS, *LINK_LOCAL, *ADMIN]
    # Even a link-local resolver is accepted before the link-local drops, and never on every port.
    assert got.index("OUT ACCEPT -dest fe80::1 -p udp -dport 53") < got.index(LINK_LOCAL[0])
    assert "OUT ACCEPT -dest fe80::1" not in got


def test_dns_is_listed_once_and_skips_the_gateway(box: Box) -> None:
    proc = box.vm("--dns", "192.0.2.53", "--dns", "192.0.2.1", "--dns", "192.0.2.53")
    assert proc.returncode == 0, proc.stderr
    got = rules(generated(proc.stdout))
    assert [r for r in got if "192.0.2.53" in r] == [
        "OUT ACCEPT -dest 192.0.2.53 -p udp -dport 53",
        "OUT ACCEPT -dest 192.0.2.53 -p tcp -dport 53",
    ]
    assert [r for r in got if "192.0.2.1 " in r] == GATEWAY


@pytest.mark.parametrize(
    "bad",
    ["192.0.2.0/24", "2001:db8::/32", "example.org", "192.0.2", "fe80::1%eth0", "::g", "$(id)"],
)
def test_dns_takes_one_address(box: Box, bad: str) -> None:
    proc = box.vm("--dns", bad)
    assert proc.returncode == 2
    assert "--dns" in proc.stderr


def test_dns_is_written_by_apply_and_replaced_freely(box: Box) -> None:
    assert box.vm("--dns", "192.0.2.53", "--apply").returncode == 0
    assert "-dest 192.0.2.53 -p udp -dport 53" in box.vmfw.read_text()
    assert box.vm("--dns", "192.0.2.54", "--apply").returncode == 0
    text = box.vmfw.read_text()
    assert "192.0.2.53" not in text
    assert "-dest 192.0.2.54 -p tcp -dport 53" in text


# ---------------------------------------------------------------- the script itself
def test_the_script_checks_that_root_does_not_use_the_test_root() -> None:
    code = SCRIPT.read_text()
    assert '"$EUID" -eq 0' in code
    assert code.index('"$EUID" -eq 0') < code.index("build > ")


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
