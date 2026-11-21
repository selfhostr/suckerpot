"""Podman phase 2 (docs/dev/design/podman.md): the overlay, the networks, the firewall, the boot unit.

Everything runs with fakes: no test reaches a real engine, nft, systemctl or sudo. The real runs on
Podman are described in the pull request that added this file.
"""

from __future__ import annotations

import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from suckerpot_guardrails.compose import BRIDGE_NAMES, _Loader, _Override, _Reset, load_compose

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"
PODMAN = ROOT / "docker-compose.podman.yml"
OVERLAYS = [ROOT / f"docker-compose.{n}.yml" for n in ("lowmem", "lite", "participant")]
HOST = ROOT / "scripts" / "host"
FIXTURES = Path(__file__).parent / "fixtures" / "firewall"
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SOCK = "unix:///run/podman/podman.sock"
EXTRA_TMPFS = [
    "/run:rw,noexec,nosuid,nodev,size=1m,mode=0755",
    "/var/tmp:rw,noexec,nosuid,nodev,size=1m,mode=1777",  # noqa: S108 (a mount target)
]
TMP_ADDED = "/tmp:rw,noexec,nosuid,nodev,size=1m,U"  # noqa: S108 (a mount target)
DNS_OFF = {"sp-ingress", "sp-dashboard", "sp-vpn"}


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _raw(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)  # noqa: S506
    return data


# --- The overlay changes what Podman needs, and nothing else ----------------------------------


def test_overlay_only_sets_services_and_networks() -> None:
    assert set(_raw(PODMAN)) == {"services", "networks"}


def test_every_network_is_external_under_its_bridge_name() -> None:
    base = _raw(BASE)["networks"]
    over = _raw(PODMAN)["networks"]
    assert set(over) == set(base) == set(BRIDGE_NAMES)
    merged = load_compose([BASE, PODMAN])["networks"]
    for net, cfg in merged.items():
        assert cfg == {"external": True, "name": BRIDGE_NAMES[net]}, net


def test_overlay_service_keys_are_limited() -> None:
    allowed = {"image", "volumes", "tmpfs", "logging", "healthcheck"}
    base = _raw(BASE)["services"]
    for name, svc in _raw(PODMAN)["services"].items():
        assert name in base, name
        assert set(svc) <= allowed, (name, set(svc) - allowed)
        if "healthcheck" in svc:
            assert name == "backup"
            assert set(svc["healthcheck"]) == {"interval", "start_interval"}
            assert isinstance(svc["healthcheck"]["start_interval"], _Reset)


def test_third_party_images_are_the_same_images_with_their_registry() -> None:
    base = _raw(BASE)["services"]
    over = _raw(PODMAN)["services"]
    with_image = {n for n, s in over.items() if "image" in s}
    assert with_image == {n for n, s in base.items() if "build" not in s}
    for name in with_image:
        assert over[name]["image"] == "docker.io/" + base[name]["image"], name
        # A build tag (local/...) is never qualified: source mode stays Docker-only (D6).
        assert "build" not in base[name]


def test_bind_mounts_get_the_selinux_option_and_nothing_else_changes() -> None:
    base = _raw(BASE)["services"]
    over = _raw(PODMAN)["services"]
    for name, svc in base.items():
        binds = [v for v in svc.get("volumes") or [] if isinstance(v, str) and v.startswith("./")]
        if not binds:
            assert "volumes" not in over.get(name, {}), name
            continue
        assert over[name]["volumes"] == [v + ",z" for v in binds], name
        # Compose merges volumes by target: every overlay entry replaces one base entry.
        assert all(v.endswith(":ro") for v in binds), name


def test_tmpfs_lists_are_the_base_ones_owned_by_the_user_plus_tmp_run_and_var_tmp() -> None:
    base = _raw(BASE)["services"]
    over = _raw(PODMAN)["services"]
    for name, svc in base.items():
        assert isinstance(over[name]["tmpfs"], _Override), name
        user = str(svc.get("user", ""))
        want = []
        for entry in svc["tmpfs"]:
            found = re.search(r",uid=(\d+),gid=(\d+)", entry)
            if found:
                # U gives the mount to the container's user: only right when that user is uid:gid.
                assert user == f"{found.group(1)}:{found.group(2)}", (name, entry)
                entry = entry.replace(found.group(0), ",U")
            want.append(entry)
        # Podman adds a writable, executable /tmp, /run and /var/tmp where the service has none.
        if not any(e.split(":", 1)[0] == "/tmp" for e in want):  # noqa: S108
            want.append(TMP_ADDED)
        assert list(over[name]["tmpfs"]) == want + EXTRA_TMPFS, name
        targets = {e.split(":", 1)[0] for e in over[name]["tmpfs"]}
        assert {"/tmp", "/run", "/var/tmp"} <= targets, name  # noqa: S108 (mount targets)
        for entry in over[name]["tmpfs"]:
            assert "noexec" in entry and "nosuid" in entry and "size=" in entry, (name, entry)


def test_every_service_logs_to_journald() -> None:
    for name in _raw(BASE)["services"]:
        logging = _raw(PODMAN)["services"][name]["logging"]
        assert logging["driver"] == "journald", name
        assert isinstance(logging["options"], _Reset), name


@pytest.mark.parametrize(
    "extra",
    [[], [OVERLAYS[0]], [OVERLAYS[2]], [OVERLAYS[0], OVERLAYS[2]], OVERLAYS],
    ids=["full", "lowmem", "participant", "lowmem+participant", "lite"],
)
def test_the_overlay_keeps_hardening_and_service_networks(extra: list[Path]) -> None:
    plain = load_compose([BASE, *extra])
    podman = load_compose([BASE, *extra, PODMAN])
    for name, svc in plain["services"].items():
        mine = podman["services"][name]
        for key in (
            "read_only",
            "cap_drop",
            "cap_add",
            "security_opt",
            "user",
            "networks",
            "ports",
            "dns",
            "mem_limit",
            "pids_limit",
            "environment",
            "profiles",
        ):
            assert mine.get(key) == svc.get(key), (name, key)


def test_the_test_overlays_never_use_the_podman_overlay() -> None:
    for name in ("ci", "it", "participant-it"):
        text = (ROOT / f"docker-compose.{name}.yml").read_text()
        assert "docker-compose.podman.yml" not in text


# --- ensure-networks.sh -----------------------------------------------------------------------

SPEC_LINE = re.compile(r"^(sp-[a-z-]+) ([01]) ([01])$")


def _specs() -> dict[str, tuple[bool, bool]]:
    text = (ROOT / "scripts" / "ensure-networks.sh").read_text()
    block = text.split('SPECS="', 1)[1].split('"', 1)[0]
    out = {}
    for line in block.splitlines():
        m = SPEC_LINE.match(line)
        assert m, line
        out[m.group(1)] = (m.group(2) == "1", m.group(3) == "1")
    return out


def test_network_specs_match_the_compose_file() -> None:
    specs = _specs()
    base = _raw(BASE)["networks"]
    assert set(specs) == set(BRIDGE_NAMES.values())
    for net, bridge in BRIDGE_NAMES.items():
        internal, dns = specs[bridge]
        assert internal == bool(base[net].get("internal")), bridge
        # DNS off where no member needs a name (design 5.2, 5.3).
        assert dns == (bridge not in DNS_OFF), bridge


# A fake podman with state: each network is a file holding what `network inspect` prints.
PODMAN_NET_SHIM = r"""#!/bin/bash
echo "podman $*" >> "$SHIM_LOG"
[ "$1" = --url ] && [ "$2" = "unix:///run/podman/podman.sock" ] || { echo "no --url" >&2; exit 99; }
shift 2
nets=$SHIM_DIR/nets
mkdir -p "$nets"
case "$1 $2" in
  "network inspect")
    name=${!#}
    [ -f "$nets/$name" ] || exit 125
    cat "$nets/$name" ;;
  "network ls")
    for f in "$nets"/*; do [ -f "$f" ] || continue; echo "$(basename "$f") $(cut -d' ' -f2 "$f")"; done ;;
  "network rm") rm -f "$nets/$3" ;;
  "network create")
    shift 2
    iface="" int=false dns=true spec=""
    while [ "$#" -gt 1 ]; do
      case $1 in
        --interface-name) iface=$2; shift ;;
        --internal) int=true ;;
        --disable-dns) dns=false ;;
        --label) case $2 in io.suckerpot.netspec=*) spec=${2#*=} ;; esac; shift ;;
        --opt) [ "$2" = isolate=strict ] || exit 98; shift ;;
        --driver) shift ;;
      esac
      shift
    done
    echo "bridge $iface $int $dns false opts=isolate=strict; routes=0 managed=1 spec=$spec" > "$nets/$1" ;;
  "ps -a")
    want=${!#}; want=${want#network=}
    for u in ${SHIM_USED:-}; do [ "$u" = "$want" ] && echo "c0ffee"; done ;;
esac
exit 0
"""


# The host firewall as fwcheck.sh sees it: unit active unless SHIM_FW=1; `sudo -n nft list tables`
# prints SHIM_TABLES (default: both SuckerPot tables) or fails with SHIM_NFT_RC.
SYSTEMCTL_FW = r"""#!/bin/sh
case "$1 $2 $3" in
  "is-active --quiet suckerpot-firewall.service") exit "${SHIM_FW:-0}" ;;
  "show -p BindsTo") echo "${SHIM_BINDS:-}" ;;
  is-active*) exit 3 ;;
esac
exit 0
"""
SUDO_NFT = r"""#!/bin/sh
if [ "$*" = "-n nft list tables" ]; then
  [ "${SHIM_NFT_RC:-0}" = 0 ] || exit "$SHIM_NFT_RC"
  printf '%s\n' "${SHIM_TABLES-table inet suckerpot_host;table bridge suckerpot_bridge}" | tr ';' '\n'
  exit 0
fi
exit 1
"""


@pytest.fixture
def netbox(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for rel in ("scripts/ensure-networks.sh", "scripts/lib/engine.sh", "scripts/lib/fwcheck.sh"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, root / rel)
    (root / ".env").write_text(
        "SUCKERPOT_ENGINE=podman\nCOMPOSE_FILE=docker-compose.yml:docker-compose.podman.yml\n"
    )
    shim = tmp_path / "shim"
    shim.mkdir()
    _write_exec(shim / "podman", PODMAN_NET_SHIM)
    _write_exec(shim / "docker", '#!/bin/sh\necho "docker $*" >> "$SHIM_LOG"\nexit 1\n')
    _write_exec(shim / "systemctl", SYSTEMCTL_FW)
    _write_exec(shim / "sudo", SUDO_NFT)
    return root


def _nets(root: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    shim = root.parent / "shim"
    return subprocess.run(  # noqa: S603
        ["bash", str(root / "scripts/ensure-networks.sh"), *args],  # noqa: S607
        cwd=root,
        env={"PATH": f"{shim}:{PATH}", "SHIM_DIR": str(shim), "SHIM_LOG": str(shim / "log"), **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _log(root: Path) -> list[str]:
    log = root.parent / "shim" / "log"
    return log.read_text().splitlines() if log.exists() else []


def test_networks_are_created_with_netavark_options(netbox: Path) -> None:
    result = _nets(netbox)
    assert result.returncode == 0, result.stderr
    creates = [c for c in _log(netbox) if " network create " in c]
    assert len(creates) == len(BRIDGE_NAMES)
    by_name = {c.rsplit(" ", 1)[1]: c for c in creates}
    for name, (internal, dns) in _specs().items():
        call = by_name[name]
        assert f"--url {SOCK} network create --driver bridge --interface-name {name} " in call
        assert "--opt isolate=strict" in call
        assert ("--internal" in call) == internal, name
        assert ("--disable-dns" in call) == (not dns), name
    # A second run changes nothing.
    before = len(_log(netbox))
    assert _nets(netbox).returncode == 0
    assert not [c for c in _log(netbox)[before:] if " create " in c or " rm " in c]
    assert _nets(netbox, "--check").returncode == 0


def test_a_wrong_network_is_recreated_when_unused(netbox: Path) -> None:
    assert _nets(netbox).returncode == 0
    nets = netbox.parent / "shim" / "nets"
    (nets / "sp-ingress").write_text(
        "bridge sp-ingress false true false opts=isolate=strict; routes=0 managed=1 spec=1\n"
    )  # DNS on
    check = _nets(netbox, "--check")
    assert check.returncode == 1 and "sp-ingress differs" in check.stderr
    result = _nets(netbox)
    assert result.returncode == 0, result.stderr
    assert "recreating network sp-ingress" in result.stdout
    assert (nets / "sp-ingress").read_text().split()[3] == "false"


def test_a_wrong_network_in_use_stops_with_exit_3(netbox: Path) -> None:
    assert _nets(netbox).returncode == 0
    nets = netbox.parent / "shim" / "nets"
    (nets / "sp-s-ssh").write_text(
        "bridge sp-s-ssh true true false opts=isolate=strict; routes=0 managed=1 spec=0\n"
    )  # old spec
    result = _nets(netbox, SHIM_USED="sp-s-ssh")
    assert result.returncode == 3
    assert "containers use it" in result.stderr
    assert not [c for c in _log(netbox) if "network rm sp-s-ssh" in c]


def test_a_compat_network_on_the_same_bridge_is_replaced(netbox: Path) -> None:
    nets = netbox.parent / "shim" / "nets"
    nets.mkdir(parents=True)
    (nets / "suckerpot_backend").write_text("bridge sp-backend true true false  \n")
    result = _nets(netbox)
    assert result.returncode == 0, result.stderr
    assert not (nets / "suckerpot_backend").exists()
    assert (nets / "sp-backend").exists()


def test_without_the_overlay_in_compose_file_nothing_is_created(netbox: Path) -> None:
    (netbox / ".env").write_text("SUCKERPOT_ENGINE=podman\nCOMPOSE_FILE=docker-compose.yml\n")
    result = _nets(netbox)
    assert result.returncode == 1
    assert "docker-compose.podman.yml" in result.stderr
    assert _log(netbox) == []


def test_ensure_networks_does_nothing_on_docker(netbox: Path) -> None:
    (netbox / ".env").write_text("SUCKERPOT_ENGINE=docker\n")
    result = _nets(netbox)
    assert result.returncode == 0
    assert _log(netbox) == []


@pytest.mark.parametrize(
    ("env", "why"),
    [
        ({"SHIM_FW": "1"}, "is not active"),
        ({"SHIM_TABLES": "table inet suckerpot_host"}, "bridge suckerpot_bridge are not loaded"),
        ({"SHIM_TABLES": ""}, "inet suckerpot_host,bridge suckerpot_bridge are not loaded"),
    ],
    ids=["unit-stopped", "bridge-table-gone", "flushed"],
)
def test_no_network_is_made_without_the_firewall_in_force(
    netbox: Path, env: dict[str, str], why: str
) -> None:
    result = _nets(netbox, **env)
    assert result.returncode == 4, result.stderr
    assert why in result.stderr
    assert not [c for c in _log(netbox) if " create " in c]
    # --check only reads: it never needs the firewall.
    assert _nets(netbox, "--check", **env).returncode == 1  # networks missing, not refused


def test_the_firewall_guard_accepts_an_active_unit_when_tables_cannot_be_read(
    netbox: Path,
) -> None:
    result = _nets(netbox, SHIM_NFT_RC="1")
    assert result.returncode == 0, result.stderr
    assert "tables were not read" in result.stderr


def test_the_firewall_opt_out_skips_the_guard(netbox: Path) -> None:
    result = _nets(netbox, SHIM_FW="1", SUCKERPOT_NO_FIREWALL="1")
    assert result.returncode == 0, result.stderr
    (netbox / ".env").write_text(
        "SUCKERPOT_ENGINE=podman\nSUCKERPOT_NO_FIREWALL=1\n"
        "COMPOSE_FILE=docker-compose.yml:docker-compose.podman.yml\n"
    )
    assert _nets(netbox, SHIM_FW="1").returncode == 0


def test_a_network_with_extra_options_routes_or_without_our_label_is_wrong(netbox: Path) -> None:
    assert _nets(netbox).returncode == 0
    nets = netbox.parent / "shim" / "nets"
    good = (nets / "sp-backend").read_text()
    for bad in (
        good.replace("opts=isolate=strict;", "opts=isolate=strict;mtu=9000;"),
        good.replace("routes=0", "routes=1"),
        good.replace("managed=1", "managed="),
    ):
        (nets / "sp-backend").write_text(bad)
        check = _nets(netbox, "--check")
        assert check.returncode == 1 and "sp-backend differs" in check.stderr, bad
    (nets / "sp-backend").write_text(good)


# --- Firewall: Docker unchanged, Podman additions ---------------------------------------------

IP_STUB = (
    '#!/bin/sh\n[ "$*" = "-o link show type bridge" ] || exit 1\nprintf "%s" "${STUB_IP_OUT:-}"\n'
)
ENGINE_STUB = """#!/bin/sh
echo "$(basename "$0") $*" >> "${STUB_LOG:-/dev/null}"
case "$*" in
  *"network ls --format {{.NetworkInterface}}") printf '%s' "${STUB_PODMAN_BRIDGES:-}" ;;
  "network ls --filter driver=bridge --no-trunc -q") ;;
  *) exit 1 ;;
esac
"""


@pytest.fixture
def resolv(tmp_path: Path) -> Path:
    path = tmp_path / "resolv.conf"
    path.write_text("# test\nnameserver 192.0.2.53\nnameserver 198.51.100.53\nsearch .\n")
    return path


def render(tmp_path: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "stubs"
    stubs.mkdir(exist_ok=True)
    _write_exec(stubs / "ip", IP_STUB)
    _write_exec(stubs / "docker", ENGINE_STUB)
    _write_exec(stubs / "podman", ENGINE_STUB)
    return subprocess.run(  # noqa: S603
        ["bash", str(HOST / "render-firewall.sh"), *args],  # noqa: S607
        env={"PATH": f"{stubs}:{PATH}", **env},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


DOCKER_RENDERS = {
    "participant": ["--participant"],
    "full": ["--full", "--vpn-endpoint", "203.0.113.10:51820"],
}


@pytest.mark.parametrize("mode", sorted(DOCKER_RENDERS))
@pytest.mark.parametrize("engine", [[], ["--engine", "docker"]], ids=["default", "explicit"])
def test_docker_rendering_is_byte_for_byte_the_v0_12_1_one(
    tmp_path: Path, resolv: Path, mode: str, engine: list[str]
) -> None:
    result = render(
        tmp_path,
        *DOCKER_RENDERS[mode],
        "--admin-ssh-port",
        "2200",
        "--resolv-conf",
        str(resolv),
        *engine,
    )
    assert result.returncode == 0, result.stderr
    body = result.stdout.split("\n", 1)[1]
    assert body == (FIXTURES / f"docker-{mode}.nft").read_text()
    assert "podman" not in body


def _podman(tmp_path: Path, resolv: Path, mode: str, *extra: str) -> str:
    result = render(
        tmp_path,
        *DOCKER_RENDERS[mode],
        "--admin-ssh-port",
        "2200",
        "--resolv-conf",
        str(resolv),
        "--engine",
        "podman",
        *extra,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _rules(text: str) -> list[str]:
    """Rule and define lines, without comments and braces, in order."""
    keep = ("iifname", "ct state", "define")
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith(keep)]


@pytest.mark.parametrize("mode", sorted(DOCKER_RENDERS))
def test_podman_rendering_adds_dns_podman_bridges_and_the_bridge_table(
    tmp_path: Path, resolv: Path, mode: str
) -> None:
    text = _podman(tmp_path, resolv, mode)
    assert text.splitlines()[0].startswith(
        f"# Rendered by scripts/host/render-firewall.sh --{mode} --engine podman"
    )
    assert not [ln for ln in text.splitlines() if ln.startswith("#podman")]
    rules = _rules(text)
    dns = [r for r in rules if "th dport 53" in r]
    assert len(dns) == 1
    assert "ct state new meta nfproto ipv4 fib daddr . iif" in dns[0]
    # Only DNS, only to the address of the bridge the query came in on, never on the sensor uplink.
    assert (
        "fib daddr . iif type local meta l4proto { tcp, udp } th dport 53 counter accept" in dns[0]
    )
    assert (
        '"sp-ingress"' not in dns[0] and '"sp-dashboard"' not in dns[0] and '"sp-vpn"' not in dns[0]
    )
    # The DNS accept comes before every input drop on the same bridges.
    input_chain = text.split("chain input", 1)[1].split("chain forward", 1)[0]
    first_drop = min(i for i, r in enumerate(_rules(input_chain)) if r.endswith("drop"))
    assert _rules(input_chain).index(dns[0]) < first_drop
    assert any(
        r.startswith('iifname { "podman*", "cni-podman*" } ct state new tcp dport')
        and r.endswith("drop")
        for r in rules
    )
    bridge = text.split("table bridge suckerpot_bridge {", 1)[1]
    assert (
        'meta ibrname { "sp-ingress", "sp-dashboard", "sp-vpn", "sp-hubgate" } counter drop'
        in bridge
    )
    assert "type filter hook forward priority -10; policy accept;" in bridge
    assert (
        "add table bridge suckerpot_bridge" in text
        and "delete table bridge suckerpot_bridge" in text
    )
    # Everything of the Docker rendering is still there: Podman only adds rules.
    docker = _rules((FIXTURES / f"docker-{mode}.nft").read_text())
    docker = [r.replace("{ 192.0.2.53, 198.51.100.53 }", "{ 127.0.0.1 }") for r in docker]
    assert [r for r in rules if r in docker] == docker


def test_podman_rendering_never_opens_dns_through_sp_hubgate(tmp_path: Path, resolv: Path) -> None:
    """aardvark-dns asks upstream from the host: nothing has to cross sp-hubgate."""
    text = _podman(tmp_path, resolv, "participant", "--dns", "192.0.2.99")
    assert "define HUBGATE_DNS = { 127.0.0.1 }" in text


def test_hand_filled_templates_keep_podman_lines_as_comments() -> None:
    for name in ("firewall.nft", "firewall-participant.nft"):
        for line in (HOST / name).read_text().splitlines():
            if any(k in line for k in ("suckerpot_bridge", "ibrname", "podman*", "fib daddr")):
                assert line.startswith("#podman: "), line


def test_podman_bridges_count_for_the_foreign_bridge_check(tmp_path: Path, resolv: Path) -> None:
    ip_out = "".join(
        f"{i}: {n}: <UP> mtu 1500\n" for i, n in enumerate(["podman0", "podman-lan"], 3)
    )
    result = render(
        tmp_path,
        "--participant",
        "--admin-ssh-port",
        "2200",
        "--resolv-conf",
        str(resolv),
        "--engine",
        "podman",
        STUB_IP_OUT=ip_out,
        STUB_PODMAN_BRIDGES="podman0\nsp-ingress\n",
    )
    assert result.returncode == 2
    found = re.search(r"host bridge\(s\) (.*?) match", result.stderr)
    assert found and found.group(1) == "podman-lan", result.stderr
    # Docker ignores podman* bridges, as before.
    docker = render(
        tmp_path,
        "--participant",
        "--admin-ssh-port",
        "2200",
        "--resolv-conf",
        str(resolv),
        STUB_IP_OUT=ip_out,
    )
    assert docker.returncode == 0, docker.stderr


def test_renderer_refuses_an_unknown_engine(tmp_path: Path) -> None:
    result = render(tmp_path, "--participant", "--admin-ssh-port", "2200", "--engine", "lxc")
    assert result.returncode == 2 and "--engine must be docker or podman" in result.stderr


def _nft_can_check() -> bool:
    nft = shutil.which("nft", path=PATH)
    if nft is None:
        return False
    probe = subprocess.run(  # noqa: S603
        [nft, "-c", "-f", "/dev/null"], capture_output=True, text=True, timeout=10, check=False
    )
    return probe.returncode == 0


@pytest.mark.skipif(not _nft_can_check(), reason="nft missing or not allowed to check (needs root)")
@pytest.mark.parametrize("mode", sorted(DOCKER_RENDERS))
def test_podman_rendering_passes_nft_check(tmp_path: Path, resolv: Path, mode: str) -> None:
    out = tmp_path / "fw.nft"
    result = render(
        tmp_path,
        *DOCKER_RENDERS[mode],
        "--admin-ssh-port",
        "2200",
        "--resolv-conf",
        str(resolv),
        "--engine",
        "podman",
        "--out",
        str(out),
    )
    assert result.returncode == 0, result.stderr
    assert "ruleset is valid" in result.stderr


def test_the_firewall_unit_also_removes_the_bridge_table() -> None:
    unit = (HOST / "suckerpot-firewall.service").read_text()
    assert "ExecStop=-/usr/sbin/nft delete table bridge suckerpot_bridge" in unit
    assert "ExecStop=/usr/sbin/nft delete table inet suckerpot_host" in unit
    # A restart of the stock nftables service (flush ruleset) restarts this unit after it.
    assert "PartOf=nftables.service\n" in unit
    assert "ReloadPropagatedFrom=nftables.service\n" in unit
    assert re.search(r"^After=.*\bnftables\.service\b", unit, re.M)
    # A new file is loaded by a reload: one nft transaction, nothing bound to the unit stops.
    assert "ExecReload=/usr/sbin/nft -f /etc/suckerpot-firewall.nft\n" in unit


# --- install-firewall.sh with a Podman rendering ----------------------------------------------

SHIM = '#!/bin/sh\necho "$(basename "$0") $*" >> "$SHIM_LOG"\n'


@pytest.fixture
def shims(tmp_path: Path) -> Path:
    shim = tmp_path / "shim"
    shim.mkdir()
    _write_exec(
        shim / "id", SHIM + 'case "$*" in -u) echo "${SHIM_UID:-0}" ;; "-u "*) echo 1000 ;; esac\n'
    )
    for name in ("sudo", "install", "chown"):
        _write_exec(shim / name, SHIM + "exit 0\n")
    _write_exec(
        shim / "systemctl",
        SHIM + 'case "$1" in is-active) exit "${SHIM_ACTIVE:-1}" ;; esac\nexit 0\n',
    )
    _write_exec(
        shim / "podman", SHIM + 'case "$1" in ps) printf "%s" "${SHIM_RUNNING:-}" ;; esac\n'
    )
    _write_exec(
        shim / "nft",
        SHIM
        + 'case "$*" in "list table bridge suckerpot_bridge") exit "${SHIM_BRIDGE_RC:-0}" ;; esac\nexit 0\n',
    )
    _write_exec(shim / "docker-compose", SHIM)
    return shim


@pytest.fixture
def fsroot(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "etc" / "systemd" / "system").mkdir(parents=True)
    return root


def _run(
    script: Path, shims: Path, fsroot: Path, *args: str, **env: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", str(script), *args],  # noqa: S607
        env={
            "PATH": f"{shims}:{PATH}",
            "SHIM_LOG": str(shims / "log"),
            "SUCKERPOT_FW_ROOT": str(fsroot),
            "SUCKERPOT_UNIT_ROOT": str(fsroot),
            **env,
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _calls(shims: Path) -> list[str]:
    log = shims / "log"
    return log.read_text().splitlines() if log.exists() else []


def test_installing_a_podman_rendering_checks_the_bridge_table(
    tmp_path: Path, resolv: Path, shims: Path, fsroot: Path
) -> None:
    rendered = tmp_path / "fw.nft"
    rendered.write_text(_podman(tmp_path, resolv, "participant"))
    ok = _run(HOST / "install-firewall.sh", shims, fsroot, str(rendered))
    assert ok.returncode == 0, ok.stderr
    assert "nft list table bridge suckerpot_bridge" in _calls(shims)
    bad = _run(HOST / "install-firewall.sh", shims, fsroot, str(rendered), SHIM_BRIDGE_RC="1")
    assert bad.returncode == 5 and "bridge suckerpot_bridge is not loaded" in bad.stderr


def test_uninstall_removes_the_bridge_table_too(shims: Path, fsroot: Path) -> None:
    assert _run(HOST / "install-firewall.sh", shims, fsroot, "--uninstall").returncode == 0
    assert "nft delete table bridge suckerpot_bridge" in _calls(shims)


# --- install-stack-unit.sh --------------------------------------------------------------------


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    root = tmp_path / "srv" / "suckerpot"
    (root / "scripts").mkdir(parents=True)
    (root / "docker-compose.yml").write_text("services: {}\n")
    (root / "scripts" / "ensure-networks.sh").write_text("#!/bin/sh\n")
    return root


def _stack(shims: Path, fsroot: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return _run(HOST / "install-stack-unit.sh", shims, fsroot, *args, **env)


def _user() -> str:
    """A plain user name: the fake id knows every user."""
    return "alice"


def test_stack_unit_requires_the_firewall_and_runs_compose_as_the_user(
    shims: Path, fsroot: Path, checkout: Path
) -> None:
    (fsroot / "etc/systemd/system/suckerpot-firewall.service").write_text("x")
    result = _stack(shims, fsroot, _user(), str(checkout))
    assert result.returncode == 0, result.stderr
    unit = (fsroot / "etc/systemd/system/suckerpot-stack.service").read_text()
    assert "Requires=podman.socket\n" in unit
    # Bound to the firewall: the stack stops when the firewall unit stops, fails or restarts.
    assert "BindsTo=suckerpot-firewall.service\n" in unit
    assert "PartOf=suckerpot-firewall.service\n" in unit
    # After a stop and after a failed start alike.
    assert f"ExecStopPost={shims}/docker-compose stop\n" in unit
    assert "\nExecStop=" not in unit
    # The tables are checked as root before anything starts.
    assert re.search(r"^ExecStartPre=\+\S*nft list table inet suckerpot_host$", unit, re.M)
    assert re.search(r"^ExecStartPre=\+\S*nft list table bridge suckerpot_bridge$", unit, re.M)
    assert "After=network-online.target podman.socket suckerpot-firewall.service\n" in unit
    assert f"User={_user()}\n" in unit and f"WorkingDirectory={checkout}\n" in unit
    assert f"ExecStartPre=/bin/bash {checkout}/scripts/ensure-networks.sh\n" in unit
    assert f"ExecStart={shims}/docker-compose up -d --no-build --pull never --wait" in unit
    assert "Environment=DOCKER_HOST=unix:///run/podman/podman.sock\n" in unit
    assert not re.search(r"@[A-Z_]+@", unit)
    dropin = fsroot / "etc/systemd/system/podman-restart.service.d/suckerpot-firewall.conf"
    assert "After=suckerpot-firewall.service" in dropin.read_text()
    assert "systemctl enable suckerpot-stack.service" in _calls(shims)
    assert not [c for c in _calls(shims) if c.startswith("systemctl start")]


def test_stack_unit_refuses_without_the_firewall_unit(
    shims: Path, fsroot: Path, checkout: Path
) -> None:
    result = _stack(shims, fsroot, _user(), str(checkout))
    assert result.returncode == 4
    assert not (fsroot / "etc/systemd/system/suckerpot-stack.service").exists()


def test_no_firewall_drops_the_requirement_with_a_warning(
    shims: Path, fsroot: Path, checkout: Path
) -> None:
    result = _stack(shims, fsroot, "--no-firewall", _user(), str(checkout))
    assert result.returncode == 0, result.stderr
    assert "WARNING" in result.stderr
    unit = (fsroot / "etc/systemd/system/suckerpot-stack.service").read_text()
    lines = [ln for ln in unit.splitlines() if not ln.startswith("#")]
    assert not [ln for ln in lines if "suckerpot-firewall" in ln or "list table" in ln]
    assert "Requires=podman.socket" in lines
    assert "ExecStopPost=" + str(shims) + "/docker-compose stop" in lines
    # ensure-networks.sh must not refuse at boot for the missing firewall.
    assert "Environment=DOCKER_HOST=unix:///run/podman/podman.sock SUCKERPOT_NO_FIREWALL=1" in lines


@pytest.mark.parametrize(
    "args",
    [
        ["root", "/srv/x"],
        ["Bad User", "/srv/x"],
        ["{user}", "relative/path"],
        ["{user}", "/srv/a b"],
        ["{user}", "/srv/../etc"],
        ["{user}", "/nonexistent-checkout"],
    ],
)
def test_stack_unit_refuses_odd_values(shims: Path, fsroot: Path, args: list[str]) -> None:
    args = [a.replace("{user}", _user()) for a in args]
    result = _stack(shims, fsroot, *args)
    assert result.returncode == 2, result.stderr


def test_stack_unit_reruns_itself_through_sudo(shims: Path, fsroot: Path, checkout: Path) -> None:
    result = _stack(shims, fsroot, "--no-firewall", "alice", str(checkout), SHIM_UID="1000")
    assert result.returncode == 0, result.stderr
    assert (
        _calls(shims)[-1] == f"sudo -- {HOST}/install-stack-unit.sh --no-firewall alice {checkout}"
    )


def test_stack_unit_uninstall(shims: Path, fsroot: Path) -> None:
    unit = fsroot / "etc/systemd/system/suckerpot-stack.service"
    unit.write_text("x")
    assert _stack(shims, fsroot, "--uninstall").returncode == 0
    assert not unit.exists()
    assert "systemctl disable suckerpot-stack.service" in _calls(shims)


# --- Library hooks for the installer (Podman phase 3): engine.sh, firewall.sh, env.sh ---------

LIB_FILES = [
    "scripts/lib/engine.sh",
    "scripts/lib/env.sh",
    "scripts/lib/firewall.sh",
    "scripts/host/render-firewall.sh",
    "scripts/host/firewall.nft",
    "scripts/host/firewall-participant.nft",
    "scripts/egress-check.sh",
    "scripts/ensure-networks.sh",
    "scripts/lib/fwcheck.sh",
]
LOADER_STUB = '#!/bin/sh\necho "install-firewall $*" >> "$SHIM_LOG"\nexit "${SHIM_FW_RC:-0}"\n'
UNIT_STUB = '#!/bin/sh\necho "install-stack-unit $*" >> "$SHIM_LOG"\nexit 0\n'
NETS_STUB = '#!/bin/sh\necho "ensure-networks $*" >> "$SHIM_LOG"\nn=$(cat "$SHIM_DIR/nets-rc" 2>/dev/null || echo 0)\necho 0 > "$SHIM_DIR/nets-rc"\nexit "$n"\n'
RECORD = '#!/bin/sh\necho "$(basename "$0") $*" >> "$SHIM_LOG"\nexit 0\n'


@pytest.fixture
def libbox(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for rel in LIB_FILES:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, root / rel)
    _write_exec(root / "scripts/host/install-firewall.sh", LOADER_STUB)
    _write_exec(root / "scripts/host/install-stack-unit.sh", UNIT_STUB)
    shim = tmp_path / "shim"
    shim.mkdir()
    for name in ("docker", "podman", "docker-compose", "sudo", "systemctl"):
        _write_exec(shim / name, RECORD)
    _write_exec(shim / "ip", "#!/bin/sh\nexit 0\n")
    return root


LIB_PRELUDE = "set -uo pipefail\n. scripts/lib/env.sh\n. scripts/lib/firewall.sh\n"


def _lib(root: Path, body: str, env_file: str, **env: str) -> subprocess.CompletedProcess[str]:
    (root / ".env").write_text(env_file)
    shim = root.parent / "shim"
    return subprocess.run(  # noqa: S603
        ["bash", "-c", LIB_PRELUDE + body],  # noqa: S607
        cwd=root,
        env={
            "PATH": f"{shim}:{PATH}",
            "HOME": str(root.parent),
            "SHIM_DIR": str(shim),
            "SHIM_LOG": str(shim / "log"),
            **env,
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


PODMAN_ENV = "SUCKERPOT_ENGINE=podman\nADMIN_SSH_PORT=2200\nCOMPOSE_FILE=docker-compose.yml:docker-compose.podman.yml\n"
DOCKER_ENV = "SUCKERPOT_ENGINE=docker\nADMIN_SSH_PORT=2200\n"


def test_engine_hooks_do_nothing_on_docker(libbox: Path) -> None:
    result = _lib(
        libbox,
        "engine_prepare_networks; engine_install_boot_unit; echo overlay=[$(engine_compose_overlay)]\n"
        "engine_image timescale/x:1; engine_image alpine:3",
        DOCKER_ENV,
    )
    assert result.returncode == 0, result.stderr
    assert "overlay=[]" in result.stdout
    assert "timescale/x:1\nalpine:3\n" in result.stdout
    assert _log(libbox) == []


def test_engine_hooks_on_podman(libbox: Path) -> None:
    _write_exec(libbox / "scripts/ensure-networks.sh", NETS_STUB)
    result = _lib(
        libbox,
        "engine_prepare_networks; engine_install_boot_unit --no-firewall; engine_install_boot_unit\n"
        "echo overlay=[$(engine_compose_overlay)]\n"
        "engine_image timescale/x:1; engine_image alpine:3; engine_image ghcr.io/a/b:1; "
        "engine_image localhost/a:1",
        PODMAN_ENV,
    )
    assert result.returncode == 0, result.stderr
    assert "overlay=[docker-compose.podman.yml]" in result.stdout
    assert (
        "docker.io/timescale/x:1\ndocker.io/library/alpine:3\nghcr.io/a/b:1\nlocalhost/a:1\n"
        in result.stdout
    )
    real = libbox.resolve()
    calls = _log(libbox)
    assert calls[0] == "ensure-networks "
    assert len(calls) == 3
    assert calls[1].startswith("install-stack-unit --no-firewall ") and calls[1].endswith(
        f" {real}"
    )
    assert calls[2].startswith("install-stack-unit ") and "--no-firewall" not in calls[2]


def test_firewall_is_required_on_podman_and_a_failure_stops(libbox: Path) -> None:
    ok = _lib(libbox, "fw_step participant auto; echo rc=$?", PODMAN_ENV, SHIM_FW_RC="0")
    assert "rc=0" in ok.stdout, ok.stdout + ok.stderr
    assert "required on Podman" in ok.stdout
    assert "Install the host firewall now?" not in ok.stderr
    rendered = (libbox / ".suckerpot-state/host-firewall.nft").read_text()
    assert "table bridge suckerpot_bridge" in rendered
    bad = _lib(libbox, "fw_step participant auto; echo rc=$?", PODMAN_ENV, SHIM_FW_RC="5")
    assert "rc=1" in bad.stdout and "does not start without it" in bad.stdout


def test_firewall_opt_out_on_podman_only_warns(libbox: Path) -> None:
    result = _lib(
        libbox, "fw_step participant auto; echo rc=$?", PODMAN_ENV + "SUCKERPOT_NO_FIREWALL=1\n"
    )
    assert "rc=0" in result.stdout and "WARNING: skipped (--no-firewall)" in result.stdout
    assert not [c for c in _log(libbox) if c.startswith("install-firewall")]


def test_docker_firewall_step_stays_optional(libbox: Path) -> None:
    result = _lib(
        libbox,
        "fw_required && echo required || echo optional; fw_step participant; echo rc=$?",
        DOCKER_ENV,
        SHIM_FW_RC="5",
    )
    assert "optional" in result.stdout and "rc=0" in result.stdout
    assert "required on Podman" not in result.stdout
    rendered = (libbox / ".suckerpot-state/host-firewall.nft").read_text()
    assert "suckerpot_bridge" not in rendered


def test_compose_up_recreating_on_podman_recreates_networks_once(libbox: Path) -> None:
    _write_exec(libbox / "scripts/ensure-networks.sh", NETS_STUB)
    (libbox.parent / "shim" / "nets-rc").write_text("3")
    result = _lib(libbox, "compose_up_recreating -d --wait; echo rc=$?", PODMAN_ENV)
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    calls = _log(libbox)
    assert calls == [
        "ensure-networks ",
        "docker-compose down --remove-orphans",
        "ensure-networks ",
        "docker-compose up -d --wait",
    ]


# --- egress-check.sh --isolation (both engines, D10) ------------------------------------------

# One fake for docker, docker-compose and podman: two sensors, each with one gateway, one address
# and one port. A probe succeeds only when listed in SHIM_YES (resolve:redis always does).
FAKE_ENGINE = r"""#!/bin/bash
me=$(basename "$0")
args=("$@")
[ "$me" = podman ] && args=("${args[@]:2}")
if [ "$me" = docker ] && [ "${args[0]}" = compose ]; then args=("${args[@]:1}"); me=compose; fi
[ "$me" = docker-compose ] && me=compose
set -- "${args[@]}"
case "$me $1" in
  "compose ps")
    case "$*" in
      *"--status running"*) [ -n "${SHIM_NO_SENSORS:-}" ] || printf 'sensor-ssh\nsensor-web\n' ;;
      "ps -q "*) echo "cid-${!#}" ;;
    esac ;;
  "compose exec")
    shift 6  # exec -T SERVICE python -c CODE
    for p in "$@"; do
      r=no
      [ "$p" = resolve:redis ] && r=yes
      for y in ${SHIM_YES:-}; do [ "$y" = "$p" ] && r=yes; done
      echo "$p $r"
    done ;;
  "docker inspect" | "podman inspect")
    c=${!#}
    case "$3" in
      *Gateway*) echo "192.0.2.1 " ;;
      *HostPort*) [ "$c" = cid-sensor-ssh ] && echo "22 " || echo "80 443 " ;;
      *IPAddress*) [ "$c" = cid-sensor-ssh ] && echo "192.0.2.2 " || echo "192.0.2.3 " ;;
      *Ports*) [ "$c" = cid-sensor-ssh ] && echo "2222/tcp " || echo "8080/tcp 8443/tcp " ;;
    esac ;;
esac
exit 0
"""


def _isolation(root: Path, env_file: str, **env: str) -> subprocess.CompletedProcess[str]:
    shim = root.parent / "shim"
    for name in ("docker", "docker-compose", "podman"):
        _write_exec(shim / name, FAKE_ENGINE)
    _write_exec(shim / "systemctl", SYSTEMCTL_FW)
    _write_exec(shim / "sudo", SUDO_NFT)
    _write_exec(
        shim / "sshd",
        '#!/bin/sh\n[ -n "${SHIM_SSHD_PORT:-}" ] || exit 1\necho "port $SHIM_SSHD_PORT"\n',
    )
    _write_exec(shim / "sudo", SUDO_NFT)
    _write_exec(root / "scripts/ensure-networks.sh", '#!/bin/sh\nexit "${SHIM_NETS_RC:-0}"\n')
    (root / ".env").write_text(env_file + "DASHBOARD_PORT=8443\n")
    fw_root = root.parent / "fwroot"
    (fw_root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
    env = {"SHIM_FW": "1", "SUCKERPOT_FW_ROOT": str(fw_root), **env}
    return subprocess.run(  # noqa: S603
        ["bash", str(root / "scripts/egress-check.sh"), "--isolation"],  # noqa: S607
        cwd=root,
        env={"PATH": f"{shim}:{PATH}", **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_isolation_passes_on_a_healthy_docker_node(libbox: Path) -> None:
    result = _isolation(libbox, DOCKER_ENV)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FAIL" not in result.stdout and "NOTE" not in result.stdout
    for line in (
        "sensor-ssh: resolves service names (redis)",
        "sensor-web: cannot resolve outside names",
        "sensor-ssh: no connection to the internet",
        "sensor-ssh: cannot reach another sensor (sensor-web)",
        "sensor-web: cannot reach the host's SSH or dashboard port",
    ):
        assert f"PASS  {line}" in result.stdout
    assert "podman:" not in result.stdout


def test_docker_without_the_firewall_only_notes_a_reachable_host_port(libbox: Path) -> None:
    result = _isolation(libbox, DOCKER_ENV, SHIM_YES="connect:192.0.2.1:2200", SHIM_FW="1")
    assert result.returncode == 0, result.stdout
    assert "NOTE  sensor-ssh: reaches the host on port(s) 2200" in result.stdout


def test_docker_with_the_firewall_fails_on_a_reachable_host_port(libbox: Path) -> None:
    result = _isolation(libbox, DOCKER_ENV, SHIM_YES="connect:192.0.2.1:8443", SHIM_FW="0")
    assert result.returncode == 1
    assert (
        "FAIL  sensor-ssh: cannot reach the host's SSH or dashboard port (reached port(s) 8443)"
        in result.stdout
    )


@pytest.mark.parametrize(
    ("probe", "line"),
    [
        ("connect:192.0.2.3:8443", "sensor-ssh: cannot reach another sensor"),
        ("resolve:example.com", "sensor-ssh: cannot resolve outside names"),
        ("connect:1.1.1.1:443", "sensor-ssh: no connection to the internet"),
    ],
)
def test_a_broken_guarantee_fails_on_docker(libbox: Path, probe: str, line: str) -> None:
    result = _isolation(libbox, DOCKER_ENV, SHIM_YES=probe)
    assert result.returncode == 1
    assert f"FAIL  {line}" in result.stdout


def test_isolation_on_podman_checks_networks_firewall_and_boot_unit(libbox: Path) -> None:
    good = _isolation(
        libbox,
        PODMAN_ENV,
        SHIM_FW="0",
        SHIM_BINDS="suckerpot-firewall.service",
    )
    assert good.returncode == 0, good.stdout
    assert "PASS  host firewall loaded" in good.stdout
    assert "PASS  podman: the boot unit is bound to the host firewall" in good.stdout
    bad = _isolation(
        libbox, PODMAN_ENV, SHIM_FW="1", SHIM_NETS_RC="1", SHIM_YES="connect:192.0.2.1:2200"
    )
    assert bad.returncode == 1
    for line in (
        "podman: every sp-* network has its options",
        "host firewall loaded",
        "podman: the boot unit is bound to the host firewall",
        "sensor-ssh: cannot reach the host's SSH or dashboard port (reached port(s) 2200)",
    ):
        assert f"FAIL  {line}" in bad.stdout


def test_a_port_a_sensor_publishes_is_not_probed_as_a_host_port(libbox: Path) -> None:
    """Without ADMIN_SSH_PORT the admin port is 22, which the SSH sensor publishes here: a probe
    there would reach the sensor (and add a fake event), not the host."""
    conf = Path("/etc/ssh/sshd_config")
    if conf.exists() and re.search(r"^\s*Port\s+\d+", conf.read_text(errors="replace"), re.M):
        pytest.skip("this machine's sshd_config names a port")
    result = _isolation(
        libbox, "SUCKERPOT_ENGINE=docker\n", SHIM_YES="connect:192.0.2.1:22", SHIM_FW="0"
    )
    assert result.returncode == 0, result.stdout
    assert "PASS  sensor-ssh: cannot reach the host's SSH or dashboard port" in result.stdout
    assert "NOTE  the admin SSH port is unknown" in result.stdout


def test_the_configured_sshd_port_is_probed_without_admin_ssh_port(libbox: Path) -> None:
    """ADMIN_SSH_PORT empty, a sensor on 22: the port sshd is configured with is still probed."""
    result = _isolation(
        libbox,
        "SUCKERPOT_ENGINE=docker\n",
        SHIM_SSHD_PORT="2022",
        SHIM_YES="connect:192.0.2.1:2022",
        SHIM_FW="0",
    )
    assert result.returncode == 1
    assert "reached port(s) 2022" in result.stdout


def test_install_starts_an_inactive_unit_and_reloads_an_active_one(
    tmp_path: Path, resolv: Path, shims: Path, fsroot: Path
) -> None:
    rendered = tmp_path / "fw.nft"
    rendered.write_text(_podman(tmp_path, resolv, "participant"))
    assert _run(HOST / "install-firewall.sh", shims, fsroot, str(rendered)).returncode == 0
    assert "systemctl start suckerpot-firewall.service" in _calls(shims)
    (shims / "log").unlink()
    ok = _run(HOST / "install-firewall.sh", shims, fsroot, str(rendered), SHIM_ACTIVE="0")
    assert ok.returncode == 0, ok.stderr
    calls = _calls(shims)
    assert "systemctl reload suckerpot-firewall.service" in calls
    # Never a restart or a stop: on Podman the stack is bound to the unit.
    assert not [c for c in calls if " restart " in c or " stop " in c]


def test_uninstall_refuses_while_podman_containers_run(shims: Path, fsroot: Path) -> None:
    unit = fsroot / "etc/systemd/system/suckerpot-firewall.service"
    unit.write_text("x")
    result = _run(
        HOST / "install-firewall.sh", shims, fsroot, "--uninstall", SHIM_RUNNING="c0ffee\n"
    )
    assert result.returncode == 6
    assert "SUCKERPOT_NO_FIREWALL=1" in result.stderr
    assert unit.exists()
    assert not [c for c in _calls(shims) if c.startswith(("systemctl disable", "nft delete"))]
    forced = _run(
        HOST / "install-firewall.sh",
        shims,
        fsroot,
        "--uninstall",
        SHIM_RUNNING="c0ffee\n",
        SUCKERPOT_NO_FIREWALL="1",
    )
    assert forced.returncode == 0, forced.stderr
    assert not unit.exists()


def test_uninstall_keeps_the_opt_out_through_sudo(shims: Path, fsroot: Path) -> None:
    result = _run(
        HOST / "install-firewall.sh",
        shims,
        fsroot,
        "--uninstall",
        SHIM_UID="1000",
        SUCKERPOT_NO_FIREWALL="1",
    )
    assert result.returncode == 0, result.stderr
    assert _calls(shims)[-1] == (
        f"sudo -- env SUCKERPOT_NO_FIREWALL=1 {HOST}/install-firewall.sh --uninstall"
    )


def test_docker_firewall_installed_but_not_in_force_fails(libbox: Path) -> None:
    fw_root = libbox.parent / "fwroot" / "etc/systemd/system"
    fw_root.mkdir(parents=True, exist_ok=True)
    (fw_root / "suckerpot-firewall.service").write_text("[Unit]\n")
    stopped = _isolation(libbox, DOCKER_ENV, SHIM_FW="1")
    assert stopped.returncode == 1
    assert "FAIL  host firewall loaded (suckerpot-firewall.service is installed but not active" in (
        stopped.stdout
    )
    flushed = _isolation(libbox, DOCKER_ENV, SHIM_FW="0", SHIM_TABLES="")
    assert flushed.returncode == 1
    assert "table(s) inet suckerpot_host are gone" in flushed.stdout
    # Docker needs only the inet table.
    good = _isolation(libbox, DOCKER_ENV, SHIM_FW="0", SHIM_TABLES="table inet suckerpot_host")
    assert good.returncode == 0, good.stdout
    assert "PASS  host firewall loaded" in good.stdout


def test_unreadable_tables_fail_on_podman_and_note_on_docker(libbox: Path) -> None:
    podman = _isolation(
        libbox, PODMAN_ENV, SHIM_FW="0", SHIM_NFT_RC="1", SHIM_BINDS="suckerpot-firewall.service"
    )
    assert podman.returncode == 1
    assert "FAIL  host firewall loaded (unit active; its tables cannot be read" in podman.stdout
    docker = _isolation(libbox, DOCKER_ENV, SHIM_FW="0", SHIM_NFT_RC="1")
    assert docker.returncode == 0, docker.stdout
    assert "NOTE  host firewall unit active; its tables were not read" in docker.stdout


def test_podman_with_the_bridge_table_gone_fails(libbox: Path) -> None:
    result = _isolation(
        libbox,
        PODMAN_ENV,
        SHIM_FW="0",
        SHIM_TABLES="table inet suckerpot_host",
        SHIM_BINDS="suckerpot-firewall.service",
    )
    assert result.returncode == 1
    assert "table(s) bridge suckerpot_bridge are gone" in result.stdout


def test_no_running_sensor_is_a_failure(libbox: Path) -> None:
    result = _isolation(libbox, DOCKER_ENV, SHIM_NO_SENSORS="1")
    assert result.returncode == 1
    assert "FAIL  at least one sensor is running" in result.stdout


def test_a_podman_rendering_gets_a_drop_in_that_stops_the_containers_first(
    tmp_path: Path, resolv: Path, shims: Path, fsroot: Path
) -> None:
    dropin = fsroot / "etc/systemd/system/suckerpot-firewall.service.d/podman-stop.conf"
    rendered = tmp_path / "fw.nft"
    rendered.write_text(_podman(tmp_path, resolv, "participant"))
    assert _run(HOST / "install-firewall.sh", shims, fsroot, str(rendered)).returncode == 0
    stops = [ln for ln in dropin.read_text().splitlines() if ln.startswith("ExecStop=")]
    # The list is reset, then: containers first, then the tables.
    assert stops[0] == "ExecStop="
    assert (
        stops[1]
        == f"ExecStop=-{shims}/podman stop --time 10 --filter label=com.docker.compose.project"
    )
    assert stops[2:] == [
        "ExecStop=/usr/sbin/nft delete table inet suckerpot_host",
        "ExecStop=-/usr/sbin/nft delete table bridge suckerpot_bridge",
    ]
    # A Docker rendering removes it again: the Docker unit is the plain unit file.
    docker = tmp_path / "docker.nft"
    docker.write_text("table inet suckerpot_host {\n}\n")
    assert _run(HOST / "install-firewall.sh", shims, fsroot, str(docker)).returncode == 0
    assert not dropin.exists()
    rendered_again = _run(HOST / "install-firewall.sh", shims, fsroot, str(rendered))
    assert rendered_again.returncode == 0 and dropin.exists()
    assert _run(HOST / "install-firewall.sh", shims, fsroot, "--uninstall").returncode == 0
    assert not dropin.exists()


def test_the_docker_firewall_unit_is_unchanged_apart_from_the_nftables_binding() -> None:
    unit = (HOST / "suckerpot-firewall.service").read_text()
    assert not [ln for ln in unit.splitlines() if "podman" in ln and not ln.startswith("#")]
    assert [ln for ln in unit.splitlines() if ln.startswith("ExecStop")] == [
        "ExecStop=/usr/sbin/nft delete table inet suckerpot_host",
        "ExecStop=-/usr/sbin/nft delete table bridge suckerpot_bridge",
    ]
