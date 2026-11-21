"""Host firewall (scripts/host): the participant and full templates, the renderer and the installer.

The renderer is pure, so it runs for real. The installer runs with fake ``id``, ``nft``,
``systemctl``, ``install`` and ``sudo`` programs first on PATH: they only record their calls.
When a real ``nft`` may check a ruleset (root), the rendered files are also checked with ``nft -c``.
"""

import fnmatch
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from suckerpot_guardrails.compose import BRIDGE_NAMES

ROOT = Path(__file__).resolve().parents[3]
HOST = ROOT / "scripts" / "host"
RENDER = HOST / "render-firewall.sh"
INSTALL = HOST / "install-firewall.sh"
PARTICIPANT_TEMPLATE = HOST / "firewall-participant.nft"
FULL_TEMPLATE = HOST / "firewall.nft"
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Not on a public network: none of these may ever be reached from sp-hubgate.
PRIVATE_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",  # gitleaks:allow (a private range, the point of the test)
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",  # gitleaks:allow (a private range, the point of the test)
    "192.168.0.0/16",  # gitleaks:allow (a private range, the point of the test)
    "224.0.0.0/3",
)


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def resolv(tmp_path: Path) -> Path:
    """A resolver configuration with one public and one private upstream (documentation IPs)."""
    path = tmp_path / "resolv.conf"
    path.write_text("# test\nnameserver 192.0.2.53\nnameserver 198.51.100.53\nsearch .\n")
    return path


# Fake `ip` and `docker` for the renderer's bridge check: they print what the test puts in the
# STUB_* variables and never touch the real host or daemon.
IP_STUB = """#!/bin/sh
[ "$*" = "-o link show type bridge" ] || exit 1
printf '%s' "${STUB_IP_OUT:-}"
"""
DOCKER_STUB = """#!/bin/sh
[ "${STUB_DOCKER_RC:-0}" = 0 ] || exit "$STUB_DOCKER_RC"
case "$*" in
  "network ls --filter driver=bridge --no-trunc -q") printf '%s' "${STUB_DOCKER_IDS:-}" ;;
  "network inspect "*) printf '%s' "${STUB_DOCKER_INSPECT:-}" ;;
  *) exit 1 ;;
esac
"""


def _ip_lines(*names: str) -> str:
    return "".join(
        f"{i}: {n}: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP\\    link/ether\n"
        for i, n in enumerate(names, start=3)
    )


def render(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as stubs:
        _write_exec(Path(stubs) / "ip", IP_STUB)
        _write_exec(Path(stubs) / "docker", DOCKER_STUB)
        return subprocess.run(  # noqa: S603
            ["bash", str(RENDER), *args],  # noqa: S607
            env={"PATH": f"{stubs}:{PATH}", **(env or {})},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )


def _participant(resolv: Path, *extra: str) -> str:
    result = render(
        "--participant", "--admin-ssh-port", "2200", "--resolv-conf", str(resolv), *extra
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _rules(text: str) -> list[str]:
    """Rule lines, without comments, in order."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _chain(text: str, name: str) -> list[str]:
    rules = _rules(text)
    start = rules.index(f"chain {name} {{")
    end = rules.index("}", start)
    return rules[start + 1 : end]


def _iif(rule: str, bridge: str) -> bool:
    """Whether a rule's iifname match covers the bridge (exact name, a set or a wildcard)."""
    match = re.search(r'iifname (\{[^}]*\}|"[^"]*")', rule)
    if not match:
        return False
    names = re.findall(r'"([^"]+)"', match.group(1))
    return any(fnmatch.fnmatchcase(bridge, n) for n in names)


# --- Participant ruleset -----------------------------------------------------------------------


def test_participant_template_has_one_placeholder_only() -> None:
    text = PARTICIPANT_TEMPLATE.read_text()
    assert text.count("CHANGE_ME") == 1
    assert "define ADMIN_SSH_PORT = CHANGE_ME" in text
    assert "VPN_ENDPOINT" not in text and "DASHBOARD_PORT" not in text


def test_participant_rendering_is_complete(resolv: Path) -> None:
    text = _participant(resolv)
    assert "CHANGE_ME" not in text
    assert not re.search(r"@[A-Z_]+@", text)
    assert "define ADMIN_SSH_PORT = 2200" in _rules(text)
    assert "define HUBGATE_DNS = { 192.0.2.53, 198.51.100.53 }" in _rules(text)
    assert _rules(text)[:3] == [
        "define ADMIN_SSH_PORT = 2200",
        "define HUBGATE_DNS = { 192.0.2.53, 198.51.100.53 }",
        "add table inet suckerpot_host",
    ]
    # Its own table, never a flush of Docker's rules.
    assert "flush ruleset" not in text
    assert "delete table inet suckerpot_host" in _rules(text)


def test_participant_sensors_start_nothing(resolv: Path) -> None:
    text = _participant(resolv)
    forward = _chain(text, "forward")
    assert forward[1] == "ct state established,related accept"
    drop = 'iifname { "sp-ingress", "sp-dashboard" } counter drop'
    assert drop in forward
    # Nothing from sp-ingress is ever accepted, before or after the drop.
    assert not [r for r in forward if _iif(r, "sp-ingress") and r.endswith("accept")]
    assert 'iifname "sp-*" meta nfproto ipv6 counter drop' in forward


def test_participant_no_container_network_talks_to_the_host(resolv: Path) -> None:
    text = _participant(resolv)
    inp = _chain(text, "input")
    drop = 'iifname "sp-*" counter drop'
    assert drop in inp
    for bridge in BRIDGE_NAMES.values():
        assert _iif(drop, bridge), bridge
    # The only accept from a SuckerPot bridge is DNS to the listed resolvers.
    accepts = [r for r in inp if r.endswith("accept") and "iifname" in r and '"lo"' not in r]
    assert accepts == [
        'iifname "sp-hubgate" ct state new ip daddr $HUBGATE_DNS udp dport 53 counter accept'
    ]
    assert inp.index(accepts[0]) < inp.index(drop)
    # Other Docker networks never reach the admin port; the LAN (no Docker bridge) is not matched.
    assert (
        'iifname { "docker0", "br-*" } ct state new tcp dport $ADMIN_SSH_PORT counter drop' in inp
    )
    for rule in inp:
        if "drop" in rule:
            assert "iifname" in rule, rule


def test_participant_hubgate_allows_443_and_restricted_dns_only(resolv: Path) -> None:
    forward = _chain(_participant(resolv), "forward")
    hub = [r for r in forward if _iif(r, "sp-hubgate") and r.startswith('iifname "sp-hubgate"')]
    assert hub[0] == (
        'iifname "sp-hubgate" ct state new ip daddr $HUBGATE_DNS udp dport 53 counter accept'
    )
    assert hub[1].startswith('iifname "sp-hubgate" ct state new ip daddr {')
    assert hub[1].endswith("counter drop")
    for net in PRIVATE_V4:
        assert net in hub[1], net
    assert hub[2:] == [
        'iifname "sp-hubgate" ct state new tcp dport 443 counter accept',
        'iifname "sp-hubgate" counter drop',
    ]
    # IPv6 from the uplink is dropped before any of these.
    v6 = forward.index('iifname "sp-*" meta nfproto ipv6 counter drop')
    assert v6 < forward.index(hub[0])


@pytest.mark.parametrize(
    "template", [PARTICIPANT_TEMPLATE, FULL_TEMPLATE], ids=["participant", "full"]
)
def test_hubgate_dns_is_never_open_to_any_destination(template: Path) -> None:
    for rule in _rules(template.read_text()):
        if "sp-hubgate" in rule and re.search(r"\b53\b", rule):
            assert "ip daddr $HUBGATE_DNS udp dport 53" in rule, rule
            assert "tcp" not in rule and "th dport" not in rule, rule


def test_participant_vpn_endpoint_is_optional(resolv: Path) -> None:
    forward = _chain(_participant(resolv), "forward")
    assert not [r for r in forward if "sp-vpn" in r and r.endswith("accept")]
    assert 'iifname "sp-vpn" counter drop' in forward
    forward = _chain(_participant(resolv, "--vpn-endpoint", "203.0.113.10:51820"), "forward")
    accept = 'iifname "sp-vpn" ct state new ip daddr 203.0.113.10 udp dport 51820 counter accept'
    assert forward.index(accept) == forward.index('iifname "sp-vpn" counter drop') - 1


UPLINKS = ("sp-ingress", "sp-dashboard", "sp-vpn", "sp-hubgate")
INTERNAL = (
    "sp-s-ssh",
    "sp-s-web",
    "sp-backend",
    "sp-tools",
    "sp-hubproxy",
    "sp-egress",
    "sp-samples",
)


def _full(resolv: Path) -> str:
    result = render("--full", "--admin-ssh-port", "2200", "--resolv-conf", str(resolv))
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.parametrize("mode", ["participant", "full"])
def test_invalid_and_untracked_packets_never_pass(resolv: Path, mode: str) -> None:
    text = _participant(resolv) if mode == "participant" else _full(resolv)
    forward = _chain(text, "forward")
    for bridge in UPLINKS:
        rules = [r for r in forward if _iif(r, bridge) and "nfproto ipv6" not in r]
        # The last word on every uplink is a drop that does not depend on the connection state.
        assert rules[-1].endswith("counter drop") and "ct state" not in rules[-1], (bridge, rules)
        # Before it, only new connections are accepted (replies passed at the top already).
        for rule in rules[:-1]:
            assert "ct state new" in rule, rule
    inp = _chain(text, "input")
    for bridge in BRIDGE_NAMES.values():
        stateless = [r for r in inp if _iif(r, bridge) and r.endswith("counter drop")]
        assert any("ct state" not in r and "dport" not in r for r in stateless), bridge
        for rule in inp:
            if _iif(rule, bridge) and rule.endswith("accept"):
                assert "ct state new" in rule and "udp dport 53" in rule, rule


@pytest.mark.parametrize("mode", ["participant", "full"])
def test_same_bridge_traffic_on_internal_networks_is_left_alone(resolv: Path, mode: str) -> None:
    text = _participant(resolv) if mode == "participant" else _full(resolv)
    for rule in _chain(text, "forward"):
        for bridge in INTERNAL:
            if _iif(rule, bridge):
                # Only the IPv6 drop may name an internal bridge (through the sp-* wildcard).
                assert rule == 'iifname "sp-*" meta nfproto ipv6 counter drop', (bridge, rule)


# --- Bridges that are not Docker's ------------------------------------------------------------

DOCKER_ID = "a1b2c3d4e5f6" + "0" * 52


def _bridges(resolv: Path, *extra: str, **env: str) -> subprocess.CompletedProcess[str]:
    return render(
        "--participant", "--admin-ssh-port", "2200", "--resolv-conf", str(resolv), *extra, env=env
    )


def test_docker_bridges_are_accepted(resolv: Path) -> None:
    result = _bridges(
        resolv,
        STUB_IP_OUT=_ip_lines("docker0", "br-a1b2c3d4e5f6", "sp-ingress", "virbr0", "lxdbr0"),
        STUB_DOCKER_IDS=f"{DOCKER_ID}\n{'f' * 64}\n{'e' * 64}\n",
        STUB_DOCKER_INSPECT=(
            f"{DOCKER_ID} <no value>\n{'f' * 64} sp-ingress\n{'e' * 64} docker0\n"
        ),
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", ["br-lan", "br0x", "br-a1b2c3d4e5f6", "sp-vms"])
def test_a_host_bridge_that_matches_a_wildcard_is_refused(resolv: Path, name: str) -> None:
    # Docker answers and does not own the bridge (even br-<12 hex>: Docker's word wins).
    result = _bridges(
        resolv,
        STUB_IP_OUT=_ip_lines("docker0", name),
        STUB_DOCKER_IDS=f"{'e' * 64}\n",
        STUB_DOCKER_INSPECT=f"{'e' * 64} docker0\n",
    )
    if not (name.startswith("br-") or name.startswith("sp-")):
        assert result.returncode == 0, result.stderr  # br0x: no wildcard matches it
        return
    assert result.returncode == 2
    assert result.stdout == ""
    assert name in result.stderr and "lock yourself out" in result.stderr
    assert "--allow-bridge" in result.stderr


def test_allow_bridge_accepts_a_named_host_bridge(resolv: Path) -> None:
    env = {"STUB_IP_OUT": _ip_lines("br-lan", "sp-vms"), "STUB_DOCKER_IDS": ""}
    assert _bridges(resolv, "--allow-bridge", "br-lan", **env).returncode == 2
    result = _bridges(resolv, "--allow-bridge", "br-lan", "--allow-bridge", "sp-vms", **env)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("name", "ok"),
    [("br-a1b2c3d4e5f6", True), ("sp-backend", True), ("br-lan", False), ("sp-other", False)],
)
def test_without_docker_bridges_are_judged_by_name(resolv: Path, name: str, ok: bool) -> None:
    result = _bridges(resolv, STUB_IP_OUT=_ip_lines(name), STUB_DOCKER_RC="1")
    assert (result.returncode == 0) is ok, result.stderr
    if not ok:
        assert "judged by name only" in result.stderr


def test_renderer_knows_every_fixed_bridge_name() -> None:
    match = re.search(r'^SP_BRIDGES="([^"]+)"$', RENDER.read_text(), re.M)
    assert match
    assert set(match.group(1).split()) == set(BRIDGE_NAMES.values())


# --- Arguments ---------------------------------------------------------------------------------


@pytest.mark.parametrize("port", ["0", "65536", "99999", "22a", "-1", "022", " 22", "1e3", ""])
def test_admin_port_must_be_an_integer_from_1_to_65535(resolv: Path, port: str) -> None:
    result = render("--participant", "--admin-ssh-port", port, "--resolv-conf", str(resolv))
    assert result.returncode == 2
    assert result.stdout == ""


@pytest.mark.parametrize("port", ["1", "22", "2200", "65535"])
def test_admin_port_is_substituted(resolv: Path, port: str) -> None:
    assert f"define ADMIN_SSH_PORT = {port}" in _participant(resolv, "--admin-ssh-port", port)


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--participant"],
        ["--participant", "--full", "--admin-ssh-port", "2200"],
        ["--participant", "--admin-ssh-port", "2200", "--vpn-endpoint", "203.0.113.10"],
        ["--participant", "--admin-ssh-port", "2200", "--vpn-endpoint", "203.0.113.300:51820"],
        ["--participant", "--admin-ssh-port", "2200", "--vpn-endpoint", "203.0.113.1:0"],
        ["--participant", "--admin-ssh-port", "2200", "--dns", "2001:db8::1"],
        ["--participant", "--admin-ssh-port", "2200", "--dns", "192.0.2.1; flush ruleset"],
        ["--participant", "--admin-ssh-port", "2200", "--dashboard-port", "9000"],
        ["--full", "--admin-ssh-port", "8443"],
        ["--participant", "--admin-ssh-port", "2200", "--bogus"],
    ],
)
def test_bad_arguments_are_refused(args: list[str]) -> None:
    result = render(*args)
    assert result.returncode == 2, result.stdout
    assert result.stdout == ""


# --- Resolvers ---------------------------------------------------------------------------------


def _dns_line(text: str) -> str:
    return next(r for r in _rules(text) if r.startswith("define HUBGATE_DNS"))


def test_systemd_stub_uses_the_upstream_list(tmp_path: Path) -> None:
    stub = tmp_path / "resolv.conf"
    stub.write_text("nameserver 127.0.0.53\noptions edns0 trust-ad\n")
    upstream = tmp_path / "upstream.conf"
    upstream.write_text("nameserver 192.0.2.10\nnameserver 2001:db8::1\nnameserver 192.0.2.11\n")
    text = _participant(stub, "--systemd-resolv-conf", str(upstream))
    assert _dns_line(text) == "define HUBGATE_DNS = { 192.0.2.10, 192.0.2.11 }"


def test_loopback_only_resolver_gets_no_dns_rule(tmp_path: Path) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.1\nnameserver ::1\n")
    result = render(
        "--participant",
        "--admin-ssh-port",
        "2200",
        "--resolv-conf",
        str(conf),
        "--systemd-resolv-conf",
        str(tmp_path / "missing"),
    )
    assert result.returncode == 0
    assert _dns_line(result.stdout) == "define HUBGATE_DNS = { 127.0.0.1 }"
    assert "no non-loopback IPv4 resolver" in result.stderr


def test_stub_without_upstream_list_falls_back_to_none(tmp_path: Path) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.53\n")
    text = _participant(conf, "--systemd-resolv-conf", str(tmp_path / "missing"))
    assert _dns_line(text) == "define HUBGATE_DNS = { 127.0.0.1 }"


def test_mixed_resolv_conf_is_read_as_is(tmp_path: Path) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.53\nnameserver 198.51.100.7\nnameserver fe80::1%eth0\n")
    upstream = tmp_path / "upstream.conf"
    upstream.write_text("nameserver 192.0.2.99\n")
    text = _participant(conf, "--systemd-resolv-conf", str(upstream))
    assert _dns_line(text) == "define HUBGATE_DNS = { 198.51.100.7 }"


def test_dns_option_replaces_the_resolver_file(resolv: Path) -> None:
    text = _participant(resolv, "--dns", "203.0.113.53", "--dns", "203.0.113.53")
    assert _dns_line(text) == "define HUBGATE_DNS = { 203.0.113.53 }"


# --- Full mode ---------------------------------------------------------------------------------


def test_full_rendering_keeps_the_owner_rules(resolv: Path) -> None:
    result = render(
        "--full",
        "--admin-ssh-port",
        "2200",
        "--dashboard-port",
        "9443",
        "--vpn-endpoint",
        "203.0.113.10:51820",
        "--resolv-conf",
        str(resolv),
    )
    assert result.returncode == 0, result.stderr
    text = result.stdout
    assert "CHANGE_ME" not in text
    rules = _rules(text)
    for line in (
        "define ADMIN_SSH_PORT = 2200",
        "define DASHBOARD_PORT = 9443",
        "define VPN_ENDPOINT_IP = 203.0.113.10",
        "define VPN_ENDPOINT_PORT = 51820",
        "define HUBGATE_DNS = { 192.0.2.53, 198.51.100.53 }",
    ):
        assert line in rules, line
    forward = _chain(text, "forward")
    assert 'iifname { "sp-ingress", "sp-dashboard" } counter drop' in forward
    assert 'iifname "sp-*" meta nfproto ipv6 counter drop' in forward
    inp = _chain(text, "input")
    assert 'iifname { "sp-s-*", "sp-backend", "sp-tools" } counter drop' in inp
    # Every SuckerPot bridge is covered by a "new connection to the host" drop.
    host_drops = [r for r in inp if r.endswith("counter drop") and "dport" not in r]
    for bridge in BRIDGE_NAMES.values():
        assert any(_iif(r, bridge) for r in host_drops), bridge


def test_full_rendering_without_vpn_matches_nothing(resolv: Path) -> None:
    result = render("--full", "--admin-ssh-port", "2200", "--resolv-conf", str(resolv))
    assert result.returncode == 0
    assert "define VPN_ENDPOINT_IP = 127.0.0.1" in _rules(result.stdout)


def test_out_file_is_private(tmp_path: Path, resolv: Path) -> None:
    out = tmp_path / "fw.nft"
    result = render(
        "--participant", "--admin-ssh-port", "2200", "--resolv-conf", str(resolv), "--out", str(out)
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "define ADMIN_SSH_PORT = 2200" in out.read_text()


def _nft_can_check() -> bool:
    nft = shutil.which("nft", path=PATH)
    if nft is None:
        return False
    probe = subprocess.run(  # noqa: S603
        [nft, "-c", "-f", "/dev/null"], capture_output=True, text=True, timeout=10, check=False
    )
    return probe.returncode == 0


@pytest.mark.skipif(not _nft_can_check(), reason="nft missing or not allowed to check (needs root)")
@pytest.mark.parametrize("mode", ["--participant", "--full"])
def test_rendered_ruleset_passes_nft_check(tmp_path: Path, resolv: Path, mode: str) -> None:
    out = tmp_path / "fw.nft"
    result = render(
        mode, "--admin-ssh-port", "2200", "--resolv-conf", str(resolv), "--out", str(out)
    )
    assert result.returncode == 0, result.stderr
    assert "ruleset is valid" in result.stderr


# --- Installer ---------------------------------------------------------------------------------

SHIM = """#!/bin/sh
echo "$(basename "$0") $*" >> "$SHIM_LOG"
"""
# Fake nft: `-c -f FILE` records a copy of what it checked, and can rewrite the user's source
# file at that moment (SHIM_SWAP) to stand for a race between the check and the install.
NFT_SHIM = (
    SHIM
    + """case "$1" in
  -c)
    cp "$3" "$SHIM_DIR/checked"
    [ -z "${SHIM_SWAP:-}" ] || echo "table inet suckerpot_host { }  # swapped" > "$SHIM_SWAP"
    exit "${SHIM_NFT_CHECK_RC:-0}" ;;
esac
exit 0
"""
)


@pytest.fixture
def shims(tmp_path: Path) -> Path:
    shim = tmp_path / "shim"
    shim.mkdir()
    _write_exec(shim / "id", SHIM + 'echo "${SHIM_UID:-0}"\n')
    _write_exec(shim / "sudo", SHIM)
    _write_exec(shim / "install", SHIM)
    _write_exec(shim / "systemctl", SHIM)
    _write_exec(shim / "chown", SHIM)
    _write_exec(shim / "nft", NFT_SHIM)
    _write_exec(shim / "podman", SHIM)
    return shim


@pytest.fixture
def fsroot(tmp_path: Path) -> Path:
    """Stands for / : the installer writes <root>/etc/... and nothing else."""
    root = tmp_path / "root"
    (root / "etc" / "systemd" / "system").mkdir(parents=True)
    return root


def install(
    shims: Path,
    fsroot: Path,
    *args: str,
    cwd: Path | None = None,
    **env: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", str(INSTALL), *args],  # noqa: S607
        cwd=cwd,
        env={
            "PATH": f"{shims}:{PATH}",
            "SHIM_LOG": str(shims / "log"),
            "SHIM_DIR": str(shims),
            "SUCKERPOT_FW_ROOT": str(fsroot),
            **env,
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _calls(shims: Path) -> list[str]:
    log = shims / "log"
    return (
        [c for c in log.read_text().splitlines() if not c.startswith("id ")] if log.exists() else []
    )


def _leftovers(fsroot: Path) -> list[str]:
    return [p.name for p in (fsroot / "etc").iterdir() if p.name.startswith(".suckerpot-firewall")]


@pytest.fixture
def rendered(tmp_path: Path, resolv: Path) -> Path:
    out = tmp_path / "fw.nft"
    result = render(
        "--participant", "--admin-ssh-port", "2200", "--resolv-conf", str(resolv), "--out", str(out)
    )
    assert result.returncode == 0, result.stderr
    return out


def test_install_checks_a_private_copy_then_moves_it_into_place(
    shims: Path, fsroot: Path, rendered: Path
) -> None:
    original = rendered.read_text()
    result = install(shims, fsroot, str(rendered))
    assert result.returncode == 0, result.stderr
    calls = _calls(shims)
    tmp = re.fullmatch(
        rf"nft -c -f ({re.escape(str(fsroot))}/etc/\.suckerpot-firewall\.\w+)", calls[1]
    )
    assert calls[0].startswith("chown root:root ") and tmp, calls
    assert calls[0] == f"chown root:root {tmp.group(1)}"
    assert calls[2] == (
        f"install -m 0644 -o root -g root {HOST}/suckerpot-firewall.service "
        f"{fsroot}/etc/systemd/system/suckerpot-firewall.service"
    )
    assert calls[3:] == [
        "systemctl daemon-reload",
        "systemctl enable suckerpot-firewall.service",
        "systemctl is-active --quiet suckerpot-firewall.service",
        # Active: a reload loads the new file in one transaction (never a stop and start).
        "systemctl reload suckerpot-firewall.service",
        "nft list table inet suckerpot_host",
    ]
    target = fsroot / "etc" / "suckerpot-firewall.nft"
    assert target.read_text() == original == (shims / "checked").read_text()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert _leftovers(fsroot) == []
    assert "--uninstall" in result.stdout


def test_a_file_changed_after_the_check_is_not_what_gets_installed(
    shims: Path, fsroot: Path, rendered: Path
) -> None:
    original = rendered.read_text()
    result = install(shims, fsroot, str(rendered), SHIM_SWAP=str(rendered))
    assert result.returncode == 0, result.stderr
    assert "swapped" in rendered.read_text()
    assert (fsroot / "etc" / "suckerpot-firewall.nft").read_text() == original


def test_install_refuses_a_placeholder(shims: Path, fsroot: Path, tmp_path: Path) -> None:
    raw = tmp_path / "raw.nft"
    shutil.copy(PARTICIPANT_TEMPLATE, raw)
    result = install(shims, fsroot, str(raw))
    assert result.returncode == 4
    assert [c for c in _calls(shims) if not c.startswith("chown ")] == []
    assert not (fsroot / "etc" / "suckerpot-firewall.nft").exists()
    assert _leftovers(fsroot) == []


def test_install_refuses_what_nft_refuses(shims: Path, fsroot: Path, rendered: Path) -> None:
    result = install(shims, fsroot, str(rendered), SHIM_NFT_CHECK_RC="1")
    assert result.returncode == 4
    assert [c.split()[0] for c in _calls(shims)] == ["chown", "nft"]
    assert not (fsroot / "etc" / "suckerpot-firewall.nft").exists()
    assert _leftovers(fsroot) == []


def test_install_refuses_a_foreign_file(shims: Path, fsroot: Path, tmp_path: Path) -> None:
    other = tmp_path / "other.nft"
    other.write_text("flush ruleset\n")
    assert install(shims, fsroot, str(other)).returncode == 4
    assert [c for c in _calls(shims) if not c.startswith("chown ")] == []
    assert _leftovers(fsroot) == []


def test_install_needs_nft(shims: Path, fsroot: Path, rendered: Path) -> None:
    if shutil.which("nft", path=PATH):
        pytest.skip("a real nft is installed")
    (shims / "nft").unlink()
    result = install(shims, fsroot, str(rendered))
    assert result.returncode == 3, result.stderr
    assert _calls(shims) == []


def test_install_reruns_itself_through_sudo(
    shims: Path, fsroot: Path, rendered: Path, tmp_path: Path
) -> None:
    result = install(shims, fsroot, rendered.name, cwd=tmp_path, SHIM_UID="1000")
    assert result.returncode == 0, result.stderr
    assert _calls(shims) == [f"sudo -- {HOST}/install-firewall.sh {rendered}"]


@pytest.mark.parametrize("args", [[], ["a", "b"]])
def test_install_usage(shims: Path, fsroot: Path, args: list[str]) -> None:
    assert install(shims, fsroot, *args).returncode == 2


def test_uninstall(shims: Path, fsroot: Path) -> None:
    (fsroot / "etc" / "suckerpot-firewall.nft").write_text("x")
    unit = fsroot / "etc" / "systemd" / "system" / "suckerpot-firewall.service"
    unit.write_text("x")
    result = install(shims, fsroot, "--uninstall")
    assert result.returncode == 0
    calls = _calls(shims)
    # Podman is asked first whether SuckerPot containers run (none here).
    assert calls.pop(0) == "podman ps -q --filter label=com.docker.compose.project"
    assert calls[0] == "systemctl disable --now suckerpot-firewall.service"
    assert "nft delete table inet suckerpot_host" in calls
    assert calls[-1] == "systemctl daemon-reload"
    assert not unit.exists() and not (fsroot / "etc" / "suckerpot-firewall.nft").exists()
