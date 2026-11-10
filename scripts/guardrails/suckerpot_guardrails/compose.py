"""Loads compose files (with overlays) and checks the egress and isolation invariants of M21.

The checks read the YAML as written: no variable is interpolated and profiles are ignored, so a
service that only exists under a profile is checked like any other.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

Compose = dict[str, Any]

# Networks that may have a route to the internet or accept inbound traffic, with the
# bridge name and the options that make them safe.
EXTERNAL_NETWORKS: dict[str, dict[str, str]] = {
    "ingress": {
        "name": "sp-ingress",
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    },
    "dashboard": {
        "name": "sp-dashboard",
        "com.docker.network.bridge.enable_ip_masquerade": "false",
    },
    "vpn-uplink": {
        "name": "sp-vpn",
        "com.docker.network.bridge.enable_icc": "false",
    },
    # M32: the uplink of hubproxy (participant mode without a VPN), its only member.
    "hub-uplink": {
        "name": "sp-hubgate",
        "com.docker.network.bridge.enable_icc": "false",
    },
}
# The host's own admin SSH port is private to each operator, so it is configuration, never a
# constant: ADMIN_SSH_PORT in the environment (the variable scripts/check-ports.sh reads from
# .env). When it is unset, PUBLISHABLE_PORTS below still refuses any port that is not a sensor
# port or the dashboard port.
ADMIN_SSH_PORT_VAR = "ADMIN_SSH_PORT"
# Explicit allow-list of the host ports a service may publish by default: one per sensor listener
# (SSH, Telnet, HTTP, HTTPS, RDP, Redis, Docker, MySQL, MSSQL, ADB, SMB, SIP, Synology HTTP and
# HTTPS) and the dashboard. A new sensor port must be added here on purpose.
PUBLISHABLE_PORTS = frozenset(
    {"22", "23", "80", "443", "3389", "6379", "2375", "3306", "1433", "5555", "445", "5060"}
    | {"5000", "5001", "8443"}
)
PROXY_ENV = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

BRIDGE_NAME = "com.docker.network.bridge.name"
GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"
# Linux interface names hold at most 15 characters.
MAX_BRIDGE_NAME = 15

# The fixed bridge name of every network in a real install (base file, with or without the
# low-memory and participant overlays). The host firewall (scripts/host/*.nft) matches these.
# Test overlays drop them, so a throwaway project never clashes with a live stack.
BRIDGE_NAMES: dict[str, str] = {
    "ingress": "sp-ingress",
    "dashboard": "sp-dashboard",
    "vpn-uplink": "sp-vpn",
    "hub-uplink": "sp-hubgate",
    "egress-proxy": "sp-egress",
    "hub-proxy": "sp-hubproxy",
    "samples": "sp-samples",
    "backend": "sp-backend",
    "tools": "sp-tools",
    **{
        f"sensors-{s}": f"sp-s-{s}"
        for s in "ssh rdp telnet web redis docker mysql mssql adb smb sip synology".split()
    },
}

# --- Container hardening (every service of every supported rendering) --------------------------
# Each exemption names the service and the reason; anything not listed here gets the full rule.
ROOT_ALLOWED: dict[str, str] = {
    "vpn": "gluetun programs its own firewall and the tunnel as root, with NET_ADMIN only",
}
HEALTHCHECK_EXEMPT: dict[str, str] = {
    "migrate": "one-shot job: runs the migrations, then exits (restart: no)",
    "demo": "one-shot job: pushes demo events, then exits (restart: no)",
}
CAP_ADD_ALLOWED: dict[str, set[str]] = {"vpn": {"NET_ADMIN"}}
DEVICES_ALLOWED: dict[str, set[str]] = {"vpn": {"/dev/net/tun"}}
SYSCTLS_ALLOWED: dict[str, dict[str, str]] = {
    # WireGuard marks its own packets so they bypass the tunnel route.
    "vpn": {"net.ipv4.conf.all.src_valid_mark": "1"},
}
# (service, source, target): the only bind mounts, all read-only files from the repository.
BIND_MOUNTS_ALLOWED: set[tuple[str, str, str]] = {
    ("backup", "./scripts/backup-service.sh", "/backup-service.sh"),
    ("vpn", "./vpn/control-auth.toml", "/gluetun/auth/config.toml"),
    ("vpn", "./vpn/entrypoint.sh", "/vpn/entrypoint.sh"),
    ("vpn", "./vpn/health.sh", "/vpn/health.sh"),
}
TMPFS_FLAGS = ("noexec", "nosuid", "nodev")
HOST_NAMESPACE_KEYS = ("pid", "ipc", "uts", "cgroup", "userns_mode")
FORBIDDEN_KEYS = (
    "privileged",
    "network_mode",
    "volumes_from",
    "device_cgroup_rules",
    "group_add",
    "cgroup_parent",
    "runtime",
)
USER_SPEC = re.compile(r"^[1-9][0-9]*:[1-9][0-9]*$")
# Compose secrets and configs are files from the host mounted into a container. None is used
# today; an entry here would name (service, secret or config) with the reason it is needed.
SECRETS_ALLOWED: dict[tuple[str, str], str] = {}
CONFIGS_ALLOWED: dict[tuple[str, str], str] = {}
UNSAFE_SECURITY_OPT = re.compile(
    r"unconfined|label[=:]disable|no-new-privileges[=:]false", re.IGNORECASE
)
PINNED_IMAGE = re.compile(r"^[^@\s]+:[^@:/\s]+@sha256:[0-9a-f]{64}$")


class _Override(list[Any]):
    """A sequence tagged ``!override``: replaces the base value instead of extending it."""


class _OverrideMap(dict[Any, Any]):
    """A mapping tagged ``!override``: replaces the base mapping instead of merging into it."""


class _Reset:
    """A value tagged ``!reset``: removes the key."""


class _Loader(yaml.SafeLoader):
    pass


def _override(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return _Override(loader.construct_sequence(node, deep=True))
    if isinstance(node, yaml.MappingNode):
        return _OverrideMap(loader.construct_mapping(node, deep=True))
    return loader.construct_scalar(node)  # type: ignore[arg-type]


def _reset(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    return _Reset()


_Loader.add_constructor("!override", _override)
_Loader.add_constructor("!reset", _reset)


def _merge(base: Any, over: Any) -> Any:
    if isinstance(over, _Override):
        return list(over)
    if isinstance(over, _OverrideMap):
        return dict(over)
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for key, value in over.items():
            if isinstance(value, _Reset):
                out.pop(key, None)
            elif key in out:
                out[key] = _merge(out[key], value)
            else:
                out[key] = _merge(None, value)
        return out
    if isinstance(base, list) and isinstance(over, list):
        return [*base, *over]
    if isinstance(over, dict):
        return {k: _merge(None, v) for k, v in over.items() if not isinstance(v, _Reset)}
    return over


def load_compose(paths: Iterable[Path]) -> Compose:
    """Loads the files in order and merges them the way ``docker compose -f a -f b`` does."""
    merged: Compose = {}
    for path in paths:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)  # noqa: S506
        merged = _merge(merged, data or {})
    return merged


def _service_networks(service: Mapping[str, Any]) -> set[str]:
    nets = service.get("networks") or []
    return set(nets) if not isinstance(nets, Mapping) else set(nets.keys())


def _env(service: Mapping[str, Any]) -> dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, Mapping):
        return {str(k): "" if v is None else str(v) for k, v in env.items()}
    out: dict[str, str] = {}
    for item in env:
        key, _, value = str(item).partition("=")
        out[key] = value
    return out


def _mounts(service: Mapping[str, Any], volume: str) -> list[bool]:
    """For each mount of the named volume, whether it is read-only."""
    found: list[bool] = []
    for item in service.get("volumes") or []:
        if isinstance(item, Mapping):
            if item.get("source") == volume:
                found.append(bool(item.get("read_only", False)))
            continue
        parts = str(item).split(":")
        if parts[0] == volume:
            found.append(len(parts) > 2 and "ro" in parts[2].split(","))
    return found


def _mount_targets(service: Mapping[str, Any]) -> list[tuple[str, bool]]:
    """(container path, read-only) for every volume entry of a service."""
    found: list[tuple[str, bool]] = []
    for item in service.get("volumes") or []:
        if isinstance(item, Mapping):
            found.append((str(item.get("target")), bool(item.get("read_only", False))))
            continue
        parts = str(item).split(":")
        if len(parts) > 1:
            found.append((parts[1], len(parts) > 2 and "ro" in parts[2].split(",")))
    return found


def check_compose(compose: Compose) -> list[str]:
    """Returns one message per violation (an empty list means the file is acceptable)."""
    problems: list[str] = []
    services: dict[str, Any] = compose.get("services") or {}
    networks: dict[str, Any] = compose.get("networks") or {}

    # 1. Only three networks may leave "internal" mode, each with its safe options.
    if "egress" in networks:
        problems.append("network 'egress' must not exist (outbound goes through the vpn proxy)")
    for net, cfg in networks.items():
        cfg = cfg or {}
        if net in EXTERNAL_NETWORKS:
            if cfg.get("internal"):
                continue  # stricter than required (used by test overlays)
            expected = EXTERNAL_NETWORKS[net]
            if cfg.get("name") != expected["name"]:
                problems.append(f"network '{net}' must be named {expected['name']}")
            opts = cfg.get("driver_opts") or {}
            if opts.get("com.docker.network.bridge.name") != expected["name"]:
                problems.append(f"network '{net}' must set the bridge name {expected['name']}")
            for key, value in expected.items():
                if key != "name" and str(opts.get(key)) != value:
                    problems.append(f"network '{net}' must set {key}={value}")
        elif cfg.get("internal") is not True:
            problems.append(f"network '{net}' must be internal: true")
    problems += _check_network_isolation(networks)

    # Bridges that hold a proxy or sample traffic are named, so the host firewall can match them.
    for net, bridge in (
        ("egress-proxy", "sp-egress"),
        ("samples", "sp-samples"),
        ("hub-proxy", "sp-hubproxy"),
    ):
        opts = (networks.get(net) or {}).get("driver_opts") or {}
        if net in networks and opts.get("com.docker.network.bridge.name") != bridge:
            problems.append(f"network '{net}' must set the bridge name {bridge}")

    # 2. Exact membership.
    members: dict[str, set[str]] = {n: set() for n in networks}
    for name, svc in services.items():
        for net in _service_networks(svc):
            if net not in networks:
                problems.append(f"service '{name}' uses undefined network '{net}'")
            members.setdefault(net, set()).add(name)
    sensors = {n for n in services if n.startswith("sensor-")}
    expected_members = {
        "ingress": sensors,
        "dashboard": {"api"},
        "vpn-uplink": {"vpn"},
        "egress-proxy": {"vpn", "ingest", "collector"},
        "hub-uplink": {"hubproxy"},
    }
    for net, want in expected_members.items():
        if net in networks and members.get(net, set()) != want:
            problems.append(
                f"network '{net}' members must be exactly {sorted(want)}, "
                f"found {sorted(members.get(net, set()))}"
            )
    for net in ("egress-proxy", "vpn-uplink", "hub-uplink", "hub-proxy"):
        if net not in networks:
            problems.append(f"network '{net}' is missing")
    # hub-proxy: hubproxy and ingest only (never a sensor, the api or the vpn side).
    extra = members.get("hub-proxy", set()) - {"hubproxy", "ingest"}
    if extra:
        problems.append(
            f"network 'hub-proxy' members must be hubproxy and ingest only: {sorted(extra)}"
        )

    # 3. Egress clients sit on internal networks only and cannot resolve external names.
    for name in ("ingest", "collector", "analyzer"):
        svc = services.get(name)
        if svc is None:
            problems.append(f"service '{name}' is missing")
            continue
        for net in _service_networks(svc):
            if net in EXTERNAL_NETWORKS or (networks.get(net) or {}).get("internal") is not True:
                problems.append(f"service '{name}' is on non-internal network '{net}'")
        if list(svc.get("dns") or []) != ["127.0.0.1"]:
            problems.append(f"service '{name}' must set dns: [\"127.0.0.1\"]")

    # 4. The vpn container.
    vpn = services.get("vpn")
    if vpn is None:
        problems.append("service 'vpn' is missing")
    else:
        if _service_networks(vpn) != {"vpn-uplink", "egress-proxy"}:
            problems.append("service 'vpn' must be on exactly vpn-uplink and egress-proxy")
        if list(vpn.get("cap_add") or []) != ["NET_ADMIN"]:
            problems.append("service 'vpn' cap_add must be exactly [NET_ADMIN]")
        if "ALL" not in (vpn.get("cap_drop") or []):
            problems.append("service 'vpn' must set cap_drop: [ALL]")
        devices = [str(d).split(":")[0] for d in vpn.get("devices") or []]
        if devices != ["/dev/net/tun"]:
            problems.append("service 'vpn' devices must be exactly /dev/net/tun")
        if "no-new-privileges:true" not in (vpn.get("security_opt") or []):
            problems.append("service 'vpn' must set no-new-privileges:true")
        if vpn.get("ports"):
            problems.append("service 'vpn' must not publish ports")
        if vpn.get("privileged"):
            problems.append("service 'vpn' must not be privileged")
        if not re.search(r"@sha256:[0-9a-f]{64}$", str(vpn.get("image", ""))):
            problems.append("service 'vpn' image must be pinned by sha256 digest")
        if vpn.get("read_only") is not True:
            problems.append("service 'vpn' must be read_only")
        if _env(vpn).get("FIREWALL_OUTBOUND_SUBNETS"):
            problems.append("service 'vpn' must not set FIREWALL_OUTBOUND_SUBNETS")

    # 5, 6. Nobody else gets privileges, host namespaces or published ports.
    for name, svc in services.items():
        if name != "vpn":
            for key in ("cap_add", "devices", "privileged", "pid", "ipc", "network_mode"):
                if svc.get(key):
                    problems.append(f"service '{name}' must not set {key}")
        if svc.get("ports") and not (name.startswith("sensor-") or name == "api"):
            problems.append(f"service '{name}' must not publish ports")
        proxy_vars = sorted(k for k in _env(svc) if k.lower() in PROXY_ENV)
        if proxy_vars:
            problems.append(f"service '{name}' must not set {', '.join(proxy_vars)}")

    # 7. Quarantine: collector read-write, analyzer and api read-only, nobody else.
    for name, svc in services.items():
        mounts = _mounts(svc, "quarantine")
        if not mounts:
            if name in ("collector", "analyzer"):
                problems.append(f"service '{name}' must mount quarantine")
            continue
        if name == "collector":
            continue
        if name not in ("analyzer", "api"):
            problems.append(f"service '{name}' must not mount quarantine")
        elif not all(mounts):
            problems.append(f"service '{name}' must mount quarantine read-only")

    # 8. Uploaded VPN settings (M23): api read-write, vpn read-only, nobody else. The api gets no
    # privilege and no route out, and the vpn entrypoint script is mounted read-only.
    for name, svc in services.items():
        mounts = _mounts(svc, "vpn-config")
        if name == "api":
            if not mounts or any(mounts):
                problems.append("service 'api' must mount vpn-config read-write")
        elif name == "vpn":
            if not mounts or not all(mounts):
                problems.append("service 'vpn' must mount vpn-config read-only")
        elif mounts:
            problems.append(f"service '{name}' must not mount vpn-config")
    api = services.get("api")
    if api is not None:
        if _service_networks(api) != {"backend", "dashboard"}:
            problems.append("service 'api' must be on exactly backend and dashboard")
        if any("docker.sock" in str(v) for v in api.get("volumes") or []):
            problems.append("service 'api' must not mount the docker socket")
        if api.get("read_only") is not True:
            problems.append("service 'api' must be read_only")
        if "ALL" not in (api.get("cap_drop") or []):
            problems.append("service 'api' must set cap_drop: [ALL]")
        if "NET_ADMIN" in (api.get("cap_add") or []):
            problems.append("service 'api' must not have NET_ADMIN")
    if vpn is not None:
        entry = list(vpn.get("entrypoint") or [])
        if entry[-1:] != ["/vpn/entrypoint.sh"]:
            problems.append("service 'vpn' must run /vpn/entrypoint.sh")
        script_mounts = [
            read_only for target, read_only in _mount_targets(vpn) if target == "/vpn/entrypoint.sh"
        ]
        script_ro = all(script_mounts)
        if len(script_mounts) != 1 or not script_ro:
            problems.append("service 'vpn' must mount /vpn/entrypoint.sh read-only")

    problems += _check_hubproxy(services)
    problems += _check_ports(services)
    problems += _check_sensor_switches(services)
    problems += _check_images(services)
    problems += check_hardening(services)
    problems += check_top_level(compose)
    if vpn is not None:
        health = [
            read_only for target, read_only in _mount_targets(vpn) if target == "/vpn/health.sh"
        ]
        if len(health) != 1 or not all(health):
            problems.append("service 'vpn' must mount /vpn/health.sh read-only")
        test = list((vpn.get("healthcheck") or {}).get("test") or [])
        if test != ["CMD", "/bin/sh", "/vpn/health.sh"]:
            problems.append("service 'vpn' healthcheck must run /vpn/health.sh")
    return problems


def _check_hubproxy(services: Mapping[str, Any]) -> list[str]:
    """M32: hubproxy is the only other route out. Profile ``direct``, never with ``vpn``."""
    problems: list[str] = []
    for name in ("vpn", "collector", "analyzer"):
        svc = services.get(name)
        if svc is not None and list(svc.get("profiles") or []) != ["egress"]:
            problems.append(f"service '{name}' profiles must be exactly [egress]")
    # No service may belong to both route-out profiles.
    for name, svc in services.items():
        if {"egress", "direct"} <= set(svc.get("profiles") or []):
            problems.append(f"service '{name}' must not be in both profiles egress and direct")
    hub = services.get("hubproxy")
    if hub is None:
        problems.append("service 'hubproxy' is missing")
        return problems
    if list(hub.get("profiles") or []) != ["direct"]:
        problems.append("service 'hubproxy' profiles must be exactly [direct]")
    vpn = services.get("vpn") or {}
    if "hubproxy" in _depends(vpn) or "vpn" in _depends(hub):
        problems.append("services 'vpn' and 'hubproxy' must not depend on each other")
    if _service_networks(hub) != {"hub-uplink", "hub-proxy"}:
        problems.append("service 'hubproxy' must be on exactly hub-uplink and hub-proxy")
    for key in ("ports", "cap_add", "devices", "volumes", "privileged", "network_mode"):
        if hub.get(key):
            problems.append(f"service 'hubproxy' must not set {key}")
    if hub.get("read_only") is not True:
        problems.append("service 'hubproxy' must be read_only")
    if "ALL" not in (hub.get("cap_drop") or []):
        problems.append("service 'hubproxy' must set cap_drop: [ALL]")
    if "no-new-privileges:true" not in (hub.get("security_opt") or []):
        problems.append("service 'hubproxy' must set no-new-privileges:true")
    user = str(hub.get("user", "0")).split(":")[0]
    if not user.isdigit() or int(user) == 0:
        problems.append("service 'hubproxy' must run as a non-root user")
    for key in ("mem_limit", "memswap_limit", "cpus", "pids_limit"):
        if not hub.get(key):
            problems.append(f"service 'hubproxy' must set {key}")
    if hub.get("dns"):
        problems.append("service 'hubproxy' needs Docker's resolver (no dns override)")
    return problems


def _depends(service: Mapping[str, Any]) -> set[str]:
    deps = service.get("depends_on") or []
    return set(deps) if not isinstance(deps, Mapping) else set(deps.keys())


def _host_port(entry: Any) -> str:
    """The host-side part of a ports entry, as written (``${X:-22}`` stays whole)."""
    if isinstance(entry, Mapping):
        return str(entry.get("published", ""))
    # Split on colons that are not part of a ${VAR:-default} expression.
    parts = re.split(r":(?![-?+])", str(entry))
    return parts[-2] if len(parts) >= 2 else parts[0]


def _default_port(host: str) -> str:
    match = re.fullmatch(r"\$\{[A-Z0-9_]+:-(\d+)\}", host)
    return match.group(1) if match else host


def _check_ports(services: Mapping[str, Any]) -> list[str]:
    """M32: nobody publishes the admin SSH port; the dashboard never uses a sensor port.

    Without ADMIN_SSH_PORT in the environment, the allow-list check (PUBLISHABLE_PORTS) is what
    keeps an unknown port, the admin one included, from being published.
    """
    problems: list[str] = []
    admin = os.environ.get(ADMIN_SSH_PORT_VAR, "").strip()
    sensor_ports = {
        _default_port(_host_port(p))
        for n, s in services.items()
        if n.startswith("sensor-")
        for p in s.get("ports") or []
    }
    for name, svc in services.items():
        for entry in svc.get("ports") or []:
            host = _host_port(entry)
            port = _default_port(host)
            if admin and port == admin:
                problems.append(f"service '{name}' must not publish the admin SSH port")
            if port not in PUBLISHABLE_PORTS:
                problems.append(
                    f"service '{name}' publishes host port {port}: not a sensor or dashboard port"
                )
            if name == "api" and (_default_port(host) in sensor_ports or "_HOST_PORT" in host):
                problems.append("service 'api' must not publish a sensor port")
    return problems


def _check_sensor_switches(services: Mapping[str, Any]) -> list[str]:
    """M28: a sensor is switched on or off by deploy.replicas and nothing else."""
    problems: list[str] = []
    for name, svc in services.items():
        deploy = svc.get("deploy")
        if not name.startswith("sensor-"):
            if deploy and "replicas" in deploy:
                problems.append(f"service '{name}' must not use deploy.replicas")
            continue
        want = {"replicas": "${SENSOR_" + name.removeprefix("sensor-").upper() + ":-1}"}
        if deploy != want:
            problems.append(f"service '{name}' deploy must be exactly {want}")
    return problems


def _check_images(services: Mapping[str, Any]) -> list[str]:
    """M28: built services are tagged from the release prefix and version, never ``latest``."""
    problems: list[str] = []
    for name, svc in services.items():
        image = str(svc.get("image", ""))
        if re.search(r":latest($|[@\s])", image) or (image and ":" not in image.split("/")[-1]):
            problems.append(f"service '{name}' image must carry an explicit non-latest tag")
        if svc.get("build") is not None and not (
            (image.startswith("${SUCKERPOT_IMAGE_PREFIX") and ":${SUCKERPOT_VERSION" in image)
            # A test overlay names images after its throwaway project, never the release prefix.
            or (image.startswith("local/${COMPOSE_PROJECT_NAME:?}-") and image.endswith(":test"))
        ):
            problems.append(
                f"service '{name}' image must use ${{SUCKERPOT_IMAGE_PREFIX...}} and "
                "${SUCKERPOT_VERSION...}"
            )
        # A third-party image (nothing to build) is pinned by digest; the tag stays for readers.
        if svc.get("build") is None and not PINNED_IMAGE.match(image):
            problems.append(
                f"service '{name}' third-party image must be pinned as <name>:<tag>@sha256:<digest>"
            )
    return problems


def _check_network_isolation(networks: Mapping[str, Any]) -> list[str]:
    """No IPv6 anywhere; internal networks leave the host no address on their bridge."""
    problems: list[str] = []
    for net, cfg in networks.items():
        cfg = cfg or {}
        if cfg.get("external"):
            continue  # created outside this file (test overlays only)
        if cfg.get("enable_ipv6") is not False:
            problems.append(f"network '{net}' must set enable_ipv6: false")
        opts = cfg.get("driver_opts") or {}
        bridge = opts.get(BRIDGE_NAME)
        if bridge is not None and len(str(bridge)) > MAX_BRIDGE_NAME:
            problems.append(f"network '{net}' bridge name '{bridge}' is longer than 15 characters")
        if cfg.get("internal") is True and opts.get(GATEWAY_MODE) != "isolated":
            problems.append(f"network '{net}' must set {GATEWAY_MODE}=isolated")
    return problems


def check_bridge_names(compose: Compose) -> list[str]:
    """A real install (not a test overlay): every network has its fixed bridge name."""
    problems: list[str] = []
    networks: dict[str, Any] = compose.get("networks") or {}
    for net, cfg in networks.items():
        want = BRIDGE_NAMES.get(net)
        got = ((cfg or {}).get("driver_opts") or {}).get(BRIDGE_NAME)
        if want is None:
            problems.append(f"network '{net}' has no fixed bridge name in the guardrails")
        elif got != want:
            problems.append(f"network '{net}' must set the bridge name {want}")
    return problems


def check_top_level(compose: Compose) -> list[str]:
    """Top-level volumes, secrets and configs cannot smuggle in a host path."""
    problems: list[str] = []
    for name, cfg in (compose.get("volumes") or {}).items():
        cfg = cfg or {}
        if cfg.get("external"):
            continue
        # The local driver with driver_opts (type=none, o=bind, device=/host/path) is a bind mount.
        if cfg.get("driver_opts"):
            problems.append(f"volume '{name}' must not set driver_opts")
        if str(cfg.get("driver", "local")) != "local":
            problems.append(f"volume '{name}' must use the default local driver")
    for key, allowed in (("secrets", SECRETS_ALLOWED), ("configs", CONFIGS_ALLOWED)):
        allowed_names = {ref for _, ref in allowed}
        for name in compose.get(key) or {}:
            if name not in allowed_names:
                problems.append(f"top-level {key} '{name}' is not allowed")
    return problems


def _volume_entries(service: Mapping[str, Any]) -> list[tuple[str, str, str, bool]]:
    """(type, source, target, read-only) for every volume entry of a service."""
    found: list[tuple[str, str, str, bool]] = []
    for item in service.get("volumes") or []:
        if isinstance(item, Mapping):
            kind = str(item.get("type", "volume"))
            found.append(
                (
                    kind,
                    str(item.get("source", "")),
                    str(item.get("target", "")),
                    bool(item.get("read_only", False)),
                )
            )
            continue
        parts = str(item).split(":")
        source = parts[0]
        target = parts[1] if len(parts) > 1 else parts[0]
        read_only = len(parts) > 2 and "ro" in parts[2].split(",")
        kind = "bind" if source.startswith((".", "/", "~", "$")) or len(parts) == 1 else "volume"
        found.append((kind, source, target, read_only))
    return found


def _tmpfs_entries(service: Mapping[str, Any]) -> list[str]:
    value = service.get("tmpfs") or []
    return [value] if isinstance(value, str) else [str(v) for v in value]


def _sysctls(service: Mapping[str, Any]) -> dict[str, str]:
    value = service.get("sysctls") or {}
    if isinstance(value, Mapping):
        return {str(k): str(v) for k, v in value.items()}
    out: dict[str, str] = {}
    for item in value:
        key, _, val = str(item).partition("=")
        out[key] = val
    return out


def check_hardening(services: Mapping[str, Any]) -> list[str]:
    """Isolation rules for every service: one loop, explicit exemptions with reasons."""
    problems: list[str] = []
    for name, svc in services.items():
        svc = svc or {}

        def bad(message: str, name: str = name) -> None:
            problems.append(f"service '{name}' {message}")

        if svc.get("read_only") is not True:
            bad("must set read_only: true")
        if "ALL" not in [str(c).upper() for c in svc.get("cap_drop") or []]:
            bad("must set cap_drop: [ALL]")
        opts = [str(o) for o in svc.get("security_opt") or []]
        if "no-new-privileges:true" not in opts:
            bad("must set security_opt no-new-privileges:true")
        for opt in opts:
            if UNSAFE_SECURITY_OPT.search(opt):
                bad(f"must not set security_opt {opt}")

        # Non-root, numeric uid and gid.
        if name not in ROOT_ALLOWED and not USER_SPEC.match(str(svc.get("user", ""))):
            bad("must run as a numeric non-root user (user: <uid>:<gid>, neither 0)")

        # Compose secrets and configs (files from the host): allow-list only.
        for key, allowed in (("secrets", SECRETS_ALLOWED), ("configs", CONFIGS_ALLOWED)):
            for item in svc.get(key) or []:
                ref = str(item.get("source", "")) if isinstance(item, Mapping) else str(item)
                if (name, ref) not in allowed:
                    bad(f"must not use {key} '{ref}'")

        # Resource limits: memory without swap, CPU and processes.
        for key in ("mem_limit", "memswap_limit", "cpus", "pids_limit"):
            if not svc.get(key):
                bad(f"must set {key}")
        if svc.get("mem_limit") and str(svc.get("memswap_limit")) != str(svc.get("mem_limit")):
            bad("memswap_limit must equal mem_limit (no swap)")
        if str(svc.get("pids_limit", "")).lstrip("-").isdigit() and int(svc["pids_limit"]) <= 0:
            bad("pids_limit must be positive")
        if svc.get("oom_kill_disable"):
            bad("must not set oom_kill_disable")

        # Healthcheck, except for the listed one-shot jobs.
        health = svc.get("healthcheck") or {}
        test = health.get("test") if isinstance(health, Mapping) else None
        disabled = bool(health.get("disable")) if isinstance(health, Mapping) else False
        if disabled or not test or list(test if isinstance(test, list) else [test])[:1] == ["NONE"]:
            if name not in HEALTHCHECK_EXEMPT:
                bad("must have a healthcheck")
            elif str(svc.get("restart", "no")) != "no":
                bad("is exempt from a healthcheck only as a one-shot job (restart: no)")

        for entry in _tmpfs_entries(svc):
            flags = set(entry.partition(":")[2].split(","))
            missing = [f for f in TMPFS_FLAGS if f not in flags]
            if missing:
                bad(f"tmpfs {entry.partition(':')[0]} must be mounted {','.join(missing)}")

        # Host namespaces, privileges, devices, capabilities, kernel settings.
        for key in FORBIDDEN_KEYS:
            if svc.get(key):
                bad(f"must not set {key}")
        for key in HOST_NAMESPACE_KEYS:
            if svc.get(key):
                bad(f"must not set {key}")
        extra_caps = {str(c).upper() for c in svc.get("cap_add") or []} - CAP_ADD_ALLOWED.get(
            name, set()
        )
        if extra_caps:
            bad(f"must not add capabilities {sorted(extra_caps)}")
        allowed_devices = DEVICES_ALLOWED.get(name, set())
        for device in svc.get("devices") or []:
            parts = str(device).split(":")
            if parts[0] not in allowed_devices or parts[1:2] not in ([], [parts[0]]):
                bad(f"must not map device {device}")
        allowed_sysctls = SYSCTLS_ALLOWED.get(name, {})
        for key, value in _sysctls(svc).items():
            if allowed_sysctls.get(key) != value:
                bad(f"must not set sysctl {key}")

        # Volumes: named volumes, or a read-only repository file from the allow-list.
        for kind, source, target, read_only in _volume_entries(svc):
            if "docker.sock" in source or "docker.sock" in target:
                bad("must not mount the Docker socket")
            elif kind == "bind":
                if (name, source, target) not in BIND_MOUNTS_ALLOWED:
                    bad(f"must not bind mount {source}")
                elif not read_only:
                    bad(f"must bind mount {source} read-only")
            elif kind != "volume":
                bad(f"must not use a {kind} mount (use tmpfs: for scratch space)")
    return problems


def check_vpn_entrypoint(script: str) -> list[str]:
    """The vpn entrypoint must read wg.env with fixed patterns, never source or eval it."""
    problems: list[str] = []
    code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    if re.search(r"(^|[;&|(]\s*|\s)(source|eval)\s", code, re.M):
        problems.append("vpn entrypoint must not use source or eval")
    if re.search(r"(^|[;&|(]\s*)\.\s+\S", code, re.M):
        problems.append("vpn entrypoint must not dot-source a file")
    return problems


def find_hash_named_files(root: Path) -> list[str]:
    """Paths under ``root`` whose file name is a 64-hex string (a quarantined sample)."""
    skip = {".git", "node_modules", ".venv", "dist", "__pycache__"}
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        found += [str(Path(current, f).relative_to(root)) for f in files if HEX64.match(f)]
    return found


def active_services(compose: Compose, profiles: Iterable[str]) -> set[str]:
    """Services compose would start for the given ``COMPOSE_PROFILES`` (no ``--profile`` flag)."""
    wanted = set(profiles)
    active: set[str] = set()
    for name, svc in (compose.get("services") or {}).items():
        service_profiles = set(svc.get("profiles") or [])
        if not service_profiles or service_profiles & wanted:
            active.add(name)
    return active


def check_participant(compose: Compose, profiles: Iterable[str]) -> list[str]:
    """M32: the participant rendering (base + lowmem + participant overlay) for one profile set.

    ``profiles`` is ``["direct"]`` (no VPN) or ``["egress"]`` (with a VPN). Returns violations.
    """
    wanted = set(profiles)
    problems = check_compose(compose)
    services: dict[str, Any] = compose.get("services") or {}
    networks: dict[str, Any] = compose.get("networks") or {}
    active = active_services(compose, wanted)
    sensors = {n for n in active if n.startswith("sensor-")}
    if wanted not in ({"direct"}, {"egress"}):
        problems.append(
            f"participant profiles must be exactly direct or egress, got {sorted(wanted)}"
        )
    if {"vpn", "hubproxy"} <= active:
        problems.append("vpn and hubproxy must never run together")
    want = {"redis", "db", "migrate", "backup", "ingest"} | sensors
    want |= {"hubproxy"} if wanted == {"direct"} else {"vpn", "collector", "analyzer"}
    if active != want:
        problems.append(
            f"participant active services must be {sorted(want)}, "
            f"extra {sorted(active - want)}, missing {sorted(want - active)}"
        )
    if "api" in active:
        problems.append("participant mode must not start the api")
    for name in sorted(active):
        svc = services[name]
        if name in ("hubproxy", "vpn"):
            continue
        for net in _service_networks(svc):
            if name.startswith("sensor-") and net == "ingress":
                continue
            if (networks.get(net) or {}).get("internal") is not True:
                problems.append(f"participant service '{name}' is on non-internal network '{net}'")
        if svc.get("ports") and not name.startswith("sensor-"):
            problems.append(f"participant service '{name}' must not publish ports")
    # Sensors never share a network with hubproxy.
    hub_nets = _service_networks(services.get("hubproxy") or {})
    for name in sensors:
        if _service_networks(services[name]) & hub_nets:
            problems.append(f"sensor '{name}' shares a network with hubproxy")
    return problems


ALLOWED_OVERLAY_KEYS: dict[str, set[str]] = {
    "api": {"profiles"},
    "vpn": {"depends_on"},
    "ingest": {"networks"},
    "backup": {"mem_limit", "memswap_limit"},
}


def check_participant_overlay(base: Compose, overlay: Compose) -> list[str]:
    """M32: the overlay changes only profiles, depends_on, ingest networks and backup limits."""
    problems: list[str] = []
    extra_top = set(overlay) - {"services"}
    if extra_top:
        problems.append(f"participant overlay may only set services, found {sorted(extra_top)}")
    base_services: dict[str, Any] = base.get("services") or {}
    for name, svc in (overlay.get("services") or {}).items():
        allowed = ALLOWED_OVERLAY_KEYS.get(name)
        if allowed is None or name not in base_services:
            problems.append(f"participant overlay must not touch service '{name}'")
            continue
        svc = svc or {}
        if set(svc) - allowed:
            problems.append(f"participant overlay: '{name}' may only set {sorted(allowed)}")
        if name == "api" and list(svc.get("profiles") or []) != ["dashboard"]:
            problems.append("participant overlay: api profiles must be exactly [dashboard]")
        if name == "ingest":
            added = _service_networks(svc) - _service_networks(base_services[name])
            if added != {"hub-proxy"}:
                problems.append("participant overlay: ingest may only add the hub-proxy network")
        if name == "backup":
            for key in ("mem_limit", "memswap_limit"):
                limit = base_services[name].get(key) or base_services[name]["mem_limit"]
                if key in svc and _mem_bytes(str(svc[key])) > _mem_bytes(str(limit)):
                    problems.append(f"participant overlay must not raise backup {key}")
    return problems


def _mem_bytes(value: str) -> int:
    match = re.fullmatch(r"(\d+)([mg])", value)
    if match is None:
        return 1 << 62
    return int(match.group(1)) * (1024**2 if match.group(2) == "m" else 1024**3)


def check_hubproxy_allow(value: str, defaults: str) -> list[str]:
    """M32: ``HUBPROXY_ALLOW`` holds at most two ``<name>:443`` entries naming default hosts."""
    problems: list[str] = []
    hosts = {
        m.group(1)
        for m in re.finditer(r"^NETWORK_(?:HUB|FEED)_URL=https://([a-z0-9.-]+)", defaults, re.M)
    }
    entries = [e for e in value.split(",") if e.strip()]
    if not 1 <= len(entries) <= 2:
        problems.append("HUBPROXY_ALLOW must hold one or two entries")
    for entry in entries:
        host, _, port = entry.strip().rpartition(":")
        if port != "443" or not host:
            problems.append(f"HUBPROXY_ALLOW entry '{entry}' must be <name>:443")
        elif host not in hosts:
            problems.append(
                f"HUBPROXY_ALLOW host '{host}' is not a host of config/network-defaults.env"
            )
    return problems


def profile_view(compose: Compose, profiles: Iterable[str]) -> dict[str, Any]:
    """What compose would create for a profile set: active services as written, the networks and
    volumes they use, and nothing else. Used to prove that an install does not change."""
    services: dict[str, Any] = compose.get("services") or {}
    active = active_services(compose, profiles)
    used_networks: set[str] = set()
    for name in active:
        used_networks |= _service_networks(services[name])
    return {
        "services": {n: services[n] for n in sorted(active)},
        "networks": {
            n: (compose.get("networks") or {}).get(n) or {} for n in sorted(used_networks)
        },
    }
