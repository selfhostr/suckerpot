"""M32 participant mode: compose rendering, overlay limits, hubproxy isolation, owner snapshot."""

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from suckerpot_guardrails import (
    active_services,
    check_compose,
    check_hubproxy_allow,
    check_participant,
    check_participant_overlay,
    load_compose,
    profile_view,
)

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"
LOWMEM = ROOT / "docker-compose.lowmem.yml"
PARTICIPANT = ROOT / "docker-compose.participant.yml"
CI = ROOT / "docker-compose.ci.yml"
IT = ROOT / "docker-compose.it.yml"
BASELINE = Path(__file__).parent / "fixtures" / "owner_baseline.json"
DEFAULTS = (ROOT / "config" / "network-defaults.env").read_text(encoding="utf-8")

EXTERNAL = {"ingress", "dashboard", "vpn-uplink", "hub-uplink"}
PROFILES = [["direct"], ["egress"]]


def _participant() -> dict[str, Any]:
    return load_compose([BASE, LOWMEM, PARTICIPANT])


def _mutated(mutate: Any) -> dict[str, Any]:
    compose = copy.deepcopy(_participant())
    mutate(compose)
    return compose


@pytest.mark.parametrize(
    "files",
    [
        [BASE],
        [BASE, LOWMEM],
        [BASE, LOWMEM, PARTICIPANT],
        [BASE, PARTICIPANT],
        [BASE, CI],
        [BASE, IT],
    ],
    ids=["base", "lowmem", "participant", "base+participant", "ci", "it"],
)
def test_every_rendering_keeps_the_guardrails(files: list[Path]) -> None:
    compose = load_compose(files)
    assert check_compose(compose) == []
    # 1. Only the documented networks leave internal mode.
    for name, cfg in compose["networks"].items():
        if name in EXTERNAL:
            continue
        assert (cfg or {}).get("internal") is True, name


def test_hub_network_membership_and_bridge_names() -> None:
    compose = _participant()
    members: dict[str, set[str]] = {}
    for name, svc in compose["services"].items():
        nets = svc.get("networks") or []
        for net in nets if not isinstance(nets, dict) else nets.keys():
            members.setdefault(net, set()).add(name)
    assert members["hub-uplink"] == {"hubproxy"}
    assert members["hub-proxy"] == {"hubproxy", "ingest"}
    uplink = compose["networks"]["hub-uplink"]
    assert uplink["name"] == "sp-hubgate"
    assert uplink.get("internal") is not True
    assert uplink["driver_opts"]["com.docker.network.bridge.enable_icc"] == "false"
    proxy = compose["networks"]["hub-proxy"]
    assert proxy["internal"] is True
    assert proxy["driver_opts"]["com.docker.network.bridge.name"] == "sp-hubproxy"


def test_hubproxy_definition() -> None:
    hub = load_compose([BASE])["services"]["hubproxy"]
    assert hub["profiles"] == ["direct"]
    assert set(hub["networks"]) == {"hub-uplink", "hub-proxy"}
    for key in ("ports", "cap_add", "devices", "volumes"):
        assert key not in hub
    assert hub["read_only"] is True
    assert hub["cap_drop"] == ["ALL"]
    assert hub["user"] == "10001:10001"
    assert hub["build"]["dockerfile"] == "hubproxy/Dockerfile"
    assert (hub["mem_limit"], hub["pids_limit"], hub["cpus"]) == ("48m", 32, 0.25)


def test_route_out_profiles_are_disjoint() -> None:
    services = load_compose([BASE])["services"]
    for name in ("vpn", "collector", "analyzer"):
        assert services[name]["profiles"] == ["egress"]
    assert services["hubproxy"]["profiles"] == ["direct"]
    for profiles in PROFILES:
        assert not {"vpn", "hubproxy"} <= active_services(load_compose([BASE]), profiles)


@pytest.mark.parametrize("profiles", PROFILES, ids=["direct", "egress"])
def test_participant_rendering(profiles: list[str]) -> None:
    compose = _participant()
    assert check_participant(compose, profiles) == []
    active = active_services(compose, profiles)
    assert "api" not in active
    assert "demo" not in active
    sensors = {n for n in active if n.startswith("sensor-")}
    assert len(sensors) == 12
    base = {"redis", "db", "migrate", "backup", "ingest"} | sensors
    extra = {"hubproxy"} if profiles == ["direct"] else {"vpn", "collector", "analyzer"}
    assert active == base | extra
    # Ingest has no non-internal network; only sensors publish ports.
    ingest_nets = set(compose["services"]["ingest"]["networks"])
    assert ingest_nets == {"backend", "egress-proxy", "hub-proxy"}
    assert not [n for n in active if compose["services"][n].get("ports") and n not in sensors]


def test_participant_overlay_only_changes_the_allowed_keys() -> None:
    base = load_compose([BASE])
    overlay = load_compose([PARTICIPANT])
    assert check_participant_overlay(base, overlay) == []
    services = overlay["services"]
    assert services["api"]["profiles"] == ["dashboard"]
    assert set(services["ingest"]["networks"]) - set(base["services"]["ingest"]["networks"]) == {
        "hub-proxy"
    }
    merged = load_compose([BASE, PARTICIPANT])
    assert "depends_on" not in merged["services"]["vpn"]
    # Everything else is identical to the base file.
    for name, svc in base["services"].items():
        for key, value in svc.items():
            if (name, key) in {
                ("api", "profiles"),
                ("vpn", "depends_on"),
                ("ingest", "networks"),
                ("backup", "mem_limit"),
                ("backup", "memswap_limit"),
            }:
                continue
            assert merged["services"][name].get(key) == value, (name, key)
    assert merged["networks"] == base["networks"]
    assert merged["volumes"] == base["volumes"]


def test_dashboard_never_uses_a_sensor_port_or_the_admin_port() -> None:
    compose = load_compose([BASE])
    ports = compose["services"]["api"]["ports"]
    assert len(ports) == 1
    assert "DASHBOARD_PORT" in ports[0]
    assert "2200" not in json.dumps(compose["services"])


@pytest.mark.parametrize(
    "value",
    [
        "suckerpot-hub.selfhostr.io:443",
        "suckerpot-hub.selfhostr.io:443,suckerpot-feeds.selfhostr.io:443",
    ],
)
def test_allow_list_accepts_the_defaults(value: str) -> None:
    assert check_hubproxy_allow(value, DEFAULTS) == []


@pytest.mark.parametrize(
    "value",
    [
        "",
        "suckerpot-hub.selfhostr.io:443,suckerpot-feeds.selfhostr.io:443,example.org:443",
        "suckerpot-hub.selfhostr.io:80",
        "suckerpot-hub.selfhostr.io",
        "example.org:443",
    ],
)
def test_allow_list_rejects_everything_else(value: str) -> None:
    assert check_hubproxy_allow(value, DEFAULTS) != []


# --- Mutation tests: each broken rendering must be caught -----------------------------------


def _hub_uplink_on_ingest(c: dict[str, Any]) -> None:
    c["services"]["ingest"]["networks"].append("hub-uplink")


def _hubproxy_on_backend(c: dict[str, Any]) -> None:
    c["services"]["hubproxy"]["networks"]["backend"] = {}


def _ports_on_hubproxy(c: dict[str, Any]) -> None:
    c["services"]["hubproxy"]["ports"] = ["127.0.0.1:8888:8888"]


def _vpn_without_profile(c: dict[str, Any]) -> None:
    del c["services"]["vpn"]["profiles"]


def _api_active_with_ports(c: dict[str, Any]) -> None:
    del c["services"]["api"]["profiles"]


def _ingest_on_external_network(c: dict[str, Any]) -> None:
    c["services"]["ingest"]["networks"].append("ingress")


def _sensor_on_hub_proxy(c: dict[str, Any]) -> None:
    c["services"]["sensor-ssh"]["networks"].append("hub-proxy")


def _both_profiles_on_hubproxy(c: dict[str, Any]) -> None:
    c["services"]["hubproxy"]["profiles"] = ["direct", "egress"]


def _hub_proxy_not_internal(c: dict[str, Any]) -> None:
    c["networks"]["hub-proxy"]["internal"] = False


def _hub_uplink_internal_dropped_name(c: dict[str, Any]) -> None:
    c["networks"]["hub-uplink"]["name"] = "sp-other"


def _hubproxy_cap_add(c: dict[str, Any]) -> None:
    c["services"]["hubproxy"]["cap_add"] = ["NET_ADMIN"]


def _hubproxy_volume(c: dict[str, Any]) -> None:
    c["services"]["hubproxy"]["volumes"] = ["quarantine:/q"]


def _hubproxy_root(c: dict[str, Any]) -> None:
    c["services"]["hubproxy"]["user"] = "0:0"


def _dashboard_on_ssh_port(c: dict[str, Any]) -> None:
    c["services"]["api"]["ports"] = ["0.0.0.0:${SSH_HOST_PORT:-22}:8000"]


def _dashboard_on_admin_port(c: dict[str, Any]) -> None:
    c["services"]["api"]["ports"] = ["127.0.0.1:2200:8000"]


def _sensor_on_admin_port(c: dict[str, Any]) -> None:
    c["services"]["sensor-web"]["ports"] = ["0.0.0.0:2200:8080"]


def _collector_in_direct(c: dict[str, Any]) -> None:
    c["services"]["collector"]["profiles"] = ["egress", "direct"]


def _vpn_depends_on_hubproxy(c: dict[str, Any]) -> None:
    c["services"]["vpn"]["depends_on"] = {"hubproxy": {"condition": "service_started"}}


MUTATIONS = [
    _hub_uplink_on_ingest,
    _hubproxy_on_backend,
    _ports_on_hubproxy,
    _vpn_without_profile,
    _api_active_with_ports,
    _ingest_on_external_network,
    _sensor_on_hub_proxy,
    _both_profiles_on_hubproxy,
    _hub_proxy_not_internal,
    _hub_uplink_internal_dropped_name,
    _hubproxy_cap_add,
    _hubproxy_volume,
    _hubproxy_root,
    _dashboard_on_ssh_port,
    _dashboard_on_admin_port,
    _sensor_on_admin_port,
    _collector_in_direct,
    _vpn_depends_on_hubproxy,
]


@pytest.mark.parametrize("mutation", MUTATIONS, ids=lambda m: m.__name__.lstrip("_"))
def test_mutations_are_caught(mutation: Any) -> None:
    for profiles in PROFILES:
        assert check_participant(_mutated(mutation), profiles) != [], profiles


def test_admin_port_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # An operator whose admin SSH daemon sits on a port that is also a sensor default (here 22)
    # sets ADMIN_SSH_PORT: the guardrail then refuses to publish it. Unset, the allow-list
    # check alone applies and the shipped compose is clean.
    monkeypatch.delenv("ADMIN_SSH_PORT", raising=False)
    assert check_participant(_participant(), ["direct"]) == []
    monkeypatch.setenv("ADMIN_SSH_PORT", "22")
    assert any("admin SSH port" in p for p in check_participant(_participant(), ["direct"]))
    monkeypatch.setenv("ADMIN_SSH_PORT", "")
    assert check_participant(_participant(), ["direct"]) == []


def test_vpn_and_hubproxy_running_together_is_caught() -> None:
    compose = _participant()
    assert check_participant(compose, ["direct", "egress"]) != []


def test_overlay_mutations_are_caught() -> None:
    base = load_compose([BASE])
    mutations: list[Callable[[dict[str, Any]], object]] = [
        lambda o: o["services"]["ingest"]["networks"].append("hub-uplink"),
        lambda o: o["services"]["api"].pop("profiles"),
        lambda o: o["services"]["ingest"].update(ports=["1:1"]),
        lambda o: o["services"]["backup"].update(mem_limit="1g"),
        lambda o: o["services"].setdefault("db", {}).update(cap_add=["SYS_ADMIN"]),
        lambda o: o["services"]["api"].update(ports=[]),
        lambda o: o.update(volumes={"x": {}}),
    ]
    for mutate in mutations:
        overlay = copy.deepcopy(load_compose([PARTICIPANT]))
        mutate(overlay)
        assert check_participant_overlay(base, overlay) != []


def test_allow_mutation_in_hubproxy_env_is_not_hardcoded() -> None:
    env = load_compose([BASE])["services"]["hubproxy"]["environment"]
    assert env["HUBPROXY_ALLOW"] == "${HUBPROXY_ALLOW:-}"
    assert env["HUBPROXY_PASSWORD"] == "${EGRESS_PROXY_PASSWORD:-}"  # noqa: S105


# --- The owner's install must not change -----------------------------------------------------

# Environment lines M32 adds to ingest and collector (docs/design/m32.md section 4.4). Their
# defaults reproduce today's behaviour: full mode, VPN egress, no network consent.
ALLOWED_NEW_ENV = {
    "ingest": {
        "SUCKERPOT_STACK_MODE": "${SUCKERPOT_STACK_MODE:-full}",
        "EGRESS_MODE": "${EGRESS_MODE:-vpn}",
        "NETWORK_CONSENT": "${NETWORK_CONSENT:-}",
        "NETWORK_PSEUDONYM": "${NETWORK_PSEUDONYM:-}",
        "NETWORK_COUNTRY": "${NETWORK_COUNTRY:-}",
        "NETWORK_SHOW_COUNTRY": "${NETWORK_SHOW_COUNTRY:-false}",
        "NETWORK_VERIFY_REVEALS": "${NETWORK_VERIFY_REVEALS:-false}",
        "NETWORK_VERIFIER": "${NETWORK_VERIFIER:-false}",
        "NETWORK_VERIFY_DAILY_CAP": "${NETWORK_VERIFY_DAILY_CAP:-100}",
        "NETWORK_VERIFY_HOST_DAILY_CAP": "${NETWORK_VERIFY_HOST_DAILY_CAP:-3}",
        "SELF_TERMS_AUTO_CONFIRM": "${SELF_TERMS_AUTO_CONFIRM:-false}",
        "SELF_ADDRESS": "${SELF_ADDRESS:-}",
    },
    "collector": {"COLLECTOR_VERIFY_ENABLED": "${COLLECTOR_VERIFY_ENABLED:-false}"},
}


def _strip_allowed(view: dict[str, Any]) -> dict[str, Any]:
    view = copy.deepcopy(view)
    for name, allowed in ALLOWED_NEW_ENV.items():
        env = view["services"][name]["environment"]
        for key, value in allowed.items():
            assert env.pop(key) == value, (name, key)
    return view


def test_owner_install_renders_the_same_stack() -> None:
    """Base file + COMPOSE_PROFILES=egress, no overlay: only the allowed env lines are new."""
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    current = profile_view(load_compose([BASE]), ["egress"])
    current = json.loads(json.dumps(_strip_allowed(current), default=str))
    assert current["services"].keys() == baseline["services"].keys()
    for name, svc in baseline["services"].items():
        assert current["services"][name] == svc, name
    assert current["networks"] == baseline["networks"]
    assert "hubproxy" not in current["services"]
    assert not {"hub-uplink", "hub-proxy"} & set(current["networks"])


def test_owner_install_without_profiles_also_has_no_hubproxy() -> None:
    for profiles in ([], ["egress"], ["egress", "tools"]):
        assert "hubproxy" not in active_services(load_compose([BASE]), profiles)


def test_owner_egress_defaults_are_unchanged() -> None:
    env = load_compose([BASE])["services"]["ingest"]["environment"]
    assert env["EGRESS_PROXY_URL"] == "${EGRESS_PROXY_URL:-http://vpn:8888}"
    assert env["EGRESS_CONTROL_URL"] == "${EGRESS_CONTROL_URL:-http://vpn:8000}"
    assert env["EGRESS_MODE"] == "${EGRESS_MODE:-vpn}"
    ingest = load_compose([BASE])["services"]["ingest"]
    assert ingest["networks"] == ["backend", "egress-proxy"]


def test_snapshot_detects_a_change() -> None:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    changed = load_compose([BASE])
    changed["services"]["ingest"]["networks"] = ["backend", "egress-proxy", "hub-proxy"]
    view = json.loads(json.dumps(_strip_allowed(profile_view(changed, ["egress"])), default=str))
    assert view["services"]["ingest"] != baseline["services"]["ingest"]
