"""``gate_open(host=...)`` in direct mode (M32) and unchanged in VPN mode."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from suckerpot_egress import EgressGate, EgressSettings, selftest
from suckerpot_netproto import defaults, sign
from suckerpot_netproto.feeds import minisign

from ingest.egress import egress_settings, gate_open
from ingest.network.config import NetworkSettings

HUB = "hub.example.org"


def _gate(*, direct: bool) -> EgressGate:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"mode": "direct", "allow": [f"{HUB}:443"], "ok": True})

    settings = EgressSettings(
        mode="direct" if direct else "vpn",
        scope_hosts=frozenset({HUB}) if direct else frozenset(),
        control_url="http://hubproxy:8000",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return EgressGate(settings, client=client)


async def test_direct_mode_needs_a_host_in_scope() -> None:
    gate = _gate(direct=True)
    assert (await gate.check()).open
    assert gate_open(gate, host=HUB) is True
    assert gate_open(gate) is False
    assert gate_open(gate, host="example.org") is False


async def test_vpn_mode_ignores_the_host() -> None:
    gate = _gate(direct=False)  # never checked, so closed as before
    assert gate_open(gate, host=HUB) is False
    assert gate_open(gate) is False


# --- the scope uses the same effective hub and feed as the network code (shipped defaults) ---

REPO = Path(__file__).resolve().parents[2]
KEY = sign.node_key(sign.public_key_of(sign.generate_private_key()))
FEED_KEY = minisign.generate_keypair().public.encoded


def _defaults_text(**over: str) -> str:
    values = {
        "NETWORK_DEFAULTS_VERSION": "1",
        "NETWORK_HUB_URL": "https://hub.example.org",
        "NETWORK_HUB_KEY": KEY,
        "NETWORK_FEED_URL": "https://feeds.example.org/v1",
        "NETWORK_FEED_KEY": FEED_KEY,
    }
    values.update(over)
    return "".join(f"{k}={v}\n" for k, v in values.items())


def _use_defaults(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    # Parsed on each load, so a malformed file raises DefaultsError like the real loader.
    monkeypatch.setattr(defaults, "load", lambda: defaults.from_text(text))


def _direct_env(**over: str) -> dict[str, str]:
    return {"EGRESS_MODE": "direct", **over}


def _hubproxy_gate(settings: EgressSettings, allow: list[str]) -> EgressGate:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"mode": "direct", "allow": allow, "ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return EgressGate(settings, client=client)


async def test_direct_mode_scope_comes_from_the_shipped_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The real participant install: no hub or feed URL in .env, HUBPROXY_ALLOW from the defaults.
    _use_defaults(monkeypatch, _defaults_text())
    settings = egress_settings(_direct_env())
    assert settings.scope_hosts == {"hub.example.org", "feeds.example.org"}
    for allow in (["hub.example.org:443"], ["hub.example.org:443", "feeds.example.org:443"]):
        gate = _hubproxy_gate(settings, allow)
        assert (await gate.check()).open
        assert gate_open(gate, host="hub.example.org") is True
        assert gate_open(gate, host="feeds.example.org") is True
        assert gate_open(gate, host="example.org") is False
        assert gate_open(gate) is False


def test_an_explicit_value_wins_over_the_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    env = _direct_env(NETWORK_HUB_URL="https://other.example.net", NETWORK_HUB_KEY=KEY)
    assert egress_settings(env).scope_hosts == {"other.example.net", "feeds.example.org"}
    # A half-set pair is not mixed with the default of the other half.
    half = _direct_env(NETWORK_HUB_URL="https://other.example.net")
    assert egress_settings(half).scope_hosts == {"feeds.example.org"}


@pytest.mark.parametrize(
    "text",
    [
        _defaults_text(NETWORK_HUB_URL="<HUB_URL>", NETWORK_FEED_URL="<FEED_URL>"),
        _defaults_text(NETWORK_HUB_KEY="<HUB_PUBLIC_KEY>", NETWORK_FEED_KEY="<FEED_PUBLIC_KEY>"),
        "this is not a defaults file\n",
        _defaults_text(NETWORK_HUB_URL="http://hub.example.org"),
        _defaults_text(NETWORK_DEFAULTS_VERSION="99"),
    ],
)
async def test_placeholder_or_malformed_defaults_give_an_empty_scope(
    monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    _use_defaults(monkeypatch, text)
    settings = egress_settings(_direct_env())
    assert settings.scope_hosts == frozenset()
    gate = _hubproxy_gate(settings, ["hub.example.org:443"])
    assert not (await gate.check()).open
    assert gate_open(gate, host="hub.example.org") is False


def test_a_placeholder_half_leaves_only_the_other_host(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text(NETWORK_FEED_URL="<FEED_URL>"))
    assert egress_settings(_direct_env()).scope_hosts == {"hub.example.org"}


def test_vpn_mode_scope_stays_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    for env in ({}, {"EGRESS_MODE": "vpn"}):
        settings = egress_settings(env)
        assert settings.scope_hosts == frozenset()
        assert not settings.direct


def test_the_installer_allow_list_is_inside_the_scope() -> None:
    # scripts/lib/env.sh hubproxy_allow() reads config/network-defaults.env, a byte-for-byte mirror
    # of the package data (test_host_mirror_is_identical_to_package_data in netproto). Its hosts
    # must be what the gate scopes to, computed here from the package defaults.
    mirror = defaults.parse((REPO / "config" / "network-defaults.env").read_text("utf-8"))
    hosts = {urlsplit(mirror[n]).hostname for n in ("NETWORK_HUB_URL", "NETWORK_FEED_URL")}
    assert hosts == egress_settings(_direct_env()).scope_hosts


# --- a bad hub URL must never break VPN mode, and never open the gate in direct mode ---

BAD_URL = "https://[oops"


async def test_a_malformed_hub_url_gives_no_hub_in_the_direct_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    env = _direct_env(NETWORK_HUB_URL=BAD_URL, NETWORK_HUB_KEY=KEY)
    settings = egress_settings(env)
    assert "hub.example.org" not in settings.scope_hosts
    gate = _hubproxy_gate(settings, ["hub.example.org:443"])
    assert not (await gate.check()).open
    assert gate_open(gate, host="hub.example.org") is False


def test_vpn_mode_never_resolves_the_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(env: object) -> dict[str, str]:
        raise AssertionError("scope_env must not run in VPN mode")

    monkeypatch.setattr(defaults, "scope_env", boom)
    for env in (
        {"NETWORK_HUB_URL": BAD_URL, "NETWORK_HUB_KEY": KEY},
        {"EGRESS_MODE": "vpn", "NETWORK_HUB_URL": BAD_URL, "NETWORK_HUB_KEY": KEY},
        {"EGRESS_MODE": " VPN "},
    ):
        assert egress_settings(env) == EgressSettings.from_env(env)


def test_an_invalid_mode_still_raises() -> None:
    with pytest.raises(ValueError):
        egress_settings({"EGRESS_MODE": "bridge"})


def test_the_environment_is_not_mutated(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    env = _direct_env()
    before = dict(env)
    egress_settings(env)
    assert env == before
    monkeypatch.setenv("EGRESS_MODE", "direct")
    snapshot = dict(os.environ)
    assert egress_settings().scope_hosts
    assert dict(os.environ) == snapshot


def test_selftest_uses_the_resolver_and_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    monkeypatch.setenv("EGRESS_MODE", "direct")
    assert selftest.load_settings().scope_hosts == {"hub.example.org", "feeds.example.org"}
    real_import = importlib.import_module

    def no_ingest(name: str, package: str | None = None) -> object:
        if name == "ingest.egress":
            raise ImportError(name)
        return real_import(name, package)

    monkeypatch.setattr(importlib, "import_module", no_ingest)
    assert selftest.load_settings() == EgressSettings.from_env()
    assert selftest.load_settings().scope_hosts == frozenset()


@pytest.mark.parametrize("url", ["https://HUB.Example.ORG", "https://hub.example.org."])
def test_scope_host_matches_the_network_worker_host(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    env = _direct_env(NETWORK_HUB_URL=url, NETWORK_HUB_KEY=KEY)
    settings = egress_settings(env)
    try:
        host = NetworkSettings.from_env(env).hub_host
    except ValueError:
        assert "hub.example.org" not in settings.scope_hosts  # both reject it
        return
    # The gate lower-cases and strips a trailing dot, so the worker's host is in scope.
    gate = _hubproxy_gate(settings, ["hub.example.org:443"])
    assert host.lower().rstrip(".") in settings.scope_hosts
    assert gate._in_scope(host)
