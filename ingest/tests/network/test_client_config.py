"""Hub client, settings and schedule: the pieces the worker leans on (N2, N5, N9)."""

from __future__ import annotations

import random
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
from suckerpot_egress import EgressClosed
from suckerpot_netproto import ProtoError, sign

from ingest.features import FeatureSettings
from ingest.network import identity as ident
from ingest.network import scheduler
from ingest.network.client import HubClient, HubError, HubUnavailable
from ingest.network.config import NetworkSettings

from .helpers import HUB_KEY, HUB_URL, NOW, FakeGate, FakeHub, hub_client, settings


def test_defaults_are_off_and_nothing_joins() -> None:
    s = NetworkSettings.from_env({})
    assert not s.enabled and s.interval_s == 900 and s.max_sources == 5000
    # The committed release defaults name the project hub; joining still needs an explicit opt-in.
    assert s.hub_configured and s.hub_url == "https://suckerpot-hub.selfhostr.io"


def test_the_network_is_off_unless_explicitly_enabled() -> None:
    assert not NetworkSettings.from_env({"NETWORK_ENABLED": "false"}).enabled
    assert not FeatureSettings.from_env({"NETWORK_ENABLED": "false"}).network_enabled
    assert not FeatureSettings.from_env({}).network_enabled
    assert NetworkSettings.from_env({"NETWORK_ENABLED": "true"}).enabled
    assert FeatureSettings.from_env({"NETWORK_ENABLED": "true"}).network_enabled


def test_settings_validation() -> None:
    ok = {"NETWORK_ENABLED": "true", "NETWORK_HUB_URL": HUB_URL + "/", "NETWORK_HUB_KEY": HUB_KEY}
    s = NetworkSettings.from_env(ok)
    assert s.enabled and s.hub_url == HUB_URL and s.hub_host == "hub.example.org"
    for bad in (
        {**ok, "NETWORK_HUB_URL": "http://hub.example.org"},
        {**ok, "NETWORK_HUB_URL": "https://hub.example.org/path"},
        {**ok, "NETWORK_HUB_URL": "https://user:pw@hub.example.org"},
        {**ok, "NETWORK_HUB_KEY": "short"},
        {"NETWORK_HUB_URL": HUB_URL},
        {"NETWORK_HUB_KEY": HUB_KEY},
        {"NETWORK_SUBMIT_DELAY_MIN_H": "20", "NETWORK_SUBMIT_DELAY_MAX_H": "2"},
        {"NETWORK_MAX_SOURCES": "99999"},
    ):
        with pytest.raises(ValueError):
            NetworkSettings.from_env(bad)


@pytest.mark.parametrize(
    "url",
    [
        "https://192.0.2.10",
        "https://" + ".".join(("10", "0", "0", "1")) + ":9443",
        "https://[::1]",
        "https://localhost",
        "https://hub",
        "https://hub.local",
        "https://hub.lan",
        "https://hub.internal",
        "https://hub.home.arpa",
        "https://hub.localhost",
        "https://hub.test",
    ],
)
def test_a_hub_host_must_be_a_public_dns_name(url: str) -> None:
    env = {"NETWORK_HUB_URL": url, "NETWORK_HUB_KEY": HUB_KEY}
    with pytest.raises(ValueError):
        NetworkSettings.from_env(env)


def test_the_submit_delay_has_a_two_hour_floor() -> None:
    with pytest.raises(ValueError):
        NetworkSettings.from_env({"NETWORK_SUBMIT_DELAY_MIN_H": "1"})
    assert NetworkSettings.from_env({"NETWORK_SUBMIT_DELAY_MIN_H": "2"}).delay_min_h == 2.0


def test_the_schedule_stays_in_bounds_and_never_picks_the_current_day() -> None:
    rng = random.Random(1)  # noqa: S311
    for _ in range(200):
        at = scheduler.next_submit_at(NOW, 2, 20, rng)
        assert datetime(2026, 11, 4, 2, tzinfo=UTC) <= at <= datetime(2026, 11, 4, 20, tzinfo=UTC)
    assert scheduler.last_closed_day(NOW) == date(2026, 11, 2)
    days = scheduler.due_days(NOW, NOW - timedelta(hours=1), set())
    assert days == [date(2026, 11, 1), date(2026, 11, 2)]  # never older, never today
    assert scheduler.due_days(NOW, NOW + timedelta(hours=1), set()) == []
    assert scheduler.due_days(NOW, None, {date(2026, 11, 1)}) == [date(2026, 11, 2)]
    assert scheduler.due_days(NOW, None, set(), since=date(2026, 11, 2)) == [date(2026, 11, 2)]


def test_identity_roundtrip_and_a_wrong_key_is_refused() -> None:
    from suckerpot_db.secretbox import SecretBox

    box = SecretBox(bytes(range(32)))
    me = ident.generate()
    assert me.seed.hex() not in repr(me) and str(me.seed) not in repr(me)
    cipher, nonce = ident.seal(me, box)
    assert ident.unseal(box, cipher, nonce, me.public).public == me.public
    with pytest.raises(ident.NoSettingsKey):
        ident.unseal(box, cipher, nonce, ident.generate().public)
    with pytest.raises(ident.NoSettingsKey):
        ident.seal(me, None)


async def test_requests_are_signed_padded_and_answers_verified() -> None:
    hub = FakeHub()
    me = ident.generate()
    client = HubClient(
        settings(),
        me,
        gate=FakeGate(),  # type: ignore[arg-type]
        client=hub_client(hub),
        clock=lambda: NOW.timestamp(),
    )
    node = await client.node()
    assert node.fingerprint == "3f9a1c07" and hub.node_key == me.node_key
    cur = await client.targets("a b/c", 10)
    assert cur.cursor == "c_1"
    assert hub.calls[-1] == ("GET", "/v1/targets")


async def test_a_forged_answer_is_thrown_away() -> None:
    hub = FakeHub()
    hub.bad_signature = True
    client = HubClient(settings(), ident.generate(), gate=FakeGate(), client=hub_client(hub))  # type: ignore[arg-type]
    with pytest.raises(ProtoError) as err:
        await client.node()
    assert err.value.code == "hub_signature"


async def test_hub_errors_carry_their_code() -> None:
    hub = FakeHub()
    hub.fail["GET /v1/node"] = (429, "rate_limited")
    client = HubClient(settings(), ident.generate(), gate=FakeGate(), client=hub_client(hub))  # type: ignore[arg-type]
    with pytest.raises(HubError) as err:
        await client.node()
    assert err.value.code == "rate_limited" and err.value.status == 429


@pytest.mark.parametrize("sent", ["made_up_code", "x" * 80, "has space", "pow_timeout"])
async def test_a_code_outside_the_protocol_list_becomes_hub_error(sent: str) -> None:
    hub = FakeHub()
    hub.fail["GET /v1/node"] = (418, sent)
    client = HubClient(settings(), ident.generate(), gate=FakeGate(), client=hub_client(hub))  # type: ignore[arg-type]
    with pytest.raises(HubError) as err:
        await client.node()
    assert err.value.code == "hub_error"


async def test_a_closed_gate_makes_no_call() -> None:
    hub = FakeHub()
    client = HubClient(settings(), ident.generate(), gate=FakeGate(False), client=hub_client(hub))  # type: ignore[arg-type]
    with pytest.raises(EgressClosed):
        await client.info()
    assert hub.calls == []


async def test_only_the_configured_host_and_protocol_paths_are_reachable() -> None:
    client = HubClient(settings(), ident.generate(), gate=FakeGate())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        client._url("/etc/passwd")
    with pytest.raises(ValueError):
        client._url("@evil.example.org/v1/x")
    with pytest.raises(ValueError):
        HubClient(NetworkSettings())
    assert sign.node_key(ident.generate().public)


async def test_an_answer_bound_to_another_request_is_refused() -> None:
    """The answer to GET /v1/node must not pass as the answer to GET /v1/targets."""
    hub = FakeHub()
    me = ident.generate()
    seen: list[httpx.Response] = []

    def replay(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/node":
            resp = hub.handle(request)
            seen.append(resp)
            return resp
        return seen[0]  # the hub's signed answer to a different request

    transport = httpx.MockTransport(replay)
    client = HubClient(
        settings(),
        me,
        gate=FakeGate(),  # type: ignore[arg-type]
        client=httpx.AsyncClient(transport=transport),
    )
    await client.node()
    with pytest.raises(ProtoError) as err:
        await client.targets(None)
    assert err.value.code == "hub_signature"


async def test_an_unsigned_error_is_not_authenticated_and_retried_later() -> None:
    hub = FakeHub()
    hub.unsigned_errors = True
    hub.fail["GET /v1/node"] = (401, "bad_signature")
    client = HubClient(settings(), ident.generate(), gate=FakeGate(), client=hub_client(hub))  # type: ignore[arg-type]
    with pytest.raises(HubUnavailable):
        await client.node()
