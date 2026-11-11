"""The feed worker against a fake feed site: verification, rollback, atomic swap, privacy (M30)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import replace as dc_replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from suckerpot_netproto import defaults, sign
from suckerpot_netproto.feeds import (
    FeedEntry,
    RenderContext,
    build_index,
    index_list,
    minisign,
    render_index,
    render_list,
)

from ingest.egress import EgressClosed, egress_settings
from ingest.features import FeatureSettings
from ingest.network.feed import FeedState, FeedWorker
from ingest.network.feed_client import FeedClient, FeedSettings

from .helpers import FakeGate

BASE = "https://feeds.example.org/v1"
SECRET = minisign.SecretKey(bytes(range(64, 96)), bytes(range(1, 9)))
PUBLIC = SECRET.public
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def entry(value: str, family: Any, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "value": value,
        "family": family,
        "tier": "standard",
        "categories": ["c2"] if family != "dns" else ["payload-host"],
        "first_seen": "2026-10-28",
        "last_seen": "2026-10-30",
        "expires": "2026-11-29",
    }
    base.update(kw)
    return base


LISTS: dict[str, list[dict[str, Any]]] = {
    "inbound": [entry("198.51.100.9", 4, categories=["brute-force"], services=["ssh"])],
    "outbound": [entry("203.0.113.50", 4, families=["mirai"], ports=[23])],
    "outbound-domains": [entry("dl.example.net", "dns")],
}


class Site:
    """Serves one signed generation of the feed and records every request."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.files: dict[str, bytes] = {}
        self.etag = '"e1"'
        self.override: dict[str, Callable[[httpx.Request], httpx.Response]] = {}
        self.publish(1)

    def publish(
        self,
        serial: int,
        lists: dict[str, list[dict[str, Any]]] | None = None,
        *,
        valid_until: datetime | None = None,
        tamper: str | None = None,
    ) -> None:
        gen = NOW - timedelta(hours=1)
        until = valid_until or NOW + timedelta(days=2)
        refs = []
        files: dict[str, bytes] = {}
        for lid, raw in (lists or LISTS).items():
            ctx = RenderContext(lid, serial, gen, until, allow_documentation=True)
            rendered = render_list(ctx, raw)
            refs.append(index_list(rendered, {n: gen for n in rendered.files}))
            for name in (f"{lid}.json",):
                files[name] = rendered.files[name]
                files[f"{name}.minisig"] = minisign.sign_feed_file(
                    rendered.files[name], name, serial, SECRET, timestamp=1
                ).encode()
        index = build_index(
            serial=serial,
            generated_at=gen,
            valid_until=until,
            key_id=PUBLIC.key_id_hex,
            lists=refs,
        )
        data = render_index(index)
        files["index.json"] = data
        files["index.json.minisig"] = minisign.sign_feed_file(
            data, "index.json", serial, SECRET, timestamp=1
        ).encode()
        if tamper:
            files[tamper] = files[tamper] + b" "
        self.files = files
        self.etag = f'"e{serial}"'

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        name = request.url.path.rsplit("/", 1)[-1]
        if name in self.override:
            return self.override[name](request)
        if name not in self.files:
            return httpx.Response(404)
        if name == "index.json" and request.headers.get("if-none-match") == self.etag:
            return httpx.Response(304, headers={"etag": self.etag})
        return httpx.Response(200, content=self.files[name], headers={"etag": self.etag})


class MemoryFeedStore:
    def __init__(self) -> None:
        self.st: FeedState | None = None
        self.entries: dict[str, list[FeedEntry]] = {}
        self.seen_calls = 0
        self.wiped = 0

    async def state(self) -> FeedState | None:
        return dc_replace(self.st) if self.st else None

    async def record_error(self, code: str, now: datetime) -> None:
        self.st = self.st or FeedState()
        self.st.error_code, self.st.last_fetch_at = code, now

    async def touch_ok(self, now: datetime) -> None:
        assert self.st
        self.st.error_code, self.st.last_fetch_at, self.st.last_ok_at = None, now, now

    async def apply(
        self, state: FeedState, replace: dict[str, list[FeedEntry]], keep_lists: set[str]
    ) -> None:
        self.entries = {k: v for k, v in self.entries.items() if k in keep_lists}
        self.entries.update(replace)
        self.st = state

    async def recompute_seen_here(self, now: datetime) -> int:
        self.seen_calls += 1
        return 0

    async def wipe(self) -> bool:
        # Like the SQL store: the last serial and its key survive (rollback protection).
        had = bool(self.entries) or (self.st is not None and self.st.valid_until is not None)
        self.st = FeedState(serial=self.st.serial, key_id=self.st.key_id) if self.st else None
        self.entries = {}
        self.wiped += 1
        return had


def feed_settings(**kw: Any) -> FeedSettings:
    base: dict[str, Any] = {"url": BASE, "key": PUBLIC.encoded}
    base.update(kw)
    return FeedSettings(**base)


def make(
    site: Site,
    store: MemoryFeedStore,
    *,
    gate: FakeGate | None = None,
    enabled: bool = True,
    allow_documentation: bool = True,
    **kw: Any,
) -> FeedWorker:
    client = httpx.AsyncClient(transport=httpx.MockTransport(site.handler))
    return FeedWorker(
        FeatureSettings(network_feed_enabled=enabled),
        feed_settings(**kw),
        store,
        gate=gate or FakeGate(),  # type: ignore[arg-type]
        client=client,
        clock=lambda: NOW,
        allow_documentation=allow_documentation,
    )


async def test_first_fetch_stores_every_configured_list() -> None:
    site, store = Site(), MemoryFeedStore()
    w = make(site, store)
    await w.run_once()
    assert w.state == "ok" and w.reason is None
    assert store.st and store.st.serial == 1 and store.st.error_code is None
    assert set(store.entries) == {"inbound", "outbound", "outbound-domains"}
    assert [e.value for e in store.entries["outbound"]] == ["203.0.113.50"]
    assert store.st.files["outbound.json"]["sha256"]
    assert store.seen_calls == 1


async def test_only_configured_lists_are_downloaded() -> None:
    site, store = Site(), MemoryFeedStore()
    await make(site, store, lists=("outbound",)).run_once()
    assert set(store.entries) == {"outbound"}
    names = {r.url.path.rsplit("/", 1)[-1] for r in site.requests}
    assert names == {"index.json", "index.json.minisig", "outbound.json", "outbound.json.minisig"}


async def test_an_unchanged_index_is_a_conditional_get_and_nothing_else() -> None:
    site, store = Site(), MemoryFeedStore()
    w = make(site, store)
    await w.run_once()
    site.requests.clear()
    await w.run_once()
    assert [r.url.path.rsplit("/", 1)[-1] for r in site.requests] == ["index.json"]
    assert site.requests[0].headers["if-none-match"] == '"e1"'
    assert w.state == "ok"


async def test_only_changed_lists_are_fetched_again() -> None:
    site, store = Site(), MemoryFeedStore()
    w = make(site, store)
    await w.run_once()
    changed = {**LISTS, "outbound": [entry("203.0.113.51", 4, families=["gafgyt"], ports=[23])]}
    site.publish(2, changed)
    site.requests.clear()
    await w.run_once()
    assert store.st and store.st.serial == 2
    assert [e.value for e in store.entries["outbound"]] == ["203.0.113.51"]


async def test_rollback_is_refused_and_the_last_good_data_stays() -> None:
    site, store = Site(), MemoryFeedStore()
    w = make(site, store)
    site.publish(5)
    await w.run_once()
    site.publish(4, {"outbound": [entry("203.0.113.99", 4)]})
    await w.run_once()
    assert w.state == "error" and w.reason == "feed_rollback"
    assert store.st and store.st.serial == 5 and store.st.error_code == "feed_rollback"
    assert [e.value for e in store.entries["outbound"]] == ["203.0.113.50"]


async def test_an_expired_index_is_refused() -> None:
    site, store = Site(), MemoryFeedStore()
    site.publish(2, valid_until=NOW - timedelta(minutes=1))
    w = make(site, store)
    await w.run_once()
    assert w.reason == "feed_expired" and store.entries == {}


async def test_a_stored_index_that_expired_is_reported_on_a_304() -> None:
    site, store = Site(), MemoryFeedStore()
    w = make(site, store)
    await w.run_once()
    assert store.st
    store.st.valid_until = NOW - timedelta(hours=1)
    await w.run_once()
    assert w.reason == "feed_expired" and store.entries  # kept for display


async def test_a_wrong_signing_key_is_refused() -> None:
    site, store = Site(), MemoryFeedStore()
    other = minisign.generate_keypair().public
    w = make(site, store, key=other.encoded)
    await w.run_once()
    assert w.reason == "bad_signature" and store.entries == {}


async def test_a_tampered_list_keeps_the_previous_generation_whole() -> None:
    site, store = Site(), MemoryFeedStore()
    w = make(site, store)
    await w.run_once()
    changed = {**LISTS, "inbound": [entry("198.51.100.77", 4, categories=["brute-force"])]}
    site.publish(2, changed, tamper="outbound.json")
    await w.run_once()
    assert w.reason == "feed_invalid"
    assert store.st and store.st.serial == 1  # nothing of generation 2 was applied
    assert [e.value for e in store.entries["inbound"]] == ["198.51.100.9"]


async def test_a_list_signed_for_another_name_is_refused() -> None:
    site, store = Site(), MemoryFeedStore()
    site.files["outbound.json.minisig"] = site.files["inbound.json.minisig"]
    w = make(site, store)
    await w.run_once()
    assert w.reason == "bad_signature" and store.entries == {}


async def test_too_many_invalid_entries_reject_the_file() -> None:
    site, store = Site(), MemoryFeedStore()
    # Documentation addresses are rendered by the test hub but are not global unicast: the
    # node (without the test overlay) drops every entry, which is over the 1 % limit.
    w = make(site, store, allow_documentation=False)
    await w.run_once()
    assert w.reason == "feed_invalid" and store.entries == {}


async def test_a_closed_gate_fetches_nothing() -> None:
    site, store = Site(), MemoryFeedStore()
    w = make(site, store, gate=FakeGate(open_=False))
    await w.run_once()
    assert site.requests == []
    assert w.reason == "egress_closed" and w.interval_s < 600
    assert store.st and store.st.error_code == "egress_closed"


async def test_http_errors_become_codes_and_redirects_are_not_followed() -> None:
    site, store = Site(), MemoryFeedStore()
    site.override["index.json"] = lambda r: httpx.Response(503)
    w = make(site, store)
    await w.run_once()
    assert w.reason == "http_503"
    site.override["index.json"] = lambda r: httpx.Response(
        302, headers={"location": "https://other.example.net/index.json"}
    )
    await w.run_once()
    assert w.reason == "http_302"
    assert {r.url.host for r in site.requests} == {"feeds.example.org"}


async def test_an_oversized_answer_is_cut_off() -> None:
    site, store = Site(), MemoryFeedStore()
    site.override["index.json"] = lambda r: httpx.Response(200, content=b"x" * (300 * 1024))
    w = make(site, store)
    await w.run_once()
    assert w.reason == "too_large"


async def test_a_compressed_answer_is_refused() -> None:
    site, store = Site(), MemoryFeedStore()
    site.override["index.json"] = lambda r: httpx.Response(
        200, content=b"x", headers={"content-encoding": "gzip"}
    )
    w = make(site, store)
    await w.run_once()
    assert w.reason == "unreachable"


async def test_the_request_identifies_nobody() -> None:
    site, store = Site(), MemoryFeedStore()
    site.override["index.json.minisig"] = lambda r: httpx.Response(
        200, content=site.files["index.json.minisig"], headers={"set-cookie": "sid=1"}
    )
    w = make(site, store)
    await w.run_once()
    await w.run_once()
    assert site.requests
    for r in site.requests:
        assert r.method == "GET" and r.url.query == b"" and r.url.scheme == "https"
        assert r.headers["user-agent"] == "spn-feed/1"
        assert r.headers["accept-encoding"] == "identity"
        assert "cookie" not in r.headers and "authorization" not in r.headers
        assert {k.lower() for k in r.headers} <= {
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "if-none-match",
            "connection",
        }


async def test_unconfigured_does_nothing_and_says_so() -> None:
    site, store = Site(), MemoryFeedStore()
    w = FeedWorker(FeatureSettings(network_feed_enabled=True), FeedSettings(), store)
    await w.run_once()
    assert site.requests == [] and w.reason == "not_configured"
    assert store.st and store.st.error_code == "not_configured"


async def test_disabled_wipes_stored_data() -> None:
    site, store = Site(), MemoryFeedStore()
    await make(site, store).run_once()
    site.requests.clear()
    w = make(site, store, enabled=False)
    task = asyncio.create_task(w.run())
    for _ in range(50):
        await asyncio.sleep(0.01)
        if store.wiped:
            break
    task.cancel()
    assert store.entries == {}
    assert store.st is not None and store.st.valid_until is None and store.st.files == {}
    assert w.reason == "feed_disabled_wiped"
    assert site.requests == []  # nothing fetched by the disabled worker


async def test_rollback_protection_survives_a_disable_and_re_enable() -> None:
    """Security review L8: turning the feed off wiped the last accepted serial, so an old
    signed generation was accepted again once the feed was turned back on."""
    site, store = Site(), MemoryFeedStore()
    site.publish(5)
    await make(site, store).run_once()
    assert store.st and store.st.serial == 5
    assert await store.wipe() is True  # what the disabled worker does
    site.publish(4, {"outbound": [entry("203.0.113.99", 4)]})  # a replayed older generation
    w = make(site, store)
    await w.run_once()
    assert w.state == "error" and w.reason == "feed_rollback"
    assert store.entries == {}
    site.publish(6)
    await w.run_once()
    assert w.state == "ok" and store.st and store.st.serial == 6


async def test_a_new_key_starts_a_new_serial_space() -> None:
    site, store = Site(), MemoryFeedStore()
    site.publish(5)
    await make(site, store).run_once()
    assert store.st is not None
    store.st.key_id = "0000000000000000"  # the serial was accepted under another key
    site.publish(2)
    w = make(site, store)
    await w.run_once()
    assert w.state == "ok" and store.st and store.st.serial == 2


async def test_client_refuses_a_name_outside_the_feed() -> None:
    client = FeedClient(feed_settings(), gate=FakeGate())  # type: ignore[arg-type]
    for bad in ("../x", "a/b", "x?y=1", ".hidden", ""):
        with pytest.raises(ValueError):
            await client.get(bad, max_bytes=10)


async def test_client_checks_the_gate_before_any_byte() -> None:
    site = Site()
    http = httpx.AsyncClient(transport=httpx.MockTransport(site.handler))
    client = FeedClient(feed_settings(), gate=FakeGate(open_=False), client=http)  # type: ignore[arg-type]
    with pytest.raises(EgressClosed):
        await client.get("index.json", max_bytes=10)
    assert site.requests == []


def test_settings_defaults_and_validation() -> None:
    s = FeedSettings.from_env({})
    assert s.interval_s == 3600
    assert s.lists == ("inbound", "outbound", "outbound-domains")
    ok = {"NETWORK_FEED_URL": BASE + "/", "NETWORK_FEED_KEY": PUBLIC.encoded}
    assert FeedSettings.from_env(ok).url == BASE
    bad_envs = [
        {"NETWORK_FEED_URL": BASE},  # URL without key
        {**ok, "NETWORK_FEED_URL": "http://feeds.example.org/v1"},
        {**ok, "NETWORK_FEED_URL": "https://203.0.113.5/v1"},
        {**ok, "NETWORK_FEED_URL": BASE + "?x=1"},
        {**ok, "NETWORK_FEED_URL": "https://user:pw@feeds.example.org/v1"},
        {**ok, "NETWORK_FEED_KEY": "RWnotakey"},
        {**ok, "NETWORK_FEED_INTERVAL_S": "10"},
        {**ok, "NETWORK_FEED_LISTS": "inbound,bogus"},
        {**ok, "NETWORK_FEED_LISTS": ","},
    ]
    for env in bad_envs:
        with pytest.raises(ValueError):
            FeedSettings.from_env(env)


def test_the_flag_is_off_by_default() -> None:
    assert FeatureSettings.from_env({}).network_feed_enabled is False
    assert FeatureSettings.from_env({"NETWORK_FEED_ENABLED": "true"}).network_feed_enabled


def _defaults_text(**over: str) -> str:
    values = {
        "NETWORK_DEFAULTS_VERSION": "1",
        "NETWORK_HUB_URL": "https://hub.example.org",
        "NETWORK_HUB_KEY": sign.node_key(sign.public_key_of(sign.generate_private_key())),
        "NETWORK_FEED_URL": BASE,
        "NETWORK_FEED_KEY": PUBLIC.encoded,
    }
    values.update(over)
    return "".join(f"{k}={v}\n" for k, v in values.items())


def _use_defaults(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(defaults, "load", lambda: defaults.from_text(text))


def test_the_shipped_defaults_apply_when_nothing_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    s = FeedSettings.from_env({})
    assert s.configured and s.url == BASE and s.key == PUBLIC.encoded
    assert s.host == "feeds.example.org"


def test_an_explicit_pair_wins_over_the_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    other = minisign.generate_keypair().public.encoded
    env = {"NETWORK_FEED_URL": "https://other.example.net/v1", "NETWORK_FEED_KEY": other}
    s = FeedSettings.from_env(env)
    assert (s.url, s.key, s.host) == ("https://other.example.net/v1", other, "other.example.net")


def test_a_half_set_pair_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    with pytest.raises(ValueError):
        FeedSettings.from_env({"NETWORK_FEED_URL": "https://other.example.net/v1"})
    with pytest.raises(ValueError):
        FeedSettings.from_env({"NETWORK_FEED_KEY": PUBLIC.encoded})


def test_placeholder_defaults_leave_the_feed_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(
        monkeypatch, _defaults_text(NETWORK_FEED_URL="<FEED_URL>", NETWORK_FEED_KEY="<FEED_KEY>")
    )
    assert not FeedSettings.from_env({}).configured
    _use_defaults(monkeypatch, _defaults_text(NETWORK_FEED_KEY="<FEED_KEY>"))
    assert not FeedSettings.from_env({}).configured


def test_a_malformed_defaults_file_is_a_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # build_feed_worker catches ValueError, so ingest starts with the feed unconfigured.
    _use_defaults(monkeypatch, "not a defaults file\n")
    with pytest.raises(ValueError):
        FeedSettings.from_env({})


def test_the_feed_host_is_the_host_of_the_gate_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_defaults(monkeypatch, _defaults_text())
    other = minisign.generate_keypair().public.encoded
    for env in (
        {},
        {"NETWORK_FEED_URL": "https://other.example.net/v1", "NETWORK_FEED_KEY": other},
    ):
        scope = egress_settings({**env, "EGRESS_MODE": "direct"}).scope_hosts
        assert FeedSettings.from_env(env).host in scope
