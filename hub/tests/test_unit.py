"""Unit tests that need no database."""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.requests import Request
from suckerpot_netproto import ProtoError, models, sign

from hub import pseudonym
from hub.config import ConfigError, Settings, load_signing_key
from hub.never import Never
from hub.ratelimit import AddressLimiter, Counter, client_address
from hub.roles import check_passwords, scram_verifier
from hub.routes.observations import build_rows

H1, H2 = "ab" * 32, "cd" * 32


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def fake_request(client: tuple[str, int] | None, headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": client,
    }
    return Request(scope)


# --- rate limits ---


def test_counter_window_and_retry_after() -> None:
    clock = Clock()
    c = Counter(60, 2, clock)
    assert (c.hit("a"), c.hit("a")) == (0, 0)
    assert 1 <= c.hit("a") <= 60
    assert c.hit("b") == 0  # keys are independent
    clock.now += timedelta(seconds=61)
    assert c.hit("a") == 0
    c.forget("a")
    assert c.peek("a") == 0
    assert c.hit("big", cost=3) > 0  # an over-sized cost never fits


def test_counter_memory_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import hub.ratelimit as rl

    monkeypatch.setattr(rl, "MAX_ENTRIES", 10)
    c = Counter(60, 5, Clock())
    for i in range(100):
        c.hit(str(i))
    assert len(c._data) <= 10


def test_address_is_hashed_and_key_rotates_daily() -> None:
    clock = Clock()
    lim = AddressLimiter(
        per_min=100, per_day=1000, failures_per_min=10, trust_proxy=False, clock=clock
    )
    req = fake_request(("203.0.113.5", 1))
    first = lim._id(req)
    assert first == lim._id(req) and "203.0.113.5" not in first and len(first) == 24
    expected = hmac.new(lim._key, b"203.0.113.5", hashlib.sha256).hexdigest()[:24]
    assert first == expected
    clock.now += timedelta(days=1)
    assert lim._id(req) != first  # a new random key every day
    # in-memory only: nothing on the limiter object holds the clear address
    assert "203.0.113.5" not in repr(vars(lim)) + repr(lim._minute._data)


def test_client_address_sources() -> None:
    assert client_address(fake_request(("203.0.113.5", 1)), False) == "203.0.113.5"
    proxied = fake_request(("100.64.9.9", 1), {"X-Forwarded-For": "198.51.100.1, 203.0.113.9"})
    assert client_address(proxied, True) == "203.0.113.9"  # the entry the trusted proxy appended
    assert client_address(proxied, False) == "100.64.9.9"
    assert client_address(fake_request(None), False) == ""


# --- pseudonyms ---


@pytest.mark.parametrize("name", ["night owl", "Owl_7", "a.b-c", "Quiet Fox 12"])
def test_pseudonym_valid(name: str) -> None:
    assert pseudonym.validate(name)


@pytest.mark.parametrize(
    "name",
    [
        "ab",
        "",
        "x" * 30,
        "a@b.c",
        "http://x.y",
        "owl 2026",
        "Admin",
        "ADMIN",
        "official",
        "my selfhostr",
        "-owl-",
        "ow l  x",
    ],
)
def test_pseudonym_invalid(name: str) -> None:
    with pytest.raises(ProtoError) as err:
        pseudonym.validate(name)
    assert err.value.code == "pseudonym_invalid"


def test_pseudonym_key_collapses_case_and_separators() -> None:
    keys = {pseudonym.validate(n) for n in ("Night Owl", "night-owl", "NIGHT_OWL", "night.owl")}
    assert len(keys) == 1


# --- config, roles, never-list ---


def test_settings_from_env_and_errors() -> None:
    s = Settings.from_env(
        {"HUB_POW_DIFFICULTY": "9", "HUB_ALLOW_DOCUMENTATION": "1", "HUB_REPORT_MODE": "auto"}
    )
    assert (s.pow_difficulty, s.allow_documentation, s.report_mode) == (9, True, "auto")
    assert (
        Settings.from_env({}).report_mode == "review" and Settings.from_env({}).pow_difficulty == 27
    )
    for env in (
        {"HUB_POW_DIFFICULTY": "x"},
        {"HUB_POW_DIFFICULTY": "99"},
        {"HUB_REPORT_MODE": "yes"},
    ):
        with pytest.raises(ConfigError):
            Settings.from_env(env)
    assert "password" not in repr(Settings(smtp_password="topsecret"))
    assert Settings.from_env({}).volume_min_nodes == 5
    assert Settings.from_env({"HUB_VOLUME_MIN_NODES": "2"}).volume_min_nodes == 2
    with pytest.raises(ConfigError):
        Settings.from_env({"HUB_VOLUME_MIN_NODES": "1"})
    with pytest.raises(ConfigError):
        Settings.from_env({"HUB_VOLUME_MIN_NODES": "1001"})


def test_signing_key_file(tmp_path: Path) -> None:
    good = tmp_path / "k"
    good.write_text(sign.b64u_encode(bytes(range(32))) + "\n")
    assert load_signing_key(str(good)) == bytes(range(32))
    for content in ("short", sign.b64u_encode(b"x" * 31), "!!!!"):
        bad = tmp_path / "bad"
        bad.write_text(content)
        with pytest.raises(ConfigError):
            load_signing_key(str(bad))
    for missing in ("", str(tmp_path / "nope")):
        with pytest.raises(ConfigError):
            load_signing_key(missing)


def test_password_policy_and_scram() -> None:
    ok = {
        "HUB_DB_PASSWORD": "a" * 24,
        "HUB_API_DB_PASSWORD": "b" * 24,
        "HUB_WORKER_DB_PASSWORD": "c" * 24,
    }
    assert check_passwords(ok) == []
    assert check_passwords({**ok, "HUB_API_DB_PASSWORD": "short"})
    assert check_passwords({**ok, "HUB_API_DB_PASSWORD": "a" * 24})  # not distinct
    assert check_passwords({**ok, "HUB_API_DB_PASSWORD": "b" * 23 + "@"})  # not URL safe
    assert check_passwords({k: v for k, v in ok.items() if k != "HUB_DB_PASSWORD"})
    assert (
        check_passwords({**ok, "HUB_API_DB_PASSWORD": "short", "HUB_ALLOW_DEFAULT_SECRETS": "1"})
        == []
    )
    v = scram_verifier("pw", salt=b"0" * 16)
    assert v.startswith("SCRAM-SHA-256$4096:") and "pw" not in v
    salted = hashlib.pbkdf2_hmac("sha256", b"pw", b"0" * 16, 4096)
    stored = hashlib.sha256(hmac.new(salted, b"Client Key", hashlib.sha256).digest()).digest()
    assert base64.b64encode(stored).decode() in v


def test_never_list_matching() -> None:
    never = Never.from_rows(
        [
            ("198.51.100.128/25", "ip"),
            ("2001:db8:1::/48", "ip"),
            ("Example.NET.", "domain"),
            (H1, "sha256"),
            ("bad", "ip"),
            ("x", "asn"),
        ]
    )
    assert (
        never.has_ip("198.51.100.130")
        and never.has_ip("2001:db8:1::8888")
        and not never.has_ip("192.0.2.4")
    )
    assert never.has_ip("198.51.100.130:23")  # c2 values carry a port
    assert never.has_domain("a.b.example.net") and never.has_domain("example.net")
    assert not never.has_domain("notexample.net") and not never.has_domain("example.org")
    assert never.has_url("http://cdn.example.net/x") and never.has_url("http://198.51.100.130/x")
    assert never.has_url("http://[2001:db8:1::1]/x") and not never.has_url("http://example.org/x")
    assert never.has_hash(H1.upper()) and not never.has_hash(H2)
    assert never.matches("c2_ip", "198.51.100.130:23") and never.matches("sha256", H1)
    assert not never.matches("url", "http://example.org/")


# --- observation rows ---


def _batch(**parts: object) -> models.ObservationBatch:
    data = {"protocol": "spn/1", "batch_id": sign.new_nonce(), "day": "2026-10-31", **parts}
    return models.ObservationBatch.model_validate(data, context={"allow_documentation": True})


def _src(ip: str, **kw: object) -> dict[str, object]:
    return {
        "ip": ip,
        "services": ["ssh"],
        "activity": ["login"],
        "tags": [],
        "sessions": 1,
        "attempts": 1,
        **kw,
    }


def test_build_rows_keeps_a_source_and_a_payload_host_apart() -> None:
    """Security review H3: a payload host is recorded as ``payload_ip`` only. The ``ip`` row of
    the same address carries what it did as a source, nothing that was typed about it."""
    parsed = _batch(
        sources=[_src("192.0.2.4", tags=["mirai"], sessions=2, attempts=0)],
        payloads=[{"url_b": H1, "host_ip": "192.0.2.4", "sha256": H2, "fetched": True}],
        files=[{"sha256": H2, "family": "mirai"}],
    )
    out, accepted, rejected = build_rows(parsed, Never())
    by_key = {(r["kind"], r["value"]): r for r in out}
    assert len(out) == 4 and not rejected  # ip, url, sha256 and the hub-internal payload_ip
    assert by_key[("ip", "192.0.2.4")]["activity"] == ["login"]
    assert by_key[("ip", "192.0.2.4")]["tags"] == ["mirai"]
    assert by_key[("ip", "192.0.2.4")]["fetched"] is False
    assert by_key[("ip", "192.0.2.4")]["sessions"] == 2
    assert by_key[("payload_ip", "192.0.2.4")]["activity"] == ["download"]
    assert by_key[("payload_ip", "192.0.2.4")]["fetched"] is True
    assert (
        by_key[("sha256", H2)]["families"] == ["mirai"]
        and by_key[("sha256", H2)]["fetched"] is True
    )
    assert accepted == {"sources": 1, "payloads": 1, "c2": 0, "files": 1}


def test_build_rows_blinded_hosts_and_c2() -> None:
    parsed = _batch(
        payloads=[{"url_b": H1, "host_b": H2}],
        c2=[
            {"ip": "192.0.2.9", "port": 23},
            {"ip": "192.0.2.9", "port": 24},
            {"domain_b": H2, "port": 80},
        ],
    )
    out, accepted, _ = build_rows(parsed, Never())
    assert {(r["kind"], r["value"]) for r in out} == {
        ("url", H1), ("domain", H2), ("c2_ip", "192.0.2.9:23"), ("c2_ip", "192.0.2.9:24"), ("c2_domain", H2),
    }  # fmt: skip
    assert accepted["c2"] == 3


def test_build_rows_payload_host_on_never_list_is_not_stored() -> None:
    never = Never.from_rows([("198.51.100.128/25", "ip")])
    out, _, rejected = build_rows(
        _batch(payloads=[{"url_b": H1, "host_ip": "198.51.100.130"}]), never
    )
    assert {(r["kind"]) for r in out} == {"url"} and not rejected


# --- review fixes: rate limit keys, eviction, never-list parsing ---


def test_ipv6_clients_share_a_slash_64() -> None:
    a = fake_request(("2001:db8:1:2:aaaa::1", 1))
    b = fake_request(("2001:db8:1:2:bbbb::9", 1))
    c = fake_request(("2001:db8:1:3::1", 1))
    assert client_address(a, False) == client_address(b, False) == "2001:db8:1:2::/64"
    assert client_address(c, False) != client_address(a, False)
    clock = Clock()
    lim = AddressLimiter(
        per_min=1, per_day=100, failures_per_min=10, trust_proxy=False, clock=clock
    )
    assert lim.check_unsigned(a) == 0 and lim.check_unsigned(b) > 0  # same prefix, same bucket
    assert lim.check_unsigned(c) == 0


def test_pending_challenges_are_capped_per_prefix() -> None:
    lim = AddressLimiter(
        per_min=100, per_day=1000, failures_per_min=10, challenges_per_prefix=2,
        trust_proxy=False, clock=Clock(),
    )  # fmt: skip
    req = fake_request(("203.0.113.5", 1))
    assert (lim.check_challenge(req), lim.check_challenge(req)) == (0, 0)
    assert lim.check_challenge(req) > 0
    assert lim.check_challenge(fake_request(("203.0.113.6", 1))) == 0


def test_eviction_drops_the_oldest_window_not_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    import hub.ratelimit as rl

    monkeypatch.setattr(rl, "MAX_ENTRIES", 3)
    clock = Clock()
    c = Counter(60, 1, clock)
    for key in "abc":
        assert c.hit(key) == 0
    assert c.hit("d") == 0  # evicts "a" only
    assert c.hit("b") > 0 and c.hit("c") > 0 and c.hit("d") > 0  # others keep their counts
    assert c.hit("a") == 0  # a was evicted, so it starts fresh


def test_never_list_parses_bracketed_ipv6_c2_values() -> None:
    from hub.never import split_host_port
    from hub.routes.observations import c2_value

    never = Never.from_rows([("2001:db8:1::8888", "ip"), ("198.51.100.128/25", "ip")])
    assert c2_value("2001:db8:1::8888", 53) == "[2001:db8:1::8888]:53"
    assert c2_value("198.51.100.130", 53) == "198.51.100.130:53"
    assert never.matches("c2_ip", c2_value("2001:db8:1::8888", 53))
    assert never.matches("c2_ip", "198.51.100.130:53") and not never.matches(
        "c2_ip", "[2001:db8:2::1]:53"
    )
    assert split_host_port("[2001:db8::1]:53") == ("2001:db8::1", 53)
    assert split_host_port("2001:db8::1") == ("2001:db8::1", None)
    assert split_host_port("198.51.100.1:23") == ("198.51.100.1", 23)


def test_a_scanner_named_in_wget_commands_is_never_listed_inbound() -> None:
    """Security review H3: an address that only scans over TCP, and that attackers type into
    honeypots as a wget host, must not reach ``inbound`` as a malware dropper."""
    import uuid
    from datetime import date

    from hub.feeds import select

    nodes = [uuid.UUID(int=i + 1) for i in range(10)]
    days = [date(2026, 10, 30), date(2026, 10, 31)]
    obs: list[select.Obs] = []
    for n in nodes:
        for d in days:
            parsed = _batch(
                sources=[_src("192.0.2.4", services=["ssh"], activity=["scan"], attempts=0)],
                payloads=[{"url_b": H1, "host_ip": "192.0.2.4"}],
            )
            out, _, _ = build_rows(parsed, Never())
            ip = next(r for r in out if r["kind"] == "ip")
            assert "download" not in ip["activity"] and "malware-drop" not in ip["tags"]
            obs.append(
                select.Obs(
                    node=n,
                    day=d,
                    services=tuple(ip["services"]),
                    activity=tuple(ip["activity"]),
                    tags=tuple(ip["tags"]),
                    attempts=ip["attempts"],
                )
            )
    t = select.TargetInput("t_000000000001", "ip", "192.0.2.4", "confirmed", days[0], False, obs)
    ctx = select.SelectContext(k=5, today=date(2026, 11, 1), cohort_of={})
    assert select.evaluate(t, ctx, True).candidate is None


def test_malware_like_needs_a_known_family_or_an_executable_type() -> None:
    from hub.malware import is_malware_like

    assert is_malware_like([], "elf-arm")
    assert is_malware_like(None, "pe")
    assert is_malware_like([], "script-sh")
    assert is_malware_like(["mirai"], None)
    assert not is_malware_like([], None)
    assert not is_malware_like([], "other")
    assert not is_malware_like([], "archive")
    assert not is_malware_like(["not-a-family"], "other")
