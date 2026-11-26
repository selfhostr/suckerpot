from __future__ import annotations

import hashlib
from datetime import date

import pytest

from suckerpot_netproto import blind, buckets, pow


def test_url_canonical_equivalences() -> None:
    same = [
        "http://Example.org:80/a?b=1#x",
        "HTTP://EXAMPLE.ORG/a?b=1",
        "http://example.org:80/a?b=1",
    ]
    assert len({blind.blind_url(u) for u in same}) == 1
    assert blind.blind_url("http://example.org/a?b=1") != blind.blind_url(
        "http://example.org/a?b=2"
    )
    assert blind.blind_url("http://example.org/A") != blind.blind_url("http://example.org/a")
    assert blind.blind_url("http://example.org:8080/") != blind.blind_url("http://example.org/")
    assert blind.canonical_url("https://example.org:443") == "https://example.org"


def test_url_rejections() -> None:
    for bad in (
        "",
        "example.org/x",
        "http://",
        "http://user:pw@example.org/",
        "http://example.org/a b",
        "http://example.org:99999/",
        "http://example.org:x/",
        "http://exa mple.org/",
        "http://example.org/\x00",
        "http://" + "a" * 64 + ".org/",
        "http://" + "x" * 3000,
        "1http://example.org/",
    ):
        with pytest.raises(ValueError):
            blind.canonical_url(bad)


def test_domain_rules() -> None:
    assert blind.canonical_domain("WWW.Example.Org.") == "www.example.org"
    assert blind.canonical_domain("bücher.example.org") == "xn--bcher-kva.example.org"
    for bad in ("", "198.51.100.1", "a..b", "-a.org", "a b.org", "x" * 64 + ".org"):
        with pytest.raises(ValueError):
            blind.canonical_domain(bad)


def test_blind_formula() -> None:
    expected = hashlib.sha256(b"spn/1|domain|example.org").hexdigest()
    assert blind.blind_domain("Example.org") == expected
    with pytest.raises(ValueError):
        blind.blind("ip", "198.51.100.1")


def test_verify_reveal() -> None:
    value_b = blind.blind_url("http://example.org/x.sh")
    assert blind.verify_reveal("url", "HTTP://example.org:80/x.sh", value_b) == (
        "http://example.org/x.sh"
    )
    assert blind.verify_reveal("url", "http://example.org/y.sh", value_b) is None
    assert blind.verify_reveal("domain", "http://example.org/x.sh", value_b) is None
    assert blind.verify_reveal("url", "not a url", value_b) is None


def test_url_host() -> None:
    assert blind.url_host("http://example.org:8080/x") == "example.org"
    assert blind.url_host("http://[2001:db8::1]:8080/x") == "[2001:db8::1]"
    assert blind.url_host("http://198.51.100.9/x") == "198.51.100.9"


CHALLENGE = hashlib.sha256(b"c").digest()
PUB = hashlib.sha256(b"k").digest()


def test_leading_zero_bits() -> None:
    assert pow.leading_zero_bits(b"\x00\x00\x80") == 16
    assert pow.leading_zero_bits(b"\x00\x01") == 15
    assert pow.leading_zero_bits(b"\x0f") == 4
    assert pow.leading_zero_bits(b"\x00\x00") == 16


def test_pow_valid_one_bit_short_and_wrong_challenge() -> None:
    nonce = pow.solve_pow(CHALLENGE, PUB, 10)
    assert nonce is not None
    bits = pow.leading_zero_bits(pow.pow_digest(CHALLENGE, PUB, nonce))
    assert pow.verify_pow(CHALLENGE, PUB, nonce, 10)
    assert pow.verify_pow(CHALLENGE, PUB, nonce, bits)
    assert not pow.verify_pow(CHALLENGE, PUB, nonce, bits + 1)  # one bit short
    wrong = [
        c
        for c in (hashlib.sha256(bytes([i])).digest() for i in range(8))
        if not pow.verify_pow(c, PUB, nonce, 10)
    ]
    assert wrong


def test_pow_limits() -> None:
    assert pow.solve_pow(CHALLENGE, PUB, 40, max_iterations=100) is None
    assert pow.solve_pow(CHALLENGE, PUB, 40, should_stop=lambda: True) is None
    assert not pow.verify_pow(CHALLENGE, PUB, b"", 0)
    assert not pow.verify_pow(CHALLENGE, PUB, b"x" * 17, 0)
    assert not pow.verify_pow(CHALLENGE, PUB, b"x", 49)
    with pytest.raises(ValueError):
        pow.solve_pow(CHALLENGE, PUB, 49)


def test_count_bucket() -> None:
    cases = {0: 0, 1: 0, 2: 1, 9: 1, 10: 2, 99: 2, 100: 3, 999: 3, 1000: 4, 10**6: 4}
    for n, b in cases.items():
        assert buckets.count_bucket(n) == b
    with pytest.raises(ValueError):
        buckets.count_bucket(-1)


def test_nodes_bucket_tier_countries() -> None:
    assert [buckets.nodes_bucket(n) for n in (5, 9, 10, 24, 25, 500)] == [0, 0, 1, 1, 2, 2]
    with pytest.raises(ValueError):
        buckets.nodes_bucket(4)
    assert [buckets.tier(n) for n in (0, 1, 99, 100, 999, 1000, 9999, 10000)] == [
        0,
        1,
        1,
        2,
        2,
        3,
        3,
        4,
    ]
    assert buckets.countries_or_none(2) is None
    assert buckets.countries_or_none(3) == 3


def test_country_thresholds_are_apart() -> None:
    # a member's country shows from 2 members; a count of countries still needs 3
    assert buckets.MIN_MEMBERS_COUNTRY_SHOWN == 2
    assert buckets.MIN_COUNTRIES_SHOWN == 3


def test_batch_day_rules() -> None:
    today = date(2026, 11, 1)
    assert buckets.check_batch_day(date(2026, 11, 1), today) == "day_not_closed"
    assert buckets.check_batch_day(date(2026, 11, 2), today) == "day_not_closed"
    assert buckets.check_batch_day(date(2026, 10, 31), today) is None
    assert buckets.check_batch_day(date(2026, 10, 29), today) is None
    assert buckets.check_batch_day(date(2026, 10, 28), today) == "day_too_old"
    assert buckets.parse_day("2026-11-01") == today
    for bad in ("2026-1-01", "20261101", "2026-13-01"):
        with pytest.raises(ValueError):
            buckets.parse_day(bad)
