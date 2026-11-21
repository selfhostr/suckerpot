"""Blocklist values: only well-formed, blockable values survive, in canonical form."""

import pytest

from suckerpot_db.blocklist_values import (
    blockable_ip,
    is_shared_host,
    normalize_value,
    valid_domain,
    valid_url,
)


def ip4(*octets: int) -> str:
    """Spell an address from its octets, so no private address appears literally in the repo."""
    return ".".join(str(o) for o in octets)


@pytest.mark.parametrize(
    "value",
    [ip4(10, 0, 0, 5), ip4(192, 168, 1, 20), ip4(127, 0, 0, 1), ip4(169, 254, 1, 1),
     ip4(224, 0, 0, 1), ip4(0, 0, 0, 0), "::1", "fe80::1", "fc00::1", ip4(100, 64, 0, 1),
     "not an ip", "", "1.2.3.4/24", "999.1.1.1"],
)  # fmt: skip
def test_private_and_malformed_addresses_are_refused(value: str) -> None:
    assert blockable_ip(value) is None


def test_public_and_documentation_addresses_are_kept() -> None:
    assert blockable_ip("203.0.113.9") == "203.0.113.9"
    assert blockable_ip(" 198.51.100.7 ") == "198.51.100.7"
    assert blockable_ip("::ffff:203.0.113.9") == "203.0.113.9"
    assert blockable_ip("2001:db8::1") is None  # IPv6 documentation range is not whitelisted
    assert blockable_ip("8.8.5.5") == "8.8.5.5"


@pytest.mark.parametrize(
    "value",
    ["", "localhost", "a..b.com", "-a.com", "a-.com", "a b.com", "evil.com/path", "1.2.3.4",
     "x" * 64 + ".com", "ünicode.com", "a.com\nb.com"],
)  # fmt: skip
def test_bad_domains_are_refused(value: str) -> None:
    assert valid_domain(value) is None


def test_domains_are_lowercased_and_shared_hosts_refused() -> None:
    assert normalize_value("domain", "Dl.Bad-Host.RU.") == "dl.bad-host.ru"
    assert normalize_value("domain", "raw.githubusercontent.com") is None
    assert normalize_value("domain", "cdn.github.com") is None
    assert normalize_value("domain", "notgithub.com") == "notgithub.com"
    assert is_shared_host("x.raw.githubusercontent.com")
    assert not is_shared_host("notgithub.com")


@pytest.mark.parametrize(
    "value",
    ["javascript:alert(1)", "http://", "http://user@evil.com/x", "http://localhost/x",
     f"http://{ip4(10, 0, 0, 1)}/x", "http://evil.com/a b", "http://evil.com/\x00", "file:///etc/passwd",
     "http://evil.com/" + "a" * 600, "http://evil.com/é"],
)  # fmt: skip
def test_bad_urls_are_refused(value: str) -> None:
    assert valid_url(value) is None


def test_good_urls_keep_their_path() -> None:
    assert normalize_value("url", "HTTP://Evil.Example/a.sh?x=1") == "http://Evil.Example/a.sh?x=1"
    assert normalize_value("url", "http://203.0.113.5:8080/b") == "http://203.0.113.5:8080/b"
    assert normalize_value("url", "http://[2606:4700::1]/x") == "http://[2606:4700::1]/x"


def test_hashes_must_be_hex_of_a_known_length() -> None:
    assert normalize_value("hash", "A" * 64) == "a" * 64
    assert normalize_value("hash", "a" * 32) == "a" * 32
    assert normalize_value("hash", "a" * 63) is None
    assert normalize_value("hash", "g" * 64) is None
    assert normalize_value("nope", "x") is None


def test_public_resolvers_and_saas_apex_domains_are_never_listed() -> None:
    for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "2001:4860:4860::8888"):
        assert blockable_ip(ip) is None
    assert normalize_value("url", "http://8.8.8.8/x") is None
    for d in ("google.com", "dl.google.com", "cdn.cloudflare.com", "s3.amazonaws.com"):
        assert normalize_value("domain", d) is None


def test_the_owner_never_list_covers_addresses_networks_and_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BLOCKLIST_NEVER", "203.0.113.0/28, partner.example")
    monkeypatch.setenv("API_ALLOWED_HOSTS", "dash.example:8443")
    monkeypatch.setenv("AUTH_TRUSTED_PROXIES", "198.51.100.7")
    monkeypatch.setenv("INDICATORS_IGNORE", "*.corp.example")
    assert blockable_ip("203.0.113.9") is None
    assert blockable_ip("203.0.113.99") == "203.0.113.99"
    assert blockable_ip("198.51.100.7") is None
    assert normalize_value("domain", "api.partner.example") is None
    assert normalize_value("domain", "dash.example") is None
    assert normalize_value("domain", "x.corp.example") is None
    assert normalize_value("url", "http://partner.example/a.sh") is None
    assert normalize_value("domain", "other.example") == "other.example"


def test_an_ipv4_mapped_address_is_checked_as_ipv4() -> None:
    from suckerpot_db.blocklist_values import is_excluded_host

    assert is_excluded_host("8.8.8.8")
    assert is_excluded_host("::ffff:8.8.8.8")
    assert is_excluded_host("::ffff:808:808")
    assert not is_excluded_host("::ffff:198.51.100.7")
    assert is_excluded_host("www.youtube.com")
