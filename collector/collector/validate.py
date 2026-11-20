"""URL validation for the collector (SSRF defence), docs/dev/design/m21.md section 5.3.

Pure and offline: nothing here resolves a name. It runs on every URL and again on every redirect
hop. Names are resolved by the VPN's resolver inside the tunnel, whose rebinding protection and the
host firewall are the second line.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urljoin, urlsplit

from collector.config import Network

MAX_URL = 1024
FETCHABLE = {"http", "https"}
RECORD_ONLY = {"ftp", "tftp"}
DEFAULT_PORTS = {"http": 80, "https": 443}

DENIED_SUFFIXES = (
    ".local", ".localhost", ".internal", ".lan", ".home.arpa", ".arpa", ".intranet", ".corp",
    ".private",
)  # fmt: skip
DENIED_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]+)$")
# Compose service names (the last label of "<service>.<network>" style aliases).
INTERNAL_NAMES = frozenset(
    {"vpn", "ingest", "collector", "analyzer", "api", "db", "redis", "migrate", "egress", "demo"}
)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_DOTTED_QUAD = re.compile(rf"^{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}$")
_NUMERIC_LABEL = re.compile(r"^(?:0[xX][0-9a-fA-F]*|[0-9]+)$")

# Address blocks that are not "global" for every Python version, or that wrap another address.
_EXTRA_BLOCKED: tuple[Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "224.0.0.0/4",
        "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
        "2001::/32", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
    )
)  # fmt: skip


class UrlRefused(Exception):
    """The URL must not be fetched. ``code`` is a constant, safe to store and display."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ValidUrl:
    url: str  # normalised, at most MAX_URL characters
    scheme: str
    host: str  # lower-case, IDNA (ASCII); IPv6 without brackets
    port: int


def blocked_address(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    deny_nets: tuple[Network, ...] = (),
) -> bool:
    """True for anything that is not a public unicast address, or is on the deny list."""
    if not addr.is_global:
        return True
    for net in (*_EXTRA_BLOCKED, *deny_nets):
        if net.version == addr.version and addr in net:
            return True
    return False


def _host_of(netloc: str) -> tuple[str, int | None]:
    if "@" in netloc:
        raise UrlRefused("userinfo")
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            raise UrlRefused("bad_host")
        host, rest = netloc[1:end], netloc[end + 1 :]
        if rest and not rest.startswith(":"):
            raise UrlRefused("bad_host")
        port_text = rest[1:]
    else:
        host, _, port_text = netloc.partition(":")
        if ":" in port_text:
            raise UrlRefused("bad_host")
    port: int | None = None
    if port_text:
        if not port_text.isascii() or not port_text.isdigit() or len(port_text) > 5:
            raise UrlRefused("bad_port")
        port = int(port_text)
    elif netloc.endswith(":"):
        raise UrlRefused("bad_port")
    return host, port


def _check_name(host: str, policy_hosts: tuple[str, ...]) -> str:
    name = host.lower().rstrip(".")
    if not name:
        raise UrlRefused("bad_host")
    # Decimal, octal, hex and short IPv4 forms ("3232235777", "0x7f.1", "10.1") end in a number.
    if _NUMERIC_LABEL.match(name.rsplit(".", 1)[-1]):
        raise UrlRefused("ip_form")
    if "." not in name:
        raise UrlRefused("single_label")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError:
        raise UrlRefused("bad_host") from None
    # No underscore: Docker's resolver answers "<container>.<network>" names (networks here are
    # called suckerpot_*), which would bypass the VPN resolver's rebinding protection.
    if len(ascii_name) > 253 or not re.fullmatch(r"[a-z0-9.-]+", ascii_name):
        raise UrlRefused("bad_host")
    labels = ascii_name.split(".")
    if any(not label for label in labels):
        raise UrlRefused("bad_host")
    if (
        not _TLD.match(labels[-1])
        or INTERNAL_NAMES & set(labels)
        or any(label.startswith("suckerpot") for label in labels)
    ):
        raise UrlRefused("denied_host")
    if ascii_name in DENIED_NAMES or ascii_name.endswith(DENIED_SUFFIXES):
        raise UrlRefused("denied_host")
    for denied in policy_hosts:
        if ascii_name == denied or ascii_name.endswith("." + denied):
            raise UrlRefused("denied_host")
    return ascii_name


def normalize_url(
    raw: str,
    *,
    deny_nets: tuple[Network, ...] = (),
    deny_hosts: tuple[str, ...] = (),
) -> ValidUrl:
    """Validate and normalise one URL. Raises ``UrlRefused`` with a constant code."""
    if not raw or len(raw) > 4 * MAX_URL:
        raise UrlRefused("too_long")
    if any(ord(c) <= 0x20 or ord(c) == 0x7F or c == "\\" for c in raw):
        raise UrlRefused("bad_chars")
    try:
        parts = urlsplit(raw)
    except ValueError:
        raise UrlRefused("malformed") from None
    scheme = parts.scheme.lower()
    if scheme in RECORD_ONLY:
        raise UrlRefused("unsupported")
    if scheme not in FETCHABLE:
        raise UrlRefused("bad_scheme")
    if not parts.netloc:
        raise UrlRefused("no_host")
    host_text, port = _host_of(parts.netloc)
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise UrlRefused("bad_port")

    host: str
    if parts.netloc.startswith("["):
        if "%" in host_text:
            raise UrlRefused("ip_form")  # zone ids
        try:
            addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv6Address(host_text)
        except ValueError:
            raise UrlRefused("bad_host") from None
        if blocked_address(addr, deny_nets):
            raise UrlRefused("ip_forbidden")
        host = str(addr)
    elif _DOTTED_QUAD.match(host_text):
        addr = ipaddress.IPv4Address(host_text)
        if blocked_address(addr, deny_nets):
            raise UrlRefused("ip_forbidden")
        host = str(addr)
    else:
        host = _check_name(host_text, deny_hosts)

    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/%:@!$&'()*+,;=-._~?")
    shown_host = f"[{host}]" if ":" in host else host
    netloc = shown_host if port == DEFAULT_PORTS[scheme] else f"{shown_host}:{port}"
    url = f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")
    if len(url) > MAX_URL:
        raise UrlRefused("too_long")
    return ValidUrl(url=url, scheme=scheme, host=host, port=port)


def resolve_redirect(
    base: str,
    location: str,
    *,
    deny_nets: tuple[Network, ...] = (),
    deny_hosts: tuple[str, ...] = (),
) -> ValidUrl:
    """The next hop, validated like any other URL (a redirect to a private address is refused)."""
    if len(location) > 4 * MAX_URL:
        raise UrlRefused("too_long")
    return normalize_url(
        urljoin(base, location.strip()), deny_nets=deny_nets, deny_hosts=deny_hosts
    )
