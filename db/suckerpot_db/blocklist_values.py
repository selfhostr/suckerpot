"""Validation and canonical form of blocklist values (M16), shared by ingest and the API.

Every value comes from attacker-controlled text, so nothing is trusted: a value is accepted only
when it is a well-formed IP address, host name, URL or hash, and what comes back is the canonical
spelling. Nothing here resolves a name or opens a connection, and there is no regular expression
(only ``ipaddress`` and character sets), so no input can make it slow.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from typing import Literal

Kind = Literal["ip", "domain", "url", "hash"]
KINDS: tuple[Kind, ...] = ("ip", "domain", "url", "hash")

MAX_VALUE = 512
MAX_HOST = 253
MAX_LABEL = 63
URL_SCHEMES = ("http", "https", "ftp", "tftp")
HASH_LENGTHS = (32, 40, 64)

_DOC_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_HEX = frozenset("0123456789abcdef")

# Hosts that serve legitimate content for everybody. Attackers download tools from them, but
# blocking them would break normal work, so they are never listed as domains.
SHARED_HOSTS: frozenset[str] = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
        "objects.githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "pastebin.com",
        "paste.ee",
        "transfer.sh",
        "discord.com",
        "cdn.discordapp.com",
        "dropbox.com",
        "dl.dropboxusercontent.com",
        "drive.google.com",
        "docs.google.com",
        "storage.googleapis.com",
        "s3.amazonaws.com",
        "cloudfront.net",
        "azureedge.net",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "deb.debian.org",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "dl.google.com",
        "download.docker.com",
        "get.docker.com",
        "sourceforge.net",
        "telegram.org",
        "api.telegram.org",
        # Major SaaS, CDN and cloud apex domains: never worth a firewall rule.
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "microsoft.com",
        "windows.net",
        "windowsupdate.com",
        "office.com",
        "live.com",
        "azure.com",
        "amazon.com",
        "amazonaws.com",
        "cloudflare.com",
        "cloudflare-dns.com",
        "akamai.net",
        "akamaihd.net",
        "fastly.net",
        "apple.com",
        "icloud.com",
        "github.io",
        "githubusercontent.com",
        "ubuntu.com",
        "debian.org",
        "docker.com",
        "docker.io",
        "npmjs.org",
        "python.org",
        "mozilla.org",
        "cloudflare-ipfs.com",
        # CDN and update hosts of Google, Cloudflare, Microsoft, Akamai, Meta and Apple.
        "gvt1.com",
        "gvt2.com",
        "1e100.net",
        "googlevideo.com",
        "ggpht.com",
        "google-analytics.com",
        "cloudflare.net",
        "msftncsi.com",
        "msedge.net",
        "microsoftonline.com",
        "trafficmanager.net",
        "akadns.net",
        "edgekey.net",
        "edgesuite.net",
        "cdn-apple.com",
        "mzstatic.com",
        "fbcdn.net",
        "facebook.com",
        # Video and social platforms: an attacker types them in a command, the platform is not
        # the attacker, and a report to a registrar about the whole domain is wrong.
        "youtube.com",
        "youtu.be",
        "ytimg.com",
        "youtube-nocookie.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "t.me",
        "reddit.com",
        "vimeo.com",
        "tiktok.com",
        "twitch.tv",
        "linkedin.com",
        # URL shorteners and similar redirect services.
        "is.gd",
        "v.gd",
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "rebrand.ly",
        "ow.ly",
        "goo.gl",
        "shorturl.at",
        "rb.gy",
        # File, paste and storage services that host payloads for everybody.
        "mega.nz",
        "onedrive.live.com",
        "1drv.ms",
        "wetransfer.com",
        "we.tl",
        "mediafire.com",
        "ghostbin.com",
        "hastebin.com",
        "gist.github.com",
        "catbox.moe",
    }
)

# Public resolvers and similar infrastructure that attackers type into commands (for example
# ``wget http://8.8.8.8/x``) and that must never be blocked.
NEVER_IPS: frozenset[str] = frozenset(
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2", "76.76.19.19",
        "94.140.14.14", "94.140.15.15", "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2606:4700:4700::1111", "2606:4700:4700::1001", "2620:fe::fe",
    }
)  # fmt: skip
NEVER_ENV = ("BLOCKLIST_NEVER", "AUTH_TRUSTED_PROXIES", "API_ALLOWED_HOSTS", "INDICATORS_IGNORE")


Net = ipaddress.IPv4Network | ipaddress.IPv6Network
NeverList = tuple[tuple[Net, ...], tuple[str, ...]]


@lru_cache(maxsize=8)
def _owner_never(
    raw: str,
) -> NeverList:
    nets: list[Net] = []
    hosts: list[str] = []
    for item in raw.replace(",", " ").replace(";", " ").split():
        item = item.strip().lower()
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
            continue
        except ValueError:
            pass
        host = item.removeprefix("*.").removeprefix(".")
        host = host.split("/", 1)[0].rsplit(":", 1)[0] if host.count(":") == 1 else host
        if host:
            hosts.append(host)
    return tuple(nets), tuple(hosts)


def owner_never() -> tuple[
    tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...], tuple[str, ...]
]:
    """The owner's never-block list, read from the environment (cached per value).

    BLOCKLIST_NEVER plus the trusted proxies, the allowed host names and the ignore list.
    """
    return _owner_never("\n".join(os.environ.get(name, "") for name in NEVER_ENV))


def is_never_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    if h in NEVER_IPS:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return any(h == n or h.endswith("." + n) for n in owner_never()[1])
    nets = owner_never()[0]
    return any(ip.version == n.version and ip in n for n in nets)


def is_shared_host(host: str) -> bool:
    """True for a shared hosting name or any sub-domain of one."""
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in SHARED_HOSTS)


def is_excluded_host(host: str) -> bool:
    """True when a host or address must never be blocked or reported: the never list (public
    resolvers, the owner's own entries, by address or network) or a shared service."""
    h = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return is_never_host(h) or is_shared_host(h)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:8.8.8.8 is 8.8.8.8
    return is_never_host(str(ip))


def blockable_ip(value: str) -> str | None:
    """The canonical IP, or ``None`` for anything that must never be on a blocklist.

    Private, loopback, link-local, multicast, reserved and unspecified addresses are refused,
    so the owner's own network can never be listed. The three documentation ranges are allowed:
    demo data and the examples in the docs use them.
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if is_never_host(str(ip)):
        return None
    if any(ip.version == net.version and ip in net for net in _DOC_NETS):
        return str(ip)
    return str(ip) if ip.is_global and not ip.is_multicast else None


def valid_domain(value: str) -> str | None:
    host = value.strip().lower().rstrip(".")
    if not host or len(host) > MAX_HOST or "." not in host:
        return None
    labels = host.split(".")
    for label in labels:
        if not 1 <= len(label) <= MAX_LABEL or label[0] == "-" or label[-1] == "-":
            return None
        if not set(label) <= _HOST_CHARS:
            return None
    if labels[-1].isdigit():  # an IP address spelled with dots is not a domain
        return None
    return host


def _host_of_url(rest: str) -> str:
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority:
        return ""
    if authority.startswith("["):
        return authority[1:].split("]", 1)[0]
    return authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority


def valid_url(value: str) -> str | None:
    text = value.strip()
    if not text or len(text) > MAX_VALUE:
        return None
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in text):
        return None
    scheme, sep, rest = text.partition("://")
    if not sep or scheme.lower() not in URL_SCHEMES or not rest:
        return None
    host = _host_of_url(rest)
    if not host or is_never_host(host) or not (blockable_ip(host) or valid_domain(host)):
        return None
    return scheme.lower() + "://" + rest


def valid_hash(value: str) -> str | None:
    h = value.strip().lower()
    return h if len(h) in HASH_LENGTHS and set(h) <= _HEX else None


def normalize_value(kind: str, value: str) -> str | None:
    """Canonical value for ``kind``, or ``None`` when it is not well formed or not blockable."""
    if len(value) > MAX_VALUE * 2:
        return None
    if kind == "ip":
        return blockable_ip(value)
    if kind == "domain":
        host = valid_domain(value)
        return None if host is None or is_shared_host(host) or is_never_host(host) else host
    if kind == "url":
        return valid_url(value)
    if kind == "hash":
        return valid_hash(value)
    return None
