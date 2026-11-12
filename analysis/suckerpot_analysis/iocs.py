"""IOC and C2 extraction from deobfuscated scripts and binary strings.

Documentation ranges are deliberately kept: the collector applies the same ignore filter as
ingest (`INDICATORS_IGNORE`, `API_ALLOWED_HOSTS`). Only addresses that can never be a remote
C2 (loopback, link-local, multicast, unspecified, RFC 1918, CGNAT) are dropped here.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator

from .models import Confidence, Ioc, IocKind, IocSource

_SCAN_CAP = 16 * 1024 * 1024
_URL = re.compile(r"\b(?:https?|tftp|ftp)://[^\s'\"<>\\|;()`$\x00-\x1f\x7f-\xff]{1,512}")
_IP_PORT = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)")
_IP = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_TLDS = (
    "com net org io ru cn xyz top info biz cc tk ml ga cf gq pw su to me in us de uk nl fr br kr "
    "jp co site online club win bid work ws vip shop live fun icu cyou"
).split()
_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}(?:"
    + "|".join(_TLDS)
    + r"))(?![A-Za-z0-9-])",
    re.IGNORECASE,
)
_MIRAI_KEYS = (0x22, 0x37, 0x54)
_HOSTISH = re.compile(rb"[A-Za-z0-9.\-]{4,253}")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def urls_in(text: str) -> Iterator[str]:
    """The URLs of `text`, cut the way `extract_iocs` cuts them."""
    for m in _URL.finditer(text[:_SCAN_CAP]):
        yield m.group().rstrip(".,)")


def _useful_ip(text: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_reserved or ip in _CGNAT:
        return False
    return not (
        ip.is_private
        and ip not in ipaddress.ip_network("192.0.2.0/24")
        and ip not in ipaddress.ip_network("198.51.100.0/24")
        and ip not in ipaddress.ip_network("203.0.113.0/24")
    )


def extract_iocs(
    texts: Iterable[str],
    *,
    source: IocSource = "script_url",
    trusted: bool = False,
    max_iocs: int = 200,
) -> list[Ioc]:
    """Extract URLs, ip:port pairs, public IPv4 literals and host names.

    `source="script_url"` is for deobfuscated scripts: URLs become `next_url`. Any other source
    marks binary strings: URLs become `c2_url`, and `trusted=True` (a YARA-matched binary)
    upgrades ip:port and URLs to high confidence.
    """
    out: list[Ioc] = []
    seen: set[tuple[str, str, int | None]] = set()

    def add(kind: IocKind, value: str, port: int | None, src: IocSource, conf: Confidence) -> None:
        key = (kind, value, port)
        if key in seen or len(out) >= max_iocs or len(value) > 1024:
            return
        seen.add(key)
        out.append(Ioc(kind=kind, value=value, port=port, source=src, confidence=conf))

    script = source == "script_url"
    for text in texts:
        text = text[:_SCAN_CAP]
        for m in _URL.finditer(text):
            url = m.group().rstrip(".,)")
            if script:
                add("next_url", url, None, "script_url", "high")
            else:
                add("c2_url", url, None, source, "high" if trusted else "low")
        if script:
            continue
        masked_ports: set[str] = set()
        for m in _IP_PORT.finditer(text):
            port = int(m.group(2))
            if 0 < port < 65536 and _useful_ip(m.group(1)):
                masked_ports.add(m.group(1))
                add("c2_ip", m.group(1), port, "binary_ip_port", "high" if trusted else "low")
        for m in _IP.finditer(text):
            if m.group(1) not in masked_ports and _useful_ip(m.group(1)):
                add("c2_ip", m.group(1), None, source, "low")
        for m in _DOMAIN.finditer(text):
            add("c2_domain", m.group(1).lower(), None, source, "low")
    return out


_MIRAI_KEYTABLES = {k: bytes(b ^ k for b in range(256)) for k in _MIRAI_KEYS}


def mirai_table_iocs(data: bytes, *, max_iocs: int = 50) -> list[Ioc]:
    """Best effort: single-byte XOR (0x22, 0x37, 0x54) over key-terminated runs, keep host names."""
    window = data[:_SCAN_CAP]
    out: list[Ioc] = []
    seen: set[tuple[str, str]] = set()
    for key in _MIRAI_KEYS:
        decoded = window.translate(_MIRAI_KEYTABLES[key])
        for m in _HOSTISH.finditer(decoded):
            # Mirai entries end with an encoded NUL, which is the key byte itself.
            if m.end() < len(window) and window[m.end()] != key:
                continue
            host = m.group().decode("ascii").lower()
            if _useful_ip(host):
                kind: IocKind = "c2_ip"
            elif _DOMAIN.fullmatch(host):
                kind = "c2_domain"
            else:
                continue
            if (kind, host) in seen or len(out) >= max_iocs:
                continue
            seen.add((kind, host))
            out.append(Ioc(kind=kind, value=host, source="mirai_table", confidence="low"))
    return out
