"""The deny set: everything that must never appear in an artefact (design M22, section 7.1).

``load_self_terms`` takes plain data (database rows already read by the caller, and an
environment mapping), so this module does no I/O. The matching itself lives in ``guard``.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from .normalize import IPAddress, addr_key, collapse

# --- built in. These literals may appear in this module only (static test) -----------------

PROJECT_TERMS: Final[tuple[str, ...]] = (
    "suckerpot",
    "selfhostr",
    "self hostr",
    "self-hostr",
    "self_hostr",
    "sucker pot",
    "sucker-pot",
    "sucker_pot",
    "honeypot",
    "honey pot",
    "honey-pot",
    "honeynet",
)
PROJECT_SKELETONS: Final[frozenset[str]] = frozenset(collapse(t) for t in PROJECT_TERMS)

# Default fake host names of the sensors. A test in the sensors compares their defaults to it.
FAKE_HOSTNAMES: Final[tuple[str, ...]] = ("srv-web01", "srv-app02", "srv-db01")

DASHBOARD_PATHS: Final[tuple[str, ...]] = ("/attacks/", "/campaigns/", "/api/v1/")

# Environment variables read by ``load_self_terms`` and the kind of term each one yields.
ENV_OWNER_HOSTS: Final = ("API_ALLOWED_HOSTS",)
ENV_URLS: Final = ("API_ALLOWED_ORIGINS", "ALERTS_DASHBOARD_URL")
ENV_RANGES: Final = ("INDICATORS_IGNORE", "BLOCKLIST_NEVER", "AUTH_TRUSTED_PROXIES")
ENV_VPN: Final = ("VPN_WG_ENDPOINT_IP",)
# The node's public name in the network (M29): free text, matched as plain text (M38).
ENV_TEXTS: Final = ("NETWORK_PSEUDONYM",)
MIN_EXTRA_TEXT: Final = 4
ENV_SENSOR_NAMES: Final = (
    "SSH_HOSTNAME",
    "RDP_HOSTNAME",
    "SMB_HOSTNAME",
    "SMB_DOMAIN",
    "WEB_HOSTNAME",
)

# Too generic to be matched as a free word.
_GENERIC_NAMES: Final = frozenset(
    {
        "localhost",
        "api",
        "web",
        "db",
        "redis",
        "testserver",
        "host",
        "admin",
        "office",
        "group",
        "intra",
        "corp",
        "workgroup",
        "workgroup.local",
        "storage",
        "fileserver",
        "diskstation",
        "server",
        "router",
        "gateway",
        "printer",
        "desktop",
        "laptop",
        "home",
        "lan",
        "local",
        "domain",
        "mshome",
        "mshome.net",
        "nas",
        "backup",
        "files",
        "share",
        "mail",
        "dc",
        "ad",
        "test",
        "dev",
        "prod",
    }
)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

TermCode = Literal["self_address", "self_name", "owner_domain", "vpn_address"]


# Words of the artefacts themselves. A deny term that equals or sits inside one of these would
# make every render fail (or hide a real leak behind noise), so it is never accepted.
ARTEFACT_VOCABULARY: Final[tuple[str, ...]] = (
    "evidence.csv",
    "evidence.txt",
    "report.txt",
    "x-arf.org",
    "www.x-arf.org",
    "xarf.org",
    "attack.mitre.org",
    "mitre.org",
    "mitre-attack",
    "reported-from",
    "report-type",
    "schema-url",
    "source-type",
    "user-agent",
    "text/plain",
    "text/csv",
    "multipart/mixed",
    "us-ascii",
    "abuse",
    "login-attack",
    "web-hack",
    "malware-distribution",
    "failed_logins",
    "login_then_commands",
    "indicator",
    "bundle",
    "tlp",
    # XARF v4 parts and field names (M38)
    "xarf.json",
    "xarf_version",
    "multipart/report",
    "feedback-report",
    "feedback-type",
    "application/json",
    "source_identifier",
    "source_port",
    "destination_port",
    "report_id",
    "content_type",
    "first_seen",
    "last_seen",
    "login_attack",
    "vulnerability_scan",
    "vulnerabilities_probed",
    "web_vuln_scan",
    "sql_injection",
    "compromise_evidence",
    "infrastructure",
    "connection",
    "malware",
    "botnet",
    "reporter",
)

FRESHNESS: Final = timedelta(hours=72)


class SelfTermRow(BaseModel):
    """One ``report_self_terms`` row, as the caller read it.

    ``manual``: typed by the owner, always trusted, never expires. ``sensor``: ingest, from our
    own sensors' declared identity, trusted. ``learned``: ingest, from attacker traffic, which is
    untrusted: it acts in the deny set only once ``confirmed``.
    """

    model_config = ConfigDict(frozen=True)

    kind: Literal["address", "cidr", "name", "text"]
    value: str
    source: Literal["manual", "learned", "sensor"] = "manual"
    distinct_sources: int = 0
    confirmed: bool = False
    last_seen: datetime | None = None


@dataclass(frozen=True)
class NameTerm:
    value: str  # lower-case, no trailing dot
    code: TermCode
    labels: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class SelfTerms:
    addresses: frozenset[str]
    networks: tuple[IPNetwork, ...]
    vpn_addresses: frozenset[str]
    names: tuple[NameTerm, ...]
    texts: tuple[str, ...]
    has_self_address: bool
    # base64 needles of the dotted form of every address (three alignments), case sensitive
    b64_needles: tuple[tuple[str, TermCode], ...] = ()

    def is_self(self, addr: IPAddress) -> TermCode | None:
        key = addr_key(addr)
        if key in self.vpn_addresses:
            return "vpn_address"
        if key in self.addresses:
            return "self_address"
        for net in self.networks:
            if net.version == addr.version and addr in net:
                return "self_address"
        return None


def _b64_alignments(text: str) -> list[str]:
    """Substrings of base64 that are fixed whatever bytes surround ``text`` (3 alignments)."""
    data = text.encode("ascii")
    out: list[str] = []
    for pad, lead in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b"\x00" * pad + data).decode("ascii").rstrip("=")
        total = pad + len(data)
        trail = 0 if total % 3 == 0 else 1
        core = enc[lead : len(enc) - trail] if trail else enc[lead:]
        if len(core) >= 6:
            out.append(core)
    return out


def _split(value: str) -> list[str]:
    return [p for p in re.split(r"[\s,;]+", value.strip()) if p]


def _norm_name(value: str) -> str:
    return value.strip().strip(".").casefold()


def _host_of(value: str) -> str:
    value = value.strip()
    if "://" in value:
        return (urlsplit(value).hostname or "").casefold()
    value = value.split("/", 1)[0]
    if value.startswith("["):
        return value[1:].split("]", 1)[0].casefold()
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.casefold()


def mask_value(kind: str, value: str) -> str:
    """Display form of a term for the Settings list, e.g. ``203.0.•••.•••``."""
    dot = "•••"
    if kind in ("address", "cidr"):
        head = value.split("/", 1)[0]
        if "." in head:
            parts = head.split(".")
            return ".".join([*parts[:2], dot, dot]) if len(parts) == 4 else dot
        if ":" in head:
            return head.split(":", 1)[0] + ":" + dot
        return dot
    return value[:2] + dot if len(value) > 2 else dot


def _in_vocabulary(term: str) -> bool:
    return any(
        term in v or v.endswith("." + term) or term.endswith("." + v) for v in ARTEFACT_VOCABULARY
    )


def _acts(row: SelfTermRow) -> bool:
    """A learned row is attacker-controlled: it counts only once confirmed."""
    return row.source != "learned" or row.confirmed


def _fresh(row: SelfTermRow, now: datetime) -> bool:
    if row.source == "manual":
        return True
    return row.last_seen is not None and timedelta(0) <= now - row.last_seen <= FRESHNESS


def load_self_terms(
    rows: Iterable[SelfTermRow],
    env: Mapping[str, str],
    *,
    vpn_exit: str | None = None,
    extra_names: Iterable[str] = (),
    extra_texts: Iterable[str] = (),
    now: datetime | None = None,
) -> SelfTerms:
    """Merge table rows, environment values and the built-in names into one ``SelfTerms``.

    ``has_self_address`` (the fail-closed precondition) needs an address row that acts (manual,
    sensor, or learned and confirmed) and is fresh (manual never expires; the others need
    ``last_seen`` within 72 hours of ``now``). Stale rows stay in the deny set.

    ``extra_texts`` (and ``NETWORK_PSEUDONYM``) are plain-text terms such as the node's network
    pseudonym; one shorter than ``MIN_EXTRA_TEXT`` characters is left out (it would match words).
    """
    clock = now or datetime.now(UTC)
    addresses: set[str] = set()
    vpn: set[str] = set()
    networks: list[IPNetwork] = []
    names: dict[str, TermCode] = {}
    texts: list[str] = []
    has_self = False

    def add_range(value: str, *, vpn_term: bool = False) -> bool:
        value = value.strip()
        try:
            if "/" in value:
                net = ipaddress.ip_network(value, strict=False)
                if net.num_addresses == 1:
                    (addresses if not vpn_term else vpn).add(str(net.network_address))
                else:
                    networks.append(net)
                return True
            addr = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            return False
        for a in _expand(addr):
            (vpn if vpn_term else addresses).add(addr_key(a))
        return True

    def add_name(value: str, code: TermCode) -> None:
        n = _norm_name(value)
        if not n or n == "*" or " " in n or _in_vocabulary(n):
            return
        if n in _GENERIC_NAMES:
            return
        # A bare word is a deny term only if it looks like a host name: a digit or a hyphen.
        if "." not in n and (len(n) < 4 or not (any(c.isdigit() for c in n) or "-" in n)):
            return
        names.setdefault(n, code)

    for row in rows:
        if not _acts(row):
            continue
        if row.kind in ("address", "cidr"):
            if add_range(row.value) and _fresh(row, clock):
                has_self = True
        elif row.kind == "name":
            add_name(row.value, "self_name")
        else:
            text = row.value.strip().casefold()
            if len(text) >= 2 and not _in_vocabulary(text):
                texts.append(text)

    for key in ENV_OWNER_HOSTS:
        for item in _split(env.get(key, "")):
            host = _host_of(item)
            if not add_range(host):
                add_name(host, "owner_domain")
    for key in ENV_URLS:
        for item in _split(env.get(key, "")):
            host = _host_of(item)
            if not add_range(host):
                add_name(host, "owner_domain")
    for key in ENV_RANGES:
        for item in _split(env.get(key, "")):
            add_range(item)
    for key in ENV_VPN:
        for item in _split(env.get(key, "")):
            if not add_range(_host_of(item), vpn_term=True):
                add_name(_host_of(item), "owner_domain")
    for key in ENV_SENSOR_NAMES:
        for item in _split(env.get(key, "")):
            add_name(item, "self_name")
    for item in (*FAKE_HOSTNAMES, *extra_names):
        add_name(item, "self_name")
    for item in (*(env.get(k, "") for k in ENV_TEXTS), *extra_texts):
        text = (item or "").strip().casefold()
        if len(text) >= MIN_EXTRA_TEXT and not _in_vocabulary(text) and text not in texts:
            texts.append(text)
    if vpn_exit:
        add_range(vpn_exit, vpn_term=True)

    needles: list[tuple[str, TermCode]] = []
    addr_codes: list[tuple[set[str], TermCode]] = [
        (addresses, "self_address"),
        (vpn, "vpn_address"),
    ]
    for keys, code in addr_codes:
        for key in sorted(keys):
            forms = {key}
            if ":" in key:
                forms.add(ipaddress.IPv6Address(key).exploded)
            for form in sorted(forms):
                needles += [(n, code) for n in _b64_alignments(form)]
    for name, code in sorted(names.items()):
        if name.isascii():
            needles += [(n, code) for n in _b64_alignments(name)]

    return SelfTerms(
        addresses=frozenset(addresses),
        networks=tuple(networks),
        vpn_addresses=frozenset(vpn),
        names=tuple(
            NameTerm(value=n, code=c, labels=tuple(n.split("."))) for n, c in sorted(names.items())
        ),
        texts=tuple(sorted(set(texts))),
        has_self_address=has_self,
        b64_needles=tuple(needles),
    )


def _expand(addr: IPAddress) -> list[IPAddress]:
    """An address and, for mapped IPv6, the IPv4 inside it."""
    out: list[IPAddress] = [addr]
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        out.append(addr.ipv4_mapped)
    return out
