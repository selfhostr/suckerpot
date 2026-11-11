"""The daily batch (design M29 section 9.4): allow-listed aggregates, guarded item by item.

Inputs are the fact rows of ``source.py`` (counters, indicator values, sample metadata). The
builder never sees an event, a credential, a command or an HTTP field (N3).

* Exclusions: non-global addresses (documentation ranges too, N10), the never-block list and
  every self term. Tags and families outside the protocol allow-lists are dropped.
* URLs and domain names leave only as blinded hashes (N6). Before blinding, the clear value goes
  through the identity guard and an extra check for the node's own address in any spelling
  (dotted, decimal, hex, octal, IPv4-mapped): a hit drops the item.
* Every item is guarded as JSON; the whole batch is guarded once more. An item failure drops the
  item; a batch failure sends nothing (N4).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Final, Protocol
from urllib.parse import urlsplit

from suckerpot_db.blocklist_values import is_never_host
from suckerpot_netproto import blind, buckets, sign
from suckerpot_netproto import models as wire
from suckerpot_netproto.enums import (
    ACTIVITIES,
    FAMILIES_V1,
    FILE_TYPES_V1,
    PROTOCOL,
    SERVICES,
    is_valid_tag,
)
from suckerpot_reporting import GuardContext, SelfTerms, guard

from .source import BatchSource, C2Fact, FileFact, PayloadFact, SessionFact

EXPLOIT_TAGS: Final = frozenset(
    "php2shell eternalblue bluekeep sql-rce exec-attempt container-escape synology-exploit "
    "c3rb3r".split()
)
SEVERITY: Final = {
    "exploit": 6,
    "download": 5,
    "command": 4,
    "login_success": 3,
    "login": 2,
    "http": 1,
    "scan": 1,
    "connect": 0,
}
SELF_CODES: Final = frozenset({"self_address", "self_name", "owner_domain", "vpn_address"})
# UDP sensors: the source address is spoofable, so a session there proves presence only. Its
# logins, commands, tags and attempts are never sent: one source row merges every service, and
# spoofed REGISTER floods must not turn into a brute force next to one real TCP connect.
UDP_SENSORS: Final = frozenset({"sip"})
_INT_HOST = re.compile(r"^(0x[0-9a-f]+|0[0-7]*|[0-9]+)$", re.IGNORECASE)


class TermsSource(Protocol):
    async def get(self) -> SelfTerms | None: ...


@dataclass
class BuildResult:
    status: str  # ok | waiting_self_address | guard_failed | terms_unavailable
    batch: dict[str, Any] | None = None
    counts: dict[str, int] = field(default_factory=dict)
    dropped: dict[str, int] = field(default_factory=dict)


BATCH_LISTS: Final = ("sources", "payloads", "c2", "files")


def batch_counts(batch: dict[str, Any]) -> dict[str, int]:
    """Item counts of a batch body, with the four keys the hub reports."""
    return {k: len(batch[k]) for k in BATCH_LISTS}


def file_type_of(kind: str | None, arch: str | None) -> str | None:
    """The coarse file type of a sample's kind and architecture, or ``None``."""
    if kind == "elf":
        mapped = {
            "x86": "elf-x86",
            "x86-64": "elf-x86_64",
            "arm": "elf-arm",
            "aarch64": "elf-aarch64",
            "mips": "elf-mips",
            "ppc": "elf-ppc",
            "ppc64": "elf-ppc",
        }.get(arch or "", "elf-other")
        return mapped
    if kind == "pe":
        return "pe"
    if kind == "script":
        return "script-sh"
    if kind in {"gzip", "zip", "tar", "xz", "7z", "bzip2"}:
        return "archive"
    return "other" if kind else None


def _family(value: str | None) -> str | None:
    return value if value in FAMILIES_V1 else None


def _tags(values: set[str]) -> list[str]:
    return sorted(t for t in values if is_valid_tag(t))[:32]


def activities_of(f: SessionFact) -> set[str]:
    out: set[str] = set()
    if f.login_attempts > 0:
        out.add("login")
    if f.login_success:
        out.add("login_success")
    if f.commands > 0:
        out.add("command")
    if f.downloads > 0:
        out.add("download")
    if f.http_requests > 0:
        out.add("http")
    if any(t in EXPLOIT_TAGS or t.startswith("cve-") for t in f.tags):
        out.add("exploit")
    if not out:
        out.add("scan" if "recon" in f.tags else "connect")
    return out & ACTIVITIES


def _addresses_in_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address a host spelling can mean: literal, decimal, hex, octal, IPv4-mapped."""
    h = host.strip("[]").lower()
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        ip = ipaddress.ip_address(h)
        found.append(ip)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            found.append(ip.ipv4_mapped)
        return found
    except ValueError:
        pass
    if _INT_HOST.fullmatch(h):
        try:
            n = int(h, 0) if h.startswith("0x") else int(h, 8 if len(h) > 1 and h[0] == "0" else 10)
            if 0 <= n < 2**32:
                found.append(ipaddress.IPv4Address(n))
        except ValueError:
            pass
    parts = h.split(".")
    if 2 <= len(parts) <= 4 and all(_INT_HOST.fullmatch(p) for p in parts):
        try:  # inet_aton style: a.b.c.d with per-part bases, last part fills the rest
            nums = [
                int(p, 0) if p.startswith("0x") else int(p, 8 if len(p) > 1 and p[0] == "0" else 10)
                for p in parts
            ]
            total = 0
            for n in nums[:-1]:
                total = (total << 8) | n
            total = (total << (8 * (5 - len(nums)))) | nums[-1]
            if 0 <= total < 2**32:
                found.append(ipaddress.IPv4Address(total))
        except ValueError:
            pass
    return found


def mentions_self(value: str, terms: SelfTerms) -> bool:
    """True when ``value`` (a URL or domain) names the node's own address in any spelling."""
    host = value
    if "://" in value:
        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            return True  # unparsable: do not ship it
    return any(terms.is_self(a) is not None for a in _addresses_in_host(host))


class BatchBuilder:
    def __init__(
        self,
        source: BatchSource,
        terms: TermsSource,
        *,
        max_sources: int = 5000,
        allow_documentation: bool = False,
        batch_id: Callable[[], str] = sign.new_nonce,
    ) -> None:
        self.source = source
        self.terms = terms
        self.max_sources = max_sources
        # Test overlay only (the hub has the same switch): documentation ranges pass.
        self.allow_documentation = allow_documentation
        self._batch_id = batch_id

    # -- guards -----------------------------------------------------------------------------

    def _ctx(self) -> GuardContext:
        return GuardContext(allow_documentation=self.allow_documentation)

    def _item_ok(
        self, item: Any, clear: str | None, terms: SelfTerms, dropped: dict[str, int]
    ) -> bool:
        codes: set[str] = set()
        if clear is not None:
            if mentions_self(clear, terms):
                codes.add("self_address")
            codes |= set(guard(clear, terms, fmt="text", ctx=self._ctx()).codes)
        codes |= set(guard(item, terms, fmt="json", ctx=self._ctx()).codes)
        codes.discard("no_self_address")
        if not codes:
            return True
        key = "self" if codes & SELF_CODES else "guard"
        dropped[key] = dropped.get(key, 0) + 1
        return False

    def _ip(self, value: str) -> str | None:
        try:
            ip = wire.parse_global_ip(value, allow_documentation=self.allow_documentation)
        except ValueError:
            return None
        return None if is_never_host(ip) else ip

    # -- sections ---------------------------------------------------------------------------

    def _sources(
        self, facts: list[SessionFact], terms: SelfTerms, dropped: dict[str, int]
    ) -> list[dict[str, Any]]:
        per_ip: dict[str, dict[str, Any]] = {}
        for f in facts:
            ip = self._ip(f.ip)
            if ip is None:
                dropped["range"] = dropped.get("range", 0) + 1
                continue
            e = per_ip.setdefault(
                ip,
                {"services": set(), "activity": set(), "tags": set(), "sessions": 0, "attempts": 0},
            )
            if f.sensor in SERVICES:
                e["services"].add(f.sensor)
            e["sessions"] += f.sessions
            if f.sensor in UDP_SENSORS:
                continue  # presence only (see UDP_SENSORS)
            e["activity"] |= activities_of(f)
            e["tags"] |= set(f.tags)
            e["attempts"] += f.login_attempts
        items: list[dict[str, Any]] = []
        for ip, e in per_ip.items():
            if not e["services"]:
                continue
            if not e["activity"]:
                e["activity"] = {"connect"}  # only UDP sessions: bare presence
            item = {
                "ip": ip,
                "services": sorted(e["services"]),
                "activity": sorted(e["activity"]),
                "tags": _tags(e["tags"]),
                "sessions": buckets.count_bucket(e["sessions"]),
                "attempts": buckets.count_bucket(e["attempts"]),
            }
            if self._item_ok(item, ip, terms, dropped):
                items.append(item)
        items.sort(
            key=lambda i: (
                -max(SEVERITY[a] for a in i["activity"]),
                -i["sessions"],
                i["ip"],
            )
        )
        return items

    def _payloads(
        self, facts: list[PayloadFact], terms: SelfTerms, dropped: dict[str, int]
    ) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for f in facts:
            try:
                canonical = blind.canonical_url(f.url)
                host = blind.url_host(canonical)
                url_b = blind.blind_canonical("url", canonical)
            except ValueError:
                dropped["invalid"] = dropped.get("invalid", 0) + 1
                continue
            item: dict[str, Any] = {"url_b": url_b, "fetched": bool(f.sha256)}
            literal = host.strip("[]")
            try:
                ipaddress.ip_address(literal)
                is_ip = True
            except ValueError:
                is_ip = False
            if is_ip:
                ip = self._ip(literal)
                if ip is None:
                    dropped["range"] = dropped.get("range", 0) + 1
                    continue
                item["host_ip"] = ip
            else:
                if is_never_host(host):
                    continue
                item["host_b"] = blind.blind_canonical("domain", blind.canonical_domain(host))
            if f.sha256:
                item["sha256"] = f.sha256
                if (fam := _family(f.family)) is not None:
                    item["family"] = fam
                if (ft := file_type_of(f.kind, f.arch)) in FILE_TYPES_V1:
                    item["file_type"] = ft
            # The clear URL is guarded before it is dropped from view: a self name in the host,
            # path or query must stop the item even though only a hash would leave.
            if self._item_ok(item, canonical, terms, dropped):
                out.setdefault(url_b, item)
        return list(out.values())

    def _c2(
        self, facts: list[C2Fact], terms: SelfTerms, dropped: dict[str, int]
    ) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for f in facts:
            item: dict[str, Any] = {"port": f.port, "via_sha256": f.sha256}
            if (fam := _family(f.family)) is not None:
                item["family"] = fam
            if f.kind == "c2_ip":
                ip = self._ip(f.value)
                if ip is None:
                    dropped["range"] = dropped.get("range", 0) + 1
                    continue
                item["ip"] = ip
                key = f"{ip}:{f.port}"
            else:
                try:
                    domain = blind.canonical_domain(f.value)
                except ValueError:
                    dropped["invalid"] = dropped.get("invalid", 0) + 1
                    continue
                if is_never_host(domain):
                    continue
                item["domain_b"] = blind.blind_canonical("domain", domain)
                key = f"{item['domain_b']}:{f.port}"
            clear = item.get("ip") or f.value
            if self._item_ok(item, clear, terms, dropped):
                out.setdefault(key, item)
        return list(out.values())

    def _files(
        self, facts: list[FileFact], terms: SelfTerms, dropped: dict[str, int]
    ) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for f in facts:
            if len(f.sha256) != 64 or f.sha256 != f.sha256.lower():
                dropped["invalid"] = dropped.get("invalid", 0) + 1
                continue
            item: dict[str, Any] = {"sha256": f.sha256}
            if (fam := _family(f.family)) is not None:
                item["family"] = fam
            if (ft := file_type_of(f.kind, f.arch)) in FILE_TYPES_V1:
                item["file_type"] = ft
            if self._item_ok(item, None, terms, dropped):
                out.setdefault(f.sha256, item)
        return list(out.values())

    # -- the batch --------------------------------------------------------------------------

    async def build(self, day: date) -> BuildResult:
        terms = await self.terms.get()
        if terms is None:
            return BuildResult("terms_unavailable")
        if not terms.has_self_address:
            return BuildResult("waiting_self_address")
        dropped: dict[str, int] = {}
        sources = self._sources(await self.source.sessions(day), terms, dropped)
        if len(sources) > self.max_sources:
            dropped["cap"] = dropped.get("cap", 0) + len(sources) - self.max_sources
            sources = sources[: self.max_sources]
        batch: dict[str, Any] = {
            "protocol": PROTOCOL,
            "batch_id": self._batch_id(),
            "day": day.isoformat(),
            "sources": sources,
            "payloads": self._payloads(await self.source.payloads(day), terms, dropped)[
                : wire.MAX_PAYLOADS
            ],
            "c2": self._c2(await self.source.c2(day), terms, dropped)[: wire.MAX_C2],
            "files": self._files(await self.source.files(day), terms, dropped)[: wire.MAX_FILES],
        }
        # The 1 MiB request cap: drop the least severe sources until the padded body fits.
        while sources and len(sign.pad_body(batch)) > wire.MAX_BODY_OBSERVATIONS:
            cut = max(1, len(sources) // 10)
            del sources[-cut:]
            dropped["cap"] = dropped.get("cap", 0) + cut
        counts = batch_counts(batch)
        # The whole body once more, then the wire models (the hub's own validation).
        whole = guard(batch, terms, fmt="json", ctx=self._ctx())
        if not set(whole.codes) <= {"no_self_address"}:
            return BuildResult("guard_failed", None, counts, dropped)
        try:
            wire.ObservationBatch.model_validate(
                batch, context={"allow_documentation": self.allow_documentation}
            )
        except Exception as exc:  # a malformed batch is a bug here, never sent
            del exc
            return BuildResult("guard_failed", None, counts, dropped)
        return BuildResult("ok", batch, counts, dropped)
