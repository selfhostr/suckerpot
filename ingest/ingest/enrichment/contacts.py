"""Probable command-and-control addresses of known malware, read from threat-intel providers.

For a file hash that VirusTotal or abuse.ch already recognise, the providers know which network
addresses public sandboxes saw that malware contact. This module holds the pure parts (parsing,
validation, confidence, caps) and the SQL; the requests themselves are made by ``IntelWorker``
under the same rules as every other lookup: fixed hosts, a body cap, persisted daily quotas.

What is read is a string. Nothing here, or anywhere after it, fetches, resolves or connects to an
address: they are shown to the owner as defanged text and offered to the blocklist scoring.

Confidence:

* ``high``: ThreatFox lists the address as ``botnet_cc`` for that hash.
* ``medium``: VirusTotal's sandboxes saw the malware contact it, and it is a public address that
  is not on the never-block list (resolvers, big SaaS and CDN names) nor in the owner's ignore
  list.
* anything else is dropped, never stored.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.blocklist_values import normalize_value
from suckerpot_db.sample_kinds import is_plain_web_hash

from ingest.enrichment.textutil import clean, parse_when
from ingest.indicators import IndicatorSettings, normalize_host

Source = Literal["virustotal", "threatfox"]
CONTACT_SOURCES: tuple[Source, ...] = ("virustotal", "threatfox")

PER_SOURCE = 20  # rows kept per hash and source: at most 40 per hash
VT_PAGE = 20  # ``limit`` sent to each VirusTotal relationship
THREATFOX_SCAN = 100  # answer entries examined
CACHE_HOURS = 24
CONTACTS_QUOTA_SHARE = (
    0.3  # of each provider's daily quota, counted apart (``<provider>:contacts``)
)
CONTACTS_PER_SOURCE_PER_DAY = 20  # contact lookups a day for hashes one source address used
MIN_NETWORKS = 3  # independent source networks that confirm a hash that no sensor computed
PER_CYCLE_CONTACTS = 2

THREATFOX_LINK = "https://threatfox.abuse.ch/ioc/{id}/"
VIRUSTOTAL_LINK = "https://www.virustotal.com/gui/file/{h}/relations"


# Big shared infrastructure: a sandbox that talks to Google, Cloudflare, Microsoft, Akamai,
# Fastly, Meta or Apple addresses says nothing about the malware, and blocking them would break
# normal work. VirusTotal contacts in these networks are dropped (ThreatFox ``botnet_cc`` never is).
SHARED_INFRA_ASNS: frozenset[int] = frozenset(
    {15169, 13335, 8075, 20940, 16625, 54113, 32934, 714, 6185}
)  # Google, Cloudflare, Microsoft, Akamai (x2), Fastly, Meta, Apple (x2)
SHARED_ASNS_ENV = "CONTACTS_SHARED_ASNS"  # comma separated AS numbers; replaces the default list


def shared_asns(env: Mapping[str, str] | None = None) -> frozenset[int]:
    """The shared-infrastructure AS numbers (``CONTACTS_SHARED_ASNS`` replaces the default)."""
    raw = (os.environ if env is None else env).get(SHARED_ASNS_ENV, "").strip()
    if not raw:
        return SHARED_INFRA_ASNS
    out = {
        int(t.upper().removeprefix("AS"))
        for t in raw.replace(";", ",").replace(" ", ",").split(",")
        if t.upper().removeprefix("AS").isdigit() and len(t) <= 12
    }
    return frozenset(n for n in out if 0 < n < 2**32) or SHARED_INFRA_ASNS


@dataclass(frozen=True, slots=True)
class Contact:
    address: str
    kind: str  # ip | domain
    port: int | None
    source: Source
    confidence: str  # high | medium
    family: str | None = None
    provider_score: int | None = None
    reference: str | None = None
    first_seen: datetime | None = None  # the provider's date when it gives one


@dataclass(frozen=True, slots=True)
class ContactCandidate:
    id: int
    value: str
    missing: tuple[Source, ...]


def accept_address(raw: Any, settings: IndicatorSettings) -> tuple[str, str] | None:
    """``(kind, canonical value)`` for an address worth listing, else None.

    Refuses private, loopback, reserved and (unless the owner keeps them) documentation ranges,
    the owner's ignore list, resolvers and big SaaS or CDN names. Never resolves anything.
    """
    if not isinstance(raw, str) or not raw or len(raw) > 253:
        return None
    host = normalize_host(raw, settings)
    if host is None:
        return None
    kind, value = host
    value = normalize_value(kind, value) or ""
    return (kind, value) if value else None


def _port(value: Any) -> int | None:
    if isinstance(value, str) and value.isdigit() and len(value) <= 5:
        number = int(value)
        return number if 1 <= number <= 65535 else None
    return None


def split_host_port(raw: str) -> tuple[str, int | None]:
    """``203.0.113.5:443`` -> host and port; a bare IPv6 address has no port."""
    text_ = raw.strip()
    if text_.startswith("["):
        host, _, rest = text_[1:].partition("]")
        return host, _port(rest[1:]) if rest.startswith(":") else None
    try:
        ipaddress.ip_address(text_)
    except ValueError:
        pass
    else:
        return text_, None
    if text_.count(":") == 1:
        host, _, port = text_.partition(":")
        return host, _port(port)
    return text_, None


def virustotal_contacts(
    ips: Any,
    domains: Any,
    settings: IndicatorSettings,
    reference: str | None,
    is_shared_ip: Callable[[str], bool] | None = None,
) -> list[Contact]:
    """Medium-confidence contacts from the two relationship answers (``data[].id``).

    ``is_shared_ip`` tells whether an address belongs to big shared infrastructure (local ASN
    database); such addresses are dropped.
    """
    out: list[Contact] = []
    seen: set[str] = set()
    for payload, cap in ((ips, PER_SOURCE // 2), (domains, PER_SOURCE // 2)):
        taken = 0
        data = payload.get("data") if isinstance(payload, dict) else None
        for item in data[:VT_PAGE] if isinstance(data, list) else ():
            ident = item.get("id") if isinstance(item, dict) else None
            if taken >= cap or not isinstance(ident, str):
                continue
            host, port = split_host_port(ident)
            accepted = accept_address(host, settings)
            if accepted is None or accepted[1] in seen:
                continue
            if accepted[0] == "ip" and is_shared_ip is not None and is_shared_ip(accepted[1]):
                continue
            seen.add(accepted[1])
            taken += 1
            out.append(Contact(accepted[1], accepted[0], port, "virustotal", "medium", None,
                               None, reference))  # fmt: skip
    return out


def threatfox_contacts(
    payload: Any,
    settings: IndicatorSettings,
) -> list[Contact]:
    """High-confidence contacts: entries of type ``botnet_cc`` (IP:port, domain or URL IOCs)."""
    entries = payload.get("data") if isinstance(payload, dict) else None
    out: list[Contact] = []
    seen: set[str] = set()
    for entry in entries[:THREATFOX_SCAN] if isinstance(entries, list) else ():
        if len(out) >= PER_SOURCE:
            break
        if not isinstance(entry, dict) or entry.get("threat_type") != "botnet_cc":
            continue
        ioc, ioc_type = entry.get("ioc"), entry.get("ioc_type")
        if not isinstance(ioc, str) or len(ioc) > 512:
            continue
        if ioc_type == "ip:port" or ioc_type == "domain":
            host, port = split_host_port(ioc)
        elif ioc_type == "url":
            authority = ioc.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
            host, port = split_host_port(authority.rsplit("@", 1)[-1])
        else:
            continue
        accepted = accept_address(host, settings)
        if accepted is None or accepted[1] in seen:
            continue
        seen.add(accepted[1])
        ident = str(entry.get("id", ""))
        score = entry.get("confidence_level")
        out.append(
            Contact(
                accepted[1],
                accepted[0],
                port,
                "threatfox",
                "high",
                clean(entry.get("malware_printable"), 64) or clean(entry.get("malware"), 64),
                score if isinstance(score, int) and 0 <= score <= 100 else None,
                THREATFOX_LINK.format(id=ident) if ident.isdigit() and len(ident) <= 12 else None,
                parse_when(entry.get("first_seen_utc") or entry.get("first_seen")),
            )
        )
    return out


async def candidates(
    factory: async_sessionmaker[AsyncSession],
    sources: tuple[Source, ...],
    limit: int = PER_CYCLE_CONTACTS,
) -> list[ContactCandidate]:
    """Known hashes without a fresh contact lookup at each wanted source, best evidence first.

    A hash is "known" when VirusTotal, URLhaus or ThreatFox already recognise it (an
    ``indicator_intel`` row with ``known``). Demo hashes are never looked up. A hash that no
    sensor computed (text typed in a command can plant any hash) needs sessions from at least
    ``MIN_NETWORKS`` distinct source networks. One source address cannot spend more than
    ``CONTACTS_PER_SOURCE_PER_DAY`` contact lookups a day.
    """
    if not sources:
        return []
    stmt = text(
        f"""
        SELECT i.id, i.value,
               COALESCE(array_agg(c.source) FILTER (
                   WHERE c.source = ANY(:srcs)
                     AND c.checked_at > now() - make_interval(hours => :hours)), '{{}}') AS fresh
        FROM indicators i
        CROSS JOIN LATERAL (
            SELECT count(DISTINCT network(set_masklen(s.src_ip,
                       CASE WHEN family(s.src_ip) = 4 THEN 24 ELSE 48 END))) AS nets,
                   count(DISTINCT s.src_ip) AS ips, min(s.src_ip) AS one
            FROM indicator_sessions s WHERE s.indicator_id = i.id
        ) l
        CROSS JOIN LATERAL (
            SELECT CASE WHEN l.ips = 1 THEN (
                SELECT count(DISTINCT k.indicator_id)
                FROM indicator_sessions s2
                JOIN indicator_contact_checks k ON k.indicator_id = s2.indicator_id
                WHERE s2.src_ip = l.one AND k.checked_at > date_trunc('day', now())
            ) ELSE 0 END AS used
        ) u
        LEFT JOIN indicator_contact_checks c ON c.indicator_id = i.id
        WHERE i.type = 'hash' AND NOT i.demo AND i.last_seen > now() - interval '7 days'
          AND (i.trusted OR l.nets >= :min_nets)
          AND NOT {is_plain_web_hash("i.value")}
          AND u.used < :per_ip
          AND EXISTS (SELECT 1 FROM indicator_intel n
                      WHERE n.indicator_id = i.id AND n.known
                        AND NOT ('not-checked' = ANY (n.tags)))
        GROUP BY i.id, l.nets, l.ips, u.used
        HAVING count(*) FILTER (
                   WHERE c.source = ANY(:srcs)
                     AND c.checked_at > now() - make_interval(hours => :hours)) < :n
        ORDER BY l.ips DESC, i.sightings DESC, i.id
        LIMIT :k
        """  # noqa: S608  (constant fragments only)
    )
    async with factory() as session:
        rows = (
            await session.execute(
                stmt,
                {
                    "srcs": list(sources),
                    "hours": CACHE_HOURS,
                    "n": len(sources),
                    "k": limit,
                    "min_nets": MIN_NETWORKS,
                    "per_ip": CONTACTS_PER_SOURCE_PER_DAY,
                },
            )
        ).all()
    out: list[ContactCandidate] = []
    for r in rows:
        wanted = tuple(s for s in sources if s not in (r.fresh or []))
        if wanted:
            out.append(ContactCandidate(r.id, r.value, wanted))
    return out


async def store(
    factory: async_sessionmaker[AsyncSession],
    indicator_id: int,
    source: Source,
    contacts: list[Contact],
) -> None:
    """Replace one hash's contacts from one source (at most ``PER_SOURCE`` rows) and cache it."""
    async with factory() as session, session.begin():
        for c in contacts[:PER_SOURCE]:
            await session.execute(
                text(
                    """
                    INSERT INTO indicator_contacts (hash_indicator_id, address, kind, port, source,
                        confidence, family, provider_score, reference, first_seen, checked_at)
                    VALUES (:i, :a, :k, :p, :s, :c, :f, :sc, :r, COALESCE(:fs, now()), now())
                    ON CONFLICT (hash_indicator_id, address, source) DO UPDATE SET
                        kind = :k, port = :p, confidence = :c, family = :f, provider_score = :sc,
                        reference = :r, checked_at = now()
                    """
                ),
                {
                    "i": indicator_id,
                    "a": c.address,
                    "k": c.kind,
                    "p": c.port,
                    "s": c.source,
                    "c": c.confidence,
                    "f": c.family,
                    "sc": c.provider_score,
                    "r": c.reference,
                    "fs": c.first_seen,
                },
            )
        # Addresses the provider no longer lists (checked_at is the transaction start).
        await session.execute(
            text(
                "DELETE FROM indicator_contacts WHERE hash_indicator_id = :i AND source = :s "
                "AND checked_at < now()"
            ),
            {"i": indicator_id, "s": source},
        )
        await session.execute(
            text(
                """
                INSERT INTO indicator_contact_checks (indicator_id, source, checked_at)
                VALUES (:i, :s, now())
                ON CONFLICT (indicator_id, source) DO UPDATE SET checked_at = now()
                """
            ),
            {"i": indicator_id, "s": source},
        )


async def cleanup_stored(
    factory: async_sessionmaker[AsyncSession],
    settings: IndicatorSettings,
    is_shared_ip: Callable[[str], bool] | None,
    limit: int = 100_000,
) -> int:
    """Delete stored rows that no longer pass today's filters. Returns how many were removed.

    Every row is re-validated (the never-list and shared names grow over time); VirusTotal IPs are
    also checked against the shared-infrastructure networks. ThreatFox rows are never dropped for
    their network.
    """
    async with factory() as session:
        rows = (
            await session.execute(
                text("SELECT DISTINCT kind, address, source FROM indicator_contacts LIMIT :k"),
                {"k": limit},
            )
        ).all()
    bad: list[tuple[str, str, str]] = []
    for r in rows:
        accepted = accept_address(r.address, settings)
        shared = (
            r.source == "virustotal"
            and r.kind == "ip"
            and is_shared_ip is not None
            and is_shared_ip(r.address)
        )
        if accepted is None or accepted[1] != r.address or shared:
            bad.append((r.kind, r.address, r.source))
    removed = 0
    for start in range(0, len(bad), 1000):
        chunk = bad[start : start + 1000]
        async with factory() as session, session.begin():
            result = await session.execute(
                text(
                    "DELETE FROM indicator_contacts WHERE (kind, address, source) IN "
                    "(SELECT * FROM unnest(CAST(:k AS text[]), CAST(:a AS text[]), "
                    "CAST(:s AS text[])))"
                ),
                {
                    "k": [b[0] for b in chunk],
                    "a": [b[1] for b in chunk],
                    "s": [b[2] for b in chunk],
                },
            )
            removed += int(getattr(result, "rowcount", 0) or 0)
    return removed
