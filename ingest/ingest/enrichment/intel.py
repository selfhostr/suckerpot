"""Threat-intelligence lookups for indicators (abuse.ch URLhaus and ThreatFox, VirusTotal).

Passive and read-only. For every indicator this sends the indicator value to a fixed intel API
and reads back "known or not", a malware family and a reference link. It never contacts the
indicator itself (no fetch, no DNS, no connection to the host), never follows a redirect, never
reads more than ``MAX_BODY`` bytes and sends nothing else: no session, no source address, no
sensor name, no other event data.

Like the reputation worker it runs outside the event path, spends one unit of a persisted daily
quota per request (``abusech`` counts URLhaus and ThreatFox together, they share one key), caches
every answer for 24 hours (negative answers too) in ``indicator_intel``, backs off on rate
limits and stops using a key the provider rejects.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.sample_kinds import is_benign_web_hash

from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate, make_client
from ingest.enrichment import contacts as contacts_mod
from ingest.enrichment.config import EnrichmentSettings
from ingest.enrichment.geo import GeoResolver
from ingest.enrichment.reputation import RATE_LIMIT_PAUSE_S, ProviderError, reserve_quota
from ingest.enrichment.textutil import clean as clean  # re-exported for the tests
from ingest.enrichment.textutil import parse_when as parse_when
from ingest.indicators import IndicatorSettings, normalize_host, normalize_url
from ingest.jsondepth import exceeds_depth

log = logging.getLogger(__name__)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/files/"
ALLOWED_HOSTS = frozenset({"urlhaus-api.abuse.ch", "threatfox-api.abuse.ch", "www.virustotal.com"})
# Links shown to the owner are built here, never taken from an answer.
URLHAUS_LINK_PREFIX = "https://urlhaus.abuse.ch/"
THREATFOX_LINK = "https://threatfox.abuse.ch/ioc/{id}/"
VIRUSTOTAL_LINK = "https://www.virustotal.com/gui/file/{h}"

MAX_BODY = 256 * 1024
HTTP_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
PER_CYCLE = 5
MIN_GAP_S = {"abusech": 0.5, "virustotal": 16.0}  # VirusTotal's free tier allows 4 requests/min
SOURCE_PROVIDER = {"urlhaus": "abusech", "threatfox": "abusech", "virustotal": "virustotal"}
TEST_HOST = "example.com"  # fixed, harmless value for "Test key"
TEST_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # empty file
MAX_TAGS = 8
_IOC_MATCH_LIMIT = 25
_LOOKUP_SETTINGS = IndicatorSettings()  # strict: documentation and reserved names are skipped
# Quota policy: one source address must not be able to spend the day's quota.
RESERVED_FOR_SHARED = 0.3  # share of each quota only multi-source indicators may use
PER_SOURCE_PER_DAY = 20  # lookups per day for indicators seen from a single address
NEGATIVE_TTL_SINGLE = "7 days"  # an unknown, single-source indicator is not asked about again
MARK_INTERVAL_S = 600.0
MARK_LIMIT = 5000


@dataclass(frozen=True, slots=True)
class Candidate:
    id: int
    type: str
    value: str
    missing: tuple[str, ...]  # sources without a fresh answer
    ips: int = 0  # distinct source addresses that used it


@dataclass(frozen=True, slots=True)
class IntelResult:
    source: str  # urlhaus | threatfox | virustotal
    known: bool
    family: str | None = None
    threat_type: str | None = None
    tags: tuple[str, ...] = ()
    first_seen_ext: datetime | None = None
    reference: str | None = None
    # URLhaus only (M27): "online" | "offline" | "unknown" and when it was last seen online.
    url_status: str | None = None
    last_online: datetime | None = None


@dataclass(slots=True)
class _State:
    paused_until: dict[str, float] = field(default_factory=dict)
    disabled: dict[str, str] = field(default_factory=dict)
    retry_after: dict[tuple[str, int], float] = field(default_factory=dict)
    last_call: dict[str, float] = field(default_factory=dict)
    last_error: dict[str, str] = field(default_factory=dict)
    test_result: dict[str, dict[str, Any]] = field(default_factory=dict)


def clean_tags(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    tags = (clean(v, 32) for v in value[: MAX_TAGS * 2])
    return tuple(dict.fromkeys(t.lower() for t in tags if t))[:MAX_TAGS]


def eligible(kind: str, value: str, settings: IndicatorSettings = _LOOKUP_SETTINGS) -> bool:
    """True for values worth asking an intel API about (public hosts, URLs, valid hashes).

    ``settings`` carries the owner's ignore list; documentation values are always refused here,
    whatever ``INDICATORS_KEEP_DOCUMENTATION`` says.
    """
    if kind == "hash":
        return len(value) in (32, 40, 64) and set(value) <= set("0123456789abcdef")
    strict = replace(settings, keep_documentation=False)
    if kind == "url":
        return normalize_url(value, strict) is not None
    return normalize_host(value, strict) is not None


def sources_for(kind: str, value: str) -> tuple[str, ...]:
    """The intel sources that can answer about an indicator of this kind."""
    if kind == "hash":
        sha1 = len(value) == 40
        return ("threatfox", "virustotal") if sha1 else ("urlhaus", "threatfox", "virustotal")
    return ("urlhaus", "threatfox")


def _host_of_ioc(ioc: str) -> str:
    """Host part of a ThreatFox IOC (``ip:port``, domain or URL)."""
    host = ioc.split("://", 1)[-1].split("/", 1)[0].lower()
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


class IntelWorker:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: EnrichmentSettings,
        client: httpx.AsyncClient | None = None,
        indicator_settings: IndicatorSettings | None = None,
        resolver: GeoResolver | None = None,
        gate: EgressGate | None = None,
    ) -> None:
        self.factory = factory
        self._gate = gate or get_gate()
        self.resolver = resolver  # the local ASN database; None: no network filter
        self._shared_asns = contacts_mod.shared_asns()
        self._contacts_cleaned = False
        self.s = settings
        self.ind = indicator_settings or IndicatorSettings.from_env()
        self._last_mark: float | None = None  # None: mark on the first cycle
        # follow_redirects is off: a redirect from an intel API is an error, never a hop.
        self.client = client or make_client(HTTP_TIMEOUT, gate=self._gate)
        self.state = _State()

    def apply_settings(self, settings: EnrichmentSettings, changed: set[str]) -> None:
        self.s = settings
        st = self.state
        for provider in changed & {"abusech", "virustotal"}:
            st.disabled.pop(provider, None)
            st.paused_until.pop(provider, None)
            st.last_error.pop(provider, None)
            st.test_result.pop(provider, None)
            for pair in [k for k in st.retry_after if k[0].split(":")[0] == provider]:
                del st.retry_after[pair]

    def _key(self, provider: str) -> str:
        return self.s.abusech_auth_key if provider == "abusech" else self.s.virustotal_api_key

    def quota(self, provider: str) -> int:
        if provider == "abusech":
            return self.s.abusech_daily_quota
        return self.s.virustotal_daily_quota

    def enabled(self, provider: str) -> bool:
        return (
            bool(self._key(provider))
            and self.quota(provider) > 0
            and provider not in self.state.disabled
        )

    def _paused(self, provider: str) -> bool:
        return time.monotonic() < self.state.paused_until.get(provider, 0.0)

    async def _request(
        self,
        provider: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        data: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        """One request to a fixed host. Returns ``(status, parsed JSON or None)``."""
        if urlsplit(url).hostname not in ALLOWED_HOSTS:  # defence in depth: never a free host
            raise ProviderError("error", "host not allowed")
        gap = MIN_GAP_S.get(provider, 0.0) - (
            time.monotonic() - self.state.last_call.get(provider, -math.inf)
        )
        if gap > 0:
            await asyncio.sleep(gap)
        self.state.last_call[provider] = time.monotonic()
        try:
            async with self.client.stream(
                method,
                url,
                # identity: the byte cap then counts what really comes over the wire.
                headers={**headers, "Accept": "application/json", "Accept-Encoding": "identity"},
                data=data,
                json=body,
                follow_redirects=False,
            ) as resp:
                status = resp.status_code
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY:
                        raise ProviderError("error", "body too large")
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise ProviderError("error", f"http error {type(exc).__name__}") from None
        if status == 429:
            raise ProviderError("rate_limited")
        if status in (401, 403):
            raise ProviderError("auth")
        if 300 <= status < 400:
            raise ProviderError("error", f"redirect {status}")
        if status == 404:
            return status, None
        if status != 200:
            raise ProviderError("error", f"status {status}")
        raw = b"".join(chunks)
        if exceeds_depth(raw):
            raise ProviderError("error", "json too deep")
        try:
            return status, json.loads(raw)
        except ValueError, RecursionError:
            raise ProviderError("error", "bad json") from None

    def _abusech_headers(self) -> dict[str, str]:
        return {"Auth-Key": self.s.abusech_auth_key}

    @staticmethod
    def _check_status(payload: Any) -> str:
        if not isinstance(payload, dict):
            raise ProviderError("error")
        status = payload.get("query_status")
        if not isinstance(status, str):
            raise ProviderError("error")
        if "auth" in status or status in {"unauthorized", "forbidden"}:
            raise ProviderError("auth")
        return status

    async def urlhaus(self, kind: str, value: str) -> IntelResult:
        if kind == "url":
            endpoint, form = "url/", {"url": value}
        elif kind == "hash":
            endpoint = "payload/"
            form = {("md5_hash" if len(value) == 32 else "sha256_hash"): value}
        else:
            endpoint, form = "host/", {"host": value}
        _, payload = await self._request(
            "abusech", "POST", URLHAUS_API + endpoint, headers=self._abusech_headers(), data=form
        )
        status = self._check_status(payload)
        if status in {"no_results", "invalid_url", "invalid_host", "invalid_hash"}:
            return IntelResult("urlhaus", False)
        if status != "ok":
            raise ProviderError("error")
        ref = payload.get("urlhaus_reference")
        reference = (
            ref[:256] if isinstance(ref, str) and ref.startswith(URLHAUS_LINK_PREFIX) else None
        )
        family: str | None = None
        tags: tuple[str, ...] = ()
        threat = clean(payload.get("threat"), 64)
        first = parse_when(payload.get("date_added") or payload.get("firstseen"))
        if kind == "hash":
            family = clean(payload.get("signature"), 64)
            threat = threat or "payload"
            tags = clean_tags([payload.get("file_type")])
        else:
            for item in (payload.get("payloads") or [])[:10]:
                if isinstance(item, dict) and (family := clean(item.get("signature"), 64)):
                    break
            tags = clean_tags(payload.get("tags"))
            if kind != "url":  # host answer: tags live on the listed URLs
                collected: list[str] = []
                for item in (payload.get("urls") or [])[:25]:
                    if isinstance(item, dict) and isinstance(item.get("tags"), list):
                        collected.extend(t for t in item["tags"] if isinstance(t, str))
                tags = clean_tags(collected)
                threat = threat or "malware_download"
        url_status: str | None = None
        last_online: datetime | None = None
        if kind == "url":
            raw_status = payload.get("url_status")
            url_status = raw_status if raw_status in ("online", "offline") else "unknown"
            last_online = parse_when(payload.get("last_online"))
        elif kind != "hash":  # host answer: online when any listed URL is
            listed = [
                i.get("url_status")
                for i in (payload.get("urls") or [])[:100]
                if isinstance(i, dict)
            ]
            url_status = "online" if "online" in listed else "offline" if listed else "unknown"
        return IntelResult(
            "urlhaus", True, family, threat, tags, first, reference, url_status, last_online
        )

    async def threatfox(self, kind: str, value: str) -> IntelResult:
        if kind == "hash":
            query: dict[str, Any] = {"query": "search_hash", "hash": value}
        else:
            query = {"query": "search_ioc", "search_term": value, "exact_match": kind == "url"}
        _, payload = await self._request(
            "abusech", "POST", THREATFOX_API, headers=self._abusech_headers(), body=query
        )
        status = self._check_status(payload)
        if status in {"no_result", "no_results", "illegal_search_term", "illegal_hash"}:
            return IntelResult("threatfox", False)
        if status != "ok":
            raise ProviderError("error")
        for entry in (payload.get("data") or [])[:_IOC_MATCH_LIMIT]:
            if not isinstance(entry, dict):
                continue
            ioc = entry.get("ioc")
            if not isinstance(ioc, str):
                continue
            if kind in {"domain", "ip"} and _host_of_ioc(ioc) != value:
                continue  # a substring search also returns unrelated IOCs
            if kind == "url" and ioc.lower().rstrip("/") != value.lower().rstrip("/"):
                continue
            if kind == "hash" and ioc.lower() != value:
                continue
            ident = str(entry.get("id", ""))
            return IntelResult(
                "threatfox",
                True,
                clean(entry.get("malware_printable"), 64) or clean(entry.get("malware"), 64),
                clean(entry.get("threat_type"), 64),
                clean_tags(entry.get("tags")),
                parse_when(entry.get("first_seen_utc") or entry.get("first_seen")),
                THREATFOX_LINK.format(id=ident) if ident.isdigit() and len(ident) <= 12 else None,
            )
        return IntelResult("threatfox", False)

    async def virustotal(self, value: str) -> IntelResult:
        if not (len(value) in (32, 40, 64) and set(value) <= set("0123456789abcdef")):
            raise ProviderError("error")
        status, payload = await self._request(
            "virustotal",
            "GET",
            VIRUSTOTAL_API + value,
            headers={"x-apikey": self.s.virustotal_api_key},
        )
        if status == 404:
            return IntelResult("virustotal", False)
        try:
            attrs = payload["data"]["attributes"]
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        except KeyError, TypeError, ValueError, AttributeError:
            raise ProviderError("error") from None
        cls = attrs.get("popular_threat_classification")
        family = threat = None
        if isinstance(cls, dict):
            family = clean(cls.get("suggested_threat_label"), 64)
            cats = cls.get("popular_threat_category")
            if isinstance(cats, list) and cats and isinstance(cats[0], dict):
                threat = clean(cats[0].get("value"), 64)
        return IntelResult(
            "virustotal",
            malicious > 0,
            family,
            threat,
            clean_tags(attrs.get("tags")),
            parse_when(attrs.get("first_submission_date")),
            VIRUSTOTAL_LINK.format(h=value),
        )

    async def lookup(self, source: str, kind: str, value: str) -> IntelResult:
        if source == "urlhaus":
            return await self.urlhaus(kind, value)
        if source == "threatfox":
            return await self.threatfox(kind, value)
        return await self.virustotal(value)

    async def virustotal_contacts(self, sha: str) -> list[contacts_mod.Contact]:
        """Addresses and domains VirusTotal's sandboxes saw the file contact (two requests).

        Uses the descriptor-only relationship endpoints (``{type, id}`` items), whose answers are
        small; the full-object endpoints carry whole analysis results and exceed ``MAX_BODY``.
        """
        if not (len(sha) in (32, 40, 64) and set(sha) <= set("0123456789abcdef")):
            raise ProviderError("error")
        answers: list[Any] = []
        for relation in ("contacted_ips", "contacted_domains"):
            if relation == "contacted_domains":
                if answers[0] is None:  # 404 on the addresses: VirusTotal does not know the file
                    return []
                if not await self._reserve_contacts("virustotal"):
                    raise ProviderError("quota")
            _, payload = await self._request(
                "virustotal",
                "GET",
                f"{VIRUSTOTAL_API}{sha}/relationships/{relation}?limit={contacts_mod.VT_PAGE}",
                headers={"x-apikey": self.s.virustotal_api_key},
            )
            answers.append(payload)
        return contacts_mod.virustotal_contacts(
            answers[0], answers[1], self.ind, VIRUSTOTAL_LINK.format(h=sha), self.is_shared_ip
        )

    def is_shared_ip(self, ip: str) -> bool:
        """True when the local ASN database puts the address in big shared infrastructure."""
        if self.resolver is None:
            return False
        return self.resolver.lookup(ip).asn in self._shared_asns

    async def threatfox_contacts(self, sha: str) -> list[contacts_mod.Contact]:
        """``botnet_cc`` IOCs ThreatFox links to the hash (one request)."""
        if len(sha) not in (32, 64):  # ThreatFox searches MD5 and SHA-256 only
            return []
        _, payload = await self._request(
            "abusech",
            "POST",
            THREATFOX_API,
            headers=self._abusech_headers(),
            body={"query": "search_hash", "hash": sha},
        )
        status = self._check_status(payload)
        if status in {"no_result", "no_results", "illegal_search_term", "illegal_hash"}:
            return []
        if status != "ok":
            raise ProviderError("error")
        return contacts_mod.threatfox_contacts(payload, self.ind)

    def _contacts_limit(self, provider: str) -> int:
        """Contact lookups have their own persisted counter (``<provider>:contacts``) and share."""
        return int(self.quota(provider) * contacts_mod.CONTACTS_QUOTA_SHARE)

    async def _reserve_contacts(self, provider: str) -> bool:
        """One unit from the contact share (30 %) and from the provider's real daily quota."""
        self._gate.require_open()  # EgressClosed before any quota is spent
        return await reserve_quota(
            self.factory, f"{provider}:contacts", self._contacts_limit(provider)
        ) and await reserve_quota(self.factory, provider, self.quota(provider))

    async def run_contacts(self) -> int:
        """Look up contacted addresses of known hashes. Returns how many requests were made."""
        st = self.state
        made = 0
        if not self._contacts_cleaned:  # once per start: rows stored under older, looser filters
            self._contacts_cleaned = True
            try:
                removed = await contacts_mod.cleanup_stored(
                    self.factory, self.ind, self.is_shared_ip
                )
                if removed:
                    log.info("removed %d stored contact rows that fail the filters", removed)
            except Exception:
                log.warning("contact clean-up failed", exc_info=True)
                self._contacts_cleaned = False
        providers = {"virustotal": "virustotal", "threatfox": "abusech"}
        sources = tuple(
            s
            for s in contacts_mod.CONTACT_SOURCES
            if self.enabled(providers[s]) and not self._paused(providers[s])
        )
        for cand in await contacts_mod.candidates(self.factory, sources):
            if not eligible("hash", cand.value, self.ind):
                continue
            for source in cand.missing:
                provider = providers[source]
                if not self.enabled(provider) or self._paused(provider):
                    continue
                key = (f"{provider}:contacts", cand.id)
                if time.monotonic() < st.retry_after.get(key, 0.0):
                    continue
                if not await self._reserve_contacts(provider):
                    log.info("%s quota share for contact lookups exhausted", provider)
                    break
                made += 1
                try:
                    found = (
                        await self.virustotal_contacts(cand.value)
                        if source == "virustotal"
                        else await self.threatfox_contacts(cand.value)
                    )
                    await contacts_mod.store(self.factory, cand.id, source, found)
                    st.last_error.pop(provider, None)
                except ProviderError as exc:
                    st.last_error[provider] = exc.kind
                    st.retry_after[key] = time.monotonic() + 900
                    if exc.kind == "auth":
                        st.disabled[provider] = "auth"
                        log.error("%s rejected the API key: lookups disabled", provider)
                    elif exc.kind == "rate_limited":
                        st.paused_until[provider] = time.monotonic() + RATE_LIMIT_PAUSE_S
                        log.warning("%s rate limited: paused for an hour", provider)
                    else:
                        log.warning(
                            "%s contact lookup failed: %s (%s)",
                            provider,
                            exc.kind,
                            exc.reason or "no detail",
                        )
                    break
        return made

    async def run_key_test(self, provider: str) -> dict[str, Any]:
        """One real, quota-counted request with a fixed harmless value. Never raises."""
        error: str | None = None
        if not self._key(provider):
            error = "no_key"
        elif not gate_open(self._gate):
            error = "egress_closed"  # nothing is sent and no quota is spent
        elif not await reserve_quota(self.factory, provider, self.quota(provider)):
            error = "quota_exhausted"
        else:
            try:
                if provider == "abusech":
                    await self.urlhaus("domain", TEST_HOST)
                else:
                    await self.virustotal(TEST_SHA256)
                self.state.disabled.pop(provider, None)
                self.state.last_error.pop(provider, None)
            except EgressClosed:
                error = "egress_closed"
            except ProviderError as exc:
                error = exc.kind
                if exc.kind == "auth":
                    self.state.disabled[provider] = "auth"
        result = {
            "ok": error is None,
            "error": error,
            "checked_at": datetime.now(UTC).isoformat(),
        }
        self.state.test_result[provider] = result
        return result

    async def candidates(self, provider: str, limit: int = PER_CYCLE) -> list[Candidate]:
        """Indicators without a fresh answer from ``provider``, best evidence first.

        Ranked by distinct source addresses, then payload-source role, then sightings. Hashes need
        a sensor-computed digest or two distinct sources; URLs wait until their host is known to
        be listed (a host lookup covers its URLs); one address cannot spend more than
        ``PER_SOURCE_PER_DAY`` lookups a day; unknown single-source answers last a week. The hash
        of a plain web page the collector kept is never looked up.
        """
        fresh = (
            "n.checked_at > now() - CASE WHEN n.known OR l.ips >= 2 "
            f"THEN interval '24 hours' ELSE interval '{NEGATIVE_TTL_SINGLE}' END"
        )
        if provider == "virustotal":
            where_type = "AND i.type = 'hash'"
            sources: tuple[str, ...] = ("virustotal",)
            having = f"count(*) FILTER (WHERE n.source = 'virustotal' AND {fresh}) = 0"
        else:
            where_type = ""
            sources = ("urlhaus", "threatfox")
            having = f"count(*) FILTER (WHERE n.source IN ('urlhaus', 'threatfox') AND {fresh}) < 2"
        stmt = text(
            f"""
            SELECT i.id, i.type, i.value, l.ips, host(l.one) AS one, u.used,
                   COALESCE(array_agg(n.source) FILTER (WHERE {fresh}), '{{}}') AS fresh
            FROM indicators i
            CROSS JOIN LATERAL (
                SELECT count(DISTINCT s.src_ip) AS ips, min(s.src_ip) AS one
                FROM indicator_sessions s WHERE s.indicator_id = i.id
            ) l
            CROSS JOIN LATERAL (
                SELECT CASE WHEN l.ips = 1 THEN (
                    SELECT count(DISTINCT x.indicator_id)
                    FROM indicator_sessions s2
                    JOIN indicator_intel x ON x.indicator_id = s2.indicator_id
                    WHERE s2.src_ip = l.one AND x.checked_at > date_trunc('day', now())
                      AND NOT ('not-checked' = ANY (x.tags))) ELSE 0 END AS used
            ) u
            LEFT JOIN indicator_intel n ON n.indicator_id = i.id
            WHERE i.last_seen > now() - interval '7 days' AND NOT i.demo {where_type}
              AND (i.type <> 'hash' OR i.trusted OR l.ips >= 2)
              AND (i.type <> 'hash' OR NOT {is_benign_web_hash("i.value")})
              AND (i.type <> 'url' OR EXISTS (
                    SELECT 1 FROM indicators h
                    JOIN indicator_intel hn ON hn.indicator_id = h.id
                         AND hn.source = 'urlhaus' AND hn.known
                    WHERE h.type IN ('domain', 'ip') AND h.value = i.host))
              AND u.used < :per_ip
            GROUP BY i.id, l.ips, l.one, u.used
            HAVING {having}
            ORDER BY l.ips DESC, (i.role = 'download_host') DESC, i.sightings DESC, i.id
            LIMIT :k
            """  # noqa: S608 - fixed fragments chosen above, no user input
        )
        async with self.factory() as session:
            rows = (await session.execute(stmt, {"k": limit, "per_ip": PER_SOURCE_PER_DAY})).all()
        out: list[Candidate] = []
        batch: dict[str, int] = {}  # single-source lookups already picked in this batch
        for r in rows:
            if r.ips == 1:
                if r.used + batch.get(r.one, 0) >= PER_SOURCE_PER_DAY:
                    continue
                batch[r.one] = batch.get(r.one, 0) + 1
            wanted = [
                s for s in sources if s in sources_for(r.type, r.value) and s not in (r.fresh or [])
            ]
            if wanted:
                out.append(Candidate(r.id, r.type, r.value, tuple(wanted), r.ips))
        return out

    async def mark_unlookable(self) -> int:
        """Mark stored indicators that must never be sent anywhere as "not checked".

        Demo indicators and values that match the owner's ignore list or the private, reserved
        and documentation rules (including ones added to the ignore list after they were stored).
        """
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT i.id, i.type, i.value, i.demo FROM indicators i
                        WHERE i.last_seen > now() - interval '7 days'
                          AND NOT EXISTS (SELECT 1 FROM indicator_intel n
                                          WHERE n.indicator_id = i.id
                                            AND 'not-checked' = ANY (n.tags))
                        ORDER BY i.id LIMIT :k
                        """
                    ),
                    {"k": MARK_LIMIT},
                )
            ).all()
        marked = 0
        for r in rows:
            if r.demo or not eligible(r.type, r.value, self.ind):
                await self._store_skipped(
                    Candidate(r.id, r.type, r.value, sources_for(r.type, r.value))
                )
                marked += 1
        return marked

    async def _store(self, indicator_id: int, result: IntelResult) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO indicator_intel (indicator_id, source, known, family, threat_type,
                                                 tags, first_seen_ext, reference, checked_at)
                    VALUES (:i, :s, :k, :f, :t, :tags, :fs, :r, now())
                    ON CONFLICT (indicator_id, source) DO UPDATE SET known = :k, family = :f,
                        threat_type = :t, tags = :tags, first_seen_ext = :fs, reference = :r,
                        checked_at = now()
                    """
                ),
                {
                    "i": indicator_id,
                    "s": result.source,
                    "k": result.known,
                    "f": result.family,
                    "t": result.threat_type,
                    "tags": list(result.tags),
                    "fs": result.first_seen_ext,
                    "r": result.reference,
                },
            )

    async def _store_skipped(self, cand: Candidate) -> None:
        """Reserved or private values are never sent anywhere; cache that for a day."""
        for source in cand.missing:
            await self._store(cand.id, IntelResult(source, False, tags=("not-checked",)))

    async def run_once(self) -> int:
        """One cycle over both providers. Returns how many requests were made."""
        made = 0
        st = self.state
        now = time.monotonic()
        if not gate_open(self._gate):
            return 0
        st.retry_after = {k: v for k, v in st.retry_after.items() if v > now}
        if self._last_mark is None or now - self._last_mark >= MARK_INTERVAL_S:
            self._last_mark = now
            await self.mark_unlookable()
        for provider in ("abusech", "virustotal"):
            if not self.enabled(provider) or self._paused(provider):
                continue
            quota = self.quota(provider)
            for cand in await self.candidates(provider):
                if time.monotonic() < st.retry_after.get((provider, cand.id), 0.0):
                    continue
                if not eligible(cand.type, cand.value, self.ind):
                    await self._store_skipped(cand)
                    continue
                stop = False
                for source in cand.missing:
                    # A share of the quota is kept for indicators several addresses used.
                    limit = quota if cand.ips >= 2 else int(quota * (1 - RESERVED_FOR_SHARED))
                    self._gate.require_open()  # EgressClosed before any quota is spent
                    if not await reserve_quota(self.factory, provider, limit):
                        log.info("%s daily quota exhausted", provider)
                        if cand.ips >= 2:
                            st.paused_until[provider] = time.monotonic() + 600
                            stop = True
                        break
                    made += 1
                    try:
                        await self._store(cand.id, await self.lookup(source, cand.type, cand.value))
                        st.last_error.pop(provider, None)
                    except ProviderError as exc:
                        st.last_error[provider] = exc.kind
                        st.retry_after[(provider, cand.id)] = time.monotonic() + 900
                        if exc.kind == "auth":
                            st.disabled[provider] = "auth"
                            log.error("%s rejected the API key: lookups disabled", provider)
                            stop = True
                        elif exc.kind == "rate_limited":
                            st.paused_until[provider] = time.monotonic() + RATE_LIMIT_PAUSE_S
                            log.warning("%s rate limited: paused for an hour", provider)
                            stop = True
                        else:
                            log.warning("%s lookup failed", provider)
                        break
                if stop:
                    break
        return made + await self.run_contacts()

    async def status(self) -> dict[str, Any]:
        st = self.state
        return {
            provider: {
                "configured": bool(self._key(provider)),
                "daily_quota": self.quota(provider),
                "disabled": st.disabled.get(provider),
                "paused": self._paused(provider),
                "last_error": st.last_error.get(provider),
                "test": st.test_result.get(provider),
            }
            for provider in ("abusech", "virustotal")
        }

    async def run(self, publish: Any = None) -> None:
        while True:
            try:
                try:
                    await self.run_once()
                except EgressClosed:
                    pass  # retryable: nothing was sent, no quota spent, nothing cached
                if publish is not None:
                    await publish(await self.status())
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("intel cycle failed", exc_info=True)
            await asyncio.sleep(self.s.intel_interval_s)

    async def aclose(self) -> None:
        await self.client.aclose()
