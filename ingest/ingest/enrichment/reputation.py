"""IP reputation worker (AbuseIPDB check + GreyNoise Community), fully asynchronous.

It never touches the ingest hot path: a background loop spends one unit of a persisted daily
quota per lookup, stores the answer in ``ip_reputation`` and updates the sessions of that
address. Only read endpoints are used: nothing is ever reported to AbuseIPDB.

Who is looked up. Addresses a provider has never answered for come first (busiest first), then
addresses whose answer is older than ``REPUTATION_RECHECK_DAYS`` (busiest first). A recent
answer is never asked for again. An answer never expires: the row keeps serving lookups (the
writer reads it for every new event) until a newer one replaces it, and the maintenance job only
prunes rows nobody refreshed for the whole retention window.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

import httpx
from sqlalchemy import ARRAY, Text, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate, make_client
from ingest.enrichment.config import EnrichmentSettings
from ingest.enrichment.geo import is_routable

log = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"
DEFAULT_RECHECK_DAYS = 7
PER_CYCLE = 5
RATE_LIMIT_PAUSE_S = 3600.0
HTTP_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
TEST_IP = "8.8.8.8"  # a well-known public resolver: any routable address would do


class ProviderError(Exception):
    def __init__(self, kind: str, reason: str = "") -> None:
        super().__init__(kind)
        self.kind = kind  # rate_limited | auth | error
        self.reason = reason  # short fixed text for logs, never part of a body


@dataclass(frozen=True, slots=True)
class AbuseResult:
    score: int
    reports: int
    last_reported_at: datetime | None = None  # AbuseIPDB's lastReportedAt (M27 reads it)


@dataclass(frozen=True, slots=True)
class GreyNoiseResult:
    noise: bool
    riot: bool
    classification: str | None
    name: str | None


def _quota_day() -> date:
    return datetime.now(UTC).date()


async def reserve_quota(
    factory: async_sessionmaker[AsyncSession], provider: str, limit: int
) -> bool:
    """Atomically spend one unit of today's quota. False once the quota is exhausted."""
    stmt = text(
        """
        INSERT INTO enrichment_quota (provider, day, used) VALUES (:p, :d, 1)
        ON CONFLICT (provider, day) DO UPDATE SET used = enrichment_quota.used + 1
        WHERE enrichment_quota.used < :q
        RETURNING used
        """
    )
    async with factory() as session, session.begin():
        row = await session.execute(stmt, {"p": provider, "d": _quota_day(), "q": limit})
        return row.first() is not None


async def mark_quota_spent(
    factory: async_sessionmaker[AsyncSession], provider: str, limit: int
) -> None:
    """Record that today's allowance is gone: the counter reads as full, restarts included."""
    stmt = text(
        """
        INSERT INTO enrichment_quota (provider, day, used) VALUES (:p, :d, :q)
        ON CONFLICT (provider, day) DO UPDATE SET used = GREATEST(enrichment_quota.used, :q)
        """
    )
    async with factory() as session, session.begin():
        await session.execute(stmt, {"p": provider, "d": _quota_day(), "q": limit})


async def candidate_ips(
    factory: async_sessionmaker[AsyncSession],
    provider: str,
    min_events: int,
    limit: int = PER_CYCLE,
    recheck_days: int = DEFAULT_RECHECK_DAYS,
    exclude: Sequence[str] = (),
) -> list[str]:
    """Recent source IPs to look up with ``provider``: never answered first, then stale.

    "Never answered" means no row, or a row without this provider's answer (it may hold the
    other provider's). "Stale" means answered more than ``recheck_days`` ago. Each group is
    ordered busiest first. A recent answer excludes the address, so the quota is spent on
    addresses we know nothing about before it is spent on refreshing known ones. ``exclude``
    holds addresses to skip for now (unroutable or failing): they must not fill the limit.
    """
    column = "abuse_checked_at" if provider == "abuseipdb" else "gn_checked_at"
    stmt = text(
        f"""
        SELECT host(s.src_ip) AS ip, sum(s.event_count) AS activity
        FROM sessions s LEFT JOIN ip_reputation r ON r.ip = s.src_ip
        WHERE s.last_event_at > now() - interval '7 days'
          AND (r.{column} IS NULL OR r.{column} < now() - make_interval(days => :d))
          AND NOT (host(s.src_ip) = ANY(:ex))
        GROUP BY s.src_ip, r.{column}
        HAVING bool_or(s.login_success) OR sum(s.commands) > 0 OR sum(s.downloads) > 0
            OR sum(s.event_count) >= :n
        ORDER BY (r.{column} IS NOT NULL), sum(s.event_count) DESC, s.src_ip
        LIMIT :k
        """  # noqa: S608 - column name comes from a fixed two-value choice above
    ).bindparams(bindparam("ex", type_=ARRAY(Text)))
    async with factory() as session:
        rows = await session.execute(
            stmt, {"n": min_events, "k": limit, "d": recheck_days, "ex": list(exclude)}
        )
        return [r.ip for r in rows]


class ReputationWorker:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: EnrichmentSettings,
        client: httpx.AsyncClient | None = None,
        gate: EgressGate | None = None,
    ) -> None:
        self.factory = factory
        self.s = settings
        self._gate = gate or get_gate()
        self.client = client or make_client(HTTP_TIMEOUT, gate=self._gate)
        self._paused_until: dict[str, float] = {}
        self._spent_day: dict[str, date] = {}  # provider -> UTC day its real allowance ran out
        self._disabled: dict[str, str] = {}
        self._retry_after: dict[tuple[str, str], float] = {}
        self.last_error: dict[str, str] = {}
        self.test_result: dict[str, dict[str, Any]] = {}

    def apply_settings(self, settings: EnrichmentSettings, changed: set[str]) -> None:
        """Hot-swap credentials. A changed key gets a clean slate (no stale auth failure)."""
        self.s = settings
        for provider in changed:
            self._disabled.pop(provider, None)
            self._paused_until.pop(provider, None)
            self._spent_day.pop(provider, None)
            self.last_error.pop(provider, None)
            self.test_result.pop(provider, None)
            for pair in [k for k in self._retry_after if k[0] == provider]:
                del self._retry_after[pair]

    def _key(self, provider: str) -> str:
        return self.s.abuseipdb_api_key if provider == "abuseipdb" else self.s.greynoise_api_key

    async def run_key_test(self, provider: str) -> dict[str, Any]:
        """One real, quota-counted lookup to prove the key works. Never raises."""
        error: str | None = None
        if not self._key(provider):
            error = "no_key"
        elif not gate_open(self._gate):
            error = "egress_closed"  # nothing is sent and no quota is spent
        elif not await reserve_quota(self.factory, provider, self.quota(provider)):
            error = "quota_exhausted"
        else:
            try:
                if provider == "abuseipdb":
                    await self.check_abuseipdb(TEST_IP)
                else:
                    await self.check_greynoise(TEST_IP)
                self._disabled.pop(provider, None)
                self.last_error.pop(provider, None)
            except EgressClosed:
                error = "egress_closed"
            except ProviderError as exc:
                error = exc.kind
                if exc.kind == "auth":
                    self._disabled[provider] = "auth"
        result = {
            "ok": error is None,
            "error": error,
            "checked_at": datetime.now(UTC).isoformat(),
        }
        self.test_result[provider] = result
        return result

    # ---- provider calls (read-only endpoints) ---------------------------------------------
    async def check_abuseipdb(self, ip: str) -> AbuseResult:
        try:
            resp = await self.client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": self.s.abuseipdb_api_key, "Accept": "application/json"},
            )
        except httpx.HTTPError:
            raise ProviderError("error") from None
        _raise_for_status(resp)
        try:
            data = resp.json()["data"]
            return AbuseResult(
                int(data["abuseConfidenceScore"]),
                int(data.get("totalReports", 0)),
                _parse_when(data.get("lastReportedAt")),
            )
        except ValueError, KeyError, TypeError:
            raise ProviderError("error") from None

    async def check_greynoise(self, ip: str) -> GreyNoiseResult:
        try:
            resp = await self.client.get(
                GREYNOISE_URL.format(ip=ip),
                headers={"key": self.s.greynoise_api_key, "Accept": "application/json"},
            )
        except httpx.HTTPError:
            raise ProviderError("error") from None
        if resp.status_code == 404:  # never observed scanning the internet
            return GreyNoiseResult(False, False, None, None)
        _raise_for_status(resp)
        try:
            body = resp.json()
            cls = body.get("classification")
            name = body.get("name")
            return GreyNoiseResult(
                bool(body.get("noise")),
                bool(body.get("riot")),
                cls[:32] if isinstance(cls, str) else None,
                name[:128] if isinstance(name, str) else None,
            )
        except ValueError, AttributeError:
            raise ProviderError("error") from None

    # ---- persistence ----------------------------------------------------------------------
    async def _store_abuse(self, ip: str, result: AbuseResult) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO ip_reputation (ip, abuse_score, abuse_reports, abuse_checked_at)
                    VALUES (CAST(:ip AS inet), :s, :r, now())
                    ON CONFLICT (ip) DO UPDATE SET abuse_score = :s, abuse_reports = :r,
                        abuse_checked_at = now(), updated_at = now()
                    """
                ),
                {"ip": ip, "s": result.score, "r": result.reports},
            )
            await session.execute(
                text("UPDATE sessions SET abuse_score = :s WHERE src_ip = CAST(:ip AS inet)"),
                {"ip": ip, "s": result.score},
            )

    async def _store_greynoise(self, ip: str, result: GreyNoiseResult) -> None:
        tags = ["scanner"] if result.noise else []
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO ip_reputation (ip, gn_noise, gn_riot, gn_classification, gn_name,
                                               gn_checked_at)
                    VALUES (CAST(:ip AS inet), :n, :r, :c, :nm, now())
                    ON CONFLICT (ip) DO UPDATE SET gn_noise = :n, gn_riot = :r,
                        gn_classification = :c, gn_name = :nm, gn_checked_at = now(),
                        updated_at = now()
                    """
                ),
                {"ip": ip, "n": result.noise, "r": result.riot, "c": result.classification,
                 "nm": result.name},
            )  # fmt: skip
            await session.execute(
                text(
                    """
                    UPDATE sessions SET known_scanner = :n,
                        tags = ARRAY(SELECT DISTINCT unnest(tags || :t) ORDER BY 1)
                    WHERE src_ip = CAST(:ip AS inet)
                    """
                ).bindparams(bindparam("t", type_=ARRAY(Text))),
                {"ip": ip, "n": result.noise, "t": tags},
            )

    # ---- scheduling -----------------------------------------------------------------------
    def enabled(self, provider: str) -> bool:
        key = self.s.abuseipdb_api_key if provider == "abuseipdb" else self.s.greynoise_api_key
        return bool(key) and self.quota(provider) > 0 and provider not in self._disabled

    def quota(self, provider: str) -> int:
        if provider == "abuseipdb":
            return self.s.abuseipdb_daily_quota
        return self.s.greynoise_daily_quota

    def _paused(self, provider: str) -> bool:
        if self._spent_day.get(provider) == _quota_day():
            return True
        return time.monotonic() < self._paused_until.get(provider, 0.0)

    async def _stop_for_today(self, provider: str) -> None:
        """The provider said 429: its real allowance is spent, wait for the next UTC day."""
        self._spent_day[provider] = _quota_day()
        await mark_quota_spent(self.factory, provider, self.quota(provider))

    def _backed_off(self, provider: str) -> list[str]:
        """Addresses to leave out of the next candidate query (and forget the expired ones)."""
        now = time.monotonic()
        for pair in [k for k, until in self._retry_after.items() if until <= now]:
            del self._retry_after[pair]
        return [ip for (p, ip) in self._retry_after if p == provider]

    async def run_once(self) -> int:
        """One cycle over both providers. Returns how many lookups were made."""
        made = 0
        if not gate_open(self._gate):
            return 0  # retryable "not now": no lookup, no quota, no negative cache entry
        for provider in ("abuseipdb", "greynoise"):
            if not self.enabled(provider) or self._paused(provider):
                continue
            quota = self.quota(provider)
            candidates = await candidate_ips(
                self.factory,
                provider,
                self.s.reputation_min_events,
                recheck_days=self.s.reputation_recheck_days,
                exclude=self._backed_off(provider),
            )
            for ip in candidates:
                try:
                    if not is_routable(ipaddress.ip_address(ip)):
                        self._retry_after[(provider, ip)] = time.monotonic() + 86400
                        continue
                except ValueError:
                    continue
                if not gate_open(self._gate):
                    return made
                if not await reserve_quota(self.factory, provider, quota):
                    log.info("%s daily quota exhausted", provider)
                    self._paused_until[provider] = time.monotonic() + 600
                    break
                made += 1
                try:
                    if provider == "abuseipdb":
                        await self._store_abuse(ip, await self.check_abuseipdb(ip))
                    else:
                        await self._store_greynoise(ip, await self.check_greynoise(ip))
                    self.last_error.pop(provider, None)
                except EgressClosed:
                    return made  # closed between the check and the request
                except ProviderError as exc:
                    self.last_error[provider] = exc.kind
                    self._retry_after[(provider, ip)] = time.monotonic() + 900
                    if exc.kind == "auth":
                        self._disabled[provider] = "auth"
                        log.error("%s rejected the API key: lookups disabled", provider)
                        break
                    if exc.kind == "rate_limited":
                        if provider == "greynoise":
                            # The free allowance is far below the configured quota: a 429
                            # means it is gone, and asking again an hour later only fails again.
                            await self._stop_for_today(provider)
                            log.warning("%s rate limited: stopped until the next UTC day", provider)
                        else:
                            self._paused_until[provider] = time.monotonic() + RATE_LIMIT_PAUSE_S
                            log.warning("%s rate limited: paused for an hour", provider)
                        break
                    log.warning("%s lookup failed", provider)
        return made

    async def status(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for provider in ("abuseipdb", "greynoise"):
            out[provider] = {
                "configured": bool(
                    self.s.abuseipdb_api_key
                    if provider == "abuseipdb"
                    else self.s.greynoise_api_key
                ),
                "daily_quota": self.s.abuseipdb_daily_quota
                if provider == "abuseipdb"
                else self.s.greynoise_daily_quota,
                "disabled": self._disabled.get(provider),
                "paused": self._paused(provider),
                "last_error": self.last_error.get(provider),
                "test": self.test_result.get(provider),
            }
        return out

    async def run(self, publish: Any = None) -> None:
        while True:
            try:
                await self.run_once()
                if publish is not None:
                    await publish(await self.status())
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("reputation cycle failed", exc_info=True)
            await asyncio.sleep(self.s.reputation_interval_s)

    async def aclose(self) -> None:
        await self.client.aclose()


def _parse_when(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code == 200:
        return
    if resp.status_code == 429:
        raise ProviderError("rate_limited")
    if resp.status_code in (401, 403):
        raise ProviderError("auth")
    raise ProviderError("error")
