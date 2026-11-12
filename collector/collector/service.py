"""The fetch loop: indicators to fetch targets, due targets to quarantined samples.

Everything outbound goes through the egress client and its gate. ``EgressClosed`` means "not now":
no quota is spent, no attempt is recorded, the target stays as it was. A fetch failure never
touches Redis or the events pipeline: this service reads the ``indicators`` table only.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_analysis import WEB_KINDS
from suckerpot_egress import EgressClosed, EgressGate, egress_client

from collector import fetch as fx
from collector.config import CollectorSettings
from collector.fetch import Fetcher, FetchResult
from collector.recheck import Rechecker
from collector.status import beat, publish_status
from collector.store import Quarantine, StoredFile
from collector.validate import UrlRefused, normalize_url

log = logging.getLogger(__name__)

QUOTA_PROVIDER = "collector"
RETRY_DELAYS = (timedelta(minutes=15), timedelta(hours=1), timedelta(hours=6))
MAX_FETCHES = 7
SYNC_BATCH = 200
DUE_BATCH = 10
FULL_RETRY = timedelta(hours=1)

Factory = async_sessionmaker[AsyncSession]


@dataclass(frozen=True)
class Target:
    id: int
    url: str
    host: str
    attempts: int
    fetches: int
    origin: str = "local"  # M32: "network_verify" rows are fetched for the network only
    # Found inside a web page and never typed by an attacker: not fetched (see WEB_PARENT).
    web_parent: bool = False


VERIFY_ORIGIN = "network_verify"
VERIFY_DISABLED = "verify_disabled"
# `last_error` of a target that was queued from a web page (the analyzer no longer does that).
WEB_PARENT = "web_parent"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CollectorService:
    def __init__(
        self,
        settings: CollectorSettings,
        factory: Factory,
        store: Quarantine,
        gate: EgressGate,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.s = settings
        self.factory = factory
        self.store = store
        self.gate = gate
        self._clock = clock
        self._client = client
        self._sem = asyncio.Semaphore(settings.concurrency)
        self._host_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._host_last: dict[str, float] = {}
        self._inflight = 0
        self._reserved = 0
        self._claim_lock = asyncio.Lock()
        self._cursor = 0
        self._last_retention = 0.0
        self.rechecker = Rechecker(self)

    # ---- discovery ---------------------------------------------------------------------------
    async def sync_targets(self) -> int:
        """Turn new download-URL indicators into fetch targets. Returns how many were read."""
        now = self._clock()
        async with self.factory() as session, session.begin():
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT i.id, i.value FROM indicators i
                        WHERE i.type = 'url' AND i.role = 'download_host' AND NOT i.demo
                          AND i.id > :cursor
                          AND NOT EXISTS (SELECT 1 FROM fetch_targets t WHERE t.indicator_id = i.id)
                        ORDER BY i.id LIMIT :n
                        """
                    ),
                    {"cursor": self._cursor, "n": SYNC_BATCH},
                )
            ).all()
            for ind_id, raw in rows:
                self._cursor = max(self._cursor, ind_id)
                await self._insert_target(session, ind_id, raw, now)
        return len(rows)

    async def _insert_target(
        self, session: AsyncSession, ind_id: int, raw: str, now: datetime
    ) -> None:
        status, error, url, scheme, host = "pending", None, raw, "", ""
        try:
            valid = normalize_url(raw, deny_nets=self.s.deny_nets, deny_hosts=self.s.deny_hosts)
            url, scheme, host = valid.url, valid.scheme, valid.host
        except UrlRefused as exc:
            status = "unsupported" if exc.code == "unsupported" else "refused"
            error = exc.code
            url = raw[:1024]
            scheme = raw.split(":", 1)[0].lower()[:16] if ":" in raw else "unknown"
            host = raw.split("//", 1)[-1].split("/", 1)[0][:255]
        await session.execute(
            text(
                """
                INSERT INTO fetch_targets
                    (url, scheme, host, indicator_id, depth, status, last_error, first_seen,
                     next_attempt_at)
                VALUES (:url, :scheme, :host, :ind, 0, CAST(:status AS text), :error, :now,
                        CASE WHEN CAST(:status AS text) = 'pending'
                             THEN CAST(:now AS timestamptz) END)
                ON CONFLICT (url) DO UPDATE
                    SET indicator_id = COALESCE(fetch_targets.indicator_id, EXCLUDED.indicator_id),
                        origin = 'local'
                """
            ),
            {
                "url": url, "scheme": scheme, "host": host, "ind": ind_id, "status": status,
                "error": error, "now": now,
            },
        )  # fmt: skip

    async def requeue_refetches(self) -> int:
        """Fetched targets seen again since the last fetch go back in the queue (rate limited)."""
        now = self._clock()
        async with self.factory() as session, session.begin():
            result = await session.execute(
                text(
                    """
                    UPDATE fetch_targets t SET status = 'pending', next_attempt_at = :now
                    FROM indicators i
                    WHERE t.status = 'fetched' AND t.fetches < :max_fetches
                      AND i.id = t.indicator_id AND i.last_seen > t.last_attempt_at
                      AND t.last_attempt_at < :cutoff
                    """
                ),
                {
                    "now": now,
                    "max_fetches": MAX_FETCHES,
                    "cutoff": now - timedelta(hours=self.s.refetch_hours),
                },
            )
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    # ---- limits ------------------------------------------------------------------------------
    async def quarantine_used(self) -> int:
        async with self.factory() as session:
            used = await session.scalar(
                text("SELECT COALESCE(sum(size), 0) FROM samples WHERE stored")
            )
        return int(used or 0)

    async def _reserve(self) -> str | None:
        """Spend one fetch of the hourly and daily quotas. None when granted, else a reason."""
        now = self._clock()
        async with self.factory() as session, session.begin():
            hour = await session.scalar(
                text(
                    "SELECT count(*) FROM fetch_attempts "
                    "WHERE started_at > :since AND outcome <> 'refused'"
                ),
                {"since": now - timedelta(hours=1)},
            )
            if int(hour or 0) + self._inflight >= self.s.hourly_quota:
                return "hourly_quota"
            granted = await session.scalar(
                text(
                    """
                    INSERT INTO enrichment_quota (provider, day, used) VALUES (:p, :d, 1)
                    ON CONFLICT (provider, day) DO UPDATE SET used = enrichment_quota.used + 1
                    WHERE enrichment_quota.used < :cap
                    RETURNING used
                    """
                ),
                {"p": QUOTA_PROVIDER, "d": now.date(), "cap": self.s.daily_quota},
            )
        if granted is None:
            return "daily_quota"
        self._inflight += 1
        return None

    async def _refund(self, day: date) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE enrichment_quota SET used = GREATEST(used - 1, 0) "
                    "WHERE provider = :p AND day = :d"
                ),
                {"p": QUOTA_PROVIDER, "d": day},
            )

    async def _host_wait(self, host: str) -> None:
        gap = self.s.host_interval_s - (time.monotonic() - self._host_last.get(host, -1e9))
        if gap > 0:
            await asyncio.sleep(gap)

    # ---- one pass ----------------------------------------------------------------------------
    async def step(self) -> list[tuple[int, str]]:
        """One poll. Returns (target id, outcome) for every target handled."""
        beat(self.s.heartbeat_path)
        if not self.s.enabled:
            await publish_status(self.factory, "collector", {"enabled": False, "state": "disabled"})
            return []
        await self.sync_targets()
        await self.requeue_refetches()
        used = await self.quarantine_used()
        cap = self.s.quarantine_max_bytes
        detail: dict[str, Any] = {
            "enabled": True,
            "quarantine_used_bytes": used,
            "quarantine_max_bytes": cap,
            "quarantine_full": used >= cap,
        }
        try:
            self.gate.require_open()
        except EgressClosed as closed:
            await publish_status(
                self.factory, "collector", {**detail, "state": "waiting", "reason": closed.code}
            )
            return []
        if used >= cap:
            await publish_status(self.factory, "collector", {**detail, "state": "quarantine_full"})
            await self.rechecker.run()  # hash only: a re-check stores nothing without room
            return []
        targets = await self._due(DUE_BATCH)
        results = await asyncio.gather(*(self._handle(t) for t in targets))
        await self.rechecker.run()  # M27, off unless TAKEDOWN_ENABLED
        await publish_status(self.factory, "collector", {**detail, "state": "running"})
        return [r for r in results if r is not None]

    async def _due(self, n: int) -> list[Target]:
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT t.id, t.url, t.host, t.attempts, t.fetches, t.origin,
                               (t.indicator_id IS NULL
                                AND COALESCE(p.kind = ANY(:web), false)) AS web_parent
                        FROM fetch_targets t LEFT JOIN samples p ON p.sha256 = t.parent_sha256
                        WHERE t.status = 'pending' AND t.next_attempt_at <= :now
                        ORDER BY t.next_attempt_at, t.id LIMIT :n
                        """
                    ),
                    {"now": self._clock(), "n": n, "web": sorted(WEB_KINDS)},
                )
            ).all()
        return [Target(*row) for row in rows]

    async def _handle(self, target: Target) -> tuple[int, str] | None:
        async with self._sem, self._host_locks[target.host]:
            if target.web_parent:
                # Queued before the analyzer stopped following links in web pages: a page links
                # to the public web, which is not ours to crawl. No fetch, no quota.
                await self._refuse(target, WEB_PARENT)
                return target.id, fx.REFUSED
            if target.origin == VERIFY_ORIGIN and not self.s.verify_enabled:
                # The collector's owner stopped the verifier role: nothing is fetched, no quota.
                await self._refuse(target, VERIFY_DISABLED)
                return target.id, fx.REFUSED
            try:
                normalize_url(target.url, deny_nets=self.s.deny_nets, deny_hosts=self.s.deny_hosts)
            except UrlRefused as exc:
                await self._record(target, FetchResult(fx.REFUSED, exc.code), self._clock())
                return target.id, fx.REFUSED
            await self._host_wait(target.host)
            reason = await self._reserve()
            if reason is not None:
                return None
            day = self._clock().date()
            started = self._clock()
            budget = await self._claim_bytes()
            try:
                try:
                    result = await self._fetcher().fetch(target.url, budget=budget)
                except EgressClosed:
                    await self._refund(day)
                    return None
                finally:
                    self._inflight -= 1
                    self._host_last[target.host] = time.monotonic()
                await self._record(target, result, started)
            finally:
                # Released only after the sample row is committed, so the bytes are never
                # counted by neither the reservation nor the database.
                self._reserved -= budget
            return target.id, result.outcome

    async def _refuse(self, target: Target, code: str) -> None:
        await self._record(target, FetchResult(fx.REFUSED, code), self._clock())

    async def _claim_bytes(self) -> int:
        """Reserve room in quarantine for one download, so concurrent fetches cannot overshoot."""
        async with self._claim_lock:
            used = await self.quarantine_used()
            room = max(0, self.s.quarantine_max_bytes - used - self._reserved)
            claim = min(room, self.s.max_bytes)
            self._reserved += claim
            return claim

    def client(self) -> httpx.AsyncClient:
        """The one egress client of this service (fetches and takedown re-checks share it)."""
        if self._client is None:
            self._client = self._new_client()
        return self._client

    def _new_client(self) -> httpx.AsyncClient:
        return egress_client(
            self.gate,
            timeout=httpx.Timeout(
                self.s.timeout_s, connect=self.s.connect_timeout_s, pool=self.s.connect_timeout_s
            ),
            follow_redirects=False,
            verify=False,  # hostile hosts often have broken certificates; the tunnel is the guard
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
        )

    def _fetcher(self) -> Fetcher:
        return Fetcher(self.client(), self.store, self.s)

    # ---- bookkeeping -------------------------------------------------------------------------
    async def _record(self, target: Target, result: FetchResult, started: datetime) -> None:
        now = self._clock()
        sha = result.stored.sha256 if result.stored else None
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO fetch_attempts
                        (target_id, started_at, duration_ms, http_status, bytes, redirects,
                         outcome, sha256)
                    VALUES (:t, :started, :ms, :http, :bytes, :redirects, :outcome, :sha)
                    """
                ),
                {
                    "t": target.id, "started": started, "ms": result.duration_ms,
                    "http": result.http_status, "bytes": result.bytes,
                    "redirects": result.redirects, "outcome": result.outcome, "sha": sha,
                },
            )  # fmt: skip
            if result.stored is not None:
                await self._record_sample(session, target, result.stored, now)
                return
            status, delay, error = self._next_state(target, result)
            await session.execute(
                text(
                    """
                    UPDATE fetch_targets SET status = :status, last_error = :error,
                        attempts = :attempts, last_attempt_at = :now, next_attempt_at = :next
                    WHERE id = :id
                    """
                ),
                {
                    "status": status, "error": error, "now": now, "id": target.id,
                    "attempts": target.attempts
                    + (0 if result.outcome == fx.QUARANTINE_FULL else 1),
                    "next": now + delay if delay is not None else None,
                },
            )  # fmt: skip

    @staticmethod
    def _next_state(target: Target, result: FetchResult) -> tuple[str, timedelta | None, str]:
        """(status, delay until the next attempt, last_error) after a failed fetch."""
        outcome = result.outcome
        error = result.detail or outcome
        if outcome == fx.QUARANTINE_FULL:
            return "pending", FULL_RETRY, error
        if outcome in fx.RETRYABLE:
            n = target.attempts + 1
            if n <= len(RETRY_DELAYS):
                return "pending", RETRY_DELAYS[n - 1], error
            return "failed", None, error
        if outcome in (fx.HTTP_4XX, fx.EMPTY):
            return "gone", None, error
        if outcome == fx.TOO_LARGE:
            return "too_large", None, error
        return "refused", None, error  # refused, redirect_limit, bad_redirect

    async def _record_sample(
        self, session: AsyncSession, target: Target, stored: StoredFile, now: datetime
    ) -> None:
        await session.execute(
            text(
                """
                INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen, stored)
                VALUES (:sha, :sha1, :md5, :size, :now, :now, true)
                ON CONFLICT (sha256) DO UPDATE SET last_seen = :now, stored = true
                """
            ),
            {
                "sha": stored.sha256, "sha1": stored.sha1, "md5": stored.md5,
                "size": stored.size, "now": now,
            },
        )  # fmt: skip
        await session.execute(
            text(
                """
                INSERT INTO sample_sources (sha256, target_id, first_fetched, last_fetched)
                VALUES (:sha, :t, :now, :now)
                ON CONFLICT (sha256, target_id) DO UPDATE SET last_fetched = :now
                """
            ),
            {"sha": stored.sha256, "t": target.id, "now": now},
        )
        await session.execute(
            text(
                """
                UPDATE fetch_targets SET status = 'fetched', last_error = NULL, attempts = 0,
                    fetches = fetches + 1, last_attempt_at = :now, next_attempt_at = NULL,
                    last_sha256 = :sha
                WHERE id = :id
                """
            ),
            {"now": now, "sha": stored.sha256, "id": target.id},
        )

    # ---- retention ---------------------------------------------------------------------------
    async def retention_pass(self) -> int:
        """Delete quarantined files past retention (rows are kept, ``stored = false``)."""
        now = self._clock()
        cutoff = now - timedelta(days=self.s.retention_days)
        async with self.factory() as session, session.begin():
            old = (
                await session.execute(
                    text("SELECT sha256 FROM samples WHERE stored AND last_seen < :c LIMIT 500"),
                    {"c": cutoff},
                )
            ).scalars().all()  # fmt: skip
            for sha in old:
                await asyncio.to_thread(self.store.remove, sha)
            if old:
                await session.execute(
                    text("UPDATE samples SET stored = false WHERE sha256 = ANY(:s)"), {"s": old}
                )
            await session.execute(
                text("DELETE FROM fetch_attempts WHERE started_at < :c"), {"c": cutoff}
            )
        return len(old)

    # ---- main loop ---------------------------------------------------------------------------
    async def run(self) -> None:
        await asyncio.to_thread(self.store.prepare)

        async def on_status(status: Any) -> None:
            await publish_status(
                self.factory,
                "egress_collector",
                {
                    "open": status.open,
                    "reason": status.reason,
                    "egress_ip": status.egress_ip,
                    "checked_at": status.checked_at.isoformat(),
                },
            )

        gate_task = asyncio.create_task(self.gate.run(on_status), name="egress-gate")
        try:
            while True:
                try:
                    await self.step()
                    if time.monotonic() - self._last_retention > 3600:
                        self._last_retention = time.monotonic()
                        await self.retention_pass()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning("collector pass failed (%s)", type(exc).__name__)
                await asyncio.sleep(self.s.poll_s)
        finally:
            gate_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await gate_task
