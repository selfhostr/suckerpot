"""Takedown re-checks (M27, docs/dev/design/m27.md section 4.3): is a payload URL still serving?

The only request this module ever makes is one bounded GET to a URL that already served a sample to
this collector, through the egress client, with the same identity and caps as the original fetch and
the URL validator on the URL and on every redirect hop. Nothing else is contacted: no other path of
the host, no HEAD, no connection to a command-and-control address, no packet to an attacking
address. Targets come from ``takedown_targets`` rows with ``kind = 'url' AND http_eligible`` only.

A re-check stores nothing unless the hash changed. The raw body is hashed as it streams
(``aiter_raw``: httpx never decompresses); bytes go to a quarantine temp file only while there is
room, and the temp file is unlinked unless the answer is ``changed`` (a different file, kept as a
new sample). ``EgressClosed`` and a failure of the proxy itself write no row and refund the quota.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_egress import EgressClosed

from collector.config import CollectorSettings
from collector.identity import user_agent_for
from collector.status import publish_status
from collector.store import Quarantine, StoredFile, TempFile, TooLarge
from collector.validate import UrlRefused, normalize_url, resolve_redirect

if TYPE_CHECKING:
    from collector.service import CollectorService

log = logging.getLogger(__name__)

QUOTA_PROVIDER: Final = "takedown_http"
STATUS_NAME: Final = "takedown_http"
BATCH: Final = 5
HEAD_BYTES: Final = 512
REDIRECT_CODES: Final = frozenset({301, 302, 303, 307, 308})

HTTP_OFFSETS: Final = (
    timedelta(0),
    timedelta(hours=1),
    timedelta(hours=6),
    timedelta(hours=24),
    timedelta(hours=48),
)
DAILY: Final = timedelta(hours=24)
WHILE_DOWN: Final = timedelta(hours=72)
MAX_STEP: Final = 30_000

# Constant outcome codes stored in takedown_checks.outcome (method "http").
SAME: Final = "same"
CHANGED: Final = "changed"
CHANGED_NOT_STORED: Final = "changed_not_stored"
UP_UNHASHED: Final = "up_unhashed"
HTTP_404: Final = "http_404"
HTTP_410: Final = "http_410"
HTTP_4XX: Final = "http_4xx"
HTTP_5XX: Final = "http_5xx"
SUSPENDED: Final = "suspended_page"
EMPTY: Final = "empty"
UNREACHABLE: Final = "unreachable"
TIMEOUT: Final = "timeout"
REFUSED: Final = "refused"
REDIRECT_LIMIT: Final = "redirect_limit"
BAD_REDIRECT: Final = "bad_redirect"

_HTML = re.compile(rb"<!doctype\s+html|<html", re.IGNORECASE)
HTML_KINDS: Final = frozenset({"html", "text/html"})


def next_http_at(
    step: int, reported_at: datetime, state: str, now: datetime
) -> tuple[int, datetime]:
    """Where the schedule goes after the check of slot ``step`` ran at ``now``.

    Slots are ``reported_at + HTTP_OFFSETS[i]``. A slot already in the past is skipped (a target
    created late gets one immediate baseline check, then waits for the next slot in the future).
    After the last slot: one check every 24 h, every 72 h while the target is down. Pure.
    """
    last = len(HTTP_OFFSETS) - 1
    nxt = max(step, -1) + 1
    while nxt <= last:
        at = reported_at + HTTP_OFFSETS[nxt]
        if at > now:
            return nxt, at
        nxt += 1
    gap = WHILE_DOWN if state == "down" else DAILY
    return min(max(step + 1, last + 1), MAX_STEP), now + gap


def outcome_for_status(status: int) -> str:
    """The outcome of a non-2xx answer."""
    if status == 404:
        return HTTP_404
    if status == 410:
        return HTTP_410
    if 400 <= status < 500:
        return HTTP_4XX
    if status >= 500:
        return HTTP_5XX
    return BAD_REDIRECT  # 1xx and 3xx that are not redirects we follow


def looks_like_html(head: bytes) -> bool:
    return _HTML.search(head[:HEAD_BYTES]) is not None


def classify_body(
    prev_sha: str | None,
    new_sha: str,
    head: bytes,
    size: int,
    prev_kind: str | None,
    *,
    room: bool = True,
) -> str:
    """The outcome of a 2xx answer that fit under the size cap. Pure."""
    if size == 0:
        return EMPTY
    if prev_sha is not None and new_sha == prev_sha:
        return SAME
    if looks_like_html(head) and (prev_kind or "").lower() not in HTML_KINDS:
        return SUSPENDED
    return CHANGED if room else CHANGED_NOT_STORED


class ProxySideError(Exception):
    """The connection to the egress proxy itself failed: our side, not the target's."""


@dataclass(frozen=True)
class RecheckTarget:
    id: int
    url: str
    fetch_target_id: int | None
    reported_at: datetime
    state: str
    http_step: int
    prev_sha: str | None
    prev_kind: str | None


@dataclass(frozen=True)
class Probe:
    outcome: str
    http_status: int | None = None
    sha256: str | None = None
    bytes: int | None = None
    duration_ms: int = 0
    redirects: int = 0
    stored: StoredFile | None = None


async def probe(
    client: httpx.AsyncClient,
    store: Quarantine,
    settings: CollectorSettings,
    url: str,
    *,
    prev_sha: str | None,
    prev_kind: str | None,
    budget: int,
) -> Probe:
    """One bounded GET of ``url`` (redirects by hand, every hop validated). ``budget`` is the room
    left in quarantine; with no room the body is only hashed. Raises ``EgressClosed`` (nothing
    sent) and ``ProxySideError`` (the proxy itself failed); every other failure is an outcome."""
    started = time.monotonic()
    redirects = 0
    status: int | None = None

    def done(
        outcome: str,
        *,
        sha: str | None = None,
        size: int | None = None,
        stored: StoredFile | None = None,
    ) -> Probe:
        ms = int((time.monotonic() - started) * 1000)
        return Probe(outcome, status, sha, size, ms, redirects, stored)

    try:
        async with asyncio.timeout(settings.timeout_s):
            current = normalize_url(
                url, deny_nets=settings.deny_nets, deny_hosts=settings.deny_hosts
            )
            while True:
                headers = {
                    "User-Agent": user_agent_for(current.url),
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                }
                async with client.stream("GET", current.url, headers=headers) as resp:
                    status = resp.status_code
                    if status in REDIRECT_CODES:
                        location = resp.headers.get("location")
                        if not location:
                            return done(BAD_REDIRECT)
                        if redirects >= settings.max_redirects:
                            return done(REDIRECT_LIMIT)
                        redirects += 1
                        current = resolve_redirect(
                            current.url,
                            location,
                            deny_nets=settings.deny_nets,
                            deny_hosts=settings.deny_hosts,
                        )
                        continue
                    if not 200 <= status < 300:
                        return done(outcome_for_status(status))
                    return await _body(resp, store, settings, prev_sha, prev_kind, budget, done)
    except UrlRefused:
        return done(REFUSED)
    except EgressClosed:
        raise
    except httpx.ConnectError, httpx.ConnectTimeout:
        raise ProxySideError from None
    except httpx.ProxyError:
        return done(UNREACHABLE)  # the proxy could not reach the target (DNS, refusal)
    except TimeoutError, httpx.TimeoutException:
        return done(TIMEOUT)
    except httpx.HTTPError:
        return done(UNREACHABLE)


async def _body(
    resp: httpx.Response,
    store: Quarantine,
    settings: CollectorSettings,
    prev_sha: str | None,
    prev_kind: str | None,
    budget: int,
    finish: Callable[..., Probe],
) -> Probe:
    cap = settings.max_bytes
    hasher = hashlib.sha256()
    head = b""
    total = 0
    temp: TempFile | None = store.open_temp(min(cap, budget)) if budget > 0 else None
    try:
        async for chunk in resp.aiter_raw():
            total += len(chunk)
            if total > cap:
                return finish(UP_UNHASHED, size=total)
            hasher.update(chunk)
            if len(head) < HEAD_BYTES:
                head = (head + chunk)[:HEAD_BYTES]
            if temp is not None:
                try:
                    temp.write(chunk)
                except TooLarge:
                    temp.abort()  # no room for this file: keep hashing, store nothing
                    temp = None
        sha = hasher.hexdigest()
        outcome = classify_body(prev_sha, sha, head, total, prev_kind, room=temp is not None)
        if outcome == CHANGED and temp is not None:
            stored = await asyncio.to_thread(store.commit, temp)
            return finish(CHANGED, sha=sha, size=total, stored=stored)
        return finish(outcome, sha=sha if total else None, size=total)
    finally:
        if temp is not None:
            temp.abort()  # a no-op once committed; otherwise unlinks the temp file


class Rechecker:
    """Called from ``CollectorService.step()`` after the normal fetch batch. It shares the
    service's client, semaphore, per-host locks and spacing."""

    def __init__(self, service: CollectorService) -> None:
        self.svc = service
        self.checks = 0

    @property
    def enabled(self) -> bool:
        return self.svc.s.takedown_enabled and self.svc.s.enabled

    async def due(self, n: int = BATCH) -> list[RecheckTarget]:
        now = self.svc._clock()
        async with self.svc.factory() as session:
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT t.id, t.value, t.fetch_target_id, t.reported_at, t.state,
                               t.http_step,
                               COALESCE(t.last_sha256, t.baseline_sha256, f.last_sha256) AS prev,
                               s.kind
                        FROM takedown_targets t
                        LEFT JOIN fetch_targets f ON f.id = t.fetch_target_id
                        LEFT JOIN samples s
                               ON s.sha256 = COALESCE(t.last_sha256, t.baseline_sha256,
                                                      f.last_sha256)
                        WHERE t.kind = 'url' AND t.http_eligible AND t.tracking AND NOT t.demo
                          AND t.http_next_at <= :now AND t.track_until > :now
                        ORDER BY t.http_next_at, t.id LIMIT :n
                        """
                    ),
                    {"now": now, "n": n},
                )
            ).all()
        return [RecheckTarget(*row) for row in rows]

    async def run(self) -> int:
        """One pass over the due targets. Returns how many checks were recorded."""
        if not self.enabled:
            return 0
        targets = await self.due()
        results = await asyncio.gather(*(self._handle(t) for t in targets))
        done = sum(1 for r in results if r)
        if targets:
            self.checks += done
            await publish_status(
                self.svc.factory,
                STATUS_NAME,
                {"enabled": True, "checks": self.checks, "last_batch": len(targets)},
            )
        return done

    async def _reserve(self, now: datetime) -> bool:
        async with self.svc.factory() as session, session.begin():
            granted = await session.scalar(
                text(
                    """
                    INSERT INTO enrichment_quota (provider, day, used) VALUES (:p, :d, 1)
                    ON CONFLICT (provider, day) DO UPDATE SET used = enrichment_quota.used + 1
                    WHERE enrichment_quota.used < :cap
                    RETURNING used
                    """
                ),
                {"p": QUOTA_PROVIDER, "d": now.date(), "cap": self.svc.s.takedown_http_daily_quota},
            )
        return granted is not None

    async def _refund(self, day: Any) -> None:
        async with self.svc.factory() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE enrichment_quota SET used = GREATEST(used - 1, 0) "
                    "WHERE provider = :p AND day = :d"
                ),
                {"p": QUOTA_PROVIDER, "d": day},
            )

    async def _handle(self, target: RecheckTarget) -> bool:
        svc = self.svc
        host = _host_of(target.url)
        async with svc._sem, svc._host_locks[host]:
            try:
                normalize_url(target.url, deny_nets=svc.s.deny_nets, deny_hosts=svc.s.deny_hosts)
            except UrlRefused:
                # It may now point somewhere private: stop re-checking, send nothing.
                await self._record(target, Probe(REFUSED), refused=True)
                return True
            await svc._host_wait(host)
            now = svc._clock()
            if not await self._reserve(now):
                return False
            day = now.date()
            budget = await svc._claim_bytes()
            try:
                try:
                    result = await probe(
                        svc.client(),
                        svc.store,
                        svc.s,
                        target.url,
                        prev_sha=target.prev_sha,
                        prev_kind=target.prev_kind,
                        # Without a fetch target nothing can record the file: keep none (no
                        # orphan in quarantine), only hash it.
                        budget=budget if target.fetch_target_id is not None else 0,
                    )
                except EgressClosed, ProxySideError:
                    await self._refund(day)  # nothing reached the target: no row, no quota
                    return False
                finally:
                    svc._host_last[host] = time.monotonic()
                await self._record(target, result)
            finally:
                svc._reserved -= budget
        return True

    async def _record(self, target: RecheckTarget, result: Probe, *, refused: bool = False) -> None:
        svc = self.svc
        now = svc._clock()
        step, at = next_http_at(target.http_step, target.reported_at, target.state, now)
        detail = {"redirects": result.redirects} if result.redirects else {}
        async with svc.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO takedown_checks (target_id, checked_at, method, outcome,
                                                 http_status, sha256, bytes, duration_ms, detail)
                    VALUES (:t, :now, 'http', :o, :http, :sha, :b, :ms, CAST(:d AS jsonb))
                    """
                ),
                {
                    "t": target.id, "now": now, "o": result.outcome, "http": result.http_status,
                    "sha": result.sha256, "b": result.bytes, "ms": result.duration_ms,
                    "d": json.dumps(detail),
                },
            )  # fmt: skip
            if result.stored is not None and target.fetch_target_id is not None:
                from collector.service import Target

                await svc._record_sample(
                    session,
                    Target(target.fetch_target_id, target.url, _host_of(target.url), 0, 0),
                    result.stored,
                    now,
                )
            keep_hash = result.sha256 if result.outcome in (CHANGED, CHANGED_NOT_STORED) else None
            # A hop that turned out private or denied stops the re-checks, as a refused URL does.
            stop = refused or result.outcome == REFUSED
            await self._advance(session, target.id, step, at, now, keep_hash, stop)

    @staticmethod
    async def _advance(
        session: AsyncSession,
        tid: int,
        step: int,
        at: datetime,
        now: datetime,
        sha: str | None,
        refused: bool,
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE takedown_targets SET http_step = :step, http_next_at = :at,
                    http_last_at = :now, last_sha256 = COALESCE(:sha, last_sha256),
                    http_eligible = http_eligible AND NOT :refused
                WHERE id = :id
                """
            ),
            {"step": step, "at": at, "now": now, "sha": sha, "refused": refused, "id": tid},
        )


def _host_of(url: str) -> str:
    return url.split("//", 1)[-1].split("/", 1)[0].lower()
