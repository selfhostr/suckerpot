"""The analyzer loop: pending samples to findings, links and next-stage fetch targets.

No network: this process has no route out and no Redis. It reads files from the read-only
quarantine, hands each to a limited child process (``collector.runner``) and stores the validated
result. High-confidence indicators of compromise go back into ``indicators`` (role ``c2``) so the
existing intel worker looks them up through the proxy like any other indicator.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_analysis import ANALYSIS_VERSION, AnalysisResult, Ioc
from suckerpot_db.locks import SAMPLE_TYPING
from suckerpot_db.sample_kinds import plain_web_sample

from collector.config import CollectorSettings
from collector.reopen import REOPEN_TARGET
from collector.runner import ChildOutcome, run_child
from collector.status import beat
from collector.store import Quarantine, TooLarge
from collector.validate import UrlRefused, blocked_address, normalize_url

log = logging.getLogger(__name__)

MAX_NEXT_URLS = 20
BATCH = 5
# Read right after the sample row took the new kind, severity and family (same transaction).
_PLAIN_WEB = f"SELECT {plain_web_sample('s')} FROM samples s WHERE s.sha256 = :sha"  # noqa: S608
# Labels of the links a spared file keeps from an older analysis, so the files it led to are
# judged by what this analysis read (an asset of a page, or a link in its text).
_RELABEL = """
    UPDATE sample_links l SET source = v.source
    FROM unnest(CAST(:values AS text[]), CAST(:sources AS text[])) AS v(value, source)
    WHERE l.sha256 = :sha AND l.kind = 'next_url' AND l.value = v.value
      AND l.source IS DISTINCT FROM v.source
"""
MAX_INPUT = 16 * 1024 * 1024
Factory = async_sessionmaker[AsyncSession]


def _utcnow() -> datetime:
    return datetime.now(UTC)


def clean(value: str) -> str:
    """PostgreSQL text cannot hold NUL bytes or lone surrogates."""
    return value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")


class AnalyzerService:
    def __init__(
        self,
        settings: CollectorSettings,
        factory: Factory,
        store: Quarantine,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.s = settings
        self.factory = factory
        self.store = store
        self._clock = clock

    async def step(self) -> int:
        # No status row: the analyzer role may INSERT but not SELECT enrichment_status, and an
        # upsert needs both. Its liveness is the container healthcheck.
        beat(self.s.heartbeat_path)
        if not self.s.enabled:
            return 0
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT sha256 FROM samples
                        WHERE analysis_status = 'pending'
                           OR (analysis_status = 'done' AND analysis_version < :v)
                        ORDER BY first_seen LIMIT :n
                        """
                    ),
                    {"v": ANALYSIS_VERSION, "n": BATCH},
                )
            ).scalars().all()  # fmt: skip
        for sha in rows:
            beat(self.s.heartbeat_path)
            await self.analyze_sample(sha)
        return len(rows)

    async def analyze_sample(self, sha: str) -> str:
        """Analyse one stored sample and write the outcome. Returns the analysis status."""
        started = time.monotonic()
        try:
            data = await asyncio.to_thread(self.store.read, sha, MAX_INPUT)
        except OSError, TooLarge:
            return await self._fail(sha, "failed", "file_missing", started)
        if hashlib.sha256(data).hexdigest() != sha:
            return await self._fail(sha, "failed", "hash_mismatch", started)
        outcome: ChildOutcome = await run_child(
            data,
            timeout_s=self.s.analyzer_timeout_s,
            memory_mb=self.s.analyzer_memory_mb,
            rules_dir=self.s.rules_dir,
        )
        if outcome.status != "done" or outcome.result is None:
            return await self._fail(sha, outcome.status, outcome.code or "failed", started)
        await self._store_result(sha, outcome.result, int((time.monotonic() - started) * 1000))
        return "done"

    async def _fail(self, sha: str, status: str, code: str, started: float) -> str:
        now = self._clock()
        ms = int((time.monotonic() - started) * 1000)
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO sample_analysis (sha256, analyzed_at, elapsed_ms, errors)
                    VALUES (:sha, :now, :ms, ARRAY[CAST(:code AS text)])
                    ON CONFLICT (sha256) DO UPDATE SET analyzed_at = :now,
                        elapsed_ms = :ms, errors = ARRAY[CAST(:code AS text)]
                    """
                ),
                {"sha": sha, "now": now, "ms": ms, "code": code},
            )
            await session.execute(
                text(
                    "UPDATE samples SET analysis_status = :st, analysis_version = :v "
                    "WHERE sha256 = :sha"
                ),
                {"st": status, "v": ANALYSIS_VERSION, "sha": sha},
            )
        return status

    async def _store_result(self, sha: str, result: AnalysisResult, ms: int) -> None:
        now = self._clock()
        info = result.file
        async with self.factory() as session, session.begin():
            # Shared with the other decisions; the collector takes it alone while it records
            # typed URLs, so this decision never reads a typing that is half written.
            await session.execute(
                text("SELECT pg_advisory_xact_lock_shared(:k)"), {"k": SAMPLE_TYPING}
            )
            await session.execute(
                text(
                    """
                    UPDATE samples SET kind = :kind, arch = :arch, bits = :bits,
                        endian = :endian, linking = :linking, packer = :packer,
                        family = :family, severity = :severity, tlsh = :tlsh,
                        analysis_status = 'done', analysis_version = :v
                    WHERE sha256 = :sha
                    """
                ),
                {
                    "kind": info.kind, "arch": info.arch, "bits": info.bits,
                    "endian": info.endian, "linking": info.linking, "packer": info.packer,
                    "family": result.family, "severity": result.severity,
                    "tlsh": result.digests.tlsh, "v": result.version, "sha": sha,
                },
            )  # fmt: skip
            # Plain web content: a page, style sheet, image or web script that no rule matched,
            # which the collector reached only through asset links of other web content. Kept and
            # shown, but no threat intelligence: no hash indicator, no link followed, no
            # deobfuscated text stored. Web content an attacker asked for (a typed URL, depth 0, a
            # link in the text of a page, in a script or in a binary) is attacker content.
            plain = not result.yara and bool(await session.scalar(text(_PLAIN_WEB), {"sha": sha}))
            verify_only = await self._verify_only(session, sha)
            await session.execute(
                text("UPDATE samples SET spared = :sp WHERE sha256 = :sha"),
                {"sp": plain or verify_only, "sha": sha},
            )
            yara = [hit.model_dump(mode="json") for hit in result.yara]
            await session.execute(
                text(
                    """
                    INSERT INTO sample_analysis
                        (sha256, analyzed_at, elapsed_ms, yara, strings, deobfuscated,
                         deob_steps, errors)
                    VALUES (:sha, :now, :ms, CAST(:yara AS jsonb), :strings, :deob,
                            CAST(:steps AS jsonb), :errors)
                    ON CONFLICT (sha256) DO UPDATE SET analyzed_at = EXCLUDED.analyzed_at,
                        elapsed_ms = EXCLUDED.elapsed_ms, yara = EXCLUDED.yara,
                        strings = EXCLUDED.strings, deobfuscated = EXCLUDED.deobfuscated,
                        deob_steps = EXCLUDED.deob_steps, errors = EXCLUDED.errors
                    """
                ),
                {
                    "sha": sha, "now": now, "ms": ms,
                    "yara": json.dumps(yara),
                    "strings": [clean(s) for s in result.strings],
                    "deob": (
                        clean(result.deobfuscated)
                        if result.deobfuscated is not None and not plain
                        else None
                    ),
                    "steps": json.dumps(
                        [] if plain else [s.model_dump(mode="json") for s in result.deob_steps]
                    ),
                    "errors": list(result.errors),
                },
            )  # fmt: skip
            if verify_only:
                # M32: a sample fetched only for the network is described, never acted on: no
                # local indicator, no child fetch target, no C2 indicator (design 8.6).
                await self._links(session, sha, result.iocs, now, follow=False)
                return
            if plain:
                await self._relabel(session, sha, result.iocs)
                return
            await self._hash_indicator(session, sha, now)
            await self._links(session, sha, result.iocs, now)

    @staticmethod
    async def _verify_only(session: AsyncSession, sha: str) -> bool:
        """True when every source of the sample is a network verification fetch."""
        return bool(
            await session.scalar(
                text(
                    "SELECT COALESCE(bool_and(t.origin = 'network_verify'), false) "
                    "FROM sample_sources s JOIN fetch_targets t ON t.id = s.target_id "
                    "WHERE s.sha256 = :sha"
                ),
                {"sha": sha},
            )
        )

    @staticmethod
    async def _relabel(session: AsyncSession, sha: str, iocs: list[Ioc]) -> None:
        links = [(clean(i.value)[:1024], i.source) for i in iocs if i.kind == "next_url"]
        if links:
            await session.execute(
                text(_RELABEL),
                {"sha": sha, "values": [v for v, _ in links], "sources": [s for _, s in links]},
            )

    async def _hash_indicator(self, session: AsyncSession, sha: str, now: datetime) -> None:
        await session.execute(
            text(
                """
                INSERT INTO indicators (type, value, role, first_seen, last_seen, trusted)
                VALUES ('hash', :sha, 'hash', :now, :now, true)
                ON CONFLICT (type, value) DO UPDATE
                    SET last_seen = :now, trusted = true, sightings = indicators.sightings + 1
                """
            ),
            {"sha": sha, "now": now},
        )

    async def _links(
        self,
        session: AsyncSession,
        sha: str,
        iocs: list[Ioc],
        now: datetime,
        *,
        follow: bool = True,
    ) -> None:
        depth = int(
            await session.scalar(
                text(
                    "SELECT COALESCE(min(t.depth), 0) FROM sample_sources s "
                    "JOIN fetch_targets t ON t.id = s.target_id WHERE s.sha256 = :sha"
                ),
                {"sha": sha},
            )
            or 0
        )
        next_urls = 0
        for ioc in iocs:
            target_id: int | None = None
            indicator_id: int | None = None
            queued = False
            if not follow:
                pass  # recorded for display only
            elif ioc.kind == "next_url":
                queued = depth + 1 <= self.s.max_depth and next_urls < MAX_NEXT_URLS
                # Past the caps nothing new is queued, but a URL already known still gets this
                # link: it is how the rule sees every file that leads to it.
                target_id = await self._next_target(
                    session, ioc.value, sha, depth + 1, now, insert=queued
                )
                next_urls += queued and target_id is not None
            elif ioc.confidence == "high":
                indicator_id = await self._c2_indicator(session, ioc, now)
            await session.execute(
                text(
                    """
                    INSERT INTO sample_links
                        (sha256, kind, value, port, source, confidence, target_id, indicator_id)
                    VALUES (:sha, :kind, :value, :port, :source, :conf, :target, :ind)
                    ON CONFLICT (sha256, kind, value) DO UPDATE SET port = EXCLUDED.port,
                        source = EXCLUDED.source, confidence = EXCLUDED.confidence,
                        target_id = EXCLUDED.target_id, indicator_id = EXCLUDED.indicator_id
                    """
                ),
                {
                    "sha": sha, "kind": ioc.kind, "value": clean(ioc.value)[:1024],
                    "port": ioc.port, "source": ioc.source, "conf": ioc.confidence,
                    "target": target_id, "ind": indicator_id,
                },
            )  # fmt: skip
            if target_id is not None:
                # Attacker content links to this URL: if only plain web content linked to it
                # before, it goes back in the queue (within the caps), and a file it served that
                # was spared is analysed again as attacker content.
                if queued:
                    await session.execute(
                        text("SELECT suckerpot_revive_web_target(:t, :now)"),
                        {"t": target_id, "now": now},
                    )
                await session.execute(text(REOPEN_TARGET), {"t": target_id})

    async def _next_target(
        self,
        session: AsyncSession,
        raw: str,
        sha: str,
        depth: int,
        now: datetime,
        *,
        insert: bool = True,
    ) -> int | None:
        """The fetch target of a next URL, queued at `depth` when new (only with `insert`)."""
        try:
            valid = normalize_url(raw, deny_nets=self.s.deny_nets, deny_hosts=self.s.deny_hosts)
        except UrlRefused:
            return None
        if insert:
            await session.execute(
                text(
                    """
                    INSERT INTO fetch_targets
                        (url, scheme, host, parent_sha256, depth, status, first_seen,
                         next_attempt_at)
                    VALUES (:url, :scheme, :host, :sha, :depth, 'pending', :now, :now)
                    ON CONFLICT (url) DO NOTHING
                    """
                ),
                {
                    "url": valid.url, "scheme": valid.scheme, "host": valid.host[:255],
                    "sha": sha, "depth": depth, "now": now,
                },
            )  # fmt: skip
        found = await session.scalar(
            text("SELECT id FROM fetch_targets WHERE url = :url"), {"url": valid.url}
        )
        return int(found) if found is not None else None

    async def _c2_indicator(self, session: AsyncSession, ioc: Ioc, now: datetime) -> int | None:
        kind: dict[str, Any] = {"c2_ip": "ip", "c2_domain": "domain", "c2_url": "url"}
        itype = kind[ioc.kind]
        value = clean(ioc.value)
        host: str | None = None
        if itype == "ip":
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                return None
            if blocked_address(addr, self.s.deny_nets):
                return None
        elif itype == "domain":
            host = value.lower()
        else:
            try:
                valid = normalize_url(
                    value, deny_nets=self.s.deny_nets, deny_hosts=self.s.deny_hosts
                )
            except UrlRefused:
                return None
            host = valid.host
        if host is not None and any(host == d or host.endswith("." + d) for d in self.s.deny_hosts):
            return None
        if len(value) > 512:
            return None
        found = await session.scalar(
            text(
                """
                INSERT INTO indicators (type, value, role, host, first_seen, last_seen)
                VALUES (:type, :value, 'c2', :host, :now, :now)
                ON CONFLICT (type, value) DO UPDATE
                    SET last_seen = :now, sightings = indicators.sightings + 1
                RETURNING id
                """
            ),
            {"type": itype, "value": value, "host": host and host[:255], "now": now},
        )
        return int(found) if found is not None else None

    async def run(self) -> None:
        # A broken rule must stop the analyzer at start, not fail every scan.
        from suckerpot_analysis import compile_rules

        await asyncio.to_thread(compile_rules, self.s.rules_dir)
        while True:
            try:
                handled = await self.step()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("analyzer pass failed (%s)", type(exc).__name__)
                handled = 0
            if handled == 0:
                await asyncio.sleep(self.s.poll_s)
