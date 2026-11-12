"""The abuse-report worker (design M22, sections 3, 5 and 7.3). Off until ABUSE_REPORTS_ENABLED.

Each minute it answers the API's requests; hourly it learns the monitored system's address,
resolves abuse contacts through the egress gate and rebuilds the drafts; weekly it refreshes the
RDAP bootstrap. It prepares text and files. It sends nothing by itself: mail leaves only through
``ingest.reportmail`` (M25), when the owner configured SMTP and picked a sending mode.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.secretbox import SecretBox

from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate
from ingest.features import FeatureSettings, FeatureWorker

from . import selfterms
from .bootstrap import IANA_URL, REGISTRIES, Bootstrap, load_snapshot, valid_registry
from .build import CycleStats, DraftBuilder
from .config import AbuseSettings
from .contacts import ContactResolver, make_reserve, quota_providers
from .rdap import QuotaExhausted, RdapClient, RdapError
from .reguard import DraftReguard
from .selfterms import TermsCache

if TYPE_CHECKING:
    from ingest.reportmail.sender import ReportSender

log = logging.getLogger(__name__)

BOOTSTRAP_MAX_AGE = timedelta(days=7)
LEARN_EVERY_S = 3600.0
MAX_REQUESTS = 50


class AbuseWorker(FeatureWorker):
    name = "abuse"
    interval_s = 60.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        *,
        abuse: AbuseSettings | None = None,
        env: Mapping[str, str] | None = None,
        gate: EgressGate | None = None,
        client: httpx.AsyncClient | None = None,
        host_spacing_s: float = 2.0,
        box: SecretBox | None = None,
    ) -> None:
        super().__init__(settings, enabled=settings.abuse_enabled)
        self.factory = factory
        self.abuse = abuse or AbuseSettings.from_env(env)
        self._gate = gate
        self.bootstrap: Bootstrap = load_snapshot()
        self.bootstrap_at: datetime | None = None
        self.last_stats: CycleStats | None = None
        self._last_build = -math.inf  # due at once, whatever the host uptime
        self._last_learn = -math.inf
        self.terms: TermsCache | None = None
        self.rdap: RdapClient | None = None
        self.builder: DraftBuilder | None = None
        self.reguard: DraftReguard | None = None
        self.sender: ReportSender | None = None  # M25, set when the worker is enabled
        if self.enabled and factory is not None:
            self.terms = TermsCache(factory, env)
            from ingest.reportmail.sender import ReportSender  # late: it imports this package

            self.sender = ReportSender(factory, self.terms, self.abuse, box=box, gate=gate)
            self.rdap = RdapClient(
                make_reserve(factory, self.abuse),
                lambda: self.bootstrap.hosts(),
                gate=gate,
                client=client,
                host_spacing_s=host_spacing_s,
            )
            resolver = ContactResolver(factory, self.rdap, self.bootstrap)
            self.resolver = resolver
            self.builder = DraftBuilder(factory, self.abuse, self.terms, resolver)
            self.reguard = DraftReguard(factory, self.abuse, self.terms)

    def _open(self) -> bool:
        return gate_open(self._gate or get_gate())

    # -- bootstrap -----------------------------------------------------------------------

    async def load_bootstrap(self) -> None:
        """Newest copy from the database, else the shipped seed."""
        if self.factory is None:
            return
        async with self.factory() as session:
            rows = (
                await session.execute(text("SELECT registry, body, fetched_at FROM rdap_bootstrap"))
            ).all()
        docs = {r.registry: r.body for r in rows if valid_registry(r.body)}
        if len(docs) == len(REGISTRIES):
            self.bootstrap = Bootstrap(docs)
            self.bootstrap_at = min(r.fetched_at for r in rows)
            if getattr(self, "resolver", None) is not None:
                self.resolver.bootstrap = self.bootstrap

    async def refresh_bootstrap(self) -> None:
        if self.rdap is None or self.factory is None:
            return
        for registry in REGISTRIES:
            doc = await self.rdap.get_json(IANA_URL.format(registry))
            if not valid_registry(doc):
                raise RdapError("bad_bootstrap")
            async with self.factory() as session, session.begin():
                await session.execute(
                    text(
                        """
                        INSERT INTO rdap_bootstrap (registry, body, fetched_at)
                        VALUES (:r, CAST(:b AS jsonb), now())
                        ON CONFLICT (registry) DO UPDATE SET body = CAST(:b AS jsonb),
                            fetched_at = now()
                        """
                    ),
                    {"r": registry, "b": json.dumps(doc)},
                )
        await self.load_bootstrap()

    # -- requests from the API -----------------------------------------------------------

    async def handle_requests(self) -> bool:
        """Answer pending requests. True when a rebuild was asked for."""
        if self.factory is None:
            return False
        async with self.factory() as session:
            pending = (
                await session.execute(
                    text(
                        "SELECT id, report_id, action FROM abuse_report_requests "
                        "WHERE done_at IS NULL ORDER BY id LIMIT :n"
                    ),
                    {"n": MAX_REQUESTS},
                )
            ).all()
        rebuild = False
        for req in pending:
            outcome = "ok"
            async with self.factory() as session, session.begin():
                if req.action == "lookup_again":
                    await self._forget_lookups(session, req.report_id)
                    rebuild = True
                elif req.action == "regenerate":
                    state = (
                        await session.execute(
                            text("SELECT status FROM abuse_reports WHERE id = :i"),
                            {"i": req.report_id},
                        )
                    ).first()
                    if state is None:
                        outcome = "missing"
                    elif state.status != "draft":
                        outcome = "not_draft"  # reviewed and later reports are never rebuilt
                    else:
                        rebuild = True
                else:
                    outcome = "unknown_action"
                await session.execute(
                    text(
                        "UPDATE abuse_report_requests SET done_at = now(), outcome = :o "
                        "WHERE id = :i"
                    ),
                    {"o": outcome[:64], "i": req.id},
                )
        return rebuild

    @staticmethod
    async def _forget_lookups(session: AsyncSession, report_id: int | None) -> None:
        """Make failed or empty lookups due again (of one report's subjects, or all of them)."""
        params: dict[str, Any] = {"r": report_id}
        await session.execute(
            text(
                """
                UPDATE abuse_networks SET expires_at = now()
                WHERE cardinality(mailboxes) = 0 AND id IN (
                    SELECT network_id FROM abuse_lookups WHERE status = 'no_contact' AND (
                        CAST(:r AS bigint) IS NULL OR subject IN
                            (SELECT value FROM abuse_report_subjects WHERE report_id = :r))
                )
                """
            ),
            params,
        )
        await session.execute(
            text(
                """
                UPDATE abuse_lookups SET next_check_at = now()
                WHERE status IN ('no_contact', 'error') AND (
                    CAST(:r AS bigint) IS NULL OR subject IN
                        (SELECT value FROM abuse_report_subjects WHERE report_id = :r))
                """
            ),
            params,
        )

    # -- cycle ---------------------------------------------------------------------------

    async def run_once(self) -> None:
        if self.factory is None or self.builder is None or self.rdap is None:
            return
        now = datetime.now(UTC)
        await self.load_bootstrap()
        is_open = self._open()
        if is_open and (self.bootstrap_at is None or now - self.bootstrap_at > BOOTSTRAP_MAX_AGE):
            try:
                await self.refresh_bootstrap()
            except EgressClosed, QuotaExhausted:
                pass
            except RdapError as exc:
                log.info("rdap bootstrap refresh failed (%s)", exc)
        force = await self.handle_requests()
        await self._send_cycle(now)
        mono = time.monotonic()
        if mono - self._last_learn >= LEARN_EVERY_S:
            self._last_learn = mono
            try:
                await selfterms.learn(self.factory, now)
            except Exception as exc:
                log.warning("self-term learning failed (%s)", type(exc).__name__)
        await self._reguard_cycle()
        if force or mono - self._last_build >= self.abuse.build_interval_s:
            self._last_build = mono
            self.last_stats = await self.builder.run(now, allow_lookups=self._open())

    async def _reguard_cycle(self) -> None:
        """Re-check the open drafts after a settings or deny-set change, without any lookup."""
        if self.reguard is None:
            return
        try:
            await self.reguard.run_if_changed()
        except Exception as exc:
            log.warning("abuse draft re-check failed (%s)", type(exc).__name__)

    async def _send_cycle(self, now: datetime) -> None:
        """Answer the SMTP send requests. A failure here never stops the rest of the cycle."""
        if self.sender is None:
            return
        try:
            await self.sender.run(now)
        except Exception as exc:
            log.warning("abuse mail cycle failed (%s)", type(exc).__name__)

    async def status(self) -> dict[str, Any]:
        base = (await super().status())[self.name]
        stats = self.last_stats
        if stats is not None:
            base.update(
                selected=stats.selected,
                resolved=stats.resolved,
                no_contact=stats.no_contact,
                created=stats.created,
                updated=stats.updated,
                guard_failed=stats.guard_failed,
                waiting_egress=stats.waiting_egress,
                reasons=dict(stats.reasons),
            )
        if self.enabled and self.factory is not None:
            try:
                base.update(await selfterms.self_address_state(self.factory))
            except Exception as exc:
                log.warning("self address state unavailable (%s)", type(exc).__name__)
        rdap: dict[str, Any] = {
            "enabled": self.enabled,
            "daily_quota": self.abuse.rdap_daily_quota,
            "hourly_quota": self.abuse.rdap_hourly_quota,
            "quota_exhausted": bool(stats and stats.quota_exhausted),
            "egress_open": self._open() if self.enabled else None,
            "bootstrap_at": self.bootstrap_at.isoformat() if self.bootstrap_at else None,
        }
        if self.enabled and self.factory is not None:
            daily, hourly = quota_providers(datetime.now(UTC))
            try:
                async with self.factory() as session:
                    used = (
                        await session.execute(
                            text(
                                "SELECT provider, used FROM enrichment_quota "
                                "WHERE day = (now() AT TIME ZONE 'UTC')::date "
                                "AND provider IN (:d, :h)"
                            ),
                            {"d": daily, "h": hourly},
                        )
                    ).all()
                for row in used:
                    rdap["used_today" if row.provider == daily else "used_this_hour"] = row.used
            except Exception as exc:
                log.warning("rdap quota status unavailable (%s)", type(exc).__name__)
        return {self.name: base, "rdap": rdap}

    async def aclose(self) -> None:
        if self.rdap is not None:
            await self.rdap.aclose()
