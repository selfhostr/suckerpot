"""Re-check the open drafts when the owner's wording or the deny set changed.

A draft keeps the result of its identity check (``guard_ok``, ``guard_codes``) from the moment it
was built, and the lists show that stored result. The builder refreshes it only for the drafts it
rebuilds, once an hour and within the lookup cap. Without this pass a reply contact fixed in
Settings would leave every draft marked blocked for up to an hour (or longer for a draft the cap
skips), and a new deny term would leave a leaking draft marked clean.

The pass needs no lookup and no rebuild: it renders every open draft again from its stored
evidence and the current settings, runs the same check as the builder and writes only
``guard_ok`` and ``guard_codes`` of drafts (never the evidence). It runs when the settings
revision or the deny set differs from the last pass, and once after a start. Reason codes and
counters are the only things logged. It never loosens the check: it is the same one.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_reporting import Evidence, GuardContext, SelfTerms

from .build import check_evidence, default_options, load_report_settings, options_of
from .config import AbuseSettings
from .selfterms import TermsCache

log = logging.getLogger(__name__)

MAX_SESSION_IDS = 5000


@dataclass
class ReguardStats:
    checked: int = 0
    changed: int = 0
    unblocked: int = 0
    blocked: int = 0
    skipped: int = 0  # stored evidence that no longer validates: left as it is


class DraftReguard:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: AbuseSettings,
        terms: TermsCache,
    ) -> None:
        self.factory = factory
        self.settings = settings
        self.terms = terms
        self.last: ReguardStats | None = None
        self._seen: tuple[int | None, SelfTerms] | None = None

    async def run_if_changed(self) -> ReguardStats | None:
        """One pass when the settings revision or the deny set is not the one last checked."""
        terms = await self.terms.get()
        if terms is None:
            return None  # fail closed: the stored results stay as they are
        async with self.factory() as session:
            revision = (
                await session.execute(text("SELECT revision FROM report_settings WHERE id = 1"))
            ).scalar_one_or_none()
        key = (revision, terms)
        if self._seen == key:
            return None
        stats = await self.run(terms)
        self._seen = key  # only after a complete pass: a failure is tried again next cycle
        self.last = stats
        if stats.changed:
            log.info(
                "abuse drafts re-checked: %d checked, %d unblocked, %d blocked",
                stats.checked,
                stats.unblocked,
                stats.blocked,
            )
        return stats

    async def run(self, terms: SelfTerms) -> ReguardStats:
        stats = ReguardStats()
        async with self.factory() as session:
            report_settings, defaults = await load_report_settings(session)
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT r.id, r.id_seed, r.kind, r.demo, r.evidence, r.options,
                               r.guard_ok, r.guard_codes,
                               COALESCE(c.override_mailbox, c.mailbox) AS address
                        FROM abuse_reports r JOIN abuse_recipients c ON c.id = r.recipient_id
                        WHERE r.status = 'draft' ORDER BY r.id LIMIT :n
                        """
                    ),
                    {"n": self.settings.max_open_drafts},
                )
            ).all()
        fallback = default_options(self.settings, defaults)
        for row in rows:
            data = dict(row.evidence)
            data.update(
                kind=row.kind,
                demo=row.demo,
                options=options_of(row.options, fallback).model_dump(),
            )
            if row.address:
                data["recipient"] = row.address
            try:
                evidence = Evidence.model_validate(data)
            except ValidationError:
                stats.skipped += 1
                continue
            async with self.factory() as session:
                ids = await self._internal_ids(session, evidence)
            ctx = GuardContext(
                internal_ids=frozenset(ids) | {row.id_seed.hex}, allow_documentation=row.demo
            )
            result = check_evidence(evidence, report_settings, terms, ctx)
            stats.checked += 1
            if result.ok != row.guard_ok or list(result.codes) != list(row.guard_codes or []):
                async with self.factory() as session, session.begin():
                    await session.execute(
                        text(
                            "UPDATE abuse_reports SET guard_ok = :ok, guard_codes = :codes "
                            "WHERE id = :i AND status = 'draft'"
                        ),
                        {"ok": result.ok, "codes": list(result.codes), "i": row.id},
                    )
                stats.changed += 1
                if result.ok:
                    stats.unblocked += 1
                elif row.guard_ok:
                    stats.blocked += 1
            await asyncio.sleep(0)  # the check is CPU work: let the other workers run
        return stats

    @staticmethod
    async def _internal_ids(session: AsyncSession, evidence: Evidence) -> set[str]:
        """Session ids of the report's sources that overlap its window (a superset of the build)."""
        ips = [s.value for s in evidence.subjects if s.type == "ip"]
        if not ips:
            return set()
        found = await session.execute(
            text(
                "SELECT session_id FROM sessions "
                "WHERE src_ip = ANY(CAST(CAST(:ips AS text[]) AS inet[])) "
                "AND started_at <= :we AND last_event_at >= :ws LIMIT :n"
            ),
            {
                "ips": ips,
                "ws": evidence.window_start,
                "we": evidence.window_end,
                "n": MAX_SESSION_IDS,
            },
        )
        return {r.session_id for r in found}
