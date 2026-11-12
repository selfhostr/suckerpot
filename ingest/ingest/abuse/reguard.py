"""Re-check the open drafts when the owner's wording or the deny set changed.

A draft keeps the result of its identity check (``guard_ok``, ``guard_codes``) from the moment it
was built, and the lists show that stored result. The builder refreshes it only for the drafts it
rebuilds, once an hour and within the lookup cap. Without this pass a reply contact fixed in
Settings would leave every draft marked blocked for up to an hour (or longer for a draft the cap
skips), and a new deny term would leave a leaking draft marked clean.

The pass needs no lookup and no rebuild: it renders every open draft again from its stored
evidence and the current settings, runs the same check as the builder (on the text, the X-ARF
and the ``.eml`` that the owner copies or the send path builds) and writes only ``guard_ok`` and
``guard_codes`` of drafts (never the evidence). It runs for all drafts when the settings revision
or the deny set differs from the last pass (and once after a start), and for a single draft when
its options changed (the owner's PATCH). Reason codes and counters are the only things logged.

It never loosens the check. The codes that depend on the evidence itself (an internal id, a
private or a documentation address) are set by the build, which reads the sessions behind the
evidence; this pass cannot replay that read, so it keeps them and only the build may clear them.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_reporting import (
    Evidence,
    GuardContext,
    GuardResult,
    ReferenceStyle,
    ReportOptions,
    ReportSettings,
    SelfTerms,
)

from .build import check_evidence, default_options, load_report_settings, options_of
from .config import AbuseSettings
from .selfterms import TermsCache
from .session_ids import internal_session_ids

log = logging.getLogger(__name__)

# Reason codes that come from the evidence, not from the owner's wording or the deny set.
EVIDENCE_CODES = frozenset({"internal_id", "private_address", "documentation_address"})

_COLUMNS = """
    SELECT r.id, r.id_seed, r.kind, r.demo, r.evidence, r.options, r.guard_ok, r.guard_codes,
           r.reply_token, COALESCE(c.override_mailbox, c.mailbox) AS address
    FROM abuse_reports r JOIN abuse_recipients c ON c.id = r.recipient_id
"""
_ALL_DRAFTS = text(_COLUMNS + "WHERE r.status = 'draft' ORDER BY r.id LIMIT :n")
_SOME_DRAFTS = text(
    _COLUMNS + "WHERE r.status = 'draft' AND r.id = ANY(:only) ORDER BY r.id LIMIT :n"
)


@dataclass
class ReguardStats:
    checked: int = 0
    changed: int = 0
    unblocked: int = 0
    blocked: int = 0
    skipped: int = 0  # evidence that does not validate, or a draft whose check failed: left as is


def keep_evidence_codes(result: GuardResult, stored: list[str] | None) -> GuardResult:
    """``result`` plus the evidence codes the build stored: only the build may clear those."""
    kept = EVIDENCE_CODES.intersection(stored or ())
    if not kept - set(result.codes):
        return result
    codes = tuple(sorted({*result.codes, *kept}))
    return GuardResult(ok=False, codes=codes, counts=dict(result.counts))


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
        self._options: dict[int, str] = {}  # draft id to a hash of its options, as last checked

    async def run_if_changed(self) -> ReguardStats | None:
        """A pass when the settings revision or the deny set is not the one last checked, else a
        pass over the drafts whose options changed since (the owner's edit), else nothing."""
        terms = await self.terms.get()
        if terms is None:
            return None  # fail closed: the stored results stay as they are
        async with self.factory() as session:
            revision = (
                await session.execute(text("SELECT revision FROM report_settings WHERE id = 1"))
            ).scalar_one_or_none()
            options = {
                r.id: r.h
                for r in await session.execute(
                    text(
                        "SELECT id, md5(options::text) AS h FROM abuse_reports "
                        "WHERE status = 'draft' ORDER BY id LIMIT :n"
                    ),
                    {"n": self.settings.max_open_drafts},
                )
            }
        key = (revision, terms)
        only: frozenset[int] | None = None
        if self._seen == key:
            # A draft is new to this pass (the build just checked it) or its options differ.
            edited = frozenset(i for i, h in options.items() if self._options.get(i) != h)
            if not edited:
                self._options = options
                return None
            only = edited
        stats = await self.run(terms, only)
        # Only after a complete pass: a failure (the database went away) is tried again next cycle.
        self._seen = key
        self._options = options
        self.last = stats
        if stats.changed:
            log.info(
                "abuse drafts re-checked: %d checked, %d unblocked, %d blocked",
                stats.checked,
                stats.unblocked,
                stats.blocked,
            )
        return stats

    async def run(self, terms: SelfTerms, only: frozenset[int] | None = None) -> ReguardStats:
        stats = ReguardStats()
        async with self.factory() as session:
            report_settings, defaults, style = await load_report_settings(session)
            limit = {"n": self.settings.max_open_drafts}
            rows = (
                await session.execute(
                    _ALL_DRAFTS if only is None else _SOME_DRAFTS,
                    limit if only is None else {**limit, "only": sorted(only)},
                )
            ).all()
        fallback = default_options(self.settings, defaults)
        for row in rows:
            try:
                await self._check_one(row, terms, report_settings, fallback, style, stats)
            except SQLAlchemyError:
                raise  # the database is not answering: the pass is tried again next cycle
            except Exception as exc:  # one bad draft must not stop the others
                log.warning("abuse draft re-check failed (%s)", type(exc).__name__)
                stats.skipped += 1
            await asyncio.sleep(0)  # the check is CPU work: let the other workers run
        return stats

    async def _check_one(
        self,
        row: Any,
        terms: SelfTerms,
        report_settings: ReportSettings,
        fallback: ReportOptions,
        style: ReferenceStyle,
        stats: ReguardStats,
    ) -> None:
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
            return
        async with self.factory() as session:
            ids = await internal_session_ids(session, evidence)
        ctx = GuardContext(
            internal_ids=frozenset(ids) | {row.id_seed.hex}, allow_documentation=row.demo
        )
        result = check_evidence(
            evidence,
            report_settings,
            terms,
            ctx,
            reply_token=row.reply_token,
            reference_style=style,
        )
        result = keep_evidence_codes(result, row.guard_codes)
        stats.checked += 1
        if result.ok == row.guard_ok and list(result.codes) == list(row.guard_codes or []):
            return
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
