"""Live identity check (M22): ``python -m api.abuse_selfcheck`` (``just abuse-guard-check``).

Renders every open or sent report in every format, builds a STIX and a MISP export of the last
7 days, and runs the identity guard on each. Prints PASS, FAIL and SKIP counts per format and the
reason codes, never a value. Exits non-zero on any failure, or when the monitored system's address
is not known yet.
"""

from __future__ import annotations

import asyncio
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import create_engine, create_session_factory
from suckerpot_db.models import AbuseRecipientRow, AbuseReportRow
from suckerpot_reporting import GuardFailed, RenderUnavailable

from api.abuse_core import (
    EvidenceInvalidError,
    guard_context,
    load_evidence,
    load_settings,
    load_terms,
    release,
    render_checked,
    reply_args,
)
from api.abuse_exports import build_export

FORMATS = ("text", "xarf", "eml")
SINCE_DAYS = 7


class Tally:
    def __init__(self) -> None:
        self.counts: dict[str, Counter[str]] = {}
        self.codes: dict[str, Counter[str]] = {}

    def add(self, fmt: str, outcome: str, codes: tuple[str, ...] = ()) -> None:
        self.counts.setdefault(fmt, Counter())[outcome] += 1
        self.codes.setdefault(fmt, Counter()).update(codes)

    @property
    def failures(self) -> int:
        return sum(c["FAIL"] for c in self.counts.values())


async def check_reports(db: AsyncSession, tally: Tally) -> None:
    bundle = await load_settings(db)
    terms = await load_terms(db, fresh=True)
    rows = (
        await db.execute(
            select(AbuseReportRow, AbuseRecipientRow)
            .join(AbuseRecipientRow, AbuseRecipientRow.id == AbuseReportRow.recipient_id)
            .where(AbuseReportRow.status.notin_(("discarded", "superseded")))
            .order_by(AbuseReportRow.id)
        )
    ).all()
    for row, rec in rows:
        try:
            evidence = await load_evidence(db, row, rec, bundle)
        except EvidenceInvalidError:
            for fmt in FORMATS:
                tally.add(fmt, "FAIL", ("evidence_invalid",))
            continue
        ctx = await guard_context(db, row, evidence)
        for fmt in FORMATS:
            try:
                rendered = await asyncio.to_thread(
                    render_checked,
                    evidence,
                    bundle.settings,
                    terms,
                    ctx,
                    fmt,
                    **reply_args(row, bundle),
                )
                release(rendered.guard)
            except GuardFailed as exc:
                tally.add(fmt, "FAIL", exc.codes)
            except RenderUnavailable as exc:
                tally.add(fmt, "SKIP", (exc.code,))
            else:
                tally.add(fmt, "PASS")


async def check_exports(db: AsyncSession, tally: Tally) -> None:
    now = datetime.now(UTC)
    kinds: tuple[Literal["stix"], Literal["misp"]] = ("stix", "misp")
    for kind in kinds:
        try:
            built = await build_export(
                db,
                kind,
                report=None,
                campaign=None,
                since=now - timedelta(days=SINCE_DAYS),
                until=now,
                tlp=None,
            )
        except GuardFailed as exc:
            tally.add(kind, "FAIL", exc.codes)
            continue
        if isinstance(built, tuple):
            tally.add(kind, "PASS")
        else:
            tally.add(kind, "SKIP", ("no_indicators",))


async def run() -> int:
    engine = create_engine()
    tally = Tally()
    try:
        async with create_session_factory(engine)() as db:
            terms = await load_terms(db, fresh=True)
            if terms is None:
                tally.add("deny_set", "FAIL", ("self_terms_unavailable",))
            elif not terms.has_self_address:
                tally.add("deny_set", "FAIL", ("no_self_address",))
            else:
                tally.add("deny_set", "PASS")
            await check_reports(db, tally)
            await check_exports(db, tally)
    finally:
        await engine.dispose()
    for fmt, counts in tally.counts.items():
        codes = ",".join(sorted(tally.codes[fmt])) or "-"
        print(
            f"{fmt:9} PASS {counts['PASS']:4} FAIL {counts['FAIL']:4} "
            f"SKIP {counts['SKIP']:4}  codes: {codes}"
        )
    verdict = "FAIL" if tally.failures else "PASS"
    print(f"{verdict}  identity guard ({tally.failures} failure(s))")
    return 1 if tally.failures else 0


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
