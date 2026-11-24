"""What came of a report (design M26, section 8). Pure derivation plus the ingest-side upkeep.

Only verified replies count (O7): a reply nobody vouched for is shown to the owner but never
changes the automatic outcome. The owner's override (``manual_outcome``) lives in other columns
that this module cannot write (column grants).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .desk import learn_linked

log = logging.getLogger(__name__)

# Highest first. ``none`` means no verified reply at all.
PRECEDENCE: Final = (
    "resolved",
    "rejected",
    "ticket_opened",
    "human_reply",
    "auto_ack",
    "bounce",
    "unknown",
)
BATCH: Final = 500


@dataclass(frozen=True, slots=True)
class ReplyFact:
    classification: str
    received_at: datetime
    verified: bool
    reviewed: bool = False
    ticket_id: str | None = None


@dataclass(frozen=True, slots=True)
class Summary:
    auto_outcome: str = "none"
    reply_count: int = 0
    first_reply_at: datetime | None = None
    first_human_at: datetime | None = None
    ticket_at: datetime | None = None
    resolved_at: datetime | None = None
    rejected_at: datetime | None = None
    bounced_at: datetime | None = None
    ticket_id: str | None = None
    needs_review: bool = False


def derive(replies: Iterable[ReplyFact]) -> str:
    """The automatic outcome from verified replies, by precedence."""
    seen = {r.classification for r in replies if r.verified}
    for outcome in PRECEDENCE:
        if outcome in seen:
            return outcome
    return "none"


def _first(facts: list[ReplyFact], *kinds: str) -> datetime | None:
    times = [f.received_at for f in facts if f.classification in kinds]
    return min(times) if times else None


def summarise(replies: Iterable[ReplyFact]) -> Summary:
    """Every ingest-written column of ``abuse_report_outcomes`` for one report."""
    all_replies = list(replies)
    verified = [r for r in all_replies if r.verified]
    tickets = sorted(
        (r for r in verified if r.ticket_id), key=lambda r: r.received_at, reverse=True
    )
    answers = [r for r in verified if r.classification != "bounce"]
    return Summary(
        auto_outcome=derive(all_replies),
        reply_count=len(all_replies),
        first_reply_at=min((r.received_at for r in answers), default=None),
        first_human_at=_first(verified, "human_reply", "resolved", "rejected"),
        ticket_at=_first(verified, "ticket_opened"),
        resolved_at=_first(verified, "resolved"),
        rejected_at=_first(verified, "rejected"),
        bounced_at=_first(verified, "bounce"),
        ticket_id=tickets[0].ticket_id if tickets else None,
        # A reply nobody vouched for, or a bounce, waits for the owner until they look at it.
        needs_review=any(
            not r.reviewed and (not r.verified or r.classification == "bounce") for r in all_replies
        ),
    )


CREATE_ROWS = """
INSERT INTO abuse_report_outcomes (report_id)
SELECT r.id FROM abuse_reports r
WHERE r.status IN ('sent', 'closed') AND NOT r.demo
  AND NOT EXISTS (SELECT 1 FROM abuse_report_outcomes o WHERE o.report_id = r.id)
ORDER BY r.id LIMIT :n
ON CONFLICT (report_id) DO NOTHING
"""
# Reports whose replies changed since their outcome was last computed: a new or reviewed reply,
# or a different number of replies (one moved away). Least recently computed first, so a busy
# old report can never starve a newer one. A recompute always stamps ``auto_updated_at``.
CANDIDATES = """
SELECT o.report_id FROM abuse_report_outcomes o
WHERE EXISTS (SELECT 1 FROM abuse_replies p WHERE p.report_id = o.report_id
              AND (o.auto_updated_at IS NULL OR p.processed_at > o.auto_updated_at
                   OR p.reviewed_at > o.auto_updated_at))
   OR o.reply_count <> (SELECT count(*) FROM abuse_replies p WHERE p.report_id = o.report_id)
ORDER BY o.auto_updated_at NULLS FIRST, o.report_id LIMIT :n
"""
TOUCH_ROW = "UPDATE abuse_report_outcomes SET auto_updated_at = now() WHERE report_id = :r"
LOAD_REPLIES = """
SELECT classification, received_at, verified, reviewed_at IS NOT NULL AS reviewed, ticket_id
FROM abuse_replies WHERE report_id = :r ORDER BY received_at, id LIMIT 1000
"""
SINCE = "SELECT auto_updated_at FROM abuse_report_outcomes WHERE report_id = :r"
LOAD_ROW = """
SELECT auto_outcome, reply_count, first_reply_at, first_human_at, ticket_at, resolved_at,
       rejected_at, bounced_at, ticket_id, needs_review
FROM abuse_report_outcomes WHERE report_id = :r
"""
SAVE_ROW = """
UPDATE abuse_report_outcomes SET auto_outcome = :auto_outcome, reply_count = :reply_count,
    first_reply_at = :first_reply_at, first_human_at = :first_human_at, ticket_at = :ticket_at,
    resolved_at = :resolved_at, rejected_at = :rejected_at, bounced_at = :bounced_at,
    ticket_id = :ticket_id, needs_review = :needs_review, auto_updated_at = now()
WHERE report_id = :r
"""
FIELDS = tuple(Summary.__dataclass_fields__)


async def ensure_rows(factory: async_sessionmaker[AsyncSession]) -> int:
    """An outcome row for each sent or closed report that has none. Returns how many."""
    async with factory() as session, session.begin():
        result = await session.execute(text(CREATE_ROWS), {"n": BATCH})
        return int(result.rowcount or 0)  # type: ignore[attr-defined]


async def recompute(factory: async_sessionmaker[AsyncSession]) -> int:
    """Refresh the automatic columns of the reports whose replies may have changed."""
    changed = 0
    async with factory() as session:
        ids = (await session.execute(text(CANDIDATES), {"n": BATCH})).scalars().all()
    for report_id in ids:
        async with factory() as session, session.begin():
            # A reply the owner linked by hand since the last pass teaches about the desk too.
            since = (await session.execute(text(SINCE), {"r": report_id})).scalar()
            await learn_linked(session, report_id, since)
            rows = (await session.execute(text(LOAD_REPLIES), {"r": report_id})).all()
            summary = summarise(
                ReplyFact(r.classification, r.received_at, r.verified, r.reviewed, r.ticket_id)
                for r in rows
            )
            current = (await session.execute(text(LOAD_ROW), {"r": report_id})).first()
            values = {name: getattr(summary, name) for name in FIELDS}
            if current is not None and all(
                current._mapping[name] == values[name] for name in FIELDS
            ):
                await session.execute(text(TOUCH_ROW), {"r": report_id})
                continue
            await session.execute(text(SAVE_ROW), {"r": report_id, **values})
            changed += 1
    return changed
