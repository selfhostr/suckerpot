"""The monthly roll-up (design M27 section 8): aggregates only, kept forever.

The counting is pure (``build_rollup``) and shares ``suckerpot_db.takedown_stats`` with the API.
Report outcomes come from M26's ``abuse_report_outcomes``; when that table is missing or not
readable the roll-up simply carries no outcome counts. It holds no values, no URLs, no addresses.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.takedown_stats import (
    TAKEDOWN_ROLES,
    Fact,
    median_ttd,
    window_counts,
)

log = logging.getLogger(__name__)
Factory = async_sessionmaker[AsyncSession]

ANSWERED = frozenset({"auto_ack", "ticket_opened", "resolved", "rejected", "human_reply"})
OUTCOME_COLUMN = {
    "auto_ack": "auto_ack",
    "ticket_opened": "ticket_opened",
    "resolved": "resolved",
    "rejected": "rejected",
    "bounce": "bounced",
    "human_reply": "human_reply",
}


@dataclass(frozen=True, slots=True)
class RollTarget:
    role: str
    provider_key: str
    channels: tuple[str, ...]
    reported_at: datetime
    observed_until: datetime
    asn: int | None = None
    country: str | None = None
    first_down_at: datetime | None = None
    down_before_report: bool = False


@dataclass(frozen=True, slots=True)
class RollReport:
    """One report (or submission) that put a target of this group under tracking."""

    role: str
    provider_key: str
    channel: str
    month: date
    outcome: str | None = None  # effective M26 outcome, None when unknown
    first_reply_s: float | None = None


@dataclass(slots=True)
class RollRow:
    month: date
    provider_key: str
    kind: str
    channel: str
    asn: int | None = None
    country: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    ttd_p50_s: int | None = None
    first_reply_p50_s: int | None = None


def month_of(moment: datetime) -> date:
    m = moment.astimezone(UTC)
    return date(m.year, m.month, 1)


def _p50(values: list[float]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return int(ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2)


def build_rollup(
    targets: list[RollTarget], reports: list[RollReport], months: set[date]
) -> list[RollRow]:
    """Rows for ``months`` only. Demo targets must already be filtered out."""
    groups: dict[tuple[date, str, str, str], RollRow] = {}
    facts: dict[tuple[date, str, str, str], list[Fact]] = defaultdict(list)

    def row(key: tuple[date, str, str, str]) -> RollRow:
        if key not in groups:
            groups[key] = RollRow(*key)
        return groups[key]

    for t in targets:
        month = month_of(t.reported_at)
        if month not in months:
            continue
        for channel in t.channels:
            key = (month, t.provider_key, t.role, channel)
            r = row(key)
            r.counts["targets"] = r.counts.get("targets", 0) + 1
            r.asn = r.asn if r.asn is not None else t.asn
            r.country = r.country or t.country
            if t.role in TAKEDOWN_ROLES:
                facts[key].append(
                    Fact(
                        role=t.role,
                        provider_key=t.provider_key,
                        reported_at=t.reported_at,
                        observed_until=t.observed_until,
                        first_down_at=t.first_down_at,
                        down_before_report=t.down_before_report,
                    )
                )
    for key, fs in facts.items():
        r = groups[key]
        for label, hours in (("48h", 48), ("7d", 168), ("30d", 720)):
            eligible, down = window_counts(fs, hours)
            r.counts[f"targets_eligible_{label}"] = eligible
            r.counts[f"targets_down_{label}"] = down
        r.ttd_p50_s = median_ttd(fs)[0]

    replies: dict[tuple[date, str, str, str], list[float]] = defaultdict(list)
    for rep in reports:
        if rep.month not in months:
            continue
        key = (rep.month, rep.provider_key, rep.role, rep.channel)
        r = row(key)
        r.counts["reports_sent"] = r.counts.get("reports_sent", 0) + 1
        if rep.outcome in ANSWERED:
            r.counts["reports_answered"] = r.counts.get("reports_answered", 0) + 1
        column = OUTCOME_COLUMN.get(rep.outcome or "")
        if column:
            r.counts[column] = r.counts.get(column, 0) + 1
        if rep.first_reply_s is not None:
            replies[key].append(rep.first_reply_s)
    for key, values in replies.items():
        groups[key].first_reply_p50_s = _p50(values)
    return sorted(groups.values(), key=lambda g: (g.month, g.provider_key, g.kind, g.channel))


TARGETS_SQL = """
SELECT role, provider_key, channels, reported_at, track_until, stopped_at, asn, country,
       first_down_at, down_before_report
FROM takedown_targets
WHERE NOT demo AND reported_at >= :frm
"""

REPORTS_BASE = """
SELECT DISTINCT ON (l.report_id, t.provider_key, t.role)
       t.role, t.provider_key, r.sent_at, r.sent_via {extra}
FROM takedown_target_links l
JOIN takedown_targets t ON t.id = l.target_id
JOIN abuse_reports r ON r.id = l.report_id
{join}
WHERE l.report_id IS NOT NULL AND NOT t.demo AND r.sent_at >= :frm
ORDER BY l.report_id, t.provider_key, t.role
"""
OUTCOME_EXTRA = (
    ", COALESCE(o.manual_outcome, o.auto_outcome) AS outcome, "
    "EXTRACT(epoch FROM (o.first_reply_at - r.sent_at)) AS first_reply_s"
)
OUTCOME_JOIN = "LEFT JOIN abuse_report_outcomes o ON o.report_id = r.id"

SUBMISSIONS_SQL = """
SELECT DISTINCT ON (l.submission_id, t.provider_key, t.role)
       t.role, t.provider_key, s.platform, s.submitted_at
FROM takedown_target_links l
JOIN takedown_targets t ON t.id = l.target_id
JOIN abusech_submissions s ON s.id = l.submission_id
WHERE l.submission_id IS NOT NULL AND NOT t.demo AND s.submitted_at >= :frm
ORDER BY l.submission_id, t.provider_key, t.role
"""

UPSERT = """
INSERT INTO outcome_rollup_monthly
    (month, provider_key, kind, channel, asn, country, reports_sent, reports_answered,
     auto_ack, ticket_opened, resolved, rejected, bounced, human_reply, targets,
     targets_eligible_48h, targets_down_48h, targets_eligible_7d, targets_down_7d,
     targets_eligible_30d, targets_down_30d, ttd_p50_s, first_reply_p50_s, computed_at)
VALUES
    (:month, :provider_key, :kind, :channel, :asn, :country, :reports_sent, :reports_answered,
     :auto_ack, :ticket_opened, :resolved, :rejected, :bounced, :human_reply, :targets,
     :targets_eligible_48h, :targets_down_48h, :targets_eligible_7d, :targets_down_7d,
     :targets_eligible_30d, :targets_down_30d, :ttd_p50_s, :first_reply_p50_s, now())
ON CONFLICT (month, provider_key, kind, channel) DO UPDATE SET
    asn = EXCLUDED.asn, country = EXCLUDED.country, reports_sent = EXCLUDED.reports_sent,
    reports_answered = EXCLUDED.reports_answered, auto_ack = EXCLUDED.auto_ack,
    ticket_opened = EXCLUDED.ticket_opened, resolved = EXCLUDED.resolved,
    rejected = EXCLUDED.rejected, bounced = EXCLUDED.bounced,
    human_reply = EXCLUDED.human_reply, targets = EXCLUDED.targets,
    targets_eligible_48h = EXCLUDED.targets_eligible_48h,
    targets_down_48h = EXCLUDED.targets_down_48h,
    targets_eligible_7d = EXCLUDED.targets_eligible_7d,
    targets_down_7d = EXCLUDED.targets_down_7d,
    targets_eligible_30d = EXCLUDED.targets_eligible_30d,
    targets_down_30d = EXCLUDED.targets_down_30d, ttd_p50_s = EXCLUDED.ttd_p50_s,
    first_reply_p50_s = EXCLUDED.first_reply_p50_s, computed_at = now()
"""
COUNT_COLUMNS = (
    "reports_sent reports_answered auto_ack ticket_opened resolved rejected bounced "
    "human_reply targets targets_eligible_48h targets_down_48h targets_eligible_7d "
    "targets_down_7d targets_eligible_30d targets_down_30d"
).split()


def months_to_compute(now: datetime) -> tuple[set[date], datetime]:
    """The current and the previous month, and the start of the earlier one."""
    current = month_of(now)
    previous = (
        date(current.year - 1, 12, 1)
        if current.month == 1
        else date(current.year, current.month - 1, 1)
    )
    return {current, previous}, datetime(previous.year, previous.month, 1, tzinfo=UTC)


async def _reports(session: AsyncSession, frm: datetime) -> list[RollReport]:
    out: list[RollReport] = []
    rows: Sequence[Any]
    try:
        async with session.begin_nested():
            rows = (
                await session.execute(
                    text(REPORTS_BASE.format(extra=OUTCOME_EXTRA, join=OUTCOME_JOIN)),
                    {"frm": frm},
                )
            ).all()
    except DBAPIError:
        # M26 not applied yet, or not readable: carry no outcomes.
        rows = (
            await session.execute(
                text(
                    REPORTS_BASE.format(extra=", NULL AS outcome, NULL AS first_reply_s", join="")
                ),
                {"frm": frm},
            )
        ).all()
    for r in rows:
        out.append(
            RollReport(
                r.role,
                r.provider_key,
                "form" if r.sent_via == "form" else "mail",
                month_of(r.sent_at),
                r.outcome,
                float(r.first_reply_s) if r.first_reply_s is not None else None,
            )
        )
    for r in (await session.execute(text(SUBMISSIONS_SQL), {"frm": frm})).all():
        out.append(RollReport(r.role, r.provider_key, r.platform, month_of(r.submitted_at)))
    return out


async def recompute(factory: Factory, now: datetime) -> int:
    """Rebuild the current and the previous month. Returns how many rows were written."""
    months, frm = months_to_compute(now)
    async with factory() as session, session.begin():
        trows = (await session.execute(text(TARGETS_SQL), {"frm": frm})).all()
        targets = [
            RollTarget(
                role=t.role,
                provider_key=t.provider_key,
                channels=tuple(t.channels),
                reported_at=t.reported_at,
                observed_until=min(now, t.track_until, t.stopped_at or t.track_until),
                asn=t.asn,
                country=t.country,
                first_down_at=t.first_down_at,
                down_before_report=t.down_before_report,
            )
            for t in trows
        ]
        reports = await _reports(session, frm)
        rows = build_rollup(targets, reports, months)
        for r in rows:
            params: dict[str, Any] = {c: r.counts.get(c, 0) for c in COUNT_COLUMNS}
            params.update(
                month=r.month, provider_key=r.provider_key, kind=r.kind, channel=r.channel,
                asn=r.asn, country=r.country, ttd_p50_s=r.ttd_p50_s,
                first_reply_p50_s=r.first_reply_p50_s,
            )  # fmt: skip
            await session.execute(text(UPSERT), params)
    return len(rows)
