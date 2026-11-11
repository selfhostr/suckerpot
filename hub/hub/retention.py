"""Retention (design M29 invariant H3). The hub keeps as little as the protocol allows.

* per-node observations: ``HUB_OBS_RETENTION_DAYS`` (14), day granularity;
* batch markers: 14 days; nonces and challenges: until they expire (10 minutes);
* contributor links: when the target is resolved or after 30 days;
* takedown votes: 30 days; weekly statistics: 8 weeks;
* abuse.ch submissions: finished ones 365 days, like reports;
* feeds: removed entries 90 days, runs 30 days, delisting evidence 30 days after the decision,
  decided delisting requests 180 days (open ones wait for their decision, without contact and
  evidence after 180 days), expired allow-list
  rows and payload links straight away;
* verification tasks (clear link included) and their attestations: 14 days after the task ended;
  the daily counters stay;
* observatory aggregates (network-wide, no node reference): 400 days;
* nodes with no request for 30 days are deleted with everything linked to them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings

RESOLVED_STATES = ("taken_down", "expired", "disputed")
RESOLVED_GRACE = timedelta(days=2)  # lets the daily reputation job read the links first
EXPIRED_TARGET_DAYS = 180
CANDIDATE_DAYS = 14
RECIPIENT_LOG_DAYS = 90
REPORT_DAYS = 365
FEED_REMOVED_DAYS = 90
FEED_RUN_DAYS = 30
DELIST_EVIDENCE_DAYS = 30
DELIST_REQUEST_DAYS = 180
VERIFY_TASK_DAYS = 14  # clear links go with their task (H9); attestations cascade
OBSERVATORY_DAYS = 400  # network-wide daily aggregates of the observatory (no node reference)


@dataclass
class RetentionResult:
    deleted: dict[str, int] = field(default_factory=dict)


async def _delete(
    session: AsyncSession, name: str, sql: str, params: dict[str, object], out: RetentionResult
) -> None:
    result = await session.execute(text(sql), params)
    out.deleted[name] = int(getattr(result, "rowcount", 0) or 0)


async def run_retention(
    session: AsyncSession, s: Settings, now: datetime, today: date
) -> RetentionResult:
    out = RetentionResult()
    obs_cutoff = today - timedelta(days=s.obs_retention_days)
    await _delete(
        session, "observations", "DELETE FROM observations WHERE day < :c", {"c": obs_cutoff}, out
    )
    await _delete(
        session,
        "batches",
        "DELETE FROM batches WHERE day < :c",
        {"c": today - timedelta(days=14)},
        out,
    )
    await _delete(session, "nonces", "DELETE FROM nonces WHERE expires_at < :n", {"n": now}, out)
    await _delete(
        session, "challenges", "DELETE FROM enrol_challenges WHERE expires_at < :n", {"n": now}, out
    )
    await _delete(
        session,
        "contributors",
        """
        DELETE FROM target_contributors tc USING targets t
        WHERE t.id = tc.target_id
          AND ((t.state = ANY(:resolved) AND t.updated_at < :grace)
               OR coalesce(t.confirmed_day, t.first_day) < :old)
        """,
        {
            "resolved": list(RESOLVED_STATES),
            "grace": now - RESOLVED_GRACE,
            "old": today - timedelta(days=s.contributor_retention_days),
        },
        out,
    )
    await _delete(
        session,
        "votes",
        "DELETE FROM takedown_votes WHERE day < :c",
        {"c": today - timedelta(days=s.vote_retention_days)},
        out,
    )
    await _delete(
        session,
        "recheck_assignments",
        "DELETE FROM recheck_assignments WHERE day < :c",
        {"c": today - timedelta(days=3)},
        out,
    )
    await _delete(
        session,
        "candidates",
        "DELETE FROM targets WHERE state = 'candidate' AND coalesce(last_day, first_day) < :c",
        {"c": today - timedelta(days=CANDIDATE_DAYS)},
        out,
    )
    await _delete(
        session,
        "old_targets",
        "DELETE FROM targets WHERE state = 'expired' AND updated_at < :c",
        {"c": now - timedelta(days=EXPIRED_TARGET_DAYS)},
        out,
    )
    await _delete(
        session,
        "recipient_log",
        "DELETE FROM recipient_log WHERE day < :c",
        {"c": today - timedelta(days=RECIPIENT_LOG_DAYS)},
        out,
    )
    await _delete(
        session,
        "reports",
        "DELETE FROM reports WHERE state IN ('sent', 'failed', 'cancelled') AND created_day < :c",
        {"c": today - timedelta(days=REPORT_DAYS)},
        out,
    )
    await _delete(
        session,
        "abusech_submissions",
        "DELETE FROM abusech_submissions WHERE state IN ('sent', 'failed', 'rejected') "
        "AND created_day < :c",
        {"c": today - timedelta(days=REPORT_DAYS)},
        out,
    )
    # Feeds (design M30 section 7.4). feed_daily and feed_auto_ranges are kept on purpose.
    await _delete(
        session,
        "feed_entries",
        "DELETE FROM feed_entries WHERE state = 'removed' AND removed_day < :c",
        {"c": today - timedelta(days=FEED_REMOVED_DAYS)},
        out,
    )
    await _delete(
        session,
        "feed_runs",
        "DELETE FROM feed_runs WHERE run_at < :c",
        {"c": now - timedelta(days=FEED_RUN_DAYS)},
        out,
    )
    await _delete(
        session,
        "feed_allow",
        "DELETE FROM feed_allow WHERE expires_day < :t",
        {"t": today},
        out,
    )
    await _delete(
        session,
        "payload_links",
        "DELETE FROM payload_links WHERE day < :c",
        {"c": obs_cutoff},
        out,
    )
    await _delete(
        session,
        "delist_challenges",
        "DELETE FROM delist_challenges WHERE expires_at < :n",
        {"n": now},
        out,
    )
    await _delete(
        session,
        "delist_evidence",
        "UPDATE delist_requests SET evidence = NULL, contact = NULL "
        "WHERE decided_day < :c AND (evidence IS NOT NULL OR contact IS NOT NULL)",
        {"c": today - timedelta(days=DELIST_EVIDENCE_DAYS)},
        out,
    )
    await _delete(
        session,
        "delist_open_evidence",
        # An open request keeps its row (and its suppression) until a decision, but not the
        # requester's contact and evidence beyond 180 days (security re-review L2).
        "UPDATE delist_requests SET evidence = NULL, contact = NULL "
        "WHERE decided_day IS NULL AND created_day < :c "
        "AND (evidence IS NOT NULL OR contact IS NOT NULL)",
        {"c": today - timedelta(days=DELIST_REQUEST_DAYS)},
        out,
    )
    await _delete(
        session,
        "delist_requests",
        # Decided requests only: deleting an open one would silently lift its suppression and
        # drop it from the operator queue (security review L3).
        "DELETE FROM delist_requests WHERE created_day < :c AND decided_day IS NOT NULL",
        {"c": today - timedelta(days=DELIST_REQUEST_DAYS)},
        out,
    )
    await _delete(
        session,
        "verify_tasks",
        "DELETE FROM verify_tasks WHERE ended_day < :c",
        {"c": today - timedelta(days=VERIFY_TASK_DAYS)},
        out,
    )
    await _delete(
        session,
        "observatory_daily",
        "DELETE FROM observatory_daily WHERE day < :c",
        {"c": today - timedelta(days=OBSERVATORY_DAYS)},
        out,
    )
    await _delete(
        session,
        "inactive_nodes",
        "DELETE FROM nodes WHERE last_active_day < :c",
        {"c": today - timedelta(days=s.inactive_node_days)},
        out,
    )
    await session.commit()
    return out
