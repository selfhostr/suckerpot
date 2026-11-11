"""Node reputation (design M29 section 8.3).

Daily job: rewards for targets confirmed or taken down, and a penalty for volume that nobody
else ever corroborates. Disputes apply at once (``dispute``). The number is never sent to anyone;
below 0.2 a node is soft-suspended: its requests succeed and its data is ignored.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings

START = 0.6  # five fresh eligible nodes weigh exactly HUB_MIN_WEIGHT (3.0)
CONFIRMED_BONUS = 0.01
CONFIRMED_BONUS_MAX_PER_DAY = 0.05
TAKEDOWN_BONUS = 0.02
DISPUTE_PENALTY = 0.1
VOLUME_PENALTY = 0.05
VOLUME_VALUES = 500
VOLUME_UNCORROBORATED = 0.95
SUSPEND_BELOW = 0.2
MARKER = "reputation_day"
MAX_CATCH_UP_DAYS = 3


@dataclass
class ReputationResult:
    days: list[date]
    suspended: int = 0


async def _marker(session: AsyncSession) -> date | None:
    row = (
        await session.execute(text("SELECT value FROM worker_state WHERE key = :k"), {"k": MARKER})
    ).first()
    return date.fromisoformat(row[0]) if row else None


async def _suspend_low(session: AsyncSession) -> int:
    result = await session.execute(
        text(
            "UPDATE nodes SET standing = 'soft_suspended' "
            "WHERE standing = 'active' AND reputation < CAST(:limit AS real)"
        ),
        {"limit": SUSPEND_BELOW},
    )
    return int(getattr(result, "rowcount", 0) or 0)


async def apply_day(
    session: AsyncSession, day: date, volume_min_nodes: int = 5, node_min_age_days: int = 14
) -> int:
    """Rewards and penalties for events of ``day``. Returns the number of suspensions."""
    # +0.01 per target confirmed that day (at most +0.05).
    await session.execute(
        text(
            """
            UPDATE nodes n SET reputation = LEAST(1.0, n.reputation + CAST(:bonus AS real) * LEAST(CAST(:cap AS integer), c.cnt))
            FROM (SELECT tc.node_id, count(*) AS cnt
                  FROM target_contributors tc
                  WHERE tc.target_id IN (
                      -- only values backed by contributors from at least two enrolment cohorts
                      SELECT t.id FROM targets t
                      JOIN target_contributors c ON c.target_id = t.id
                      JOIN nodes m ON m.id = c.node_id
                      WHERE t.confirmed_day = :day
                      GROUP BY t.id
                      HAVING count(DISTINCT date_trunc('week', m.enrolled_day)) >= 2)
                  GROUP BY tc.node_id) c
            WHERE c.node_id = n.id AND n.standing = 'active'
            """
        ),
        {
            "bonus": CONFIRMED_BONUS,
            "cap": round(CONFIRMED_BONUS_MAX_PER_DAY / CONFIRMED_BONUS),
            "day": day,
        },
    )
    # +0.02 per target taken down that day.
    await session.execute(
        text(
            """
            UPDATE nodes n SET reputation = LEAST(1.0, n.reputation + CAST(:bonus AS real) * c.cnt)
            FROM (SELECT tc.node_id, count(*) AS cnt
                  FROM target_contributors tc JOIN targets t ON t.id = tc.target_id
                  WHERE t.taken_down_day = :day GROUP BY tc.node_id) c
            WHERE c.node_id = n.id AND n.standing = 'active'
            """
        ),
        {"bonus": TAKEDOWN_BONUS, "day": day},
    )
    # -0.05 for a node with more than 500 distinct values in 14 days, over 95 % of them seen by
    # nobody else. Only while at least ``volume_min_nodes`` active nodes old enough to count
    # (the consensus age rule) reported in that window: below that, nobody can corroborate
    # anything and an honest lone node would be punished.
    await session.execute(
        text(
            """
            UPDATE nodes n SET reputation = GREATEST(0.0, n.reputation - CAST(:penalty AS real))
            FROM (
              SELECT o.node_id,
                     count(*) AS total,
                     count(*) FILTER (WHERE s.seen_by = 1) AS alone
              FROM (SELECT DISTINCT node_id, kind, value FROM observations
                    WHERE day > :since AND day <= :day) o
              JOIN (SELECT kind, value, count(DISTINCT node_id) AS seen_by FROM observations
                    WHERE day > :since AND day <= :day GROUP BY kind, value) s
                ON s.kind = o.kind AND s.value = o.value
              GROUP BY o.node_id
            ) v
            WHERE v.node_id = n.id AND v.total > CAST(:values AS integer) AND v.alone > CAST(:share AS double precision) * v.total
              AND (SELECT count(DISTINCT w.node_id) FROM observations w
                   JOIN nodes a ON a.id = w.node_id AND a.standing = 'active'
                        AND a.enrolled_day <= :oldest
                   WHERE w.day > :since AND w.day <= :day) >= CAST(:min_nodes AS integer)
            """
        ),
        {
            "penalty": VOLUME_PENALTY,
            "since": day - timedelta(days=14),
            "day": day,
            "values": VOLUME_VALUES,
            "share": VOLUME_UNCORROBORATED,
            "min_nodes": volume_min_nodes,
            "oldest": day - timedelta(days=node_min_age_days),
        },
    )
    return await _suspend_low(session)


async def run_daily(session: AsyncSession, s: Settings, today: date) -> ReputationResult:
    """Process every finished day since the last run (at most three), once each."""
    last = await _marker(session)
    yesterday = today - timedelta(days=1)
    first = yesterday if last is None else last + timedelta(days=1)
    first = max(first, yesterday - timedelta(days=MAX_CATCH_UP_DAYS - 1))
    result = ReputationResult(days=[])
    day = first
    while day <= yesterday:
        result.suspended += await apply_day(session, day, s.volume_min_nodes, s.node_min_age_days)
        result.days.append(day)
        day += timedelta(days=1)
    if result.days:
        await session.execute(
            text(
                "INSERT INTO worker_state (key, value) VALUES (:k, :v) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"k": MARKER, "v": result.days[-1].isoformat()},
        )
    await session.commit()
    return result


async def dispute(session: AsyncSession, target_id: str, s: Settings | None = None) -> int:
    """Mark a target disputed and lower its contributors. Returns the nodes penalised.

    Idempotent: a target that is already disputed is left alone.
    """
    del s
    changed = await session.execute(
        text(
            "UPDATE targets SET state = 'disputed', updated_at = now() "
            "WHERE id = :t AND state <> 'disputed'"
        ),
        {"t": target_id},
    )
    if not getattr(changed, "rowcount", 0):
        await session.commit()
        return 0
    penalised = await session.execute(
        text(
            """
            UPDATE nodes SET reputation = GREATEST(0.0, reputation - CAST(:penalty AS real))
            WHERE id IN (SELECT node_id FROM target_contributors WHERE target_id = :t)
            """
        ),
        {"penalty": DISPUTE_PENALTY, "t": target_id},
    )
    await _suspend_low(session)
    await session.commit()
    return int(getattr(penalised, "rowcount", 0) or 0)
