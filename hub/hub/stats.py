"""Coarse member statistics and the daily network summary (design M29 section 7.1).

Nothing here is per-node and fine-grained: members get an activity count of the last full ISO
week (0 to 7 days) and a tier (0 to 4, log scale), published with that week's delay. Countries
appear only when at least two members who chose to show one share it
(``buckets.MIN_MEMBERS_COUNTRY_SHOWN``).
"""

from __future__ import annotations

import hashlib
import json
import statistics
from datetime import date, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto import buckets, models, sign

from . import dormant

WEEKS_SHOWN = 12


def last_full_week(today: date) -> date:
    """Monday of the last ISO week that has ended."""
    this_monday = today - timedelta(days=today.weekday())
    return this_monday - timedelta(days=7)


TIER_KIND_CAP = 1000  # contributions counted per kind
TIER_NOISE = 0.25  # +- share of random-looking, stable noise


def noisy(count: int, week: date, node_id: object) -> int:
    """Count with a stable per-node-and-week jitter, so a tier edge is not a precise gauge."""
    h = hashlib.sha256(f"{week.isoformat()}|{node_id}".encode()).digest()
    unit = int.from_bytes(h[:4], "big") / 0xFFFFFFFF  # 0..1
    return round(count * (1 + (unit * 2 - 1) * TIER_NOISE))


async def weekly_stats(session: AsyncSession, today: date) -> int:
    """Upsert ``node_stats_weekly`` for the last full week. Returns the rows written.

    The tier counts only contributions to values that reached consensus in that week (never what
    a node merely sent, which an attacker can flood), capped per kind and with a stable jitter.
    """
    week = last_full_week(today)
    end = week + timedelta(days=7)
    rows = (
        await session.execute(
            text(
                """
                SELECT n.id,
                       (SELECT count(*) FROM batches b
                        WHERE b.node_id = n.id AND b.items > 0
                          AND b.day >= :week AND b.day < :end) AS active_days
                FROM nodes n WHERE n.enrolled_day < :end
                """
            ),
            {"week": week, "end": end},
        )
    ).all()
    contributions: dict[object, int] = {}
    for r in (
        await session.execute(
            text(
                """
                SELECT tc.node_id, t.kind, count(*) AS n
                FROM target_contributors tc JOIN targets t ON t.id = tc.target_id
                WHERE t.confirmed_day >= :week AND t.confirmed_day < :end
                  AND t.state <> 'candidate'
                GROUP BY tc.node_id, t.kind
                """
            ),
            {"week": week, "end": end},
        )
    ).all():
        contributions[r.node_id] = contributions.get(r.node_id, 0) + min(int(r.n), TIER_KIND_CAP)
    payload = [
        {
            "n": r.id,
            "w": week,
            "a": min(int(r.active_days), 7),
            "t": buckets.tier(noisy(contributions.get(r.id, 0), week, r.id)),
        }
        for r in rows
    ]
    if payload:
        await session.execute(
            text(
                "INSERT INTO node_stats_weekly (node_id, week, active_days, tier) "
                "VALUES (:n, :w, :a, :t) ON CONFLICT (node_id, week) DO UPDATE "
                "SET active_days = EXCLUDED.active_days, tier = EXCLUDED.tier"
            ),
            payload,
        )
    await session.execute(
        text("DELETE FROM node_stats_weekly WHERE week < :old"),
        {"old": week - timedelta(days=7 * 8)},
    )
    await session.commit()
    return len(payload)


async def daily_row(
    session: AsyncSession, today: date, dormant_days: int = dormant.DORMANT_DAYS
) -> None:
    """The ``network_daily`` row of today (transitions counted by their recorded day)."""
    counted = await dormant.count_params(session, today, dormant_days)
    row = (
        await session.execute(
            text(
                f"""
                SELECT
                  (SELECT count(*) FROM nodes n WHERE {dormant.ACTIVE}) AS members,
                  (SELECT count(DISTINCT node_id) FROM batches
                   WHERE day >= :recent AND day < :today) AS active,
                  (SELECT count(*) FROM targets WHERE confirmed_day = :today) AS confirmed,
                  (SELECT count(*) FROM targets WHERE reported_day = :today) AS reported,
                  (SELECT count(*) FROM targets WHERE taken_down_day = :today) AS taken_down
                """  # noqa: S608
            ),
            {"today": today, "recent": today - timedelta(days=7), **counted},
        )
    ).one()
    await session.execute(
        text(
            "INSERT INTO network_daily (day, active_nodes, members, confirmed, reported, taken_down) "
            "VALUES (:d, :a, :m, :c, :r, :t) ON CONFLICT (day) DO UPDATE SET "
            "active_nodes = EXCLUDED.active_nodes, members = EXCLUDED.members, "
            "confirmed = EXCLUDED.confirmed, reported = EXCLUDED.reported, "
            "taken_down = EXCLUDED.taken_down"
        ),
        {
            "d": today,
            "a": row.active,
            "m": row.members,
            "c": row.confirmed,
            "r": row.reported,
            "t": row.taken_down,
        },
    )
    await session.commit()


def _order_key(today: date, fingerprint: str) -> str:
    """A stable order that changes every day and says nothing about activity."""
    return hashlib.sha256(f"{today.isoformat()}|{fingerprint}".encode()).hexdigest()


async def build_summary(
    session: AsyncSession, today: date, dormant_days: int = dormant.DORMANT_DAYS
) -> models.NetworkSummary:
    """Dormant members (``hub/hub/dormant.py``) are left out of the list, the member count and the
    countries. The wire format has no field to flag them: older nodes refuse unknown fields."""
    counted = await dormant.count_params(session, today, dormant_days)
    since30 = today - timedelta(days=30)
    nodes = (
        await session.execute(
            text(
                f"""
                SELECT n.pubkey, n.pseudonym, n.country, n.show_country, n.enrolled_day,
                       coalesce(w.active_days, 0) AS active_days, coalesce(w.tier, 0) AS tier
                FROM nodes n
                LEFT JOIN node_stats_weekly w ON w.node_id = n.id AND w.week = :week
                WHERE n.enrolled_day < :today AND {dormant.ACTIVE}
                """  # noqa: S608
            ),
            {"week": last_full_week(today), "today": today, **counted},
        )
    ).all()
    showing: dict[str, int] = {}
    for n in nodes:
        if n.show_country and n.country:
            cc = n.country.strip()
            showing[cc] = showing.get(cc, 0) + 1
    countries = sorted(
        cc for cc, count in showing.items() if count >= buckets.MIN_MEMBERS_COUNTRY_SHOWN
    )
    members = [
        models.NetworkMember(
            fingerprint=sign.fingerprint(bytes(n.pubkey)),
            pseudonym=n.pseudonym,
            country=n.country.strip()
            if n.show_country and n.country and n.country.strip() in countries
            else None,
            member_since=n.enrolled_day.strftime("%Y-%m"),
            active_days=int(n.active_days),
            tier=int(n.tier),
        )
        for n in nodes
    ]
    members.sort(key=lambda m: _order_key(today, m.fingerprint))
    counts = (
        await session.execute(
            text(
                """
                SELECT
                  (SELECT count(DISTINCT node_id) FROM batches
                   WHERE day >= :recent AND day < :today) AS active,
                  (SELECT count(*) FROM targets WHERE confirmed_day >= :since) AS confirmed,
                  (SELECT count(*) FROM targets WHERE reported_day >= :since) AS reported,
                  (SELECT count(*) FROM targets WHERE taken_down_day >= :since) AS taken_down
                """
            ),
            {"today": today, "recent": today - timedelta(days=7), "since": since30},
        )
    ).one()
    gaps = [
        r[0]
        for r in (
            await session.execute(
                text(
                    "SELECT taken_down_day - reported_day FROM targets "
                    "WHERE taken_down_day >= :since AND reported_day IS NOT NULL"
                ),
                {"since": since30},
            )
        ).all()
    ]
    weekly_rows = (
        await session.execute(
            text(
                """
                SELECT date_trunc('week', day)::date AS week, sum(confirmed) AS confirmed,
                       sum(reported) AS reported, sum(taken_down) AS taken_down
                FROM network_daily WHERE day >= :since GROUP BY 1 ORDER BY 1
                """
            ),
            {"since": today - timedelta(days=7 * WEEKS_SHOWN)},
        )
    ).all()
    return models.NetworkSummary(
        generated_day=today.isoformat(),
        totals=models.NetworkTotals(
            members=len(nodes),
            active_7d=int(counts.active),
            countries=len(countries),
            confirmed_30d=int(counts.confirmed),
            reported_30d=int(counts.reported),
            taken_down_30d=int(counts.taken_down),
            median_days_to_takedown=round(statistics.median(gaps)) if gaps else None,
        ),
        weekly=[
            models.NetworkWeek(
                week=r.week.isoformat(),
                confirmed=int(r.confirmed),
                reported=int(r.reported),
                taken_down=int(r.taken_down),
            )
            for r in weekly_rows
        ],
        countries=[models.NetworkCountry(cc=cc, members=showing[cc]) for cc in countries],
        members=members,
    )


async def store_summary(
    session: AsyncSession, today: date, dormant_days: int = dormant.DORMANT_DAYS
) -> models.NetworkSummary:
    summary = await build_summary(session, today, dormant_days)
    data: dict[str, Any] = summary.model_dump(mode="json")
    await session.execute(
        text(
            "INSERT INTO network_summary (id, generated_day, data) "
            "VALUES (1, :d, CAST(:data AS jsonb)) ON CONFLICT (id) DO UPDATE "
            "SET generated_day = EXCLUDED.generated_day, data = EXCLUDED.data"
        ),
        {"d": today, "data": json.dumps(data)},
    )
    await session.commit()
    return summary


async def run_daily(
    session: AsyncSession, today: date, dormant_days: int = dormant.DORMANT_DAYS
) -> models.NetworkSummary:
    await weekly_stats(session, today)
    await daily_row(session, today, dormant_days)
    return await store_summary(session, today, dormant_days)
