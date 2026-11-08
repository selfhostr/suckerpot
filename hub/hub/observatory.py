"""Public network observatory (design M34): ``network.json`` on the feed site.

Three parts:

* ``freeze_days``: once a day is final (no batch for it can arrive any more), its network-wide
  aggregates are computed ONCE from the observations of ELIGIBLE nodes (the consensus rule: age,
  active days, reputation, standing) into ``observatory_daily``, and never again. A node that
  joins, leaves or sends late cannot move a number that was already published, and freshly
  enrolled nodes neither count towards the thresholds nor add to the figures.
* ``load``: reads what the document needs (frozen days, outcome counts, weekly node counts).
* ``render``: a pure function that applies every anonymity rule (tests drive it directly).

``publish`` writes the file atomically next to the feed files. It does not depend on
``HUB_FEED_MODE``: the lists can stay off while the observatory publishes.
"""

from __future__ import annotations

import json
import os
import secrets
import statistics
import uuid
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto import buckets, enums
from suckerpot_netproto.feeds.models import LICENCE
from suckerpot_netproto.feeds.render import dumps_json

from . import consensus
from .config import Settings
from .feeds.publish import FILE_MODE, gz

SCHEMA = "selfhostr-network-stats/1"
FILE = "network.json"

# A batch may be sent up to MAX_BATCH_AGE_DAYS after its day, so a day is final this many days
# after it (the hub refuses older batches). Only final days are frozen and published.
FINAL_LAG_DAYS = buckets.MAX_BATCH_AGE_DAYS + 1
# Outcome counts (confirmations, reports, takedowns) are published with at least 24 h delay:
# the last published day ended at least one full day ago.
OUTCOME_LAG_DAYS = 2
SERIES_DAYS = 90
WINDOW_DAYS = 30
RETENTION_DAYS = 400
# k: a figure needs this many eligible nodes behind it, otherwise it is coarse or null.
MIN_NODES_STANDARD = buckets.MIN_COUNTRIES_SHOWN
# An item (service, tag, family) needs this much support over the window to be named...
ITEM_MIN = 20
# ...and in coarse mode much more, spread over at least ITEM_MIN_WEEKS different ISO weeks.
ITEM_MIN_COARSE = 100
ITEM_MIN_WEEKS = 4
# In standard mode an item must have been seen by two eligible nodes on one day. A CVE tag (its
# digits are chosen by the attacker) always needs that, and is never named in coarse mode.
ITEM_MIN_NODES = 2
TOP_TAGS = 10
TOP_FAMILIES = 10
SHARE_STEP_COARSE = 5
SHARE_STEP_STANDARD = 1

ACTIVITY_FIELDS = ("login", "command", "download", "exploit")
KIND_FIELDS = ("payload_urls", "files", "c2")
SERIES_FIELDS = ("sources", *ACTIVITY_FIELDS, *KIND_FIELDS)
# Fields a coarse week may show. The others are low-volume: a few hundred attacker requests could
# move them, so they stay null until k eligible nodes stand behind them.
COARSE_FIELDS = frozenset({"sources", "login", "command"})
COARSE = "coarse"
STANDARD = "standard"

EXACT = "exact"
ROUNDED = "rounded"
SUPPRESSED = "suppressed"

WEEK_KEY = "observatory_week"

# The production thresholds are the code defaults of Settings, never repeated here.
_PRODUCTION = Settings()


def eligibility_relaxed(s: Settings) -> bool:
    """Eligibility weaker than production: STANDARD precision is refused entirely."""
    p = _PRODUCTION
    return (
        s.node_min_age_days < p.node_min_age_days
        or s.node_min_active_days < p.node_min_active_days
        or s.min_reputation < p.min_reputation
    )


def outcome_precision(s: Settings) -> str:
    """``exact`` only with production consensus; ``rounded`` (weekly, tens) when relaxed;
    ``suppressed`` when a confirmation could rest on fewer than k nodes."""
    p = _PRODUCTION
    if s.min_nodes < MIN_NODES_STANDARD:
        return SUPPRESSED
    if (
        s.min_nodes < p.min_nodes
        or s.min_weight < p.min_weight
        or s.cohort_max_share > p.cohort_max_share
        or eligibility_relaxed(s)
    ):
        return ROUNDED
    return EXACT


# --- inputs -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DayRow:
    """One frozen day: eligible nodes with attacking addresses that day (``nodes``, the k of the
    day), the distinct counts of ``SERIES_FIELDS`` and the eligible nodes behind each of them
    (``field_nodes``; a missing field defaults to ``nodes``)."""

    day: date
    nodes: int
    values: Mapping[str, int]
    field_nodes: Mapping[str, int] | None = None

    def nodes_of(self, f: str) -> int:
        if self.field_nodes is None:
            return self.nodes
        return self.field_nodes.get(f, 0)


@dataclass(frozen=True)
class ItemRow:
    """One frozen day of one service, tag or family."""

    day: date
    metric: str  # service | tag | family
    key: str
    total: int
    nodes: int


@dataclass(frozen=True)
class OutcomeDay:
    day: date
    confirmed: int = 0
    reported: int = 0
    taken_down: int = 0


@dataclass
class ObservatoryInput:
    today: date
    min_nodes: int
    members: int = 0
    # Counted once per ISO week (``week``), from batches before that week.
    week: date | None = None
    eligible_week: int = 0
    active_last_week: int = 0
    # Members per country among those who chose to show one (filtered by ``render``).
    country_members: Mapping[str, int] = field(default_factory=dict)
    days: list[DayRow] = field(default_factory=list)
    items: list[ItemRow] = field(default_factory=list)
    outcomes: list[OutcomeDay] = field(default_factory=list)
    # Sent over ``totals_span`` (30 days, or the last complete weeks in rounded mode).
    reports_sent_30d: int = 0
    abusech_sent_30d: int = 0
    takedown_gaps: list[int] = field(default_factory=list)
    allow_standard: bool = True
    outcome_mode: str = EXACT


# --- rounding (pure) ---------------------------------------------------------------------------


def round_figure(n: int, significant: int) -> int:
    """Round half up to ``significant`` figures, never finer than tens (4 -> 0, 5 -> 10)."""
    if n <= 0:
        return 0
    step: int = 10 ** max(1, len(str(n)) - significant)
    return ((n + step // 2) // step) * step


def round_tens(n: int) -> int:
    return ((max(0, n) + 5) // 10) * 10


def round_share(part: int, whole: int, step: int) -> int:
    """Percentage of ``whole``, rounded half up to a multiple of ``step``."""
    if whole <= 0 or part <= 0:
        return 0
    return int(part * 100 / whole / step + 0.5) * step


# --- render (pure) ------------------------------------------------------------------------------


def _week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


def _entry(
    start: date, days: int, precision: str, values: Mapping[str, int | None]
) -> dict[str, Any]:
    out: dict[str, Any] = {"start": start.isoformat(), "days": days, "precision": precision}
    out.update({f: values.get(f) for f in SERIES_FIELDS})
    return out


def build_series(
    rows: Sequence[DayRow], first: date, last: date, *, allow_standard: bool = True
) -> list[dict[str, Any]]:
    """Per-day figures from ``first`` to ``last``, by complete ISO week only.

    A week in which every day had at least k eligible nodes is published day by day with two
    significant figures; a field with fewer than k eligible nodes behind it that day is null. Any
    other week is ONE coarse entry: the average per reporting day of ``COARSE_FIELDS``, one
    significant figure, the other fields null (all null when no node reported that week). A
    partial week at either end is left out, so a published entry never changes shape later.
    """
    by_day = {r.day: r for r in rows}
    out: list[dict[str, Any]] = []
    week = _week_start(first)
    while week <= last:
        span = [week + timedelta(days=i) for i in range(7)]
        if span[0] < first or span[-1] > last:
            week += timedelta(days=7)
            continue
        week_rows = [by_day.get(d) for d in span]
        full = [r for r in week_rows if r is not None and r.nodes >= MIN_NODES_STANDARD]
        if allow_standard and len(full) == 7:
            for r in full:
                values: dict[str, int | None] = {
                    f: round_figure(r.values.get(f, 0), 2)
                    if r.nodes_of(f) >= MIN_NODES_STANDARD
                    else None
                    for f in SERIES_FIELDS
                }
                out.append(_entry(r.day, 1, STANDARD, values))
        else:
            reporting = [r for r in week_rows if r is not None and r.nodes > 0]
            coarse: dict[str, int | None] = {}
            for f in SERIES_FIELDS:
                if reporting and f in COARSE_FIELDS:
                    mean = sum(r.values.get(f, 0) for r in reporting) / len(reporting)
                    coarse[f] = round_figure(int(mean + 0.5), 1)
                else:
                    coarse[f] = None
            out.append(_entry(week, 7, COARSE, coarse))
        week += timedelta(days=7)
    return out


def _allowed(metric: str, key: str) -> bool:
    if metric == "service":
        return key in enums.SERVICES
    if metric == "tag":
        return enums.is_valid_tag(key)
    if metric == "family":
        return key in enums.FAMILIES_V1
    return False


def _is_cve(metric: str, key: str) -> bool:
    return metric == "tag" and key not in enums.TAGS_V1


def build_window(
    rows: Sequence[DayRow],
    items: Sequence[ItemRow],
    first: date,
    last: date,
    *,
    allow_standard: bool = True,
) -> dict[str, Any]:
    """Services, tags and families over the window, as shares of daily distinct counts."""
    reporting = [r for r in rows if first <= r.day <= last and r.nodes > 0]
    coarse = (
        not allow_standard or not reporting or any(r.nodes < MIN_NODES_STANDARD for r in reporting)
    )
    step = SHARE_STEP_COARSE if coarse else SHARE_STEP_STANDARD
    days = {r.day for r in reporting}
    totals: dict[tuple[str, str], int] = defaultdict(int)
    peak_nodes: dict[tuple[str, str], int] = defaultdict(int)
    weeks: dict[tuple[str, str], set[date]] = defaultdict(set)
    for it in items:
        if it.day not in days or not _allowed(it.metric, it.key) or it.total <= 0:
            continue
        k = (it.metric, it.key)
        totals[k] += it.total
        peak_nodes[k] = max(peak_nodes[k], it.nodes)
        weeks[k].add(_week_start(it.day))
    whole = {
        "service": sum(r.values.get("sources", 0) for r in reporting),
        "tag": sum(r.values.get("sources", 0) for r in reporting),
        "family": sum(r.values.get("files", 0) for r in reporting),
    }

    def listing(metric: str, top: int | None) -> list[dict[str, Any]]:
        picked = []
        for (m, key), total in totals.items():
            if m != metric:
                continue
            if coarse:
                if _is_cve(m, key) or total < ITEM_MIN_COARSE:
                    continue
                if len(weeks[(m, key)]) < ITEM_MIN_WEEKS:
                    continue
            elif total < ITEM_MIN or peak_nodes[(m, key)] < ITEM_MIN_NODES:
                continue
            share = round_share(total, whole[metric], step)
            if share > 0:
                picked.append((total, key, share))
        picked.sort(key=lambda p: (-p[0], p[1]))
        return [{"id": key, "share_pct": share} for _, key, share in picked[:top]]

    return {
        "first_day": first.isoformat(),
        "last_day": last.isoformat(),
        "days": (last - first).days + 1,
        "precision": COARSE if coarse else STANDARD,
        "services": listing("service", None),
        "tags": listing("tag", TOP_TAGS),
        "families": listing("family", TOP_FAMILIES),
    }


ROUNDED_WEEKS = 4
# The weekly bootstrap figures are counted from this weekday on (Thursday): the batch of the
# Sunday before can arrive until Wednesday (MAX_BATCH_AGE_DAYS), so the week is settled then.
WEEK_SETTLED_WEEKDAY = buckets.MAX_BATCH_AGE_DAYS


def totals_span(out_last: date, mode: str) -> tuple[date, date]:
    """Days the outcome totals cover: the last 30 days (exact), or the last ``ROUNDED_WEEKS``
    complete ISO weeks (rounded), so a rounding edge never moves with day resolution."""
    if mode != ROUNDED:
        return out_last - timedelta(days=29), out_last
    end = out_last if out_last.weekday() == 6 else out_last - timedelta(days=out_last.weekday() + 1)
    return end - timedelta(days=7 * ROUNDED_WEEKS - 1), end


def build_outcomes(inp: ObservatoryInput) -> dict[str, Any]:
    """Outcomes over 90 days. Exact daily figures only with production consensus thresholds."""
    out_last = inp.today - timedelta(days=OUTCOME_LAG_DAYS)
    out_first = out_last - timedelta(days=SERIES_DAYS - 1)
    by_day = {o.day: o for o in inp.outcomes}
    calendar = [out_first + timedelta(days=i) for i in range(SERIES_DAYS)]
    days = [by_day.get(d, OutcomeDay(d)) for d in calendar]
    t_first, t_last = totals_span(out_last, inp.outcome_mode)
    covered = [o for o in days if t_first <= o.day <= t_last]
    totals = {
        "confirmed_30d": sum(o.confirmed for o in covered),
        "reported_30d": sum(o.reported for o in covered),
        "taken_down_30d": sum(o.taken_down for o in covered),
        "reports_sent_30d": inp.reports_sent_30d,
        "abusech_sent_30d": inp.abusech_sent_30d,
    }
    doc: dict[str, Any] = {
        "first_day": out_first.isoformat(),
        "last_day": out_last.isoformat(),
        "precision": inp.outcome_mode,
        "totals_first_day": t_first.isoformat(),
        "totals_last_day": t_last.isoformat(),
    }
    if inp.outcome_mode == EXACT:
        doc.update(totals)
        doc["median_days_to_takedown"] = (
            round(statistics.median(inp.takedown_gaps)) if inp.takedown_gaps else None
        )
        doc["daily"] = [
            {
                "day": o.day.isoformat(),
                "confirmed": o.confirmed,
                "reported": o.reported,
                "taken_down": o.taken_down,
            }
            for o in days
        ]
        doc["weekly"] = None
        return doc
    if inp.outcome_mode == ROUNDED:
        doc.update({k: round_tens(v) for k, v in totals.items()})
        weekly = []
        start = _week_start(out_first)
        if start < out_first:
            start += timedelta(days=7)
        while start + timedelta(days=6) <= out_last:
            span = [o for o in days if start <= o.day < start + timedelta(days=7)]
            weekly.append(
                {
                    "start": start.isoformat(),
                    "confirmed": round_tens(sum(o.confirmed for o in span)),
                    "reported": round_tens(sum(o.reported for o in span)),
                    "taken_down": round_tens(sum(o.taken_down for o in span)),
                }
            )
            start += timedelta(days=7)
        doc.update({"median_days_to_takedown": None, "daily": None, "weekly": weekly})
        return doc
    doc.update({k: None for k in totals})
    doc.update(
        {
            "totals_first_day": None,
            "totals_last_day": None,
            "median_days_to_takedown": None,
            "daily": None,
            "weekly": None,
        }
    )
    return doc


def render(inp: ObservatoryInput) -> dict[str, Any]:
    today = inp.today
    # Activity: final days only.
    act_last = today - timedelta(days=FINAL_LAG_DAYS)
    frozen = sorted((r for r in inp.days if r.day <= act_last), key=lambda r: r.day)
    if frozen:
        act_first = max(act_last - timedelta(days=SERIES_DAYS - 1), frozen[0].day)
        series = build_series(frozen, act_first, act_last, allow_standard=inp.allow_standard)
    else:
        series = []
    window = build_window(
        frozen,
        inp.items,
        act_last - timedelta(days=WINDOW_DAYS - 1),
        act_last,
        allow_standard=inp.allow_standard,
    )
    countries = sorted(
        (cc, n) for cc, n in inp.country_members.items() if n >= buckets.MIN_COUNTRIES_SHOWN
    )
    week = inp.week or _week_start(today)
    return {
        "schema": SCHEMA,
        "generated_day": today.isoformat(),
        "licence": LICENCE,
        "nodes": {
            "members": inp.members,
            "active_last_week": inp.active_last_week,
            "countries": [{"cc": cc, "members": n} for cc, n in countries],
        },
        "bootstrap": {
            "week": week.isoformat(),
            "min_nodes": inp.min_nodes,
            "nodes_missing": max(0, inp.min_nodes - inp.eligible_week),
            "consensus_possible": inp.eligible_week >= inp.min_nodes,
        },
        "outcomes": build_outcomes(inp),
        "activity": {
            "last_day": act_last.isoformat(),
            "series": series,
            "window": window,
        },
        "rules": {
            "min_nodes_standard": MIN_NODES_STANDARD,
            "min_countries_shown": buckets.MIN_COUNTRIES_SHOWN,
            "activity_lag_days": FINAL_LAG_DAYS,
            "outcome_lag_days": OUTCOME_LAG_DAYS,
            "item_min": ITEM_MIN,
            "item_min_coarse": ITEM_MIN_COARSE,
            "item_min_weeks_coarse": ITEM_MIN_WEEKS,
        },
    }


def render_bytes(inp: ObservatoryInput) -> bytes:
    return dumps_json(render(inp)).encode("utf-8")


# --- freeze (database) ---------------------------------------------------------------------------

_ITEM_QUERIES = {
    "activity": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(activity) AS k "
    "WHERE day = :d AND kind = 'ip' AND node_id = ANY(:nodes) GROUP BY k",
    "service": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(services) AS k "
    "WHERE day = :d AND kind = 'ip' AND node_id = ANY(:nodes) GROUP BY k",
    "tag": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(tags) AS k "
    "WHERE day = :d AND kind = 'ip' AND node_id = ANY(:nodes) GROUP BY k",
    "family": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(families) AS k "
    "WHERE day = :d AND kind = 'sha256' AND node_id = ANY(:nodes) GROUP BY k",
    "kind": "SELECT CASE kind WHEN 'url' THEN 'payload_urls' WHEN 'sha256' THEN 'files' "
    "ELSE 'c2' END AS key, count(DISTINCT kind || '|' || value) AS total, "
    "count(DISTINCT node_id) AS nodes FROM observations WHERE day = :d "
    "AND kind IN ('url', 'sha256', 'c2_ip', 'c2_domain') AND node_id = ANY(:nodes) GROUP BY 1",
}


async def freeze_day(session: AsyncSession, day: date, nodes: Sequence[uuid.UUID]) -> None:
    """Store the aggregates of one final day from the observations of ``nodes`` only.

    The ``total`` row counts distinct attacking addresses and the eligible nodes that reported at
    least one (the k of the day). A day already stored is left as it is.
    """
    params = {"d": day, "nodes": list(nodes)}
    head = (
        await session.execute(
            text(
                "SELECT count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
                "FROM observations WHERE day = :d AND kind = 'ip' AND node_id = ANY(:nodes)"
            ),
            params,
        )
    ).one()
    rows: list[dict[str, Any]] = [
        {"d": day, "m": "total", "k": "", "t": int(head.total), "n": int(head.nodes)}
    ]
    for metric, sql in _ITEM_QUERIES.items():
        for r in await session.execute(text(sql), params):
            rows.append(
                {"d": day, "m": metric, "k": str(r.key), "t": int(r.total), "n": int(r.nodes)}
            )
    await session.execute(
        text(
            "INSERT INTO observatory_daily (day, metric, key, total, nodes) "
            "VALUES (:d, :m, :k, :t, :n) ON CONFLICT DO NOTHING"
        ),
        rows,
    )


async def freeze_days(session: AsyncSession, s: Settings, today: date) -> int:
    """Freeze every final day still covered by the observations. Returns the days stored.

    Only nodes eligible under the consensus rule at the time of the freeze count. Eligibility is
    taken at the freeze rather than on the day itself because batch markers are kept 14 days only:
    the day's own 14-day look-back is no longer complete four days later.
    """
    last = today - timedelta(days=FINAL_LAG_DAYS)
    first = today - timedelta(days=s.obs_retention_days)
    if first > last:
        return 0
    done = {
        r[0]
        for r in await session.execute(
            text(
                "SELECT day FROM observatory_daily WHERE metric = 'total' AND day BETWEEN :a AND :b"
            ),
            {"a": first, "b": last},
        )
    }
    todo = [first + timedelta(days=i) for i in range((last - first).days + 1)]
    todo = [d for d in todo if d not in done]
    if not todo:
        return 0
    nodes = list(await consensus.eligible_nodes(session, s, today))
    for d in todo:
        await freeze_day(session, d, nodes)
    await session.commit()
    return len(todo)


# --- load (database) ------------------------------------------------------------------------------


def _midnight(d: date) -> datetime:
    return datetime.combine(d, time(0), tzinfo=UTC)


async def weekly_nodes(session: AsyncSession, s: Settings, today: date) -> tuple[date, int, int]:
    """(week, eligible, active) counted once per ISO week from batches before that week.

    Stored in ``worker_state`` so that a node skipping a day mid-week changes nothing published.
    A week is counted only from its Thursday on, when the batches of the Sunday before can no
    longer arrive; until then the previous count stays (or, with none yet, the previous week is
    counted now). Batch markers are kept 14 days, so the oldest days of the look-back may be
    gone by then: that can only make the count smaller.
    """
    week = _week_start(today)
    query = text("SELECT value FROM worker_state WHERE key = :k")
    row = (await session.execute(query, {"k": WEEK_KEY})).first()
    cached: dict[str, Any] | None = None
    if row is not None:
        try:
            loaded = json.loads(row[0])
            cached = {
                "week": date.fromisoformat(loaded["week"]),
                "eligible": int(loaded["eligible"]),
                "active": int(loaded["active"]),
            }
        except ValueError, KeyError, TypeError:
            cached = None
    if cached is not None and cached["week"] == week:
        return week, cached["eligible"], cached["active"]
    if today.weekday() < WEEK_SETTLED_WEEKDAY:
        if cached is not None:
            return cached["week"], cached["eligible"], cached["active"]
        week -= timedelta(days=7)
    eligible = len(await consensus.eligible_nodes(session, s, week))
    active = int(
        (
            await session.execute(
                text(
                    "SELECT count(DISTINCT node_id) FROM batches "
                    "WHERE items > 0 AND day >= :a AND day < :b"
                ),
                {"a": week - timedelta(days=7), "b": week},
            )
        ).scalar_one()
    )
    value = json.dumps({"week": week.isoformat(), "eligible": eligible, "active": active})
    await session.execute(
        text(
            "INSERT INTO worker_state (key, value) VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": WEEK_KEY, "v": value},
    )
    await session.commit()
    return week, eligible, active


async def load(session: AsyncSession, s: Settings, today: date) -> ObservatoryInput:
    inp = ObservatoryInput(
        today=today,
        min_nodes=s.min_nodes,
        allow_standard=not eligibility_relaxed(s),
        outcome_mode=outcome_precision(s),
    )
    # Nodes.
    inp.members = int((await session.execute(text("SELECT count(*) FROM nodes"))).scalar_one())
    inp.week, inp.eligible_week, inp.active_last_week = await weekly_nodes(session, s, today)
    inp.country_members = {
        str(r.cc): int(r.n)
        for r in await session.execute(
            text(
                "SELECT btrim(country) AS cc, count(*) AS n FROM nodes "
                "WHERE show_country AND country IS NOT NULL AND btrim(country) <> '' "
                "GROUP BY 1"
            )
        )
    }
    # Activity.
    since = today - timedelta(days=FINAL_LAG_DAYS + SERIES_DAYS)
    heads: dict[date, int] = {}
    values: dict[date, dict[str, int]] = defaultdict(dict)
    field_nodes: dict[date, dict[str, int]] = defaultdict(dict)
    for r in await session.execute(
        text(
            "SELECT day, metric, key, total, nodes FROM observatory_daily "
            "WHERE day >= :since ORDER BY day"
        ),
        {"since": since},
    ):
        if r.metric == "total":
            heads[r.day] = int(r.nodes)
            values[r.day]["sources"] = int(r.total)
            field_nodes[r.day]["sources"] = int(r.nodes)
        elif (r.metric == "activity" and r.key in ACTIVITY_FIELDS) or (
            r.metric == "kind" and r.key in KIND_FIELDS
        ):
            values[r.day][r.key] = int(r.total)
            field_nodes[r.day][r.key] = int(r.nodes)
        elif r.metric in ("service", "tag", "family"):
            inp.items.append(ItemRow(r.day, r.metric, r.key, int(r.total), int(r.nodes)))
    inp.days = [DayRow(d, n, values[d], field_nodes[d]) for d, n in sorted(heads.items())]
    # Outcomes.
    out_last = today - timedelta(days=OUTCOME_LAG_DAYS)
    out_first = out_last - timedelta(days=SERIES_DAYS - 1)
    tallies: dict[date, dict[str, int]] = defaultdict(dict)
    for column in ("confirmed", "reported", "taken_down"):
        for r in await session.execute(
            text(
                f"SELECT {column}_day AS day, count(*) AS n FROM targets "  # noqa: S608
                f"WHERE {column}_day BETWEEN :a AND :b GROUP BY 1"
            ),
            {"a": out_first, "b": out_last},
        ):
            tallies[r.day][column] = int(r.n)
    inp.outcomes = [OutcomeDay(d, **t) for d, t in sorted(tallies.items())]
    w_first, w_last = totals_span(out_last, inp.outcome_mode)
    window = {"a": _midnight(w_first), "b": _midnight(w_last + timedelta(days=1))}
    inp.reports_sent_30d = int(
        (
            await session.execute(
                text(
                    "SELECT count(*) FROM reports WHERE state = 'sent' "
                    "AND sent_at >= :a AND sent_at < :b"
                ),
                window,
            )
        ).scalar_one()
    )
    inp.abusech_sent_30d = int(
        (
            await session.execute(
                text(
                    "SELECT count(*) FROM abusech_submissions WHERE state = 'sent' "
                    "AND sent_at >= :a AND sent_at < :b"
                ),
                window,
            )
        ).scalar_one()
    )
    inp.takedown_gaps = [
        int(r[0])
        for r in await session.execute(
            text(
                "SELECT taken_down_day - reported_day FROM targets "
                "WHERE taken_down_day BETWEEN :a AND :b AND reported_day IS NOT NULL"
            ),
            {"a": w_first, "b": w_last},
        )
    ]
    return inp


# --- publish (disk) -------------------------------------------------------------------------------


def publish(root: Path, data: bytes) -> None:
    """Write ``network.json`` and its ``.gz`` sidecar, each with an atomic rename."""
    root.mkdir(parents=True, exist_ok=True)
    for name, body in ((FILE + ".gz", gz(data)), (FILE, data)):
        tmp = root / f".tmp-{name}-{secrets.token_hex(4)}"
        try:
            tmp.write_bytes(body)
            tmp.chmod(FILE_MODE)
            os.replace(tmp, root / name)
        finally:
            tmp.unlink(missing_ok=True)


__all__ = [
    "FILE",
    "SCHEMA",
    "ObservatoryInput",
    "freeze_days",
    "load",
    "outcome_precision",
    "publish",
    "render",
    "render_bytes",
]
