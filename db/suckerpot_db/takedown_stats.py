"""Takedown statistics (M27, docs/dev/design/m27.md section 6): pure functions, no database.

Used by the API (live numbers) and by the ingest roll-up, so both count the same way.

Right-censoring: a target counts toward "taken down within H" only if it was observed for H (or
went down within H). A target reported 10 hours ago says nothing about the 48-hour rate, so it is
left out of the denominator. A target whose tracking stopped early is observed only until then.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import median

WINDOWS_HOURS: tuple[int, ...] = (1, 6, 24, 48, 72, 168, 336, 720)
MIN_MEDIAN_VALUES = 5
URL_ROLES = frozenset({"payload_url"})
HOST_ROLES = frozenset({"payload_host"})
TAKEDOWN_ROLES = URL_ROLES | HOST_ROLES  # c2 and attack_source are "quiet" rates, not takedowns


@dataclass(frozen=True, slots=True)
class Fact:
    """What the statistics need to know about one target."""

    role: str
    provider_key: str
    reported_at: datetime
    observed_until: datetime  # min(now, track_until, stopped_at)
    first_down_at: datetime | None = None
    down_before_report: bool = False
    demo: bool = False
    tracked_to_end: bool = False  # the tracking period ended without a stop by the owner


def counted(fact: Fact) -> bool:
    """Demo targets and targets that were already down at the first look are not statistics."""
    return not fact.demo and not fact.down_before_report


def ttd_seconds(fact: Fact) -> float | None:
    """Upper bound of the time to takedown: first confirmed down minus the report time."""
    if fact.first_down_at is None or not counted(fact):
        return None
    return max(0.0, (fact.first_down_at - fact.reported_at).total_seconds())


def down_within(fact: Fact, hours: float) -> bool:
    ttd = ttd_seconds(fact)
    return ttd is not None and ttd <= hours * 3600


def window_counts(facts: Iterable[Fact], hours: float) -> tuple[int, int]:
    """(eligible, down) for "taken down within ``hours``".

    Eligible: went down within the window, or was observed for the whole window.
    """
    window = timedelta(hours=hours)
    eligible = down = 0
    for fact in facts:
        if not counted(fact):
            continue
        if down_within(fact, hours):
            eligible += 1
            down += 1
        elif fact.observed_until - fact.reported_at >= window:
            eligible += 1
    return eligible, down


def median_ttd(facts: Iterable[Fact], track_days: int = 30) -> tuple[int | None, int]:
    """(median seconds, count) among targets that went down within the tracking period.
    The median is None below ``MIN_MEDIAN_VALUES`` values ("not enough data yet")."""
    limit = track_days * 86400
    values = [t for f in facts if (t := ttd_seconds(f)) is not None and t <= limit]
    if len(values) < MIN_MEDIAN_VALUES:
        return None, len(values)
    return int(median(values)), len(values)


def still_up_after_tracking(facts: Iterable[Fact]) -> int:
    """Tracked to the end of the period and never down."""
    return sum(1 for f in facts if counted(f) and f.first_down_at is None and f.tracked_to_end)


def curve(
    facts: Sequence[Fact], points: Sequence[int] = WINDOWS_HOURS
) -> list[dict[str, float | int | None]]:
    """Cumulative share of targets down by each point, censored like ``window_counts``."""
    out: list[dict[str, float | int | None]] = []
    for hours in points:
        eligible, down = window_counts(facts, hours)
        out.append(
            {
                "hours": hours,
                "eligible": eligible,
                "down": down,
                "percent": round(100 * down / eligible, 1) if eligible else None,
            }
        )
    return out


def percent(down: int, eligible: int) -> float | None:
    return round(100 * down / eligible, 1) if eligible else None
