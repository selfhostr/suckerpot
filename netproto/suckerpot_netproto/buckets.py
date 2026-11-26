"""Coarse buckets and k-anonymity thresholds (spec sections 4, 5.4 and 7.1)."""

from __future__ import annotations

from datetime import date, timedelta

MIN_COUNTRIES_SHOWN = 3  # a count of countries below this is hidden
# A member's country is shown only when at least this many members chose to show it. With 2,
# each of the two can tell that the other shows the same country: showing one is opt-in.
MIN_MEMBERS_COUNTRY_SHOWN = 2
MAX_BATCH_AGE_DAYS = 3

COUNT_BUCKET_LABELS = ("0-1", "2-9", "10-99", "100-999", "1000+")
NODES_BUCKET_LABELS = ("5-9", "10-24", "25+")
TIER_LABELS = ("0", "1-99", "100-999", "1000-9999", "10000+")


def count_bucket(n: int) -> int:
    """Count bucket: 0 is 0-1, 1 is 2-9, 2 is 10-99, 3 is 100-999, 4 is 1000 or more."""
    if n < 0:
        raise ValueError("negative count")
    if n <= 1:
        return 0
    if n < 10:
        return 1
    if n < 100:
        return 2
    if n < 1000:
        return 3
    return 4


def nodes_bucket(n: int) -> int:
    """Confirming-node bucket: 0 is 5-9, 1 is 10-24, 2 is 25+. Below 5 is refused."""
    if n < 5:
        raise ValueError("a published target has at least 5 nodes")
    if n < 10:
        return 0
    if n < 25:
        return 1
    return 2


def countries_or_none(n: int) -> int | None:
    """A country count is published only from 3 countries up."""
    return n if n >= MIN_COUNTRIES_SHOWN else None


def tier(distinct_values: int) -> int:
    """Member contribution tier of the last full week: 0 / 1-99 / 100-999 / 1k-9.9k / 10k+."""
    if distinct_values < 0:
        raise ValueError("negative count")
    if distinct_values == 0:
        return 0
    if distinct_values < 100:
        return 1
    if distinct_values < 1000:
        return 2
    if distinct_values < 10000:
        return 3
    return 4


def parse_day(value: str) -> date:
    """Parse a strict ``YYYY-MM-DD`` day."""
    if len(value) != 10 or value[4] != "-" or value[7] != "-":
        raise ValueError("day must be YYYY-MM-DD")
    return date.fromisoformat(value)


def check_batch_day(day: date, today: date) -> str | None:
    """Error code for a batch day, or None. ``today`` is the hub's UTC date."""
    if day >= today:
        return "day_not_closed"
    if today - day > timedelta(days=MAX_BATCH_AGE_DAYS):
        return "day_too_old"
    return None
