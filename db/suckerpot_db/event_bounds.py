"""Time bounds for lookups of a session's events.

``events`` is a TimescaleDB hypertable on ``ts`` and old chunks are compressed. A
statement that filters on ``session_id`` alone has to open and decompress every
chunk. The ``sessions`` row knows when the session started and when its last event
arrived, so every lookup adds that range (plus a little slack) to let chunks be
excluded. Use these helpers instead of writing the bound by hand.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, and_, select
from sqlalchemy.sql import Select

from suckerpot_db.models import EventRow, SessionRow

# Event timestamps come from the sensor clock, the session bounds from the same
# events: one minute absorbs clock skew and the last event racing the aggregate.
SLACK = timedelta(minutes=1)

# SQL fragments for raw ``text()`` statements. ``sessions`` must be aliased ``s``
# and ``events`` ``e``. They carry no bind parameter.
SQL_EVENT_TS_BOUND = "e.ts >= s.started_at AND e.ts <= s.last_event_at + interval '1 minute'"


def session_ts_range(started_at: datetime, last_event_at: datetime) -> tuple[datetime, datetime]:
    """The ``(low, high)`` ``events.ts`` range that holds one session's events."""
    return started_at, last_event_at + SLACK


def events_ts_range(rows: Iterable[tuple[datetime, datetime]]) -> tuple[datetime, datetime] | None:
    """The covering range of several ``(started_at, last_event_at)`` pairs, or None."""
    lows: list[datetime] = []
    highs: list[datetime] = []
    for started_at, last_event_at in rows:
        lows.append(started_at)
        highs.append(last_event_at)
    if not lows:
        return None
    return min(lows), max(highs) + SLACK


def session_events_where(session: SessionRow, *, sensor: bool = True) -> list[ColumnElement[bool]]:
    """WHERE terms selecting the events of one loaded session, bounded on ``ts``."""
    lo, hi = session_ts_range(session.started_at, session.last_event_at)
    terms: list[ColumnElement[bool]] = [
        EventRow.session_id == session.session_id,
        EventRow.ts >= lo,
        EventRow.ts <= hi,
    ]
    if sensor:
        terms.append(EventRow.sensor == session.sensor)
    return terms


def session_events_select(session: SessionRow, *entities: Any) -> Select[Any]:
    """``SELECT <entities> FROM events`` for one loaded session (all of ``EventRow`` by default)."""
    return select(*(entities or (EventRow,))).where(and_(*session_events_where(session)))


def bounded_slices[T](
    items: Sequence[T],
    span: Callable[[T], tuple[datetime, datetime]],
    *,
    max_span: timedelta = timedelta(days=1),
    max_items: int = 200,
) -> list[list[T]]:
    """Split sessions into slices that each fit one ``ts`` range and at most ``max_items``.

    ``span`` returns ``(started_at, last_event_at)`` of an item. Items are ordered by start;
    a slice is closed when the next item would stretch its covering range past ``max_span`` or
    its size past ``max_items``. A single session longer than ``max_span`` gets its own slice.
    Query each slice with ``events_ts_range`` so a list of old and new sessions never turns
    into one range that covers the whole table.
    """
    out: list[list[T]] = []
    cur: list[T] = []
    lo: datetime | None = None
    hi: datetime | None = None
    for item in sorted(items, key=lambda i: span(i)[0]):
        a, b = span(item)
        if cur and lo is not None and hi is not None:
            if len(cur) >= max_items or max(hi, b) - lo > max_span:
                out.append(cur)
                cur, lo, hi = [], None, None
        cur.append(item)
        lo = a if lo is None else min(lo, a)
        hi = b if hi is None else max(hi, b)
    if cur:
        out.append(cur)
    return out
