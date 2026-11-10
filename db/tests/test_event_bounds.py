from datetime import UTC, datetime, timedelta

from sqlalchemy.dialects import postgresql

from suckerpot_db.event_bounds import (
    SLACK,
    bounded_slices,
    events_ts_range,
    session_events_select,
    session_ts_range,
)
from suckerpot_db.event_lint import find_unbounded_event_queries
from suckerpot_db.models import EventRow, SessionRow

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _session() -> SessionRow:
    return SessionRow(
        session_id="s1",
        sensor="ssh",
        started_at=T0,
        last_event_at=T0 + timedelta(minutes=5),
    )


def test_session_range_adds_slack_after_the_last_event() -> None:
    lo, hi = session_ts_range(T0, T0 + timedelta(minutes=5))
    assert lo == T0
    assert hi == T0 + timedelta(minutes=5) + SLACK


def test_events_range_covers_all_and_is_none_when_empty() -> None:
    assert events_ts_range([]) is None
    got = events_ts_range([(T0, T0 + timedelta(hours=1)), (T0 - timedelta(days=2), T0)])
    assert got == (T0 - timedelta(days=2), T0 + timedelta(hours=1) + SLACK)


def test_session_events_select_bounds_ts_and_sensor() -> None:
    stmt = session_events_select(_session())
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    sql = str(stmt.compile(dialect=dialect, compile_kwargs={"literal_binds": True}))
    assert "events.session_id = 's1'" in sql
    assert "events.ts >= '2026-11-01 12:00:00+00:00'" in sql
    assert "events.ts <= '2026-11-01 12:06:00+00:00'" in sql
    assert "events.sensor = 'ssh'" in sql


def test_session_events_select_takes_columns() -> None:
    stmt = session_events_select(_session(), EventRow.id)
    assert [c.name for c in stmt.selected_columns] == ["id"]


def test_bounded_slices_split_old_from_new_and_cap_size() -> None:
    day = timedelta(days=1)
    rows = [
        ("old1", T0 - 30 * day, T0 - 30 * day + timedelta(minutes=1)),
        ("new1", T0, T0 + timedelta(minutes=1)),
        ("new2", T0 + timedelta(hours=1), T0 + timedelta(hours=1, minutes=1)),
        ("old2", T0 - 30 * day - timedelta(hours=1), T0 - 30 * day),
    ]
    out = bounded_slices(rows, lambda r: (r[1], r[2]), max_span=day)
    assert [[r[0] for r in s] for s in out] == [["old2", "old1"], ["new1", "new2"]]
    capped = bounded_slices(rows, lambda r: (r[1], r[2]), max_span=365 * day, max_items=3)
    assert [len(s) for s in capped] == [3, 1]


def test_lint_flags_raw_sql_without_ts() -> None:
    src = 'q = text("SELECT 1 FROM events WHERE session_id = ANY(:ids)")\n'
    assert find_unbounded_event_queries(src) == [1]


def test_lint_accepts_raw_sql_with_ts_bound() -> None:
    src = (
        'q = text("SELECT 1 FROM events WHERE session_id = ANY(:ids) "\n'
        '         "AND ts >= :lo AND ts <= :hi")\n'
        'r = f"JOIN events e ON e.session_id = s.session_id AND e.ts >= {lo}"\n'
    )
    assert find_unbounded_event_queries(src) == []


def test_lint_ignores_other_tables() -> None:
    assert find_unbounded_event_queries('q = "SELECT 1 FROM sessions WHERE session_id = :s"') == []


def test_lint_flags_orm_without_ts() -> None:
    src = "def f():\n    return select(EventRow).where(EventRow.session_id == sid)\n"
    assert find_unbounded_event_queries(src) == [2]


def test_lint_accepts_orm_with_ts_alias_or_helper() -> None:
    with_ts = (
        "def f(ids, lo):\n"
        "    e = EventRow\n"
        "    return select(e).where(e.session_id.in_(ids), e.ts >= lo)\n"
    )
    helper = (
        "def g(row):\n    return session_events_select(row).where(EventRow.session_id == 'x')\n"
    )
    assert find_unbounded_event_queries(with_ts) == []
    assert find_unbounded_event_queries(helper) == []
