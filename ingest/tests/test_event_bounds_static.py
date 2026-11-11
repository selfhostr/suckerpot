"""No lookup of events by session_id without a ts bound (hypertable chunk exclusion)."""

from pathlib import Path

from suckerpot_db.event_lint import find_unbounded_event_queries

SRC = Path(__file__).resolve().parents[1] / "ingest"


def test_every_event_lookup_by_session_is_time_bounded() -> None:
    problems = [
        f"{path.relative_to(SRC.parent)}:{line}"
        for path in sorted(SRC.rglob("*.py"))
        for line in find_unbounded_event_queries(path.read_text())
    ]
    assert not problems, (
        "events filtered by session_id without a ts bound (use suckerpot_db.event_bounds): "
        + ", ".join(problems)
    )
