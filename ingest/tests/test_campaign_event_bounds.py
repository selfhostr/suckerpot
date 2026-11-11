"""The campaign worker reads events of old and new sessions in separate, ts-bounded slices."""

from datetime import UTC, datetime, timedelta
from typing import Any

from ingest.campaigns.cluster import ContentCache, _content_keys
from ingest.campaigns.plan import Cand

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, stmt: Any, params: dict[str, Any]) -> list[Any]:
        self.calls.append((str(stmt), params))
        return []


def _cand(sid: str, start: datetime) -> Cand:
    return Cand(sid, "ssh", "192.0.2.1", start + timedelta(minutes=2), start)


async def test_content_queries_carry_a_ts_range_per_slice() -> None:
    rec = _Recorder()
    old, new = T0 - timedelta(days=40), T0
    cands = [_cand("old", old), _cand("new", new)]
    await _content_keys(rec, cands, ContentCache())  # type: ignore[arg-type]
    assert rec.calls
    ranges = set()
    for sql, params in rec.calls:
        assert "events" in sql
        assert "ts >= :lo" in sql, sql
        assert "ts <= :hi" in sql, sql
        ranges.add((params["lo"], params["hi"], tuple(params["ids"])))
    # Two slices, each only as wide as its own session (plus one minute of slack).
    assert ranges == {
        (old, old + timedelta(minutes=3), ("old",)),
        (new, new + timedelta(minutes=3), ("new",)),
    }
