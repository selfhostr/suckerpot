"""The API reads a session's events inside the session's own time range."""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from suckerpot_db.models import SessionRow

from api import analytics_queries as q
from api import campaigns, routes

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _row() -> SessionRow:
    return SessionRow(
        session_id="s1", sensor="ssh", started_at=T0, last_event_at=T0 + timedelta(minutes=5)
    )


def _sql(stmt: Any) -> str:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    return str(stmt.compile(dialect=dialect, compile_kwargs={"literal_binds": True}))


class _Scalars:
    def all(self) -> list[Any]:
        return []


class _FakeDb:
    """Records the statements it is given; returns the loaded session row for ``get``."""

    def __init__(self, row: SessionRow | None) -> None:
        self.row = row
        self.stmts: list[Any] = []

    async def get(self, _model: Any, _key: Any) -> SessionRow | None:
        return self.row

    async def scalars(self, stmt: Any) -> _Scalars:
        self.stmts.append(stmt)
        return _Scalars()


def _assert_bounded(sql: str) -> None:
    assert "events.session_id = 's1'" in sql
    assert "events.ts >= '2026-11-01 12:00:00+00:00'" in sql
    assert "events.ts <= '2026-11-01 12:06:00+00:00'" in sql
    assert "events.sensor = 'ssh'" in sql


async def test_session_events_route_bounds_ts() -> None:
    db = _FakeDb(_row())
    page = await routes.list_session_events("s1", db, 100, None)  # type: ignore[arg-type]
    assert page.items == []
    _assert_bounded(_sql(db.stmts[0]))


async def test_session_events_route_404_without_session() -> None:
    import pytest
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await routes.list_session_events("s1", _FakeDb(None), 100, None)  # type: ignore[arg-type]
    assert exc.value.status_code == 404


async def test_campaign_excerpt_bounds_ts() -> None:
    db = _FakeDb(_row())
    assert await campaigns._excerpt(db, "s1") is None  # type: ignore[arg-type]
    sql = _sql(db.stmts[0])
    _assert_bounded(sql)
    assert "events.type != 'connect'" in sql


async def test_campaign_excerpt_without_session_row_runs_no_event_query() -> None:
    db = _FakeDb(None)
    assert await campaigns._excerpt(db, "gone") is None  # type: ignore[arg-type]
    assert db.stmts == []


def test_session_has_value_correlates_the_session_time_range() -> None:
    sql = _sql(select(SessionRow.session_id).where(q.session_has_value("command", "x")))
    assert "events.ts >= sessions.started_at" in sql
    assert "events.ts <= sessions.last_event_at + " in sql
