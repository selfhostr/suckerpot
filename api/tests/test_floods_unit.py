"""Flood groups in the API without a database: which statements are built, and what they read.

A group (``kind = 'burst'``) has no events under its own id. These tests pin that the events
endpoint, the credentials endpoint and the value filter read a group's events by source, sensor and
port inside its time range, that a folded id is placed from its own events at ``at`` +- 1 h, and
that the counters weigh a group by its connections.
"""

import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import create_async_engine
from suckerpot_db import create_session_factory
from suckerpot_db.models import SessionRow

from api import abuse_exports, routes, session_floods, story
from api import analytics_queries as q
from api.main import create_app
from api.schemas import SessionDetail, SessionOut

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
GROUP_ID = "burst-0123456789abcdef01234567"


def _row(**over: Any) -> SessionRow:
    base: dict[str, Any] = {
        "session_id": "s1",
        "sensor": "rdp",
        "src_ip": "203.0.113.7",
        "src_port": 40000,
        "dst_port": 3389,
        "started_at": T0,
        "ended_at": T0 + timedelta(minutes=5),
        "last_event_at": T0 + timedelta(minutes=5),
        "event_count": 3,
        "login_attempts": 1,
        "login_success": False,
        "commands": 0,
        "downloads": 0,
        "http_requests": 0,
        "tags": [],
        "techniques": [],
        "benign": False,
        "kind": "session",
        "connections": 1,
    }
    return SessionRow(**{**base, **over})


def _group(login_attempts: int = 800) -> SessionRow:
    return _row(
        session_id=GROUP_ID,
        kind="burst",
        connections=800,
        src_port=0,
        event_count=2400,
        login_attempts=login_attempts,
        last_event_at=T0 + timedelta(minutes=50),
        ended_at=T0 + timedelta(minutes=50),
        tags=["credential-stuffing"],
    )


def _plain() -> SessionRow:
    return _row()


def _sql(stmt: Any) -> str:
    """The statement with its bound values written in (an inet value has no literal renderer)."""
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = stmt.compile(dialect=dialect)
    sql = str(compiled)
    for name, value in compiled.params.items():
        shown = str(value) if isinstance(value, int) else f"'{value}'"
        sql = sql.replace(f"%({name})s", shown)
    return re.sub(r"::(?:VARCHAR|TEXT|INTEGER|INET|TIMESTAMP WITH TIME ZONE)", "", sql)


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    def all(self) -> list[Any]:
        return self.rows

    def first(self) -> Any:
        return self.rows[0] if self.rows else None

    def one(self) -> Any:
        return self.rows[0]


class _FakeDb:
    """Records the statements; ``rows`` is what each execute/scalars call answers."""

    def __init__(self, row: SessionRow | None, rows: list[Any] | None = None) -> None:
        self.row = row
        self.rows = rows or []
        self.stmts: list[Any] = []

    async def get(self, _model: Any, _key: Any) -> SessionRow | None:
        return self.row

    async def scalars(self, stmt: Any) -> _Result:
        self.stmts.append(stmt)
        return _Result(self.rows)

    async def execute(self, stmt: Any) -> _Result:
        self.stmts.append(stmt)
        return _Result(self.rows)


# ---- the events of a group -----------------------------------------------------------------


async def test_group_events_route_reads_by_source_sensor_port_and_time() -> None:
    db = _FakeDb(_group())
    page = await routes.list_session_events(GROUP_ID, db, 100, None)  # type: ignore[arg-type]
    assert page.items == []
    sql = _sql(db.stmts[0])
    assert "events.src_ip = '203.0.113.7'" in sql
    assert "events.sensor = 'rdp'" in sql
    assert "events.dst_port = 3389" in sql
    assert "events.ts >= '2026-11-01 12:00:00+00:00'" in sql
    assert "events.ts <= '2026-11-01 12:51:00+00:00'" in sql
    # The connections that kept a row of their own are told on their own page.
    assert (
        "NOT (EXISTS (SELECT * \nFROM sessions \nWHERE sessions.session_id = events.session_id))"
        in sql
    )
    assert "events.session_id = '" not in sql


async def test_plain_session_events_route_is_unchanged() -> None:
    db = _FakeDb(_plain())
    await routes.list_session_events("s1", db, 100, None)  # type: ignore[arg-type]
    sql = _sql(db.stmts[0])
    where = sql.split("WHERE", 1)[1]
    assert "events.session_id = 's1'" in where
    assert "events.src_ip" not in where


async def test_credentials_route_404_without_session() -> None:
    with pytest.raises(HTTPException) as exc:
        await routes.get_session_credentials("gone", _FakeDb(None), 10)  # type: ignore[arg-type]
    assert exc.value.status_code == 404


async def test_credentials_of_a_group_without_logins_reads_nothing() -> None:
    db = _FakeDb(None)
    out = await session_floods.credentials_of(db, _group(login_attempts=0), 10)  # type: ignore[arg-type]
    assert out.attempts == 0
    assert (out.usernames, out.passwords, out.pairs) == ([], [], [])
    assert db.stmts == []


def test_credentials_read_the_group_bound_and_only_login_attempts() -> None:
    sql = _sql(session_floods._login_attempts(_group()))
    assert "events.src_ip = '203.0.113.7'" in sql
    assert "events.type = 'login_attempt'" in sql
    assert "events.ts >= '2026-11-01 12:00:00+00:00'" in sql
    assert f"LIMIT {session_floods.MAX_CREDENTIAL_EVENTS}" in sql
    assert "left(coalesce(events.data ->> 'password', ''), 256)" in sql


def test_credentials_of_a_plain_session_read_its_own_bound() -> None:
    sql = _sql(session_floods._login_attempts(_plain()))
    assert "events.session_id = 's1'" in sql
    assert "events.ts <= '2026-11-01 12:06:00+00:00'" in sql
    assert "events.src_ip" not in sql.split("WHERE", 1)[1]


class _CredDb(_FakeDb):
    """The totals statement answers one row of zeros, every other statement no rows."""

    def __init__(self) -> None:
        super().__init__(None)

    async def execute(self, stmt: Any) -> _Result:
        self.stmts.append(stmt)
        return _Result([(0, 0, 0, 0)] if len(self.stmts) == 1 else [])


@pytest.mark.parametrize(("asked", "expected"), [(0, 1), (7, 7), (500, session_floods.MAX_TOP)])
async def test_credentials_top_is_clamped(asked: int, expected: int) -> None:
    db = _CredDb()
    await session_floods.credentials_of(db, _group(), asked)  # type: ignore[arg-type]
    limits = [_sql(s).rsplit("LIMIT ", 1)[-1] for s in db.stmts[1:]]
    assert limits and all(int(x) == expected for x in limits)


# ---- a folded id ---------------------------------------------------------------------------


class _Ev:
    def __init__(self, type_: str, ts: datetime) -> None:
        self.type, self.ts = type_, ts
        self.src_ip, self.sensor, self.dst_port = "203.0.113.7", "rdp", 3389


class _ProbeDb:
    """The probe query answers events, the group query answers the group."""

    def __init__(self, events: list[_Ev], group: SessionRow | None) -> None:
        self.events, self.group = events, group
        self.stmts: list[Any] = []

    async def execute(self, stmt: Any) -> _Result:
        self.stmts.append(stmt)
        return _Result(self.events)

    async def scalars(self, stmt: Any) -> _Result:
        self.stmts.append(stmt)
        return _Result([self.group] if self.group is not None else [])

    async def get(self, _model: Any, _key: Any) -> None:
        return None


async def test_folded_id_is_found_in_the_events_around_at() -> None:
    at = T0 + timedelta(minutes=10)
    db = _ProbeDb([_Ev("connect", at), _Ev("login_attempt", at)], _group())
    found = await session_floods.find_group_of(db, "gone-1", at)  # type: ignore[arg-type]
    assert found is not None and found.session_id == GROUP_ID
    probe, group_stmt = (_sql(s) for s in db.stmts)
    assert "events.session_id = 'gone-1'" in probe
    assert "events.ts >= '2026-11-01 11:10:00+00:00'" in probe  # at - 1 h
    assert "events.ts <= '2026-11-01 13:10:00+00:00'" in probe  # at + 1 h
    assert "sessions.kind = 'burst'" in group_stmt
    assert "sessions.src_ip = '203.0.113.7'" in group_stmt
    assert "sessions.dst_port = 3389" in group_stmt


async def test_folded_id_prefers_the_group_that_agrees_on_login() -> None:
    at = T0 + timedelta(minutes=10)
    for events, stage in (([_Ev("login_attempt", at)], "true"), ([_Ev("connect", at)], "false")):
        db = _ProbeDb(events, _group())
        await session_floods.find_group_of(db, "gone", at)  # type: ignore[arg-type]
        sql = _sql(db.stmts[1])
        assert f"ORDER BY CASE WHEN ((sessions.login_attempts > 0) = {stage})" in sql, sql


async def test_folded_id_with_no_events_is_not_found() -> None:
    db = _ProbeDb([], _group())
    assert await session_floods.find_group_of(db, "gone", T0) is None  # type: ignore[arg-type]
    assert len(db.stmts) == 1  # the group is not even looked for


async def test_detail_route_404_without_row_or_at() -> None:
    with pytest.raises(HTTPException) as exc:
        await routes.get_session_detail("gone", _FakeDb(None), None)  # type: ignore[arg-type]
    assert exc.value.status_code == 404


async def test_detail_route_404_when_no_group_holds_the_id() -> None:
    db = _ProbeDb([], None)
    with pytest.raises(HTTPException) as exc:
        await routes.get_session_detail("gone", db, T0)  # type: ignore[arg-type]
    assert exc.value.status_code == 404


async def test_detail_route_returns_the_group_with_folded_from() -> None:
    at = T0 + timedelta(minutes=10)
    db = _ProbeDb([_Ev("connect", at)], _group())
    out = await routes.get_session_detail("gone-1", db, at)  # type: ignore[arg-type]
    assert isinstance(out, SessionDetail)
    assert (out.session_id, out.kind, out.connections) == (GROUP_ID, "burst", 800)
    assert out.folded_from == "gone-1"


async def test_detail_route_of_an_existing_row_has_no_folded_from() -> None:
    out = await routes.get_session_detail("s1", _FakeDb(_group()), None)  # type: ignore[arg-type]
    assert out.session_id == GROUP_ID
    assert out.folded_from is None


def test_session_out_defaults_describe_a_plain_connection() -> None:
    fields = SessionOut.model_fields
    assert fields["kind"].default == "session"
    assert fields["connections"].default == 1
    assert "folded_from" not in fields
    assert "folded_from" in SessionDetail.model_fields


# ---- the filters and the counters ----------------------------------------------------------


def test_value_filter_has_a_branch_for_groups_and_one_for_connections() -> None:
    sql = _sql(select(SessionRow.session_id).where(q.session_has_value("password", "123456")))
    assert "sessions.kind = 'session' AND (EXISTS" in sql
    assert "sessions.kind = 'burst' AND (EXISTS" in sql
    assert "events.src_ip = sessions.src_ip" in sql
    assert "events.sensor = sessions.sensor" in sql
    assert "events.dst_port = sessions.dst_port" in sql
    assert "events.session_id = sessions.session_id" in sql
    assert "x.session_id = events.session_id" in sql
    # The same truncated expression as /stats/top, in both branches.
    assert sql.count("left((events.data ->> 'password'), 256) = '123456'") == 2


def test_top_of_a_session_field_sums_connections_and_ends_a_group_at_its_last_event() -> None:
    w = q.Window(T0, T0 + timedelta(hours=1))
    sql = _sql(q.top_stmt("country", w, None, 5))
    assert "sessions.connections AS w" in sql
    assert "coalesce(sum(v.w), 0) AS n" in sql
    assert "CASE WHEN (sessions.kind = 'burst') THEN sessions.last_event_at" in sql
    assert "max(v.last_ts) AS last_seen" in sql


def test_top_of_an_event_field_still_counts_events() -> None:
    w = q.Window(T0, T0 + timedelta(hours=1))
    sql = _sql(q.top_stmt("password", w, None, 5))
    assert "1 AS w" in sql
    assert "FROM sessions" not in sql


def test_sessions_per_bucket_sum_connections_and_events_per_bucket_count_rows() -> None:
    w = q.Window(T0, T0 + timedelta(hours=3))
    assert "coalesce(sum(sessions.connections), 0) AS n" in _sql(
        q.sessions_bucket_stmt("1h", w, None)
    )
    ev = _sql(q.events_bucket_stmt("1h", w, None))
    assert "count(*) AS n" in ev and "connections" not in ev


def test_attackers_and_asns_sum_connections() -> None:
    a = _sql(q.attackers_stmt(sort="sessions", order="desc", limit=5))
    assert "coalesce(sum(sessions.connections), 0) AS sessions" in a
    assert (
        "sum(sessions.connections) FILTER (WHERE sessions.login_success), 0) AS login_success" in a
    )
    n = _sql(q.asns_stmt("sessions", 5, None))
    assert "coalesce(sum(sessions.connections), 0) AS sessions" in n


def test_the_brute_force_severity_is_per_connection() -> None:
    assert "s.kind = 'session' AND s.login_attempts >= 50" in abuse_exports.SEVERE


async def test_stories_come_from_connections_only() -> None:
    db = _FakeDb(None)
    assert await story._stories(db, [], T0) == []  # type: ignore[arg-type]
    assert "sessions.kind = 'session'" in _sql(db.stmts[0])


# ---- request validation (no query reaches the database) -------------------------------------


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    engine = create_async_engine(
        "postgresql+asyncpg://u:p@127.0.0.1:1/d", connect_args={"timeout": 1}
    )
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            yield c
    await engine.dispose()


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/sessions?kind=group",
        "/api/v1/sessions?kind=",
        "/api/v1/sessions/abc?at=2026-11-01T12:00:00",  # no time zone
        "/api/v1/sessions/abc?at=yesterday",
        "/api/v1/sessions/abc/credentials?limit=0",
        "/api/v1/sessions/abc/credentials?limit=51",
        "/api/v1/sessions/a.b/credentials",
    ],
)
async def test_flood_parameters_are_validated(client: httpx.AsyncClient, path: str) -> None:
    assert (await client.get(path)).status_code == 422
