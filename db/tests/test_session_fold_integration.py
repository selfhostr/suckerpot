"""Flood groups (0034): ``fold_session_buckets`` against a real TimescaleDB.

A source that opens many plain connections in one UTC hour has them merged into one group row
(``kind = 'burst'``). These tests pin what folds and what never does, that the sums survive,
the privileges (ingest may only execute the function), the CHECK constraints, the roll-up into
``sessions_daily`` and the refusing downgrade. Addresses are from the documentation ranges.
"""

# ruff: noqa: S608  (test SQL is built from constants)

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.event_bounds import group_events_select, session_events_select
from suckerpot_db.locks import SESSION_FOLD
from suckerpot_db.models import SessionRow
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": "collector-test-password",
    "POSTGRES_ANALYZER_PASSWORD": "analyzer-test-password",
}
PLAIN = ["credential-stuffing", "weak-credentials", "rdp-cleartext", "scanner", "smb-v1-probe"]
SRC = "203.0.113.10"
IDLE = timedelta(minutes=15)
HOUR = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=6)
PREV = HOUR - timedelta(hours=1)
OLD_DAY = (datetime.now(UTC) - timedelta(days=100)).replace(
    hour=10, minute=0, second=0, microsecond=0
)

INSERT_SESSION = text(
    """
    INSERT INTO sessions (
        session_id, sensor, src_ip, src_port, dst_port, started_at, ended_at, last_event_at,
        event_count, login_attempts, login_success, commands, downloads, http_requests, country,
        city, asn, org, abuse_score, known_scanner, tags, client_tool, techniques, campaign_id,
        benign, scanner_name
    ) VALUES (
        :sid, :sensor, CAST(CAST(:ip AS text) AS inet), :src_port, :dst_port, :started, :ended,
        :last, :events, :logins, :ok, :cmds, :dl, :http, :country, :city, :asn, :org, :abuse,
        :scanner, CAST(:tags AS text[]), :tool, CAST(:techniques AS text[]), :campaign, :benign,
        :scanner_name
    )
    """
)


def row(sid: str, offset_s: int = 0, hour: datetime = HOUR, **over: Any) -> dict[str, Any]:
    """One plain, closed RDP connection of ``SRC`` in ``hour``; ``over`` changes any field."""
    started = hour + timedelta(seconds=offset_s)
    base: dict[str, Any] = {
        "sid": sid, "sensor": "rdp", "ip": SRC, "src_port": 40000 + offset_s % 20000,
        "dst_port": 3389, "started": started, "ended": started + timedelta(seconds=2),
        "last": started + timedelta(seconds=2), "events": 3, "logins": 1, "ok": False,
        "cmds": 0, "dl": 0, "http": 0, "country": "NL", "city": "Amsterdam", "asn": 64500,
        "org": "Example Net", "abuse": 40, "scanner": None, "tags": ["credential-stuffing"],
        "tool": None, "techniques": [], "campaign": None, "benign": False, "scanner_name": None,
    }  # fmt: skip
    return {**base, **over}


def plain_rows(
    n: int, prefix: str = "p", hour: datetime = HOUR, **over: Any
) -> list[dict[str, Any]]:
    return [row(f"{prefix}{i:03d}", offset_s=i * 30, hour=hour, **over) for i in range(n)]


def _as(user: str, password: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env({**ENV, "POSTGRES_USER": user, "POSTGRES_PASSWORD": password})
    )


async def _roles(env: Mapping[str, str]) -> None:
    engine = create_async_engine(database_url_from_env(env))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: apply_roles(c, env))
    finally:
        await engine.dispose()


def _alembic(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=DB_DIR,
        env=ENV,
        check=check,
        timeout=180,
        capture_output=True,
        text=True,
    )


TRUNCATE = "TRUNCATE sessions, events, indicators, sessions_daily, campaigns CASCADE"


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    await _roles(ENV)
    engine = create_async_engine(database_url_from_env(ENV))
    async with engine.begin() as conn:
        await conn.execute(text(TRUNCATE))
    yield engine
    # The other migration tests of this package downgrade the same database, and a downgrade
    # refuses while a flood group exists: leave none behind.
    async with engine.begin() as conn:
        await conn.execute(text(TRUNCATE))
    await engine.dispose()


async def seed(engine: AsyncEngine, rows: list[dict[str, Any]]) -> None:
    async with engine.begin() as conn:
        await conn.execute(INSERT_SESSION, rows)


CLOCK = object()  # ``as_of`` default: the caller has stored everything up to now


async def fold(
    engine: AsyncEngine,
    buckets: list[tuple[str, str, datetime]] | None = None,
    *,
    minimum: int | None = 20,
    tags: list[str] | None = None,
    idle: timedelta | None = IDLE,
    limit: int | None = 1000,
    as_of: datetime | object | None = CLOCK,
) -> int:
    """Call the function with one bucket (SRC, rdp, HOUR) unless ``buckets`` is given."""
    given = buckets if buckets is not None else [(SRC, "rdp", HOUR)]
    async with engine.begin() as conn:
        value = await conn.scalar(
            text(
                "SELECT fold_session_buckets(CAST(CAST(:ips AS text[]) AS inet[]), "
                "CAST(:sensors AS text[]), CAST(:hours AS timestamptz[]), CAST(:m AS integer), "
                "CAST(:tags AS text[]), CAST(:idle AS interval), CAST(:lim AS integer), "
                "CAST(:now AS timestamptz))"
            ),
            {
                "ips": [b[0] for b in given],
                "sensors": [b[1] for b in given],
                "hours": [b[2] for b in given],
                "m": minimum,
                "tags": PLAIN if tags is None else tags,
                "idle": idle,
                "lim": limit,
                "now": datetime.now(UTC) if as_of is CLOCK else as_of,
            },
        )
    return int(value)


async def restore(
    engine: AsyncEngine,
    ids: list[str],
    tags: list[str] | None = None,
    *,
    techniques: list[str] | None = None,
    tool: str | None = None,
) -> list[str]:
    """Call the restore function with the same group key for every id: the tags the connection
    carried when it was folded (``credential-stuffing``, like ``row()``, unless given)."""
    conns = [
        {"id": i, "tags": ["credential-stuffing"] if tags is None else tags,
         "techniques": techniques or [], "tool": tool}
        for i in ids
    ]  # fmt: skip
    async with engine.begin() as conn:
        got = await conn.scalars(
            text("SELECT restore_folded_sessions(CAST(:c AS jsonb))"), {"c": json.dumps(conns)}
        )
        return sorted(got.all())


EVENT = text(
    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data, tags)"
    " VALUES (:ts, :sensor, :sid, :type, CAST(CAST(:ip AS text) AS inet), 1, :port,"
    " CAST(:data AS jsonb), CAST(:tags AS text[]))"
)


async def add_events(engine: AsyncEngine, *events: dict[str, Any]) -> None:
    """Events with defaults: an RDP connect of SRC on port 3389, no data, no tags."""
    base = {"sensor": "rdp", "type": "connect", "ip": SRC, "port": 3389, "data": {}, "tags": []}
    async with engine.begin() as conn:
        for ev in events:
            values = {**base, **ev}
            await conn.execute(EVENT, {**values, "data": json.dumps(values["data"])})


def story(r: dict[str, Any], *, logins: int = 1) -> list[dict[str, Any]]:
    """The events of one seeded row: a connect, ``logins`` login attempts and a disconnect."""
    at = r["started"]
    out = [{"ts": at, "sid": r["sid"], "sensor": r["sensor"], "port": r["dst_port"]}]
    for k in range(logins):
        out.append({**out[0], "ts": at + timedelta(milliseconds=500 + k), "type": "login_attempt"})
    out.append({**out[0], "ts": r["ended"] or r["last"], "type": "disconnect"})
    return out


async def table(engine: AsyncEngine, where: str = "true") -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(f"SELECT *, host(src_ip) AS ip FROM sessions WHERE {where} ORDER BY session_id")
        )
        return [dict(r) for r in result.mappings()]


async def groups(engine: AsyncEngine) -> list[dict[str, Any]]:
    return await table(engine, "kind = 'burst'")


async def singles(engine: AsyncEngine) -> list[dict[str, Any]]:
    return await table(engine, "kind = 'session'")


async def total_connections(engine: AsyncEngine) -> int:
    async with engine.connect() as conn:
        return int(await conn.scalar(text("SELECT coalesce(sum(connections), 0) FROM sessions")))


# ---- what folds -----------------------------------------------------------------------------


async def test_thirty_connections_fold_into_one_group_with_equal_sums(owner: AsyncEngine) -> None:
    rows = plain_rows(30)
    for i, r in enumerate(rows):
        r.update(events=2 + i % 3, logins=1 + i % 2, abuse=10 + i, scanner=True if i == 7 else None)
    rows[3]["country"] = None  # geo comes from the rows that have it
    await seed(owner, rows)
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,"
                " data) VALUES (:ts, 'rdp', 'p000', 'connect', CAST('203.0.113.10' AS inet), 1,"
                " 3389, CAST('{}' AS jsonb))"
            ),
            {"ts": HOUR},
        )

    assert await fold(owner) == 30

    assert await singles(owner) == []
    (g,) = await groups(owner)
    assert g["session_id"].startswith("burst-") and len(g["session_id"]) == len("burst-") + 24
    assert (g["kind"], g["connections"], g["ip"], g["sensor"], g["dst_port"]) == (
        "burst", 30, SRC, "rdp", 3389,
    )  # fmt: skip
    assert g["event_count"] == sum(r["events"] for r in rows)
    assert g["login_attempts"] == sum(r["logins"] for r in rows)
    assert g["started_at"] == min(r["started"] for r in rows)
    assert g["last_event_at"] == max(r["last"] for r in rows)
    assert g["ended_at"] == max(r["ended"] for r in rows)
    assert (g["country"], g["city"], g["asn"], g["org"]) == (
        "NL",
        "Amsterdam",
        64500,
        "Example Net",
    )
    assert g["abuse_score"] == 39 and g["known_scanner"] is True
    assert (g["src_port"], g["login_success"], g["commands"], g["benign"]) == (0, False, 0, False)
    assert g["tags"] == ["credential-stuffing"] and g["clustered_at"] is not None
    assert g["campaign_id"] is None and g["scanner_name"] is None
    async with owner.connect() as conn:  # the events are never touched
        assert await conn.scalar(text("SELECT count(*) FROM events")) == 1


async def test_an_interesting_connection_keeps_its_row(owner: AsyncEngine) -> None:
    async with owner.begin() as conn:
        campaign = await conn.scalar(
            text(
                "INSERT INTO campaigns (name, first_seen, last_seen) "
                "VALUES ('example', now(), now()) RETURNING id"
            )
        )
    variants: dict[str, dict[str, Any]] = {
        "login_success": {"ok": True},
        "command": {"cmds": 1},
        "download": {"dl": 1},
        "http": {"http": 1},
        "twenty_logins": {"logins": 20},
        "campaign": {"campaign": campaign},
        "benign": {"benign": True},
        "scanner_name": {"scanner_name": "example-scanner"},
        "payload_tag": {"tags": ["credential-stuffing", "malware-drop"]},
    }
    rows = plain_rows(25)
    rows += [
        row(f"x-{name}", offset_s=3000 + i, **over)
        for i, (name, over) in enumerate(variants.items())
    ]
    await seed(owner, rows)
    assert await fold(owner) == 25
    assert {r["session_id"] for r in await singles(owner)} == {f"x-{n}" for n in variants}
    (g,) = await groups(owner)
    assert g["connections"] == 25
    assert await total_connections(owner) == 25 + len(variants)


async def test_nineteen_connections_do_not_fold_and_twenty_do(owner: AsyncEngine) -> None:
    await seed(owner, plain_rows(19))
    assert await fold(owner) == 0
    assert len(await singles(owner)) == 19 and await groups(owner) == []
    await seed(owner, [row("p-twenty", offset_s=1000)])
    assert await fold(owner) == 20
    assert await singles(owner) == []


async def test_the_bucket_counts_every_connection_of_the_hour(owner: AsyncEngine) -> None:
    """15 plain and 5 interesting ones make a flood: the 15 fold, the 5 stay."""
    await seed(owner, plain_rows(15) + [row(f"c{i}", offset_s=2000 + i, cmds=2) for i in range(5)])
    assert await fold(owner) == 15
    assert len(await singles(owner)) == 5


async def test_a_group_of_the_previous_hour_continues_in_this_one(owner: AsyncEngine) -> None:
    await seed(owner, plain_rows(25, "a", hour=PREV))
    assert await fold(owner, [(SRC, "rdp", PREV)]) == 25
    await seed(owner, plain_rows(3, "b"))
    assert await fold(owner, minimum=20) == 3  # three rows, but the address was flooding before
    assert len(await groups(owner)) == 2
    assert await singles(owner) == []
    # A gap of two hours is not a continuation.
    await seed(owner, plain_rows(3, "c", hour=HOUR + timedelta(hours=2)))
    assert await fold(owner, [(SRC, "rdp", HOUR + timedelta(hours=2))]) == 0


async def test_a_second_pass_folds_the_next_hour_but_one_call_does_not_chain(
    owner: AsyncEngine,
) -> None:
    await seed(owner, plain_rows(25, "a") + plain_rows(3, "b", hour=HOUR + timedelta(hours=1)))
    both = [(SRC, "rdp", HOUR), (SRC, "rdp", HOUR + timedelta(hours=1))]
    assert await fold(owner, both) == 25
    assert await fold(owner, both) == 3
    assert await fold(owner, both) == 0


async def test_a_connection_still_open_waits_for_the_idle_time(owner: AsyncEngine) -> None:
    now = datetime.now(UTC)
    started = now - timedelta(minutes=1)
    hour = started.replace(minute=0, second=0, microsecond=0)
    rows = [row(f"o{i:02d}", offset_s=0, hour=started, ended=None, last=started) for i in range(25)]
    await seed(owner, rows)
    assert await fold(owner, [(SRC, "rdp", hour)]) == 0
    # An idle time below five minutes is clamped to five.
    assert await fold(owner, [(SRC, "rdp", hour)], idle=timedelta(seconds=1)) == 0
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE sessions SET last_event_at = now() - interval '20 minutes'")
        )
    assert await fold(owner, [(SRC, "rdp", hour)]) == 25
    (g,) = await groups(owner)
    assert g["ended_at"] is not None  # a group is closed even when its rows had no end time


async def test_a_closed_connection_folds_at_once(owner: AsyncEngine) -> None:
    now = datetime.now(UTC)
    started = now - timedelta(seconds=30)
    hour = started.replace(minute=0, second=0, microsecond=0)
    await seed(owner, [row(f"e{i:02d}", hour=started, last=started) for i in range(25)])
    assert await fold(owner, [(SRC, "rdp", hour)]) == 25


# ---- what never folds -----------------------------------------------------------------------


async def test_a_connection_with_a_demo_event_never_folds(owner: AsyncEngine) -> None:
    """Demo data must never end up inside a group (the network node checks demo per session).
    The test reads the events of the row itself, not every event of the source's hour."""
    rows = plain_rows(25)
    await seed(owner, rows)
    for r in rows:
        await add_events(owner, *story(r))
    demo = {"data": {"demo": True}, "type": "scan"}
    await add_events(
        owner,
        # inside the rows' own time: these two keep their row
        {**demo, "ts": rows[3]["started"] + timedelta(seconds=1), "sid": rows[3]["sid"]},
        {**demo, "ts": rows[9]["started"] + timedelta(seconds=1), "sid": rows[9]["sid"],
         "data": {"demo": "true"}},
        # another session of the same source and hour, and a demo flag set to false
        {**demo, "ts": HOUR + timedelta(minutes=1), "sid": "someone-else"},
        {**demo, "ts": rows[5]["started"], "sid": rows[5]["sid"], "data": {"demo": False}},
        # the same id, but outside the row's own time
        {**demo, "ts": rows[7]["started"] - timedelta(minutes=5), "sid": rows[7]["sid"]},
    )  # fmt: skip
    assert await fold(owner) == 23
    assert [r["session_id"] for r in await singles(owner)] == ["p003", "p009"]


async def test_a_connection_with_an_indicator_keeps_its_row(owner: AsyncEngine) -> None:
    await seed(owner, plain_rows(25))
    async with owner.begin() as conn:
        indicator = await conn.scalar(
            text(
                "INSERT INTO indicators (type, value, role, first_seen, last_seen) "
                "VALUES ('ip', '203.0.113.9', 'c2', now(), now()) RETURNING id"
            )
        )
        for sid in ("p001", "p002", "p003"):
            await conn.execute(
                text(
                    "INSERT INTO indicator_sessions (indicator_id, session_id, src_ip, sensor,"
                    " seen_at) VALUES (:i, :s, CAST('203.0.113.10' AS inet), 'rdp', now())"
                ),
                {"i": indicator, "s": sid},
            )
    assert await fold(owner) == 22
    assert [r["session_id"] for r in await singles(owner)] == ["p001", "p002", "p003"]


async def test_tags_other_than_the_plain_ones_never_fold(owner: AsyncEngine) -> None:
    await seed(owner, plain_rows(25, tags=["credential-stuffing", "cve-2026-0001"]))
    assert await fold(owner) == 0
    assert await fold(owner, tags=["credential-stuffing"]) == 0
    await seed(owner, plain_rows(25, "u", tags=[], logins=0))  # untagged rows are plain
    assert await fold(owner, tags=[]) == 25
    assert len(await groups(owner)) == 1
    assert await fold(owner, tags=None) == 0  # the first 25 still carry a tag outside the set


async def test_the_function_refuses_cve_payload_and_severe_tags_whatever_it_is_given(
    owner: AsyncEngine,
) -> None:
    """A careless (or compromised) caller cannot call a payload tag plain."""
    for prefix, tag in (("m", "malware-drop"), ("c", "CVE-2026-0001"), ("x", "exploit"),
                        ("b", "bluekeep"), ("e", "eternalblue")):  # fmt: skip
        await seed(owner, plain_rows(22, prefix, tags=[tag]))
        assert await fold(owner, tags=[*PLAIN, tag]) == 0
    assert len(await singles(owner)) == 5 * 22 and await groups(owner) == []
    await seed(owner, plain_rows(22, "ok"))  # the plain ones of the same list still fold
    assert await fold(owner, tags=[*PLAIN, "malware-drop", "cve-2026-0001"]) == 22


@pytest.mark.parametrize(
    ("sensor", "extra", "folds"),
    [("rdp", 3, True), ("rdp", 4, False), ("smb", 4, False), ("sip", 4, True), ("sip", 5, False)],
)
async def test_a_connection_with_more_events_than_its_logins_explain_keeps_its_row(
    owner: AsyncEngine, sensor: str, extra: int, folds: bool
) -> None:
    """A payload sent as a scan event, untagged, is still more than a plain connection holds:
    connect, disconnect, the handshake (and on SIP its first message and summary)."""
    await seed(owner, plain_rows(24, sensor=sensor))
    await seed(owner, [row("odd", offset_s=2000, sensor=sensor, logins=2, events=2 + extra)])
    assert await fold(owner, [(SRC, sensor, HOUR)]) == (25 if folds else 24)
    assert [r["session_id"] for r in await singles(owner)] == ([] if folds else ["odd"])


async def test_idle_is_measured_against_the_callers_progress_not_the_clock(
    owner: AsyncEngine,
) -> None:
    """A connection with no disconnect, silent for 20 minutes in the database, is not idle when
    the caller has stored the streams only up to 10 minutes ago: its later events may be queued."""
    now = datetime.now(UTC)
    started = now - timedelta(minutes=21)
    hour = started.replace(minute=0, second=0, microsecond=0)
    last = started + timedelta(minutes=1)
    rows = [row(f"o{i:02d}", hour=started, ended=None, last=last) for i in range(25)]
    await seed(owner, rows)
    lagging = last + timedelta(minutes=10)
    assert await fold(owner, [(SRC, "rdp", hour)], as_of=lagging) == 0
    assert await fold(owner, [(SRC, "rdp", hour)], as_of=None) == 0  # unknown: only ended rows
    # A progress in the future counts as now, never later.
    young = [row(f"y{i:02d}", hour=started, ended=None, last=now - timedelta(minutes=3))
             for i in range(5)]  # fmt: skip
    await seed(owner, young)
    assert await fold(owner, [(SRC, "rdp", hour)], as_of=now + timedelta(hours=2)) == 25
    assert sorted(r["session_id"] for r in await singles(owner)) == [f"y{i:02d}" for i in range(5)]


async def test_a_connection_that_ended_folds_whatever_the_progress(owner: AsyncEngine) -> None:
    await seed(owner, plain_rows(25))
    assert await fold(owner, as_of=None) == 25


# ---- a late event of a folded connection ----------------------------------------------------


async def folded_flood(owner: AsyncEngine, n: int = 25) -> list[dict[str, Any]]:
    """``n`` plain connections with their events, folded into one group."""
    rows = plain_rows(n)
    await seed(owner, rows)
    for r in rows:
        await add_events(owner, *story(r))
    assert await fold(owner) == n
    return rows


async def late_row(owner: AsyncEngine, r: dict[str, Any], **over: Any) -> None:
    """What the writer's upsert leaves for a late event of ``r``: a fresh row from it alone."""
    late = r["started"] + timedelta(minutes=30)
    fields = {
        "started": late, "ended": None, "last": late, "events": 1, "logins": 0, "tags": [],
        "abuse": None, "scanner": None, **over,
    }  # fmt: skip
    await seed(owner, [row(r["sid"], **fields)])
    await add_events(owner, {"ts": late, "sid": r["sid"], "type": "command",
                             "data": {"input": "uname -a"}})  # fmt: skip


async def test_a_late_event_gives_a_folded_connection_its_row_back(owner: AsyncEngine) -> None:
    rows = await folded_flood(owner)
    (before,) = await groups(owner)
    await late_row(owner, rows[4], cmds=1)

    assert await restore(owner, [rows[4]["sid"], "unknown-id", before["session_id"]]) == ["p004"]

    (g,) = await groups(owner)
    assert g["session_id"] == before["session_id"]
    assert (g["connections"], g["event_count"], g["login_attempts"]) == (
        24, before["event_count"] - 3, before["login_attempts"] - 1,
    )  # fmt: skip
    (r,) = await singles(owner)
    assert r["session_id"] == "p004" and r["started_at"] == rows[4]["started"]  # its first event
    assert (r["event_count"], r["login_attempts"], r["commands"]) == (4, 1, 1)
    assert r["ended_at"] == rows[4]["ended"] and r["last_event_at"] > rows[4]["ended"]
    assert r["benign"] is False
    assert await total_connections(owner) == 25  # counted once
    async with AsyncSession(owner) as session:  # every event is read from one place
        group = await session.get(SessionRow, g["session_id"])
        own = await session.get(SessionRow, "p004")
        assert group is not None and own is not None
        in_group = (await session.execute(group_events_select(group))).scalars().all()
        assert "p004" not in {e.session_id for e in in_group} and len(in_group) == 24 * 3
        mine = (await session.execute(session_events_select(own))).scalars().all()
        assert len(mine) == 4

    assert await restore(owner, ["p004"]) == []  # once is enough


async def test_restoring_the_last_connection_of_a_group_removes_the_group(
    owner: AsyncEngine,
) -> None:
    """A group of the next hour can hold a single connection (it continues the hour before)."""
    first = plain_rows(25, "a", hour=PREV)
    await seed(owner, first)
    assert await fold(owner, [(SRC, "rdp", PREV)]) == 25
    (alone,) = plain_rows(1, "b")
    await seed(owner, [alone])
    await add_events(owner, *story(alone))
    assert await fold(owner) == 1
    assert sorted(g["connections"] for g in await groups(owner)) == [1, 25]
    await late_row(owner, alone)
    assert await restore(owner, ["b000"]) == ["b000"]
    assert [g["connections"] for g in await groups(owner)] == [25]
    assert await total_connections(owner) == 26


async def test_the_group_that_agrees_on_the_login_stage_is_the_one_that_gives_it_back(
    owner: AsyncEngine,
) -> None:
    rows = plain_rows(15, "t") + plain_rows(15, "n", logins=0, events=2)
    await seed(owner, rows)
    for r in rows:
        await add_events(owner, *story(r, logins=r["logins"]))
    assert await fold(owner) == 30
    before = {g["login_attempts"] > 0: g for g in await groups(owner)}
    await late_row(owner, rows[20])  # n005: never tried a password
    assert await restore(owner, ["n005"]) == ["n005"]
    after = {g["login_attempts"] > 0: g for g in await groups(owner)}
    assert after[True]["connections"] == before[True]["connections"] == 15
    assert after[False]["connections"] == 14
    assert await total_connections(owner) == 30


async def test_a_restarted_id_counter_never_takes_another_addresses_events(
    owner: AsyncEngine,
) -> None:
    """Some sensors name summary sessions ``sum-<counter>`` and start again at 0 after a restart:
    the id alone does not say which connection an event belongs to."""
    a, b = "198.51.100.20", "198.51.100.21"
    rows = plain_rows(25, "d", ip=a, sensor="docker", dst_port=2375)
    rows[0]["sid"] = "sum-0"
    await seed(owner, rows)
    for r in rows:
        await add_events(owner, *(dict(ev, ip=a) for ev in story(r)))
    assert await fold(owner, [(a, "docker", HOUR)]) == 25
    (before,) = await groups(owner)
    later = HOUR + timedelta(minutes=40)
    await seed(owner, [row("sum-0", ip=b, sensor="docker", dst_port=2375, hour=later, ended=None,
                           last=later, events=1, logins=0)])  # fmt: skip
    await add_events(owner, {"ts": later, "sid": "sum-0", "ip": b, "sensor": "docker",
                             "port": 2375, "type": "scan"})  # fmt: skip
    assert await restore(owner, ["sum-0"]) == []
    assert await groups(owner) == [before]
    (fresh,) = await singles(owner)
    assert (fresh["ip"], fresh["event_count"], fresh["started_at"]) == (b, 1, later)
    assert await total_connections(owner) == 26


async def test_a_restore_touches_only_the_exact_group_of_its_connection(owner: AsyncEngine) -> None:
    """Two groups of one source, hour and stage that differ only in tags: the group a restored
    connection leaves is the one whose id its own key gives, never the first sibling."""
    plain = plain_rows(24, "a")
    flagged = [row("s000", offset_s=1500, tags=["credential-stuffing", "scanner"])]
    await seed(owner, plain + flagged)
    for r in plain + flagged:
        await add_events(owner, *story(r))  # the events carry no tags: they cannot tell
    assert await fold(owner) == 25
    assert sorted(g["connections"] for g in await groups(owner)) == [1, 24]

    await late_row(owner, plain[5])
    assert await restore(owner, ["a005"]) == ["a005"]
    assert sorted(g["connections"] for g in await groups(owner)) == [1, 23]
    await late_row(owner, flagged[0])
    assert await restore(owner, ["s000"], ["scanner", "credential-stuffing"]) == ["s000"]
    assert [g["connections"] for g in await groups(owner)] == [23]
    assert await total_connections(owner) == 25

    # A key that names no group restores the row and touches no group at all.
    await late_row(owner, plain[6])
    assert await restore(owner, ["a006"], ["weak-credentials"]) == ["a006"]
    assert [g["connections"] for g in await groups(owner)] == [23]
    assert await restore(owner, ["a007"], None) == []  # no row: nothing


async def test_restore_leaves_a_row_with_no_earlier_events_alone(owner: AsyncEngine) -> None:
    await seed(owner, [row("fresh")])
    await add_events(owner, {"ts": HOUR, "sid": "fresh"})
    before = await table(owner)
    assert await restore(owner, ["fresh"]) == []
    assert await restore(owner, []) == []
    assert await table(owner) == before
    with pytest.raises(DBAPIError, match="too many sessions"):
        await restore(owner, [f"x{i}" for i in range(5001)])


async def test_a_group_row_is_never_folded_again_and_the_call_is_idempotent(
    owner: AsyncEngine,
) -> None:
    await seed(owner, plain_rows(30))
    assert await fold(owner) == 30
    before = await table(owner)
    assert await fold(owner) == 0
    assert await table(owner) == before
    # Late rows of the same hour join the existing group, whatever their number.
    await seed(owner, [row("late1", offset_s=3000), row("late2", offset_s=3010, events=4)])
    assert await fold(owner) == 2
    (g,) = await groups(owner)
    assert (g["session_id"], g["connections"]) == (before[0]["session_id"], 32)
    assert g["event_count"] == before[0]["event_count"] + 3 + 4
    assert g["last_event_at"] == HOUR + timedelta(seconds=3010 + 2)


# ---- how groups are keyed -----------------------------------------------------------------------


async def test_groups_are_keyed_by_port_stage_tags_and_tool(owner: AsyncEngine) -> None:
    rows = (
        plain_rows(5, "a")  # port 3389, tried a password, one tag
        + plain_rows(5, "b", logins=0)  # same, never tried one: another stage
        + plain_rows(4, "c", dst_port=3390)
        + plain_rows(2, "d", tags=["scanner", "credential-stuffing"])
        + plain_rows(2, "e", tags=["credential-stuffing", "scanner"])  # the same set
        + plain_rows(2, "f", tool="example-tool")
        + plain_rows(2, "g", techniques=["T1110"])
    )
    for i, r in enumerate(rows):
        r["sid"] = f"{r['sid']}-{i}"
        r["started"] = r["ended"] = r["last"] = HOUR + timedelta(seconds=i)
    await seed(owner, rows)
    assert await fold(owner) == len(rows)
    found = await groups(owner)
    assert sorted(g["connections"] for g in found) == [2, 2, 4, 4, 5, 5]
    assert len({g["session_id"] for g in found}) == 6
    assert sum(g["connections"] for g in found) == len(rows)
    both = [g for g in found if g["tags"] == ["credential-stuffing", "scanner"]]
    assert [g["connections"] for g in both] == [4]  # one group for both orders; tags are sorted
    assert sorted(g["login_attempts"] for g in found) == [0, 2, 2, 4, 4, 5]  # one per row


async def test_one_group_per_source_and_sensor(owner: AsyncEngine) -> None:
    await seed(
        owner,
        plain_rows(20, "a")
        + plain_rows(20, "b", sensor="smb", tags=["smb-v1-probe"], dst_port=445)
        + plain_rows(20, "c", ip="203.0.113.11"),
    )
    buckets = [(SRC, "rdp", HOUR), (SRC, "smb", HOUR), ("203.0.113.11", "rdp", HOUR)]
    assert await fold(owner, buckets) == 60
    found = await groups(owner)
    assert sorted((g["ip"], g["sensor"]) for g in found) == [
        (SRC, "rdp"), (SRC, "smb"), ("203.0.113.11", "rdp"),
    ]  # fmt: skip


# ---- inputs, locks ------------------------------------------------------------------------


async def test_inputs_are_clamped(owner: AsyncEngine) -> None:
    await seed(owner, plain_rows(4))
    assert await fold(owner, minimum=1) == 0  # the threshold is never below 5
    await seed(owner, [row("more", offset_s=2000)])
    assert await fold(owner, minimum=1) == 5
    await seed(owner, plain_rows(30, "q", hour=PREV))
    assert await fold(owner, [(SRC, "rdp", PREV)], limit=0) == 1  # at least one row
    assert await fold(owner, [(SRC, "rdp", PREV)], limit=10**9) == 29  # at most 5000
    await seed(owner, plain_rows(22, "r", hour=HOUR - timedelta(hours=3)))
    assert await fold(owner, [(SRC, "rdp", HOUR - timedelta(hours=3))], minimum=None) == 22
    assert await fold(owner, [(SRC, "rdp", HOUR)], tags=None, idle=None, limit=None) == 0


async def test_malformed_buckets(owner: AsyncEngine) -> None:
    assert await fold(owner, []) == 0
    async with owner.begin() as conn:
        assert (
            await conn.scalar(
                text("SELECT fold_session_buckets(NULL, NULL, NULL, 20, NULL, NULL, 10, NULL)")
            )
            == 0
        )
        with pytest.raises(DBAPIError, match="differ in length"):
            await conn.execute(
                text(
                    "SELECT fold_session_buckets(ARRAY[CAST('203.0.113.1' AS inet)], "
                    "ARRAY['rdp', 'ssh'], ARRAY[now()], 20, ARRAY['scanner'], "
                    "interval '15 minutes', 10, now())"
                )
            )
    async with owner.begin() as conn:
        with pytest.raises(DBAPIError, match="too many buckets"):
            await conn.execute(
                text(
                    "SELECT fold_session_buckets("
                    "array_fill(CAST('203.0.113.1' AS inet), ARRAY[5001]), "
                    "array_fill('rdp'::text, ARRAY[5001]), array_fill(now(), ARRAY[5001]), 20, "
                    "ARRAY['scanner'], interval '15 minutes', 10, now())"
                )
            )


async def test_a_held_advisory_lock_folds_nothing(owner: AsyncEngine) -> None:
    await seed(owner, plain_rows(25))
    async with owner.connect() as other:
        await other.execute(text("SELECT pg_advisory_lock(:k)"), {"k": SESSION_FOLD})
        try:
            assert await asyncio.wait_for(fold(owner), 10) == 0  # no waiting
            assert len(await singles(owner)) == 25
        finally:
            await other.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": SESSION_FOLD})
    assert await fold(owner) == 25


async def test_a_row_locked_by_another_transaction_is_skipped_not_waited_for(
    owner: AsyncEngine,
) -> None:
    await seed(owner, plain_rows(25))
    async with owner.connect() as other:
        await other.execute(
            text("SELECT session_id FROM sessions WHERE session_id < 'p005' FOR UPDATE")
        )
        assert await asyncio.wait_for(fold(owner), 10) == 20
        assert [r["session_id"] for r in await singles(owner)] == [f"p00{i}" for i in range(5)]
        await other.rollback()
    assert await fold(owner) == 5  # the existing group makes the bucket hot whatever is left
    (g,) = await groups(owner)
    assert g["connections"] == 25 and await singles(owner) == []


# ---- privileges ---------------------------------------------------------------------------


async def test_ingest_can_execute_the_function_but_not_delete_sessions(owner: AsyncEngine) -> None:
    ingest = _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"])
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    try:
        await seed(owner, plain_rows(25))
        with pytest.raises(DBAPIError) as denied:
            async with ingest.begin() as conn:
                await conn.execute(text("DELETE FROM sessions WHERE session_id = 'p000'"))
        assert getattr(denied.value.orig, "sqlstate", None) == "42501"
        with pytest.raises(DBAPIError) as refused:
            await fold(api)
        assert getattr(refused.value.orig, "sqlstate", None) == "42501"
        async with ingest.begin() as conn:
            # A temp table named like a real one must not capture the function's statements.
            await conn.execute(text("CREATE TEMP TABLE sessions (session_id text)"))
        assert await fold(ingest) == 25
        assert len(await groups(owner)) == 1
        assert await restore(ingest, ["p000"]) == []  # ingest may call it too
        with pytest.raises(DBAPIError) as refused:
            await restore(api, ["p000"])
        assert getattr(refused.value.orig, "sqlstate", None) == "42501"
    finally:
        await ingest.dispose()
        await api.dispose()


@pytest.mark.parametrize("name", ["fold_session_buckets", "restore_folded_sessions"])
async def test_the_function_is_owned_and_locked_down(owner: AsyncEngine, name: str) -> None:
    async with owner.connect() as conn:
        info = (
            await conn.execute(
                text(
                    "SELECT prosecdef, proconfig, proowner::regrole::text AS owner,"
                    " has_function_privilege('public', oid, 'EXECUTE') AS public_exec,"
                    " has_function_privilege(CAST(CAST(:ingest AS text) AS name), oid, 'EXECUTE')"
                    " AS ingest_exec,"
                    " has_function_privilege(CAST(CAST(:api AS text) AS name), oid, 'EXECUTE')"
                    " AS api_exec"
                    " FROM pg_proc WHERE proname = :name"
                ),
                {"ingest": ENV["POSTGRES_INGEST_USER"], "api": ENV["POSTGRES_API_USER"],
                 "name": name},
            )
        ).mappings().one()  # fmt: skip
        assert info["prosecdef"] is True
        assert set(info["proconfig"]) == {"search_path=pg_catalog, pg_temp", "lock_timeout=2s"}
        assert info["owner"] == ENV.get("POSTGRES_USER", "suckerpot")
        assert (info["public_exec"], info["ingest_exec"], info["api_exec"]) == (False, True, False)
        can_delete = await conn.scalar(
            text(
                "SELECT has_table_privilege(CAST(CAST(:u AS text) AS name), 'sessions', 'DELETE')"
            ),
            {"u": ENV["POSTGRES_INGEST_USER"]},
        )
        assert can_delete is False


# ---- schema ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"kind": "other"},
        {"kind": "burst"},  # a group needs a burst- id
        {"sid": "burst-forged"},  # a burst- id needs a group
        {"connections": 0},
        {"connections": 2},  # only a group stands for more than one connection
    ],
)
async def test_check_constraints(owner: AsyncEngine, fields: dict[str, Any]) -> None:
    stmt = text(
        "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,"
        " last_event_at, kind, connections) VALUES (:sid, 'rdp', CAST('203.0.113.10' AS inet), 1,"
        " 3389, now(), now(), :kind, :connections)"
    )
    params = {"sid": "ok-id", "kind": "session", "connections": 1} | fields
    with pytest.raises(DBAPIError) as err:
        async with owner.begin() as conn:
            await conn.execute(stmt, params)
    assert getattr(err.value.orig, "sqlstate", None) == "23514"  # check_violation
    good = {"sid": "burst-" + "a" * 24, "kind": "burst", "connections": 9}
    async with owner.begin() as conn:
        await conn.execute(stmt, good)


async def test_index_and_storage_settings(owner: AsyncEngine) -> None:
    async with owner.connect() as conn:
        indexes = {
            r[0]: r[1]
            for r in await conn.execute(
                text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'sessions'")
            )
        }
        assert "ix_sessions_src_ip" not in indexes
        assert (
            "(src_ip, sensor, started_at DESC)" in indexes["ix_sessions_src_ip_sensor_started_at"]
        )
        options = await conn.scalar(
            text("SELECT reloptions FROM pg_class WHERE relname = 'sessions'")
        )
        assert set(options) == {
            "autovacuum_vacuum_scale_factor=0.05",
            "autovacuum_analyze_scale_factor=0.05",
        }


async def test_a_group_has_the_events_of_its_connections_only(owner: AsyncEngine) -> None:
    """A group's events: same source, sensor and port, in range, minus a connection with a row."""
    rows = [*plain_rows(25), row("hero", offset_s=100, cmds=2, tags=["recon"])]
    await seed(owner, rows)
    async with owner.begin() as conn:
        for r in rows:
            for k in range(2):
                await conn.execute(
                    text(
                        "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port,"
                        " dst_port, data) VALUES (:ts, 'rdp', :sid, 'login_attempt',"
                        " CAST('203.0.113.10' AS inet), 1, 3389, CAST('{}' AS jsonb))"
                    ),
                    {"ts": r["started"] + timedelta(seconds=k), "sid": r["sid"]},
                )
        await conn.execute(  # same source and time, another port: not part of the group
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,"
                " data) VALUES (:ts, 'rdp', 'other', 'connect', CAST('203.0.113.10' AS inet), 1,"
                " 3390, CAST('{}' AS jsonb))"
            ),
            {"ts": HOUR + timedelta(seconds=40)},
        )
    assert await fold(owner) == 25
    async with AsyncSession(owner) as session:
        (g,) = await groups(owner)
        group = await session.get(SessionRow, g["session_id"])
        assert group is not None
        events = (await session.execute(group_events_select(group))).scalars().all()
        assert len(events) == 50
        assert {e.session_id for e in events}.isdisjoint({"hero", "other"})


# ---- the roll-up and the downgrade ----------------------------------------------------------


async def test_sessions_daily_is_the_same_with_and_without_folding(owner: AsyncEngine) -> None:
    def day_rows(sensor: str) -> list[dict[str, Any]]:
        rows = plain_rows(30, f"{sensor}-", hour=OLD_DAY, sensor=sensor)
        for i, r in enumerate(rows):
            r.update(logins=1 + i % 3, events=2 + i % 3 + i % 2)
        win = row(f"{sensor}-win", 1900, hour=OLD_DAY, sensor=sensor, ok=True, cmds=3, dl=1, http=2)
        return [*rows, win]

    await seed(owner, day_rows("rdp") + day_rows("smb"))  # the same data on two sensors
    assert await fold(owner, [(SRC, "rdp", OLD_DAY)], tags=["credential-stuffing"]) == 30
    assert len(await groups(owner)) == 1
    async with owner.begin() as conn:
        await conn.execute(
            text("CALL suckerpot_maintenance(0, CAST(:cfg AS jsonb))"),
            {"cfg": json.dumps({"retention_days": 90})},
        )
    async with owner.connect() as conn:
        daily = (
            await conn.execute(
                text(
                    "SELECT sensor, sessions, events, login_attempts, logins_succeeded, commands,"
                    " downloads, http_requests, unique_ips FROM sessions_daily ORDER BY sensor"
                )
            )
        ).all()
        assert await conn.scalar(text("SELECT count(*) FROM sessions")) == 0
    by_sensor = {r[0]: tuple(r[1:]) for r in daily}
    assert by_sensor["rdp"] == by_sensor["smb"]
    assert by_sensor["rdp"][0] == 31  # sessions: the sum of connections, not the 2 rows left
    assert by_sensor["rdp"][3] == 1  # logins_succeeded


async def test_the_downgrade_refuses_while_groups_exist_and_round_trips_otherwise(
    owner: AsyncEngine,
) -> None:
    await seed(owner, [*plain_rows(25), row("keep", offset_s=3000, cmds=1)])
    assert await fold(owner) == 25
    refused = _alembic("downgrade", "0033", check=False)
    assert refused.returncode != 0 and "downgrade refused" in refused.stderr
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "0034"
        assert await conn.scalar(text("SELECT count(*) FROM sessions WHERE kind = 'burst'")) == 1

    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM sessions WHERE kind = 'burst'"))
    _alembic("downgrade", "0033")
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "0033"
        cols = {
            r[0]
            for r in await conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'sessions'"
                )
            )
        }
        assert not {"kind", "connections"} & cols
        assert (
            await conn.scalar(text("SELECT to_regclass('ix_sessions_src_ip') IS NOT NULL")) is True
        )
        assert await conn.scalar(text("SELECT to_regproc('fold_session_buckets') IS NULL")) is True
        assert (
            await conn.scalar(text("SELECT to_regproc('restore_folded_sessions') IS NULL")) is True
        )
        assert await conn.scalar(text("SELECT count(*) FROM sessions")) == 1  # the row it kept
        # The old maintenance body runs on the old table.
        await conn.execute(text("CALL suckerpot_maintenance(0, CAST('{}' AS jsonb))"))
        await conn.commit()

    _alembic("upgrade", "head")
    await _roles(ENV)
    fresh = create_async_engine(database_url_from_env(ENV))  # no statement cached before the change
    try:
        async with fresh.connect() as conn:
            assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "0034"
            kept = (await conn.execute(text("SELECT kind, connections FROM sessions"))).one()
            assert tuple(kept) == ("session", 1)  # existing rows get the defaults
        await seed(fresh, plain_rows(25, "n"))
        assert await fold(fresh) == 25
    finally:
        await fresh.dispose()
