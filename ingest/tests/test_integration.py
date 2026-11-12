"""End-to-end against a real TimescaleDB (set POSTGRES_* to enable).

Runs the Alembic migration, writes through the ingest writer and reads through the API.
"""

import asyncio
import contextlib
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from api.main import create_app
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from suckerpot_common import Event, EventPublisher
from suckerpot_db import create_engine, create_session_factory, database_url_from_env

from ingest.config import Settings
from ingest.consumer import Consumer
from ingest.writer import write_batch

from .db_fixtures import ROLE_ENV, _migrate, _role_url
from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


@pytest.fixture
async def client(engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    """API client connected AS the read-only api role."""
    eng = create_engine(_role_url("API"), pool_size=2)
    app = create_app(create_session_factory(eng))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            yield c
    await eng.dispose()


async def test_roles_are_least_privilege(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles "
                    "WHERE rolname IN (:i, :a)"
                ),
                {"i": ROLE_ENV["POSTGRES_INGEST_USER"], "a": ROLE_ENV["POSTGRES_API_USER"]},
            )
        ).all()
    assert len(rows) == 2
    assert all(not any(r[1:]) for r in rows)

    # ingest role: inserts work, including into brand-new chunks (events 3 days apart)
    await write_batch(
        factory,
        [
            make_event("connect", sid="r1", offset_s=0),
            make_event("connect", sid="r2", offset_s=3 * 86400),
        ],
    )
    async with engine.connect() as conn:
        chunks = await conn.scalar(
            text(
                "SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name='events'"
            )
        )
    assert chunks is not None and chunks >= 2

    # api role: reads fine, writes denied
    api_eng = create_engine(_role_url("API"), pool_size=1)
    try:
        async with api_eng.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM sessions")) == 2
            assert await conn.scalar(text("SHOW statement_timeout")) == "5s"
        for stmt in (
            "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, "
            "last_event_at) VALUES ('x','ssh','192.0.2.1',1,2,now(),now())",
            "DELETE FROM events",
            "UPDATE sessions SET commands = 1",
            "DROP TABLE events",
        ):
            async with api_eng.connect() as conn:
                with pytest.raises(DBAPIError):
                    await conn.execute(text(stmt))
    finally:
        await api_eng.dispose()

    # ingest role cannot delete or create roles
    async with factory() as s:
        assert await s.scalar(text("SHOW statement_timeout")) == "30s"
        with pytest.raises(DBAPIError):
            await s.execute(text("DELETE FROM events"))


async def test_schema(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        hyper = await conn.scalar(
            text(
                "SELECT count(*) FROM timescaledb_information.hypertables "
                "WHERE hypertable_name = 'events'"
            )
        )
        interval = await conn.scalar(
            text(
                "SELECT time_interval FROM timescaledb_information.dimensions "
                "WHERE hypertable_name = 'events'"
            )
        )
        idx = {
            r[0]
            for r in await conn.execute(
                text("SELECT indexname FROM pg_indexes WHERE tablename IN ('events','sessions')")
            )
        }
    assert hyper == 1
    assert str(interval) == "1 day, 0:00:00"
    assert {
        "ix_events_session_id_ts",
        "ix_events_src_ip_ts",
        "ix_events_sensor_ts",
        "ix_events_tags",
        "ix_sessions_started_at",
        "ix_sessions_sensor_started_at",
        "ix_sessions_src_ip_sensor_started_at",
        "ix_sessions_tags",
        "ix_sessions_country",
    } <= idx


async def test_write_and_query(
    factory: async_sessionmaker[AsyncSession], client: httpx.AsyncClient
) -> None:
    batch1 = [
        make_event("connect", offset_s=0),
        make_event("login_attempt", offset_s=1, data={"success": False, "username": "root\x00"}),
        make_event("login_attempt", offset_s=2, data={"success": True}),
    ]
    batch2 = [
        make_event("command", offset_s=3, data={"input": "uname -a"}),
        make_event("download_attempt", offset_s=4, data={"url": "http://198.51.100.9/x.sh"}),
        make_event("disconnect", offset_s=9),
        make_event("http_request", sid="s2", offset_s=100, sensor="web", ip="192.0.2.5"),
    ]
    await write_batch(factory, batch1)
    await write_batch(factory, batch2)
    # out-of-order late event for s1 must not move started_at/ended_at backwards
    await write_batch(factory, [make_event("command", offset_s=-5)])

    r = await client.get("/api/v1/sessions/s1")
    assert r.status_code == 200
    s = r.json()
    assert s["event_count"] == 7
    assert (s["login_attempts"], s["commands"], s["downloads"]) == (2, 2, 1)
    assert s["login_success"] is True
    assert s["src_ip"] == "203.0.113.7" and s["sensor"] == "ssh"
    assert s["started_at"].startswith("2026-10-24T09:59:55")
    assert s["ended_at"].startswith("2026-10-24T10:00:09")
    assert s["country"] is None and s["tags"] == []

    r = await client.get("/api/v1/sessions", params={"sensor": "web"})
    assert [i["session_id"] for i in r.json()["items"]] == ["s2"]
    r = await client.get("/api/v1/sessions", params={"src_ip": "203.0.113.7"})
    assert [i["session_id"] for i in r.json()["items"]] == ["s1"]
    r = await client.get("/api/v1/sessions", params={"since": "2026-10-24T10:01:00Z"})
    assert [i["session_id"] for i in r.json()["items"]] == ["s2"]

    r = await client.get("/api/v1/sessions/s1/events", params={"limit": 3})
    page = r.json()
    assert [e["type"] for e in page["items"]] == ["command", "connect", "login_attempt"]
    assert page["next_cursor"]
    assert page["items"][1]["data"] == {}
    r = await client.get(
        "/api/v1/sessions/s1/events", params={"limit": 50, "cursor": page["next_cursor"]}
    )
    rest = r.json()
    assert len(rest["items"]) == 4 and rest["next_cursor"] is None
    assert rest["items"][0]["data"]["success"] is True
    assert (await client.get("/api/v1/sessions/nope/events")).status_code == 404
    assert (await client.get("/api/v1/sessions/nope")).status_code == 404


async def test_rdp_client_tool_reaches_the_api(
    factory: async_sessionmaker[AsyncSession], client: httpx.AsyncClient
) -> None:
    ntlm = {"method": "rdp-ntlm", "username": "admin", "success": False, "client_tool": "FreeRDP"}
    await write_batch(
        factory,
        [make_event("login_attempt", sid="r1", sensor="rdp", ip="198.51.100.4", data=ntlm)],
    )
    # A later event without a tool, or with "unknown", must not erase what was learned.
    await write_batch(
        factory,
        [
            make_event(
                "disconnect",
                sid="r1",
                offset_s=3,
                sensor="rdp",
                ip="198.51.100.4",
                data={"client_tool": "unknown"},
            )
        ],
    )
    assert (await client.get("/api/v1/sessions/r1")).json()["client_tool"] == "FreeRDP"
    await write_batch(factory, [make_event("connect", sid="ssh9", offset_s=0)])
    assert (await client.get("/api/v1/sessions/ssh9")).json()["client_tool"] is None


async def test_pagination_walks_all_sessions(
    factory: async_sessionmaker[AsyncSession], client: httpx.AsyncClient
) -> None:
    # Identical timestamps force the session_id tie-break.
    events = [make_event("connect", sid=f"sess-{i:03d}", offset_s=i // 10) for i in range(25)]
    await write_batch(factory, events)
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        params: dict[str, str | int] = {"limit": 7}
        if cursor:
            params["cursor"] = cursor
        body = (await client.get("/api/v1/sessions", params=params)).json()
        seen += [i["session_id"] for i in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == 25 and len(set(seen)) == 25
    assert seen == sorted(seen, key=lambda s: (int(s[5:]) // 10, s), reverse=True)


async def test_stats_summary(
    factory: async_sessionmaker[AsyncSession], client: httpx.AsyncClient
) -> None:
    from datetime import UTC, datetime

    from suckerpot_common import Event

    now = datetime.now(UTC)

    def ev(sid: str, etype: str, sensor: str, ip: str) -> Event:
        return Event.model_validate(
            {
                "ts": now,
                "sensor": sensor,
                "session_id": sid,
                "src_ip": ip,
                "src_port": 1,
                "dst_port": 2,
                "type": etype,
            }
        )

    await write_batch(
        factory,
        [
            ev("a", "connect", "ssh", "198.51.100.1"),
            ev("a", "command", "ssh", "198.51.100.1"),
            ev("b", "download_attempt", "web", "198.51.100.1"),
            ev("c", "connect", "telnet", "198.51.100.2"),
        ],
    )
    body = (await client.get("/api/v1/stats/summary")).json()
    assert body["events"] == 4 and body["sessions"] == 3 and body["unique_ips"] == 2
    assert body["sessions_with_commands"] == 1 and body["download_attempts"] == 1
    assert body["by_sensor"]["ssh"] == {"events": 2, "sessions": 1}
    assert (await client.get("/healthz")).json() == {"status": "ok", "db": "ok"}


async def test_password_rotation_on_every_migrate(engine: AsyncEngine) -> None:
    new_pw = "rotated-ingest-password"
    _migrate({"POSTGRES_INGEST_PASSWORD": new_pw})
    try:
        good = create_engine(
            database_url_from_env(
                {
                    **os.environ,
                    "POSTGRES_USER": ROLE_ENV["POSTGRES_INGEST_USER"],
                    "POSTGRES_PASSWORD": new_pw,
                }
            ),
            pool_size=1,
        )
        async with good.connect() as conn:
            assert await conn.scalar(text("SELECT 1")) == 1
        await good.dispose()
        old = create_engine(_role_url("INGEST"), pool_size=1)
        with pytest.raises(Exception, match="password authentication failed"):
            async with old.connect() as conn:
                await conn.scalar(text("SELECT 1"))
        await old.dispose()
    finally:
        _migrate()  # restore the original password for the other tests


async def test_no_default_privileges_left(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        n = await conn.scalar(
            text(
                "SELECT count(*) FROM pg_default_acl d JOIN pg_namespace n ON n.oid = "
                "d.defaclnamespace WHERE n.nspname = 'public' AND d.defaclacl::text ~ 'suckerpot'"
            )
        )
    assert n == 0


# ---- Redis + TimescaleDB end to end (needs REDIS_HOST; works with an unauthenticated Redis,
# the test creates the contract ACL users itself) ----------------------------------------------

needs_redis = pytest.mark.skipif(not os.environ.get("REDIS_HOST"), reason="REDIS_HOST not set")

SENSOR_ACL = "resetkeys ~itest:ssh -@all +xadd +hello +auth"
INGEST_ACL = (
    "resetkeys ~itest:* -@all +xreadgroup +xack +xgroup|create +xautoclaim +xtrim +hello +auth"
)


def _redis(user: str | None = None, password: str | None = None) -> Redis:
    return Redis(
        host=os.environ["REDIS_HOST"],
        port=int(os.environ.get("REDIS_PORT", "6379")),
        username=user or os.environ.get("REDIS_ADMIN_USER"),
        password=password or os.environ.get("REDIS_ADMIN_PASSWORD"),
        lib_name=None,
        lib_version=None,
    )


COMMAND_DATA = {
    "input": "uname -a",
    "output": "Linux",
    "prompt": "root@srv:~#",
    "cwd": "/root",
    "user": "root",
    "status": 0,
}


def _ssh_event(etype: str, offset_s: float, sid: str, data: dict[str, Any]) -> Event:
    return make_event(etype, sid=sid, offset_s=offset_s, data=data, sensor="ssh")


@needs_redis
async def test_redis_to_timescale_end_to_end(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    admin = _redis()
    streams = ("itest:ssh", "itest:web")
    await admin.delete(*streams)
    for s in streams:
        with contextlib.suppress(Exception):
            await admin.xgroup_destroy(s, "ingest")
    raw: Any = admin  # redis-py's execute_command is untyped
    for user, pw, acl in (
        ("itest-sensor-ssh", "sens", SENSOR_ACL),
        ("itest-ingest", "ing", INGEST_ACL),
    ):
        await raw.execute_command("ACL", "SETUSER", user, "on", f">{pw}", *acl.split())

    replay = [[0.1 * i, "o" if i % 2 else "i", "x" * 190] for i in range(55)]
    assert 11_000 < len(json.dumps(replay)) <= 12 * 1024
    sensor = EventPublisher(
        host=os.environ["REDIS_HOST"],
        port=int(os.environ.get("REDIS_PORT", "6379")),
        username="itest-sensor-ssh",
        password="sens",
        stream="itest:ssh",
    )
    events = [
        _ssh_event("connect", 0, "ssh-1", {}),
        _ssh_event(
            "login_attempt", 1, "ssh-1", {"username": "root", "password": "x", "success": True}
        ),
        _ssh_event(
            "command",
            2,
            "ssh-1",
            {
                "input": "uname -a",
                "output": "Linux",
                "prompt": "root@srv:~#",
                "cwd": "/root",
                "user": "root",
                "status": 0,
            },
        ),
        _ssh_event("download_attempt", 3, "ssh-1", {"url": "http://198.51.100.9/x.sh"}),
        _ssh_event("scan", 4, "ssh-1", {"kind": "tcp_forward_attempt", "host": "h", "port": 25}),
        _ssh_event(
            "disconnect", 9, "ssh-1", {"duration_s": 9.0, "reason": "closed", "replay": replay}
        ),
    ]
    # Orphans: delivered to a dead consumer before ingest starts.
    await sensor.publish_many(events[:3])
    await admin.xgroup_create("itest:ssh", "ingest", id="0", mkstream=True)
    await admin.xgroup_create("itest:web", "ingest", id="0", mkstream=True)
    got: Any = await admin.xreadgroup("ingest", "dead-host", {"itest:ssh": ">"}, count=10)
    assert len(got[0][1]) == 3
    await sensor.publish_many(events[3:])
    # A forged event: web sensor name on the ssh stream (accepted by Redis, dropped by ingest).
    await sensor.publish(make_event("connect", sid="forged", sensor="web"))
    # The sensor user may not write elsewhere.
    with pytest.raises(Exception, match="No permissions"):
        await _redis("itest-sensor-ssh", "sens").xadd("itest:web", {"v": "1"})

    settings = Settings.from_env(
        {
            "INGEST_STREAMS": ",".join(streams),
            "INGEST_HEARTBEAT_PATH": str(tmp_path / "hb"),
            "INGEST_CLAIM_IDLE_MS": "0",
        }
    )
    consumer = Consumer(settings, _redis("itest-ingest", "ing"), factory)
    task = asyncio.create_task(consumer.run())
    try:
        for _ in range(100):
            await asyncio.sleep(0.1)
            async with engine.connect() as conn:
                n = await conn.scalar(text("SELECT count(*) FROM events"))
            if n == 6 and consumer.sensor_mismatches == 1:
                break
        else:
            pytest.fail(
                f"ingest did not finish (events={n}, mismatches={consumer.sensor_mismatches})"
            )
    finally:
        consumer.stop.set()
        await asyncio.wait_for(task, 10)
        await consumer.redis.aclose()

    async with engine.connect() as conn:
        row = await conn.execute(text("SELECT * FROM sessions WHERE session_id = 'ssh-1'"))
        sess = row.mappings().one()
        counters = (sess["event_count"], sess["login_attempts"], sess["commands"])
        assert counters == (6, 1, 1)
        assert sess["downloads"] == 1
        assert sess["login_success"] is True and sess["ended_at"] is not None
        stored = await conn.scalar(
            text("SELECT data->'replay' FROM events WHERE type = 'disconnect'")
        )
        cmd = await conn.scalar(text("SELECT data FROM events WHERE type = 'command'"))
        assert (
            await conn.scalar(text("SELECT count(*) FROM sessions WHERE session_id = 'forged'"))
            == 0
        )
    assert stored == replay
    assert cmd["prompt"] == "root@srv:~#" and cmd["cwd"] == "/root" and cmd["status"] == 0
    for stream in streams:
        pending = await admin.xpending(stream, "ingest")
        assert pending["pending"] == 0
    await admin.delete(*streams)
    await admin.aclose()
