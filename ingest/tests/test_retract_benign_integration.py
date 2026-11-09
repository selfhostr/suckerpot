"""``retract_benign`` must not decompress old chunks (the incident behind migration 0031).

The 0015 body joined ``events`` to ``sessions`` on ``e.ts >= s.started_at``, a bound the planner
cannot use to exclude chunks. Once the oldest chunk was compressed, one call decompressed it and
hit the ingest role's 30 s statement timeout, which stalled the whole pipeline.

Needs POSTGRES_HOST (owner credentials) like the other integration tests.
"""

import os
import time

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession, async_sessionmaker

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

OLD_DAYS = 10  # older than the 7 day compression policy
SESSION_INSERT = text(
    "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,"
    " last_event_at, event_count, login_attempts, login_success, commands, downloads,"
    " http_requests, benign, scanner_name) VALUES (:id, 'web', CAST('203.0.113.9' AS inet), 1, 80,"
    " now() - make_interval(secs => :start), now() - make_interval(secs => :end), 3, 0, false,"
    " 0, 0, 3, false, 'ExampleScanner')"
)
EVENT_INSERT = text(
    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data, benign)"
    " VALUES (now() - make_interval(secs => :age), 'web', :id, 'http_request',"
    " CAST('203.0.113.9' AS inet), 1, 80, '{}', true)"
)


async def _seed(conn: AsyncConnection, session_id: str, age_s: float) -> None:
    """A scanner session whose three events start ``age_s`` seconds ago, 10 s apart."""
    await conn.execute(SESSION_INSERT, {"id": session_id, "start": age_s, "end": age_s - 20})
    for i in range(3):
        await conn.execute(EVENT_INSERT, {"id": session_id, "age": age_s - 10 * i})


async def _benign_flags(conn: AsyncConnection, session_id: str) -> list[bool | None]:
    rows = await conn.execute(
        text("SELECT benign FROM events WHERE session_id = :id ORDER BY ts"), {"id": session_id}
    )
    return [r[0] for r in rows]


async def test_retraction_skips_compressed_chunks_and_still_reaches_them(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE events, sessions CASCADE"))
        await _seed(conn, "old", OLD_DAYS * 86400)
        await _seed(conn, "recent", 600)
        # Padding so the compressed chunk holds real rows to scan.
        for i in range(500):
            await conn.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,"
                    " data, benign) VALUES (now() - make_interval(secs => :age), 'web', 'pad',"
                    " 'http_request', CAST('203.0.113.10' AS inet), 1, 80, '{}', true)"
                ),
                {"age": OLD_DAYS * 86400 - 3600 + i},
            )
    async with engine.connect() as conn:
        conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
        compressed = (
            await conn.execute(
                text(
                    "SELECT compress_chunk(c, if_not_compressed => true)::text"
                    " FROM show_chunks('events', older_than => interval '7 days') c"
                )
            )
        ).all()
        assert compressed, "the old chunk was not compressed"
        names = [r[0] for r in compressed]
        # The statement the function runs for the recent session (constant bounds): the plan
        # must not mention any compressed chunk.
        plan = "\n".join(
            r[0]
            for r in await conn.execute(
                text(
                    "EXPLAIN UPDATE events SET benign = false WHERE sensor = 'web'"
                    " AND session_id = 'recent' AND ts >= now() - interval '11 minutes'"
                    " AND ts <= now() - interval '5 minutes' AND benign IS TRUE"
                )
            )
        )
        for name in names:
            assert name.split(".")[1] not in plan, plan

    async with factory() as session:
        start = time.monotonic()
        await session.execute(
            text("SELECT retract_benign(CAST(:ids AS text[]))"), {"ids": ["recent"]}
        )
        await session.commit()
        assert time.monotonic() - start < 1.0

    # A session whose events sit in the compressed chunk is still retracted.
    async with factory() as session:
        await session.execute(text("SELECT retract_benign(CAST(:ids AS text[]))"), {"ids": ["old"]})
        await session.commit()
    async with engine.connect() as conn:
        assert await _benign_flags(conn, "recent") == [False, False, False]
        assert await _benign_flags(conn, "old") == [False, False, False]
        # Other sessions are untouched.
        pad = await _benign_flags(conn, "pad")
        assert pad and all(f is True for f in pad)
