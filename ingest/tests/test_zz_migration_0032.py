"""Migration 0032: reputation answers are kept, and the lost ones are rebuilt from the sessions.

Named test_zz_* on purpose: re-running the migrations re-schedules the TimescaleDB maintenance job,
which must not fire while the retention tests drive that job by hand. This file runs last.
"""

import os
import subprocess
import sys
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from .db_fixtures import DB_DIR, ROLE_ENV, _migrate

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

BOTH = "198.51.100.31"  # two scored sessions: the newest score wins
UNSCORED = "198.51.100.32"
GN_ROW = "198.51.100.33"  # a row with a GreyNoise answer only: the score completes it
KNOWN = "198.51.100.34"  # a row with a real answer: never overwritten
GN_FALSE = "198.51.100.35"  # checked by GreyNoise, not a scanner


def alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=DB_DIR,
        env={**os.environ, **ROLE_ENV},
        check=True,
        timeout=120,
    )


async def maintenance_source(engine: AsyncEngine) -> str:
    async with engine.connect() as conn:
        return str(
            await conn.scalar(
                text("SELECT prosrc FROM pg_proc WHERE proname = 'suckerpot_maintenance'")
            )
        )


async def add_session(
    engine: AsyncEngine,
    sid: str,
    ip: str,
    age_days: int,
    score: int | None,
    scanner: bool | None = None,
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,"
                " last_event_at, event_count, login_attempts, login_success, commands, downloads,"
                " http_requests, abuse_score, known_scanner) VALUES (:id, 'ssh',"
                " CAST(:ip AS inet), 1, 22, now() - make_interval(days => :age),"
                " now() - make_interval(days => :age), 12, 0, false, 0, 0, 0, :score, :scanner)"
            ),
            {"id": sid, "ip": ip, "age": age_days, "score": score, "scanner": scanner},
        )


async def test_rebuilds_lost_answers_and_keeps_existing_ones(engine: AsyncEngine) -> None:
    alembic("downgrade", "0031")
    assert "48 hours" in await maintenance_source(engine)  # the old pruning is back

    await add_session(engine, "a1", BOTH, 5, 40, True)
    await add_session(engine, "a2", BOTH, 2, 55, True)
    await add_session(engine, "b1", UNSCORED, 2, None)
    await add_session(engine, "c1", GN_ROW, 3, 20)
    await add_session(engine, "d1", KNOWN, 1, 10, True)
    await add_session(engine, "e1", GN_FALSE, 4, None, False)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO ip_reputation (ip, gn_noise, gn_checked_at) VALUES"
                " (CAST(:c AS inet), true, now() - INTERVAL '2 days')"
            ),
            {"c": GN_ROW},
        )
        await conn.execute(
            text(
                "INSERT INTO ip_reputation (ip, abuse_score, abuse_checked_at, gn_noise,"
                " gn_checked_at) VALUES (CAST(:k AS inet), 99, now() - INTERVAL '1 hour',"
                " false, now() - INTERVAL '1 hour')"
            ),
            {"k": KNOWN},
        )

    _migrate()  # up to head again, same path as the migrate service
    source = await maintenance_source(engine)
    assert "48 hours" not in source and "GREATEST(days, 90)" in source

    async with engine.connect() as conn:
        found = {
            r.ip: r
            for r in await conn.execute(
                text(
                    "SELECT host(ip) AS ip, abuse_score, gn_noise,"
                    " abuse_checked_at IS NULL AS no_abuse_time,"
                    " gn_checked_at IS NULL AS no_gn_time,"
                    " abuse_checked_at > now() - INTERVAL '3 days' AS abuse_recent"
                    " FROM ip_reputation"
                )
            )
        }
    assert set(found) == {BOTH, GN_ROW, KNOWN, GN_FALSE}  # nothing for an unscored address
    both: Any = found[BOTH]
    assert both.abuse_score == 55 and both.gn_noise is True  # from the newest session
    assert both.abuse_recent is True  # the time of that session, two days ago
    assert not both.no_abuse_time and not both.no_gn_time
    completed: Any = found[GN_ROW]
    assert completed.abuse_score == 20 and completed.gn_noise is True  # GN answer untouched
    assert not completed.no_abuse_time
    known: Any = found[KNOWN]
    assert known.abuse_score == 99 and known.gn_noise is False  # a real answer is never replaced
    not_scanner: Any = found[GN_FALSE]
    assert not_scanner.abuse_score is None and not_scanner.gn_noise is False
    assert not_scanner.no_abuse_time and not not_scanner.no_gn_time
