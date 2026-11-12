"""The blocklist worker against a real TimescaleDB: scoring, overrides, stale rows, grants."""

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.blocklist import BlocklistWorker
from ingest.features import FeatureSettings

from .helpers import fold_hour

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC)


def worker(factory: async_sessionmaker[AsyncSession], **kw: Any) -> BlocklistWorker:
    return BlocklistWorker(FeatureSettings(blocklist_enabled=True, **kw), factory)


async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE blocklist_entries, blocklist_overrides, indicator_intel, "
                "indicator_sessions, indicator_contacts, indicator_contact_checks, indicators CASCADE"
            )
        )


async def add_session(
    engine: AsyncEngine, sid: str, ip: str, hours_ago: float = 1, **kw: Any
) -> None:
    started = NOW - timedelta(hours=hours_ago)
    row: dict[str, Any] = {
        "sid": sid, "ip": ip, "t": started, "sensor": "ssh", "attempts": 0, "success": False,
        "commands": 0, "downloads": 0, "abuse": None, "scanner": None, "tags": [],
        "benign": False,
    }  # fmt: skip
    row.update(kw)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,
                    last_event_at, login_attempts, login_success, commands, downloads,
                    abuse_score, known_scanner, tags, benign)
                VALUES (:sid, :sensor, CAST(:ip AS inet), 40000, 2222, :t, :t, :attempts,
                    :success, :commands, :downloads, :abuse, :scanner, CAST(:tags AS text[]),
                    :benign)
                """
            ),
            row,
        )
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, "
                "data, tags) VALUES (:t, :sensor, :sid, 'connect', CAST(:ip AS inet), 40000, "
                "2222, CAST(:data AS jsonb), '{}')"
            ),
            {
                "t": started, "sensor": row["sensor"], "sid": sid, "ip": ip,
                "data": '{"demo": true}' if row.get("demo") else "{}",
            },
        )  # fmt: skip


async def entries(engine: AsyncEngine) -> dict[tuple[str, str], Any]:
    async with engine.connect() as conn:
        rows = (await conn.execute(text("SELECT * FROM blocklist_entries"))).mappings().all()
    return {(r["kind"], r["value"]): r for r in rows}


async def test_sessions_and_indicators_become_scored_entries(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await clean(engine)
    await add_session(
        engine, "s1", "203.0.113.5", commands=3, downloads=1, success=True, tags=["malware-drop"]
    )
    await add_session(engine, "s2", "203.0.113.5", 2, attempts=20, tags=["weak-credentials"])
    await add_session(engine, "s3", "198.51.100.8")  # a lone connection: too low to list
    private = ".".join(("10", "1", "2", "3"))
    await add_session(engine, "s4", private, commands=9, downloads=2)  # never listed
    await add_session(engine, "s5", "203.0.113.77", 1, commands=1, demo=True)
    await add_session(engine, "old", "198.51.100.99", 24 * 60, commands=5, downloads=5)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO indicators (type, value, role, host, first_seen, last_seen, sightings,
                    sensors, trusted, demo) VALUES
                ('url', 'http://dl.bad-host.example/x.sh', 'download_host', 'dl.bad-host.example',
                 now(), now(), 4, '{ssh}', false, false),
                ('domain', 'raw.githubusercontent.com', 'download_host', NULL, now(), now(), 9,
                 '{ssh}', false, false),
                ('hash', :h, 'hash', NULL, now(), now(), 1, '{ssh}', true, false)
                """
            ),
            {"h": "ab" * 32},
        )
        await conn.execute(
            text(
                "INSERT INTO indicator_intel (indicator_id, source, known, family) "
                "SELECT id, 'urlhaus', true, 'mirai' FROM indicators WHERE type = 'url'"
            )
        )
    w = worker(factory)
    await w.run_once()
    got = await entries(engine)
    assert set(got) == {
        ("ip", "203.0.113.5"),
        ("ip", "203.0.113.77"),
        ("url", "http://dl.bad-host.example/x.sh"),
        ("hash", "ab" * 32),
    }
    top = got[("ip", "203.0.113.5")]
    assert top["score"] >= 80 and top["sessions"] == 2 and not top["demo"]
    assert {"dropped-malware", "ran-commands", "brute-force"} <= set(top["reasons"])
    assert got[("ip", "203.0.113.77")]["demo"] is True
    assert got[("url", "http://dl.bad-host.example/x.sh")]["reasons"][:2] == [
        "download-source",
        "known-malware",
    ]
    assert w.entries == 4
    assert (await w.status())["blocklist"]["entries"] == 4


async def test_overrides_and_stale_rows(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await clean(engine)
    await add_session(engine, "a", "203.0.113.5", commands=3, downloads=1)
    await add_session(engine, "b", "203.0.113.6", commands=3, downloads=1)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO blocklist_overrides (kind, value, action, created_by) VALUES "
                "('ip', '203.0.113.5', 'allow', 'admin'), ('ip', '198.51.100.40', 'block', 'admin')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO blocklist_entries (kind, value, score, first_seen, last_seen, "
                "computed_at) VALUES ('ip', '192.0.2.222', 70, now(), now(), now() - interval '1 day')"
            )
        )
    await worker(factory).run_once()
    got = await entries(engine)
    assert set(got) == {("ip", "203.0.113.6"), ("ip", "198.51.100.40")}
    assert got[("ip", "198.51.100.40")]["score"] == 100
    assert got[("ip", "198.51.100.40")]["reasons"] == ["manual-block"]


async def test_the_row_cap_keeps_the_best_scores(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await clean(engine)
    await add_session(engine, "c1", "203.0.113.1", commands=1)
    await add_session(engine, "c2", "203.0.113.2", commands=1, downloads=1)
    await add_session(engine, "c3", "203.0.113.3", commands=1, attempts=30)
    await add_session(engine, "c4", "203.0.113.4", commands=1, downloads=1, attempts=30)
    await worker(factory, blocklist_max_rows=2).run_once()
    assert {v for _, v in await entries(engine)} == {"203.0.113.2", "203.0.113.4"}


async def test_folding_a_flood_changes_no_score(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    """The scores read the number of sessions and the sums of what they did: a flood folded into
    one group row scores exactly as the rows it replaced."""
    await clean(engine)
    ip = "203.0.113.90"
    for n in range(30):  # plain: one password each, no tag
        await add_session(engine, f"spray-{n}", ip, 2, sensor="rdp", attempts=1)
    await add_session(engine, "typed", ip, 2, sensor="rdp", commands=3, downloads=1)
    await add_session(engine, "lone", "198.51.100.77", 2, sensor="rdp", attempts=1)

    def numbers(got: dict[tuple[str, str], Any]) -> dict[tuple[str, str], tuple[Any, ...]]:
        return {
            key: (
                r["score"], r["reasons"], r["first_seen"], r["last_seen"], r["sessions"],
                r["sources"], r["campaign_ids"], r["benign"], r["demo"],
            )
            for key, r in got.items()
        }  # fmt: skip

    await worker(factory).run_once()
    before = numbers(await entries(engine))
    assert before[("ip", ip)][4] == 31  # sessions: the 30 and the one that typed

    hour = (NOW - timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)
    assert await fold_hour(factory, ip, "rdp", hour) == 30
    async with engine.connect() as conn:
        groups = (
            await conn.execute(text("SELECT count(*) FROM sessions WHERE kind = 'burst'"))
        ).scalar()
    assert groups == 1

    await worker(factory).run_once()
    assert numbers(await entries(engine)) == before


async def test_ingest_cannot_touch_feed_tokens(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with factory() as db:
        with pytest.raises(DBAPIError):
            await db.execute(text("SELECT count(*) FROM feed_tokens"))
