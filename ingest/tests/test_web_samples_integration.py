"""A plain web page the collector kept is not evidence: it feeds no lookup, list, draft or batch."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.abuse.candidates import Seed
from ingest.abuse.evidence_build import sample_refs
from ingest.blocklist.worker import _indicator_candidates
from ingest.enrichment.contacts import Source
from ingest.enrichment.contacts import candidates as contact_candidates
from ingest.network.source import SqlSource

from .test_intel import Remote
from .test_intel_policy import add, worker

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC) - timedelta(hours=1)
DAY = NOW.date()
PAGE = "a1" * 32  # an HTML page, nothing matched it
FLAGGED = "b2" * 32  # an HTML page that a detection rule matched
SCRIPT = "c3" * 32  # a shell script
RAW = "d4" * 32  # not analysed yet (no kind)
SOURCE_IP = "198.51.100.7"
PAYLOAD_URL = "http://dl.example.test/index.html"


async def add_sample(
    engine: AsyncEngine, sha: str, kind: str | None, severity: str, family: str | None
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, kind, severity, family, "
                "first_seen, last_seen, stored, analysis_status) VALUES "
                "(:sha, :sha1, :md5, 100, :kind, :sev, :fam, :t, :t, true, 'done')"
            ),
            {
                "sha": sha, "sha1": sha[:40], "md5": sha[:32], "kind": kind, "sev": severity,
                "fam": family, "t": NOW,
            },
        )  # fmt: skip


@pytest.fixture
async def samples(engine: AsyncEngine) -> None:
    await add_sample(engine, PAGE, "html", "info", None)
    await add_sample(engine, FLAGGED, "html", "severe", "shell-dropper")
    await add_sample(engine, SCRIPT, "script", "notice", None)
    await add_sample(engine, RAW, None, "notice", None)


async def hash_indicator(engine: AsyncEngine, sha: str) -> int:
    iid = await add(
        engine, sha, ["198.51.100.1", "198.51.100.2"], kind="hash", role="hash", trusted=True
    )
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO indicator_intel (indicator_id, source, known, family, tags) "
                "VALUES (:i, 'urlhaus', true, 'mirai', '{}')"
            ),
            {"i": iid},
        )
    return iid


async def test_the_network_batch_leaves_out_plain_web_pages(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    for sha in (PAGE, SCRIPT):
        await hash_indicator(engine, sha)
    got = {f.sha256: f for f in await SqlSource(factory).files(DAY)}
    assert set(got) == {FLAGGED, SCRIPT, RAW}
    assert got[FLAGGED].kind == "html"  # a rule matched it: it stays evidence


async def test_a_payload_url_stays_but_not_the_page_it_served(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                "started_at, last_event_at) VALUES ('s1', 'ssh', CAST(:ip AS inet), 40000, 22, "
                ":t, :t)"
            ),
            {"ip": SOURCE_IP, "t": NOW},
        )
        for url, sha in [(PAYLOAD_URL, PAGE), ("http://dl.example.test/x.sh", SCRIPT)]:
            iid = await conn.scalar(
                text(
                    "INSERT INTO indicators (type, value, role, first_seen, last_seen) "
                    "VALUES ('url', :v, 'download_host', :t, :t) RETURNING id"
                ),
                {"v": url, "t": NOW},
            )
            await conn.execute(
                text(
                    "INSERT INTO indicator_sessions VALUES (:i, 's1', CAST(:ip AS inet), 'ssh', :t)"
                ),
                {"i": iid, "ip": SOURCE_IP, "t": NOW},
            )
            await conn.execute(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, status, first_seen, "
                    "last_sha256) VALUES (:u, 'http', 'dl.example.test', 'fetched', :t, :sha)"
                ),
                {"u": url, "t": NOW, "sha": sha},
            )
    facts = {p.url: p for p in await SqlSource(factory).payloads(DAY)}
    assert set(facts) == {PAYLOAD_URL, "http://dl.example.test/x.sh"}
    page = facts[PAYLOAD_URL]
    assert (page.sha256, page.kind, page.family, page.arch) == (None, None, None, None)
    script = facts["http://dl.example.test/x.sh"]
    assert (script.sha256, script.kind) == (SCRIPT, "script")


async def test_no_lookup_is_made_for_the_hash_of_a_plain_web_page(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    for sha in (PAGE, FLAGGED, SCRIPT):
        await hash_indicator(engine, sha)
    for provider in ("virustotal", "abusech"):
        got = {c.value for c in await worker(Remote(), factory).candidates(provider, limit=10)}
        assert got == {FLAGGED, SCRIPT}, provider
    sources: tuple[Source, ...] = ("virustotal", "threatfox")
    assert {c.value for c in await contact_candidates(factory, sources, 10)} == {FLAGGED, SCRIPT}


async def test_the_blocklist_does_not_list_the_hash_of_a_plain_web_page(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    for sha in (PAGE, SCRIPT):
        await hash_indicator(engine, sha)
    await add(engine, "dl.example.test", [SOURCE_IP], kind="domain")
    async with factory() as db:
        got = await _indicator_candidates(db, NOW - timedelta(days=1))
    assert {(c.kind, c.value) for c in got} == {("hash", SCRIPT), ("domain", "dl.example.test")}


async def test_an_abuse_draft_does_not_name_the_hash_of_a_plain_web_page(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    async with engine.begin() as conn:
        for n, sha in enumerate((PAGE, FLAGGED, SCRIPT)):
            await conn.execute(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, status, first_seen, "
                    "last_sha256) VALUES (:u, 'http', 'dl.example.test', 'fetched', :t, :sha)"
                ),
                {"u": f"http://dl.example.test/{n}", "t": NOW, "sha": sha},
            )
            await conn.execute(
                text(
                    "INSERT INTO sample_sources (sha256, target_id, first_fetched, last_fetched) "
                    "SELECT :sha, id, :t, :t FROM fetch_targets WHERE last_sha256 = :sha"
                ),
                {"sha": sha, "t": NOW},
            )
    seed = Seed("payload_host", "domain", "dl.example.test", NOW, NOW, 1, 1)
    async with factory() as db:
        refs = await sample_refs(db, seed)
    assert {r.sha256 for r in refs} == {FLAGGED, SCRIPT}
