"""Plain web content the collector kept is not evidence: it feeds no lookup, list, draft or batch.

Plain web means a web kind that no rule matched AND reached only by following links found in other
web content. A page an attacker asked for (a typed URL, or a link in a script) is attacker content
whatever its kind, and feeds everything like any other sample.
"""

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
TYPED = "e5" * 32  # an HTML page an attacker typed the URL of
PAGE = "a1" * 32  # an HTML page found through a link of TYPED, nothing matched it: plain web
FLAGGED = "b2" * 32  # an HTML page found the same way that a detection rule matched
SCRIPT = "c3" * 32  # a shell script an attacker typed the URL of
STAGE = "f6" * 32  # an HTML page found through a link of SCRIPT: the dropper's next stage
RAW = "d4" * 32  # not analysed yet (no kind), no source
TEXT_LINKED = "a7" * 32  # an HTML page named in the text of TYPED (not an asset): evidence
SOURCE_IP = "198.51.100.7"
HOST = "dl.example.test"
TYPED_URL = f"http://{HOST}/index.html"


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


async def add_source(
    engine: AsyncEngine,
    sha: str,
    url: str,
    *,
    depth: int,
    parent: str | None = None,
    indicator: int | None = None,
    via: str = "web_asset",
) -> None:
    """A fetched target that served `sha`, linked from `parent` (a link labelled `via`)."""
    async with engine.begin() as conn:
        tid = await conn.scalar(
            text(
                "INSERT INTO fetch_targets (url, scheme, host, indicator_id, parent_sha256, depth, "
                "status, first_seen, last_sha256, typed) VALUES "
                "(:u, 'http', :h, :i, :p, :d, 'fetched', :t, :sha, :ty) RETURNING id"
            ),
            {
                "u": url, "h": HOST, "i": indicator, "p": parent, "d": depth, "t": NOW,
                "sha": sha, "ty": indicator is not None,
            },
        )  # fmt: skip
        if parent is not None:
            await conn.execute(
                text(
                    "INSERT INTO sample_links (sha256, kind, value, source, confidence, "
                    "target_id) VALUES (:p, 'next_url', :u, :via, 'high', :t)"
                ),
                {"p": parent, "u": url, "via": via, "t": tid},
            )
        await conn.execute(
            text(
                "INSERT INTO sample_sources (sha256, target_id, first_fetched, last_fetched) "
                "VALUES (:sha, :tid, :t, :t)"
            ),
            {"sha": sha, "tid": tid, "t": NOW},
        )


async def typed_url(engine: AsyncEngine, url: str) -> int:
    """A download URL an attacker typed in session s1."""
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                "started_at, last_event_at) VALUES ('s1', 'ssh', CAST(:ip AS inet), 40000, 22, "
                ":t, :t) ON CONFLICT DO NOTHING"
            ),
            {"ip": SOURCE_IP, "t": NOW},
        )
        iid = await conn.scalar(
            text(
                "INSERT INTO indicators (type, value, role, first_seen, last_seen) "
                "VALUES ('url', :v, 'download_host', :t, :t) RETURNING id"
            ),
            {"v": url, "t": NOW},
        )
        await conn.execute(
            text("INSERT INTO indicator_sessions VALUES (:i, 's1', CAST(:ip AS inet), 'ssh', :t)"),
            {"i": iid, "ip": SOURCE_IP, "t": NOW},
        )
    return int(iid)


@pytest.fixture
async def samples(engine: AsyncEngine) -> None:
    await add_sample(engine, TYPED, "html", "info", None)
    await add_sample(engine, PAGE, "html", "info", None)
    await add_sample(engine, FLAGGED, "html", "severe", "shell-dropper")
    await add_sample(engine, SCRIPT, "script", "notice", None)
    await add_sample(engine, STAGE, "html", "info", None)
    await add_sample(engine, RAW, None, "notice", None)
    await add_source(
        engine, TYPED, TYPED_URL, depth=0, indicator=await typed_url(engine, TYPED_URL)
    )
    script_url = f"http://{HOST}/x.sh"
    await add_source(
        engine, SCRIPT, script_url, depth=0, indicator=await typed_url(engine, script_url)
    )
    await add_source(engine, PAGE, f"http://{HOST}/about.html", depth=1, parent=TYPED)
    await add_source(engine, FLAGGED, f"http://{HOST}/f.html", depth=1, parent=TYPED)
    await add_source(
        engine, STAGE, f"http://{HOST}/stage.html", depth=1, parent=SCRIPT, via="script_url"
    )
    # A page that only names another page in its text: that one is not crawled either.
    await add_sample(engine, TEXT_LINKED, "html", "info", None)
    await add_source(
        engine, TEXT_LINKED, f"http://{HOST}/named.html", depth=1, parent=TYPED, via="script_url"
    )


EVIDENCE = {TYPED, FLAGGED, SCRIPT, STAGE, TEXT_LINKED}  # every analysed sample but the plain page
ALL = EVIDENCE | {PAGE, RAW}


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


async def test_the_network_batch_leaves_out_plain_web_content(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    for sha in (PAGE, SCRIPT, TYPED):
        await hash_indicator(engine, sha)
    files = await SqlSource(factory).files(DAY)  # a stored sample and its hash indicator
    assert {f.sha256 for f in files} == EVIDENCE | {RAW}
    kinds = {(f.sha256, f.kind) for f in files}
    assert (FLAGGED, "html") in kinds  # a rule matched it: it stays evidence
    assert (TYPED, "html") in kinds  # an attacker asked for it: it is evidence
    assert (STAGE, "html") in kinds  # a script asked for it: it is evidence


async def test_a_page_served_from_a_typed_url_keeps_its_hash(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    facts = {p.url: p for p in await SqlSource(factory).payloads(DAY)}
    assert set(facts) == {TYPED_URL, f"http://{HOST}/x.sh"}
    page = facts[TYPED_URL]
    assert (page.sha256, page.kind) == (TYPED, "html")
    script = facts[f"http://{HOST}/x.sh"]
    assert (script.sha256, script.kind) == (SCRIPT, "script")


async def test_no_lookup_is_made_for_the_hash_of_plain_web_content(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    for sha in (PAGE, *EVIDENCE):
        await hash_indicator(engine, sha)
    for provider in ("virustotal", "abusech"):
        found = await worker(Remote(), factory).candidates(provider, limit=20)
        assert {c.value for c in found if c.value in ALL} == EVIDENCE, provider
    sources: tuple[Source, ...] = ("virustotal", "threatfox")
    assert {c.value for c in await contact_candidates(factory, sources, 10)} == EVIDENCE


async def test_the_blocklist_does_not_list_the_hash_of_plain_web_content(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    for sha in (PAGE, TYPED, SCRIPT):
        await hash_indicator(engine, sha)
    await add(engine, "other.example.test", [SOURCE_IP], kind="domain")
    async with factory() as db:
        got = await _indicator_candidates(db, NOW - timedelta(days=1))
    hashes = {c.value for c in got if c.kind == "hash"}
    assert hashes == {TYPED, SCRIPT}
    assert ("domain", "other.example.test") in {(c.kind, c.value) for c in got}


async def test_an_abuse_draft_does_not_name_the_hash_of_plain_web_content(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    seed = Seed("payload_host", "domain", HOST, NOW, NOW, 1, 1)
    async with factory() as db:
        refs = await sample_refs(db, seed)
    assert {r.sha256 for r in refs} == EVIDENCE


async def test_a_typed_url_makes_a_crawled_page_evidence(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], samples: None
) -> None:
    await hash_indicator(engine, PAGE)
    assert PAGE not in {f.sha256 for f in await SqlSource(factory).files(DAY)}
    # An attacker types the URL that served the plain page: from now on it is attacker content.
    iid = await typed_url(engine, f"http://{HOST}/about.html")
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE fetch_targets SET indicator_id = :i, typed = true WHERE url = :u"),
            {"i": iid, "u": f"http://{HOST}/about.html"},
        )
    assert PAGE in {f.sha256 for f in await SqlSource(factory).files(DAY)}
    found = await worker(Remote(), factory).candidates("virustotal", limit=20)
    assert PAGE in {c.value for c in found}
