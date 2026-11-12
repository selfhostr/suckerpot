"""Enrichment against a real TimescaleDB: writer, tagging, reputation worker, grants."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db import create_engine

from ingest.enrichment import EnrichmentSettings, GeoResolver
from ingest.enrichment import reputation as rep
from ingest.enrichment.enricher import Enricher
from ingest.enrichment.reputation import ReputationWorker, candidate_ips
from ingest.enrichment.status import publish_status
from ingest.tagging import load_rules
from ingest.writer import write_batch

from .db_fixtures import _role_url
from .helpers import make_event as _make_event

# The reputation worker only looks at sessions from the last 7 days: keep events recent.
RECENT = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)


def make_event(*args: Any, **kwargs: Any) -> Any:
    return _make_event(*args, base=RECENT, **kwargs)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

RULES = load_rules(Path(__file__).resolve().parents[1] / "rules")
TEST_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"]


@pytest.fixture
def enricher(tmp_path: Path) -> Enricher:
    return Enricher(GeoResolver(tmp_path, fake_for_private=True), RULES)


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def test_writer_enriches_and_tags(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], enricher: Enricher
) -> None:
    ip = "203.0.113.50"
    batch1 = [
        make_event("connect", sid="e1", offset_s=0, ip=ip),
        make_event("login_attempt", sid="e1", offset_s=1, ip=ip, data={"success": True}),
        make_event("command", sid="e1", offset_s=2, ip=ip, data={"input": "uname -a"}),
        make_event("download_attempt", sid="e1", offset_s=3, ip=ip, data={"url": "http://x/a.sh"}),
    ]
    await write_batch(factory, batch1, enricher)
    ev = await rows(engine, "SELECT type, country, asn, org, tags FROM events ORDER BY ts")
    assert all(r.country and r.asn for r in ev)
    assert next(r for r in ev if r.type == "command").tags == ["recon"]
    assert next(r for r in ev if r.type == "connect").tags == []
    (s,) = await rows(engine, "SELECT country, city, asn, org, tags FROM sessions")
    assert s.country and s.city and s.asn and s.org
    assert s.tags == ["recon"]

    # The exec step arrives in a later batch: session-scope malware-drop fires then.
    batch2 = [
        make_event("command", sid="e1", offset_s=4, ip=ip, data={"input": "chmod +x a.sh; ./a.sh"}),
        make_event("command", sid="e1", offset_s=5, ip=ip, data={"input": "uname"}),
    ]
    await write_batch(factory, batch2, enricher)
    (s,) = await rows(engine, "SELECT tags, event_count, downloads, country FROM sessions")
    assert s.tags == ["exec-attempt", "malware-drop", "recon"]  # sorted, no duplicates
    assert (s.event_count, s.downloads) == (6, 1) and s.country


async def test_credential_stuffing_and_cached_reputation(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], enricher: Enricher
) -> None:
    ip = "198.51.100.77"
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO ip_reputation (ip, abuse_score, abuse_checked_at, gn_noise, "
                "gn_checked_at) VALUES (CAST(:ip AS inet), 77, now(), true, now())"
            ),
            {"ip": ip},
        )
    events = [
        make_event("login_attempt", sid="cs1", offset_s=i, ip=ip, data={"success": False})
        for i in range(25)
    ]
    await write_batch(factory, events, enricher)
    (s,) = await rows(engine, "SELECT tags, abuse_score, known_scanner FROM sessions")
    assert s.tags == ["credential-stuffing", "scanner"]
    assert s.abuse_score == 77 and s.known_scanner is True
    (e,) = await rows(engine, "SELECT abuse_score, known_scanner FROM events LIMIT 1")
    assert (e.abuse_score, e.known_scanner) == (77, True)


async def test_writer_without_enricher_still_works(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await write_batch(factory, [make_event("command", data={"input": "uname"})])
    (e,) = await rows(engine, "SELECT country, tags FROM events")
    assert e.country is None and e.tags == []


# ---- reputation worker ------------------------------------------------------------------------


class Providers:
    """Mock AbuseIPDB + GreyNoise."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.abuse_status = 200
        self.gn_status = 200

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host == "api.abuseipdb.com":
            if self.abuse_status != 200:
                return httpx.Response(self.abuse_status)
            return httpx.Response(
                200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 12}}
            )
        if req.url.host == "api.greynoise.io":
            ip = req.url.path.rsplit("/", 1)[-1]
            if self.gn_status != 200:
                return httpx.Response(self.gn_status)
            if ip.endswith(".13"):
                return httpx.Response(404, json={"message": "not seen"})
            return httpx.Response(
                200, json={"noise": True, "riot": False, "classification": "malicious", "name": "x"}
            )
        raise AssertionError(f"unexpected host {req.url.host}")

    def calls(self, host: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host]


def worker(
    factory: async_sessionmaker[AsyncSession], providers: Providers, **env: str
) -> ReputationWorker:
    base = {"ABUSEIPDB_API_KEY": "k1", "GREYNOISE_API_KEY": "k2"}
    settings = EnrichmentSettings.from_env({**base, **env})
    client = httpx.AsyncClient(transport=httpx.MockTransport(providers))
    return ReputationWorker(factory, settings, client)


async def seed_sessions(factory: async_sessionmaker[AsyncSession]) -> None:
    a, b, c, d = TEST_IPS
    events = [make_event("login_attempt", sid="ra", ip=a, offset_s=0, data={"success": True})]
    events += [
        make_event("command", sid="ra", ip=a, offset_s=i, data={"input": "x"}) for i in range(1, 6)
    ]
    events += [make_event("command", sid="rb", ip=b, data={"input": "ls"})]
    events += [make_event("connect", sid="rc", ip=c)]  # one idle event: not worth a lookup
    events += [make_event("connect", sid=f"rd{i}", ip=d, offset_s=i) for i in range(12)]
    await write_batch(factory, events)


@pytest.fixture(autouse=False)
def routable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Documentation addresses are never looked up; pretend they are routable for the test.
    monkeypatch.setattr("ingest.enrichment.reputation.is_routable", lambda _a: True)


async def test_quota_priority_cache_and_session_updates(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    await seed_sessions(factory)
    p = Providers()
    w = worker(factory, p, ABUSEIPDB_DAILY_QUOTA="2", GREYNOISE_DAILY_QUOTA="50")
    # A fifth of the quota (here 1 of 2) is kept for stale answers; none is stale, so the second
    # lookup follows in the next cycle.
    made = await w.run_once() + await w.run_once()
    ips = [r.url.params["ipAddress"] for r in p.calls("api.abuseipdb.com")]
    assert ips == [TEST_IPS[3], TEST_IPS[0]]  # most active first (12 events, then 6)
    assert TEST_IPS[2] not in ips  # one idle connect is not worth a lookup
    gn_ips = [r.url.path.rsplit("/", 1)[-1] for r in p.calls("api.greynoise.io")]
    assert set(gn_ips) == {TEST_IPS[0], TEST_IPS[1], TEST_IPS[3]} and made == len(ips) + 3
    # read-only: only GET, only the two providers, never a report endpoint
    assert all(r.method == "GET" for r in p.requests)
    assert not any("report" in r.url.path for r in p.requests)
    assert p.requests[0].headers.get("key") or p.requests[0].headers.get("Key")

    quota = {
        r.provider: r.used
        for r in await rows(engine, "SELECT provider, used FROM enrichment_quota")
    }
    assert quota == {"abuseipdb": 2, "greynoise": 3}
    ses = {
        r.sid: r
        for r in await rows(
            engine, "SELECT session_id AS sid, abuse_score, known_scanner, tags FROM sessions"
        )
    }
    assert ses["ra"].abuse_score == 88 and ses["ra"].known_scanner is True
    assert "scanner" in ses["ra"].tags
    assert ses["rd0"].known_scanner is False and "scanner" not in ses["rd0"].tags  # GN 404

    # Recently answered and the abuse quota is spent: a new worker (restart) makes no calls.
    p2 = Providers()
    w2 = worker(factory, p2, ABUSEIPDB_DAILY_QUOTA="2", GREYNOISE_DAILY_QUOTA="50")
    assert await w2.run_once() == 0 and not p2.requests
    # With a larger quota the remaining uncached IP is looked up; cached ones are not.
    p3 = Providers()
    w3 = worker(factory, p3, ABUSEIPDB_DAILY_QUOTA="10")
    await w3.run_once()
    checked = {r.url.params["ipAddress"] for r in p3.calls("api.abuseipdb.com")}
    assert checked == {TEST_IPS[1]}  # the other two were answered a moment ago
    st = await w3.status()
    assert st["abuseipdb"]["configured"] and "k1" not in str(st)


async def test_rate_limit_pauses_and_auth_disables(
    factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    await seed_sessions(factory)
    p = Providers()
    p.abuse_status, p.gn_status = 429, 401
    w = worker(factory, p)
    await w.run_once()
    assert len(p.calls("api.abuseipdb.com")) == 1 and len(p.calls("api.greynoise.io")) == 1
    assert w.last_error == {"abuseipdb": "rate_limited", "greynoise": "auth"}
    await w.run_once()  # paused / disabled: no retry storm
    assert len(p.requests) == 2
    assert not w.enabled("greynoise") and w.enabled("abuseipdb")


# ---- who is looked up first ---------------------------------------------------------------------

STALE_BUSY = "198.51.100.21"  # 40 events, abuse answer 30 days old
FRESH = "198.51.100.22"  # 20 events, abuse answer 1 hour old
NEW_BUSY = "198.51.100.23"  # 12 events, no row
GN_ONLY = "198.51.100.24"  # 10 events, a row with only a GreyNoise answer
STALE_QUIET = "198.51.100.25"  # 11 events, abuse answer 8 days old


async def seed_activity(
    factory: async_sessionmaker[AsyncSession], counts: dict[str, int], age_days: float = 0
) -> None:
    """One session per address with that many events."""
    base = RECENT - timedelta(days=age_days)
    events = [
        _make_event(
            "connect",
            sid="act-" + ip.replace(".", "_").replace(":", "-"),
            ip=ip,
            offset_s=i,
            base=base,
        )
        for ip, n in counts.items()
        for i in range(n)
    ]
    await write_batch(factory, events)


async def seed_known(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO ip_reputation (ip, abuse_score, abuse_checked_at, gn_noise,"
                " gn_checked_at) VALUES"
                " (CAST(:a AS inet), 30, now() - INTERVAL '30 days', NULL, NULL),"
                " (CAST(:b AS inet), 5, now() - INTERVAL '1 hour', NULL, NULL),"
                " (CAST(:d AS inet), NULL, NULL, true, now() - INTERVAL '1 hour'),"
                " (CAST(:e AS inet), 9, now() - INTERVAL '8 days', NULL, NULL)"
            ),
            {"a": STALE_BUSY, "b": FRESH, "d": GN_ONLY, "e": STALE_QUIET},
        )


async def test_new_addresses_come_before_stale_ones_and_fresh_ones_are_left_alone(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    counts = {STALE_BUSY: 40, FRESH: 20, NEW_BUSY: 12, GN_ONLY: 10, STALE_QUIET: 11}
    await seed_activity(factory, counts)
    await seed_known(engine)

    async def pick(provider: str, **kw: Any) -> list[str]:
        return [c.ip for c in await candidate_ips(factory, provider, 10, limit=10, **kw)]

    # AbuseIPDB: never answered (busiest first), then older than 7 days (busiest first).
    # FRESH was answered an hour ago and is not asked again, however busy it is.
    assert await pick("abuseipdb") == [NEW_BUSY, GN_ONLY, STALE_BUSY, STALE_QUIET]
    # Same query for GreyNoise: only GN_ONLY has an answer there, and it is recent.
    assert await pick("greynoise") == [STALE_BUSY, FRESH, NEW_BUSY, STALE_QUIET]
    # A longer recheck age turns the stale answers into fresh ones.
    assert await pick("abuseipdb", recheck_days=40) == [NEW_BUSY, GN_ONLY]
    assert await pick("abuseipdb", recheck_days=9) == [NEW_BUSY, GN_ONLY, STALE_BUSY]
    # The limit cuts the stale group first, and skipped addresses do not take a place.
    cut = await candidate_ips(factory, "abuseipdb", 10, limit=2)
    assert [c.ip for c in cut] == [NEW_BUSY, GN_ONLY]
    assert await pick("abuseipdb", exclude=[NEW_BUSY]) == [GN_ONLY, STALE_BUSY, STALE_QUIET]
    # Each address says whether it is a refresh, and the refreshes can be asked for alone.
    both = await candidate_ips(factory, "abuseipdb", 10, limit=10)
    assert [(c.ip, c.stale) for c in both] == [
        (NEW_BUSY, False),
        (GN_ONLY, False),
        (STALE_BUSY, True),
        (STALE_QUIET, True),
    ]
    assert await pick("abuseipdb", stale_only=True) == [STALE_BUSY, STALE_QUIET]
    assert await pick("greynoise", stale_only=True) == []  # no GreyNoise answer is old


async def test_a_long_skip_list_with_both_address_families_still_filters(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    v6 = "2001:db8::25"
    await seed_activity(factory, {NEW_BUSY: 12, GN_ONLY: 10, v6: 11})
    skipped = [f"203.0.113.{i % 250}" for i in range(400)] + [
        f"2001:db8:1::{i:x}" for i in range(99)
    ]

    async def pick(*skip: str) -> list[str]:
        found = await candidate_ips(factory, "abuseipdb", 10, limit=10, exclude=[*skipped, *skip])
        return [c.ip for c in found]

    assert await pick() == [NEW_BUSY, v6, GN_ONLY]
    assert await pick(NEW_BUSY, v6) == [GN_ONLY]  # an address of either family is left out


async def test_the_quota_goes_to_a_new_address_before_a_stale_one(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    await seed_activity(factory, {STALE_BUSY: 40, NEW_BUSY: 10})
    await seed_known(engine)
    p = Providers()
    w = worker(factory, p, ABUSEIPDB_DAILY_QUOTA="1", GREYNOISE_API_KEY="")
    assert await w.run_once() == 1
    assert [r.url.params["ipAddress"] for r in p.calls("api.abuseipdb.com")] == [NEW_BUSY]
    # The stale answer was not touched: still there, still the old one.
    (old,) = await rows(
        engine,
        "SELECT abuse_score, abuse_checked_at < now() - INTERVAL '29 days' AS old"
        " FROM ip_reputation WHERE ip = CAST(:ip AS inet)",
        ip=STALE_BUSY,
    )
    assert old.abuse_score == 30 and old.old is True

    # Quota left: now the stale address is refreshed.
    p2 = Providers()
    w2 = worker(factory, p2, ABUSEIPDB_DAILY_QUOTA="2", GREYNOISE_API_KEY="")
    assert await w2.run_once() == 1
    assert [r.url.params["ipAddress"] for r in p2.calls("api.abuseipdb.com")] == [STALE_BUSY]
    (new,) = await rows(
        engine,
        "SELECT abuse_score, abuse_checked_at > now() - INTERVAL '1 hour' AS recent"
        " FROM ip_reputation WHERE ip = CAST(:ip AS inet)",
        ip=STALE_BUSY,
    )
    assert new.abuse_score == 88 and new.recent is True


async def abuse_calls(p: Providers) -> list[str]:
    return [r.url.params["ipAddress"] for r in p.calls("api.abuseipdb.com")]


async def test_a_share_of_each_day_goes_to_stale_answers(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    new_ips = [f"198.51.100.{100 + i}" for i in range(12)]
    stale_ips = [f"198.51.100.{150 + i}" for i in range(3)]
    activity = {ip: 10 for ip in new_ips} | {ip: 20 + i for i, ip in enumerate(stale_ips)}
    await seed_activity(factory, activity)
    async with engine.begin() as conn:
        for ip in stale_ips:
            await conn.execute(
                text(
                    "INSERT INTO ip_reputation (ip, abuse_score, abuse_checked_at)"
                    " VALUES (CAST(:ip AS inet), 30, now() - INTERVAL '30 days')"
                ),
                {"ip": ip},
            )
    p = Providers()
    w = worker(factory, p, ABUSEIPDB_DAILY_QUOTA="10", GREYNOISE_API_KEY="")
    for _ in range(6):
        await w.run_once()
    checked = await abuse_calls(p)
    # Quota 10 keeps 2 for stale answers: new addresses took 8, the busiest 2 stale ones the rest.
    assert len(checked) == 10
    assert sum(ip in new_ips for ip in checked) == 8
    assert [ip for ip in checked if ip in stale_ips] == [stale_ips[2], stale_ips[1]]
    assert checked[-2:] == [stale_ips[2], stale_ips[1]]  # the new ones came first
    used = {
        r.provider: r.used
        for r in await rows(engine, "SELECT provider, used FROM enrichment_quota")
    }
    assert used == {"abuseipdb": 10, "abuseipdb:recheck": 2}
    refreshed = await rows(
        engine,
        "SELECT count(*) AS n FROM ip_reputation WHERE abuse_checked_at > now() - INTERVAL '1 hour'",
    )
    assert refreshed[0].n == 10


async def test_the_reserved_share_is_not_wasted_when_nothing_is_stale(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    new_ips = [f"198.51.100.{100 + i}" for i in range(6)]
    await seed_activity(factory, {ip: 10 for ip in new_ips})
    p = Providers()
    w = worker(factory, p, ABUSEIPDB_DAILY_QUOTA="4", GREYNOISE_API_KEY="")
    for _ in range(5):
        await w.run_once()
    assert len(await abuse_calls(p)) == 4  # the whole quota went to new addresses
    used = {
        r.provider: r.used
        for r in await rows(engine, "SELECT provider, used FROM enrichment_quota")
    }
    assert used == {"abuseipdb": 4}


async def test_a_stale_score_is_kept_and_used_until_it_is_refreshed(
    engine: AsyncEngine,
    factory: async_sessionmaker[AsyncSession],
    enricher: Enricher,
    routable: None,
) -> None:
    await seed_known(engine)
    # New events from an address whose answer is 30 days old still get its score.
    events = [make_event("connect", sid="stale-1", ip=STALE_BUSY, offset_s=i) for i in range(10)]
    await write_batch(factory, events, enricher)
    (s,) = await rows(engine, "SELECT abuse_score FROM sessions WHERE session_id = 'stale-1'")
    assert s.abuse_score == 30
    # A failing provider leaves the row as it was.
    p = Providers()
    p.abuse_status = 500
    w = worker(factory, p, GREYNOISE_API_KEY="")
    await w.run_once()
    assert w.last_error == {"abuseipdb": "error"}
    (r,) = await rows(
        engine,
        "SELECT abuse_score, abuse_checked_at < now() - INTERVAL '29 days' AS old"
        " FROM ip_reputation WHERE ip = CAST(:ip AS inet)",
        ip=STALE_BUSY,
    )
    assert r.abuse_score == 30 and r.old is True
    # Nor does the worker drop rows when it has no quota or no key.
    quiet = worker(factory, Providers(), ABUSEIPDB_API_KEY="", GREYNOISE_API_KEY="")
    assert await quiet.run_once() == 0
    (n,) = await rows(engine, "SELECT count(*) AS n FROM ip_reputation")
    assert n.n == 4


async def test_a_late_score_reaches_the_sessions_already_stored(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    ip = NEW_BUSY
    old = RECENT - timedelta(days=5)
    events = [_make_event("connect", sid="old-1", ip=ip, offset_s=i, base=old) for i in range(3)]
    events += [make_event("connect", sid="new-1", ip=ip, offset_s=i) for i in range(10)]
    await write_batch(factory, events)
    sessions = "SELECT session_id, abuse_score, known_scanner FROM sessions ORDER BY session_id"
    assert [r.abuse_score for r in await rows(engine, sessions)] == [None, None]
    p = Providers()
    w = worker(factory, p)
    await w.run_once()
    got = {r.session_id: (r.abuse_score, r.known_scanner) for r in await rows(engine, sessions)}
    assert got == {"new-1": (88, True), "old-1": (88, True)}


async def test_greynoise_429_stops_for_the_day_and_the_counter_stays_full(
    engine: AsyncEngine,
    factory: async_sessionmaker[AsyncSession],
    routable: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await seed_activity(factory, {NEW_BUSY: 12, GN_ONLY: 10})
    p = Providers()
    p.gn_status = 429
    w = worker(factory, p, ABUSEIPDB_API_KEY="", GREYNOISE_DAILY_QUOTA="50")
    assert await w.run_once() == 1
    assert len(p.calls("api.greynoise.io")) == 1
    quota = await rows(engine, "SELECT provider, used FROM enrichment_quota")
    assert [(r.provider, r.used) for r in quota] == [("greynoise", 50)]
    assert w.last_error == {"greynoise": "rate_limited"}

    # Same day, more cycles and even a restart: not one more request.
    assert await w.run_once() == 0
    restarted = worker(factory, p, ABUSEIPDB_API_KEY="", GREYNOISE_DAILY_QUOTA="50")
    assert await restarted.run_once() == 0
    assert len(p.calls("api.greynoise.io")) == 1

    # The next UTC day starts with a clean counter and asks again.
    tomorrow = rep._quota_day() + timedelta(days=1)
    monkeypatch.setattr(rep, "_quota_day", lambda: tomorrow)
    p.gn_status = 200
    next_day = worker(factory, p, ABUSEIPDB_API_KEY="", GREYNOISE_DAILY_QUOTA="50")
    assert await next_day.run_once() == 2
    assert len(p.calls("api.greynoise.io")) == 3
    quota = await rows(engine, "SELECT day, used FROM enrichment_quota ORDER BY day")
    assert [r.used for r in quota] == [50, 2]


async def test_without_keys_nothing_happens(
    factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    await seed_sessions(factory)
    p = Providers()
    w = worker(factory, p, ABUSEIPDB_API_KEY="", GREYNOISE_API_KEY="")
    assert await w.run_once() == 0 and not p.requests


async def test_private_and_documentation_ips_are_not_sent_to_providers(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await seed_sessions(factory)  # documentation range, real is_routable
    p = Providers()
    assert await worker(factory, p).run_once() == 0 and not p.requests


# ---- grants -----------------------------------------------------------------------------------


async def test_role_grants_for_enrichment_tables(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await publish_status(factory, "geoip", {"provider": "dbip", "available": True})
    async with factory() as s, s.begin():
        await s.execute(text("INSERT INTO ip_reputation (ip, abuse_score) VALUES ('192.0.2.1', 5)"))
        await s.execute(text("UPDATE ip_reputation SET abuse_score = 6"))
        await s.execute(
            text("INSERT INTO enrichment_quota (provider, day, used) VALUES ('x', current_date, 1)")
        )
    async with factory() as s:
        with pytest.raises(DBAPIError):
            await s.execute(text("DELETE FROM ip_reputation"))

    api = create_engine(_role_url("API"), pool_size=1)
    try:
        async with api.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM ip_reputation")) == 1
            assert await conn.scalar(text("SELECT count(*) FROM enrichment_status")) == 1
            assert await conn.scalar(text("SELECT count(*) FROM enrichment_quota")) == 1
        for stmt in (
            "INSERT INTO ip_reputation (ip) VALUES ('192.0.2.2')",
            "UPDATE enrichment_quota SET used = 0",
            "DELETE FROM enrichment_status",
        ):
            async with api.connect() as conn:
                with pytest.raises(DBAPIError):
                    await conn.execute(text(stmt))
    finally:
        await api.dispose()
