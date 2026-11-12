"""Folding a flood into groups changes no number the dashboard shows (migration 0034).

Plain RDP connections from one address are seeded one row each, every aggregate endpoint is read,
``fold_session_buckets`` runs as the database owner, and every endpoint is read again: the numbers
must be equal. What does change is asserted too: the list of sessions now shows groups next to the
standalone rows, ``/sessions/{id}/events`` and ``/credentials`` read a group's events, a folded id
resolves to its group with ``?at=``, and ``/attacks?password=`` still finds a flood.

The API role (read-only) serves every request when ``POSTGRES_API_USER`` is configured; the owner
only seeds and folds. Addresses are from the documentation ranges.
"""

import os
from collections import Counter
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import Seed, api_engine, owner_engine
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from suckerpot_db import create_session_factory

from api.live import fetch_stats
from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PLAIN = ["credential-stuffing", "weak-credentials", "rdp-cleartext", "scanner", "smb-v1-probe"]
FLOODER = "203.0.113.7"
FEW = "198.51.100.4"
SSH_IP = "198.51.100.9"
NL = ("NL", "Amsterdam", 64500, "Example Net")
DE = ("DE", "Frankfurt", 64501, "Other Net")
NOW = datetime.now(UTC).replace(microsecond=0)
HOUR = NOW.replace(minute=0, second=0) - timedelta(hours=3)
NEXT_HOUR = HOUR + timedelta(hours=1)
WINDOW = {
    "since": (HOUR - timedelta(hours=1)).isoformat(),
    "until": (HOUR + timedelta(hours=4)).isoformat(),
}
CVE_ID = "CVE-2099-0100"

Event = tuple[float, str, dict[str, Any]]


def _login(offset: float, user: str, password: str) -> Event:
    return (offset, "login_attempt", {"username": user, "password": password, "success": False})


def _evs(logins: list[tuple[str, str]]) -> list[Event]:
    evs: list[Event] = [(0.0, "connect", {})]
    evs += [_login(1.0 + 0.5 * j, u, p) for j, (u, p) in enumerate(logins)]
    evs.append((1.0 + 0.5 * len(logins) + 1.0, "disconnect", {}))
    return evs


# The three kinds of flood connection of FLOODER in HOUR; every group lies at least five minutes
# from the next, so the events of one group never reach into another's time range.
STUFFING = [(f"cs-{i:02d}", HOUR + timedelta(minutes=i)) for i in range(20)]
WEAK = [(f"wk-{i:02d}", HOUR + timedelta(minutes=25 + i)) for i in range(8)]
LOOKED = [(f"lk-{i:02d}", HOUR + timedelta(minutes=40 + i)) for i in range(5)]
LATER = [(f"nx-{i:02d}", NEXT_HOUR + timedelta(minutes=i)) for i in range(22)]
WEAK_LOGINS = [("Administrator", "123456"), ("admin", "password"), ("user", "admin")]


def _stuffing_login(i: int) -> tuple[str, str]:
    return "Administrator", f"cs-pass-{i}"


def build_seed() -> Seed:
    seed = Seed()
    for i, (sid, start) in enumerate(STUFFING):
        seed.session(
            sid, "rdp", FLOODER, start, _evs([_stuffing_login(i)]),
            tags=["credential-stuffing"], geo=NL, abuse=40,
        )  # fmt: skip
    for sid, start in WEAK:
        seed.session(
            sid, "rdp", FLOODER, start, _evs(WEAK_LOGINS),
            tags=["credential-stuffing", "weak-credentials"], geo=NL, abuse=40,
        )  # fmt: skip
    for sid, start in LOOKED:
        seed.session(sid, "rdp", FLOODER, start, _evs([]), tags=[], geo=NL, abuse=40)
    for i, (sid, start) in enumerate(LATER):
        seed.session(
            sid, "rdp", FLOODER, start, _evs([("Administrator", f"nx-pass-{i}")]),
            tags=["credential-stuffing"], geo=NL, abuse=40,
        )  # fmt: skip
    for i in range(5):  # a few connections of another address: below the threshold, never fold
        seed.session(
            f"few-{i}", "rdp", FEW, HOUR + timedelta(minutes=10 + i),
            _evs([("Administrator", f"rdp-pass-{i}")]),
            tags=["credential-stuffing"], geo=DE, abuse=10,
        )  # fmt: skip
    seed.session(  # one successful login with commands: always keeps its row
        "ssh-in", "ssh", SSH_IP, HOUR + timedelta(minutes=50),
        [
            (0.0, "connect", {}),
            (1.0, "login_attempt", {"username": "root", "password": "toor", "success": True}),
            (2.0, "command", {"input": "uname -a"}),
            (3.0, "disconnect", {}),
        ],
        tags=["recon"], geo=DE, success=True,
    )  # fmt: skip
    for i in range(3):  # research scanner connections: hidden by default, never folded
        seed.session(
            f"scan-{i}", "rdp", "192.0.2.50", HOUR + timedelta(minutes=30 + i), _evs([]),
            tags=["scanner"], geo=NL,
        )  # fmt: skip
        seed.sessions[-1]["benign"] = True
        seed.sessions[-1]["scanner_name"] = "example-scanner"
    for row in seed.sessions:  # one insert statement: every row names the same columns
        row.setdefault("benign", False)
        row.setdefault("scanner_name", None)
    return seed


async def seed_world(owner: AsyncEngine) -> None:
    await build_seed().write(owner)
    async with owner.begin() as conn:
        await conn.execute(text("TRUNCATE cve, inventory_services"))
        await conn.execute(
            text(
                "INSERT INTO cve (cve_id, vendor, product, title, description, cvss_severity, "
                "cvss_score, in_kev, relevance, matched_services, tags, published_at, rank_score,"
                " sources) VALUES (:id, 'Example', 'RDP', 'Weak credentials flaw', 'text', "
                "'HIGH', 8.1, false, 'high', ARRAY['rdp'], ARRAY['weak-credentials'], :pub, 5, "
                "ARRAY['nvd'])"
            ),
            {"id": CVE_ID, "pub": NOW - timedelta(days=2)},
        )
        await conn.execute(
            text(
                "INSERT INTO inventory_services (name, service, product, version, exposure, "
                "created_by) VALUES ('Remote desktop', 'rdp', 'Example RDP', '10', 'internet', "
                "'test')"
            )
        )


async def fold(owner: AsyncEngine, buckets: list[tuple[str, str, datetime]]) -> int:
    async with owner.begin() as conn:
        value = await conn.scalar(
            text(
                "SELECT fold_session_buckets(CAST(CAST(:ips AS text[]) AS inet[]), "
                "CAST(:sensors AS text[]), CAST(:hours AS timestamptz[]), 20, "
                "CAST(:tags AS text[]), interval '15 minutes', 1000)"
            ),
            {
                "ips": [b[0] for b in buckets],
                "sensors": [b[1] for b in buckets],
                "hours": [b[2] for b in buckets],
                "tags": PLAIN,
            },
        )
    return int(value)


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    async with owner_engine() as engine:
        yield engine
        # A later test file seeds with TRUNCATE; the migration tests refuse to downgrade over a
        # group: leave none behind.
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE events, sessions, cve, inventory_services"))


async def client_of() -> tuple[httpx.AsyncClient, AsyncEngine, Any]:
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    ctx = app.router.lifespan_context(app)
    await ctx.__aenter__()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1")
    return client, engine, ctx


async def get(client: httpx.AsyncClient, path: str, **params: Any) -> Any:
    r = await client.get(path, params=params)
    assert r.status_code == 200, f"{path} {params}: {r.status_code} {r.text}"
    return r.json()


async def snapshot() -> dict[str, Any]:
    """Every number the dashboard derives from sessions, read through a fresh app (no caches)."""
    client, engine, ctx = await client_of()
    try:
        out: dict[str, Any] = {}
        summary = await get(client, "/stats/summary")
        out["summary"] = {k: v for k, v in summary.items() if not k.startswith("flood_")}
        out["flood"] = (summary["flood_sessions"], summary["flood_sources"])
        incl = await get(client, "/stats/summary", include_benign="true")
        out["summary_with_benign"] = {k: v for k, v in incl.items() if not k.startswith("flood_")}

        series = await get(client, "/stats/timeseries", bucket="1h", **WINDOW)
        out["timeseries"] = [(p["ts"], p["sessions"], p["events"]) for p in series["points"]]
        for name in ("country", "asn", "org", "tag", "src_ip", "username", "password"):
            top = await get(client, "/stats/top", field=name, limit=100, **WINDOW)
            # last_seen is left out: a group ends at its last event, a plain row at its start
            out[f"top_{name}"] = (
                top["total"],
                [(i["value"], i["count"], i["share"], i["first_seen"]) for i in top["items"]],
            )

        for sort in ("sessions", "events", "first_seen", "last_seen"):
            page = await get(client, "/attackers", sort=sort, limit=50)
            out[f"attackers_{sort}"] = [tuple(a.values()) for a in page["items"]]
        detail = await get(client, f"/attackers/{FLOODER}")
        out["attacker"] = detail["attacker"]
        out["attacker_top_usernames"] = detail["top_usernames"]
        out["asns"] = [
            (a["asn"], a["ips"], a["sessions"], a["events"], a["last_seen"])
            for a in (await get(client, "/asns", sort="sessions"))["items"]
        ]

        story = await get(client, "/story", hours=24)
        out["story"] = {k: story[k] for k in ("headline", "totals", "flow", "timeline")}
        out["story_ids"] = [s["session_id"] for s in story["stories"]]
        today = await get(client, "/today")
        out["today"] = {k: v for k, v in today.items() if k != "generated_at"}
        tags = await get(client, "/trends/tags", bucket="1h", **WINDOW)
        out["trend_tags"] = (tags["series"], tags["points"])
        new_asn = await get(client, "/trends/new", field="asn", days=7)
        out["new_asn"] = [(i["value"], i["count"], i["first_seen"]) for i in new_asn["items"]]
        cves = await get(client, "/cves")
        out["cves"] = [(i["cve_id"], i["seen_sessions"]) for i in cves["items"]]
        traffic = (await get(client, f"/cves/{CVE_ID}"))["traffic"]
        exposure = await get(client, "/defend/exposure")
        guidance = (await get(client, "/defend/guidance"))["items"]
        # "Last seen": a group is seen when its last event arrived, a plain row when it started,
        # so these can only move later by the length of a connection. Kept apart.
        out["lasts"] = {
            "cve": traffic.pop("last_seen"),
            "exposure": [s["attacks"].pop("last_attack_at") for s in exposure["services"]],
            "guidance": [i["seen"].pop("last_seen") for i in guidance],
        }
        out["cve_traffic"] = traffic
        out["exposure"] = {k: v for k, v in exposure.items() if k != "generated_at"}
        out["guidance"] = [(i["tag"], i["seen"]) for i in guidance]
        groups = (await get(client, "/search", q=FLOODER))["groups"]
        out["search"] = [
            (h["value"], h["count"]) for g in groups if g["kind"] == "ip" for h in g["hits"]
        ]
        return out
    finally:
        await client.aclose()
        await ctx.__aexit__(None, None, None)
        await engine.dispose()


async def listing(**params: Any) -> list[dict[str, Any]]:
    client, engine, ctx = await client_of()
    try:
        page = await get(client, "/sessions", limit=200, include_benign="true", **params)
        items: list[dict[str, Any]] = page["items"]
        return items
    finally:
        await client.aclose()
        await ctx.__aexit__(None, None, None)
        await engine.dispose()


BUCKETS = [(FLOODER, "rdp", HOUR), (FLOODER, "rdp", NEXT_HOUR), (FEW, "rdp", HOUR)]


async def test_folding_changes_no_number_the_dashboard_shows(owner: AsyncEngine) -> None:
    await seed_world(owner)
    before = await snapshot()
    rows_before = await listing()
    assert {r["kind"] for r in rows_before} == {"session"}
    assert len(rows_before) == 20 + 8 + 5 + 22 + 5 + 1 + 3

    # The snapshot is meaningful: the flood is in every aggregate that was compared.
    assert before["summary"]["sessions"] == 20 + 8 + 5 + 22 + 5 + 1
    assert before["summary"]["unique_ips"] == 3
    assert before["summary"]["sessions_with_commands"] == 1
    assert before["summary_with_benign"]["sessions"] == before["summary"]["sessions"] + 3
    assert before["flood"] == (0, 0)
    tag_counts = {value: count for value, count, *_ in before["top_tag"][1]}
    assert tag_counts["credential-stuffing"] == 20 + 8 + 22 + 5
    assert tag_counts["weak-credentials"] == 8
    assert (CVE_ID, 8) in before["cves"]
    assert before["cve_traffic"]["sessions"] == 8
    assert before["story"]["totals"]["sessions"] == before["summary"]["sessions"]
    assert ("weak-credentials", 8) in [(tag, seen["sessions"]) for tag, seen in before["guidance"]]
    assert before["exposure"]["services"][0]["attacks"]["sessions"] == 20 + 8 + 5 + 22 + 5
    assert before["search"] == [(FLOODER, 20 + 8 + 5 + 22)]

    folded = await fold(owner, BUCKETS)
    assert folded == 20 + 8 + 5 + 22  # FEW stays below the threshold, the rest is not plain

    after = await snapshot()
    assert after["flood"] == (55, 1)
    assert after["story_ids"]
    assert not [i for i in after["story_ids"] if i.startswith("burst-")]
    for name, value in before.items():
        if name in ("flood", "story_ids", "lasts"):
            continue
        assert after[name] == value, f"{name} changed after folding"
    # A group is last seen when its last connection ended: never earlier than before, and
    # within the span of one connection (a few seconds here).
    assert after["lasts"]["cve"] >= before["lasts"]["cve"]
    for kind, was in before["lasts"].items():
        now = after["lasts"][kind]
        for was_one, now_one in zip(
            was if isinstance(was, list) else [was],
            now if isinstance(now, list) else [now],
            strict=True,
        ):
            lag = datetime.fromisoformat(now_one) - datetime.fromisoformat(was_one)
            assert timedelta(0) <= lag <= timedelta(seconds=10), kind

    # What changes is the list: the groups, then the standalone rows.
    rows_after = await listing()
    groups = [r for r in rows_after if r["kind"] == "burst"]
    singles = [r for r in rows_after if r["kind"] == "session"]
    assert len(groups) == 4  # stuffing, weak, looked (HOUR) and the next hour
    assert sorted(g["connections"] for g in groups) == [5, 8, 20, 22]
    assert len(singles) == 5 + 1 + 3
    assert {s["session_id"] for s in singles} == {r["session_id"] for r in rows_before} - {
        sid for sid, _ in STUFFING + WEAK + LOOKED + LATER
    }
    assert sum(r["connections"] for r in rows_after) == len(rows_before)
    for g in groups:
        assert g["session_id"].startswith("burst-") and g["src_port"] == 0
        assert g["src_ip"] == FLOODER and g["sensor"] == "rdp" and g["dst_port"] == 3389
        assert g["login_success"] is False and g["commands"] == 0 and g["benign"] is False
    only_groups = await listing(kind="burst")
    assert {r["session_id"] for r in only_groups} == {g["session_id"] for g in groups}
    only_singles = await listing(kind="session")
    assert {r["session_id"] for r in only_singles} == {s["session_id"] for s in singles}


async def test_the_events_credentials_and_folded_ids_of_a_group(owner: AsyncEngine) -> None:
    await seed_world(owner)
    assert await fold(owner, BUCKETS) == 55
    client, engine, ctx = await client_of()
    try:
        groups = {
            g["connections"]: g
            for g in (await get(client, "/sessions", kind="burst", include_benign="true"))["items"]
        }
        looked, weak, stuffing = groups[5], groups[8], groups[20]

        # Events: those of the group's source, sensor and port in its time range.
        events = (await get(client, f"/sessions/{looked['session_id']}/events", limit=200))["items"]
        assert len(events) == 5 * 2  # connect and disconnect of each of the five connections
        assert {e["session_id"] for e in events} == {sid for sid, _ in LOOKED}
        assert {e["src_ip"] for e in events} == {FLOODER}
        weak_events = (await get(client, f"/sessions/{weak['session_id']}/events", limit=200))[
            "items"
        ]
        assert len(weak_events) == 8 * (2 + len(WEAK_LOGINS))
        stamps = [datetime.fromisoformat(e["ts"]) for e in weak_events]
        assert stamps == sorted(stamps)
        page = await get(client, f"/sessions/{stuffing['session_id']}/events", limit=7)
        assert len(page["items"]) == 7 and page["next_cursor"]
        more = await get(
            client,
            f"/sessions/{stuffing['session_id']}/events",
            limit=200,
            cursor=page["next_cursor"],
        )
        assert len(page["items"]) + len(more["items"]) == 20 * 3 and more["next_cursor"] is None

        # Credentials.
        cred = await get(client, f"/sessions/{weak['session_id']}/credentials", limit=10)
        assert cred["attempts"] == 8 * 3 and not cred["truncated"]
        assert (cred["distinct_usernames"], cred["distinct_passwords"], cred["distinct_pairs"]) == (
            3, 3, 3,
        )  # fmt: skip
        assert {p["count"] for p in cred["pairs"]} == {8}
        assert Counter(u["value"] for u in cred["usernames"] for _ in range(u["count"])) == Counter(
            {"Administrator": 8, "admin": 8, "user": 8}
        )
        stuff = await get(client, f"/sessions/{stuffing['session_id']}/credentials", limit=3)
        assert stuff["attempts"] == 20 and stuff["distinct_passwords"] == 20
        assert stuff["distinct_usernames"] == 1 and len(stuff["passwords"]) == 3
        assert (await get(client, f"/sessions/{looked['session_id']}/credentials"))["attempts"] == 0
        r = await client.get("/sessions/nope/credentials")
        assert r.status_code == 404
        # A plain connection answers from its own events.
        own = await get(client, "/sessions/few-3/credentials")
        assert own["attempts"] == 1 and own["pairs"][0]["password"] == "rdp-pass-3"

        # A folded id resolves to its group at the time it happened.
        at = dict(STUFFING)["cs-05"].isoformat()
        folded = await get(client, "/sessions/cs-05", at=at)
        assert folded["session_id"] == stuffing["session_id"]
        assert (folded["kind"], folded["connections"], folded["folded_from"]) == (
            "burst", 20, "cs-05",
        )  # fmt: skip
        assert (await get(client, "/sessions/wk-03", at=dict(WEAK)["wk-03"].isoformat()))[
            "session_id"
        ] == weak["session_id"]
        # A looking connection and a guessing one of the same hour map to their own group.
        assert (await get(client, "/sessions/lk-02", at=dict(LOOKED)["lk-02"].isoformat()))[
            "session_id"
        ] == looked["session_id"]
        assert "folded_from" in (await get(client, f"/sessions/{stuffing['session_id']}"))
        assert (await get(client, f"/sessions/{stuffing['session_id']}"))["folded_from"] is None
        # Without ``at``, far from it, or for an id that never existed: not found.
        assert (await client.get("/sessions/cs-05")).status_code == 404
        far = (dict(STUFFING)["cs-05"] + timedelta(days=3)).isoformat()
        assert (await client.get("/sessions/cs-05", params={"at": far})).status_code == 404
        assert (await client.get("/sessions/never", params={"at": at})).status_code == 404
        assert (
            await client.get("/sessions/cs-05", params={"at": "2026-01-01T00:00:00"})
        ).status_code == 422

        # The value filters still find a flood: by password, username and tag.
        found = await get(client, "/sessions", password="cs-pass-7", include_benign="true")
        assert [i["session_id"] for i in found["items"]] == [stuffing["session_id"]]
        found = await get(client, "/sessions", password="123456", include_benign="true")
        assert [i["session_id"] for i in found["items"]] == [weak["session_id"]]
        found = await get(client, "/sessions", password="rdp-pass-2", include_benign="true")
        assert [i["session_id"] for i in found["items"]] == ["few-2"]  # a plain row still matches
        found = await get(client, "/sessions", username="Administrator", include_benign="true")
        assert {i["kind"] for i in found["items"]} == {"burst", "session"}
        assert {i["session_id"] for i in found["items"] if i["kind"] == "session"} == {
            f"few-{i}" for i in range(5)
        }
        assert (await get(client, "/sessions", password="never-tried"))["items"] == []
    finally:
        await client.aclose()
        await ctx.__aexit__(None, None, None)
        await engine.dispose()


async def test_live_counters_and_one_minute_sessions_are_equal_after_folding(
    owner: AsyncEngine,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    seed = Seed()
    for i in range(25):
        seed.session(
            f"lv-{i:02d}", "rdp", FLOODER, now - timedelta(seconds=40 - i), _evs([("a", f"p{i}")]),
            tags=["credential-stuffing"], geo=NL,
        )  # fmt: skip
    await seed.write(owner)

    async def counters() -> tuple[Any, Any]:
        engine = api_engine()
        try:
            factory = create_session_factory(engine)
            async with factory() as session:
                stats = await fetch_stats(session, include_benign=False)
            return stats.sessions_last_minute, stats.by_sensor["rdp"].sessions
        finally:
            await engine.dispose()

    before = await counters()
    assert before == (25, 25)
    buckets = sorted(
        {(FLOODER, "rdp", s["started_at"].replace(minute=0, second=0)) for s in seed.sessions}
    )
    assert await fold(owner, buckets) == 25
    assert await counters() == before
