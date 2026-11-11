"""Takedown sync, passive signals, states and the roll-up against a real database, as the ingest
role. Reports and fetch targets are synthetic; nothing is fetched or sent."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.takedown import rollup
from ingest.takedown.config import TakedownSettings
from ingest.takedown.passive import sample_signals, sightings, update_states
from ingest.takedown.sync import TargetSync

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]
Factory = async_sessionmaker[AsyncSession]
NOW = datetime.now(UTC).replace(microsecond=0)
SHA = "a" * 64
OTHER = "b" * 64


@pytest.fixture(autouse=True)
async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE takedown_target_links, takedown_checks, takedown_targets, "
                "abusech_submissions, abusech_submission, outcome_rollup_monthly, "
                "sample_links, sample_sources, samples, fetch_targets CASCADE"
            )
        )
        await conn.execute(text("DELETE FROM sessions WHERE session_id LIKE 'tk-%'"))


async def seed_network(conn: Any, asn: int | None = 64500) -> int:
    return int(
        await conn.scalar(
            text(
                "INSERT INTO abuse_networks (kind, cidr, name, country, asn, source, fetched_at, "
                "expires_at) VALUES ('ip', '198.51.100.0/24', 'EXAMPLE-NET', 'NL', :a, 'rdap', "
                "now(), now() + interval '30 days') ON CONFLICT (cidr) DO UPDATE SET "
                "name = EXCLUDED.name RETURNING id"
            ),
            {"a": asn},
        )
        or 0
    )


async def seed_report(
    engine: AsyncEngine,
    kind: str,
    subjects: list[tuple[str, str]],
    *,
    sent_hours_ago: float = 3,
    demo: bool = False,
    status: str = "sent",
    mailbox: str = "abuse@example.net",
    network: bool = True,
) -> int:
    async with engine.begin() as conn:
        net = await seed_network(conn) if network else None
        rec = await conn.scalar(
            text(
                "INSERT INTO abuse_recipients (mailbox, name, source) VALUES (:m, 'Example NOC', "
                "'rdap') ON CONFLICT (mailbox) DO UPDATE SET name = 'Example NOC' RETURNING id"
            ),
            {"m": mailbox},
        )
        rid = int(
            await conn.scalar(
                text(
                    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, "
                    "demo, window_start, window_end, subject_count, evidence, content_sha256, "
                    "guard_ok, sent_at) VALUES (gen_random_uuid(), gen_random_uuid(), :r, :k, "
                    ":s, :d, :t, :t, 1, CAST(:e AS jsonb), 'x', true, :sent) RETURNING id"
                ),
                {
                    "r": rec,
                    "k": kind,
                    "s": status,
                    "d": demo,
                    "t": NOW,
                    "e": json.dumps({}),
                    "sent": NOW - timedelta(hours=sent_hours_ago),
                },
            )
            or 0
        )
        for stype, value in subjects:
            await conn.execute(
                text(
                    "INSERT INTO abuse_report_subjects (report_id, subject_type, value, "
                    "network_id, first_ts, last_ts, sessions, events) VALUES "
                    "(:r, :t, :v, :n, :ts, :ts, 1, 1)"
                ),
                {"r": rid, "t": stype, "v": value, "n": net, "ts": NOW},
            )
    return rid


async def seed_fetched(engine: AsyncEngine, url: str, host: str, sha: str = SHA) -> int:
    async with engine.begin() as conn:
        fid = int(
            await conn.scalar(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, status, first_seen, "
                    "last_attempt_at, last_sha256) VALUES (:u, 'http', :h, 'fetched', :n, :n, :s) "
                    "RETURNING id"
                ),
                {"u": url, "h": host, "n": NOW, "s": sha},
            )
            or 0
        )
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, kind, first_seen, last_seen) "
                "VALUES (:s, 'x', 'y', 10, 'script', :n, :n) ON CONFLICT DO NOTHING"
            ),
            {"s": sha, "n": NOW},
        )
    return fid


async def targets(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text("SELECT * FROM takedown_targets ORDER BY id"))).all())


def sync(factory: Factory, **kw: Any) -> TargetSync:
    return TargetSync(factory, TakedownSettings(**kw))


async def test_sent_reports_become_targets_with_a_provider(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "attack_source", [("ip", "198.51.100.7")])
    await seed_report(
        engine, "c2", [("ip", "203.0.113.9")], mailbox="c2@example.net", network=False
    )
    await seed_report(engine, "attack_source", [("ip", "198.51.100.8")], status="draft",
                      mailbox="draft@example.net")  # fmt: skip
    made = await sync(factory).sync(NOW)
    assert made["reports"] == 2
    rows = {(t.role, t.value): t for t in await targets(engine)}
    assert set(rows) == {("attack_source", "198.51.100.7"), ("c2", "203.0.113.9")}
    a = rows[("attack_source", "198.51.100.7")]
    assert (a.provider_key, a.provider_name, a.asn, a.country) == (
        "as64500", "EXAMPLE-NET", 64500, "NL"
    )  # fmt: skip
    assert a.channels == ["mail"] and a.kind == "ip" and not a.http_eligible
    assert a.track_until == a.reported_at + timedelta(days=30)
    assert a.listing_next_at == a.reported_at and len(a.target_key) == 64
    c = rows[("c2", "203.0.113.9")]
    assert c.provider_key.startswith("recipient:")
    # A second pass changes nothing (each report is linked once).
    assert (await sync(factory).sync(NOW))["reports"] == 0
    assert len(await targets(engine)) == 2


async def test_the_earliest_report_wins_and_channels_merge(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "attack_source", [("ip", "198.51.100.7")], sent_hours_ago=2)
    await seed_report(engine, "attack_source", [("ip", "198.51.100.7")], sent_hours_ago=30,
                      mailbox="other@example.net")  # fmt: skip
    await sync(factory).sync(NOW)
    (t,) = await targets(engine)
    assert abs((NOW - t.reported_at).total_seconds() - 30 * 3600) < 5
    async with engine.connect() as conn:
        links = await conn.scalar(text("SELECT count(*) FROM takedown_target_links"))
    assert links == 2


async def test_payload_host_children_are_fetched_urls_only_and_capped(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")])
    for i in range(25):
        await seed_fetched(engine, f"http://198.51.100.7/bins/x{i}.sh", "198.51.100.7")
    async with engine.begin() as conn:  # a failed fetch and another host's URL: no children
        await conn.execute(
            text(
                "INSERT INTO fetch_targets (url, scheme, host, status, first_seen) VALUES "
                "('http://198.51.100.7/gone.sh', 'http', '198.51.100.7', 'gone', now()), "
                "('http://203.0.113.5/a.sh', 'http', '203.0.113.5', 'fetched', now())"
            )
        )
    made = await sync(factory).sync(NOW)
    assert made["children"] == 20
    rows = await targets(engine)
    host = next(t for t in rows if t.role == "payload_host")
    kids = [t for t in rows if t.role == "payload_url"]
    assert len(kids) == 20 and all(k.parent_id == host.id for k in kids)
    assert all(k.http_eligible and k.baseline_sha256 == SHA for k in kids)
    assert all(k.provider_key == "as64500" and k.reported_at == host.reported_at for k in kids)
    assert all(k.http_next_at == host.reported_at for k in kids)
    assert (await sync(factory).sync(NOW))["children"] == 0  # capped, idempotent
    async with engine.connect() as conn:
        linked = await conn.scalar(
            text("SELECT count(*) FROM takedown_target_links WHERE target_id = :t"),
            {"t": kids[0].id},
        )
    assert linked == 1  # the child belongs to the host's report


async def test_sightings_and_states_for_an_attacking_address(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "attack_source", [("ip", "198.51.100.7")], sent_hours_ago=24)
    await sync(factory).sync(NOW)
    assert await sightings(factory, NOW) == 1  # first answer: not_seen
    assert await sightings(factory, NOW) == 0  # unchanged: no new row
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                "started_at, last_event_at) VALUES ('s1', 'ssh', '198.51.100.7', 4000, 22, "
                "now() - interval '1 hour', now())"
            )
        )
    assert await sightings(factory, NOW) == 1  # now seen
    await update_states(factory, NOW, 7)
    (t,) = await targets(engine)
    assert t.state == "up" and t.state_source == "sightings"
    async with engine.connect() as conn:
        outcomes = (
            await conn.execute(text("SELECT outcome FROM takedown_checks ORDER BY id"))
        ).scalars().all()  # fmt: skip
    assert outcomes == ["not_seen", "seen"]


async def test_a_benign_scanner_is_not_a_sighting(engine: AsyncEngine, factory: Factory) -> None:
    await seed_report(engine, "attack_source", [("ip", "198.51.100.7")], sent_hours_ago=24)
    await sync(factory).sync(NOW)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                "started_at, last_event_at, benign, scanner_name) VALUES ('s2', 'ssh', "
                "'198.51.100.7', 4000, 22, now(), now(), true, 'research')"
            )
        )
    await sightings(factory, NOW)
    async with engine.connect() as conn:
        assert await conn.scalar(text("SELECT outcome FROM takedown_checks")) == "not_seen"


async def test_c2_is_up_when_a_new_sample_points_to_it_and_never_down(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "c2", [("ip", "203.0.113.9")], sent_hours_ago=48)
    await sync(factory).sync(NOW)
    assert await sample_signals(factory, NOW) == 0  # none, first time: nothing to write
    await update_states(factory, NOW, 7)
    assert (await targets(engine))[0].state == "unknown"
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen) "
                "VALUES (:s, 'x', 'y', 1, now(), now())"
            ),
            {"s": OTHER},
        )
        await conn.execute(
            text(
                "INSERT INTO sample_links (sha256, kind, value, port, source, confidence) "
                "VALUES (:s, 'c2_ip', '203.0.113.9', 4444, 'strings', 'high')"
            ),
            {"s": OTHER},
        )
    later = NOW + timedelta(minutes=1)  # a check must be newer than the last state update
    assert await sample_signals(factory, later) == 1
    await update_states(factory, later, 7)
    t = (await targets(engine))[0]
    assert (t.state, t.state_source) == ("up", "samples")


async def test_url_goes_down_after_two_confirming_http_checks(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")], sent_hours_ago=10)
    await seed_fetched(engine, "http://198.51.100.7/a.sh", "198.51.100.7")
    await sync(factory).sync(NOW)
    kid = next(t for t in await targets(engine) if t.role == "payload_url")
    # The collector writes these rows; the owner role stands in for it here.
    async with engine.begin() as conn:
        for hours, outcome, sha in ((9, "same", SHA), (5, "http_404", None), (2, "http_404", None)):
            await conn.execute(
                text(
                    "INSERT INTO takedown_checks (target_id, checked_at, method, outcome, sha256) "
                    "VALUES (:t, :at, 'http', :o, :s)"
                ),
                {"t": kid.id, "at": NOW - timedelta(hours=hours), "o": outcome, "s": sha},
            )
    await update_states(factory, NOW, 7)
    rows = {t.role: t for t in await targets(engine)}
    assert rows["payload_url"].state == "down"
    assert rows["payload_url"].first_down_at == NOW - timedelta(hours=5)
    assert rows["payload_host"].state == "down" and rows["payload_host"].state_source == "children"
    assert rows["payload_host"].first_down_at == NOW - timedelta(hours=5)


async def test_rollup_counts_targets_and_tolerates_missing_outcomes(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")], sent_hours_ago=100)
    await seed_fetched(engine, "http://198.51.100.7/a.sh", "198.51.100.7")
    await sync(factory).sync(NOW)
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE takedown_targets SET first_down_at = reported_at + interval '5 hours'")
        )
    written = await rollup.recompute(factory, NOW)
    assert written >= 2
    async with engine.connect() as conn:
        rows = (await conn.execute(text("SELECT * FROM outcome_rollup_monthly"))).all()
    by = {(r.provider_key, r.kind, r.channel): r for r in rows}
    url = by[("as64500", "payload_url", "mail")]
    assert url.targets == 1 and url.targets_down_48h == 1 and url.targets_eligible_48h == 1
    assert url.reports_sent == 1  # the report that put it under tracking
    assert "198.51.100.7" not in json.dumps([dict(r._mapping) for r in rows], default=str)


# ---- T1: nothing is requested from an attacking or C2 address (security review) -------------


async def seed_session(engine: AsyncEngine, ip: str, days_ago: float = 1) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                "started_at, last_event_at) VALUES (:s, 'ssh', :ip, 4000, 22, :t, :t) "
                "ON CONFLICT DO NOTHING"
            ),
            {"s": f"tk-{ip}-{days_ago}", "ip": ip, "t": NOW - timedelta(days=days_ago)},
        )


async def payload_urls(engine: AsyncEngine) -> list[Any]:
    return [t for t in await targets(engine) if t.role == "payload_url"]


async def test_a_loader_on_an_attacking_address_is_never_eligible(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")], sent_hours_ago=10)
    await seed_fetched(engine, "http://198.51.100.7/bins.sh", "198.51.100.7")
    await seed_session(engine, "198.51.100.7", days_ago=2)
    await sync(factory).sync(NOW)
    (url,) = await payload_urls(engine)
    assert url.http_eligible is False and url.baseline_sha256 is None


async def test_an_attacker_older_than_thirty_days_does_not_count(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")], sent_hours_ago=10)
    await seed_fetched(engine, "http://198.51.100.7/bins.sh", "198.51.100.7")
    await seed_session(engine, "198.51.100.7", days_ago=40)
    await sync(factory).sync(NOW)
    (url,) = await payload_urls(engine)
    assert url.http_eligible is True


async def test_a_host_that_starts_attacking_later_is_dropped_at_the_next_cycle(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")], sent_hours_ago=10)
    await seed_fetched(engine, "http://198.51.100.7/bins.sh", "198.51.100.7")
    await sync(factory).sync(NOW)
    (url,) = await payload_urls(engine)
    assert url.http_eligible is True
    await seed_session(engine, "198.51.100.7", days_ago=0.1)
    made = await sync(factory).sync(NOW)
    assert made["demoted"] == 1
    (url,) = await payload_urls(engine)
    assert url.http_eligible is False


async def test_a_url_on_a_known_c2_address_is_never_eligible(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")], sent_hours_ago=10)
    await seed_fetched(engine, "http://198.51.100.7/bins.sh", "198.51.100.7")
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen) "
                "VALUES (:s, 'x', 'y', 1, now(), now()) ON CONFLICT DO NOTHING"
            ),
            {"s": OTHER},
        )
        await conn.execute(
            text(
                "INSERT INTO sample_links (sha256, kind, value, port, source, confidence) "
                "VALUES (:s, 'c2_ip', '198.51.100.7', 4444, 'strings', 'high')"
            ),
            {"s": OTHER},
        )
    await sync(factory).sync(NOW)
    (url,) = await payload_urls(engine)
    assert url.http_eligible is False


async def test_a_clean_host_stays_eligible(engine: AsyncEngine, factory: Factory) -> None:
    await seed_report(engine, "payload_host", [("ip", "198.51.100.7")], sent_hours_ago=10)
    await seed_fetched(engine, "http://198.51.100.7/a.sh", "198.51.100.7")
    await seed_session(engine, "203.0.113.200", days_ago=1)  # someone else attacked
    await sync(factory).sync(NOW)
    made = await sync(factory).sync(NOW)
    (url,) = await payload_urls(engine)
    assert url.http_eligible is True and made["demoted"] == 0
