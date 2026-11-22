"""The report effect worker against a real database, as the ingest role (M38 G1).

Reports and sessions are synthetic, on documentation addresses (``include_demo`` lets them into the
pool, as in CI). Nothing is contacted.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_reporting import SelfTerms

from ingest.abuse.candidates import Seed, without_holdouts
from ingest.takedown import effect

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]
Factory = async_sessionmaker[AsyncSession]

D = datetime.now(UTC).date() - timedelta(days=20)  # the index day
T0 = datetime.combine(D, time(10, 0), UTC)
CFG = effect.EffectConfig(include_demo=True)
TERMS = SelfTerms(
    addresses=frozenset({"198.51.100.99"}),
    networks=(),
    vpn_addresses=frozenset(),
    names=(),
    texts=(),
    has_self_address=True,
)
R1, R2, R3, R5 = "198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.15"
C1, C2, C3, C5 = "198.51.100.20", "198.51.100.21", "198.51.100.30", "198.51.100.25"
SELF = "198.51.100.99"


def at(day: date, hour: int = 12) -> datetime:
    return datetime.combine(day, time(hour, 0), UTC)


@pytest.fixture(autouse=True)
async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE report_effect_pairs, report_effect_unmatched, report_effect_days, "
                "abuse_holdouts, network_targets, takedown_targets, abuse_report_subjects, "
                "abuse_reports CASCADE"
            )
        )
        await conn.execute(text("DELETE FROM sessions WHERE session_id LIKE 'fx-%'"))


async def add_session(
    engine: AsyncEngine,
    ip: str,
    when: datetime,
    *,
    logins: int = 0,
    events: int = 1,
    asn: int | None = 64500,
    tags: tuple[str, ...] = (),
) -> None:
    async with engine.begin() as conn:
        n = await conn.scalar(text("SELECT count(*) FROM sessions WHERE session_id LIKE 'fx-%'"))
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                "started_at, last_event_at, event_count, login_attempts, asn, country, tags) "
                "VALUES (:s, 'ssh', CAST(:ip AS inet), 4000, 22, :t, :t, :e, :l, :a, 'NL', "
                "CAST(:tags AS text[]))"
            ),
            {
                "s": f"fx-{n}", "ip": ip, "t": when, "e": events, "l": logins, "a": asn,
                "tags": list(tags),
            },
        )  # fmt: skip


async def add_report(engine: AsyncEngine, values: list[str], sent: datetime) -> None:
    async with engine.begin() as conn:
        rec = await conn.scalar(
            text(
                "INSERT INTO abuse_recipients (mailbox, name, source) VALUES "
                "('abuse@example.net', 'Example NOC', 'rdap') ON CONFLICT (mailbox) DO UPDATE "
                "SET name = 'Example NOC' RETURNING id"
            )
        )
        rid = await conn.scalar(
            text(
                "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, "
                "window_start, window_end, subject_count, evidence, content_sha256, guard_ok, "
                "sent_at) VALUES (gen_random_uuid(), gen_random_uuid(), :r, 'attack_source', "
                "'sent', :t, :t, 1, CAST(:e AS jsonb), 'x', true, :t) RETURNING id"
            ),
            {"r": rec, "t": sent, "e": json.dumps({})},
        )
        for v in values:
            await conn.execute(
                text(
                    "INSERT INTO abuse_report_subjects (report_id, subject_type, value, "
                    "first_ts, last_ts, sessions, events) VALUES (:r, 'ip', :v, :t, :t, 1, 1)"
                ),
                {"r": rid, "v": v, "t": sent},
            )
            # What the takedown tracker's sync makes of a sent report (the units of the measure).
            await conn.execute(
                text(
                    "INSERT INTO takedown_targets (kind, role, value, target_key, provider_key, "
                    "reported_at, channels, track_until) VALUES ('ip', 'attack_source', :v, "
                    "encode(sha256(convert_to('ip:' || :v, 'UTF8')), 'hex'), 'as64500', :t, '{mail}', :until) "
                    "ON CONFLICT (kind, role, value) DO UPDATE SET "
                    "reported_at = LEAST(takedown_targets.reported_at, EXCLUDED.reported_at)"
                ),
                {"v": v, "t": sent, "until": sent + timedelta(days=30)},
            )


async def scenario(engine: AsyncEngine, *, noise: bool = True) -> None:
    yesterday = D - timedelta(days=1)
    # R1 and its controls: 60 login attempts the day before (login, 10-99 events, 1-2 days).
    for ip, asn in ((R1, 64500), (C1, 64500), (C2, 64501), (SELF, 64500)):
        await add_session(engine, ip, at(yesterday), logins=60, events=60, asn=asn)
    await add_session(engine, C3, at(yesterday), logins=2000, events=2000)  # other volume
    await add_session(engine, R2, at(yesterday), logins=5, events=5, tags=("exploit",))
    # R5 and its only comparable candidate, which the network reported.
    await add_session(engine, R5, at(yesterday), logins=500, events=500)
    await add_session(engine, C5, at(yesterday), logins=500, events=500)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO network_targets (hub_id, kind, value, state, nodes, first_day, "
                "last_day, reported_day) VALUES ('t_0123456789ab', 'ip', :v, 'reported', 2, :d, :d, :d)"
            ),
            {"v": C5, "d": D - timedelta(days=2)},
        )
    await add_report(engine, [R1, R2, R3, R5], T0)
    # Outcome: R1 is seen in its 7-day window (days 7 to 13), C1 is not.
    await add_session(engine, R1, T0 + timedelta(days=8))
    if noise:  # 12 distinct addresses on each day of the window: the sensors were up
        for i in range(7):
            for j in range(12):
                await add_session(
                    engine, f"203.0.113.{j + 1}", at(D + timedelta(days=7 + i), 3), asn=None
                )


async def pairs(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        return list(
            (
                await conn.execute(
                    text(
                        "SELECT host(reported_value) AS r, host(control_value) AS c, tier, "
                        "activity_class, volume_bucket, recency_bucket, seen_r_7, seen_c_7, "
                        "observed_7, excluded_7, frozen_7_at, frozen_30_at "
                        "FROM report_effect_pairs ORDER BY id"
                    )
                )
            ).all()
        )


async def unmatched(engine: AsyncEngine) -> dict[str, str]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT host(value) AS v, reason FROM report_effect_unmatched")
        )
        return {r.v: r.reason for r in rows}


async def test_pairs_outcomes_and_freeze(engine: AsyncEngine, factory: Factory) -> None:
    await scenario(engine)
    # Too early: the index day needs 3 more days of candidates.
    assert await effect.make_pairs(factory, at(D + timedelta(days=2)), TERMS, CFG) == {}
    out = await effect.make_pairs(factory, at(D + timedelta(days=5)), TERMS, CFG)
    assert out["pairs"] == 1 and out["unmatched"] == 3
    (p,) = await pairs(engine)
    assert (p.r, p.c, p.tier) == (R1, C1, "A")  # same ASN beats C2; the self term never counts
    assert (p.activity_class, p.volume_bucket, p.recency_bucket) == ("login", 1, 1)
    assert await unmatched(engine) == {
        R2: "no_control", R3: "no_activity", R5: "no_control",
    }  # fmt: skip
    # Idempotent: a second run makes nothing new.
    assert await effect.make_pairs(factory, at(D + timedelta(days=5)), TERMS, CFG) == {}

    later = at(D + timedelta(days=16))
    assert await effect.fill_days(factory, later, 90) > 0
    frozen = await effect.freeze(factory, later)
    assert frozen == {"frozen_7": 1}
    (p,) = await pairs(engine)
    assert (p.seen_r_7, p.seen_c_7, p.observed_7, p.excluded_7) == (True, False, True, None)
    assert p.frozen_7_at is not None and p.frozen_30_at is None
    assert await effect.freeze(factory, later) == {}  # frozen once

    # The frozen outcome cannot change; the addresses can only be cleared.
    with pytest.raises(DBAPIError, match="7-day outcome is frozen"):
        async with factory() as session, session.begin():
            await session.execute(text("UPDATE report_effect_pairs SET seen_r_7 = false"))
    with pytest.raises(DBAPIError, match="may only be cleared"):
        async with factory() as session, session.begin():
            await session.execute(
                text("UPDATE report_effect_pairs SET control_value = '198.51.100.40'")
            )
    with pytest.raises(DBAPIError):
        async with factory() as session, session.begin():
            await session.execute(text("DELETE FROM report_effect_pairs"))  # no grant


async def test_a_control_reported_later_drops_the_pair(
    engine: AsyncEngine, factory: Factory
) -> None:
    await scenario(engine)
    await effect.make_pairs(factory, at(D + timedelta(days=5)), TERMS, CFG)
    await add_report(engine, [C1], T0 + timedelta(days=10))
    later = at(D + timedelta(days=16))
    await effect.fill_days(factory, later, 90)
    assert await effect.freeze(factory, later) == {
        "frozen_7": 1, "excluded_7_control_reported": 1,
    }  # fmt: skip
    (p,) = await pairs(engine)
    assert p.excluded_7 == "control_reported" and p.seen_r_7 is None


async def test_a_week_with_the_node_down_is_not_observed(
    engine: AsyncEngine, factory: Factory
) -> None:
    await scenario(engine, noise=False)
    await effect.make_pairs(factory, at(D + timedelta(days=5)), TERMS, CFG)
    later = at(D + timedelta(days=16))
    await effect.fill_days(factory, later, 90)
    await effect.freeze(factory, later)
    (p,) = await pairs(engine)
    assert (p.observed_7, p.excluded_7, p.seen_r_7) == (False, "not_observed", None)


async def test_addresses_are_cleared_after_the_30_day_outcome(
    engine: AsyncEngine, factory: Factory
) -> None:
    await scenario(engine)
    await effect.make_pairs(factory, at(D + timedelta(days=5)), TERMS, CFG)
    far = at(D + timedelta(days=40))
    await effect.fill_days(factory, far, 90)
    await effect.freeze(factory, far)
    (p,) = await pairs(engine)
    assert p.frozen_30_at is not None and p.r == R1
    assert await effect.clear(factory, far + timedelta(days=29)) == 0
    assert await effect.clear(factory, far + timedelta(days=31)) == 1
    (p,) = await pairs(engine)
    assert p.r is None and p.c is None and p.seen_r_7 is True  # the counts stay
    # The summary view the API reads has no address column at all.
    async with engine.connect() as conn:
        cols = {
            r[0]
            for r in await conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'report_effect_summary'"
                )
            )
        }
    assert not {"reported_value", "control_value"} & cols


async def test_holdout_decides_each_new_candidate_once(
    engine: AsyncEngine, factory: Factory
) -> None:
    now = datetime.now(UTC)
    seeds = [Seed("attack_source", "ip", ip, now, now, 1, 1) for ip in (R1, C1)]
    draws = iter([0, 9999])  # R1 held, C1 not
    async with factory() as session:
        kept = await without_holdouts(
            session, seeds, 10, now, lambda _n: next(draws), include_demo=True
        )
    assert [s.value for s in kept] == [C1]
    async with factory() as session:  # no new draw: an exhausted iterator would raise
        kept = await without_holdouts(
            session, seeds, 10, now, lambda _n: next(draws), include_demo=True
        )
        assert [s.value for s in kept] == [C1]
        # Off releases every held source; after 21 days it is released anyway.
        assert len(await without_holdouts(session, seeds, 0, now)) == 2
        later = await without_holdouts(
            session, seeds, 10, now + timedelta(days=22), lambda _n: 0, include_demo=True
        )
        assert len(later) == 2
    async with engine.connect() as conn:
        row = (await conn.execute(text("SELECT held_now FROM abuse_holdout_summary"))).one()
    assert row.held_now == 1


async def test_status_line_follows_the_frozen_pairs(engine: AsyncEngine, factory: Factory) -> None:
    """``just status`` (M38): nothing before the first attack-source report, then progress."""
    from ingest.network import cli

    async with factory() as session:
        assert await cli.report_effect(session, datetime.now(UTC)) is None
    await scenario(engine)
    await effect.make_pairs(factory, at(D + timedelta(days=5)), TERMS, CFG)
    await effect.fill_days(factory, at(D + timedelta(days=16)), 90)
    await effect.freeze(factory, at(D + timedelta(days=16)))
    async with factory() as session:
        doc = await cli.report_effect(session, datetime.now(UTC))
    assert doc is not None
    assert doc["verdict"] == "not_enough_data" and doc["pairs"] == 1 and doc["needed"] == 30
    assert doc["seen_reported"] is None and doc["lo"] is None
    assert doc["line"] == "Report effect: not enough data yet (1 of 30 pairs)"
