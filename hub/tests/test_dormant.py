"""Dormant members and freed pseudonyms (hub/hub/dormant.py, 2026-11-21 field report)."""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError

from hub import dormant, observatory, stats

from .conftest import Env
from .helpers import NodeClient, batch, source
from .seed import TODAY, add_nodes

D = timedelta(days=1)
REF = date(2026, 10, 26)  # count_ref(TODAY): the Monday of the week of TODAY - 4 days


# --- the rules (no database) ------------------------------------------------------------------


def test_the_count_reference_moves_once_a_week_over_settled_days() -> None:
    assert dormant.count_ref(TODAY) == REF
    refs = {dormant.count_ref(date(2026, 10, 30) + i * D) for i in range(7)}
    assert refs == {REF}  # one value for seven days
    for i in range(60):
        day = TODAY + i * D
        ref = dormant.count_ref(day)
        assert ref.weekday() == 0
        assert ref <= day - dormant.SETTLE_DAYS * D  # every day before it is settled


@pytest.mark.parametrize(
    ("enrolled", "last_batch", "expected"),
    [
        (REF - 7 * D, None, False),  # a week without a batch: still new
        (REF - 8 * D, None, True),  # enrolled more than 7 days before, never sent
        (REF - 60 * D, REF - 30 * D, False),
        (REF - 60 * D, REF - 31 * D, True),  # no accepted batch for 30 days
        (REF - 60 * D, REF - D, False),
    ],
)
def test_dormant_rule(enrolled: date, last_batch: date | None, expected: bool) -> None:
    assert dormant.is_dormant(enrolled, last_batch, TODAY) is expected


@pytest.mark.parametrize(
    ("ever_batched", "silent_days", "expected"),
    [
        (False, 1, False),
        (False, 2, True),  # a never-batched ghost, silent on two served days
        (True, 2, False),  # a node that ever sent a batch never loses its name
        (True, 400, False),
    ],
)
def test_name_free_rule(ever_batched: bool, silent_days: int, expected: bool) -> None:
    assert dormant.name_free(ever_batched, silent_days) is expected


class _Orig(Exception):
    def __init__(self, sqlstate: str, text_: str = "") -> None:
        super().__init__(text_)
        self.sqlstate = sqlstate


def test_a_lost_race_is_recognised() -> None:
    dup = IntegrityError("x", {}, _Orig("23505", 'duplicate key "nodes_pseudonym_key_key"'))
    assert dormant.lost_race(dup)
    assert not dormant.lost_race(IntegrityError("x", {}, _Orig("23505", "nodes_pubkey_key")))
    assert dormant.lost_race(OperationalError("x", {}, _Orig("40P01")))
    assert dormant.lost_race(OperationalError("x", {}, _Orig("40001")))
    assert not dormant.lost_race(OperationalError("x", {}, _Orig("57014")))
    assert not dormant.lost_race(ValueError("x"))


# --- summary, feed statistics and observatory -------------------------------------------------


async def _set(env: Env, node_id: uuid.UUID, **values: object) -> None:
    sets = ", ".join(f"{k} = :{k}" for k in values)
    async with env.worker() as s:
        await s.execute(text(f"UPDATE nodes SET {sets} WHERE id = :i"), {**values, "i": node_id})
        await s.commit()


@pytest.mark.integration
async def test_dormant_members_are_left_out_of_every_count(env: Env) -> None:
    await add_nodes(env.worker, 3, countries=["CH"] * 3, show_country=True)
    await add_nodes(
        env.worker, 1, enrolled=[TODAY - 20 * D], active_days=0, countries=["CH"], show_country=True
    )
    (gone,) = await add_nodes(env.worker, 1, active_days=0)
    await _set(env, gone, last_batch_day=TODAY - 40 * D)
    await add_nodes(env.worker, 1, enrolled=[TODAY - 3 * D], active_days=0)  # still new
    async with env.worker() as s:
        summary = await stats.run_daily(s, TODAY)
        members_row = (
            await s.execute(text("SELECT members FROM network_daily WHERE day = :d"), {"d": TODAY})
        ).scalar_one()
        inp = await observatory.load(s, env.settings, TODAY)
        left = (await s.execute(text("SELECT count(*) FROM nodes"))).scalar_one()
    assert summary.totals.members == 4  # three active and the fresh one
    assert len(summary.members) == 4 and members_row == 4
    assert [(c.cc, c.members) for c in summary.countries] == [("CH", 3)]
    assert inp.members == 4 and inp.country_members == {"CH": 3}
    assert left == 6  # nothing is deleted


@pytest.mark.integration
async def test_a_country_at_the_edge_does_not_flip_day_by_day(env: Env) -> None:
    await add_nodes(env.worker, 2, countries=["CH"] * 2, show_country=True)
    (edge,) = await add_nodes(
        env.worker, 1, active_days=0, countries=["CH"], show_country=True,
        enrolled=[TODAY - 90 * D],
    )  # fmt: skip
    # A daily 30-day window would drop it on 2026-11-03; the weekly one keeps the week stable.
    await _set(env, edge, last_batch_day=date(2026, 10, 3))
    seen = set()
    async with env.worker() as s:
        for i in range(7):
            summary = await stats.build_summary(s, date(2026, 10, 30) + i * D)
            seen.add((summary.totals.members, tuple((c.cc, c.members) for c in summary.countries)))
        later = await stats.build_summary(s, date(2026, 11, 13))
    assert seen == {(3, (("CH", 3),))}
    assert later.totals.members == 2 and later.countries == []


@pytest.mark.integration
async def test_a_dormant_node_that_sends_counts_again_from_the_next_week(env: Env) -> None:
    (node,) = await env.enrolled()
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET enrolled_day = :d"), {"d": TODAY - 20 * D})
        await s.commit()
        assert (await stats.build_summary(s, TODAY)).totals.members == 0
    sent = await node.call(
        "POST", "/v1/observations", batch("2026-10-31", sources=[source("192.0.2.4")])
    )
    assert sent.status == 200, sent.json
    async with env.worker() as s:
        day = (await s.execute(text("SELECT last_batch_day FROM nodes"))).scalar_one()
        assert (await stats.build_summary(s, TODAY)).totals.members == 0  # not mid-week
        await s.execute(text("DELETE FROM batches"))  # markers expire after 14 days
        await s.commit()
        assert (await stats.build_summary(s, TODAY + 7 * D)).totals.members == 1
    assert day == date(2026, 10, 31)


# --- pseudonyms -------------------------------------------------------------------------------


async def _served(env: Env, *days: date, blocked: bool = False) -> None:
    async with env.worker() as s:
        for d in days:
            await s.execute(
                text(
                    "INSERT INTO hub_served_days (day, blocked) VALUES (:d, :b) "
                    "ON CONFLICT (day) DO UPDATE SET blocked = EXCLUDED.blocked"
                ),
                {"d": d, "b": blocked},
            )
        await s.commit()


async def _silent_since(env: Env, node: NodeClient, last_active: date, **values: object) -> None:
    await _set(env, uuid.UUID(node.node_id), last_active_day=last_active,
               enrolled_day=TODAY - 10 * D, **values)  # fmt: skip


@pytest.mark.integration
async def test_requests_mark_the_day_as_served(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    (node,) = await env.enrolled()
    assert (await node.call("GET", "/v1/node")).status == 200
    async with env.worker() as s:
        rows = (await s.execute(text("SELECT day, blocked FROM hub_served_days"))).all()
    assert [(r.day, r.blocked) for r in rows] == [(TODAY, False)]
    # A refusal by the address limiter marks the day: it never counts as anyone's silence.
    monkeypatch.setattr(env.ctx.address_limiter, "blocked", lambda _request: 30)
    assert (await node.call("GET", "/v1/node")).error == "rate_limited"
    async with env.worker() as s:
        rows = (await s.execute(text("SELECT day, blocked FROM hub_served_days"))).all()
    assert [(r.day, r.blocked) for r in rows] == [(TODAY, True)]


@pytest.mark.integration
async def test_a_silent_never_batched_ghost_frees_its_pseudonym(env: Env) -> None:
    (ghost,) = await env.enrolled(pseudonym="bignoe")
    await _silent_since(env, ghost, TODAY - 3 * D)
    await _served(env, TODAY - 2 * D, TODAY - D)  # two served days without a request from it
    reply = await env.node().enrol(pseudonym="Bignoe")
    assert reply.status == 200, reply.json
    me = await ghost.call("GET", "/v1/node")
    assert me.status == 200 and me.json["pseudonym"] is None  # kept, but nameless
    # It may take a new name at once when it comes back.
    body = {"protocol": "spn/1", "pseudonym": "other name"}
    assert (await ghost.call("PATCH", "/v1/node", body)).status == 200


@pytest.mark.integration
async def test_outages_and_blocked_days_are_not_silence(env: Env) -> None:
    (ghost,) = await env.enrolled(pseudonym="lone owl")
    await _silent_since(env, ghost, TODAY - 9 * D)
    # The hub served only one day since (an outage), plus one day with an address block.
    await _served(env, TODAY - 5 * D)
    await _served(env, TODAY - 2 * D, blocked=True)
    await _served(env, TODAY)  # today does not count: it is not over
    assert (await env.node().enrol(pseudonym="lone owl")).error == "pseudonym_taken"
    await _served(env, TODAY - D)
    assert (await env.node().enrol(pseudonym="lone owl")).status == 200


@pytest.mark.integration
async def test_a_node_that_ever_sent_a_batch_keeps_its_pseudonym(env: Env) -> None:
    # Paused for its own address, no traffic, or gone quiet: it batched once, so the name stays.
    (paused,) = await env.enrolled(pseudonym="quiet owl")
    await _silent_since(env, paused, TODAY - 20 * D, last_batch_day=TODAY - 60 * D)
    await _served(env, *(TODAY - i * D for i in range(1, 20)))
    assert (await env.node().enrol(pseudonym="quiet owl")).error == "pseudonym_taken"
    (other,) = await env.enrolled(pseudonym="third owl")
    patched = await other.call("PATCH", "/v1/node", {"protocol": "spn/1", "pseudonym": "quiet owl"})
    assert patched.error == "pseudonym_taken"
    assert (await paused.call("GET", "/v1/node")).json["pseudonym"] == "quiet owl"


@pytest.mark.integration
async def test_a_live_never_batched_node_keeps_its_pseudonym(env: Env) -> None:
    (fresh,) = await env.enrolled(pseudonym="fresh owl")
    await _served(env, *(TODAY - i * D for i in range(1, 5)))
    # Enrolled today: the served days before do not count against it.
    assert (await env.node().enrol(pseudonym="fresh owl")).error == "pseudonym_taken"
    await _silent_since(env, fresh, TODAY - 2 * D)  # one served day of silence only
    assert (await env.node().enrol(pseudonym="fresh owl")).error == "pseudonym_taken"
    assert (await fresh.call("GET", "/v1/node")).json["pseudonym"] == "fresh owl"


# --- races (L3) -------------------------------------------------------------------------------


async def _no_check(*_args: Any, **_kw: Any) -> bool:
    return True  # as if a concurrent claim slipped between the check and the write


async def _deadlock(*_args: Any, **_kw: Any) -> bool:
    raise OperationalError("SELECT", {}, _Orig("40P01"))


@pytest.mark.integration
async def test_a_lost_race_answers_pseudonym_taken(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    (holder,) = await env.enrolled(pseudonym="race owl")
    (other,) = await env.enrolled(pseudonym="other owl")
    monkeypatch.setattr(dormant, "claim_pseudonym", _no_check)
    assert (await env.node().enrol(pseudonym="race owl")).error == "pseudonym_taken"
    body = {"protocol": "spn/1", "pseudonym": "race owl"}
    assert (await other.call("PATCH", "/v1/node", body)).error == "pseudonym_taken"
    monkeypatch.setattr(dormant, "claim_pseudonym", _deadlock)
    assert (await env.node().enrol(pseudonym="race owl")).error == "pseudonym_taken"
    assert (await other.call("PATCH", "/v1/node", body)).error == "pseudonym_taken"
    assert (await holder.call("GET", "/v1/node")).json["pseudonym"] == "race owl"
    assert (await other.call("GET", "/v1/node")).json["pseudonym"] == "other owl"
