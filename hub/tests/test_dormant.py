"""Dormant members and freed pseudonyms (hub/hub/dormant.py, 2026-11-21 field report)."""

from __future__ import annotations

import uuid
from datetime import date, timedelta

import pytest
from sqlalchemy import text

from hub import dormant, observatory, stats

from .conftest import Env
from .helpers import NodeClient, batch, source
from .seed import TODAY, add_nodes

D = timedelta(days=1)


# --- the rule (no database) -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("enrolled", "last_batch", "expected"),
    [
        (TODAY - 7 * D, None, False),  # a week without a batch: still new
        (TODAY - 8 * D, None, True),  # enrolled more than 7 days ago, never sent
        (TODAY - 60 * D, TODAY - 30 * D, False),
        (TODAY - 60 * D, TODAY - 31 * D, True),  # no accepted batch for 30 days
        (TODAY - 60 * D, TODAY - D, False),
    ],
)
def test_dormant_rule(enrolled: date, last_batch: date | None, expected: bool) -> None:
    assert dormant.is_dormant(enrolled, last_batch, TODAY) is expected


@pytest.mark.parametrize(
    ("enrolled", "last_batch", "expected"),
    [
        (TODAY, None, False),  # enrolled today: keeps its name
        (TODAY - D, None, False),  # yesterday: maybe less than 24 h
        (TODAY - 2 * D, None, True),  # at least 24 h and never a batch: a ghost
        (TODAY - 2 * D, TODAY - D, False),  # it sends: never freed
        (TODAY - 60 * D, TODAY - 31 * D, True),  # dormant
    ],
)
def test_name_free_rule(enrolled: date, last_batch: date | None, expected: bool) -> None:
    assert dormant.name_free(enrolled, last_batch, TODAY) is expected


# --- summary, feed statistics and observatory -------------------------------------------------


async def _set(env: Env, node_id: uuid.UUID, **values: object) -> None:
    sets = ", ".join(f"{k} = :{k}" for k in values)
    async with env.worker() as s:
        await s.execute(text(f"UPDATE nodes SET {sets} WHERE id = :i"), {**values, "i": node_id})
        await s.commit()


@pytest.mark.integration
async def test_dormant_members_are_left_out_of_every_count(env: Env) -> None:
    active = await add_nodes(env.worker, 3, countries=["CH"] * 3, show_country=True)
    await add_nodes(
        env.worker, 1, enrolled=[TODAY - 10 * D], active_days=0, countries=["CH"], show_country=True
    )
    (gone,) = await add_nodes(env.worker, 1, active_days=0)
    await _set(env, gone, last_batch_day=TODAY - 40 * D)
    (fresh,) = await add_nodes(env.worker, 1, enrolled=[TODAY - 3 * D], active_days=0)
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
    assert active and fresh


@pytest.mark.integration
async def test_a_dormant_node_that_sends_counts_again(env: Env) -> None:
    (node,) = await env.enrolled()
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET enrolled_day = :d"), {"d": TODAY - 10 * D})
        await s.commit()
        assert (await stats.build_summary(s, TODAY)).totals.members == 0
    sent = await node.call(
        "POST", "/v1/observations", batch("2026-10-31", sources=[source("192.0.2.4")])
    )
    assert sent.status == 200, sent.json
    async with env.worker() as s:
        day = (await s.execute(text("SELECT last_batch_day FROM nodes"))).scalar_one()
        await s.execute(text("DELETE FROM batches"))  # markers expire after 14 days
        await s.commit()
        assert (await stats.build_summary(s, TODAY)).totals.members == 1
    assert day == date(2026, 10, 31)


# --- pseudonyms -------------------------------------------------------------------------------


async def _age(env: Env, node: NodeClient, days: int) -> None:
    await _set(env, uuid.UUID(node.node_id), enrolled_day=TODAY - days * D)


@pytest.mark.integration
async def test_a_ghost_frees_its_pseudonym_for_a_reinstall(env: Env) -> None:
    (ghost,) = await env.enrolled(pseudonym="bignoe")
    await _age(env, ghost, 2)
    again = env.node()
    reply = await again.enrol(pseudonym="Bignoe")
    assert reply.status == 200, reply.json
    me = await ghost.call("GET", "/v1/node")
    assert me.status == 200 and me.json["pseudonym"] is None  # kept, but nameless
    # It may take a new name at once when it comes back.
    body = {"protocol": "spn/1", "pseudonym": "other name"}
    renamed = await ghost.call("PATCH", "/v1/node", body)
    assert renamed.status == 200


@pytest.mark.integration
async def test_a_fresh_or_active_holder_keeps_its_pseudonym(env: Env) -> None:
    (fresh,) = await env.enrolled(pseudonym="fresh owl")
    await _age(env, fresh, 1)  # less than a full day ago
    assert (await env.node().enrol(pseudonym="fresh owl")).error == "pseudonym_taken"
    (active,) = await env.enrolled(pseudonym="busy owl")
    await _age(env, active, 20)
    sent = await active.call(
        "POST", "/v1/observations", batch("2026-10-31", sources=[source("192.0.2.4")])
    )
    assert sent.status == 200
    assert (await env.node().enrol(pseudonym="busy owl")).error == "pseudonym_taken"
    (other,) = await env.enrolled(pseudonym="third owl")
    patched = await other.call("PATCH", "/v1/node", {"protocol": "spn/1", "pseudonym": "busy owl"})
    assert patched.error == "pseudonym_taken"
    assert (await active.call("GET", "/v1/node")).json["pseudonym"] == "busy owl"


@pytest.mark.integration
async def test_a_rename_takes_a_dormant_members_pseudonym(env: Env) -> None:
    (old,) = await env.enrolled(pseudonym="old owl")
    await _set(env, uuid.UUID(old.node_id), enrolled_day=TODAY - 90 * D,
               last_batch_day=TODAY - 40 * D)  # fmt: skip
    (new,) = await env.enrolled(pseudonym="new owl")
    patched = await new.call("PATCH", "/v1/node", {"protocol": "spn/1", "pseudonym": "old owl"})
    assert patched.status == 200 and patched.json["pseudonym"] == "old owl"
    assert (await old.call("GET", "/v1/node")).json["pseudonym"] is None
