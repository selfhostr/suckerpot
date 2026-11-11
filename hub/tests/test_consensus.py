"""Consensus, eligibility, k-support, reputation and takedown voting."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text

from hub import consensus, reputation
from hub.config import Settings
from hub.never import Never
from hub.support import first_day_supported, k_supported, last_day_supported

from .conftest import Env, make_settings
from .seed import TODAY, add_nodes, observe, target

D1, D2 = TODAY - timedelta(days=2), TODAY - timedelta(days=1)
IP = "192.0.2.109"


async def run(
    env: Env, never: Never | None = None, ok: bool = True, **over: Any
) -> consensus.ConsensusResult:
    s: Settings = make_settings(**over) if over else env.settings

    async def corroborate(_ip: str) -> bool:
        return ok

    async with env.worker() as ses:
        return await consensus.run_consensus(
            ses, s, TODAY, never=never or Never(), corroborate=corroborate
        )


# --- pure helpers ---


def test_k_supported_helpers() -> None:
    assert k_supported({"a": {1, 2, 3}, "b": {1}}, 2) == {"a"}
    days = {1: {D1, D2}, 2: {D1}, 3: {D1}}
    assert last_day_supported(days, 2) == D1  # only one node saw D2
    assert last_day_supported(days, 1) == D2
    assert first_day_supported(days, 3) == D1
    assert last_day_supported(days, 4) is None


# --- table of cases (design section 10) ---


@pytest.mark.integration
async def test_five_aged_nodes_on_two_days_are_confirmed(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes, "ip", IP, [D1, D2])
    res = await run(env)
    assert res.confirmed == 1
    t = await target(env.worker, "ip", IP)
    assert t["state"] == "confirmed" and t["confirmed_day"] == TODAY and t["node_count"] == 5


@pytest.mark.integration
async def test_five_eligible_nodes_with_start_reputation_confirm_a_target(env: Env) -> None:
    from hub.reputation import START

    nodes = await add_nodes(env.worker, 5, reputation=START)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env)
    assert (await target(env.worker, "sha256", "ab" * 32))["state"] == "confirmed"


@pytest.mark.integration
async def test_default_reputation_of_a_new_row_is_the_start_value(env: Env) -> None:
    from hub.reputation import START

    (n,) = await add_nodes(env.worker, 1)
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET reputation = DEFAULT WHERE id = :i"), {"i": n})
        rep = (await s.execute(text("SELECT reputation FROM nodes"))).scalar_one()
    assert rep == pytest.approx(START)


@pytest.mark.integration
async def test_four_nodes_stay_candidate(env: Env) -> None:
    nodes = await add_nodes(env.worker, 4)
    await observe(env.worker, nodes, "ip", IP, [D1, D2])
    await run(env)
    assert (await target(env.worker, "ip", IP))["state"] == "candidate"


@pytest.mark.integration
async def test_same_enrolment_week_is_a_cohort_and_stays_candidate(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5, enrolled=[TODAY - timedelta(days=20)] * 5)
    await observe(env.worker, nodes, "ip", IP, [D1, D2])
    await run(env)
    assert (await target(env.worker, "ip", IP))["state"] == "candidate"


@pytest.mark.integration
async def test_cohort_share_limit_is_half(env: Env) -> None:
    # 6 nodes, 3 in one week = exactly 0.5: allowed; 4 of 6 is not
    weeks = [TODAY - timedelta(days=20 + 7 * w) for w in (0, 0, 0, 1, 2, 3)]
    nodes = await add_nodes(env.worker, 6, enrolled=weeks)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env)
    assert (await target(env.worker, "sha256", "ab" * 32))["state"] == "confirmed"
    weeks = [TODAY - timedelta(days=20 + 7 * w) for w in (0, 0, 0, 0, 1, 2)]
    nodes = await add_nodes(env.worker, 6, enrolled=weeks)
    await observe(env.worker, nodes, "sha256", "cd" * 32, [D1, D2])
    await run(env)
    assert (await target(env.worker, "sha256", "cd" * 32))["state"] == "candidate"


@pytest.mark.integration
async def test_new_nodes_do_not_count(env: Env) -> None:
    nodes = await add_nodes(
        env.worker, 5, enrolled=[TODAY - timedelta(days=7 * i) for i in range(5)]
    )
    # enrolled 0, 7, 14, 21, 28 days ago: only the last two are 14+ days old
    await observe(env.worker, nodes, "ip", IP, [D1, D2])
    await run(env)
    assert (await target(env.worker, "ip", IP))["state"] == "candidate"


@pytest.mark.integration
async def test_nodes_need_seven_active_days(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5, active_days=6)
    await observe(env.worker, nodes, "ip", IP, [D1, D2])
    res = await run(env)
    assert res.groups == 0  # no eligible node, nothing is even a candidate


@pytest.mark.integration
async def test_low_weight_blocks(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5, reputation=0.5)  # 5 x 0.5 = 2.5 < 3.0 (below start)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env)
    assert (await target(env.worker, "sha256", "ab" * 32))["state"] == "candidate"


@pytest.mark.integration
async def test_single_day_needs_double_nodes(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D2])
    await run(env)
    assert (await target(env.worker, "sha256", "ab" * 32))["state"] == "candidate"
    ten = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await observe(env.worker, ten, "sha256", "cd" * 32, [D2])
    await run(env)
    assert (await target(env.worker, "sha256", "cd" * 32))["state"] == "confirmed"


@pytest.mark.integration
async def test_uncorroborated_ip_needs_ten_nodes(env: Env) -> None:
    five = await add_nodes(env.worker, 5)
    await observe(env.worker, five, "ip", IP, [D1, D2])
    await run(env, ok=False)
    assert (await target(env.worker, "ip", IP))["state"] == "candidate"
    ten = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await observe(env.worker, ten, "ip", "192.0.2.110", [D1, D2])
    await run(env, ok=False)
    assert (await target(env.worker, "ip", "192.0.2.110"))["state"] == "confirmed"


@pytest.mark.integration
async def test_never_list_value_is_never_confirmed(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes, "ip", "198.51.100.130", [D1, D2])
    await run(env, never=Never.from_rows([("198.51.100.128/25", "ip")]))
    assert await target(env.worker, "ip", "198.51.100.130") is None


@pytest.mark.integration
async def test_single_node_values_get_no_row(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes[:1], "ip", "192.0.2.177", [D1, D2])
    await run(env)
    assert await target(env.worker, "ip", "192.0.2.177") is None


@pytest.mark.integration
async def test_blinded_kind_keeps_value_b_only(env: Env) -> None:
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await observe(env.worker, nodes, "url", "ab" * 32, [D1, D2], fetched=True)
    await run(env)
    t = await target(env.worker, "url", "ab" * 32)
    assert t["state"] == "confirmed" and t["value"] is None and t["value_b"] == "ab" * 32


@pytest.mark.integration
async def test_suspended_nodes_are_ignored(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    async with env.worker() as s:
        await s.execute(
            text("UPDATE nodes SET standing = 'soft_suspended' WHERE id = :i"), {"i": nodes[0]}
        )
        await s.commit()
    await run(env)
    assert (await target(env.worker, "sha256", "ab" * 32))["state"] == "candidate"


# --- k-support: a single node cannot move what members see ---


@pytest.mark.integration
async def test_single_sighting_changes_no_published_field(env: Env) -> None:
    nodes = await add_nodes(env.worker, 6)
    await observe(env.worker, nodes[:5], "sha256", "ab" * 32, [D1, D2])
    await run(env)
    before = await target(env.worker, "sha256", "ab" * 32)
    assert before["state"] == "confirmed"
    # one node (the probed sensor) sees the listed value later, with a new service and tag
    env.clock.advance(days=1)
    probe_day = TODAY  # still closed relative to the next run
    await observe(
        env.worker, nodes[5:], "sha256", "ab" * 32, [probe_day],
        services=["redis"], activity=["exploit"], tags=["db-ransom"], families=["xmrig"],
    )  # fmt: skip
    async with env.worker() as ses:
        await consensus.run_consensus(
            ses, env.settings, TODAY + timedelta(days=1), never=Never(), corroborate=None
        )
    after = await target(env.worker, "sha256", "ab" * 32)
    for field in ("last_day", "first_day", "services", "activity", "tags", "families", "state"):
        assert after[field] == before[field], field
    # a node that was already eligible, but only a second sighting: still below k=5
    # (k nodes agreeing does move the fields)
    await observe(env.worker, nodes[:5], "sha256", "ab" * 32, [probe_day], services=["redis"])
    async with env.worker() as ses:
        await consensus.run_consensus(
            ses, env.settings, TODAY + timedelta(days=1), never=Never(), corroborate=None
        )
    moved = await target(env.worker, "sha256", "ab" * 32)
    assert moved["last_day"] == probe_day and "redis" in moved["services"]
    assert "db-ransom" not in moved["tags"] and moved["families"] == []


@pytest.mark.integration
async def test_weak_group_does_not_touch_a_confirmed_target(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1])
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D2])
    await run(env)
    before = await target(env.worker, "sha256", "ab" * 32)
    async with env.worker() as s:  # three of five nodes lose eligibility: group is a candidate now
        await s.execute(
            text("UPDATE nodes SET standing = 'soft_suspended' WHERE id = ANY(:i)"),
            {"i": nodes[:3]},
        )
        await s.commit()
    await observe(
        env.worker, nodes[3:], "sha256", "ab" * 32, [TODAY - timedelta(days=3)], services=["redis"]
    )
    await run(env)
    after = await target(env.worker, "sha256", "ab" * 32)
    assert after["services"] == before["services"] and after["state"] == "confirmed"


# --- contributors, expiry, never re-check, dispute ---


@pytest.mark.integration
async def test_contributors_are_linked_for_confirmed_targets(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env)
    async with env.worker() as s:
        n = (await s.execute(text("SELECT count(*) FROM target_contributors"))).scalar_one()
    assert n == 5


@pytest.mark.integration
async def test_expire_stale(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env)
    async with env.worker() as ses:
        assert await consensus.expire_stale(ses, TODAY) == 0
        assert await consensus.expire_stale(ses, TODAY + timedelta(days=40)) == 1
    assert (await target(env.worker, "sha256", "ab" * 32))["state"] == "expired"


@pytest.mark.integration
async def test_dispute_lowers_contributors_and_suspends_silently(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5, reputation=0.25)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env, min_weight=1.0, min_reputation=0.2)
    t = await target(env.worker, "sha256", "ab" * 32)
    assert t["state"] == "confirmed"
    async with env.worker() as s:
        assert await reputation.dispute(s, t["id"]) == 5
        assert await reputation.dispute(s, t["id"]) == 0  # idempotent
        rows = (await s.execute(text("SELECT reputation, standing FROM nodes"))).all()
    assert all(r.reputation == pytest.approx(0.15) and r.standing == "soft_suspended" for r in rows)
    assert (await target(env.worker, "sha256", "ab" * 32))["state"] == "disputed"


@pytest.mark.integration
async def test_revealed_never_listed_value_is_disputed(env: Env) -> None:
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await observe(env.worker, nodes, "url", "ab" * 32, [D1, D2])
    await run(env)
    async with env.worker() as s:
        await s.execute(text("UPDATE targets SET value = 'http://cdn.example.net/x'"))
        await s.commit()
    never = Never.from_rows([("example.net", "domain")])
    async with env.worker() as s:
        hits = await consensus.recheck_never_list(s, never, env.settings, TODAY)
    assert len(hits) == 1
    assert (await target(env.worker, "url", "ab" * 32))["state"] == "disputed"
    async with env.worker() as s:
        assert (
            await s.execute(text("SELECT min(reputation) FROM nodes"))
        ).scalar_one() == pytest.approx(0.7)


# --- reputation ---


@pytest.mark.integration
async def test_reputation_rewards_once_per_day(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5, reputation=0.5)
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env, min_weight=1.0)
    yesterday_target = TODAY  # confirmed_day = TODAY; processed when the next day starts
    assert (await target(env.worker, "sha256", "ab" * 32))["confirmed_day"] == yesterday_target
    async with env.worker() as s:
        res = await reputation.run_daily(s, env.settings, TODAY + timedelta(days=1))
        assert res.days == [TODAY]
        rep = (await s.execute(text("SELECT reputation FROM nodes LIMIT 1"))).scalar_one()
        assert rep == pytest.approx(0.51)
        again = await reputation.run_daily(s, env.settings, TODAY + timedelta(days=1))
        assert again.days == []
        assert (
            await s.execute(text("SELECT reputation FROM nodes LIMIT 1"))
        ).scalar_one() == pytest.approx(0.51)


@pytest.mark.integration
async def test_reputation_takedown_bonus_and_cap(env: Env) -> None:
    nodes = await add_nodes(env.worker, 2, reputation=0.5)  # two enrolment cohorts
    async with env.worker() as s:
        for i in range(8):
            await s.execute(
                text(
                    "INSERT INTO targets (id, kind, value, state, confirmed_day, first_day, last_day) "
                    "VALUES (:i, 'ip', :v, 'confirmed', :d, :d, :d)"
                ),
                {"i": f"t_{i:012x}", "v": f"203.0.113.{i + 20}", "d": TODAY},
            )
            for n in nodes:
                await s.execute(
                    text("INSERT INTO target_contributors VALUES (:i, :n)"),
                    {"i": f"t_{i:012x}", "n": n},
                )
        await s.execute(
            text(
                "UPDATE targets SET state = 'taken_down', taken_down_day = :d WHERE id = 't_000000000000'"
            ),
            {"d": TODAY},
        )
        await s.commit()
        await reputation.run_daily(s, env.settings, TODAY + timedelta(days=1))
        reps = (await s.execute(text("SELECT reputation FROM nodes"))).scalars().all()
    assert all(r == pytest.approx(0.5 + 0.05 + 0.02) for r in reps)  # +0.01 x 5 (capped) + 0.02


async def _flood(
    env: Env,
    contributors: int,
    *,
    extra_standing: str = "active",
    fresh: int = 0,
    edge: bool = False,
) -> list[Any]:
    """Node 0 floods 600 values nobody else sees; ``contributors - 1`` others saw one value each."""
    # ``fresh`` of the other nodes enrolled yesterday; with ``edge`` the last node's only
    # observation is exactly 14 days before the judged day, just outside the window.
    enrolled = [TODAY - timedelta(days=30)] * (contributors - fresh) + [D2] * fresh
    nodes = await add_nodes(env.worker, contributors, enrolled=enrolled, reputation=0.5)
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO observations (node_id, day, kind, value) "
                "SELECT :n, :d, 'ip', '2001:db8::' || to_hex(g) "
                "FROM generate_series(1, 600) g"
            ),
            {"n": nodes[0], "d": D2},
        )
        for i, node in enumerate(nodes[1:]):
            await s.execute(
                text(
                    "INSERT INTO observations (node_id, day, kind, value) VALUES (:n, :d, 'ip', :v)"
                ),
                {
                    "n": node,
                    "d": TODAY - timedelta(days=15) if edge and node == nodes[-1] else D2,
                    "v": f"203.0.113.{200 + i}",
                },
            )
        if extra_standing != "active":
            await s.execute(
                text("UPDATE nodes SET standing = :st WHERE id = ANY(:ids)"),
                {"st": extra_standing, "ids": nodes[1:]},
            )
        await s.commit()
    return nodes


async def _reputations(env: Env, settings: Settings | None = None) -> dict[Any, Any]:
    async with env.worker() as s:
        await reputation.run_daily(s, settings or env.settings, TODAY)
        return dict((await s.execute(text("SELECT id, reputation FROM nodes"))).all())


@pytest.mark.integration
async def test_uncorroborated_volume_is_penalised(env: Env) -> None:
    nodes = await _flood(env, 5)
    reps = await _reputations(env)
    assert reps[nodes[0]] == pytest.approx(0.45)
    assert all(reps[n] == pytest.approx(0.5) for n in nodes[1:])


@pytest.mark.integration
async def test_volume_penalty_needs_enough_contributing_nodes(env: Env) -> None:
    nodes = await _flood(env, 4)
    reps = await _reputations(env)
    assert all(reps[n] == pytest.approx(0.5) for n in nodes)


@pytest.mark.integration
async def test_volume_penalty_ignores_freshly_enrolled_nodes(env: Env) -> None:
    nodes = await _flood(env, 5, fresh=4)
    reps = await _reputations(env)
    assert all(reps[n] == pytest.approx(0.5) for n in nodes)


@pytest.mark.integration
async def test_volume_penalty_window_excludes_the_edge_day(env: Env) -> None:
    nodes = await _flood(env, 5, edge=True)
    reps = await _reputations(env)
    assert all(reps[n] == pytest.approx(0.5) for n in nodes)


@pytest.mark.integration
async def test_volume_penalty_ignores_nodes_that_are_not_active(env: Env) -> None:
    nodes = await _flood(env, 5, extra_standing="soft_suspended")
    reps = await _reputations(env)
    assert all(reps[n] == pytest.approx(0.5) for n in nodes)


@pytest.mark.integration
async def test_lower_volume_min_nodes_restores_the_penalty(env: Env) -> None:
    nodes = await _flood(env, 2)
    reps = await _reputations(env, make_settings(volume_min_nodes=2))
    assert reps[nodes[0]] == pytest.approx(0.45) and reps[nodes[1]] == pytest.approx(0.5)


# --- takedown voting ---


async def _reported(env: Env, nodes: list[Any]) -> str:
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, state, reported_day, confirmed_day, first_day, last_day) "
                "VALUES ('t_aaaaaaaaaaaa', 'ip', '203.0.113.202', 'reported', :r, :r, :r, :r)"
            ),
            {"r": TODAY - timedelta(days=8)},
        )
        await s.commit()
    return "t_aaaaaaaaaaaa"


async def _vote(env: Env, node: Any, day: Any, state: str) -> None:
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO takedown_votes VALUES ('t_aaaaaaaaaaaa', :n, :d, :s) ON CONFLICT DO NOTHING"
            ),
            {"n": node, "d": day, "s": state},
        )
        await s.commit()


async def _takedowns(env: Env, today: Any = TODAY) -> tuple[int, int]:
    async with env.worker() as s:
        eligible = await consensus.eligible_nodes(s, env.settings, today)
        return await consensus.update_takedowns(s, env.settings, today, eligible)


@pytest.mark.integration
async def test_takedown_needs_two_nodes_on_three_days_and_no_up_on_the_last(env: Env) -> None:
    nodes = await add_nodes(env.worker, 3)
    await _reported(env, nodes)
    days = [TODAY - timedelta(days=d) for d in (5, 4, 3)]
    for d in days:
        await _vote(env, nodes[0], d, "down")
    assert await _takedowns(env) == (0, 0)  # one node only
    await _vote(env, nodes[1], days[0], "down")
    assert await _takedowns(env) == (1, 0)
    t = await target(env.worker, "ip", "203.0.113.202")
    assert t["state"] == "taken_down" and t["taken_down_day"] == days[-1]


@pytest.mark.integration
async def test_an_up_vote_on_the_last_day_blocks_takedown(env: Env) -> None:
    nodes = await add_nodes(env.worker, 3)
    await _reported(env, nodes)
    days = [TODAY - timedelta(days=d) for d in (5, 4, 3)]
    for d in days:
        await _vote(env, nodes[0], d, "down")
    await _vote(env, nodes[1], days[0], "down")
    await _vote(env, nodes[2], days[-1], "up")
    assert await _takedowns(env) == (0, 0)


@pytest.mark.integration
async def test_votes_of_ineligible_nodes_do_not_count(env: Env) -> None:
    nodes = await add_nodes(env.worker, 2)
    young = await add_nodes(env.worker, 2, enrolled=[TODAY - timedelta(days=3)] * 2)
    await _reported(env, nodes)
    days = [TODAY - timedelta(days=d) for d in (5, 4, 3)]
    for d in days:
        await _vote(env, young[0], d, "down")
        await _vote(env, young[1], d, "down")
    assert await _takedowns(env) == (0, 0)


@pytest.mark.integration
async def test_up_votes_bring_a_taken_down_target_back(env: Env) -> None:
    nodes = await add_nodes(env.worker, 3)
    await _reported(env, nodes)
    days = [TODAY - timedelta(days=d) for d in (5, 4, 3)]
    for d in days:
        await _vote(env, nodes[0], d, "down")
        await _vote(env, nodes[1], d, "down")
    await _takedowns(env)
    await _vote(env, nodes[0], TODAY - timedelta(days=1), "up")
    assert await _takedowns(env) == (0, 1)
    t = await target(env.worker, "ip", "203.0.113.202")
    assert (
        t["state"] == "reported" and t["taken_down_day"] is None
    )  # reported 8 days ago: no re-report yet


# --- Sybil hardening: corroboration for every kind, droppers for C2, empty batches ---


def ten(env: Env) -> Any:
    return add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )


@pytest.mark.integration
async def test_url_and_c2_and_payload_host_need_twice_the_nodes(env: Env) -> None:
    five = await add_nodes(env.worker, 5)
    await observe(env.worker, five, "url", "ab" * 32, [D1, D2], fetched=True)
    await observe(env.worker, five, "c2_ip", "203.0.113.108:23", [D1, D2], via="cd" * 32)
    await observe(env.worker, five, "c2_domain", "ef" * 32, [D1, D2], via="cd" * 32)
    await observe(env.worker, five, "ip", "203.0.113.109", [D1, D2], activity=["download"])
    await run(env, ok=False)
    for kind, value in (
        ("url", "ab" * 32),
        ("c2_ip", "203.0.113.108:23"),
        ("c2_domain", "ef" * 32),
        ("ip", "203.0.113.109"),
    ):
        assert (await target(env.worker, kind, value))["state"] == "candidate", kind


@pytest.mark.integration
async def test_c2_address_may_be_corroborated_by_an_external_source(env: Env) -> None:
    five = await add_nodes(env.worker, 5)
    await observe(env.worker, five, "sha256", "cd" * 32, [D1, D2], fetched=True)
    await observe(env.worker, five, "c2_ip", "203.0.113.108:23", [D1, D2], via="cd" * 32)
    await run(env, ok=True)
    assert (await target(env.worker, "c2_ip", "203.0.113.108:23"))["state"] == "confirmed"


@pytest.mark.integration
async def test_c2_needs_a_confirmed_dropper_fetched_by_two_eligible_nodes(env: Env) -> None:
    nodes = await ten(env)
    await observe(env.worker, nodes, "c2_ip", "203.0.113.101:23", [D1, D2], via="aa" * 32)
    await observe(env.worker, nodes, "c2_ip", "203.0.113.102:23", [D1, D2], via="bb" * 32)
    await observe(env.worker, nodes, "c2_ip", "203.0.113.103:23", [D1, D2])  # no dropper named
    await observe(env.worker, nodes, "sha256", "aa" * 32, [D1, D2], fetched=True)
    await observe(env.worker, nodes, "sha256", "bb" * 32, [D1, D2], fetched=False)
    await run(env)
    got = {
        v: (await target(env.worker, "c2_ip", v))["state"]
        for v in ("203.0.113.101:23", "203.0.113.102:23", "203.0.113.103:23")
    }
    assert got == {
        "203.0.113.101:23": "confirmed",
        "203.0.113.102:23": "candidate",
        "203.0.113.103:23": "candidate",
    }


@pytest.mark.integration
async def test_c2_needs_k_of_its_own_nodes_to_have_fetched_the_dropper(env: Env) -> None:
    nodes = await ten(env)
    await observe(env.worker, nodes, "c2_ip", "203.0.113.104:23", [D1, D2], via="dd" * 32)
    # the dropper is confirmed and fetched by two nodes only; the other eight did not fetch it
    await observe(env.worker, nodes[:2], "sha256", "dd" * 32, [D1, D2], fetched=True)
    await observe(env.worker, nodes[2:], "sha256", "dd" * 32, [D1, D2], fetched=False)
    await run(env)
    assert (await target(env.worker, "sha256", "dd" * 32))["state"] == "confirmed"
    assert (await target(env.worker, "c2_ip", "203.0.113.104:23"))["state"] == "candidate"


@pytest.mark.integration
async def test_empty_batches_do_not_keep_a_node_eligible(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    async with env.worker() as s:
        await s.execute(
            text("UPDATE batches SET items = 0 WHERE node_id = ANY(:i)"), {"i": nodes[:3]}
        )
        await s.commit()
    await observe(env.worker, nodes, "sha256", "ab" * 32, [D1, D2])
    await run(env)
    assert (await target(env.worker, "sha256", "ab" * 32))[
        "state"
    ] == "candidate"  # only 2 eligible


@pytest.mark.integration
async def test_reputation_bonus_needs_two_cohorts(env: Env) -> None:
    (n,) = await add_nodes(env.worker, 1, reputation=0.5)
    (m,) = await add_nodes(env.worker, 1, reputation=0.5, enrolled=[TODAY - timedelta(days=40)])
    async with env.worker() as s:
        for tid, members in (("t_000000000001", [n]), ("t_000000000002", [n, m])):
            await s.execute(
                text(
                    "INSERT INTO targets (id, kind, value, state, confirmed_day, first_day, last_day) VALUES (:i,'ip',:v,'confirmed',:d,:d,:d)"
                ),
                {"i": tid, "v": f"203.0.113.{tid[-1]}", "d": TODAY},
            )
            for member in members:
                await s.execute(
                    text("INSERT INTO target_contributors VALUES (:i, :n)"), {"i": tid, "n": member}
                )
        await s.commit()
        await reputation.run_daily(s, env.settings, TODAY + timedelta(days=1))
        reps: dict[Any, Any] = dict(
            (await s.execute(text("SELECT id, reputation FROM nodes"))).all()
        )
    # n is in a one-cohort target and a two-cohort target: one bonus; m only the two-cohort one
    assert reps[n] == pytest.approx(0.51) and reps[m] == pytest.approx(0.51)


@pytest.mark.integration
async def test_published_counts_are_frozen_at_confirmation(env: Env) -> None:
    nodes = await add_nodes(env.worker, 6, countries=["CH", "DE", "FR", None, None, None])
    await observe(env.worker, nodes[:5], "sha256", "ab" * 32, [D1, D2])
    await run(env)
    before = await target(env.worker, "sha256", "ab" * 32)
    assert (before["node_count"], before["country_count"]) == (5, 3)
    # a sixth node with a fourth country sees the listed value: nothing a member sees moves
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET country = 'IT' WHERE id = :i"), {"i": nodes[5]})
        await s.commit()
    await observe(env.worker, nodes[5:], "sha256", "ab" * 32, [D1, D2])
    await run(env)
    after = await target(env.worker, "sha256", "ab" * 32)
    assert (after["node_count"], after["country_count"], after["seq"]) == (5, 3, before["seq"])
