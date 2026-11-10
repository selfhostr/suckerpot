"""Retention (H3), statistics and the k-rules of the published summary, worker steps, admin CLI."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text

from hub import admin, retention, stats
from hub.models import Base
from hub.worker import WorkerContext, healthy, run_cycle

from .conftest import Env
from .seed import TODAY, add_nodes, observe

pytestmark = pytest.mark.integration


async def count(env: Env, table: str, where: str = "true") -> int:
    async with env.worker() as s:
        return int(
            (await s.execute(text(f"SELECT count(*) FROM {table} WHERE {where}"))).scalar_one()
        )


async def test_observations_expire_after_fourteen_days(env: Env) -> None:
    (n,) = await add_nodes(env.worker, 1)
    await observe(
        env.worker,
        [n],
        "ip",
        "203.0.113.201",
        [TODAY - timedelta(days=14), TODAY - timedelta(days=15)],
    )
    async with env.worker() as s:
        res = await retention.run_retention(s, env.settings, env.clock(), TODAY)
    assert res.deleted["observations"] == 1
    assert await count(env, "observations") == 1  # the 14-day-old row stays, 15 is gone


async def test_nonces_challenges_votes_stats_expire(env: Env) -> None:
    (n,) = await add_nodes(env.worker, 1)
    now = env.clock()
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO nonces VALUES (:n, :x, :e), (:n, :y, :f)"),
            {
                "n": n,
                "x": b"a" * 16,
                "y": b"b" * 16,
                "e": now - timedelta(minutes=1),
                "f": now + timedelta(minutes=5),
            },
        )
        await s.execute(
            text("INSERT INTO enrol_challenges VALUES (:c, :k, 8, :e)"),
            {"c": b"c" * 32, "k": b"k" * 32, "e": now - timedelta(minutes=1)},
        )
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, state, confirmed_day, first_day, last_day) VALUES ('t_000000000001','ip','203.0.113.201','confirmed',:d,:d,:d)"
            ),
            {"d": TODAY},
        )
        await s.execute(
            text("INSERT INTO takedown_votes VALUES ('t_000000000001', :n, :d, 'down')"),
            {"n": n, "d": TODAY - timedelta(days=31)},
        )
        await s.execute(
            text(
                "INSERT INTO recheck_assignments (target_id, node_id, day) VALUES ('t_000000000001', :n, :d)"
            ),
            {"n": n, "d": TODAY - timedelta(days=4)},
        )
        await s.execute(
            text("INSERT INTO node_stats_weekly VALUES (:n, :w, 3, 2)"),
            {"n": n, "w": TODAY - timedelta(days=120)},
        )
        await s.commit()
    async with env.worker() as s:
        await retention.run_retention(s, env.settings, now, TODAY)
    assert await count(env, "nonces") == 1
    assert await count(env, "enrol_challenges") == 0
    assert await count(env, "takedown_votes") == 0
    assert await count(env, "recheck_assignments") == 0


async def test_contributor_links_go_when_resolved_or_after_thirty_days(env: Env) -> None:
    (n,) = await add_nodes(env.worker, 1)
    async with env.worker() as s:
        for tid, state, day, upd in (
            ("t_000000000001", "taken_down", TODAY, env.clock() - timedelta(days=3)),
            ("t_000000000002", "taken_down", TODAY, env.clock()),  # resolved today: kept 2 days
            ("t_000000000003", "confirmed", TODAY - timedelta(days=31), env.clock()),
            ("t_000000000004", "confirmed", TODAY, env.clock()),
        ):
            await s.execute(
                text(
                    "INSERT INTO targets (id, kind, value, state, confirmed_day, first_day, last_day, updated_at) VALUES (:i,'ip',:v,:s,:d,:d,:d,:u)"
                ),
                {"i": tid, "v": f"203.0.113.{tid[-1]}", "s": state, "d": day, "u": upd},
            )
            await s.execute(
                text("INSERT INTO target_contributors VALUES (:i, :n)"), {"i": tid, "n": n}
            )
        await s.commit()
        await retention.run_retention(s, env.settings, env.clock(), TODAY)
        left = set((await s.execute(text("SELECT target_id FROM target_contributors"))).scalars())
    assert left == {"t_000000000002", "t_000000000004"}


async def test_inactive_nodes_are_deleted_with_their_data(env: Env) -> None:
    keep, gone = await add_nodes(env.worker, 2)
    async with env.worker() as s:
        await s.execute(
            text("UPDATE nodes SET last_active_day = :d WHERE id = :i"),
            {"d": TODAY - timedelta(days=31), "i": gone},
        )
        await s.commit()
    await observe(env.worker, [gone, keep], "ip", "203.0.113.201", [TODAY - timedelta(days=1)])
    async with env.worker() as s:
        res = await retention.run_retention(s, env.settings, env.clock(), TODAY)
    assert res.deleted["inactive_nodes"] == 1
    assert await count(env, "nodes") == 1 and await count(env, "observations") == 1
    assert await count(env, "batches", f"node_id = '{gone}'") == 0


async def test_every_node_table_cascades() -> None:
    node_fk = [t.name for t in Base.metadata.tables.values() if "node_id" in t.c]
    assert {
        "nonces",
        "batches",
        "observations",
        "target_contributors",
        "takedown_votes",
        "node_stats_weekly",
    } <= set(node_fk)


# --- statistics and summary ---


async def test_summary_k_rules_and_no_ranking(env: Env) -> None:
    ch = await add_nodes(env.worker, 3, countries=["CH"] * 3, show_country=True)
    await add_nodes(env.worker, 2, countries=["DE", "DE"], show_country=True)  # only two: hidden
    await add_nodes(env.worker, 1, countries=["FR"], show_country=False)
    await observe(env.worker, ch[:1], "ip", "203.0.113.201", [TODAY - timedelta(days=8)])
    async with env.worker() as s:
        summary = await stats.run_daily(s, TODAY)
    assert summary.totals.members == 6 and summary.totals.countries == 1
    assert [(c.cc, c.members) for c in summary.countries] == [("CH", 3)]
    assert {m.country for m in summary.members} == {"CH", None}
    assert sum(1 for m in summary.members if m.country == "CH") == 3
    assert all(0 <= m.tier <= 4 and 0 <= m.active_days <= 7 for m in summary.members)
    raw = json.dumps(summary.model_dump(mode="json"))
    for n in ch:
        assert str(n) not in raw  # node ids never appear
    # stored once, read back by the API model
    async with env.worker() as s:
        data = (await s.execute(text("SELECT data FROM network_summary"))).scalar_one()
    assert data["totals"]["members"] == 6


async def test_summary_member_order_changes_daily_and_ignores_activity(env: Env) -> None:
    await add_nodes(env.worker, 8)
    async with env.worker() as s:
        a = [m.fingerprint for m in (await stats.build_summary(s, TODAY)).members]
        b = [
            m.fingerprint for m in (await stats.build_summary(s, TODAY + timedelta(days=1))).members
        ]
    assert sorted(a) == sorted(b) and a != b


async def test_weekly_tier_follows_consensus_not_what_a_node_sent(env: Env) -> None:
    flooder, helper = await add_nodes(env.worker, 2, active_days=7)
    week = stats.last_full_week(TODAY)
    assert week.weekday() == 0 and TODAY - week < timedelta(days=14)
    async with env.worker() as s:
        # one node floods 20,000 unique values that nobody else saw
        await s.execute(
            text(
                "INSERT INTO observations (node_id, day, kind, value) SELECT :n, :d, 'url', "
                "md5(g::text) || md5(g::text) FROM generate_series(1, 20000) g"
            ),
            {"n": flooder, "d": week},
        )
        # the other contributed to 150 values that reached consensus that week
        for i in range(150):
            tid = f"t_{i:012x}"
            await s.execute(
                text(
                    "INSERT INTO targets (id, kind, value, state, confirmed_day, first_day, last_day) VALUES (:i, 'ip', :v, 'confirmed', :d, :d, :d)"
                ),
                {"i": tid, "v": f"2001:db8::{i:x}", "d": week},
            )
            await s.execute(
                text("INSERT INTO target_contributors VALUES (:i, :n)"), {"i": tid, "n": helper}
            )
        await s.commit()
        assert await stats.weekly_stats(s, TODAY) == 2
        rows: dict[Any, Any] = dict(
            (await s.execute(text("SELECT node_id, tier FROM node_stats_weekly"))).all()
        )
    assert rows[flooder] == 0  # flooding moved nothing
    assert rows[helper] in (2, 3)  # about 150, with jitter


def test_tier_jitter_is_stable_and_bounded() -> None:
    week = stats.last_full_week(TODAY)
    values = {stats.noisy(1000, week, f"node{i}") for i in range(50)}
    assert min(values) >= 750 and max(values) <= 1250 and len(values) > 10
    assert stats.noisy(1000, week, "node1") == stats.noisy(1000, week, "node1")


# --- worker cycle and admin ---


async def test_worker_cycle_end_to_end_idempotent(env: Env) -> None:
    nodes = await add_nodes(env.worker, 5)
    await observe(
        env.worker,
        nodes,
        "sha256",
        "ab" * 32,
        [TODAY - timedelta(days=2), TODAY - timedelta(days=1)],
    )
    ctx = WorkerContext(settings=env.settings, sessionmaker=env.worker, clock=env.clock)
    first = await run_cycle(ctx)
    assert first.failed == [] and first.steps["consensus"]["confirmed"] == 1  # type: ignore[index]
    assert await healthy(ctx)
    async with env.worker() as s:
        seq1 = (await s.execute(text("SELECT seq FROM targets"))).scalar_one()
    second = await run_cycle(ctx)
    assert second.failed == [] and second.steps["stats"] == "done_today"
    async with env.worker() as s:
        seq2 = (await s.execute(text("SELECT seq FROM targets"))).scalar_one()
        seeded = (await s.execute(text("SELECT count(*) FROM never_list"))).scalar_one()
    assert seq1 == seq2  # a quiet hour does not make nodes re-download targets
    assert seeded > 10
    env.clock.advance(hours=7)
    assert not await healthy(ctx)


async def test_a_failing_step_does_not_stop_the_others(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hub import consensus

    async def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("203.0.113.9 secret")

    monkeypatch.setattr(consensus, "run_consensus", boom)
    out = await run_cycle(
        WorkerContext(settings=env.settings, sessionmaker=env.worker, clock=env.clock)
    )
    assert out.failed == ["consensus"] and "retention" in out.steps and "heartbeat" in out.steps


class Capture:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)


async def test_admin_cli(env: Env, tmp_path: Any) -> None:
    out = Capture()
    await add_nodes(env.worker, 1)
    async with env.worker() as s:
        fp = (
            await s.execute(text("SELECT substr(encode(sha256(pubkey), 'hex'), 1, 8) FROM nodes"))
        ).scalar_one()
        await s.execute(
            text(
                "INSERT INTO reports (recipient, kind, target_ids, state, body_text, created_day) VALUES ('a@example.net','c2',ARRAY['t_x'],'queued','Subject: s\n\nbody',:d)"
            ),
            {"d": TODAY},
        )
        await s.commit()

    async def cli(*argv: str) -> int:
        return await admin.run(list(argv), sessionmaker=env.worker, out=out, actor="tester")

    assert (
        await cli("reports", "list", "--state", "queued") == 0 and "a@example.net" in out.lines[-1]
    )
    assert await cli("reports", "show", "1") == 0
    assert await cli("reports", "approve", "1") == 0
    assert await cli("reports", "approve", "1") == 1  # no longer queued
    assert await cli("reports", "cancel", "1") == 0
    assert await cli("reports", "show", "99") == 1
    assert await cli("never", "add", "Evil.Example.ORG", "--note", "test") == 0
    assert await cli("never", "add", "203.0.113.0/24") == 0
    assert await cli("never", "list") == 0 and any("evil.example.org" in line for line in out.lines)
    assert (
        await cli("never", "remove", "203.0.113.0/24") == 0
        and await cli("never", "remove", "nope") == 1
    )
    assert await cli("node", "suspend", fp) == 0
    assert await count(env, "nodes", "standing = 'soft_suspended'") == 1
    assert await cli("node", "unsuspend", fp) == 0 and await cli("node", "suspend", "00000000") == 1
    assert await cli("stats") == 0
    async with env.worker() as s:
        audit = (
            await s.execute(text("SELECT actor, action, detail FROM hub_audit ORDER BY id"))
        ).all()
    actions = [a.action for a in audit]
    assert "report.approve" in actions and "node.suspend" in actions and "never.add" in actions
    assert {a.actor for a in audit} == {"tester"}
    assert fp not in json.dumps([a.detail for a in audit])  # no node identifier in the audit


async def test_admin_dispute_and_keys(env: Env, tmp_path: Any) -> None:
    out = Capture()
    nodes = await add_nodes(env.worker, 2)
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, state, confirmed_day, first_day, last_day) VALUES ('t_000000000001','ip','203.0.113.201','confirmed',:d,:d,:d)"
            ),
            {"d": TODAY},
        )
        for n in nodes:
            await s.execute(
                text("INSERT INTO target_contributors VALUES ('t_000000000001', :n)"), {"n": n}
            )
        await s.commit()
    assert (
        await admin.run(
            ["target", "dispute", "t_000000000001", "--note", "desk says wrong"],
            sessionmaker=env.worker,
            out=out,
        )
        == 0
    )
    assert out.lines[-1].startswith("disputed") and "2 contributors" in out.lines[-1]
    key = tmp_path / "hub.key"
    assert admin.gen_signing_key(str(key), False, out) == 0
    first = out.lines[-1]
    assert oct(key.stat().st_mode & 0o777) == "0o400"
    assert admin.gen_signing_key(str(key), False, out) == 1  # no silent overwrite
    assert await admin.run(["show-public-key", "--key-file", str(key)], out=out) == 0
    assert out.lines[-1] == first
    assert admin.gen_signing_key(str(key), True, out) == 0 and out.lines[-1] != first
