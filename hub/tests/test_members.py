"""Member life cycle: dormant, expired, coming back (hub/hub/dormant.py, 2026-11-26 report).

Dormant members are left out of every count and are never eligible for consensus; expired
members are deleted like a leave; the history they contributed is never rewritten.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Any

import pytest
from sqlalchemy import text

from hub import admin, consensus, dormant, observatory, retention, stats
from hub.config import ConfigError, Settings

from .conftest import Env
from .helpers import START
from .seed import TODAY, add_nodes, observe

D = timedelta(days=1)

# --- settings and rules (no database) ---------------------------------------------------------


def test_member_settings_default_to_thirty_days() -> None:
    s = Settings.from_env({})
    assert s.member_dormant_days == 30 and s.member_expire_days == 30
    s = Settings.from_env({"HUB_MEMBER_DORMANT_DAYS": "14", "HUB_MEMBER_EXPIRE_DAYS": "7"})
    assert s.member_dormant_days == 14 and s.member_expire_days == 7


@pytest.mark.parametrize(
    ("name", "value"),
    [
        # Below 14 a node could be dormant while still eligible for consensus (7 of 14 days).
        ("HUB_MEMBER_DORMANT_DAYS", "13"),
        ("HUB_MEMBER_DORMANT_DAYS", "91"),
        # Beyond 30 days the hub would keep silent nodes longer than M29 H3 promises.
        ("HUB_MEMBER_EXPIRE_DAYS", "31"),
        ("HUB_MEMBER_EXPIRE_DAYS", "90"),
        ("HUB_MEMBER_EXPIRE_DAYS", "6"),
    ],
)
def test_member_settings_out_of_range_are_refused(name: str, value: str) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env({name: value})


def test_the_dormant_threshold_follows_the_setting() -> None:
    ref = dormant.count_ref(TODAY)
    last = ref - 20 * D
    assert not dormant.is_dormant(TODAY - 90 * D, last, TODAY)  # 30 days by default
    assert dormant.is_dormant(TODAY - 90 * D, last, TODAY, dormant_days=14)
    assert dormant.expire_cutoff(TODAY) == TODAY - 30 * D
    assert dormant.expire_cutoff(TODAY, 7) == TODAY - 7 * D


# --- dormant --------------------------------------------------------------------------------------


async def _set(env: Env, node_id: uuid.UUID, **values: object) -> None:
    sets = ", ".join(f"{k} = :{k}" for k in values)
    async with env.worker() as s:
        await s.execute(text(f"UPDATE nodes SET {sets} WHERE id = :i"), {**values, "i": node_id})
        await s.commit()


@pytest.mark.integration
async def test_a_shorter_dormant_setting_drops_silent_members_from_every_count(
    env_factory: Any,
) -> None:
    env: Env = await env_factory(member_dormant_days=14)
    await add_nodes(env.worker, 3, countries=["CH"] * 3, show_country=True)
    (silent,) = await add_nodes(
        env.worker, 1, active_days=0, countries=["CH"], show_country=True, enrolled=[TODAY - 90 * D]
    )
    # 20 days before the reference Monday: counted with 30 days, dormant with 14.
    await _set(env, silent, last_batch_day=dormant.count_ref(TODAY) - 20 * D)
    async with env.worker() as s:
        summary = await stats.run_daily(s, TODAY, env.settings.member_dormant_days)
        inp = await observatory.load(s, env.settings, TODAY)
        rows = {r.counted for r in await dormant.members(s, TODAY, dormant_days=14)}
    assert summary.totals.members == 3 and len(summary.members) == 3
    assert inp.members == 3 and inp.country_members == {"CH": 3}
    assert rows == {True, False}


@pytest.mark.integration
async def test_a_dormant_member_is_never_eligible_for_consensus(env: Env) -> None:
    (active,) = await add_nodes(env.worker, 1)
    (gone,) = await add_nodes(env.worker, 1, active_days=0, enrolled=[TODAY - 90 * D])
    # Dormant: its last batch is more than 30 days before the week's reference Monday.
    await _set(env, gone, last_batch_day=dormant.count_ref(TODAY) - 31 * D)
    async with env.worker() as s:
        eligible = await consensus.eligible_nodes(s, env.settings, TODAY)
        rows = {r.last_batch_day: r.counted for r in await dormant.members(s, TODAY)}
    assert set(eligible) == {active}
    assert rows[dormant.count_ref(TODAY) - 31 * D] is False


@pytest.mark.integration
async def test_a_dormant_member_comes_back_without_a_new_enrolment(env: Env) -> None:
    (node,) = await env.enrolled()
    node_id = uuid.UUID(node.node_id or "")
    await _set(
        env, node_id, enrolled_day=TODAY - 90 * D, last_batch_day=TODAY - 40 * D,
        last_active_day=TODAY - 20 * D,
    )  # fmt: skip
    async with env.worker() as s:
        assert (await stats.build_summary(s, TODAY)).totals.members == 0
        await retention.run_retention(s, env.settings, env.clock(), TODAY)
    back = await node.call("GET", "/v1/node")
    assert back.status == 200 and back.signature_ok
    assert back.json["node_id"] == str(node_id)  # the same membership, no proof of work
    async with env.worker() as s:
        day = (
            await s.execute(text("SELECT last_active_day FROM nodes WHERE id = :i"), {"i": node_id})
        ).scalar_one()
    assert day == START.date()


# --- expired --------------------------------------------------------------------------------------


async def _history(env: Env) -> tuple[list[Any], list[Any], list[Any]]:
    async with env.worker() as s:
        frozen = list(
            (await s.execute(text("SELECT * FROM observatory_daily ORDER BY 1, 2, 3"))).all()
        )
        daily = list((await s.execute(text("SELECT * FROM network_daily ORDER BY day"))).all())
        targets = list(
            (
                await s.execute(
                    text("SELECT id, state, node_count, confirmed_day FROM targets ORDER BY id")
                )
            ).all()
        )
    return frozen, daily, targets


@pytest.mark.integration
async def test_expiry_deletes_the_member_and_leaves_the_history_alone(env: Env) -> None:
    ids = await add_nodes(env.worker, 3)
    day = TODAY - 6 * D  # final: frozen by the observatory
    await observe(env.worker, ids, "ip", "192.0.2.50", [day])
    async with env.worker() as s:
        assert await observatory.freeze_days(s, env.settings, TODAY) > 0
        await stats.run_daily(s, TODAY)
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, state, node_count, confirmed_day, "
                "first_day, last_day, updated_at) VALUES ('t_000000000101', 'ip', '192.0.2.50', "
                "'confirmed', 3, :d, :d, :d, now())"
            ),
            {"d": day},
        )
        await s.commit()
    before = await _history(env)
    assert before[0] and before[1] and before[2]
    await _set(env, ids[2], last_active_day=TODAY - 31 * D)
    async with env.worker() as s:
        res = await retention.run_retention(s, env.settings, env.clock(), TODAY)
        assert await observatory.freeze_days(s, env.settings, TODAY) == 0
        left = (await s.execute(text("SELECT count(*) FROM nodes"))).scalar_one()
        obs = (
            await s.execute(
                text("SELECT count(*) FROM observations WHERE node_id = :n"), {"n": ids[2]}
            )
        ).scalar_one()
    assert res.deleted["inactive_nodes"] == 1 and left == 2 and obs == 0
    assert await _history(env) == before  # frozen days, daily rows and targets unchanged


@pytest.mark.integration
async def test_the_expiry_setting_is_used(env_factory: Any) -> None:
    env: Env = await env_factory(member_expire_days=7)
    keep, gone = await add_nodes(env.worker, 2)
    await _set(env, keep, last_active_day=TODAY - 7 * D)
    await _set(env, gone, last_active_day=TODAY - 8 * D)
    async with env.worker() as s:
        res = await retention.run_retention(s, env.settings, env.clock(), TODAY)
        left = list((await s.execute(text("SELECT id FROM nodes"))).scalars())
    assert res.deleted["inactive_nodes"] == 1 and left == [keep]


@pytest.mark.integration
async def test_an_expired_member_is_told_unknown_node_and_can_enrol_again(env: Env) -> None:
    (node,) = await env.enrolled(pseudonym="amber-falcon-42")
    old_id = node.node_id
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET last_active_day = :d"), {"d": TODAY - 31 * D})
        await s.commit()
        await retention.run_retention(s, env.settings, env.clock(), TODAY)
    gone = await node.call("GET", "/v1/node")
    assert gone.status == 401 and gone.error == "unknown_node" and gone.signature_ok
    again = await node.enrol(pseudonym="amber-falcon-42")  # same key, same name, new proof of work
    assert again.status == 200, again.json
    assert again.json["node_id"] != old_id


# --- admin ----------------------------------------------------------------------------------------


class Cli:
    def __init__(self, env: Env, answer: str = "") -> None:
        self.env, self.answer = env, answer
        self.lines: list[str] = []
        self.asked: list[str] = []

    def _ask(self, prompt: str) -> str:
        self.asked.append(prompt)
        return self.answer

    async def __call__(self, *argv: str) -> int:
        self.lines.clear()
        return await admin.run(
            list(argv),
            sessionmaker=self.env.worker,
            out=self.lines.append,
            actor="op",
            settings=self.env.settings,
            ask=self._ask,
        )


async def _fp(env: Env, node: uuid.UUID) -> str:
    async with env.worker() as s:
        return str(
            (
                await s.execute(
                    text(
                        "SELECT substr(encode(sha256(pubkey), 'hex'), 1, 8) FROM nodes "
                        "WHERE id = :n"
                    ),
                    {"n": node},
                )
            ).scalar_one()
        )


@pytest.fixture
def frozen_today(monkeypatch: pytest.MonkeyPatch) -> date:
    monkeypatch.setattr(admin, "utcnow", lambda: START)
    return START.date()


@pytest.mark.integration
async def test_node_list_shows_last_contact_and_state(env: Env, frozen_today: date) -> None:
    (active,) = await add_nodes(env.worker, 1)
    (gone,) = await add_nodes(env.worker, 1, active_days=0, enrolled=[TODAY - 90 * D])
    await _set(env, gone, last_active_day=TODAY - 25 * D, last_batch_day=TODAY - 40 * D)
    await _set(env, active, pseudonym="night\x1bowl")
    cli = Cli(env)
    assert await cli("node", "list") == 0
    fp_active, fp_gone = await _fp(env, active), await _fp(env, gone)
    lines = {line.split("\t")[0]: line.split("\t") for line in cli.lines[1:-1]}
    assert lines[fp_gone][3:] == [
        str(TODAY - 25 * D), str(TODAY - 40 * D), "dormant", str(TODAY + 5 * D),
    ]  # fmt: skip
    assert lines[fp_active][1] == "night?owl" and lines[fp_active][5] == "active"
    assert cli.lines[-1] == "2 node(s), 1 dormant"
    assert await cli("node", "list", "--inactive", "20") == 0
    assert [line.split("\t")[0] for line in cli.lines[1:-1]] == [fp_gone]


@pytest.mark.integration
async def test_node_expire_asks_then_deletes_like_a_leave(env: Env, frozen_today: date) -> None:
    keep, gone = await add_nodes(env.worker, 2)
    await observe(env.worker, [gone], "ip", "192.0.2.70", [TODAY - D])
    fp = await _fp(env, gone)
    no = Cli(env, answer="yes")
    assert await no("node", "expire", fp.upper()) == 1
    assert no.asked == ["type 'expire 1' to confirm: "]
    assert "nothing expired" in no.lines[-1]
    yes = Cli(env, answer="expire 1")
    assert await yes("node", "expire", fp) == 0 and yes.lines[-1] == "expired 1 node(s)"
    async with env.worker() as s:
        left = list((await s.execute(text("SELECT id FROM nodes"))).scalars())
        obs = (await s.execute(text("SELECT count(*) FROM observations"))).scalar_one()
        audit = list(
            (
                await s.execute(
                    text("SELECT detail::text FROM hub_audit WHERE action = 'node.expire'")
                )
            ).scalars()
        )
    assert left == [keep] and obs == 0 and audit == ['{"nodes": 1}']
    cli = Cli(env)
    assert await cli("node", "expire", fp, "--yes") == 1  # gone already
    assert await cli("node", "expire", await _fp(env, keep), "--yes") == 0 and cli.asked == []
