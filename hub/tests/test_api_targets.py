from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from sqlalchemy import text
from suckerpot_netproto import blind

from .conftest import Env
from .helpers import NodeClient

pytestmark = pytest.mark.integration
URL = "http://198.51.100.9/bins/x.sh"
URL_B = blind.blind_url(URL)
DOMAIN = "cnc.example.org"
DOMAIN_B = blind.blind_domain(DOMAIN)


async def seed(env: Env, **fields: Any) -> str:
    row = {
        "id": "t_"
        + hashlib.sha256(json.dumps(fields, sort_keys=True, default=str).encode()).hexdigest()[:12],
        "kind": "ip",
        "value": None,
        "value_b": None,
        "state": "confirmed",
        "node_count": 7,
        "country_count": 4,
        "first_day": "2026-10-26",
        "last_day": "2026-10-30",
        "services": ["ssh"],
        "activity": ["login", "command"],
        "tags": ["mirai"],
        "families": [],
        **fields,
    }
    cols = ", ".join(row)
    params = ", ".join(f":{k}" for k in row)
    async with env.worker() as s:
        await s.execute(
            text(f"INSERT INTO targets ({cols}) VALUES ({params})"),
            {**row, "first_day": _d(row["first_day"]), "last_day": _d(row["last_day"])},
        )
        await s.commit()
    return str(row["id"])


def _d(value: str) -> Any:
    from datetime import date

    return date.fromisoformat(value)


async def _node(env: Env) -> NodeClient:
    (node,) = await env.enrolled(pseudonym="snoop owl", country="CH", show_country=True)
    return node


async def test_pull_excludes_candidates_and_has_buckets_only(env: Env) -> None:
    node = await _node(env)
    await seed(env, value="192.0.2.4", node_count=7, country_count=4)
    await seed(
        env,
        value="198.51.100.130",
        node_count=12,
        country_count=2,
        state="reported",
        reported_day=_d("2026-10-31"),
    )
    await seed(env, value="192.0.2.1", state="candidate")
    reply = await node.call("GET", "/v1/targets")
    assert reply.status == 200 and reply.signature_ok
    targets = {t["value"]: t for t in reply.json["targets"]}
    assert set(targets) == {"192.0.2.4", "198.51.100.130"}
    assert (targets["192.0.2.4"]["nodes"], targets["192.0.2.4"]["countries"]) == (0, 4)
    assert (targets["198.51.100.130"]["nodes"], targets["198.51.100.130"]["countries"]) == (1, None)
    assert targets["198.51.100.130"]["reported_day"] == "2026-10-31"
    assert reply.json["cursor"].startswith("c_")
    # no per-node data anywhere in the view (H5)
    me = (await node.call("GET", "/v1/node")).json
    for secret in (me["node_id"], node.fingerprint, "snoop owl", node.key):
        assert secret not in reply.raw.decode()


async def test_cursor_pagination(env: Env) -> None:
    node = await _node(env)
    for i in range(1, 6):
        await seed(env, value=f"192.0.2.{i + 40}")
    seen: list[str] = []
    cursor = ""
    for _ in range(10):
        path = f"/v1/targets?since={cursor}&limit=2" if cursor else "/v1/targets?limit=2"
        page = (await node.call("GET", path)).json
        if not page["targets"]:
            assert page["cursor"] == cursor
            break
        assert len(page["targets"]) <= 2
        seen += [t["value"] for t in page["targets"]]
        cursor = page["cursor"]
    assert sorted(seen) == [f"192.0.2.{i + 40}" for i in range(1, 6)]
    # an update moves the target past the cursor
    async with env.worker() as s:
        await s.execute(
            text(
                "UPDATE targets SET state = 'taken_down', taken_down_day = '2026-11-01' WHERE value = '192.0.2.41'"
            )
        )
        await s.commit()
    changed = (await node.call("GET", f"/v1/targets?since={cursor}")).json["targets"]
    assert [(t["value"], t["state"]) for t in changed] == [("192.0.2.41", "taken_down")]


@pytest.mark.parametrize(
    "query", ["limit=0", "limit=1001", "limit=x", "since=x", "since=c_-1", "since=c_1;drop"]
)
async def test_pull_parameter_validation(env: Env, query: str) -> None:
    node = await _node(env)
    reply = await node.call("GET", f"/v1/targets?{query}")
    assert (reply.status, reply.error) == (400, "invalid_payload")


async def test_reveal_flow(env: Env) -> None:
    node = await _node(env)
    await seed(env, kind="url", value_b=URL_B, tags=["malware-drop"])
    await seed(env, kind="c2_domain", value_b=DOMAIN_B)
    await seed(
        env, kind="url", value_b=blind.blind_url("http://198.51.100.10/y"), state="candidate"
    )
    pull = (await node.call("GET", "/v1/targets")).json
    assert {(r["kind"], r["value_b"]) for r in pull["reveal"]} == {
        ("url", URL_B),
        ("domain", DOMAIN_B),
    }
    assert all(t["value"] is None and t["value_b"] for t in pull["targets"])

    wrong = {"kind": "url", "value_b": URL_B, "value": "http://198.51.100.9/other"}
    good_url = {"kind": "url", "value_b": URL_B, "value": "HTTP://198.51.100.9:80/bins/x.sh#frag"}
    good_domain = {"kind": "domain", "value_b": DOMAIN_B, "value": "CNC.example.org."}
    unknown = {"kind": "domain", "value_b": "11" * 32, "value": "x.example.org"}
    reply = await node.call(
        "POST",
        "/v1/reveals",
        {"protocol": "spn/1", "items": [wrong, good_url, good_domain, unknown]},
    )
    assert reply.status == 200 and reply.json == {"accepted": 2, "rejected": 2}
    async with env.worker() as s:
        values: dict[str, str] = dict(
            (await s.execute(text("SELECT kind, value FROM targets WHERE value IS NOT NULL"))).all()
        )
    assert values == {"url": URL.replace("198.51.100.9", "198.51.100.9"), "c2_domain": DOMAIN}
    pull = (await node.call("GET", "/v1/targets")).json
    assert pull["reveal"] == []
    # a revealed value is final: another value that hashes elsewhere cannot overwrite it
    again = await node.call("POST", "/v1/reveals", {"protocol": "spn/1", "items": [good_url]})
    assert again.json == {"accepted": 0, "rejected": 1}


async def test_reveal_refuses_never_listed_and_private_hosts(env: Env) -> None:
    node = await _node(env)
    bad_url = "http://cdn.example.net/x.sh"
    await seed(env, kind="url", value_b=blind.blind_url(bad_url))
    await seed(env, kind="domain", value_b=blind.blind_domain("localhost"))
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO never_list VALUES ('example.net', 'domain', 'large cdn')")
        )
        await s.commit()
    items = [
        {"kind": "url", "value_b": blind.blind_url(bad_url), "value": bad_url},
        {"kind": "domain", "value_b": blind.blind_domain("localhost"), "value": "localhost"},
    ]
    reply = await node.call("POST", "/v1/reveals", {"protocol": "spn/1", "items": items})
    assert reply.json == {"accepted": 0, "rejected": 2}


async def test_reveal_daily_cap(env_factory: Any) -> None:
    env: Env = await env_factory(reveals_per_day=3)
    node = await _node(env)
    item = {"kind": "domain", "value_b": "11" * 32, "value": "x.example.org"}
    ok = await node.call("POST", "/v1/reveals", {"protocol": "spn/1", "items": [item] * 3})
    assert ok.status == 200
    over = await node.call("POST", "/v1/reveals", {"protocol": "spn/1", "items": [item]})
    assert (over.status, over.error) == (429, "rate_limited")


async def test_recheck_listing_and_votes(env: Env) -> None:
    a = await _node(env)
    (b,) = await env.enrolled()
    t_ip = await seed(env, value="192.0.2.4", state="reported", reported_day=_d("2026-10-31"))
    await seed(env, kind="sha256", value="ab" * 32)
    await seed(env, kind="url", value_b=URL_B)  # blinded and unrevealed: nothing to check yet
    pull = (await a.call("GET", "/v1/targets")).json
    assert [r["id"] for r in pull["recheck"]] == [t_ip]
    assert pull["recheck"][0]["value"] == "192.0.2.4"

    await b.call("GET", "/v1/targets")  # b is asked too
    vote = {
        "protocol": "spn/1",
        "day": "2026-11-01",
        "items": [{"id": t_ip, "state": "down"}, {"id": "t_ffffffffffff", "state": "up"}],
    }
    r = await a.call("POST", "/v1/rechecks", vote)
    assert r.status == 200 and r.json == {"accepted": 1}
    assert (await a.call("GET", "/v1/targets")).json["recheck"] == []  # voted today
    assert [x["id"] for x in (await b.call("GET", "/v1/targets")).json["recheck"]] == [t_ip]
    # a replay, even with another state, is dropped: one answer per assignment
    vote["items"] = [{"id": t_ip, "state": "up"}]
    assert (await a.call("POST", "/v1/rechecks", vote)).json == {"accepted": 0}
    async with env.worker() as s:
        rows = (await s.execute(text("SELECT state FROM takedown_votes"))).scalars().all()
    assert rows == ["down"]


async def _assign(env: Env, node: NodeClient, target: str, day: str) -> None:
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO recheck_assignments (target_id, node_id, day) "
                "VALUES (:t, CAST(:n AS uuid), :d)"
            ),
            {"t": target, "d": _d(day), "n": node.node_id},
        )
        await s.commit()


async def test_recheck_day_rules(env: Env) -> None:
    a = await _node(env)
    t = await seed(env, value="192.0.2.4")
    await _assign(env, a, t, "2026-10-30")
    for day, code in (("2026-11-02", "invalid_payload"), ("2026-10-29", "day_too_old")):
        r = await a.call(
            "POST",
            "/v1/rechecks",
            {"protocol": "spn/1", "day": day, "items": [{"id": t, "state": "down"}]},
        )
        assert r.error == code, day
    bad_state = await a.call(
        "POST",
        "/v1/rechecks",
        {"protocol": "spn/1", "day": "2026-11-01", "items": [{"id": t, "state": "maybe"}]},
    )
    assert bad_state.error == "invalid_payload"
    assert (
        await a.call(
            "POST",
            "/v1/rechecks",
            {"protocol": "spn/1", "day": "2026-10-30", "items": [{"id": t, "state": "down"}]},
        )
    ).status == 200


async def test_suspended_votes_are_ignored(env: Env) -> None:
    a = await _node(env)
    t = await seed(env, value="192.0.2.4")
    await a.call("GET", "/v1/targets")
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET standing = 'soft_suspended'"))
        await s.commit()
    r = await a.call(
        "POST",
        "/v1/rechecks",
        {"protocol": "spn/1", "day": "2026-11-01", "items": [{"id": t, "state": "down"}]},
    )
    assert r.json == {"accepted": 1}
    async with env.worker() as s:
        assert (await s.execute(text("SELECT count(*) FROM takedown_votes"))).scalar_one() == 0


async def test_network_summary(env: Env) -> None:
    node = await _node(env)
    empty = await node.call("GET", "/v1/network")
    assert (
        empty.status == 200 and empty.json["members"] == [] and empty.json["totals"]["members"] == 0
    )
    summary = {
        "generated_day": "2026-11-01",
        "totals": {
            "members": 3,
            "active_7d": 2,
            "countries": 1,
            "confirmed_30d": 4,
            "reported_30d": 3,
            "taken_down_30d": 1,
            "median_days_to_takedown": 4,
        },
        "weekly": [{"week": "2026-10-26", "confirmed": 4, "reported": 3, "taken_down": 1}],
        "countries": [{"cc": "CH", "members": 3}],
        "members": [
            {
                "fingerprint": node.fingerprint,
                "pseudonym": "night-owl",
                "country": "CH",
                "member_since": "2026-09",
                "active_days": 6,
                "tier": 3,
            }
        ],
    }
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO network_summary VALUES (1, '2026-11-01', CAST(:d AS jsonb))"),
            {"d": json.dumps(summary)},
        )
        await s.commit()
    assert (await node.call("GET", "/v1/network")).json == summary
    # a cached document that breaks a privacy rule (a country below 3 members) never goes out
    summary["countries"] = [{"cc": "CH", "members": 2}]
    async with env.worker() as s:
        await s.execute(
            text("UPDATE network_summary SET data = CAST(:d AS jsonb)"), {"d": json.dumps(summary)}
        )
        await s.commit()
    assert (await node.call("GET", "/v1/network")).json["members"] == []


def _vote(day: str, *ids: str, state: str = "down") -> dict[str, Any]:
    return {"protocol": "spn/1", "day": day, "items": [{"id": i, "state": state} for i in ids]}


async def _votes(env: Env) -> int:
    async with env.worker() as s:
        return int((await s.execute(text("SELECT count(*) FROM takedown_votes"))).scalar_one())


async def test_vote_without_assignment_is_ignored(env: Env) -> None:
    a = await _node(env)
    t = await seed(env, value="192.0.2.4", state="reported", reported_day=_d("2026-10-31"))
    r = await a.call("POST", "/v1/rechecks", _vote("2026-11-01", t))
    assert (r.status, r.json) == (200, {"accepted": 0})
    assert await _votes(env) == 0


async def test_assigned_vote_counts_once_and_replay_is_dropped(env: Env) -> None:
    a = await _node(env)
    t = await seed(env, value="192.0.2.4", state="reported", reported_day=_d("2026-10-31"))
    await a.call("GET", "/v1/targets")
    await a.call("GET", "/v1/targets")  # a second pull does not reopen anything
    assert (await a.call("POST", "/v1/rechecks", _vote("2026-11-01", t))).json == {"accepted": 1}
    assert (await a.call("POST", "/v1/rechecks", _vote("2026-11-01", t))).json == {"accepted": 0}
    assert (await a.call("GET", "/v1/targets")).json["recheck"] == []
    assert await _votes(env) == 1


async def test_vote_for_another_day_is_ignored(env: Env) -> None:
    a = await _node(env)
    t = await seed(env, value="192.0.2.4", state="reported", reported_day=_d("2026-10-31"))
    await a.call("GET", "/v1/targets")  # assigned for 2026-11-01 only
    for day in ("2026-10-31", "2026-10-30"):
        assert (await a.call("POST", "/v1/rechecks", _vote(day, t))).json == {"accepted": 0}
    assert await _votes(env) == 0
    assert (await a.call("POST", "/v1/rechecks", _vote("2026-11-01", t))).json == {"accepted": 1}


async def test_assignment_belongs_to_one_node(env: Env) -> None:
    a = await _node(env)
    (b,) = await env.enrolled()
    t = await seed(env, value="192.0.2.4", state="reported", reported_day=_d("2026-10-31"))
    await a.call("GET", "/v1/targets")
    assert (await b.call("POST", "/v1/rechecks", _vote("2026-11-01", t))).json == {"accepted": 0}
    assert await _votes(env) == 0


async def test_unassigned_sybil_nodes_cannot_take_a_target_down(env: Env) -> None:
    from hub import consensus

    sybils = await env.enrolled(2)
    t = await seed(env, value="192.0.2.4", state="reported", reported_day=_d("2026-10-25"))
    for _ in range(3):
        for n in sybils:
            for back in (0, 1, 2):
                day = _d("2026-11-01").fromordinal(_d("2026-11-01").toordinal() - back)
                await n.call("POST", "/v1/rechecks", _vote(day.isoformat(), t))
    assert await _votes(env) == 0
    async with env.worker() as s:
        eligible = await consensus.eligible_nodes(s, env.settings, _d("2026-11-01"))
        assert await consensus.update_takedowns(s, env.settings, _d("2026-11-01"), eligible) == (
            0,
            0,
        )


async def test_assignments_are_capped_per_node_per_day(env: Env) -> None:
    from hub.routes.targets import MAX_ASSIGNED_PER_DAY

    a = await _node(env)
    async with env.worker() as s:
        for i in range(MAX_ASSIGNED_PER_DAY + 10):
            await s.execute(
                text(
                    "INSERT INTO targets (id, kind, value, state, node_count, country_count, "
                    "first_day, last_day) VALUES (:i, 'ip', :v, 'confirmed', 7, 4, :d, :d)"
                ),
                {
                    "i": f"t_{i:012d}",
                    "v": f"198.51.{i // 250}.{i % 250 + 1}",
                    "d": _d("2026-10-30"),
                },
            )
        await s.commit()
    for _ in range(MAX_ASSIGNED_PER_DAY // 50 + 3):
        asked = (await a.call("GET", "/v1/targets")).json["recheck"]
        if asked:
            await a.call("POST", "/v1/rechecks", _vote("2026-11-01", *(x["id"] for x in asked)))
    async with env.worker() as s:
        n = (await s.execute(text("SELECT count(*) FROM recheck_assignments"))).scalar_one()
    assert n == MAX_ASSIGNED_PER_DAY
