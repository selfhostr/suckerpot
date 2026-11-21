"""Trap pack format: the strict validator, the limits and the bundle loader (M37)."""

from __future__ import annotations

import copy
import json
from datetime import date, timedelta
from typing import Any, cast

import pytest

from suckerpot_common import traps
from suckerpot_common.traps import PackError

TODAY = date(2026, 11, 20)


def example() -> dict[str, Any]:
    """The design's example pack (fictional product and CVE), adjusted to the 2-byte minimum."""
    return {
        "schema": "suckerpot-trap/1",
        "id": "acme-edgegate-cve-2026-55501",
        "version": 1,
        "engine": 1,
        "sensor": "web",
        "title": "Acme EdgeGate pre-auth command injection",
        "cve": ["CVE-2026-55501"],
        "disclosed": "2026-11-18",
        "product": {"vendor": "Acme", "name": "EdgeGate"},
        "group": "vpn-appliance",
        "presence": 0.5,
        "tag": "acme-edgegate-rce",
        "attack": ["T1190"],
        "traps": [
            {
                "id": "version-probe",
                "level": "probe",
                "match": {"method": ["GET", "HEAD"], "path": {"exact": "/api/v1/version"}},
                "outcome": {"flags": ["edgegate_probe"]},
                "respond": {
                    "kind": "php",
                    "status": 200,
                    "content_type": "application/json",
                    "variants": [
                        '{"product":"EdgeGate","version":"7.2.{rand_int:1-4}","build":"{rand_hex:8}"}',
                        '{"product":"EdgeGate","version":"7.1.{rand_int:6-9}","build":"{rand_hex:8}"}',
                    ],
                },
            },
            {
                "id": "diag-rce",
                "level": "exploit",
                "match": {
                    "method": ["POST"],
                    "path": {"exact": "/api/v1/diag/ping"},
                    "needles": [
                        {"in": "body", "any": ["host="]},
                        {"in": "body", "any": [";w", ";c", "|s", "$(", "`w"]},
                    ],
                },
                "outcome": {"flags": ["edgegate_rce"]},
                "respond": {
                    "kind": "php",
                    "status": 200,
                    "content_type": "application/json",
                    "variants": [
                        '{"status":"ok","target":"{echo:query:host}","rtt_ms":{rand_int:9-40}}'
                    ],
                },
            },
        ],
    }


def reason(obj: object, **kw: Any) -> str:
    with pytest.raises(PackError) as err:
        traps.validate_pack(obj, **kw)
    return err.value.reason


def bundle(packs: list[dict[str, Any]], **extra: Any) -> bytes:
    return json.dumps({"schema": "suckerpot-traps/1", "seq": 3, "packs": packs, **extra}).encode()


# -- the format --------------------------------------------------------------------------------


def test_example_pack_is_valid_and_compiled() -> None:
    p = traps.validate_pack(example())
    assert p.id == "acme-edgegate-cve-2026-55501" and p.disclosed == date(2026, 11, 18)
    probe, rce = p.traps
    assert probe.path == traps.PathCond("exact", b"/api/v1/version")
    assert probe.claim_cve is False and rce.claim_cve is True and p.claims
    assert rce.needles[1].any == (b";w", b";c", b"|s", b"$(", b"`w")
    assert probe.respond is not None
    first = probe.respond.variants[0]
    assert traps.Slot("rand_int", lo=1, hi=4) in first and traps.Slot("rand_hex", n=8) in first
    assert '{"product":"EdgeGate","version":"7.2.' in first  # JSON braces stay literal text
    assert p.size == len(traps.canonical(example())) and 0 < p.cost < traps.MAX_COMPILED


def test_needles_are_lowercased_unless_exact_and_hex_is_raw() -> None:
    obj = example()
    obj["traps"][1]["match"]["needles"] = [{"in": "blob", "any": ["HOST=", "hex:00ff41"]}]
    t = traps.validate_pack(obj).traps[1]
    assert t.needles[0].any == (b"host=", b"\x00\xffa")
    obj["traps"][1]["match"]["case"] = "exact"
    t = traps.validate_pack(obj).traps[1]
    assert t.needles[0].any == (b"HOST=", b"\x00\xffA") and t.exact_case


@pytest.mark.parametrize(
    ("path", "value", "want"),
    [
        ([], "x", "schema"),  # not a mapping
        (["schema"], "suckerpot-trap/2", "schema"),
        (["id"], "Acme", "schema"),
        (["id"], "-acme", "schema"),
        (["id"], "ab", "schema"),
        (["version"], 0, "schema"),
        (["version"], True, "schema"),
        (["engine"], 2, "engine_too_new"),
        (["sensor"], "banner", "schema"),
        (["title"], "", "limits"),
        (["title"], "x" * 121, "limits"),
        (["cve"], ["CVE-26-1"], "schema"),
        (["cve"], ["CVE-2026-55501", "CVE-2026-55501"], "schema"),
        (["cve"], [f"CVE-2026-{1000 + i}" for i in range(9)], "limits"),
        (["disclosed"], "18/11/2026", "schema"),
        (["product", "vendor"], "", "limits"),
        (["presence"], 0.01, "schema"),
        (["presence"], "1", "schema"),
        (["tag"], "a_b", "schema"),
        (["attack"], ["T19"], "schema"),
        (["traps"], [], "limits"),
        (["traps", 0, "level"], "maybe", "schema"),
        (["traps", 0, "match"], {}, "schema"),  # a trap needs a condition
        (["traps", 0, "match", "method"], ["GET", "TRACE"], "schema"),
        (["traps", 0, "match", "path"], {"exact": "/a", "prefix": "/b"}, "schema"),
        (["traps", 0, "match", "path"], {"regex": "/a.*"}, "schema"),
        (["traps", 0, "match", "path"], {"exact": "api"}, "schema"),
        (["traps", 0, "match", "path"], {"contains": "x" * 257}, "limits"),
        (["traps", 0, "match", "query_keys"], [f"k{i}" for i in range(9)], "limits"),
        (["traps", 0, "match", "header_names"], ["x y"], "schema"),
        (["traps", 0, "match", "case"], "smart", "schema"),
        (["traps", 0, "outcome", "flags"], ["Bad-Flag"], "schema"),
        (["traps", 0, "outcome", "flags"], ["rce"], "schema"),  # a built-in flag
        (
            ["traps", 0, "outcome", "flags"],
            ["a_flag", "b_flag", "c_flag", "d_flag", "e_flag"],
            "limits",
        ),
        (["traps", 0, "outcome", "claim_cve"], False, "schema"),  # forbidden on a probe
        (["traps", 1, "outcome", "claim_cve"], "yes", "schema"),
        (["traps", 1, "id"], "version-probe", "schema"),  # duplicate trap id
        (["traps", 0, "unknown"], 1, "schema"),
        (["extra"], 1, "schema"),
    ],
)
def test_schema_errors(path: list[Any], value: Any, want: str) -> None:
    obj: Any = example()
    if not path:
        obj = value
    else:
        target = obj
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    assert reason(obj) == want


def test_needle_bounds() -> None:
    def with_needles(any_: list[str], n_cond: int = 1) -> dict[str, Any]:
        obj = example()
        obj["traps"][1]["match"]["needles"] = [{"in": "body", "any": any_}] * n_cond
        return obj

    assert reason(with_needles([";"])) == "limits"  # 1 byte
    assert reason(with_needles(["x" * 257])) == "limits"
    assert reason(with_needles(["hex:0"])) == "limits"
    assert reason(with_needles(["hex:" + "00" * 257])) == "limits"
    assert reason(with_needles(["hex:zz00"])) == "schema"
    assert reason(with_needles(["café"])) == "schema"
    assert reason(with_needles([f"n{i:02d}" for i in range(17)])) == "limits"
    assert reason(with_needles(["host="], n_cond=7)) == "limits"
    traps.validate_pack(with_needles([f"n{i:02d}" for i in range(16)], n_cond=6))
    obj = with_needles(["host="])
    obj["traps"][1]["match"]["needles"][0]["in"] = "cookie"
    assert reason(obj) == "schema"


def test_traps_per_pack_and_pack_size() -> None:
    obj = example()
    base = obj["traps"][0]
    obj["traps"] = [{**copy.deepcopy(base), "id": f"t{i}"} for i in range(17)]
    assert reason(obj) == "limits"
    obj["traps"] = obj["traps"][:16]
    traps.validate_pack(obj)
    big = example()
    big["traps"][0]["respond"]["variants"] = ["x" * 16000] * 4
    big["traps"][1]["respond"]["variants"] = ["y" * 16000] * 4
    assert reason(big) == "limits"  # over 64 KiB of canonical JSON


# -- evidence rule -----------------------------------------------------------------------------


def test_evidence_rule() -> None:
    obj = example()
    rce = obj["traps"][1]
    # The path is the evidence here (17 bytes, not served by the site).
    traps.validate_pack(obj)
    rce["match"]["path"] = {"exact": "/index.php"}
    assert reason(obj) == "evidence"  # a page the site serves, short needles only
    rce["match"]["needles"][0]["any"] = ["&host=192"]
    traps.validate_pack(obj)  # a 6+ byte needle outside the path
    rce["match"] = {"path": {"contains": "/api/v1/diag/ping"}}
    assert reason(obj) == "evidence"  # contains/suffix paths never count
    rce["match"] = {"path": {"exact": "/wp-admin/admin-ajax.php"}}
    assert reason(obj) == "evidence"
    rce["match"] = {"needles": [{"in": "path", "any": ["/api/v1/diag/ping"]}]}
    assert reason(obj) == "evidence"  # path needles are not specific evidence
    rce["outcome"]["claim_cve"] = False
    traps.validate_pack(obj)  # observe only: no evidence needed
    rce["outcome"]["claim_cve"] = True
    obj["cve"] = []
    traps.validate_pack(obj)  # nothing to claim


def test_get_slash_can_never_be_an_exploit() -> None:
    obj = example()
    obj["traps"][1]["match"] = {"method": ["GET"], "path": {"exact": "/"}}
    assert reason(obj) == "evidence"


# -- content rules -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        '<a href="http://malware.example.net/x">x</a>',
        "<img src='https://198.51.100.1/a.png'>",
        '<a href="//malware.example.net/x">x</a>',
        "<SCRIPT>alert(1)</SCRIPT>",
        "<iframe src=/x></iframe>",
        "<object data=/x></object>",
        "<embed src=/x>",
        '<a href="javascript:alert(1)">x</a>',
        "Powered by SuckerPot",
        "a HoneyPot page",
        "selfhostr",
        '<form action="ftp:x">',
        "<form action=elsewhere.example.net/post>",
        "<form action='//elsewhere.example.net/post'>",
        "<{echo:query:tag}>",  # the echo would become a tag name
        "htt{echo:query:s}://x",  # echo next to letters
        "{echo:query:a}{echo:query:b}",
        "{rand_hex:65}",
        "{rand_hex:0}",
        "{rand_int:9-1}",
        "{rand_int:0-2000000000}",
        "{echo:query:a b}",
        "{echo:query:}",
        "{echo:cookie:x}",
        # Security review of PR 159 (M1): each of these was accepted before.
        "<svg onload=alert(1)>",
        '<img src=x onerror="fetch(location)">',
        '<a href="&#104;ttps://evil.example/x">',
        '<img src="&#47;&#47;evil.example/x.png">',
        "<img src= //evil.example/x.png>",
        '<meta http-equiv=refresh content="0; url= //evil.example/">',
        "url( //evil.example/a)",
        'srcset=" //evil.example/a 1x"',
        # Variants of the same holes.
        '<img/onerror="x">',
        "<div onclick =x>",
        '<p ONMOUSEOVER="x">',
        "<a href='&#x2f;&#x2f;evil.example'>",
        "<a href=&sol;&sol;evil.example>",
        '<a href="/\\evil.example/">',
        '<a href="\t//evil.example/">',
        '<img src="/a.png" srcset="/a.png 1x, //evil.example/b.png 2x">',
        '<a href="ht\ntps://evil.example/">',
        '<a href="data:text/html,x">',
        "<link rel=stylesheet href=/a.css>",
        "<style>body{}</style>",
        # Re-review N1: {base_url} followed by anything but a path, query or fragment.
        '<a href="{base_url}@evil.example/">x</a>',
        '<img src="{base_url}.evil.example/x.png">',
        "<a href={base_url}:8080/>x</a>",
        "<math><mi>x</mi></math>",
        "@import '/a.css';",
        '<div style="width:expression(1)">',
    ],
)
def test_content_rules(body: str) -> None:
    obj = example()
    obj["traps"][0]["respond"]["variants"] = [body]
    assert reason(obj) == "content"


@pytest.mark.parametrize(
    "body",
    [
        '<form method="post" action="/login.cgi"><input name=u></form>',
        '<form action="{base_url}/login.cgi">',
        '<a href="/login.php?a=1&amp;b=2">Log in &gt;</a>',
        '<img src="/logo.png" alt="Acme" width="120">',
        '{"session":"x","button":"on","version":"7.2","json_on":1}',
        "<p>Monitoring is on = yes</p>",
        "<p>{site_title} on {hostname} ({server_ip}), {server_token} PHP {php_version}</p>",
        "{date_http} {year} {install_date}",
        '{"echo":"{echo:query:id}"}',
        "<td>{echo:query:id}</td>",
        "a{color:red}",  # braces that are no placeholder stay text
    ],
)
def test_content_allowed(body: str) -> None:
    obj = example()
    obj["traps"][0]["respond"]["variants"] = [body]
    traps.validate_pack(obj)


def test_response_fields() -> None:
    def respond(**kw: Any) -> dict[str, Any]:
        obj = example()
        obj["traps"][0]["respond"].update(kw)
        return obj

    assert reason(respond(kind="cgi")) == "schema"
    assert reason(respond(status=418)) == "schema"
    assert reason(respond(status=True)) == "schema"
    assert reason(respond(content_type="application/x-msdownload")) == "schema"
    assert reason(respond(headers=[["Content-Disposition", "attachment"]])) == "schema"
    assert reason(respond(headers=[["Location", "https://elsewhere.example.net/"]])) == "content"
    assert reason(respond(headers=[["Location", "//elsewhere.example.net/"]])) == "content"
    assert reason(respond(headers=[["Set-Cookie", "a=\r\nX: y"]])) == "schema"
    assert reason(respond(headers=[["Set-Cookie", "id={echo:query:id}"]])) == "content"
    assert reason(respond(headers=[["Pragma", "a"], ["Pragma", "b"]])) == "schema"
    assert reason(respond(headers=[["Pragma", "no-cache"]] * 7)) == "limits"
    assert reason(respond(variants=[])) == "limits"
    assert reason(respond(variants=["a"] * 5)) == "limits"
    assert reason(respond(variants=["x" * (traps.MAX_BODY + 1)])) == "limits"
    assert reason(respond(variants=["{echo:query:a}" * 300])) in ("limits", "content")
    traps.validate_pack(
        respond(
            status=302,
            headers=[
                ["Location", "{base_url}/login"],
                ["Set-Cookie", "sid={rand_hex:16}; path=/"],
                ["Set-Cookie", "lang=en; path=/"],
                ["Cache-Control", "no-store"],
            ],
        )
    )
    traps.validate_pack(respond(status=301, headers=[["Location", "/login"]]))


# -- bundles and limits ------------------------------------------------------------------------


def pack(
    pid: str, *, disclosed: str = "2026-11-01", traps_n: int = 1, unpathed: int = 0
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for i in range(traps_n):
        match: dict[str, Any]
        if i < unpathed:
            match = {"needles": [{"in": "path", "any": [f"{pid}-{i}-n"]}]}
        else:
            match = {"path": {"exact": f"/{pid}/{i}"}}
        items.append(
            {"id": f"t{i}", "level": "probe", "match": match, "outcome": {"flags": ["x_probe"]}}
        )
    return {
        "schema": "suckerpot-trap/1",
        "id": pid,
        "version": 1,
        "engine": 1,
        "sensor": "web",
        "title": pid,
        "cve": [],
        "disclosed": disclosed,
        "product": {"vendor": "V", "name": "N"},
        "tag": pid,
        "traps": items,
    }


def test_invalid_pack_is_rejected_alone() -> None:
    bad = pack("bad-pack")
    bad["traps"][0]["outcome"]["flags"] = ["rce"]
    newer = pack("good-one")
    newer["engine"] = 9
    res = traps.load_bundle(
        bundle([pack("aaa-pack"), bad, newer, cast(Any, "not a pack"), pack("zzz-pack")]),
        today=TODAY,
    )
    assert [p.id for p in res.packs] == ["aaa-pack", "zzz-pack"]
    assert res.rejected == [("bad-pack", "schema"), ("good-one", "engine_too_new"), ("?", "schema")]
    assert res.seq == 3


def test_bundle_file_errors_reject_everything() -> None:
    with pytest.raises(PackError) as err:
        traps.load_bundle(b"x" * (traps.MAX_BUNDLE_BYTES + 1), today=TODAY)
    assert err.value.reason == "limits"
    for data in (
        b"{",
        b"[]",
        b"[" * 100 + b"]" * 100,
        json.dumps({"schema": "x", "seq": 1, "packs": []}).encode(),
        json.dumps({"schema": "suckerpot-traps/1", "seq": -1, "packs": []}).encode(),
        json.dumps({"schema": "suckerpot-traps/1", "seq": 1, "packs": [], "more": 1}).encode(),
        bundle([pack(f"p{i:03d}") for i in range(traps.MAX_BUNDLE_ENTRIES + 1)]),
    ):
        with pytest.raises(PackError) as err:
            traps.load_bundle(data, today=TODAY)
        assert err.value.reason in ("schema", "limits")


def test_depth_scan_ignores_brackets_in_strings() -> None:
    assert traps.json_depth_ok(b'{"a": "[[[[[[[[[[[[[[[[[[[[[[[[[\\"[[[["}')
    assert not traps.json_depth_ok(b'{"a":' + b"[" * 16 + b"]" * 16 + b"}")


def test_higher_version_wins_and_disabled_packs_are_skipped() -> None:
    v2 = pack("same-pack")
    v2["version"] = 2
    v2["title"] = "second"
    res = traps.load_bundle(
        bundle([pack("same-pack"), v2, pack("off-pack"), pack("kill-pack")],
               disabled=[{"id": "kill-pack", "reason": "flags benign traffic"}]),
        today=TODAY,
        disabled=frozenset({"off-pack"}),
    )  # fmt: skip
    assert [(p.id, p.title) for p in res.packs] == [("same-pack", "second")]


def test_other_sensors_packs_are_ignored() -> None:
    other = pack("banner-pack")
    other["sensor"] = "banner"
    res = traps.load_bundle(bundle([other, pack("web-pack")]), today=TODAY)
    assert [p.id for p in res.packs] == ["web-pack"] and res.rejected == []


def test_pack_count_limit_and_room_for_new_packs() -> None:
    old = [pack(f"old-{i:03d}", disclosed="2020-01-01") for i in range(80)]
    new = [pack(f"new-{i:03d}") for i in range(10)]
    res = traps.load_bundle(bundle(old + new), today=TODAY)
    ids = [p.id for p in res.packs]
    # Old packs may fill three quarters of the limit; every new pack still loads.
    assert sum(i.startswith("new-") for i in ids) == 10
    assert sum(i.startswith("old-") for i in ids) == traps.MAX_PACKS * 3 // 4
    assert len(ids) <= traps.MAX_PACKS
    assert all(r == "over_limit" for _, r in res.rejected) and len(res.rejected) == 80 - 48
    # Newest first: the old packs that do not fit are the last ones by disclosure, then id.
    res = traps.load_bundle(bundle([pack(f"new-{i:03d}") for i in range(70)]), today=TODAY)
    assert len(res.packs) == traps.MAX_PACKS and len(res.rejected) == 6


def test_trap_and_unpathed_limits() -> None:
    packs = [pack(f"p{i:03d}", traps_n=16) for i in range(40)]  # 640 traps
    res = traps.load_bundle(bundle(packs), today=TODAY)
    assert sum(len(p.traps) for p in res.packs) == traps.MAX_TRAPS
    packs = [pack(f"u{i:03d}", traps_n=4, unpathed=4) for i in range(10)]  # 40 unpathed
    res = traps.load_bundle(bundle(packs), today=TODAY)
    assert sum(len(p.traps) for p in res.packs) == traps.MAX_UNPATHED
    # Distinct needles of unpathed traps are capped too.
    many = pack("needly", traps_n=1, unpathed=1)
    many["traps"][0]["match"]["needles"] = [
        {"in": "query", "any": [f"n{c}-{i:02d}" for i in range(16)]} for c in range(4)
    ]
    second = copy.deepcopy(many)
    second["id"] = "needly-two"
    for c in second["traps"][0]["match"]["needles"]:
        c["any"] = [n + "x" for n in c["any"]]
    res = traps.load_bundle(bundle([many, second]), today=TODAY)
    assert [p.id for p in res.packs] == ["needly"] and res.rejected == [
        ("needly-two", "over_limit")
    ]


def test_compiled_memory_cap() -> None:
    def heavy(pid: str) -> dict[str, Any]:
        obj = pack(pid, traps_n=16)
        for i, t in enumerate(obj["traps"]):
            t["match"]["needles"] = [
                {"in": "body", "any": [f"{pid}{i}{c}{n:02d}".ljust(30, "x") for n in range(16)]}
                for c in range(6)
            ]
        return obj

    packs = [traps.validate_pack(heavy(f"h{i:02d}")) for i in range(40)]
    assert all(p.size <= traps.MAX_PACK_BYTES for p in packs)
    kept, dropped = traps.select(packs, TODAY)
    assert dropped and sum(p.cost for p in kept) <= traps.MAX_COMPILED
    assert sum(p.cost for p in kept) + packs[0].cost > traps.MAX_COMPILED


def test_reserved_quarter_applies_to_every_limit() -> None:
    old = [pack(f"o{i:02d}", disclosed="2019-05-05", traps_n=16) for i in range(32)]
    kept, _ = traps.select([traps.validate_pack(p) for p in old], TODAY)
    assert sum(len(p.traps) for p in kept) == traps.MAX_TRAPS * 3 // 4
    recent_day = (TODAY - timedelta(days=traps.RECENT_DAYS)).isoformat()
    recent = [pack(f"r{i:02d}", disclosed=recent_day, traps_n=16) for i in range(32)]
    kept, _ = traps.select([traps.validate_pack(p) for p in recent], TODAY)
    assert sum(len(p.traps) for p in kept) == traps.MAX_TRAPS


def test_conflicting_responders_are_reported() -> None:
    a = example()
    b = example()
    b["id"] = "other-edgegate"
    assert traps.find_conflicts([traps.validate_pack(a), traps.validate_pack(b)])
    b["traps"][0]["match"]["path"] = {"exact": "/api/v2/version"}
    b["traps"][1]["match"]["path"] = {"exact": "/api/v2/diag/ping"}
    assert traps.find_conflicts([traps.validate_pack(a), traps.validate_pack(b)]) == []


def test_build_bundle_is_canonical_and_loads() -> None:
    data = traps.build_bundle([pack("b-pack"), pack("a-pack")])
    assert data == traps.build_bundle([pack("a-pack"), pack("b-pack")])
    doc = json.loads(data)
    assert [p["id"] for p in doc["packs"]] == ["a-pack", "b-pack"] and doc["seq"] == 0
    assert [p.id for p in traps.load_bundle(data, today=TODAY).packs] == ["a-pack", "b-pack"]


def test_safe_id_for_logs() -> None:
    assert traps.safe_id({"id": "ok-id"}) == "ok-id"
    assert traps.safe_id({"id": "\x1b[31mevil\nline"}) == "31mevilline"
    assert traps.safe_id({"id": 5}) == "?" and traps.safe_id("x") == "?"


def test_reserved_paths() -> None:
    for p in ("/", "/index.php", "/wp-admin/admin-ajax.php", "/wp-json/wp/v2/users", "/pma/"):
        assert traps.is_reserved_path(p)
    for p in ("/api/v1/version", "/cgi-bin/luci", "/vendor/phpunit/"):
        assert not traps.is_reserved_path(p)


# -- security review of PR 159 -----------------------------------------------------------------


def _claiming(match: dict[str, Any]) -> dict[str, Any]:
    obj = example()
    obj["traps"][1]["match"] = match
    return obj


def test_owned_flags_only_in_their_pack() -> None:
    """M3: flags that ingest rules give a meaning belong to one bundled pack."""
    for flag, owner in traps.PACK_OWNED_FLAGS:
        obj = example()
        obj["traps"][0]["outcome"]["flags"] = [flag]
        assert reason(obj) == "schema", flag
        obj["id"] = owner
        traps.validate_pack(obj)


def test_evidence_must_be_specific() -> None:
    """L1: the accepted examples of the review are refused now."""
    assert reason(_claiming({"needles": [{"in": "blob", "any": ["/wp-login.php"]}]})) == "evidence"
    assert reason(_claiming({"needles": [{"in": "headers", "any": ["mozilla"]}]})) == "evidence"
    # A weak sibling needle makes the whole condition weak (any one needle may match).
    weak = {"needles": [{"in": "body", "any": ["host=192.0.2", ";"]}]}
    assert reason(_claiming(weak)) == "limits"  # 1 byte is below the needle minimum anyway
    weak = {"needles": [{"in": "body", "any": ["&host=192.0.2", "id"]}]}
    assert reason(_claiming(weak)) == "evidence"
    # The needle must not be the path itself.
    same = {
        "path": {"prefix": "/a"},
        "needles": [{"in": "query", "any": ["&next=/api/v1/diag/ping"]}],
    }
    traps.validate_pack(_claiming(same))  # the query is not the path
    inside = {
        "path": {"contains": "/x/api/v1/diag/ping"},
        "needles": [{"in": "query", "any": ["diag/ping"]}],
    }
    assert reason(_claiming(inside)) == "evidence"
    # Header evidence names its header.
    named = {"needles": [{"in": "headers", "any": ["\nx-edge-token: ${jndi"]}]}
    traps.validate_pack(_claiming(named))
    short = {"needles": [{"in": "headers", "any": ["\nx-edge-token: ab"]}]}
    assert reason(_claiming(short)) == "evidence"
    traps.validate_pack(_claiming({"needles": [{"in": "body", "any": ["&host=192.0.2"]}]}))


def test_loose_paths_need_four_bytes() -> None:
    """L2: contains and suffix paths are not a few bytes that every request has."""
    obj = example()
    obj["traps"][0]["match"]["path"] = {"contains": "/a/"}
    assert reason(obj) == "limits"
    obj["traps"][0]["match"]["path"] = {"suffix": ".cgi"}
    traps.validate_pack(obj)


def test_answer_on_reserved_path_needs_specific_condition() -> None:
    """M2: a trap that answers on a built-in page needs query keys or a specific needle."""
    obj = example()
    probe = obj["traps"][0]
    probe["match"] = {"path": {"exact": "/wp-login.php"}}
    assert reason(obj) == "schema"
    probe["match"] = {
        "path": {"exact": "/wp-login.php"},
        "needles": [{"in": "path", "any": ["/wp-login.php"]}],
    }
    assert reason(obj) == "schema"
    probe["match"] = {
        "path": {"exact": "/wp-login.php"},
        "needles": [{"in": "headers", "any": [": "]}],
    }
    assert reason(obj) == "schema"
    probe["match"] = {
        "path": {"prefix": "/wp-admin/"},
        "needles": [{"in": "blob", "any": ["action=edge"]}],
    }
    assert reason(obj) == "schema"
    probe["match"] = {"path": {"exact": "/wp-login.php"}, "query_keys": ["edge"]}
    traps.validate_pack(obj)
    probe["match"] = {
        "path": {"exact": "/wp-login.php"},
        "needles": [{"in": "query", "any": ["&action=edge"]}],
    }
    traps.validate_pack(obj)
    t = traps.validate_pack(obj).traps[0]
    assert traps.may_answer_on_reserved_path(t)
    unpathed = traps.validate_pack(
        _claiming({"needles": [{"in": "headers", "any": ["\nx-a: ${jndi"]}]})
    )
    assert traps.may_answer_on_reserved_path(unpathed.traps[1])


def test_status_and_body_and_location_agree() -> None:
    """L3: 204 has an empty body; a redirect has a Location; Location only with redirects."""

    def respond(**kw: Any) -> dict[str, Any]:
        obj = example()
        obj["traps"][0]["respond"].update(kw)
        return obj

    assert reason(respond(status=204, variants=["x"])) == "schema"
    traps.validate_pack(respond(status=204, variants=[""]))
    assert reason(respond(status=301)) == "schema"
    assert reason(respond(status=302, headers=[["Cache-Control", "no-store"]])) == "schema"
    traps.validate_pack(respond(status=302, headers=[["Location", "/login"]]))
    assert reason(respond(status=200, headers=[["Location", "/login"]])) == "schema"


def test_base_url_cannot_name_another_host() -> None:
    """Re-review N1: {base_url} only ends a value or starts a path, query or fragment."""

    def location(value: str) -> dict[str, Any]:
        obj = example()
        obj["traps"][0]["respond"].update(status=302, headers=[["Location", value]])
        return obj

    assert reason(location("{base_url}@evil.example/")) == "content"
    assert reason(location("{base_url}.evil.example/")) == "content"
    for ok in ("{base_url}", "{base_url}/login", "{base_url}?a=1", "{base_url}#top"):
        traps.validate_pack(location(ok))
    obj = example()
    obj["traps"][0]["respond"]["variants"] = ['<a href="{base_url}/x">home</a> "{base_url}"']
    traps.validate_pack(obj)


@pytest.mark.parametrize(
    "needle",
    [
        "user-agent: mozilla/5.0",
        "connection: keep-alive",
        "accept-language: en-us,en",
        "accept: text/html,application",
        "sec-fetch-mode: navigate",
        "cookie: wordpress_logged_in",
        "content-type: application/json",
        "if-none-match: abcdef",
        "host: 192.0.2.10",
    ],
)
def test_common_header_needles_are_never_specific(needle: str) -> None:
    """Re-review M2(a) and L5: needles on headers every client sends are neither evidence nor
    enough to answer on a page the site serves."""
    needle = "\n" + needle  # explicitly anchored, so only the denylist can refuse it
    assert reason(_claiming({"needles": [{"in": "headers", "any": [needle]}]})) == "evidence"
    obj = example()
    obj["traps"][0]["match"] = {
        "path": {"exact": "/wp-login.php"},
        "needles": [{"in": "headers", "any": [needle]}],
    }
    assert reason(obj) == "schema"


@pytest.mark.parametrize(
    "needle",
    [
        "utm_source=newsletter",
        "?utm_campaign",
        "fbclid=abcdef",
        "gclid=123456",
        "page=2",
        "&s=hello",
    ],
)
def test_tracking_and_common_query_needles_are_not_evidence(needle: str) -> None:
    """Re-review L5."""
    for area in ("query", "body"):
        assert reason(_claiming({"needles": [{"in": area, "any": [needle]}]})) == "evidence"
        anchored = "&" + needle.lstrip("?&")
        assert reason(_claiming({"needles": [{"in": area, "any": [anchored]}]})) == "evidence"


@pytest.mark.parametrize(
    "needle",
    ["&page=123456", "&page=../../../etc", "&id=1234567", "&s=searchterm", "&cmd=wget&page=1",
     "&offset=100000", "&q=longer-query", "?ver=6.8.1-abc"],
)  # fmt: skip
def test_common_param_values_are_never_evidence(needle: str) -> None:
    """P1 security review (b): the value of a common parameter is never evidence, however long
    it is ("&page=123456" is a page number)."""
    for area in ("query", "body"):
        assert reason(_claiming({"needles": [{"in": area, "any": [needle]}]})) == "evidence"


def test_specific_query_needles_still_count() -> None:
    traps.validate_pack(_claiming({"needles": [{"in": "query", "any": ["&file=../../../etc"]}]}))
    traps.validate_pack(_claiming({"needles": [{"in": "query", "any": ["&cmd=wget "]}]}))
    traps.validate_pack(
        _claiming({"needles": [{"in": "headers", "any": ["\nx-api-version: ${jndi"]}]})
    )


# -- third review --------------------------------------------------------------------------------


def _unpathed_pack(pid: str, area: str, count: int) -> dict[str, Any]:
    obj = pack(pid, traps_n=count, unpathed=count)
    for i, t in enumerate(obj["traps"]):
        t["match"] = {"needles": [{"in": area, "any": [f"{pid}-needle-{i}"]}]}
    return obj


def test_unpathed_traps_fit_the_scan_budget_at_load() -> None:
    """B1: the worst-case bytes searched by all unpathed needles fit MAX_SCAN_BYTES, so those
    traps can never run out of search budget at run time."""
    cap = traps.AREA_CAPS["headers"]
    fits = traps.MAX_SCAN_BYTES // cap
    assert fits < traps.MAX_UNPATHED_NEEDLES  # the byte bound is the tighter one for headers
    res = traps.load_bundle(
        bundle([_unpathed_pack("hdr-a", "headers", fits), _unpathed_pack("hdr-b", "headers", 1)]),
        today=TODAY,
    )
    assert [p.id for p in res.packs] == ["hdr-a"] and res.rejected == [("hdr-b", "over_limit")]
    kept, _ = traps.select(
        [traps.validate_pack(o) for o in [_unpathed_pack("q-a", "query", 16)]], TODAY
    )
    assert traps.scan_bound(traps._needle_keys(kept[0].traps)) <= traps.MAX_SCAN_BYTES


def test_core_packs_have_their_own_capped_scan() -> None:
    """B1: the packs that own reserved flags run outside the run-time budget; the loader caps what
    they may search instead."""
    big = _unpathed_pack("log4j-log4shell", "headers", 16)
    for t in big["traps"]:
        t["outcome"]["flags"] = ["log4shell"]
    res = traps.load_bundle(bundle([big]), today=TODAY)
    assert res.packs == [] and res.rejected == [("log4j-log4shell", "over_limit")]
    small = _unpathed_pack("log4j-log4shell", "headers", 4)
    res = traps.load_bundle(bundle([small]), today=TODAY)
    assert [p.id for p in res.packs] == ["log4j-log4shell"]


@pytest.mark.parametrize(
    "needle",
    [
        "log=admin123",
        "pwd=hunter22",
        "1&pwd=hunter2",
        "wp-submit=Log+In",
        "redirect_to=/wp-admin/",
        "testcookie=1",
        "rememberme=forever",
        "a=b&log=admin123",
    ],
)
def test_login_form_needles_are_not_evidence(needle: str) -> None:
    """F2: the WordPress login form keys never count, also inside a longer needle."""
    for area in ("query", "body"):
        assert reason(_claiming({"needles": [{"in": area, "any": [needle]}]})) == "evidence"
        anchored = "&" + needle.lstrip("&")
        assert reason(_claiming({"needles": [{"in": area, "any": [anchored]}]})) == "evidence"


# -- fourth review: explicit anchors -----------------------------------------------------------


def _claim_needle(area: str, needle: str) -> dict[str, Any]:
    return _claiming({"needles": [{"in": area, "any": [needle]}]})


def test_needles_are_compiled_exactly_as_written() -> None:
    """L-a: no implicit anchoring; the engine searches the bytes the author wrote."""
    cases = [
        ("query", "allow_url_include=1"),
        ("body", "&allow_url_include=1"),
        ("headers", "-agent: mozilla/5.0"),
        ("headers", "\nx-api: ${jndi"),
    ]
    for area, needle in cases:
        obj = _claim_needle(area, needle)
        obj["traps"][1]["outcome"]["claim_cve"] = False
        t = traps.validate_pack(obj).traps[1]
        assert t.needles[0].any == (needle.lower().encode(),)


def test_only_explicitly_anchored_needles_are_strong() -> None:
    """L-a: an unanchored "name: value" or "key=value" needle is searched raw and is weak."""
    assert reason(_claim_needle("headers", "-agent: mozilla/5.0")) == "evidence"
    assert reason(_claim_needle("headers", "x-api-version: ${jndi")) == "evidence"
    assert reason(_claim_needle("headers", "\nuser-agent: mozilla/5.0")) == "evidence"  # denied
    traps.validate_pack(_claim_needle("headers", "\nx-api-version: ${jndi"))
    assert reason(_claim_needle("query", "allow_url_include=1")) == "evidence"
    traps.validate_pack(_claim_needle("query", "&allow_url_include=1"))


@pytest.mark.parametrize(
    "needle", ["admin&pw", "=admin&wp-subm", "&=admin1", "&cmd=", "&a b=cdefg"]
)
def test_param_evidence_needs_a_full_anchored_key_value(needle: str) -> None:
    """L-b: strong query and body evidence is a whole "&key=value" on a key that is not denied."""
    for area in ("query", "body"):
        assert reason(_claim_needle(area, needle)) == "evidence"


@pytest.mark.parametrize("area", ["query", "body", "path", "blob"])
def test_percent_escapes_are_refused_in_decoded_areas(area: str) -> None:
    """L-c: those areas are percent-decoded before matching, so "%2e" could never match."""
    obj = _claim_needle(area, "&file=%2e%2e/etc")
    with pytest.raises(PackError) as err:
        traps.validate_pack(obj)
    assert err.value.reason == "schema" and "percent-decoded" in err.value.detail
    obj["traps"][1]["match"]["needles"][0]["any"] = ["hex:" + b"%2e%2e/etc".hex()]
    assert reason(obj) == "schema"
    obj["traps"][1]["match"]["needles"][0]["any"] = ["100% sure"]  # a lone % is fine
    obj["traps"][1]["outcome"]["claim_cve"] = False
    traps.validate_pack(obj)


@pytest.mark.parametrize("op", ["exact", "prefix", "suffix", "contains"])
@pytest.mark.parametrize("value", ["/api/v1/%2e%2e/diag", "/cgi-bin/%2F/x.cgi", "/a/b%41c/d/e"])
def test_percent_escapes_are_refused_in_paths(op: str, value: str) -> None:
    """P1 security review (a): match.path is matched on the percent-decoded path, like the
    needles of decoded areas, so "%xx" in it could never match."""
    obj = example()
    obj["traps"][0]["match"]["path"] = {op: value}
    with pytest.raises(PackError) as err:
        traps.validate_pack(obj)
    assert err.value.reason == "schema" and "percent-decoded" in err.value.detail
    obj["traps"][0]["match"]["path"] = {op: "/api/v1/100%-sure"}  # a lone % is fine
    traps.validate_pack(obj)


def test_newline_anchor_only_in_headers() -> None:
    assert reason(_claim_needle("query", "\n&cmd=x")) == "schema"
    traps.validate_pack(_claim_needle("headers", "\nx-forwarded-host: evil.example"))


# -- several bundles (M37 P2: bundled packs plus the downloaded bundle) --------------------------


def _doc(packs: list[dict[str, Any]], seq: int, **extra: Any) -> dict[str, Any]:
    return traps.parse_bundle(
        json.dumps({"schema": "suckerpot-traps/1", "seq": seq, "packs": packs, **extra}).encode()
    )


def test_downloaded_kill_list_turns_off_a_bundled_pack() -> None:
    bundled = _doc([pack("core-pack"), pack("kept-pack")], 0)
    downloaded = _doc(
        [pack("new-pack")], 9, disabled=[{"id": "core-pack", "reason": "flags benign traffic"}]
    )
    res = traps.load_docs([bundled, downloaded], today=TODAY)
    assert [p.id for p in res.packs] == ["kept-pack", "new-pack"]
    assert res.disabled == ["core-pack"] and res.seq == 9


def test_local_disabled_set_applies_to_every_bundle() -> None:
    res = traps.load_docs(
        [_doc([pack("core-pack")], 0), _doc([pack("new-pack")], 4)],
        today=TODAY,
        disabled=frozenset({"core-pack", "new-pack"}),
    )
    assert res.packs == [] and sorted(res.disabled) == ["core-pack", "new-pack"]


def test_higher_version_wins_across_bundles() -> None:
    v3 = pack("same-pack")
    v3["version"], v3["title"] = 3, "downloaded"
    v5 = pack("same-pack")
    v5["version"], v5["title"] = 5, "bundled"
    res = traps.load_docs([_doc([v5], 0), _doc([v3], 7)], today=TODAY)
    assert [(p.id, p.title) for p in res.packs] == [("same-pack", "bundled")]
    res = traps.load_docs([_doc([v3], 0), _doc([v5], 7)], today=TODAY)
    assert [(p.id, p.title) for p in res.packs] == [("same-pack", "bundled")]


def test_bad_pack_in_a_downloaded_bundle_does_not_stop_the_others() -> None:
    bad = pack("bad-pack")
    bad["traps"][0]["outcome"]["flags"] = ["rce"]
    res = traps.load_docs(
        [_doc([pack("core-pack")], 0), _doc([bad, pack("good-pack")], 2)], today=TODAY
    )
    assert [p.id for p in res.packs] == ["core-pack", "good-pack"]
    assert res.rejected == [("bad-pack", "schema")]


def test_distributed_bundle_fields() -> None:
    data = traps.build_bundle(
        [pack("a-pack")],
        seq=1_790_000_000,
        disabled=[{"id": "z-pack", "reason": "r"}, {"id": "b-pack", "reason": "r"}],
        issued_at="2026-11-21T10:00:00Z",
    )
    doc = traps.parse_bundle(data)
    assert [d["id"] for d in doc["disabled"]] == ["b-pack", "z-pack"]
    assert doc["issued_at"] == "2026-11-21T10:00:00Z" and doc["seq"] == 1_790_000_000
    traps.parse_bundle(
        json.dumps(
            {"schema": "suckerpot-traps/1", "seq": 1, "packs": [], "bundled_seq_min": 0}
        ).encode()
    )
    with pytest.raises(PackError):
        traps.parse_bundle(
            json.dumps(
                {"schema": "suckerpot-traps/1", "seq": 1, "packs": [], "bundled_seq_min": "1"}
            ).encode()
        )
