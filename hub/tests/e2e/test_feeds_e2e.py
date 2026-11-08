"""The public feeds end to end: job, files, the real Caddyfile and the real ``minisign``.

Needs the containers of ``hub/docker-compose.test.yml`` (``feeds-caddy``, ``minisign-verify``) and
the volumes they share with the test container:

    HUB_E2E_FEEDS_DIR   the ``feeds`` volume, mounted read-write in the test container
    HUB_E2E_IO_DIR      the ``verify-io`` volume, where requests for upstream minisign are dropped
    HUB_E2E_FEEDS_URL   the feed site over plain HTTP, e.g. http://feeds-caddy:8081

Without them the tests are skipped. See ``scripts``-free recipe in docker-compose.test.yml.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from suckerpot_netproto.feeds import minisign

from hub import observatory
from hub.config import Settings
from hub.feeds import external, publish

from ..conftest import Env, make_settings
from ..seed import add_nodes, observe
from ..test_feeds_external import fake_ranges_transport
from ..test_feeds_select import NOW, SSH_FIELDS, D, confirm, run_job

pytestmark = pytest.mark.integration

FEEDS_DIR = os.environ.get("HUB_E2E_FEEDS_DIR", "")
IO_DIR = os.environ.get("HUB_E2E_IO_DIR", "")
FEEDS_URL = os.environ.get("HUB_E2E_FEEDS_URL", "")
needs_stack = pytest.mark.skipif(
    not (FEEDS_DIR and IO_DIR and FEEDS_URL),
    reason="HUB_E2E_FEEDS_DIR, HUB_E2E_IO_DIR and HUB_E2E_FEEDS_URL name the feeds test stack",
)
ATTACKER = "192.0.2.50"
HOST, C2 = "198.51.100.7", "198.51.100.8"


async def upstream(line: str, *, wait: float = 60.0) -> tuple[bool, str]:
    """Ask the real minisign (container ``minisign-verify``). Returns (ok, its output)."""
    io = Path(IO_DIR)
    ident = uuid.uuid4().hex
    tmp, req, res = io / f"{ident}.tmp", io / f"{ident}.req", io / f"{ident}.res"
    tmp.write_text(line + "\n", encoding="ascii")
    tmp.rename(req)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if res.exists():
            first, _, rest = res.read_text().partition("\n")
            res.unlink()
            return first == "ok", rest
        await asyncio.sleep(0.2)
    raise AssertionError("the minisign container did not answer: is it running?")


async def publish_scenario(env: Env, key: minisign.SecretKey, tmp_path: Path) -> Settings:
    """Seven-node style scenario: an attacker, a payload host, a C2 and a dropper domain."""
    key_file = tmp_path / "feed.key"
    key_file.write_text(minisign.serialize_secret_key(key), encoding="ascii")
    s: Settings = make_settings(
        feed_mode="auto",
        feed_dir=FEEDS_DIR,
        feed_signing_key_file=str(key_file),
        feed_breaker_min=1000,
    )
    # The real range fetcher against canned answers: also proves the exclusions are loaded.
    async with (
        httpx.AsyncClient(transport=fake_ranges_transport()) as http,
        env.worker() as ses,
    ):
        out = await external.refresh(ses, s, NOW, client=http)
    assert all(v.startswith("updated:") for v in out.values()), out
    ids = await add_nodes(env.worker, 10)
    await observe(env.worker, ids[:5], "ip", ATTACKER, D[:2], **SSH_FIELDS)
    await observe(env.worker, ids[5:], "ip", ATTACKER, D[:2], **SSH_FIELDS)
    dl: dict[str, Any] = {"families": ["mirai"], "services": [], "tags": [], "fetched": True}
    await observe(env.worker, ids[:2], "payload_ip", HOST, D[:2], activity=["download"], **dl)
    await observe(env.worker, ids[2:], "payload_ip", HOST, D[:2], activity=["download"], **dl)
    await confirm(env, s)
    await run_job(env, s)
    res = await run_job(env, s, NOW + timedelta(hours=7))
    assert res.state == "published", res
    return s


@needs_stack
async def test_feeds_through_caddy_and_upstream_minisign(env: Env, tmp_path: Path) -> None:
    key = minisign.generate_keypair()
    await publish_scenario(env, key, tmp_path)
    pub = key.public.encoded
    root = Path(FEEDS_DIR)
    index = publish.read_index(root)
    assert index is not None

    async with httpx.AsyncClient(base_url=FEEDS_URL, timeout=10, follow_redirects=False) as web:
        # Plain list: type, caching headers, no cookie, no server banner.
        r = await web.get("/v1/inbound.txt", headers={"Accept-Encoding": "identity"})
        assert r.status_code == 200
        assert r.text.split() == [ATTACKER]
        assert r.headers["content-type"] == "text/plain; charset=utf-8"
        assert r.headers["cache-control"] == "public, max-age=900"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "etag" in r.headers and "last-modified" in r.headers
        assert "set-cookie" not in r.headers and "server" not in r.headers
        assert "content-encoding" not in r.headers
        assert "access-control-allow-origin" not in r.headers

        # Conditional requests: 304, by ETag and by date.
        again = await web.get(
            "/v1/inbound.txt",
            headers={"If-None-Match": r.headers["etag"], "Accept-Encoding": "identity"},
        )
        assert again.status_code == 304 and again.content == b""
        dated = await web.get(
            "/v1/inbound.txt",
            headers={
                "If-Modified-Since": r.headers["last-modified"],
                "Accept-Encoding": "identity",
            },
        )
        assert dated.status_code == 304

        # Precompressed body only when asked for.
        gz = await web.get("/v1/outbound.txt", headers={"Accept-Encoding": "gzip"})
        assert gz.status_code == 200 and gz.headers["content-encoding"] == "gzip"
        assert gz.headers["vary"] == "Accept-Encoding"
        raw = (root / "outbound.txt.gz").read_bytes()
        assert gzip.decompress(raw) == gz.content == (root / "outbound.txt").read_bytes()
        assert HOST in gz.text.split()
        gz304 = await web.get(
            "/v1/outbound.txt",
            headers={"If-None-Match": gz.headers["etag"], "Accept-Encoding": "gzip"},
        )
        assert gz304.status_code == 304

        # Other types, CORS only where the design says so.
        sig = await web.get("/v1/index.json.minisig")
        assert sig.headers["content-type"] == "text/plain; charset=utf-8"
        idx = await web.get("/v1/index.json")
        assert idx.headers["access-control-allow-origin"] == "*"
        assert json.loads(idx.content)["serial"] == index.serial
        stats = await web.get("/v1/stats.json")
        assert stats.headers["access-control-allow-origin"] == "*"

        # The README carries the real public key; the delisting page has its pinned policy.
        readme = await web.get("/v1/README.txt")
        assert readme.status_code == 200 and readme.content == (root / "readme.txt").read_bytes()
        assert (await web.get("/v1/README.txt.minisig")).status_code == 200
        assert pub in readme.text and "@" not in readme.text.replace("@example", "")
        page = await web.get("/v1/delist.html")
        csp = page.headers["content-security-policy"]
        assert "default-src 'none'" in csp and "connect-src 'self'" in csp
        assert "content-security-policy" not in r.headers

        # Nothing but static files: other methods, dot files, query strings and the root.
        assert (await web.head("/v1/inbound.txt")).status_code == 200
        assert (await web.post("/v1/inbound.txt", content=b"x")).status_code == 405
        assert (await web.put("/v1/inbound.txt", content=b"x")).status_code == 405
        assert (await web.get("/v1/.tmp-1")).status_code == 404
        assert (await web.get("/v1/%2e%2e/etc/passwd")).status_code == 404
        assert (await web.get("/v1/")).status_code == 404
        assert (await web.get("/")).status_code == 404
        q = await web.get("/v1/inbound.txt?user=someone")
        assert q.status_code == 200 and q.text == r.text

        # What the site serves is what the real minisign verifies.
        served = {
            n: (await web.get(f"/v1/{n}", headers={"Accept-Encoding": "identity"})).content
            for n in ("index.json", "inbound.txt", "outbound.txt", "readme.txt", "delist.html")
        }
    stix = json.loads((root / "outbound.stix.json").read_bytes())
    assert stix["type"] == "bundle" and any(o["type"] == "indicator" for o in stix["objects"])
    validator = pytest.importorskip("stix2validator", reason="stix2-validator is not installed")
    result = validator.validate_file(str(root / "outbound.stix.json"))
    assert result.is_valid, [str(e) for e in result.errors]
    for name, body in served.items():
        assert body == (root / name).read_bytes()
        ok, out = await upstream(f"verify {name} {pub}")
        assert ok, out
        assert f"file:{name} serial:{index.serial}" in out  # the trusted comment was checked too
    # A wrong key, and a file changed after signing, must fail upstream as well.
    other = minisign.generate_keypair().public.encoded
    assert not (await upstream(f"verify index.json {other}"))[0]
    io = Path(IO_DIR)
    (io / "tampered.txt").write_bytes(served["inbound.txt"] + b"192.0.2.99\n")
    (io / "tampered.txt.minisig").write_bytes((root / "inbound.txt.minisig").read_bytes())
    assert not (await upstream(f"verifyio tampered.txt {pub}"))[0]


@needs_stack
async def test_the_observatory_is_served_to_one_origin() -> None:
    """network.json (design M34): CORS for the project site only, GET only, gzip sidecar."""
    root = Path(FEEDS_DIR)
    body = observatory.render_bytes(observatory.ObservatoryInput(today=NOW.date(), min_nodes=5))
    observatory.publish(root, body)
    origin = "https://suckerpot.selfhostr.io"
    async with httpx.AsyncClient(base_url=FEEDS_URL, timeout=10, follow_redirects=False) as web:
        r = await web.get("/v1/network.json", headers={"Accept-Encoding": "identity"})
        assert r.status_code == 200 and r.content == body
        assert r.headers["content-type"].startswith("application/json")
        assert r.headers["access-control-allow-origin"] == origin
        assert r.headers["access-control-allow-methods"] == "GET"
        assert "set-cookie" not in r.headers
        gz = await web.get("/v1/network.json", headers={"Accept-Encoding": "gzip"})
        assert gz.headers["content-encoding"] == "gzip" and gz.content == body
        assert gz.headers["access-control-allow-origin"] == origin
        assert (await web.post("/v1/network.json", content=b"x")).status_code == 405
        assert (await web.request("OPTIONS", "/v1/network.json")).status_code == 405
        # The wildcard stays on the feed statistics only.
        stats = await web.get("/v1/stats.json")
        assert stats.headers.get("access-control-allow-origin") in (None, "*")


@needs_stack
async def test_our_secret_key_and_signatures_interoperate_with_upstream(tmp_path: Path) -> None:
    io = Path(IO_DIR)
    name = f"k{uuid.uuid4().hex[:8]}"
    # 1. A key pair made by upstream (unencrypted, minisign -G -W): we parse and use it.
    ok, out = await upstream(f"gen {name}")
    assert ok, out
    theirs = minisign.parse_secret_key((io / f"{name}.key").read_text())
    their_pub = minisign.parse_public_key((io / f"{name}.pub").read_text().splitlines()[1])
    assert theirs.public == their_pub
    data = b"192.0.2.1\n192.0.2.2\n"
    signed = minisign.sign_feed_file(data, "inbound.txt", 7, theirs, timestamp=1_700_000_000)
    (io / "ours.txt").write_bytes(data)
    (io / "ours.txt.minisig").write_text(signed, encoding="ascii")
    ok, out = await upstream(f"verifyio ours.txt {their_pub.encoded}")
    assert ok, out
    assert "file:inbound.txt serial:7" in out
    # 2. The key file WE write is accepted by upstream, which signs with it; we verify that.
    mine = minisign.generate_keypair()
    (io / "mine.key").write_text(minisign.serialize_secret_key(mine), encoding="ascii")
    (io / "theirs.txt").write_bytes(data)
    ok, out = await upstream("sign theirs.txt mine.key")
    assert ok, out
    comment = minisign.verify(data, (io / "theirs.txt.minisig").read_text(), mine.public)
    assert comment == "timestamp:1700000000 file:theirs.txt serial:9"
    ok, out = await upstream(f"verifyio theirs.txt {mine.public.encoded}")
    assert ok, out
    # 3. Our public key file is read by upstream tools as a key: the RW... string verifies.
    assert mine.public.encoded.startswith("RW")


def test_the_feed_site_has_no_dynamic_surface_but_delisting_and_lookup() -> None:
    caddy = (Path(__file__).resolve().parents[2] / "Caddyfile").read_text()
    site = caddy[caddy.index("{$HUB_FEEDS_DOMAIN}") :]
    assert "reverse_proxy" in site and site.count("reverse_proxy") == 1
    assert "/v1/delist" in site and "/v1/lookup" in site
    assert "output discard" in site and "file_server" in site
    assert "cookie" not in site.lower()
