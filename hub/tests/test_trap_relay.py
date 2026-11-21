"""Trap pack relay (design M37 section 5): verify, refuse, copy the bytes unchanged."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from suckerpot_netproto.feeds import minisign
from suckerpot_netproto.feeds import traps as tb

from hub import trap_relay as tr
from hub.config import ConfigError, Settings

from .conftest import Env

KEY = minisign.SecretKey(bytes(range(32, 64)), bytes(range(21, 29)))
OTHER = minisign.SecretKey(bytes(range(64, 96)), bytes(range(31, 39)))
NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
BASE = "https://github.com/selfhostr/suckerpot/releases/download/trap-packs/"
CDN = "https://release-assets.githubusercontent.com/github-production-release-asset/1/"


def bundle(seq: int, note: str = "") -> bytes:
    doc = {"schema": tb.SCHEMA, "seq": seq, "packs": [], "disabled": [], "issued_at": note or "x"}
    return json.dumps(doc, sort_keys=True, indent=1).encode() + b"\n"


def signed(seq: int, key: minisign.SecretKey = KEY, note: str = "") -> tuple[bytes, bytes]:
    data = bundle(seq, note)
    return data, tb.sign_bundle(data, key).encode()


class Upstream:
    """The GitHub release: each asset answers with a redirect to the asset storage."""

    def __init__(self, data: bytes, sig: bytes) -> None:
        self.data, self.sig = data, sig
        self.requests: list[str] = []
        self.redirect_to: str | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append(url)
        if url.startswith(BASE):
            name = url[len(BASE) :]
            target = self.redirect_to or (CDN + name + "?sig=abc")
            return httpx.Response(302, headers={"location": target})
        if url.startswith(CDN):
            name = url[len(CDN) :].split("?")[0]
            body = {tb.FILE: self.data, tr.SIG: self.sig}.get(name)
            return httpx.Response(200, content=body) if body is not None else httpx.Response(404)
        return httpx.Response(200, content=b"elsewhere")

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def settings(tmp_path: Path, key: minisign.SecretKey = KEY, **over: Any) -> Settings:
    return Settings(feed_dir=str(tmp_path), trap_pack_key=key.public.encoded, **over)


async def fetch(
    up: Upstream, s: Settings, state: tr.RelayState, root: Path
) -> tuple[tr.Outcome, bytes, bytes]:
    async with up.client() as client:
        return await tr.fetch_verified(client, s, state, root)


def state_of(o: tr.Outcome, key: minisign.SecretKey = KEY) -> tr.RelayState:
    return tr.RelayState(key.public.key_id_hex, o.seq, o.sha256, o.sig_sha256)


# --- pure logic -------------------------------------------------------------------------------


async def test_good_bundle_is_written_byte_identical(tmp_path: Path) -> None:
    data, sig = signed(1_790_000_000)
    up = Upstream(data, sig)
    s = settings(tmp_path)
    out, got, got_sig = await fetch(up, s, tr.RelayState(), tr.target_dir(s))
    assert out.status == "relayed" and out.seq == 1_790_000_000
    tr.publish_files(tr.target_dir(s), got, got_sig)
    root = tmp_path / "traps"
    assert (root / "traps.json").read_bytes() == data
    assert (root / "traps.json.minisig").read_bytes() == sig
    assert gzip.decompress((root / "traps.json.gz").read_bytes()) == data
    assert not list(root.glob(".tmp-*"))
    assert tr.published_ok(root, out.sha256, out.sig_sha256)
    assert all(u.startswith((BASE, CDN)) for u in up.requests)


async def test_same_seq_again_is_a_no_op(tmp_path: Path) -> None:
    data, sig = signed(5)
    up = Upstream(data, sig)
    s = settings(tmp_path)
    root = tr.target_dir(s)
    first, d, g = await fetch(up, s, tr.RelayState(), root)
    tr.publish_files(root, d, g)
    up.requests.clear()
    second, d2, _ = await fetch(up, s, state_of(first), root)
    assert second.status == "unchanged" and d2 == b""
    assert not any(u.endswith("traps.json") for u in up.requests)  # only the signature


async def test_missing_files_are_restored(tmp_path: Path) -> None:
    data, sig = signed(5)
    up = Upstream(data, sig)
    s = settings(tmp_path)
    root = tr.target_dir(s)
    first, _, _ = await fetch(up, s, tr.RelayState(), root)
    again, d, _ = await fetch(up, s, state_of(first), root)
    assert again.status == "restored" and d == data


async def test_forged_signature_is_refused(tmp_path: Path) -> None:
    data, sig = signed(5)
    up = Upstream(data.replace(b'"packs": []', b'"packs": [{}]'), sig)
    s = settings(tmp_path)
    out, d, _ = await fetch(up, s, tr.RelayState(), tr.target_dir(s))
    assert out == tr.Outcome("error", code="bad_signature") and d == b""
    # Another key with the right key id.
    forged = minisign.SecretKey(OTHER.seed, KEY.key_id)
    out, _, _ = await fetch(Upstream(*signed(5, forged)), s, tr.RelayState(), tr.target_dir(s))
    assert out.code == "bad_signature"


async def test_wrong_key_is_refused(tmp_path: Path) -> None:
    s = settings(tmp_path)
    out, _, _ = await fetch(Upstream(*signed(5, OTHER)), s, tr.RelayState(), tr.target_dir(s))
    assert out.code == "wrong_key"


async def test_lower_seq_is_refused_and_a_new_key_starts_afresh(tmp_path: Path) -> None:
    s = settings(tmp_path)
    old = tr.RelayState(KEY.public.key_id_hex, 10, "00", "00")
    out, _, _ = await fetch(Upstream(*signed(9)), s, old, tr.target_dir(s))
    assert out.code == "rollback"
    other = tr.RelayState(OTHER.public.key_id_hex, 10, "00", "00")
    out, _, _ = await fetch(Upstream(*signed(9)), s, other, tr.target_dir(s))
    assert out.status == "relayed" and out.seq == 9


async def test_a_changed_bundle_under_the_same_seq_is_refused(tmp_path: Path) -> None:
    s = settings(tmp_path)
    first, _, _ = await fetch(Upstream(*signed(9)), s, tr.RelayState(), tr.target_dir(s))
    out, _, _ = await fetch(
        Upstream(*signed(9, note="other")), s, state_of(first), tr.target_dir(s)
    )
    assert out.code == "seq_reused"


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example.net/traps.json",
        "http://release-assets.githubusercontent.com/x/traps.json",
        "https://release-assets.githubusercontent.com:8443/x/traps.json",
        "https://user:pw@github.com/x/traps.json",
    ],
)
async def test_redirect_off_github_is_refused(tmp_path: Path, target: str) -> None:
    up = Upstream(*signed(5))
    up.redirect_to = target
    s = settings(tmp_path)
    out, _, _ = await fetch(up, s, tr.RelayState(), tr.target_dir(s))
    assert out.code == "redirect_refused"
    assert not any("evil" in u or u.startswith("http://") for u in up.requests)


async def test_redirect_loop_is_bounded(tmp_path: Path) -> None:
    def loop(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": str(request.url)})

    async with httpx.AsyncClient(transport=httpx.MockTransport(loop)) as client:
        with pytest.raises(tr.RelayError) as err:
            await tr.download(client, BASE + "traps.json", 100)
    assert err.value.code == "too_many_redirects"


async def test_size_caps(tmp_path: Path) -> None:
    s = settings(tmp_path)
    data, _ = signed(5)
    big_sig = Upstream(data, b"x" * (tr.MAX_SIG + 1))
    out, _, _ = await fetch(big_sig, s, tr.RelayState(), tr.target_dir(s))
    assert out.code == "too_large"
    huge = b"{" + b" " * tb.MAX_BYTES + b"}"
    out, _, _ = await fetch(Upstream(huge, signed(5)[1]), s, tr.RelayState(), tr.target_dir(s))
    assert out.code == "too_large"


async def test_http_errors_are_codes(tmp_path: Path) -> None:
    def gone(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    s = settings(tmp_path)
    async with httpx.AsyncClient(transport=httpx.MockTransport(gone)) as client:
        out, _, _ = await tr.fetch_verified(client, s, tr.RelayState(), tr.target_dir(s))
    assert out.code == "http_404"


def test_asset_urls_and_settings() -> None:
    assert tr.asset_url("selfhostr/suckerpot", "traps.json") == BASE + "traps.json"
    s = Settings.from_env({})
    assert not s.trap_relay_enabled and s.trap_relay_interval_s == 600
    on = Settings.from_env(
        {"HUB_TRAP_PACK_KEY": KEY.public.encoded, "HUB_TRAP_PACK_REPO": "acme/traps"}
    )
    assert on.trap_relay_enabled and on.trap_pack_repo == "acme/traps"
    for bad in ({"HUB_TRAP_PACK_KEY": "nope"}, {"HUB_TRAP_PACK_REPO": "a/b/c"},
                {"HUB_TRAP_PACK_REPO": "../x"}, {"HUB_TRAP_RELAY_INTERVAL_S": "5"}):  # fmt: skip
        with pytest.raises(ConfigError):
            Settings.from_env(bad)


def test_relay_never_logs_bundle_content() -> None:
    source = Path(tr.__file__).read_text()
    for line in source.splitlines():
        if "log." in line:
            assert "data" not in line and "sig_text" not in line, line


# --- with the database --------------------------------------------------------------------------


async def _row(env: Env) -> Any:
    async with env.worker() as ses:
        return (await ses.execute(text("SELECT * FROM trap_relay_state WHERE id = 1"))).first()


@pytest.mark.integration
async def test_relay_once_stores_the_seq_and_refuses_rollback(
    env_factory: Any, tmp_path: Path
) -> None:
    env: Env = await env_factory(feed_dir=str(tmp_path), trap_pack_key=KEY.public.encoded)
    data, sig = signed(20)
    up = Upstream(data, sig)
    async with up.client() as client, env.worker() as ses:
        out = await tr.relay_once(ses, env.settings, NOW, client)
    assert out.status == "relayed"
    row = await _row(env)
    assert row.seq == 20 and row.key_id == KEY.public.key_id_hex and row.error_code is None
    assert (tmp_path / "traps" / "traps.json").read_bytes() == data

    old = Upstream(*signed(19))
    async with old.client() as client, env.worker() as ses:
        out = await tr.relay_once(ses, env.settings, NOW, client)
    assert out.code == "rollback"
    row = await _row(env)
    assert row.seq == 20 and row.error_code == "rollback"
    assert (tmp_path / "traps" / "traps.json").read_bytes() == data  # nothing written

    async with up.client() as client, env.worker() as ses:
        out = await tr.relay_once(ses, env.settings, NOW, client)
    assert out.status == "unchanged"
    assert (await _row(env)).error_code is None


@pytest.mark.integration
async def test_relay_off_contacts_nothing(env_factory: Any, tmp_path: Path) -> None:
    env: Env = await env_factory(feed_dir=str(tmp_path))
    up = Upstream(*signed(1))
    async with up.client() as client, env.worker() as ses:
        out = await tr.relay_once(ses, env.settings, NOW, client)
    assert out.status == "off" and up.requests == [] and await _row(env) is None
