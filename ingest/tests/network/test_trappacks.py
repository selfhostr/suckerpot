"""The trap pack worker (M37 P2): fetch, verify, refuse forgeries and rollback, write for the
sensors, kill switch, direct-mode scope and gate G."""

from __future__ import annotations

import base64
import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from suckerpot_common import traps as fmt
from suckerpot_netproto import defaults, sign
from suckerpot_netproto.feeds import minisign
from suckerpot_netproto.feeds import traps as tb

from ingest import trappacks as tp
from ingest.egress import egress_settings
from ingest.features import FeatureSettings
from ingest.trappacks import TrapPackWorker, TrapSettings, TrapState

from .helpers import FakeGate

FEED = "https://feeds.example.org/v1"
SECRET = minisign.SecretKey(bytes(range(64, 96)), bytes(range(1, 9)))
OTHER = minisign.SecretKey(bytes(range(96, 128)), bytes(range(11, 19)))
NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def pack(pid: str = "acme-edgegate-cve-2026-55501", version: int = 1, **kw: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "schema": "suckerpot-trap/1",
        "id": pid,
        "version": version,
        "engine": 1,
        "sensor": "web",
        "title": "Acme EdgeGate pre-auth command injection",
        "cve": ["CVE-2026-55501"],
        "disclosed": "2026-11-18",
        "product": {"vendor": "Acme", "name": "EdgeGate"},
        "tag": "acme-edgegate-rce",
        "traps": [
            {
                "id": "diag-rce",
                "level": "exploit",
                "match": {
                    "method": ["POST"],
                    "path": {"exact": "/api/v1/diag/ping"},
                    "needles": [{"in": "body", "any": ["host="]}],
                },
                "outcome": {"flags": ["edgegate_rce"]},
            }
        ],
    }
    obj.update(kw)
    return obj


def bundle(seq: int, packs: list[dict[str, Any]] | None = None, **extra: Any) -> bytes:
    return fmt.build_bundle(packs if packs is not None else [pack()], seq, **extra)


class Site:
    """The feed site: /v1/traps/traps.json and its signature."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.data = b""
        self.sig = ""
        self.etag: str | None = '"t1"'
        self.status: int | None = None
        self.publish(5)

    def publish(self, seq: int, packs: list[dict[str, Any]] | None = None, *,
                signer: minisign.SecretKey = SECRET, sig: str | None = None) -> None:  # fmt: skip
        self.data = bundle(seq, packs)
        self.sig = sig if sig is not None else tb.sign_bundle(self.data, signer)
        self.etag = f'"t{seq}"'

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status is not None:
            return httpx.Response(self.status, headers={"Location": "https://elsewhere.example/"})
        path = request.url.path
        if path == "/v1/traps/traps.json":
            if self.etag and request.headers.get("if-none-match") == self.etag:
                return httpx.Response(304, headers={"ETag": self.etag})
            headers = {"ETag": self.etag} if self.etag else {}
            return httpx.Response(200, content=self.data, headers=headers)
        if path == "/v1/traps/traps.json.minisig":
            return httpx.Response(200, content=self.sig.encode())
        return httpx.Response(404)


class Store:
    def __init__(self, state: TrapState | None = None) -> None:
        self.st = state
        self.saves = 0

    async def state(self) -> TrapState | None:
        if self.st is None:
            return None
        return TrapState(**{k: getattr(self.st, k) for k in TrapState.__slots__})

    async def save(self, state: TrapState) -> None:
        self.st = state
        self.saves += 1


def make(site: Site, store: Store, d: Path, *, gate: Any = None, **kw: Any) -> TrapPackWorker:
    settings = TrapSettings(
        remote=kw.pop("remote", True),
        key=kw.pop("key", SECRET.public.encoded),
        feed_url=kw.pop("feed_url", FEED),
        directory=d,
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(site.handler))
    return TrapPackWorker(
        FeatureSettings(),
        settings,
        store,
        gate=gate or FakeGate(),  # type: ignore[arg-type]
        client=http,
        clock=lambda: NOW,
        jitter=lambda: 0.0,
    )


def leftovers(d: Path) -> list[Path]:
    return list(d.glob(".*.tmp"))


def files(d: Path) -> tuple[bytes, str] | None:
    if not (d / tp.ACTIVE).exists():
        return None
    return (d / tp.ACTIVE).read_bytes(), (d / tp.ACTIVE_SIG).read_text()


# -- the happy path ------------------------------------------------------------------------------


async def test_a_verified_bundle_is_written_unchanged_for_the_sensors(tmp_path: Path) -> None:
    site, store = Site(), Store()
    w = make(site, store, tmp_path)
    await w.run_once()
    assert w.state == "ok" and w.reason is None
    assert files(tmp_path) == (site.data, site.sig)
    st = store.st
    assert st is not None and st.seq == 5 and st.source == "remote" and st.packs == 1
    assert st.key_id == SECRET.public.key_id_hex and st.etag == '"t5"'
    assert st.first_seen == {
        "acme-edgegate-cve-2026-55501@1": {"cves": ["CVE-2026-55501"], "first_at": NOW.isoformat()}
    }
    assert not leftovers(tmp_path)  # no temporary file left behind
    status = (await w.status())["trap_packs"]
    assert status["seq"] == 5 and status["state"] == "ok" and not status["stale"]


async def test_requests_are_anonymous_bounded_gets_to_the_feed_host(tmp_path: Path) -> None:
    site = Site()
    await make(site, Store(), tmp_path).run_once()
    assert [r.url.path for r in site.requests] == [
        "/v1/traps/traps.json",
        "/v1/traps/traps.json.minisig",
    ]
    for r in site.requests:
        assert r.method == "GET" and r.url.host == "feeds.example.org" and r.url.scheme == "https"
        assert not r.url.query and "cookie" not in r.headers
        assert r.headers["user-agent"] == "spn-feed/1"
        assert r.headers["accept-encoding"] == "identity"


async def test_conditional_get_and_same_bundle_change_nothing(tmp_path: Path) -> None:
    site, store = Site(), Store()
    w = make(site, store, tmp_path)
    await w.run_once()
    before = (tmp_path / tp.ACTIVE).stat().st_mtime_ns
    site.requests.clear()
    await w.run_once()
    assert [r.headers.get("if-none-match") for r in site.requests] == ['"t5"']
    assert w.state == "ok" and (tmp_path / tp.ACTIVE).stat().st_mtime_ns == before
    site.etag = None  # a server without etags: the same bytes are only a successful check
    await w.run_once()
    assert w.state == "ok" and (tmp_path / tp.ACTIVE).stat().st_mtime_ns == before


async def test_a_bad_pack_does_not_stop_the_others(tmp_path: Path) -> None:
    bad = pack("bad-pack")
    bad["traps"][0]["outcome"]["flags"] = ["rce"]
    site, store = Site(), Store()
    site.publish(6, [bad, pack()])
    await make(site, store, tmp_path).run_once()
    assert store.st is not None and store.st.packs == 1
    assert store.st.rejected == [["bad-pack", "schema"]]
    assert files(tmp_path) == (site.data, site.sig)


# -- refusals ------------------------------------------------------------------------------------


async def test_forged_signature_is_refused_and_nothing_written(tmp_path: Path) -> None:
    site, store = Site(), Store()
    other_bytes = bundle(5, [pack(version=2)])
    site.publish(5, sig=tb.sign_bundle(other_bytes, SECRET))
    w = make(site, store, tmp_path)
    await w.run_once()
    assert w.state == "error" and w.reason == "bad_signature"
    assert files(tmp_path) is None and store.st is not None and store.st.seq is None
    # Another secret with the right key id.
    site.publish(5, signer=minisign.SecretKey(OTHER.seed, SECRET.key_id))
    await w.run_once()
    assert w.reason == "bad_signature" and files(tmp_path) is None


async def test_wrong_key_is_refused(tmp_path: Path) -> None:
    site, store = Site(), Store()
    site.publish(5, signer=OTHER)
    w = make(site, store, tmp_path)
    await w.run_once()
    assert w.reason == "wrong_key" and files(tmp_path) is None


async def test_lower_seq_is_refused(tmp_path: Path) -> None:
    site, store = Site(), Store()
    w = make(site, store, tmp_path)
    site.publish(9, [pack(version=3)])
    await w.run_once()
    kept = files(tmp_path)
    site.publish(8, [pack(version=4)])  # older, validly signed
    await w.run_once()
    assert w.reason == "rollback" and files(tmp_path) == kept
    assert store.st is not None and store.st.seq == 9 and store.st.error_code == "rollback"


async def test_a_new_key_starts_a_new_seq_space(tmp_path: Path) -> None:
    site = Site()
    store = Store(TrapState(key_id="0000000000000000", seq=10**9))
    w = make(site, store, tmp_path)
    await w.run_once()
    assert w.state == "ok" and store.st is not None and store.st.seq == 5


async def test_http_errors_redirects_and_size(tmp_path: Path) -> None:
    site, store = Site(), Store()
    w = make(site, store, tmp_path)
    site.status = 302
    await w.run_once()
    assert w.reason == "http_302" and len(site.requests) == 1  # never followed
    site.status = None
    site.data = b"x" * (tb.MAX_BYTES + 1)
    await w.run_once()
    assert w.reason == "too_large" and files(tmp_path) is None


async def test_an_invalid_bundle_envelope_is_refused(tmp_path: Path) -> None:
    site, store = Site(), Store()
    data = json.dumps({"schema": "suckerpot-traps/1", "seq": 5, "packs": "nope"}).encode()
    site.data, site.sig = data, tb.sign_bundle(data, SECRET)
    w = make(site, store, tmp_path)
    await w.run_once()
    assert w.reason == "bundle_invalid" and files(tmp_path) is None


# -- switches and routes -------------------------------------------------------------------------


async def test_no_key_fetches_nothing(tmp_path: Path) -> None:
    site = Site()
    w = make(site, Store(), tmp_path, key="")
    await w.run_once()
    assert w.reason == "not_configured" and site.requests == []


async def test_closed_gate_fetches_nothing(tmp_path: Path) -> None:
    site = Site()
    w = make(site, Store(), tmp_path, gate=FakeGate(open_=False))
    await w.run_once()
    assert w.state == "waiting" and w.reason == "no_route" and site.requests == []


async def test_remote_off_removes_a_downloaded_bundle_but_keeps_an_import(tmp_path: Path) -> None:
    site, store = Site(), Store()
    await make(site, store, tmp_path).run_once()
    assert files(tmp_path) is not None
    site.requests.clear()
    off = make(site, store, tmp_path, remote=False)
    await off.run_once()
    assert off.reason == "remote_disabled" and files(tmp_path) is None and site.requests == []
    imported = Store(TrapState(seq=5, source="import"))
    tp.write_active(tmp_path, site.data, site.sig)
    await make(site, imported, tmp_path, remote=False).run_once()
    assert files(tmp_path) == (site.data, site.sig)


class DirectGate:
    """Participant direct mode (M32): open only for a host in the hub/feed scope."""

    def __init__(self, scope: set[str]) -> None:
        self.scope = scope

    def require_open(self, host: str | None = None) -> None:
        from suckerpot_egress import EgressClosed

        if host is None or host not in self.scope:
            raise EgressClosed("egress_direct")


async def test_direct_mode_reaches_the_feed_host_only(tmp_path: Path) -> None:
    """The bundle comes from the feed host that hubproxy already allows: no proxy change."""
    site = Site()
    w = make(site, Store(), tmp_path, gate=DirectGate({"feeds.example.org"}))
    await w.run_once()
    assert w.state == "ok" and files(tmp_path) is not None
    w = make(Site(), Store(), tmp_path / "x", gate=DirectGate({"hub.example.org"}))
    await w.run_once()
    assert w.reason == "no_route"


def _defaults(**over: str) -> str:
    values = {
        "NETWORK_DEFAULTS_VERSION": "1",
        "NETWORK_HUB_URL": "https://hub.example.org",
        "NETWORK_HUB_KEY": sign.node_key(sign.public_key_of(sign.generate_private_key())),
        "NETWORK_FEED_URL": FEED,
        "NETWORK_FEED_KEY": OTHER.public.encoded,
        "TRAP_PACK_KEY": SECRET.public.encoded,
    }
    values.update(over)
    return "".join(f"{k}={v}\n" for k, v in values.items())


def test_settings_follow_the_release_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(defaults, "load", lambda: defaults.from_text(_defaults()))
    s = TrapSettings.from_env({})
    assert s.remote and s.configured and s.key == SECRET.public.encoded
    assert s.base_url == f"{FEED}/traps" and s.directory == Path("/traps")
    assert not TrapSettings.from_env({"TRAP_PACKS_REMOTE": "false"}).remote
    explicit = TrapSettings.from_env({"TRAP_PACK_KEY": OTHER.public.encoded})
    assert explicit.key == OTHER.public.encoded
    with pytest.raises(ValueError):
        TrapSettings.from_env({"TRAP_PACK_KEY": "garbage"})
    monkeypatch.setattr(defaults, "load", lambda: defaults.from_text(_defaults(TRAP_PACK_KEY="")))
    assert not TrapSettings.from_env({}).configured


def test_the_trap_host_is_in_the_direct_mode_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guardrail (design section 12, P2): direct mode reaches the bundle with the scope it
    already has (hub and feed hosts), whether the feed URL is the default or set in .env."""
    monkeypatch.setattr(defaults, "load", lambda: defaults.from_text(_defaults()))
    other = minisign.generate_keypair().public.encoded
    for env in (
        {},
        {"NETWORK_FEED_URL": "https://other.example.net/v1", "NETWORK_FEED_KEY": other},
    ):
        scope = egress_settings({**env, "EGRESS_MODE": "direct"}).scope_hosts
        host = httpx.URL(TrapSettings.from_env(env).base_url).host
        assert host in scope
        assert len(scope) <= 2  # hub and feed: nothing was added for trap packs


# -- import --------------------------------------------------------------------------------------


async def test_import_applies_the_same_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store()
    monkeypatch.setattr(tp, "SqlTrapStore", lambda factory: store)
    monkeypatch.setattr("suckerpot_db.create_engine", lambda: _Engine())
    monkeypatch.setattr("suckerpot_db.create_session_factory", lambda engine: None)
    env = {"TRAP_PACK_KEY": SECRET.public.encoded, "TRAP_PACKS_DIR": str(tmp_path)}
    data = bundle(7)
    sig_b64 = base64.b64encode(tb.sign_bundle(data, SECRET).encode()).decode()
    doc = await tp._import(sig_b64, data, env)
    assert doc == {"ok": True, "seq": 7, "packs": 1, "rejected": []}
    assert store.st is not None and store.st.source == "import"
    forged = await tp._import(sig_b64, bundle(7, [pack(version=2)]), env)
    assert forged == {"ok": False, "error": "bad_signature"}
    older = bundle(6)
    doc = await tp._import(
        base64.b64encode(tb.sign_bundle(older, SECRET).encode()).decode(), older, env
    )
    assert doc == {"ok": False, "error": "rollback"}
    assert (await tp._import(sig_b64, data, {"TRAP_PACK_KEY": ""}))["error"] in ("no_key",)


class _Engine:
    async def dispose(self) -> None:
        return None


# -- gate G --------------------------------------------------------------------------------------


def test_first_seen_keeps_the_first_time_and_drops_gone_versions() -> None:
    p1 = fmt.validate_pack(pack())
    p2 = fmt.validate_pack(pack(version=2))
    seen = tp.update_first_seen({}, [p1], NOW)
    later = NOW + timedelta(days=1)
    assert tp.update_first_seen(seen, [p1], later) == seen  # still the first time
    both = tp.update_first_seen(seen, [p2], later)  # v1 left the bundle, v2 is new
    assert set(both) == {"acme-edgegate-cve-2026-55501@1", "acme-edgegate-cve-2026-55501@2"}
    assert both["acme-edgegate-cve-2026-55501@2"]["first_at"] == later.isoformat()
    gone = tp.update_first_seen(both, [p2], NOW + timedelta(days=9))
    assert set(gone) == {"acme-edgegate-cve-2026-55501@2"}
    # A pack that claims no CVE holds nothing back.
    probe = fmt.validate_pack(pack("probe-only", cve=[]))
    assert tp.update_first_seen({}, [probe], NOW) == {}


def test_gated_tags_cover_48_hours() -> None:
    first = datetime(2026, 11, 20, 1, 0, tzinfo=UTC)
    seen = {"p@1": {"cves": ["CVE-2026-55501"], "first_at": first.isoformat()}}
    tag = frozenset({"cve-2026-55501"})
    assert tp.gated_tags(seen, date(2026, 11, 19)) == tag  # before: still within (fail safe)
    assert tp.gated_tags(seen, date(2026, 11, 20)) == tag
    assert tp.gated_tags(seen, date(2026, 11, 21)) == tag
    assert tp.gated_tags(seen, date(2026, 11, 22)) == tag  # 01:00 on the 22nd ends the window
    assert tp.gated_tags(seen, date(2026, 11, 23)) == frozenset()
    broken = {"p@1": {"cves": ["CVE-2026-55501"], "first_at": "not a time"}}
    assert tp.gated_tags(broken, date(2027, 1, 1)) == tag  # unreadable: fail closed


# -- security review fixes -----------------------------------------------------------------------


@pytest.mark.parametrize("etag", ['"' + "x" * 300 + '"', '"t\x01"', ""])
async def test_a_hostile_etag_is_dropped_not_stored(tmp_path: Path, etag: str) -> None:
    site, store = Site(), Store()
    site.etag = etag
    await make(site, store, tmp_path).run_once()
    assert store.st is not None and store.st.seq == 5 and store.st.etag is None
    assert tp.clean_etag('"ok-1"') == '"ok-1"'
    assert tp.clean_etag("caf\u00e9") is None


class FailingStore(Store):
    async def save(self, state: TrapState) -> None:
        if state.seq is not None and state.error_code is None:
            raise RuntimeError("check constraint")
        await super().save(state)


async def test_nothing_is_written_when_the_state_cannot_be_saved(tmp_path: Path) -> None:
    """The state (seq, first_seen) is saved before the files: a failed save leaves the sensors on
    their current set, so gate G and the rollback floor cannot be skipped."""
    site = Site()
    w = make(site, FailingStore(), tmp_path)
    with pytest.raises(RuntimeError):
        await w.run_once()  # the worker loop logs it and retries on the next cycle
    assert files(tmp_path) is None


async def test_a_failed_file_write_leaves_no_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site, store = Site(), Store()

    def boom(directory: Path, data: bytes, sig: str) -> None:
        (directory / tp.ACTIVE_SIG).write_text(sig)
        raise OSError("disk full")

    monkeypatch.setattr(tp, "write_active", boom)
    with pytest.raises(OSError):
        await tp.accept(store, tmp_path, site.data, site.sig, SECRET.public, source="remote",
                        now=NOW)  # fmt: skip
    assert files(tmp_path) is None and not (tmp_path / tp.ACTIVE_SIG).exists()
    assert store.st is not None and store.st.first_seen  # recorded first


class _NoRow:
    async def state(self) -> TrapState | None:
        return None


async def test_gate_holds_every_cve_without_a_record_but_with_a_bundle(tmp_path: Path) -> None:
    gate = tp.SqlGateSource.__new__(tp.SqlGateSource)
    gate.store = _NoRow()  # type: ignore[assignment]
    gate.directory = tmp_path
    assert await gate.gated_tags(date(2026, 11, 21)) == frozenset()
    tp.write_active(tmp_path, b"{}", "sig")
    assert await gate.gated_tags(date(2026, 11, 21)) is None
