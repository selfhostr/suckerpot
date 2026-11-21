"""Signed trap pack bundles (design M37 section 5): fetch, verify, hand to the sensors.

The hub relays ``traps.json`` and its minisign signature, unchanged, to the feed site:
``<NETWORK_FEED_URL>/traps/traps.json``. This worker fetches them, never the sensors:

* through the paths ingest already has: the egress gate (VPN proxy) in full mode, ``hubproxy`` in
  participant direct mode (it already allows the feed host, so nothing changes there). HTTPS,
  ``GET``, no redirect, no query, ``User-Agent: spn-feed/1``, 1 MiB cap, 120 s deadline;
* every 30 minutes with up to 5 minutes of jitter, at once at start, with a conditional ``GET``;
* verified with the pack public key (``TRAP_PACK_KEY``, shipped in the release's network
  defaults); a forged signature, another key, a signed seq that is not the file's, or a lower
  ``seq`` than the last accepted one (``trap_state``) is refused and changes nothing;
* validated with the same validator as the sensors (``suckerpot_common.traps``), so ingest knows
  which packs every sensor loads and why one was rejected;
* written to the ``trap-packs`` volume as ``active.json`` and ``active.json.minisig``: temporary
  file, ``fsync``, rename. The sensors mount it read-only and check the signature themselves.

``TRAP_PACKS_REMOTE=false`` stops the fetch and removes a downloaded bundle (the sensors fall back
to their bundled packs); an imported bundle (``just trap-import``) stays. Packs never expire: a
node keeps its last bundle until a newer one is verified. Nothing from a bundle is logged, fetched
or executed; logs carry seq numbers, pack ids and reason codes only.

``python -m ingest.trappacks import --sig-b64 <base64>`` reads a bundle on stdin and applies the
same verification (``just trap-import``).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import secrets
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Protocol

import httpx
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import traps as fmt
from suckerpot_db.models import TrapStateRow
from suckerpot_netproto import defaults
from suckerpot_netproto.feeds import FeedError, minisign
from suckerpot_netproto.feeds import traps as tb

from ingest.egress import EgressClosed, EgressGate
from ingest.features import FeatureSettings, FeatureWorker, _flag
from ingest.network.feed_client import (
    FeedClient,
    FeedHttpError,
    FeedSettings,
    FeedTooLarge,
    FeedUnavailable,
)

log = logging.getLogger(__name__)

REMOTE_FILE: Final = tb.FILE  # traps.json on the feed site
REMOTE_SIG: Final = tb.FILE + ".minisig"
ACTIVE: Final = "active.json"
ACTIVE_SIG: Final = "active.json.minisig"
SUBDIR: Final = "traps"
MAX_SIG: Final = 4096
INTERVAL_S: Final = 1800
JITTER_S: Final = 300
RETRY_CLOSED_S: Final = 300
STALE_DAYS: Final = 7
GATE_HOURS: Final = 48  # design D2: gate G, the same as the release floor
KEEP_GONE_DAYS: Final = 7  # first-seen entries of packs that left the bundle
ERROR_CODES: Final = {
    "bad_signature": "bad_signature",
    "wrong_key": "wrong_key",
    "wrong_serial": "bad_signature",
    "rollback": "rollback",
    "too_large": "too_large",
}


class TrapFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class TrapSettings:
    remote: bool = True
    key: str = ""  # the pack public key, RW...
    feed_url: str = ""  # NETWORK_FEED_URL as the node resolves it (defaults included)
    directory: Path = Path("/traps")

    @property
    def configured(self) -> bool:
        return bool(self.key and self.feed_url)

    @property
    def base_url(self) -> str:
        return f"{self.feed_url}/{SUBDIR}"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> TrapSettings:
        e = os.environ if env is None else env
        remote = _flag(e, "TRAP_PACKS_REMOTE", True)
        key = defaults.effective(e, "TRAP_PACK_KEY")
        if key:
            minisign.parse_public_key(key)  # FeedError is a ValueError
        # The feed URL resolves exactly as for the blocklist feed (and the direct-mode scope).
        url, _ = defaults.effective_pair(e, "NETWORK_FEED_URL", "NETWORK_FEED_KEY")
        if url:
            url = defaults.check_https_url(url, allow_path=True)
        directory = e.get("TRAP_PACKS_DIR", "").strip() or "/traps"
        if not directory.startswith("/") or ".." in directory.split("/"):
            raise ValueError("TRAP_PACKS_DIR must be an absolute path")
        return cls(remote, key, url, Path(directory))


# -- state ---------------------------------------------------------------------------------------


@dataclass(slots=True)
class TrapState:
    key_id: str | None = None
    seq: int | None = None
    sha256: str | None = None
    etag: str | None = None
    source: str | None = None  # remote | import
    packs: int | None = None
    rejected: list[list[str]] = field(default_factory=list)
    first_seen: dict[str, dict[str, Any]] = field(default_factory=dict)
    accepted_at: datetime | None = None
    last_check_at: datetime | None = None
    last_ok_at: datetime | None = None
    error_code: str | None = None


class TrapStore(Protocol):
    async def state(self) -> TrapState | None: ...
    async def save(self, state: TrapState) -> None: ...


class SqlTrapStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self.factory = factory

    async def state(self) -> TrapState | None:
        async with self.factory() as session:
            row = await session.get(TrapStateRow, 1)
            if row is None:
                return None
            return TrapState(
                key_id=row.key_id,
                seq=row.seq,
                sha256=row.sha256,
                etag=row.etag,
                source=row.source,
                packs=row.packs,
                rejected=list(row.rejected or []),
                first_seen=dict(row.first_seen or {}),
                accepted_at=row.accepted_at,
                last_check_at=row.last_check_at,
                last_ok_at=row.last_ok_at,
                error_code=row.error_code,
            )

    async def save(self, state: TrapState) -> None:
        values = {
            "key_id": state.key_id,
            "seq": state.seq,
            "sha256": state.sha256,
            "etag": state.etag,
            "source": state.source,
            "packs": state.packs,
            "rejected": state.rejected,
            "first_seen": state.first_seen,
            "accepted_at": state.accepted_at,
            "last_check_at": state.last_check_at,
            "last_ok_at": state.last_ok_at,
            "error_code": state.error_code,
        }
        async with self.factory() as session, session.begin():
            stmt = pg_insert(TrapStateRow).values(id=1, **values)
            await session.execute(
                stmt.on_conflict_do_update(
                    index_elements=["id"], set_={**values, "updated_at": text("now()")}
                )
            )


# -- files ---------------------------------------------------------------------------------------


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def write_active(directory: Path, data: bytes, sig: str) -> None:
    """The signature first, then the bundle, each atomically, then the directory entry. A sensor
    that reads between the two renames sees a mismatch and retries on the next check."""
    _write_atomic(directory / ACTIVE_SIG, sig.encode("ascii"))
    _write_atomic(directory / ACTIVE, data)
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def remove_active(directory: Path) -> bool:
    gone = False
    for name in (ACTIVE, ACTIVE_SIG):
        try:
            (directory / name).unlink()
            gone = True
        except FileNotFoundError:
            pass
    return gone


# -- verification and gate G ---------------------------------------------------------------------


def cve_tag(cve: str) -> str:
    """``CVE-2026-55501`` -> the network tag ``cve-2026-55501``."""
    return "cve-" + cve[4:].lower()


def _ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def update_first_seen(
    old: dict[str, dict[str, Any]], packs: list[fmt.Pack], now: datetime
) -> dict[str, dict[str, Any]]:
    """Per ``<id>@<version>`` of a CVE-claiming pack, the CVEs and the first time it loaded here.
    Entries of packs that left the bundle are dropped once they are KEEP_GONE_DAYS old (they no
    longer hold anything back); entries still in the bundle are always kept."""
    current: dict[str, dict[str, Any]] = {}
    for p in packs:
        if not p.claims:
            continue
        key = f"{p.id}@{p.version}"
        prev = old.get(key)
        first = _ts(prev.get("first_at")) if prev else None
        current[key] = {"cves": list(p.cve), "first_at": (first or now).isoformat()}
    cutoff = now - timedelta(days=KEEP_GONE_DAYS)
    for key, entry in old.items():
        if key in current:
            continue
        first = _ts(entry.get("first_at"))
        if first is not None and first >= cutoff:
            current[key] = entry
    return current


def gated_tags(first_seen: Mapping[str, Mapping[str, Any]], day: date) -> frozenset[str]:
    """Gate G (design section 10, D2): the CVE tags of every pack version that first loaded less
    than 48 h before any part of ``day`` (UTC). Their hits are shared as tags but do not make the
    source's activity ``exploit``, so they make nobody reportable. An unreadable entry gates its
    CVEs (fail closed)."""
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    out: set[str] = set()
    for entry in first_seen.values():
        first = _ts(entry.get("first_at"))
        cves = entry.get("cves")
        if not isinstance(cves, list):
            continue
        if first is None or first + timedelta(hours=GATE_HOURS) > start:
            out |= {cve_tag(c) for c in cves if isinstance(c, str) and fmt.is_cve(c)}
    return frozenset(out)


@dataclass(frozen=True, slots=True)
class Accepted:
    seq: int
    result: fmt.LoadResult


def verify(data: bytes, sig: str, public: minisign.PublicKey, old: TrapState | None) -> Accepted:
    """Signature, seq (no rollback within one key) and the shared validator. Raises
    ``FeedError`` (signature, seq) or ``TrapFailure`` (``bundle_invalid``)."""
    same_key = old is not None and old.key_id == public.key_id_hex
    last = old.seq if old is not None and same_key else None
    seq = tb.verify_bundle(data, sig, public, last_seq=last)
    try:
        result = fmt.load_bundle(data, today=datetime.now(UTC).date())
    except fmt.PackError:
        raise TrapFailure("bundle_invalid") from None
    return Accepted(seq, result)


async def accept(
    store: TrapStore,
    directory: Path,
    data: bytes,
    sig: str,
    public: minisign.PublicKey,
    *,
    source: str,
    now: datetime,
    etag: str | None = None,
) -> TrapState:
    """Verify a bundle, write it for the sensors and record it. Shared by the worker and the
    import command. Nothing is written when any check fails."""
    old = await store.state()
    got = verify(data, sig, public, old)
    for pid, reason in got.result.rejected:
        log.warning("trap pack rejected: id=%s reason=%s", pid, reason)
    state = TrapState(
        key_id=public.key_id_hex,
        seq=got.seq,
        sha256=hashlib.sha256(data).hexdigest(),
        etag=clean_etag(etag),
        source=source,
        packs=len(got.result.packs),
        rejected=[[pid, reason] for pid, reason in got.result.rejected][:256],
        first_seen=update_first_seen(old.first_seen if old else {}, got.result.packs, now),
        accepted_at=now,
        last_check_at=now,
        last_ok_at=now,
        error_code=None,
    )
    # The state first (seq, hash, first_seen): a failure here writes nothing, so the sensors never
    # run a bundle whose gate G entry or seq was not recorded. If writing the files fails, the
    # recorded seq only makes the next check fetch the same bundle again.
    await store.save(state)
    try:
        write_active(directory, data, sig)
    except BaseException:
        remove_active(directory)
        raise
    log.info("trap bundle accepted: seq %d, %d packs (%s)", got.seq, state.packs, source)
    return state


MAX_ETAG: Final = 256


def clean_etag(etag: str | None) -> str | None:
    """An ETag fit for the bounded column: printable ASCII, 256 characters at most, else None
    (the next check is then a plain GET). The feed host chooses it, so it is never trusted."""
    if etag is None or not 1 <= len(etag) <= MAX_ETAG:
        return None
    if not all(" " <= c <= "~" for c in etag):
        return None
    return etag


def library_code(exc: FeedError) -> str:
    return ERROR_CODES.get(exc.code, "bundle_invalid")


# -- the worker ----------------------------------------------------------------------------------


class TrapPackWorker(FeatureWorker):
    name = "trap_packs"

    def __init__(
        self,
        features: FeatureSettings,
        settings: TrapSettings,
        store: TrapStore | None,
        *,
        gate: EgressGate | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        jitter: Callable[[], float] = lambda: float(secrets.randbelow(JITTER_S + 1)),
    ) -> None:
        super().__init__(features, enabled=True)
        self.trap = settings
        self.store = store
        self._gate = gate
        self._client = client
        self._clock = clock
        self._jitter = jitter
        self.interval_s = float(INTERVAL_S)
        self.state = "off"
        self.reason: str | None = None
        self.seq: int | None = None
        self.last_ok_at: datetime | None = None

    async def status(self) -> dict[str, Any]:
        now = self._clock()
        stale = self.trap.remote and (
            self.last_ok_at is None or now - self.last_ok_at > timedelta(days=STALE_DAYS)
        )
        return {
            self.name: {
                "enabled": self.trap.remote,
                "configured": self.trap.configured,
                "state": self.state,
                "reason": self.reason,
                "seq": self.seq,
                "last_ok_at": self.last_ok_at.isoformat() if self.last_ok_at else None,
                "stale": bool(stale and self.trap.configured),
                "cycles": self.cycles,
                "last_error": self.last_error,
            }
        }

    async def run_once(self) -> None:
        store = self.store
        self.interval_s = float(INTERVAL_S) + self._jitter()
        if store is None:
            self.state, self.reason = "off", None
            return
        now = self._clock()
        old = await store.state()
        if old is not None:
            self.seq, self.last_ok_at = old.seq, old.last_ok_at
        if not self.trap.remote:
            # The local kill switch: no fetch, and a downloaded bundle goes (bundled packs run).
            if (old is None or old.source != "import") and remove_active(self.trap.directory):
                log.info("TRAP_PACKS_REMOTE=false: the downloaded trap bundle was removed")
            self.state, self.reason = "off", "remote_disabled"
            return
        if not self.trap.configured:
            self.state, self.reason = "off", "not_configured"
            return
        try:
            await self._cycle(store, old, now)
            self.state, self.reason = "ok", None
        except TrapFailure as exc:
            await self._fail(store, old, exc.code, now)
        except EgressClosed:
            self.interval_s = float(RETRY_CLOSED_S)
            self.state, self.reason = "waiting", "no_route"
        except FeedHttpError as exc:
            await self._fail(store, old, exc.code, now)
        except FeedTooLarge:
            await self._fail(store, old, "too_large", now)
        except FeedUnavailable:
            await self._fail(store, old, "unreachable", now)
        except FeedError as exc:
            await self._fail(store, old, library_code(exc), now)

    async def _fail(
        self, store: TrapStore, old: TrapState | None, code: str, now: datetime
    ) -> None:
        self.state, self.reason = "error", code
        log.warning("trap bundle check failed: %s", code)
        state = old or TrapState()
        state.error_code = code
        state.last_check_at = now
        await store.save(state)

    async def _cycle(self, store: TrapStore, old: TrapState | None, now: datetime) -> None:
        public = minisign.parse_public_key(self.trap.key)
        feed = FeedSettings(url=self.trap.base_url, key=self.trap.key)
        client = FeedClient(feed, gate=self._gate, client=self._client, scoped=True)
        same_key = old is not None and old.key_id == public.key_id_hex
        have = (self.trap.directory / ACTIVE).exists() and (
            self.trap.directory / ACTIVE_SIG
        ).exists()
        etag = old.etag if old is not None and same_key and have else None
        resp = await client.get(REMOTE_FILE, max_bytes=tb.MAX_BYTES, etag=etag)
        if resp.status == 304 and old is not None:
            old.last_check_at = old.last_ok_at = now
            old.error_code = None
            await store.save(old)
            self.last_ok_at = now
            return
        sig = await client.get_text(REMOTE_SIG, max_bytes=MAX_SIG)
        if old is not None and same_key and old.sha256 == hashlib.sha256(resp.body).hexdigest():
            # The same bundle again (no etag support upstream): just a successful check.
            tb.verify_bundle(resp.body, sig, public, last_seq=old.seq)
            if have:
                old.last_check_at = old.last_ok_at = now
                old.error_code, old.etag = None, clean_etag(resp.etag)
                await store.save(old)
                self.last_ok_at = now
                return
        state = await accept(
            store,
            self.trap.directory,
            resp.body,
            sig,
            public,
            source="remote",
            now=now,
            etag=resp.etag,
        )
        self.seq, self.last_ok_at = state.seq, state.last_ok_at


def build_trap_worker(features: FeatureSettings, factory: Any) -> TrapPackWorker:
    """A bad TRAP_* value leaves the worker unconfigured: nothing is fetched, nothing removed."""
    try:
        settings = TrapSettings.from_env()
    except ValueError as exc:
        log.error("trap pack settings are invalid (%s): no bundle is fetched", exc)
        settings = TrapSettings(remote=True, key="", feed_url="")
    return TrapPackWorker(features, settings, SqlTrapStore(factory))


class SqlGateSource:
    """Gate G for the network batch builder: the CVE tags held back on a day."""

    def __init__(
        self, factory: async_sessionmaker[AsyncSession], directory: Path = Path("/traps")
    ) -> None:
        self.store = SqlTrapStore(factory)
        self.directory = directory

    async def gated_tags(self, day: date) -> frozenset[str] | None:
        try:
            state = await self.store.state()
        except Exception as exc:  # fail closed: the builder holds back every CVE tag
            log.warning("trap state unreadable for gate G (%s)", type(exc).__name__)
            return None
        if state is None:
            # No record, yet a bundle is there for the sensors: its packs may be new. Hold back
            # every CVE tag until the worker has recorded it (fail closed).
            return None if (self.directory / ACTIVE).exists() else frozenset()
        return gated_tags(state.first_seen, day)


def build_gate_source(factory: async_sessionmaker[AsyncSession]) -> SqlGateSource:
    """Gate G source looking at the same trap-packs directory as the worker."""
    try:
        directory = TrapSettings.from_env().directory
    except ValueError:
        directory = Path("/traps")
    return SqlGateSource(factory, directory)


# -- import (just trap-import) -------------------------------------------------------------------


async def _import(sig_b64: str, data: bytes, env: Mapping[str, str]) -> dict[str, Any]:
    from suckerpot_db import create_engine, create_session_factory

    settings = TrapSettings.from_env(env)
    if not settings.key:
        return {"ok": False, "error": "no_key"}
    try:
        sig = base64.b64decode(sig_b64, validate=True).decode("ascii")
    except binascii.Error, ValueError:
        return {"ok": False, "error": "bad_signature_file"}
    if len(data) > tb.MAX_BYTES or len(sig) > MAX_SIG:
        return {"ok": False, "error": "too_large"}
    engine = create_engine()
    try:
        store = SqlTrapStore(create_session_factory(engine))
        state = await accept(
            store,
            settings.directory,
            data,
            sig,
            minisign.parse_public_key(settings.key),
            source="import",
            now=datetime.now(UTC),
        )
    except FeedError as exc:
        return {"ok": False, "error": library_code(exc)}
    except TrapFailure as exc:
        return {"ok": False, "error": exc.code}
    finally:
        await engine.dispose()
    return {"ok": True, "seq": state.seq, "packs": state.packs, "rejected": state.rejected}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ingest.trappacks")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", help="verify a bundle read on stdin and load it")
    imp.add_argument("--sig-b64", required=True, help="the .minisig file, base64")
    args = parser.parse_args(argv)
    data = sys.stdin.buffer.read(tb.MAX_BYTES + 1)
    doc = asyncio.run(_import(args.sig_b64, data, dict(os.environ)))
    sys.stdout.write(json.dumps(doc, sort_keys=True) + "\n")
    return 0 if doc.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
