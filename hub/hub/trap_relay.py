"""Trap pack relay (design M37 section 5): GitHub release ``trap-packs`` -> the feed site.

Every ``HUB_TRAP_RELAY_INTERVAL_S`` (10 minutes) the worker downloads ``traps.json.minisig`` and,
when it changed, ``traps.json`` from the fixed release ``trap-packs`` of ``HUB_TRAP_PACK_REPO``.
It verifies the signature with the pack PUBLIC key (``HUB_TRAP_PACK_KEY``) and the sequence
against the last relayed one, then copies the bytes unchanged to ``<feed dir>/traps/``:
``traps.json``, ``traps.json.minisig`` and ``traps.json.gz``, each with an atomic rename. Caddy
serves them at ``https://<HUB_FEEDS_DOMAIN>/v1/traps/``.

The hub relays; it cannot sign: it never holds the private key, and nodes verify the same
signature themselves. A forged or altered bundle, another key, a lower sequence, a changed bundle
under the same sequence, an oversized answer or a redirect off GitHub changes nothing: the last
good copy stays and only an error code is recorded. Nothing from the bundle is logged but its
sequence. Downloads use https only, the default port, no credentials, no query of our own, a
generic client identity, byte caps and a deadline; they go through the worker's proxy settings
like every other hub fetch.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_netproto.feeds import FeedError, minisign
from suckerpot_netproto.feeds import traps as tb

from .config import Settings
from .feeds.publish import gz

log = logging.getLogger("hub.trap_relay")

TAG: Final = "trap-packs"
SIG: Final = tb.FILE + ".minisig"
SUBDIR: Final = "traps"
MAX_SIG: Final = 4096
MAX_REDIRECTS: Final = 3
DEADLINE_S: Final = 120.0
TIMEOUT: Final = httpx.Timeout(30.0, connect=10.0)
USER_AGENT: Final = "spn-relay/1"
# GitHub answers a release download with a redirect to its asset storage. Only these hosts are
# ever contacted.
ALLOWED_HOSTS: Final = frozenset(
    {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
)
FILE_MODE: Final = 0o644
DIR_MODE: Final = 0o755
REDIRECTS: Final = frozenset({301, 302, 303, 307, 308})
# Library codes -> recorded error codes.
_CODES: Final = {
    "bad_signature": "bad_signature",
    "wrong_key": "wrong_key",
    "wrong_serial": "bad_signature",
    "rollback": "rollback",
    "too_large": "too_large",
}


class RelayError(Exception):
    """A refused cycle. The message is a short code, never a value."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RelayState:
    key_id: str | None = None
    seq: int | None = None
    sha256: str | None = None
    sig_sha256: str | None = None


@dataclass(frozen=True)
class Outcome:
    status: str  # relayed | unchanged | restored | error
    seq: int | None = None
    sha256: str | None = None
    sig_sha256: str | None = None
    code: str | None = None


def asset_url(repo: str, name: str) -> str:
    return f"https://github.com/{repo}/releases/download/{TAG}/{name}"


def _check_url(url: httpx.URL) -> None:
    if (
        url.scheme != "https"
        or url.host not in ALLOWED_HOSTS
        or url.port not in (None, 443)
        or url.userinfo
        or url.fragment
    ):
        raise RelayError("redirect_refused")


async def download(client: httpx.AsyncClient, url: str, cap: int) -> bytes:
    """GET ``url`` with at most MAX_REDIRECTS redirects, all to ALLOWED_HOSTS over https, and at
    most ``cap`` bytes. Raises RelayError."""
    target = httpx.URL(url)
    try:
        async with asyncio.timeout(DEADLINE_S):
            for _ in range(MAX_REDIRECTS + 1):
                _check_url(target)
                async with client.stream(
                    "GET",
                    target,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "application/octet-stream",
                        "Accept-Encoding": "identity",
                    },
                    follow_redirects=False,
                ) as resp:
                    if resp.status_code in REDIRECTS:
                        location = resp.headers.get("location", "")
                        if not location:
                            raise RelayError("redirect_refused")
                        target = target.join(location)
                        continue
                    if resp.status_code != 200:
                        raise RelayError(f"http_{resp.status_code}")
                    encoding = resp.headers.get("content-encoding", "identity").strip().lower()
                    if encoding not in ("", "identity"):
                        raise RelayError("content_encoding")
                    declared = resp.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > cap:
                        raise RelayError("too_large")
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > cap:
                            raise RelayError("too_large")
                        chunks.append(chunk)
                    return b"".join(chunks)
            raise RelayError("too_many_redirects")
    except RelayError:
        raise
    except (httpx.HTTPError, TimeoutError, OSError) as exc:
        raise RelayError("network") from exc


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def target_dir(s: Settings) -> Path:
    return Path(s.feed_dir) / SUBDIR


def published_ok(root: Path, sha256: str | None, sig_sha256: str | None) -> bool:
    """The three files are on disk and the bundle and signature are the relayed ones."""
    try:
        data = (root / tb.FILE).read_bytes()
        sig = (root / SIG).read_bytes()
        (root / (tb.FILE + ".gz")).stat()
    except OSError:
        return False
    return _sha(data) == sha256 and _sha(sig) == sig_sha256


def publish_files(root: Path, data: bytes, sig: bytes) -> None:
    """Write the signature, the bundle and a gzip copy, each with an atomic rename, the signature
    first and the bundle right after it, so the window where the two do not match is as short as
    two renames. The bundle and signature bytes are exactly the ones downloaded."""
    root.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    packed = gz(data)
    for name, body in ((SIG, sig), (tb.FILE, data), (tb.FILE + ".gz", packed)):
        tmp = root / f".tmp-{name}-{secrets.token_hex(4)}"
        try:
            tmp.write_bytes(body)
            tmp.chmod(FILE_MODE)
            os.replace(tmp, root / name)
        finally:
            tmp.unlink(missing_ok=True)


async def fetch_verified(
    client: httpx.AsyncClient, s: Settings, state: RelayState, root: Path
) -> tuple[Outcome, bytes, bytes]:
    """Download and verify. Returns the outcome and, for ``relayed`` or ``restored``, the bytes
    to write. Never writes anything."""
    public = minisign.parse_public_key(s.trap_pack_key)
    same_key = state.key_id == public.key_id_hex
    last = state.seq if same_key else None
    try:
        sig = await download(client, asset_url(s.trap_pack_repo, SIG), MAX_SIG)
        sig_sha = _sha(sig)
        if same_key and sig_sha == state.sig_sha256 and published_ok(root, state.sha256, sig_sha):
            return Outcome("unchanged", state.seq, state.sha256, sig_sha), b"", b""
        try:
            sig_text = sig.decode("ascii")
        except UnicodeDecodeError:
            raise RelayError("bad_format") from None
        data = await download(client, asset_url(s.trap_pack_repo, tb.FILE), tb.MAX_BYTES)
        try:
            seq = tb.verify_bundle(data, sig_text, public, last_seq=last)
        except FeedError as exc:
            raise RelayError(_CODES.get(exc.code, "bad_format")) from None
        sha = _sha(data)
        if last is not None and seq == last and sha != state.sha256:
            # Sequences only go up: a different bundle under a sequence already relayed is refused.
            raise RelayError("seq_reused")
        status = "restored" if last is not None and seq == last else "relayed"
        return Outcome(status, seq, sha, sig_sha), data, sig
    except RelayError as exc:
        return Outcome("error", code=exc.code), b"", b""


# --- storage ----------------------------------------------------------------------------------


async def load_state(session: AsyncSession) -> RelayState:
    row = (
        await session.execute(
            text("SELECT key_id, seq, sha256, sig_sha256 FROM trap_relay_state WHERE id = 1")
        )
    ).first()
    if row is None:
        return RelayState()
    return RelayState(row[0], None if row[1] is None else int(row[1]), row[2], row[3])


async def _save(session: AsyncSession, values: dict[str, object]) -> None:
    cols = ", ".join(values)
    params = ", ".join(f":{k}" for k in values)
    updates = ", ".join(f"{k} = EXCLUDED.{k}" for k in values)
    await session.execute(
        text(
            f"INSERT INTO trap_relay_state (id, {cols}) VALUES (1, {params}) "  # noqa: S608
            f"ON CONFLICT (id) DO UPDATE SET {updates}, updated_at = now()"
        ),
        values,
    )
    await session.commit()


async def relay_once(
    session: AsyncSession, s: Settings, now: datetime, client: httpx.AsyncClient
) -> Outcome:
    """One relay cycle. Off (``status='off'``) without a key: nothing is contacted."""
    if not s.trap_relay_enabled:
        return Outcome("off")
    root = target_dir(s)
    state = await load_state(session)
    key_id = minisign.parse_public_key(s.trap_pack_key).key_id_hex
    outcome, data, sig = await fetch_verified(client, s, state, root)
    if outcome.status == "error":
        await _save(session, {"checked_at": now, "error_code": outcome.code})
        log.warning("trap relay kept the last copy: %s", outcome.code)
        return outcome
    if outcome.status in ("relayed", "restored"):
        try:
            await asyncio.to_thread(publish_files, root, data, sig)
        except OSError:
            await _save(session, {"checked_at": now, "error_code": "write_failed"})
            log.error("trap relay could not write the bundle: write_failed")
            return Outcome("error", code="write_failed")
        await _save(
            session,
            {
                "key_id": key_id,
                "seq": outcome.seq,
                "sha256": outcome.sha256,
                "sig_sha256": outcome.sig_sha256,
                "relayed_at": now,
                "checked_at": now,
                "error_code": None,
            },
        )
        log.info("trap relay published seq=%s (%s)", outcome.seq, outcome.status)
        return outcome
    await _save(session, {"checked_at": now, "error_code": None})
    return outcome


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession],
    s: Settings,
    *,
    client: httpx.AsyncClient | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """The relay loop of the worker. A failing cycle is logged by type and retried later."""
    own = client is None
    http = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)
    try:
        while True:
            try:
                async with sessionmaker() as session:
                    await relay_once(session, s, clock(), http)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error("trap relay cycle failed: %s", type(exc).__name__)
            await asyncio.sleep(s.trap_relay_interval_s)
    finally:
        if own:
            await http.aclose()
