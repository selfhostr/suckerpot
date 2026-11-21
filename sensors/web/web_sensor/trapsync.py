"""Downloaded trap packs (M37 P2): verify, merge with the bundled packs, reload without restart.

Ingest fetches the signed bundle and writes ``active.json`` and ``active.json.minisig`` to the
``trap-packs`` volume, which this sensor mounts read-only. The sensor never fetches anything. Every
``interval_s`` (30 s) it compares the files' (mtime, size, inode); on a change it reads them,
checks the signature with ``TRAP_PACK_KEY`` itself, validates and compiles a new immutable
``TrapSet`` and hands it over: one reference swap, requests in flight finish with the old set.

* No key (``TRAP_PACK_KEY`` empty): bundled packs only.
* A bad signature, another key, a lower ``seq`` than the highest accepted (kept in the data
  directory as ``trap-seq.json``, so a restart keeps the floor), or an unparsable bundle:
  the current set stays (at start: bundled packs only).
* The files are gone: back to the bundled packs (ingest can stop updates, never add a trap).
* A downloaded ``seq`` below the image's bundled ``seq``: ignored (the image is newer).
* A bad pack inside a good bundle is rejected alone; the other packs load.
* The bundle's ``disabled`` list and ``TRAP_PACKS_DISABLED`` turn packs off, bundled ones too.

Logs carry pack ids, reasons and seq numbers only, never pack content.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from suckerpot_common import traps as fmt

from web_sensor import packsig
from web_sensor.traps import BUNDLED, TrapSet, load_docs

log = logging.getLogger("web_sensor.trapsync")

ACTIVE = "active.json"
FLOOR = "trap-seq.json"  # in data_dir: the highest accepted (key id, seq), the rollback floor
SIGNATURE = "active.json.minisig"

type Stamp = tuple[tuple[int, int, int] | None, tuple[int, int, int] | None]
# config/network-defaults.env of the release, copied into the image (signed with it).
DEFAULTS = Path("/app/network-defaults.env")


def committed_key(path: Path) -> str:
    """The ``TRAP_PACK_KEY=`` value of the defaults file, "" when absent or unreadable."""
    try:
        if path.stat().st_size > 16384:
            return ""
        text = path.read_text("utf-8")
    except OSError, UnicodeDecodeError:
        return ""
    found = ""
    for line in text.splitlines():
        name, sep, value = line.strip().partition("=")
        if sep and name == "TRAP_PACK_KEY":
            found = value.strip()
    return found


@dataclass(frozen=True, slots=True)
class SyncSettings:
    key: str = ""  # TRAP_PACK_KEY; empty = downloaded bundles are ignored
    directory: Path = Path("/traps")
    disabled: frozenset[str] = frozenset()
    interval_s: float = 30.0
    data_dir: Path | None = None  # WEB_DATA_DIR: where the highest accepted seq is kept

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, defaults: Path = DEFAULTS
    ) -> SyncSettings:
        """``TRAP_PACK_KEY`` from the environment, else the release's committed default (the
        network defaults file copied into the image), else none."""
        e = os.environ if env is None else env
        key = e.get("TRAP_PACK_KEY", "").strip() or committed_key(defaults)
        if key.startswith("<"):
            key = ""  # a placeholder: not configured
        directory = e.get("TRAP_PACKS_DIR", "/traps").strip() or "/traps"
        if not directory.startswith("/") or ".." in directory.split("/"):
            raise ValueError("TRAP_PACKS_DIR must be an absolute path")
        # A typo in these two must not stop the sensor: the bad part is logged and ignored.
        disabled: set[str] = set()
        for item in e.get("TRAP_PACKS_DISABLED", "").split(","):
            item = item.strip()
            if not item:
                continue
            if not fmt.is_slug(item, 3, 48):
                log.error("TRAP_PACKS_DISABLED holds an entry that is not a pack id: ignored")
                continue
            disabled.add(item)
        raw = e.get("TRAP_PACKS_RELOAD_S", "").strip() or "30"
        if not raw.isdigit() or not 5 <= int(raw) <= 3600:
            log.error("TRAP_PACKS_RELOAD_S must be between 5 and 3600: using 30")
            raw = "30"
        data_dir = e.get("WEB_DATA_DIR", "/data").strip() or "/data"
        return cls(key, Path(directory), frozenset(disabled), float(raw), data_dir=Path(data_dir))


def _stat(path: Path) -> tuple[int, int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


class TrapSync:
    """Keeps the sensor's TrapSet in line with the bundled and the downloaded packs."""

    def __init__(
        self,
        settings: SyncSettings,
        *,
        bundled_path: Path = BUNDLED,
        today: Callable[[], date] | None = None,
    ) -> None:
        self.settings = settings
        self._today = today
        self.loaded_seq: int | None = None  # highest downloaded seq accepted since start
        self.using_downloaded = False
        self.refused = 0
        self.last_error: str | None = None
        self._stamp: Stamp | None = None
        self._key: packsig.PublicKey | None = None
        if settings.key:
            try:
                self._key = packsig.parse_key(settings.key)
            except packsig.SignatureError:
                log.error("TRAP_PACK_KEY is not a minisign public key: downloaded packs are off")
        self._floor_path = settings.data_dir / FLOOR if settings.data_dir else None
        if self._key is not None:
            self.loaded_seq = self._read_floor(self._key)
        self._bundled = self._read_bundled(bundled_path)
        self.current = self._build(None)
        if self._key is None:
            log.info("no trap pack key: bundled packs only")

    # -- inputs ------------------------------------------------------------------------------

    @staticmethod
    def _read_bundled(path: Path) -> dict[str, Any] | None:
        try:
            if path.stat().st_size > fmt.MAX_BUNDLE_BYTES:
                raise fmt.PackError("limits", "bundled file too large")
            return fmt.parse_bundle(path.read_bytes())
        except (OSError, fmt.PackError) as err:
            log.error("bundled trap packs rejected: %s", getattr(err, "reason", "unreadable"))
            return None

    # -- the rollback floor, kept across restarts -------------------------------------------

    def _read_floor(self, key: packsig.PublicKey) -> int | None:
        """The highest seq accepted under this key before a restart (in the data_dir), or
        None. A floor of another key is ignored: a new key starts a new seq space."""
        path = self._floor_path
        if path is None:
            return None
        try:
            if path.stat().st_size > 256:
                raise ValueError("too large")
            doc = json.loads(path.read_text("ascii"))
            key_id, seq = doc["key_id"], doc["seq"]
        except FileNotFoundError:
            return None
        except OSError, ValueError, KeyError, TypeError:
            log.error("trap seq floor unreadable: ignored")
            return None
        if key_id != key.key_id.hex() or not isinstance(seq, int) or isinstance(seq, bool):
            return None
        return seq if 0 <= seq <= 2**53 else None

    def _write_floor(self, key: packsig.PublicKey, seq: int) -> None:
        """Atomically record the highest accepted (key id, seq) below data_dir."""
        path = self._floor_path
        if path is None:
            return
        tmp = path.with_name(f".{FLOOR}.tmp")
        body = json.dumps({"key_id": key.key_id.hex(), "seq": seq}).encode("ascii")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except OSError:
            log.error("trap seq floor not saved (data_dir not writable)")

    @property
    def bundled_seq(self) -> int:
        return int(self._bundled["seq"]) if self._bundled else 0

    def _stamp_now(self) -> Stamp:
        d = self.settings.directory
        return (_stat(d / ACTIVE), _stat(d / SIGNATURE))

    def _read_downloaded(self, key: packsig.PublicKey) -> dict[str, Any] | None:
        """The verified, parsed downloaded bundle. Raises ``_Refused`` with a reason."""
        d = self.settings.directory
        try:
            if (d / ACTIVE).stat().st_size > fmt.MAX_BUNDLE_BYTES:
                raise _Refused("limits")
            if (d / SIGNATURE).stat().st_size > packsig.MAX_SIG_BYTES:
                raise _Refused("bad_format")
            data = (d / ACTIVE).read_bytes()
            sig = (d / SIGNATURE).read_bytes().decode("ascii")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError) as exc:
            raise _Refused("unreadable") from exc
        try:
            seq = packsig.verify(data, sig, key)
        except packsig.SignatureError as err:
            raise _Refused(err.code) from None
        try:
            doc = fmt.parse_bundle(data)
        except fmt.PackError as err:
            raise _Refused(err.reason) from None
        if int(doc["seq"]) != seq:
            raise _Refused("wrong_seq")
        if self.loaded_seq is not None and seq < self.loaded_seq:
            raise _Refused("rollback")
        return doc

    def _build(self, downloaded: dict[str, Any] | None) -> TrapSet:
        docs = [self._bundled] if self._bundled else []
        source = "bundled"
        if downloaded is not None:
            docs.append(downloaded)
            source = f"bundled+downloaded seq {downloaded['seq']}"
        today = self._today() if self._today else None
        return load_docs(docs, disabled=self.settings.disabled, today=today, source=source)

    # -- the check ---------------------------------------------------------------------------

    def check(self) -> TrapSet | None:
        """A new TrapSet when the downloaded files changed and the result differs, else None."""
        if self._key is None:
            return None
        stamp = self._stamp_now()
        if stamp == self._stamp:
            return None
        self._stamp = stamp
        try:
            doc = self._read_downloaded(self._key)
        except _Refused as err:
            self.refused += 1
            self.last_error = err.reason
            log.warning("trap bundle refused: %s (current set kept)", err.reason)
            return None
        self.last_error = None
        if doc is not None and int(doc["seq"]) < self.bundled_seq:
            log.info("downloaded trap bundle seq %d is older than the image's: ignored", doc["seq"])
            doc = None
        if doc is None:
            if not self.using_downloaded:
                return None  # the bundled packs are already loaded
            log.warning("no usable downloaded trap bundle: bundled packs only")
            self.using_downloaded = False
            self.current = self._build(None)
            return self.current
        seq = int(doc["seq"])
        if self.loaded_seq is None or seq > self.loaded_seq:
            self._write_floor(self._key, seq)
        self.loaded_seq = max(seq, self.loaded_seq or 0)
        self.using_downloaded = True
        self.current = self._build(doc)
        return self.current

    async def run(self, apply: Callable[[TrapSet], None]) -> None:
        """Check now and every ``interval_s``; hand every new set to ``apply``."""
        while True:
            try:
                fresh = await asyncio.to_thread(self.check)
                if fresh is not None:
                    apply(fresh)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("trap pack reload failed (current set kept)")
            await asyncio.sleep(self.settings.interval_s)


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
