"""The quarantine store: sha256-named files, mode 0400, never executable.

Layout (docs/dev/design/m21.md section 5.5)::

    <root>/.incoming/<random>        temp files, same filesystem, wiped at start
    <root>/ab/cd/abcd...<64 hex>     final files, no extension, ever

A file is written to a temp name, hashed while it streams, aborted and unlinked past the size cap,
synced, set to 0400 and only then linked to its final name. If the final name exists the temp file
is dropped (dedupe). Nothing in this module ever executes, imports or opens a stored file as code.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INCOMING = ".incoming"
DIR_MODE = 0o700
FILE_MODE = 0o400


class TooLarge(Exception):
    """The body went past the size limit while streaming."""


@dataclass(frozen=True)
class StoredFile:
    sha256: str
    sha1: str
    md5: str
    size: int
    path: Path
    new: bool  # False: the same bytes were already in quarantine


class TempFile:
    """One download in progress. Use as a context manager; unlinks itself unless committed."""

    def __init__(self, path: Path, limit: int) -> None:
        self.path = path
        self.limit = limit
        self.size = 0
        self._sha256 = hashlib.sha256()
        self._sha1 = hashlib.sha1(usedforsecurity=False)
        self._md5 = hashlib.md5(usedforsecurity=False)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        self._fd: int | None = os.open(path, flags, 0o600)
        self.committed = False

    def write(self, chunk: bytes) -> None:
        if self._fd is None:
            raise ValueError("temp file is closed")
        self.size += len(chunk)
        if self.size > self.limit:
            raise TooLarge
        view = memoryview(chunk)
        while view:
            written = os.write(self._fd, view)
            view = view[written:]
        self._sha256.update(chunk)
        self._sha1.update(chunk)
        self._md5.update(chunk)

    def digests(self) -> tuple[str, str, str]:
        return self._sha256.hexdigest(), self._sha1.hexdigest(), self._md5.hexdigest()

    def seal(self) -> None:
        """Flush to disk and drop to 0400 (read-only for the owner, no execute bit)."""
        if self._fd is None:
            return
        os.fsync(self._fd)
        os.fchmod(self._fd, FILE_MODE)
        os.close(self._fd)
        self._fd = None

    def abort(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None
        if not self.committed:
            with contextlib.suppress(FileNotFoundError):
                self.path.unlink()

    def __enter__(self) -> TempFile:
        return self

    def __exit__(self, *exc: object) -> None:
        self.abort()


class Quarantine:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.incoming = root / INCOMING

    def prepare(self) -> None:
        """Create the directories and wipe leftovers of a crashed download."""
        self.root.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        self.incoming.mkdir(mode=DIR_MODE, exist_ok=True)
        for leftover in self.incoming.iterdir():
            with contextlib.suppress(OSError):
                if leftover.is_dir() and not leftover.is_symlink():
                    continue  # never recurse into something unexpected
                leftover.unlink()

    def path_for(self, sha256: str) -> Path:
        if not SHA256_RE.match(sha256):
            raise ValueError("not a sha256")
        return self.root / sha256[:2] / sha256[2:4] / sha256

    def open_temp(self, limit: int) -> TempFile:
        return TempFile(self.incoming / secrets.token_hex(16), limit)

    def commit(self, temp: TempFile) -> StoredFile:
        """Move a finished temp file to its sha256 name. Idempotent for identical content."""
        temp.seal()
        sha256, sha1, md5 = temp.digests()
        final = self.path_for(sha256)
        final.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        new = True
        try:
            os.link(temp.path, final)  # fails if it exists: no overwrite, no race
        except FileExistsError:
            new = False
        with contextlib.suppress(FileNotFoundError):
            temp.path.unlink()
        temp.committed = True
        return StoredFile(sha256, sha1, md5, temp.size, final, new)

    def read(self, sha256: str, max_bytes: int) -> bytes:
        """Read a stored file as data (never a path handed to an exec call)."""
        path = self.path_for(sha256)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            size = os.fstat(fd).st_size
            if size > max_bytes:
                raise TooLarge
            chunks: list[bytes] = []
            remaining = size
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def remove(self, sha256: str) -> bool:
        try:
            self.path_for(sha256).unlink()
        except FileNotFoundError:
            return False
        return True
