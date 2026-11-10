"""Per-deployment identity, derived from a random secret kept under the data directory.

The secret is generated once (mode 0600). The server version string and the digest nonces are
derived from it with HMAC, so deployments differ and nothing can be predicted from public data.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("sip_sensor.identity")

SECRET_FILE = "profile_secret"  # noqa: S105 - a file name, not a secret
# chan_sip era releases only: Asterisk 20 deprecated chan_sip and answers with PJSIP.
VERSIONS = (
    "13.38.3", "16.19.0", "16.24.1", "16.26.1", "16.27.0", "16.28.0", "16.29.1", "16.30.0",
    "16.30.1", "18.12.1", "18.15.1", "18.16.0", "18.17.1", "18.18.1", "18.19.0", "18.20.0",
    "18.20.2", "18.21.0", "18.21.1", "18.22.0", "18.23.1", "18.24.0", "18.24.1", "18.24.2",
    "18.25.0", "18.26.0",
)  # fmt: skip
# A FreePBX box announces itself as FPBX-<freepbx>(<asterisk>): major 15 ships Asterisk 16,
# major 16 ships Asterisk 18, so the pair is always drawn from one generation.
_FPBX = (("15.0", (17, 23), "16."), ("16.0", (33, 44), "18."))
NONCE_BUCKET = 120  # seconds; a nonce is valid in its bucket and the next one


def write_private(path: Path, data: bytes) -> None:
    """Atomically write ``data`` with mode 0600."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    tmp.replace(path)


def load_or_create_secret(directory: str | Path) -> str:
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / SECRET_FILE
    try:
        value = path.read_text().strip()
    except OSError:
        value = ""
    if len(value) < 32:
        value = secrets.token_hex(32)
        write_private(path, (value + "\n").encode())
        log.warning("generated new profile secret in %s (persist the data volume)", root)
    return value


@dataclass(frozen=True)
class Profile:
    secret: str
    user_agent: str
    realm: str

    def _mac(self, label: str) -> bytes:
        return hmac.new(self.secret.encode(), label.encode(), hashlib.sha256).digest()

    def _nonce_for(self, ip: str, bucket: int) -> str:
        return self._mac(f"nonce/{ip}/{bucket}").hex()[:8]

    def nonce(self, ip: str, now: float | None = None) -> str:
        """Stateless chan_sip-style nonce: 8 hex digits, HMAC(secret, ip, time bucket)."""
        bucket = int((time.time() if now is None else now) // NONCE_BUCKET)
        return self._nonce_for(ip, bucket)

    def nonce_valid(self, nonce: str, ip: str, now: float | None = None) -> bool:
        """Valid for the current and the previous time bucket (2 to 4 minutes)."""
        if len(nonce) != 8:
            return False
        bucket = int((time.time() if now is None else now) // NONCE_BUCKET)
        return any(hmac.compare_digest(nonce, self._nonce_for(ip, b)) for b in (bucket, bucket - 1))


def derive_profile(secret: str, user_agent: str = "", realm: str = "asterisk") -> Profile:
    if not user_agent:
        digest = hashlib.sha256(secret.encode()).digest()
        if digest[1] % 10 < 3:
            major, (low, high), series = _FPBX[digest[2] % len(_FPBX)]
            asterisk = [v for v in VERSIONS if v.startswith(series)]
            user_agent = (
                f"FPBX-{major}.{low + digest[3] % (high - low + 1)}"
                f"({asterisk[digest[4] % len(asterisk)]})"
            )
        else:
            user_agent = f"Asterisk PBX {VERSIONS[digest[0] % len(VERSIONS)]}"
    return Profile(secret=secret, user_agent=user_agent, realm=realm)


def load_profile(directory: str | Path, user_agent: str = "", realm: str = "asterisk") -> Profile:
    return derive_profile(load_or_create_secret(directory), user_agent, realm)
