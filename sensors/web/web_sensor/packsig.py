"""Verification of the signed trap pack bundle (M37 P2), inside the sensor.

The sensor checks the minisign signature of ``active.json`` itself, with the pack public key it
gets from the release (``TRAP_PACK_KEY``). Ingest also checks it, but a compromised ingest must
not be able to give the sensor a trap: only a bundle signed by the pack key loads.

Only what the bundle uses is accepted: a pre-hashed (``ED``) minisign signature, Ed25519 over the
BLAKE2b-512 of the file, and the trusted comment ``suckerpot-traps seq=<N>``. Verify only; this
module holds no secret and touches no file. No regular expressions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_SIG_BYTES = 1024
COMMENT_PREFIX = "suckerpot-traps seq="
_UNTRUSTED = "untrusted comment: "
_TRUSTED = "trusted comment: "


class SignatureError(ValueError):
    """``code``: bad_key, bad_format, wrong_key or bad_signature."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class PublicKey:
    key_id: bytes
    raw: bytes


def _b64(text: str, length: int, code: str) -> bytes:
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error, ValueError:
        raise SignatureError(code) from None
    if len(raw) != length:
        raise SignatureError(code)
    return raw


def parse_key(text: str) -> PublicKey:
    """The ``RW...`` public key string."""
    text = text.strip()
    if not text or len(text) > 128 or not text.isascii():
        raise SignatureError("bad_key")
    raw = _b64(text, 42, "bad_key")
    if raw[:2] != b"Ed":
        raise SignatureError("bad_key")
    return PublicKey(raw[2:10], raw[10:])


def _printable(line: str) -> bool:
    return all(" " <= c <= "~" for c in line)


def verify(data: bytes, sig_text: str, key: PublicKey) -> int:
    """Verify the signature of a bundle and return the ``seq`` named by its trusted comment."""
    if len(sig_text) > MAX_SIG_BYTES or not sig_text.isascii():
        raise SignatureError("bad_format")
    lines = sig_text.split("\n")
    if len(lines) == 5 and lines[4] == "":
        lines = lines[:4]
    if len(lines) != 4 or not lines[0].startswith(_UNTRUSTED) or not lines[2].startswith(_TRUSTED):
        raise SignatureError("bad_format")
    if not _printable(lines[0]) or not _printable(lines[2]):
        raise SignatureError("bad_format")
    sig = _b64(lines[1], 74, "bad_format")
    if sig[:2] != b"ED":  # the legacy whole-file algorithm is refused
        raise SignatureError("bad_format")
    if sig[2:10] != key.key_id:
        raise SignatureError("wrong_key")
    comment = lines[2][len(_TRUSTED) :]
    global_sig = _b64(lines[3], 64, "bad_format")
    try:
        pub = Ed25519PublicKey.from_public_bytes(key.raw)
        pub.verify(sig[10:], hashlib.blake2b(data, digest_size=64).digest())
        pub.verify(global_sig, sig[10:] + comment.encode("ascii"))
    except InvalidSignature, ValueError:
        raise SignatureError("bad_signature") from None
    digits = comment[len(COMMENT_PREFIX) :] if comment.startswith(COMMENT_PREFIX) else ""
    if not 1 <= len(digits) <= 16 or not digits.isdigit() or digits != str(int(digits)):
        raise SignatureError("bad_format")
    return int(digits)
