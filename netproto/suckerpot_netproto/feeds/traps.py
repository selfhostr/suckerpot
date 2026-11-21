"""Signed trap pack bundles (design M37 section 5): signing and verification of ``traps.json``.

The bundle is one JSON file, ``{"schema": "suckerpot-traps/1", "seq": N, ...}``, signed with
minisign (pre-hashed Ed25519) by the dedicated pack key. The trusted comment is exactly
``suckerpot-traps seq=<N>`` and must name the ``seq`` of the file itself, so a signature can never
be moved to another bundle. ``seq`` only goes up: a verifier that knows the last accepted value
refuses a lower one.

This module checks the signature, the size and the envelope (schema and ``seq``). It does not
validate the packs: that is ``suckerpot_common.traps`` (ingest and the sensors). The hub only
relays the bytes, unchanged. Pure functions, no I/O.
"""

from __future__ import annotations

import json
from typing import Final

from . import minisign
from .errors import FeedError

FILE: Final = "traps.json"
SCHEMA: Final = "suckerpot-traps/1"
MAX_BYTES: Final = 1024 * 1024  # the same cap as the sensors' loader
MAX_DEPTH: Final = 16
MAX_SEQ: Final = 2**53
COMMENT_PREFIX: Final = "suckerpot-traps seq="


def trusted_comment(seq: int) -> str:
    return f"{COMMENT_PREFIX}{seq}"


def parse_comment(text: str) -> int:
    """The ``seq`` of a trusted comment ``suckerpot-traps seq=<N>``, or FeedError."""
    if not text.startswith(COMMENT_PREFIX):
        raise FeedError("bad_format", "not a trap bundle signature")
    digits = text[len(COMMENT_PREFIX) :]
    if not 1 <= len(digits) <= 16 or not digits.isascii() or not digits.isdigit():
        raise FeedError("bad_format", "trap bundle seq")
    if digits != str(int(digits)):
        raise FeedError("bad_format", "trap bundle seq has leading zeros")
    seq = int(digits)
    if seq > MAX_SEQ:
        raise FeedError("bad_format", "trap bundle seq")
    return seq


def _depth_ok(data: bytes) -> bool:
    depth = 0
    in_str = escaped = False
    for b in data:
        if in_str:
            if escaped:
                escaped = False
            elif b == 0x5C:
                escaped = True
            elif b == 0x22:
                in_str = False
        elif b == 0x22:
            in_str = True
        elif b in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif b in (0x5D, 0x7D):
            depth -= 1
    return True


def bundle_seq(data: bytes) -> int:
    """The ``seq`` of a bundle file after the envelope checks (size, depth, schema)."""
    if len(data) > MAX_BYTES:
        raise FeedError("too_large", "trap bundle over 1 MiB")
    if not _depth_ok(data):
        raise FeedError("bad_format", "trap bundle nests too deep")
    try:
        doc = json.loads(data)
    except ValueError, RecursionError:
        raise FeedError("bad_format", "trap bundle is not JSON") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise FeedError("bad_format", "trap bundle schema")
    seq = doc.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq <= MAX_SEQ:
        raise FeedError("bad_format", "trap bundle seq")
    return seq


def sign_bundle(data: bytes, secret: minisign.SecretKey) -> str:
    """The ``.minisig`` text for a bundle; the trusted comment carries the bundle's own seq."""
    seq = bundle_seq(data)
    return minisign.sign(
        data, secret, trusted_comment(seq), untrusted_comment="suckerpot trap pack bundle"
    )


def verify_bundle(
    data: bytes, sig_text: str, public: minisign.PublicKey, *, last_seq: int | None = None
) -> int:
    """Verify a bundle and return its ``seq``. Raises FeedError: ``wrong_key`` (another key),
    ``bad_signature`` (forged or altered), ``wrong_serial`` (the signed seq is not the file's),
    ``rollback`` (lower than ``last_seq``), ``too_large`` or ``bad_format``. The same seq as
    ``last_seq`` is accepted (the same bundle fetched again)."""
    if len(data) > MAX_BYTES:
        raise FeedError("too_large", "trap bundle over 1 MiB")
    signed = parse_comment(minisign.verify(data, sig_text, public))
    seq = bundle_seq(data)
    if seq != signed:
        raise FeedError("wrong_serial", "signature belongs to another seq")
    if last_seq is not None and seq < last_seq:
        raise FeedError("rollback", "trap bundle seq lower than the last accepted one")
    return seq
