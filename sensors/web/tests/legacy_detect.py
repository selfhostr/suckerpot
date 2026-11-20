"""The detection rules that M37 phase 1 moved from ``detect.py`` into trap packs, frozen here
exactly as they were in code. The differential tests compare the sensor with packs against this
reference: the flags, CVEs, the SEVERE decision and the responses must be identical.
"""

from __future__ import annotations

import contextlib
import copy
import weakref
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from web_sensor.config import Config
from web_sensor.detect import Analysis, Detector, decode_bytes
from web_sensor.httpio import Request
from web_sensor.traps import TrapSet, bundled

# SEVERE as it was before the packs.
LEGACY_SEVERE = frozenset(
    {
        "php2shell", "upload_progress", "rce", "php_code", "rfi", "log4shell", "shellshock",
        "phpunit_rce", "laravel_rce", "router_exploit", "webshell_probe", "session_include",
    }
)  # fmt: skip
# The removed lines of _PATH_SIGNATURES (same order and needles).
_LEGACY_PATHS: list[tuple[bytes, str]] = [
    (b"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php", "phpunit_rce"),
    (b"/boaform/", "router_exploit"),
    (b"/gponform/", "router_exploit"),
    (b"/vendor/phpunit", "phpunit_probe"),
]
_ANALYZE = Detector.analyze  # the real method, captured before any test patches it


def legacy_flags(req: Request) -> set[str]:
    """The removed rules, on the same areas the detector builds (copied from the old code)."""
    flags: set[str] = set()
    path_dec = decode_bytes(req.path)
    query_dec = decode_bytes(req.query)
    body_dec = decode_bytes(req.body[:16384].decode("latin-1"), cap=16384) if req.body else b""
    header_blob = bytearray()
    for k, v in req.headers:
        if len(header_blob) > 32 * 1024:
            break
        header_blob += k.encode("latin-1", "replace")[:128] + b": "
        header_blob += v.encode("latin-1", "replace")[:1024] + b"\n"
    orig = path_dec + b"?" + query_dec + b"\n" + body_dec
    orig = orig[: 24 * 1024]
    low = orig.lower()
    hdr_low = bytes(header_blob).lower()
    path_low = path_dec.lower()
    for needle, flag in _LEGACY_PATHS:
        if needle in path_low:
            flags.add(flag)
    if b"${jndi:" in hdr_low or b"${jndi:" in low or b"${${" in low or b"${lower:" in low:
        flags.add("log4shell")
    return flags


class LegacyDetector(Detector):
    """The detector as it was before M37: no packs, the removed rules in code."""

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg, TrapSet.empty())

    def analyze(self, req: Request, src_ip: str) -> Analysis:
        out = _ANALYZE(self, req, src_ip)
        out.flags = sorted(set(out.flags) | legacy_flags(req))
        out.severe_flags = LEGACY_SEVERE
        return out


def view(a: Analysis, severe: frozenset[str]) -> dict[str, Any]:
    """What the rest of the sensor sees of an analysis."""
    return {
        "flags": list(a.flags),
        "cve": list(a.cve),
        "severe": bool(set(a.flags) & severe),
        "downloads": copy.deepcopy(a.downloads),
        "php2shell": copy.deepcopy(a.php2shell),
        "basic_auth": a.basic_auth,
    }


# -- recording the requests of the whole test suite -------------------------------------------


@dataclass
class Call:
    detector: int  # which Detector instance (its php2shell state is per instance)
    cfg: Config
    req: Request
    src_ip: str
    got: dict[str, Any]


CALLS: list[Call] = []
_MAX_CALLS = 20_000


@contextlib.contextmanager
def recording() -> Iterator[None]:
    """Record every request analysed by a detector that runs the bundled packs."""
    ids: weakref.WeakKeyDictionary[Detector, int] = weakref.WeakKeyDictionary()

    def analyze(self: Detector, req: Request, src_ip: str) -> Analysis:
        out = _ANALYZE(self, req, src_ip)
        if self.traps is bundled() and len(CALLS) < _MAX_CALLS:
            key = ids.setdefault(self, len(ids))
            CALLS.append(Call(key, self._cfg, copy.copy(req), src_ip, view(out, self.severe)))
        return out

    Detector.analyze = analyze  # type: ignore[method-assign]
    try:
        yield
    finally:
        Detector.analyze = _ANALYZE  # type: ignore[method-assign]
