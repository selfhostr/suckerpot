"""The automated identity check (design M22, section 7.2).

``guard`` receives the exact artefact about to be returned and answers with constant reason
codes. It never returns, logs or raises the text that matched: a caller can pass a result to a
log, an audit row or an HTTP response without leaking the value that caused it.
"""

from __future__ import annotations

import base64
import binascii
import email
import email.errors
import email.header
import email.policy
import ipaddress
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Final, Literal

from .legacy import legacy_hit
from .normalize import candidates, collapse, is_documentation, is_forbidden_range, skeleton, views
from .terms import DASHBOARD_PATHS, PROJECT_SKELETONS, PROJECT_TERMS, NameTerm, SelfTerms

ArtifactFormat = Literal["text", "xarf", "eml", "json", "csv"]

CODES: Final[tuple[str, ...]] = (
    "self_address",
    "self_name",
    "owner_domain",
    "vpn_address",
    "project_term",
    "private_address",
    "documentation_address",
    "dashboard_path",
    "internal_id",
    "default_wording",
    "no_self_address",
    "self_terms_unavailable",
)


@dataclass(frozen=True)
class GuardContext:
    """Per-report facts the guard needs besides the self terms."""

    internal_ids: frozenset[str] = frozenset()
    allow_documentation: bool = False  # demo reports only


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    codes: tuple[str, ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)

    def merge(self, other: GuardResult) -> GuardResult:
        codes = tuple(sorted(set(self.codes) | set(other.codes)))
        counts: dict[str, int] = dict(self.counts)
        for k, v in other.counts.items():
            counts[k] = counts.get(k, 0) + v
        return GuardResult(ok=self.ok and other.ok, codes=codes, counts=counts)


def _result(counts: Mapping[str, int]) -> GuardResult:
    codes = tuple(sorted(counts))
    return GuardResult(ok=not codes, codes=codes, counts=dict(counts))


# --- name matching -------------------------------------------------------------------------


@lru_cache(maxsize=2048)
def _name_regex(labels: tuple[str, ...]) -> re.Pattern[str]:
    sep = r"(?:[.\-_]|\sdot\s)"
    body = sep.join(re.escape(label) for label in labels)
    return re.compile(rf"(?<![a-z0-9]){body}(?![a-z0-9])")


def _name_hit(term: NameTerm, *haystacks: str) -> bool:
    # Single-label names (``srv-web01``) are matched as whole words, dotted ones by labels.
    rx = _name_regex(term.labels)
    return any(rx.search(h) for h in haystacks)


# --- scanning one string -------------------------------------------------------------------


def scan_text(text: str, terms: SelfTerms, ctx: GuardContext, counts: dict[str, int]) -> None:
    """Add a count to ``counts`` for every kind of leak found in ``text``."""

    def hit(code: str) -> None:
        counts[code] = counts.get(code, 0) + 1

    for view in views(text):
        lowered = view.casefold()
        skel = skeleton(view)
        _scan_addresses(view, terms, ctx, hit)
        for needle, code in terms.b64_needles:
            if needle in view:
                hit(code)
        for term in terms.names:
            if _name_hit(term, lowered, skel):
                hit(term.code)
        for plain in terms.texts:
            if plain in lowered or plain in skel:
                hit("self_name")
        for line in skel.splitlines() or [skel]:
            flat = collapse(line)
            if any(p in flat for p in PROJECT_SKELETONS):
                hit("project_term")
        if any(path in lowered for path in DASHBOARD_PATHS):
            hit("dashboard_path")
        for internal in ctx.internal_ids:
            needle = internal.casefold()
            if len(needle) >= 8 and needle in lowered:
                hit("internal_id")


def _scan_addresses(view: str, terms: SelfTerms, ctx: GuardContext, hit: Any) -> None:
    for cand in candidates(view):
        classify = cand.judged(view)
        for addr in cand.embedded():
            code = terms.is_self(addr)
            if code is not None:
                hit(code)
            elif classify:
                if is_documentation(addr):
                    if not ctx.allow_documentation:
                        hit("documentation_address")
                elif is_forbidden_range(addr):
                    hit("private_address")


# --- artefact -> strings -------------------------------------------------------------------


def _decode(data: bytes) -> Iterator[str]:
    yield data.decode("utf-8", errors="replace")
    if b"\x00" in data:
        yield data.decode("utf-16-le", errors="replace")
        yield data.decode("utf-16-be", errors="replace")


def _walk_json(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, Mapping):
        for k, v in node.items():
            yield str(k)
            yield from _walk_json(v)
    elif isinstance(node, Sequence) and not isinstance(node, bytes | bytearray):
        for item in node:
            yield from _walk_json(item)


# Base64 hidden in a JSON value (an XARF ``evidence[].payload``, or anything else) is decoded and
# scanned too, so it cannot carry a leak past the guard (design M38, section 4.6).
_B64: Final = re.compile(r"^[A-Za-z0-9+/\s]+={0,2}$")
B64_MIN: Final = 8
B64_DEPTH: Final = 2
B64_MAX_BYTES: Final = 2_000_000


def _b64_decoded(value: str) -> bytes | None:
    """The bytes of a base64 string (standard or URL-safe alphabet), or None."""
    compact = "".join(value.split())
    if len(compact) < B64_MIN or len(compact) > B64_MAX_BYTES:
        return None
    candidates = [compact]
    if "-" in compact or "_" in compact:
        candidates.append(compact.replace("-", "+").replace("_", "/"))
    for text in candidates:
        padded = text + "=" * (-len(text) % 4)
        if not _B64.fullmatch(padded):
            continue
        try:
            return base64.b64decode(padded, validate=True)
        except binascii.Error, ValueError:
            continue
    return None


def _json_views(node: object, depth: int = 0) -> Iterator[str]:
    """Every string of a JSON document, plus the decoded text of each base64 value (and of base64
    or JSON inside that, ``B64_DEPTH`` levels deep)."""
    for text in _walk_json(node):
        yield text
        if depth >= B64_DEPTH:
            continue
        data = _b64_decoded(text)
        if data is None:
            continue
        for decoded in _decode(data):
            yield decoded
            stripped = decoded.strip()
            if stripped[:1] in ("{", "["):
                try:
                    yield from _json_views(json.loads(stripped), depth + 1)
                except ValueError:
                    pass
            else:
                yield from _json_views(stripped, depth + 1)


def _mime_strings(raw: bytes) -> Iterator[str]:
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    for part in msg.walk():
        for name, value in part.items():
            yield name
            try:
                decoded = str(email.header.make_header(email.header.decode_header(str(value))))
            except email.errors.HeaderParseError, UnicodeDecodeError, LookupError, ValueError:
                decoded = str(value)
            yield decoded
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            yield text
            if part.get_content_type() == "application/json":
                try:
                    yield from _json_views(json.loads(text))
                except ValueError:
                    pass


def artefact_strings(
    artifact: str | bytes | Mapping[str, Any] | Sequence[Any], fmt: str
) -> Iterator[str]:
    """Every string view of an artefact: raw, JSON-unescaped (with base64 values decoded),
    MIME-decoded (a JSON part walked the same way)."""
    if isinstance(artifact, str | bytes):
        raw = artifact.encode("utf-8") if isinstance(artifact, str) else artifact
        yield from _decode(raw)
        if fmt == "json":
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
            except ValueError:
                return
            yield from _json_views(parsed)
        elif fmt == "eml":
            yield from _mime_strings(raw)
    else:
        yield json.dumps(artifact, ensure_ascii=False, default=str)
        yield from _json_views(artifact)


def guard(
    artifact: str | bytes | Mapping[str, Any] | Sequence[Any],
    terms: SelfTerms | None,
    *,
    fmt: ArtifactFormat = "text",
    ctx: GuardContext | None = None,
) -> GuardResult:
    """Check one artefact. ``ok`` only when nothing identifying was found.

    ``terms=None`` means the deny set could not be loaded: the answer is a failure.
    """
    if terms is None:
        return _result({"self_terms_unavailable": 1})
    context = ctx or GuardContext()
    counts: dict[str, int] = {}
    if not terms.has_self_address:
        counts["no_self_address"] = 1
    for text in artefact_strings(artifact, fmt):
        scan_text(text, terms, context, counts)
        if legacy_hit(text):
            counts["default_wording"] = counts.get("default_wording", 0) + 1
    return _result(counts)


# --- messages, bundles and binary samples --------------------------------------------------


def guard_parts(
    parts: Sequence[tuple[str, str | bytes, ArtifactFormat]],
    terms: SelfTerms | None,
    *,
    ctx: GuardContext | None = None,
) -> GuardResult:
    """Guard several artefacts (``name, content, format``) and merge the answers."""
    if terms is None:
        return _result({"self_terms_unavailable": 1})
    out = _result({}) if terms.has_self_address else _result({"no_self_address": 1})
    for name, content, fmt in parts:
        out = out.merge(guard(content, terms, fmt=fmt, ctx=ctx))
        out = out.merge(guard(name, terms, fmt="text", ctx=ctx))
    return out


def scan_binary(data: bytes, terms: SelfTerms) -> tuple[str, ...]:
    """Reason codes for a sample's bytes (never the value).

    Self terms are searched as ASCII and UTF-16LE text; addresses also as dash/underscore
    forms, decimal and hex integers, packed 4-byte (and 16-byte IPv6) big and little endian,
    and the base64 fragments of the text forms; names also as base64 fragments.
    """
    lowered = data.lower()
    found: set[str] = set()

    def present(needle: str) -> bool:
        raw = needle.lower().encode("ascii", errors="ignore")
        if not raw:
            return False
        return raw in lowered or raw.decode("ascii").encode("utf-16-le") in lowered

    for key in terms.addresses | terms.vpn_addresses:
        code = "vpn_address" if key in terms.vpn_addresses else "self_address"
        addr = ipaddress.ip_address(key)
        forms = {key, key.replace(".", "-"), key.replace(".", "_")}
        raw_forms: set[bytes] = {addr.packed}
        if isinstance(addr, ipaddress.IPv4Address):
            forms |= {str(int(addr)), f"0x{int(addr):08x}", f"{int(addr):08x}"}
            raw_forms.add(addr.packed[::-1])
        if any(present(f) for f in forms) or any(r in data for r in raw_forms):
            found.add(code)
    for needle, code in terms.b64_needles:
        if needle.encode("ascii") in data:
            found.add(code)
    for term in terms.names:
        if present(term.value):
            found.add(term.code)
    if any(present(t) for t in terms.texts):
        found.add("self_name")
    if any(present(p) for p in PROJECT_TERMS):
        found.add("project_term")
    return tuple(sorted(found))
