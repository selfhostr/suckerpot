"""Parsing hostile mail (design M26, section 5). Pure: bytes in, a frozen dataclass out.

Everything here assumes the message was written by an attacker. The limits are fixed, the walk
is iterative, nothing is executed, rendered or followed:

* the input is cut at ``max_bytes`` before anything reads it;
* the parser is ``email`` with the legacy ``compat32`` policy (no structured header objects);
* at most 200 header lines, 4 KiB per header value, 50 MIME parts, depth 5;
* only text parts are decoded (each capped at 128 KiB); attachments are counted, never decoded,
  and their file names are not kept;
* HTML is only ever turned into plain text (tags dropped, ``script`` and ``style`` skipped);
* a charset outside a short allow-list is read as UTF-8 with replacement characters;
* the stored excerpt has no control, zero-width or bidirectional characters.

``get_payload(decode=True)`` is called only in this module (a static test enforces it).
"""

from __future__ import annotations

import codecs
import contextlib
import email.header
import email.parser
import email.policy
import email.utils
import hashlib
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import Message
from html.parser import HTMLParser
from typing import Any, Final

MAX_HEADER_LINES: Final = 200
MAX_HEADER_VALUE: Final = 4096
MAX_PARTS: Final = 50
MAX_DEPTH: Final = 5
MAX_PART_BYTES: Final = 128 * 1024
MAX_SUBJECT: Final = 300
MAX_IDS: Final = 20
MAX_ID_LEN: Final = 255
BODY_FOR_RULES: Final = 8192
DEFAULT_EXCERPT_CHARS: Final = 2000
MAX_TYPES: Final = 10
MAX_TYPE_LEN: Final = 64
MAX_ATTACHMENTS_JSON: Final = 2048  # the column's CHECK
MAX_ADDRESS: Final = 254
MAX_DOMAIN: Final = 253
MAX_EXCERPT: Final = 2000

_CHARSETS: Final = (
    ["utf-8", "us-ascii", "ascii", "latin-1", "koi8-r", "gb2312", "gbk", "gb18030", "big5"]
    + ["shift_jis", "euc-jp", "iso-2022-jp", "euc-kr"]
    + [f"iso-8859-{n}" for n in range(1, 16) if n != 12]
    + [f"windows-125{n}" for n in range(0, 9)]
    + [f"cp125{n}" for n in range(0, 9)]
)


def _canonical(name: str) -> str | None:
    try:
        return codecs.lookup(name).name
    except LookupError, ValueError:
        return None


ALLOWED_CHARSETS: Final = frozenset(c for c in map(_canonical, _CHARSETS) if c)

_MAILBOX: Final = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")
_MIME_TYPE: Final = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+\-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+\-]{0,62}$"
)
_ID: Final = re.compile(rf"<([^<>\s]{{1,{MAX_ID_LEN}}})>")
_STATUS: Final = re.compile(r"^[245]\.\d{1,3}\.\d{1,3}$")
_BLANKS: Final = re.compile(r"\n{3,}")
_SPACES: Final = re.compile(r"[ \t]+\n")
# The rule of the "Mail provider name" field (the API and the web form use the same one).
_AUTHSERV_OK: Final = re.compile(r"^[a-z0-9.\-]{1,255}$")
_WROTE: Final = re.compile(r"^(on .{1,200} )?(wrote|schrieb|a écrit|escribió|schreef):\s*$", re.I)

_BREAKS: Final = "\r\n\t\x0b\x0c\x85" + chr(0x2028) + chr(0x2029)
BLOCK_TAGS: Final = frozenset(
    {"br", "p", "div", "tr", "li", "table", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"}
)

# The headers the IMAP search fetches; the parser reads the same ones.
HEADER_FIELDS: Final = (
    "FROM SUBJECT DATE MESSAGE-ID IN-REPLY-TO REFERENCES AUTO-SUBMITTED PRECEDENCE "
    "X-AUTOREPLY X-AUTORESPOND CONTENT-TYPE AUTHENTICATION-RESULTS RETURN-PATH"
)


@dataclass(frozen=True, slots=True)
class ParsedReply:
    """What the rest of the pipeline may know about one incoming mail."""

    from_address: str | None = None
    from_domain: str | None = None
    from_local: str | None = None
    subject: str = ""
    sent_at: datetime | None = None
    message_id_sha256: str | None = None
    reference_ids: tuple[str, ...] = ()  # In-Reply-To then References, as "<id>"
    has_in_reply_to: bool = False
    auth: str = "none"  # pass | fail | none
    auto_submitted: str | None = None
    precedence: str | None = None
    x_autoreply: str | None = None
    x_autorespond: str | None = None
    content_type: str = ""
    report_type: str | None = None
    dsn_action: str | None = None
    dsn_status: str | None = None
    dsn_domain: str | None = None
    dsn_message_id: str | None = None  # the original mail's Message-ID, "<id>"
    dsn_subject: str | None = None
    body: str = ""
    excerpt: str = ""
    attachments: dict[str, Any] = field(default_factory=dict)
    size_bytes: int = 0
    truncated: bool = False


# --- text helpers --------------------------------------------------------------------------


def clean_text(value: str, *, keep_newlines: bool) -> str:
    """NFKC, then drop control characters (keeping ``\\n`` and ``\\t`` if asked), zero-width
    and bidirectional characters, and surrogates."""
    value = unicodedata.normalize("NFKC", value)
    keep = {"\n", "\t"} if keep_newlines else set()
    out = []
    for ch in value:
        cat = unicodedata.category(ch)
        if ch in keep:
            out.append(ch)
        elif cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            out.append(" " if ch in _BREAKS else "")
        else:
            out.append(ch)
    return "".join(out)


def _decode(data: bytes, charset: str | None) -> str:
    name = _canonical(charset) if charset else None
    if name not in ALLOWED_CHARSETS:
        name = "utf-8"
    return data.decode(name or "utf-8", errors="replace")


def _header_text(value: object) -> str:
    """One header value as text, cut at 4 KiB; bad encodings are replaced. Raw 8-bit bytes
    (which ``compat32`` hands back as a ``Header``) are read as UTF-8."""
    try:
        pieces = email.header.decode_header(
            value if isinstance(value, email.header.Header) else str(value)[:MAX_HEADER_VALUE]
        )
    except Exception:
        return str(value)[:MAX_HEADER_VALUE]
    out: list[str] = []
    for part, charset in pieces:
        if isinstance(part, bytes):
            out.append(_decode(part, charset if isinstance(charset, str) else None))
        else:
            out.append(part)
    return "".join(out)[:MAX_HEADER_VALUE]


def _header(msg: Message, name: str) -> str | None:
    value = msg.get(name)
    if value is None:
        return None
    return _header_text(value)


def _ids(*values: str | None) -> tuple[str, ...]:
    """Message-ID tokens (``<id>``), up to 20. The newest references come last: keep those."""
    found: list[str] = []
    for value in values:
        if value:
            found.extend(f"<{m}>" for m in _ID.findall(value[:MAX_HEADER_VALUE]))
    unique = list(dict.fromkeys(found))
    return tuple(unique[-MAX_IDS:])


def _bounded_headers(raw: bytes) -> bytes:
    """The header block cut at 200 lines (continuation lines count)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        pos = raw.find(sep)
        if pos != -1:
            head, rest = raw[:pos], raw[pos + len(sep) :]
            break
    else:
        head, rest = raw, b""
    lines = head.splitlines()
    if len(lines) <= MAX_HEADER_LINES:
        return raw
    return b"\r\n".join(lines[:MAX_HEADER_LINES]) + b"\r\n\r\n" + rest


def _parse(raw: bytes, *, headers_only: bool) -> Message:
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    return parser.parsebytes(_bounded_headers(raw), headersonly=headers_only)


# --- addresses and authentication ----------------------------------------------------------


def _from(msg: Message) -> tuple[str | None, str | None, str | None]:
    value = msg.get("From")
    if value is None:
        return None, None, None
    try:
        address = email.utils.parseaddr(_header_text(value)[:MAX_HEADER_VALUE])[1].strip()
    except Exception:
        return None, None, None
    if not _MAILBOX.match(address):
        return None, None, None
    local, _, domain = address.rpartition("@")
    domain = domain.lower()
    if len(address) > MAX_ADDRESS or len(domain) > MAX_DOMAIN:
        return None, None, None  # longer than the columns: unknown sender, never a poison pill
    return f"{local}@{domain}", domain, local.lower()


def _split(value: str, separators: str) -> list[str]:
    """Split on ``separators`` outside quoted strings and ``(comments)``; comments are dropped
    and quotes kept. A separator inside quotes or a comment never ends a segment."""
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    for ch in value:
        if quoted:
            cur.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif depth:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
        elif ch == "(":
            depth = 1
        elif ch == '"':
            quoted = True
            cur.append(ch)
        elif ch in separators:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


def _aligned(domain: str | None, from_domain: str) -> bool:
    if not domain:
        return False
    d = _unquote(domain).strip().lower().strip(".")
    return d == from_domain or from_domain.endswith("." + d) or d.endswith("." + from_domain)


def _authserv_id(header: str) -> str:
    """The authserv-id: the first token before the first ``;`` (RFC 8601), lower case."""
    first = _split(header, ";")[0].split()
    return _unquote(first[0]).lower() if first else ""


def authentication(
    values: Sequence[str] | str | None, from_domain: str | None, trusted_authserv_id: str | None
) -> str:
    """``pass`` when Authentication-Results says DMARC or DKIM passed for a domain aligned with
    From, ``fail`` on ``dmarc=fail``, else ``none``.

    Anyone can write that header. Only the first one (the topmost is the one our own mailbox
    provider added last) whose authserv-id is the owner's trusted id is read, and without a
    trusted id the answer is always ``none``."""
    trusted = (trusted_authserv_id or "").strip().lower()
    if isinstance(values, str):
        values = [values]
    if not values or not from_domain or not trusted:
        return "none"
    header = next((v for v in values if _authserv_id(v[:MAX_HEADER_VALUE]) == trusted), None)
    if header is None:
        return "none"
    verdict = "none"
    for clause in _split(header[:MAX_HEADER_VALUE], ";")[1:]:
        tokens = [t for t in _split(clause, " \t\r\n") if t]
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        method, result = method.lower(), result.lower()
        props = {k.lower(): v for k, _, v in (t.partition("=") for t in tokens[1:] if "=" in t)}
        if method == "dmarc" and result == "fail":
            if verdict != "pass":
                verdict = "fail"
        elif (
            method == "dmarc"
            and result == "pass"
            and _aligned(props.get("header.from"), from_domain)
        ) or (
            method == "dkim" and result == "pass" and _aligned(props.get("header.d"), from_domain)
        ):
            verdict = "pass"
    return verdict


HINT_MIN_MESSAGES: Final = 3  # a suggested name is on at least this many messages
HINT_MIN_DOMAINS: Final = 3  # from at least this many sender domains


def authserv_sample(raw: bytes) -> tuple[str, str]:
    """(authserv-id of the top-most Authentication-Results header, sender domain) of a header
    block, each ``""`` when missing.

    Only the top-most header counts: it is the one the owner's own provider added last, and a
    sender can write any number of lower ones. A value that is not a valid provider name (the
    rule of the settings field) is dropped, so raw header text never leaves this function.
    Never raises."""
    try:
        msg = _parse(raw[: 64 * 1024], headers_only=True)
        domain = _from(msg)[1] or ""
        value = msg.get("Authentication-Results")
        found = "" if value is None else _authserv_id(_header_text(value)[:MAX_HEADER_VALUE])
    except Exception:
        return "", ""
    return (found if _AUTHSERV_OK.match(found) else ""), domain


def top_authserv_id(raw: bytes) -> str | None:
    """The valid authserv-id of the top-most Authentication-Results header, or None."""
    return authserv_sample(raw)[0] or None


def authserv_hint(samples: Iterable[tuple[str, str]]) -> dict[str, Any] | None:
    """The most common top-most authserv-id over some (name, sender domain) samples, as
    ``{"id": name, "seen": messages with it, "of": messages read}``.

    If the provider adds no header of its own, the top-most one is whatever a sender wrote. So a
    name is only suggested when it is on at least 3 messages from at least 3 sender domains, and
    on at least half of the messages read. Otherwise None."""
    seen: Counter[str] = Counter()
    domains: dict[str, set[str]] = {}
    total = 0
    for name, domain in samples:
        total += 1
        if name:
            seen[name] += 1
            if domain:
                domains.setdefault(name, set()).add(domain)
    if not seen:
        return None
    best, count = seen.most_common(1)[0]
    if count < HINT_MIN_MESSAGES or len(domains.get(best, ())) < HINT_MIN_DOMAINS:
        return None
    if count * 2 < total:
        return None
    return {"id": best, "seen": count, "of": total}


def message_id_hash(value: str | None) -> str | None:
    if not value:
        return None
    ids = _ID.findall(value[:MAX_HEADER_VALUE])
    key = ids[0] if ids else value.strip()
    if not key:
        return None
    return hashlib.sha256(key.lower().encode("utf-8", "replace")).hexdigest()


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(value[:MAX_HEADER_VALUE])
    except TypeError, ValueError, IndexError, OverflowError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    try:
        return parsed.astimezone(UTC)
    except OverflowError, ValueError:
        return None


# --- the header-only view (what the relevance check sees) ----------------------------------


@dataclass(frozen=True, slots=True)
class HeaderView:
    from_address: str | None
    from_domain: str | None
    from_local: str | None
    subject: str
    reference_ids: tuple[str, ...]
    content_type: str
    looks_like_dsn: bool


def parse_headers(raw: bytes) -> HeaderView:
    """Headers only. Never raises."""
    try:
        msg = _parse(raw[: 64 * 1024], headers_only=True)
        address, domain, local = _from(msg)
        ctype = (msg.get_content_type() or "").lower()
        subject = clean_text(_header(msg, "Subject") or "", keep_newlines=False).strip()
        return HeaderView(
            from_address=address,
            from_domain=domain,
            from_local=local,
            subject=subject[:MAX_SUBJECT],
            reference_ids=_ids(_header(msg, "In-Reply-To"), _header(msg, "References")),
            content_type=ctype,
            looks_like_dsn=ctype == "multipart/report" or local in ("mailer-daemon", "postmaster"),
        )
    except Exception:
        return HeaderView(None, None, None, "", (), "", False)


# --- bodies --------------------------------------------------------------------------------


class _Text(HTMLParser):
    """Visible text of an HTML part. Nothing is rendered, no URL is kept."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _Text()
    with contextlib.suppress(Exception):  # broken markup: keep what was read
        parser.feed(html[:MAX_PART_BYTES])
        parser.close()
    return "".join(parser.parts)


def _payload(part: Message) -> bytes:
    """The decoded payload of a text part, capped. Only this module decodes (O3)."""
    try:
        data = part.get_payload(decode=True)
    except Exception:
        return b""
    return data[:MAX_PART_BYTES] if isinstance(data, bytes) else b""


def _part_text(part: Message) -> str:
    return _decode(_payload(part), part.get_content_charset())


def strip_quoted(text: str) -> str:
    """The reply itself: no quoted lines, cut at the first sign of the quoted original."""
    kept: list[str] = []
    previous_blank = False
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = line.strip()
        if stripped.startswith(">"):
            continue
        low = stripped.lower()
        if (
            (low.startswith("--") and "original message" in low)
            or _WROTE.match(stripped)
            or (previous_blank and low.startswith("from:"))
        ):
            break
        kept.append(line.rstrip())
        previous_blank = not stripped
    return "\n".join(kept)


def make_excerpt(text: str, limit: int) -> str:
    """The reply itself, cleaned and cut to ``limit`` characters."""
    if limit <= 0:
        return ""
    cleaned = clean_text(strip_quoted(text), keep_newlines=True)
    cleaned = _SPACES.sub("\n", cleaned)
    cleaned = _BLANKS.sub("\n\n", cleaned).strip()
    return cleaned[:limit]


@dataclass(slots=True)
class _Walk:
    plain: list[str] = field(default_factory=list)
    html: list[str] = field(default_factory=list)
    action: str | None = None
    status: str | None = None
    domain: str | None = None
    original_id: str | None = None
    original_subject: str | None = None
    attach_count: int = 0
    attach_bytes: int = 0
    attach_types: list[str] = field(default_factory=list)


def _returned_headers(block: str, walk: _Walk) -> None:
    """Message-ID and Subject of the mail a DSN gives back."""
    try:
        inner = email.parser.Parser(policy=email.policy.compat32).parsestr(
            block[:MAX_PART_BYTES], headersonly=True
        )
    except Exception:
        return
    ids = _ids(_header(inner, "Message-ID"))
    if ids and walk.original_id is None:
        walk.original_id = ids[0]
    subject = _header(inner, "Subject")
    if subject and walk.original_subject is None:
        walk.original_subject = clean_text(subject, keep_newlines=False).strip()[:MAX_SUBJECT]


def _delivery_status(part: Message, walk: _Walk) -> None:
    blocks = part.get_payload()
    if not isinstance(blocks, list):
        return
    for block in blocks[:5]:
        if not isinstance(block, Message):
            continue
        if walk.action is None:
            action = (_header(block, "Action") or "").strip().lower()
            if action in ("failed", "delayed", "delivered", "relayed", "expanded"):
                walk.action = action
        if walk.status is None:
            status = (_header(block, "Status") or "").strip()
            if _STATUS.match(status):
                walk.status = status
        if walk.domain is None:
            recipient = (_header(block, "Final-Recipient") or "").rpartition("@")[2]
            domain = recipient.strip().strip(">;").lower()
            if re.fullmatch(r"[a-z0-9.\-]{1,253}", domain):
                walk.domain = domain


def _walk(msg: Message) -> _Walk:
    walk = _Walk()
    stack: list[tuple[Message, int]] = [(msg, 0)]
    seen = 0
    while stack and seen < MAX_PARTS:
        part, depth = stack.pop()
        seen += 1
        ctype = (part.get_content_type() or "").lower()
        if ctype == "message/delivery-status":
            _delivery_status(part, walk)
        elif ctype in ("text/rfc822-headers", "message/rfc822-headers"):
            _returned_headers(_part_text(part), walk)
        elif ctype == "message/rfc822":
            inner = part.get_payload()
            if isinstance(inner, list) and inner and isinstance(inner[0], Message):
                _returned_headers(
                    "".join(
                        f"{k}: {str(v)[:MAX_HEADER_VALUE]}\n"
                        for k, v in inner[0].items()[:MAX_HEADER_LINES]
                    ),
                    walk,
                )
        elif part.is_multipart():
            children = part.get_payload()
            if depth < MAX_DEPTH and isinstance(children, list):
                stack.extend((c, depth + 1) for c in reversed(children) if isinstance(c, Message))
        elif ctype == "text/plain" and part.get_content_disposition() != "attachment":
            walk.plain.append(_part_text(part))
        elif ctype == "text/html" and part.get_content_disposition() != "attachment":
            walk.html.append(_part_text(part))
        else:
            walk.attach_count += 1
            body = part.get_payload()
            walk.attach_bytes += len(body) if isinstance(body, str) else 0
            if ctype not in walk.attach_types and len(walk.attach_types) < MAX_TYPES:
                walk.attach_types.append(ctype if _MIME_TYPE.match(ctype) else "other")
    return walk


def _attachments(walk: _Walk) -> dict[str, Any]:
    """Counts and bounded ASCII types; the JSON never exceeds the column's 2048 bytes."""
    types = [t[:MAX_TYPE_LEN] for t in walk.attach_types if t.isascii()]
    out: dict[str, Any] = {
        "count": walk.attach_count,
        "types": types,
        "bytes": walk.attach_bytes,
    }
    while len(json.dumps(out)) > MAX_ATTACHMENTS_JSON and types:
        types.pop()
    return out


def parse_message(
    raw: bytes,
    *,
    max_bytes: int = 262_144,
    excerpt_chars: int = DEFAULT_EXCERPT_CHARS,
    trusted_authserv_id: str | None = None,
) -> ParsedReply:
    """Parse one mail. Never raises: on any failure the headers (if readable) are still used."""
    size = len(raw)
    truncated = size > max_bytes
    raw = raw[:max_bytes]
    try:
        head = _parse(raw, headers_only=True)
    except Exception:
        return ParsedReply(size_bytes=size, truncated=truncated)
    address, domain, local = _from(head)
    in_reply = _header(head, "In-Reply-To")
    base = {
        "from_address": address,
        "from_domain": domain,
        "from_local": local,
        "subject": clean_text(_header(head, "Subject") or "", keep_newlines=False).strip()[
            :MAX_SUBJECT
        ],
        "sent_at": _date(head.get("Date")),
        "message_id_sha256": message_id_hash(_header(head, "Message-ID")),
        "reference_ids": _ids(in_reply, _header(head, "References")),
        "has_in_reply_to": bool(in_reply and in_reply.strip()),
        "auth": authentication(
            [_header_text(v) for v in head.get_all("Authentication-Results", [])[:10]],
            domain,
            trusted_authserv_id,
        ),
        "auto_submitted": (_header(head, "Auto-Submitted") or "").strip().lower() or None,
        "precedence": (_header(head, "Precedence") or "").strip().lower() or None,
        "x_autoreply": _present(head, "X-Autoreply"),
        "x_autorespond": _present(head, "X-Autorespond"),
        "content_type": (head.get_content_type() or "").lower(),
        "size_bytes": size,
        "truncated": truncated,
    }
    try:
        report_type = head.get_param("report-type")
    except Exception:
        report_type = None
    base["report_type"] = report_type.lower()[:64] if isinstance(report_type, str) else None
    try:
        msg = _parse(raw, headers_only=False)
        walk = _walk(msg)
    except Exception:
        return ParsedReply(**base)  # type: ignore[arg-type]
    text = "\n".join(walk.plain) if walk.plain else html_to_text("\n".join(walk.html))
    body = clean_text(text.replace("\r\n", "\n"), keep_newlines=True)[:MAX_PART_BYTES]
    return ParsedReply(
        **base,  # type: ignore[arg-type]
        dsn_action=walk.action,
        dsn_status=walk.status,
        dsn_domain=walk.domain,
        dsn_message_id=walk.original_id,
        dsn_subject=walk.original_subject,
        body=body,
        excerpt=make_excerpt(text, min(excerpt_chars, MAX_EXCERPT)),
        attachments=_attachments(walk),
    )


def _present(msg: Message, name: str) -> str | None:
    value = msg.get(name)
    return None if value is None else (_header_text(value).strip().lower()[:100])
