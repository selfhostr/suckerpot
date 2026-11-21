"""Trap packs: the data-only format, its strict validator and the bundle loader (M37).

A trap pack teaches a sensor a new trap without a code change. It is data: byte needles to
search for, flags to add, and an optional fake answer built from a fixed template. It names no
file, host or command, and nothing in it is ever executed.

The sensors, ingest and CI all use this module, so they agree on what is valid. It uses the
standard library only, never touches the file system, never uses regular expressions, and does
no network I/O. Callers read the bytes and pass them in.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal

SCHEMA = "suckerpot-trap/1"
BUNDLE_SCHEMA = "suckerpot-traps/1"
ENGINE = 1  # the engine version this code implements

# Limits (web sensor; section 4 of the design). Every one is enforced and tested.
MAX_BUNDLE_BYTES = 1024 * 1024
MAX_BUNDLE_ENTRIES = 256  # raw entries in one bundle file (the loaded count is MAX_PACKS)
MAX_JSON_DEPTH = 16
MAX_PACKS = 64
MAX_PACK_BYTES = 64 * 1024
MAX_TRAPS_PER_PACK = 16
MAX_TRAPS = 512
MAX_UNPATHED = 32  # traps without a path condition are searched on every request
MAX_UNPATHED_NEEDLES = 64  # distinct needles of those traps (keeps the per-request cost low)
MAX_CONDITIONS = 6
MAX_NEEDLES = 16
NEEDLE_MIN = 2
NEEDLE_MAX = 256
MAX_COMPILED = 4 * 1024 * 1024  # estimated memory of one compiled trap set
RECENT_DAYS = 90  # packs disclosed in the last 90 days ...
RESERVED_SHARE = 4  # ... keep a quarter of every limit for themselves
MAX_BODY = 16 * 1024  # a rendered body, UTF-8 bytes
MAX_ECHO = 64

Reason = Literal["schema", "limits", "evidence", "content", "engine_too_new", "over_limit"]
REASONS: tuple[str, ...] = (
    "schema",
    "limits",
    "evidence",
    "content",
    "engine_too_new",
    "over_limit",
)

METHODS = ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
AREAS = ("path", "query", "body", "headers", "blob")
DECODED_AREAS = ("path", "query", "body", "blob")  # percent-decoded (twice) before matching
PATH_OPS = ("exact", "prefix", "suffix", "contains")
KINDS = ("php", "static", "error")
STATUSES = (200, 201, 204, 301, 302, 400, 401, 403, 404, 405, 500, 503)
REDIRECTS = (301, 302, 303, 307, 308)  # need a Location (only 301 and 302 are allowed today)
CONTENT_TYPES = (
    "text/html; charset=UTF-8",
    "text/plain",
    "application/json",
    "text/xml",
    "application/xml",
)
HEADER_NAMES = (
    "Cache-Control",
    "Set-Cookie",
    "WWW-Authenticate",
    "X-Frame-Options",
    "Location",
    "Pragma",
    "Expires",
)
MAX_HEADERS = 6
MAX_HEADER_VALUE = 512
MAX_VARIANTS = 4

# Paths the built-in web site serves. A trap that claims a CVE cannot use one of them as its only
# evidence, and (in the web engine) a trap may answer on one only with a query or needle condition.
RESERVED_EXACT = (
    "/",
    "/index.php",
    "/wp-login.php",
    "/xmlrpc.php",
    "/robots.txt",
    "/favicon.ico",
    "/info.php",
    "/phpinfo.php",
    "/readme.html",
    "/license.txt",
    "/wp-cron.php",
    "/wp-signup.php",
    "/wp-trackback.php",
    "/wp-comments-post.php",
    "/wp-links-opml.php",
    "/wp-mail.php",
    "/wp-activate.php",
    "/wp-blog-header.php",
    "/wp-config.php",
    "/wp-load.php",
    "/wp-settings.php",
)
RESERVED_PREFIXES = (
    "/wp-admin",
    "/wp-json",
    "/wp-includes",
    "/wp-content",
    "/phpmyadmin",
    "/pma",
    "/icons",
    "/server-status",
)

# Flags the web sensor's own code sets. A pack cannot set one: ingest rules and the network tags
# rely on their meaning (a test checks this list against the sensor's code).
WEB_BUILTIN_FLAGS = frozenset(
    {
        "backup_probe", "cgi_probe", "config_leak", "console_probe", "db_admin_probe",
        "directory_listing", "docker_api_probe", "exchange_probe", "f5_probe", "geoserver_probe",
        "incomplete_body", "incomplete_request", "jenkins_probe", "laravel_probe", "laravel_rce",
        "lfi", "malformed", "no_user_agent", "oversized_body", "oversized_response",
        "oversized_upload",
        "path_traversal", "php2shell", "php_code", "php_wrapper", "phpinfo_probe", "phpmyadmin",
        "plain_http_on_tls", "rate_limited", "rce", "recon", "recon_dotfile", "rfi",
        "router_probe", "scanner_ua", "session_cookie", "session_include", "session_ref_match",
        "shellshock", "slow_upload", "solr_probe", "spring_probe", "sqli", "ssrf",
        "tomcat_probe", "upload_progress", "vpn_probe", "webshell_probe", "wordpress",
        "wp_user_enum", "xmlrpc", "xmlrpc_multicall", "xss",
    }
)  # fmt: skip

# Network tags that make a source's activity "exploit" (ingest/ingest/network/builder.py,
# EXPLOIT_TAGS; a test keeps both lists equal). A pack tag may not be one of them or a cve-* tag.
EXPLOIT_TAGS = frozenset(
    "php2shell eternalblue bluekeep sql-rce exec-attempt container-escape synology-exploit "
    "c3rb3r".split()
)

# Flags a bundled pack owns. Ingest rules give them a meaning (web.yaml, scanners.py), so only
# that pack may set them, like the built-in flags above.
PACK_OWNED_FLAGS: tuple[tuple[str, str], ...] = (
    ("log4shell", "log4j-log4shell"),
    ("phpunit_probe", "phpunit-eval-stdin"),
    ("phpunit_rce", "phpunit-eval-stdin"),
    ("router_exploit", "router-boaform-gponform"),
)
_OWNED = dict(PACK_OWNED_FLAGS)
# The packs that own those flags run first and outside the per-request search budget, so a crafted
# request can never make the sensor lose their detection. Their own scan bound is capped.
CORE_PACKS = frozenset(_OWNED.values())
CORE_SCAN_BYTES = 256 * 1024
# The largest haystack of each search area, as the web detector builds it (headers: 32 KiB plus one
# last "name: value" line of at most 128 + 2 + 1024 + 1 bytes; query, body and headers carry one
# separator byte in front for anchored needles).
AREA_CAPS = {"path": 4096, "query": 4097, "body": 16385, "headers": 33924, "blob": 24576}
# Per request, the bytes searched by traps without a path (all their distinct needles, each over
# its whole area) must fit this, so they can never run out of search budget. Checked at load.
MAX_SCAN_BYTES = 512 * 1024
PATH_MIN_LOOSE = 4  # contains and suffix paths: at least this many bytes
EVIDENCE_MIN = 6
# Header names every browser or client sends: a needle on one of them is never specific, whatever
# its value ("user-agent: mozilla", "connection: keep-alive" are in every request).
COMMON_HEADERS = frozenset(
    {
        "user-agent", "accept", "connection", "host", "cache-control", "pragma", "te",
        "upgrade-insecure-requests", "dnt", "referer", "cookie", "content-type", "content-length",
        "priority", "origin", "x-requested-with", "x-forwarded-for", "x-forwarded-proto",
        "x-real-ip", "keep-alive", "range", "authorization", "via", "forwarded", "upgrade",
        "transfer-encoding", "expect", "from",
    }
)  # fmt: skip
COMMON_HEADER_PREFIXES = ("accept", "sec-", "if-", "content-")
# Query and form keys that tracking links, search and paging put in ordinary requests.
TRACKING_PARAMS = frozenset(
    {"fbclid", "gclid", "msclkid", "yclid", "dclid", "igshid", "mc_cid", "mc_eid", "_ga", "_gl",
     "ref", "source",
     # The WordPress login form: every brute-force request carries these.
     "log", "pwd", "wp-submit", "redirect_to", "testcookie", "rememberme"}
)  # fmt: skip
_PARAM_KEY = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-[]%")
TRACKING_PREFIXES = ("utm_",)
# Keys that search, paging, sorting and cache busting put in ordinary requests. Their values are
# never evidence, whatever the value: "&page=123456" is a page number, not an exploit.
COMMON_PARAMS = frozenset(
    {"page", "paged", "lang", "s", "p", "q", "id", "search", "query", "sort", "order", "format",
     "callback", "v", "ver", "cat", "tag", "author", "feed", "preview", "replytocom",
     "offset", "limit", "start", "per_page", "count", "size", "num", "n", "t", "ts", "_", "cb",
     "year", "month", "day", "hl", "locale", "type", "category", "keyword", "keywords", "filter",
     "orderby", "sortby", "dir", "view", "amp", "nocache", "rand", "random", "timestamp",
     "time", "date"}
)  # fmt: skip

# Content rules: what a fake answer may never contain. Checked lowercased with placeholders masked,
# both as written and with every ASCII whitespace removed (browsers drop tabs and newlines inside
# URLs, and "src= //host" is a link like "src=//host").
_BANNED_TEXT = (
    "http:",
    "https:",
    "ftp:",
    "javascript:",
    "vbscript:",
    "<script",
    "<iframe",
    "<frame",
    "<object",
    "<embed",
    "<applet",
    "<base",
    "<svg",
    "<math",
    "<meta",
    "<link",
    "<style",
    "url(",
    "@import",
    "expression(",
    "suckerpot",
    "selfhostr",
    "honeypot",
)
# A URL that starts like these leaves the site: protocol-relative ("//host"), backslash variants
# browsers read as slashes, and data: URLs. Checked at every place a URL value can start.
_URL_STARTS = ("//", "/\\", "\\/", "\\\\", "data:")
_URL_OPENERS = ('"', "'", "=", "(", ",")
# The only character references allowed: a numeric or other named one could spell anything.
_ENTITIES = ("&amp;", "&lt;", "&gt;", "&quot;", "&apos;", "&nbsp;")
_WS = " \t\r\n\f\v"
_ATTR_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-:.")
# What may follow {base_url}: a path, the end of the value, a query or a fragment. Anything else
# ("@evil.example", ".evil.example", ":8080") would name another host.
_BASE_URL_NEXT = frozenset("/\"' \t\r\n#?")
_SIMPLE_SLOTS = (
    "hostname",
    "server_ip",
    "site_title",
    "base_url",
    "server_token",
    "php_version",
    "date_http",
    "year",
    "install_date",
)
_PARAM_SLOTS = ("rand_hex:", "rand_int:", "echo:query:")
_SLOT_NAMES = frozenset(
    {*_SIMPLE_SLOTS, "rand_hex", "rand_int", "echo", "echo:query"}
)  # a known name: a malformed use is an error, not literal text
ECHO_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
# Characters allowed right next to {echo:...}: an echoed value can then never join literal text
# into a tag name, a URL scheme or a word.
_ECHO_BEFORE = frozenset(" \t\r\n\"',;&=?#()[]{}|>")
_ECHO_AFTER = frozenset(" \t\r\n\"',;&?#()[]{}|<")
_MAX_RAND_INT = 1_000_000_000

_LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
_DIGITS = frozenset("0123456789")
_SLUG = _LOWER | _DIGITS | {"-"}
_FLAG = _LOWER | _DIGITS | {"_"}
_HEX = frozenset("0123456789abcdefABCDEF")
_TOKEN = _LOWER | _DIGITS | frozenset("!#$%&'*+-.^_`|~ABCDEFGHIJKLMNOPQRSTUVWXYZ")


class PackError(ValueError):
    """A pack (or bundle) is invalid. ``reason`` is one of REASONS; the message has the detail.

    Sensors log the pack id and the reason only. Authoring tools show the detail too.
    """

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason: Reason = reason
        self.detail = detail


# -- compiled form ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Slot:
    """A placeholder in a template."""

    name: str  # one of _SIMPLE_SLOTS, "rand_hex", "rand_int" or "echo"
    n: int = 0  # rand_hex length
    lo: int = 0  # rand_int bounds
    hi: int = 0
    key: str = ""  # echo: the query key, lowercased


type Template = tuple[str | Slot, ...]


@dataclass(frozen=True, slots=True)
class Respond:
    kind: str
    status: int
    content_type: str
    headers: tuple[tuple[str, Template], ...]
    variants: tuple[Template, ...]


@dataclass(frozen=True, slots=True)
class PathCond:
    op: str  # one of PATH_OPS
    value: bytes  # lowercased unless the trap matches with case: exact


@dataclass(frozen=True, slots=True)
class Needles:
    area: str  # one of AREAS
    any: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class Trap:
    id: str
    level: str  # probe or exploit
    methods: frozenset[str]
    path: PathCond | None
    query_keys: tuple[str, ...]
    header_names: tuple[str, ...]
    needles: tuple[Needles, ...]
    exact_case: bool
    flags: tuple[str, ...]
    claim_cve: bool
    respond: Respond | None

    @property
    def conditions(self) -> int:
        return (
            (1 if self.methods else 0)
            + (1 if self.path else 0)
            + len(self.query_keys)
            + len(self.header_names)
            + len(self.needles)
        )


@dataclass(frozen=True, slots=True)
class Pack:
    id: str
    version: int
    engine: int
    sensor: str
    title: str
    cve: tuple[str, ...]
    disclosed: date
    vendor: str
    product: str
    group: str | None
    presence: float
    tag: str
    attack: tuple[str, ...]
    traps: tuple[Trap, ...]
    size: int = 0  # canonical JSON bytes
    cost: int = 0  # estimated compiled memory, bytes

    @property
    def claims(self) -> bool:
        return bool(self.cve) and any(t.claim_cve for t in self.traps)


@dataclass
class LoadResult:
    packs: list[Pack] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (pack id, reason)
    seq: int = 0
    disabled: list[str] = field(default_factory=list)  # valid packs turned off by a kill list


# -- helpers ---------------------------------------------------------------------------------


def canonical(obj: Any) -> bytes:
    """Canonical JSON: sorted keys, no spaces, ASCII only. Sizes are measured on this form."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _fail(reason: Reason, detail: str) -> PackError:
    return PackError(reason, detail)


def _dict(obj: object, where: str, required: set[str], optional: set[str]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise _fail("schema", f"{where}: must be a mapping")
    keys = set(obj)
    if not all(isinstance(k, str) for k in keys):
        raise _fail("schema", f"{where}: keys must be text")
    missing = required - keys
    if missing:
        raise _fail("schema", f"{where}: missing {', '.join(sorted(missing))}")
    unknown = keys - required - optional
    if unknown:
        raise _fail("schema", f"{where}: unknown field {', '.join(sorted(unknown))}")
    return obj


def _int(value: object, where: str, lo: int, hi: int, reason: Reason = "schema") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _fail("schema", f"{where}: must be an integer")
    if not lo <= value <= hi:
        raise _fail(reason, f"{where}: must be between {lo} and {hi}")
    return value


def _list(value: object, where: str, lo: int, hi: int, reason: Reason = "limits") -> list[Any]:
    if not isinstance(value, list):
        raise _fail("schema", f"{where}: must be a list")
    if not lo <= len(value) <= hi:
        raise _fail(reason, f"{where}: needs {lo} to {hi} items")
    return value


def _printable(value: object, where: str, lo: int, hi: int, *, ascii_only: bool = False) -> str:
    if not isinstance(value, str):
        raise _fail("schema", f"{where}: must be text")
    if not lo <= len(value) <= hi:
        raise _fail("limits", f"{where}: must be {lo} to {hi} characters")
    if not value.isprintable() or (ascii_only and not value.isascii()):
        raise _fail("schema", f"{where}: must be printable{' ASCII' if ascii_only else ''} text")
    return value


def is_slug(value: object, lo: int, hi: int) -> bool:
    """``^[a-z0-9][a-z0-9-]{lo-1,hi-1}$`` without a regular expression."""
    return (
        isinstance(value, str)
        and lo <= len(value) <= hi
        and value[0] != "-"
        and all(c in _SLUG for c in value)
    )


def _slug(value: object, where: str, lo: int, hi: int) -> str:
    if not is_slug(value, lo, hi):
        raise _fail("schema", f"{where}: must be {lo} to {hi} of a-z 0-9 - (not starting with -)")
    return str(value)


def _is_flag(value: object) -> bool:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 32
        and value[0] in _LOWER
        and all(c in _FLAG for c in value)
    )


def is_cve(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("CVE-"):
        return False
    year, sep, num = value[4:].partition("-")
    return (
        bool(sep)
        and len(year) == 4
        and all(c in _DIGITS for c in year)
        and 4 <= len(num) <= 7
        and all(c in _DIGITS for c in num)
    )


def _is_technique(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("T"):
        return False
    main, dot, sub = value[1:].partition(".")
    ok = len(main) == 4 and all(c in _DIGITS for c in main)
    return ok and (not dot or (len(sub) == 3 and all(c in _DIGITS for c in sub)))


def _day(value: object, where: str) -> date:
    if isinstance(value, str) and len(value) == 10:
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise _fail("schema", f"{where}: must be a day, YYYY-MM-DD")


def _needle(value: object, where: str, area: str) -> bytes:
    """One needle, exactly as written. In ``headers`` a needle may start with one newline (an
    explicit header line start); otherwise needles are printable ASCII or ``hex:``."""
    if not isinstance(value, str):
        raise _fail("schema", f"{where}: must be text")
    if value.startswith("hex:"):
        digits = value[4:]
        if not 2 * NEEDLE_MIN <= len(digits) <= 2 * NEEDLE_MAX or len(digits) % 2:
            raise _fail("limits", f"{where}: hex needles have 4 to 512 hex digits, even count")
        if not all(c in _HEX for c in digits):
            raise _fail("schema", f"{where}: not hex")
        raw = bytes.fromhex(digits)
    else:
        text = value[1:] if area == "headers" and value.startswith("\n") else value
        if not text.isascii() or not text.isprintable():
            raise _fail("schema", f"{where}: needles are printable ASCII (or hex:...); in headers "
                        "one leading newline marks a header line start")  # fmt: skip
        if not NEEDLE_MIN <= len(value) <= NEEDLE_MAX:
            raise _fail("limits", f"{where}: needles are {NEEDLE_MIN} to {NEEDLE_MAX} bytes")
        raw = value.encode("ascii")
    if area in DECODED_AREAS and _has_percent_escape(raw):
        raise _fail(
            "schema",
            f"{where}: the {area} is percent-decoded before matching: write the decoded bytes, "
            "not %xx",
        )
    return raw


def _has_percent_escape(raw: bytes) -> bool:
    pos = raw.find(b"%")
    while pos != -1:
        pair = raw[pos + 1 : pos + 3]
        if len(pair) == 2 and all(chr(b) in _HEX for b in pair):
            return True
        pos = raw.find(b"%", pos + 1)
    return False


def is_reserved_path(path: str) -> bool:
    """True for a path (decoded, lowercased) that the built-in web site serves."""
    if path in RESERVED_EXACT:
        return True
    return any(path.startswith(p) for p in RESERVED_PREFIXES)


# -- templates -------------------------------------------------------------------------------


def _slot(inner: str, where: str) -> Slot | None:
    """The placeholder ``{inner}``, None when it is literal text, an error when malformed."""
    if inner in _SIMPLE_SLOTS:
        return Slot(inner)
    head = inner.split(":", 1)[0]
    two = ":".join(inner.split(":", 2)[:2])
    if head not in _SLOT_NAMES and two not in _SLOT_NAMES:
        return None
    if inner.startswith("rand_hex:"):
        arg = inner[9:]
        if arg and all(c in _DIGITS for c in arg) and len(arg) <= 2 and 1 <= int(arg) <= 64:
            return Slot("rand_hex", n=int(arg))
    elif inner.startswith("rand_int:"):
        lo, sep, hi = inner[9:].partition("-")
        if (
            sep
            and lo
            and hi
            and len(lo) <= 10
            and len(hi) <= 10
            and all(c in _DIGITS for c in lo + hi)
            and int(lo) <= int(hi) <= _MAX_RAND_INT
        ):
            return Slot("rand_int", lo=int(lo), hi=int(hi))
    elif inner.startswith("echo:query:"):
        key = inner[11:]
        if 1 <= len(key) <= 64 and all(c in ECHO_CHARS for c in key):
            return Slot("echo", key=key.lower())
    raise _fail("content", f"{where}: malformed placeholder {{{inner[:40]}}}")


def parse_template(text: str, where: str) -> Template:
    """Split text into literal parts and placeholders. Braces that are no placeholder stay."""
    parts: list[str | Slot] = []
    buf: list[str] = []
    i = 0
    while i < len(text):
        at = text.find("{", i)
        if at == -1:
            buf.append(text[i:])
            break
        buf.append(text[i:at])
        end = text.find("}", at + 1, at + 80)
        slot = _slot(text[at + 1 : end], where) if end != -1 else None
        if slot is None:
            buf.append("{")
            i = at + 1
            continue
        if buf:
            parts.append("".join(buf))
            buf = []
        parts.append(slot)
        i = end + 1
    if buf and "".join(buf):
        parts.append("".join(buf))
    return tuple(p for p in parts if p != "")


def _masked(tpl: Template) -> str:
    """Lowercased text with placeholders masked, for the content rules."""
    out: list[str] = []
    for p in tpl:
        if isinstance(p, str):
            out.append(p.lower())
        elif p.name == "base_url":
            out.append("\x01")
        elif p.name == "echo":
            out.append("\x02")
        else:
            out.append("\x00")
    return "".join(out)


def _check_content(tpl: Template, where: str) -> None:
    text = _masked(tpl)
    tight = "".join(c for c in text if c not in _WS)
    for bad in _BANNED_TEXT:
        if bad in text or bad in tight:
            raise _fail("content", f"{where}: {bad!r} is not allowed in a fake answer")
    for start in _URL_STARTS:
        if tight.startswith(start) or any(o + start in tight for o in _URL_OPENERS):
            raise _fail("content", f"{where}: links to another host are not allowed")
    # {base_url} is the start of a URL on this site: only a path, a query, a fragment or the end
    # of the value may follow it.
    pos = text.find("\x01")
    while pos != -1:
        nxt = text[pos + 1 : pos + 2]
        if nxt and nxt not in _BASE_URL_NEXT:
            raise _fail(
                "content", f"{where}: {{base_url}} may only be followed by /, ?, # or the end"
            )
        pos = text.find("\x01", pos + 1)
    # Character references: only the few that cannot spell a URL or a tag.
    pos = text.find("&")
    while pos != -1:
        nxt = text[pos + 1 : pos + 2]
        if nxt == "#" or (nxt.isascii() and nxt.isalpha() and not text.startswith(_ENTITIES, pos)):
            raise _fail("content", f"{where}: character references other than &amp; &lt; "
                        "&gt; &quot; &apos; &nbsp; are not allowed")  # fmt: skip
        pos = text.find("&", pos + 1)
    # Event handler attributes: on<letters>, optional whitespace, "=" (a byte scan).
    pos = text.find("on")
    while pos != -1:
        before = text[pos - 1] if pos else " "
        end = pos + 2
        while end < len(text) and "a" <= text[end] <= "z":
            end += 1
        eq = end
        while eq < len(text) and text[eq] in _WS:
            eq += 1
        if before not in _ATTR_CHARS and end > pos + 2 and eq < len(text) and text[eq] == "=":
            raise _fail("content", f"{where}: event handler attributes (on...=) are not allowed")
        pos = text.find("on", pos + 1)
    # A form may only post to this site.
    pos = 0
    while True:
        at = tight.find("action=", pos)
        if at == -1:
            break
        pos = at + 7
        rest = tight[pos : pos + 3].lstrip("\"'")
        local = rest[:1] == "/" and rest[1:2] not in ("/", "\\")
        if rest and not (rest[0] in "#\x01\"'" or local):
            raise _fail("content", f"{where}: a form action must be a path on this site")
    for i, ch in enumerate(text):
        if ch != "\x02":
            continue
        before = text[i - 1] if i else " "
        after = text[i + 1] if i + 1 < len(text) else " "
        if before not in _ECHO_BEFORE or after not in _ECHO_AFTER:
            raise _fail(
                "content", f"{where}: {{echo:...}} must stand alone (quotes, spaces or punctuation)"
            )


def _template_bound(tpl: Template) -> int:
    """Upper bound of the rendered size, request-dependent parts excluded (capped at render)."""
    size = 0
    for p in tpl:
        if isinstance(p, str):
            size += len(p.encode("utf-8"))
        elif p.name == "rand_hex":
            size += p.n
        elif p.name == "rand_int":
            size += 10
        else:
            size += 64
    return size


def _template_cost(tpl: Template) -> int:
    return 64 + sum((len(p.encode("utf-8")) + 64) if isinstance(p, str) else 96 for p in tpl)


def _respond(obj: object, where: str) -> Respond:
    d = _dict(obj, where, {"kind", "status", "content_type", "variants"}, {"headers"})
    if d["kind"] not in KINDS:
        raise _fail("schema", f"{where}.kind: one of {', '.join(KINDS)}")
    status = d["status"]
    if isinstance(status, bool) or status not in STATUSES:
        raise _fail("schema", f"{where}.status: one of {', '.join(map(str, STATUSES))}")
    if d["content_type"] not in CONTENT_TYPES:
        raise _fail("schema", f"{where}.content_type: one of {', '.join(CONTENT_TYPES)}")
    headers: list[tuple[str, Template]] = []
    seen: set[str] = set()
    for i, item in enumerate(_list(d.get("headers", []), f"{where}.headers", 0, MAX_HEADERS)):
        w = f"{where}.headers[{i}]"
        if not isinstance(item, list) or len(item) != 2:
            raise _fail("schema", f"{w}: must be [name, value]")
        name, value = item
        if name not in HEADER_NAMES:
            raise _fail("schema", f"{w}: header {str(name)[:40]!r} is not allowed")
        if name in seen and name != "Set-Cookie":
            raise _fail("schema", f"{w}: {name} twice")
        seen.add(name)
        text = _printable(value, w, 1, MAX_HEADER_VALUE, ascii_only=True)
        tpl = parse_template(text, w)
        _check_content(tpl, w)
        if name == "Location":
            first = tpl[0]
            ok = (isinstance(first, Slot) and first.name == "base_url") or (
                isinstance(first, str) and first.startswith("/") and first[1:2] not in ("/", "\\")
            )
            if not ok:
                raise _fail("content", f"{w}: Location must be a path or start with {{base_url}}")
        if any(isinstance(p, Slot) and p.name == "echo" for p in tpl):
            raise _fail("content", f"{w}: {{echo:...}} is not allowed in headers")
        headers.append((name, tpl))
    variants: list[Template] = []
    for i, item in enumerate(_list(d["variants"], f"{where}.variants", 1, MAX_VARIANTS)):
        w = f"{where}.variants[{i}]"
        if not isinstance(item, str):
            raise _fail("schema", f"{w}: must be text")
        if len(item.encode("utf-8")) > MAX_BODY:
            raise _fail("limits", f"{w}: at most {MAX_BODY} bytes")
        if any(c in item for c in "\x00\x01\x02"):
            raise _fail("content", f"{w}: control characters are not allowed")
        tpl = parse_template(item, w)
        _check_content(tpl, w)
        if _template_bound(tpl) > MAX_BODY:
            raise _fail("limits", f"{w}: the rendered body can exceed {MAX_BODY} bytes")
        variants.append(tpl)
    if status in (204, 304) and any(variants):
        raise _fail("schema", f"{where}.variants: a {status} answer has an empty body")
    if status in REDIRECTS and "Location" not in seen:
        raise _fail("schema", f"{where}.headers: a {status} answer needs a Location header")
    if "Location" in seen and status not in (*REDIRECTS, 201):
        raise _fail("schema", f"{where}.headers: Location only with 201 or a redirect status")
    return Respond(d["kind"], status, d["content_type"], tuple(headers), tuple(variants))


# -- pack validation -------------------------------------------------------------------------

_PACK_REQUIRED = {
    "schema", "id", "version", "engine", "sensor", "title", "cve", "disclosed", "product", "tag",
    "traps",
}  # fmt: skip
_PACK_OPTIONAL = {"group", "presence", "attack"}
_MATCH_KEYS = {"method", "path", "query_keys", "header_names", "needles", "case"}


def _trap(obj: object, where: str, reserved_flags: frozenset[str], pack_id: str) -> Trap:
    d = _dict(obj, where, {"id", "level", "match", "outcome"}, {"respond"})
    tid = _slug(d["id"], f"{where}.id", 1, 32)
    where = f"trap {tid}"
    level = d["level"]
    if level not in ("probe", "exploit"):
        raise _fail("schema", f"{where}.level: probe or exploit")
    m = _dict(d["match"], f"{where}.match", set(), _MATCH_KEYS)
    case = m.get("case", "insensitive")
    if case not in ("insensitive", "exact"):
        raise _fail("schema", f"{where}.match.case: insensitive or exact")
    exact = case == "exact"

    methods_raw = _list(m.get("method", []), f"{where}.match.method", 0, len(METHODS))
    if any(x not in METHODS for x in methods_raw) or len(set(methods_raw)) != len(methods_raw):
        raise _fail("schema", f"{where}.match.method: distinct items of {' '.join(METHODS)}")
    methods = frozenset(methods_raw)

    path: PathCond | None = None
    if "path" in m:
        pd = m["path"]
        if not isinstance(pd, dict) or len(pd) != 1 or next(iter(pd)) not in PATH_OPS:
            raise _fail("schema", f"{where}.match.path: exactly one of {', '.join(PATH_OPS)}")
        op, value = next(iter(pd.items()))
        text = _printable(value, f"{where}.match.path", 1, 256, ascii_only=True)
        if op in ("exact", "prefix") and not text.startswith("/"):
            raise _fail("schema", f"{where}.match.path: exact and prefix paths start with /")
        if op in ("contains", "suffix") and len(text) < PATH_MIN_LOOSE:
            raise _fail("limits", f"{where}.match.path: {op} needs {PATH_MIN_LOOSE} bytes or more")
        raw = text.encode("ascii")
        if _has_percent_escape(raw):
            raise _fail(
                "schema",
                f"{where}.match.path: the path is percent-decoded before matching: write the "
                "decoded bytes, not %xx",
            )
        path = PathCond(op, raw if exact else raw.lower())

    def names(key: str, token: bool) -> tuple[str, ...]:
        items = _list(m.get(key, []), f"{where}.match.{key}", 0, 8)
        out: list[str] = []
        for i, item in enumerate(items):
            text = _printable(item, f"{where}.match.{key}[{i}]", 1, 64, ascii_only=True)
            if token and not all(c in _TOKEN for c in text):
                raise _fail("schema", f"{where}.match.{key}[{i}]: not a header name")
            out.append(text.lower())
        if len(set(out)) != len(out):
            raise _fail("schema", f"{where}.match.{key}: duplicates")
        return tuple(out)

    query_keys = names("query_keys", False)
    header_names = names("header_names", True)

    conds: list[Needles] = []
    for i, c in enumerate(_list(m.get("needles", []), f"{where}.match.needles", 0, MAX_CONDITIONS)):
        w = f"{where}.match.needles[{i}]"
        cd = _dict(c, w, {"in", "any"}, set())
        if cd["in"] not in AREAS:
            raise _fail("schema", f"{w}.in: one of {', '.join(AREAS)}")
        items = _list(cd["any"], f"{w}.any", 1, MAX_NEEDLES)
        found = tuple(_needle(x, f"{w}.any[{j}]", cd["in"]) for j, x in enumerate(items))
        if not exact:
            found = tuple(n.lower() for n in found)
        conds.append(Needles(cd["in"], tuple(dict.fromkeys(found))))
    if path is None and not query_keys and not header_names and not conds:
        raise _fail("schema", f"{where}.match: needs a path, query_keys, header_names or needles")

    od = _dict(d["outcome"], f"{where}.outcome", {"flags"}, {"claim_cve"})
    flags_raw = _list(od["flags"], f"{where}.outcome.flags", 1, 4)
    for f in flags_raw:
        if not _is_flag(f):
            raise _fail("schema", f"{where}.outcome.flags: {str(f)[:40]!r} is not a flag name")
        if f in reserved_flags:
            raise _fail("schema", f"{where}.outcome.flags: {f} is a built-in flag")
        if _OWNED.get(f, pack_id) != pack_id:
            raise _fail("schema", f"{where}.outcome.flags: {f} belongs to pack {_OWNED[f]}")
    if len(set(flags_raw)) != len(flags_raw):
        raise _fail("schema", f"{where}.outcome.flags: duplicates")
    if "claim_cve" in od:
        if level == "probe":
            raise _fail("schema", f"{where}.outcome.claim_cve: a probe never claims a CVE")
        if not isinstance(od["claim_cve"], bool):
            raise _fail("schema", f"{where}.outcome.claim_cve: true or false")
    claim = bool(od.get("claim_cve", level == "exploit"))

    respond = _respond(d["respond"], f"{where}.respond") if "respond" in d else None
    return Trap(
        tid,
        level,
        methods,
        path,
        query_keys,
        header_names,
        tuple(conds),
        exact,
        tuple(flags_raw),
        claim,
        respond,
    )


def _header_name(n: bytes) -> bytes | None:
    """The header name of a "name: value" needle, or None."""
    name, sep, _ = n.partition(b": ")
    if sep and name and all(chr(b) in _TOKEN for b in name):
        return name
    return None


def _header_needle_specific(n: bytes) -> bool:
    """A headers needle is anchored "name: value" with a value of 6 bytes or more, on a header
    that browsers and clients do not all send."""
    if not n.startswith(b"\n"):
        return False
    name = _header_name(n[1:])
    if name is None:
        return False
    text = name.decode("latin-1")
    value = n[1:].partition(b": ")[2]
    return (
        text not in COMMON_HEADERS
        and not text.startswith(COMMON_HEADER_PREFIXES)
        and len(value.strip()) >= EVIDENCE_MIN
    )


def _param_needle_generic(n: bytes) -> bool:
    """A query or form needle that ordinary requests carry: any "key=value" part of it on a
    tracking or login-form key (utm_*, fbclid, log, pwd...) or on a common key (page, s, id...),
    whatever the value ("&page=123456" is a page number). A "key=value" needle is anchored at a
    parameter start, so a key suffix ("og=admin") cannot match a longer key ("log=admin")."""
    for part in n.split(b"&"):
        key = part.lstrip(b"?").partition(b"=")[0]
        text = key.decode("latin-1")
        if text in TRACKING_PARAMS or text.startswith(TRACKING_PREFIXES):
            return True
        if text in COMMON_PARAMS:
            return True
    return False


def _param_needle_specific(n: bytes) -> bool:
    """An explicitly anchored "&key=value" needle with a non-empty value, whose key (and the key
    of every further "&key=value" part) is not generic."""
    if not n.startswith(b"&"):
        return False
    key, sep, value = n[1:].partition(b"=")
    if not sep or not value or not key or not all(chr(b) in _PARAM_KEY for b in key):
        return False
    return not _param_needle_generic(n[1:])


def strong_condition(c: Needles, t: Trap) -> bool:
    """A needle condition that is specific to an exploit: in the query, body or headers (never
    the path or the whole-request blob), and every one of its needles (any one may match) has 6
    bytes or more, does not occur in the trap's path, and is explicitly anchored: in headers
    "\nname: value" on a header clients do not all send, in the query or body "&key=value" on a
    key that is no tracking, login-form or common short parameter. The engine searches exactly
    these bytes (the areas start with "\n" and "&"), so what is checked here is what matches."""
    if c.area not in ("query", "body", "headers"):
        return False
    path = t.path.value.lower() if t.path is not None else b""
    for compiled in c.any:
        n = compiled.lower()
        bare = n.lstrip(b"\n&")
        if len(bare) < EVIDENCE_MIN or (path and bare in path):
            return False
        if c.area == "headers" and not _header_needle_specific(n):
            return False
        if c.area in ("query", "body") and not _param_needle_specific(n):
            return False
    return True


def may_answer_on_reserved_path(t: Trap) -> bool:
    """On a path the built-in site serves, a trap answers only with a query key condition or a
    specific needle condition (design 3.6, rule 4)."""
    return bool(t.query_keys) or any(strong_condition(c, t) for c in t.needles)


def _only_reserved(p: PathCond) -> bool:
    """Every path this condition matches is one the site serves (so the trap could never answer
    without a specific condition)."""
    value = p.value.decode("ascii").lower()
    if p.op == "exact":
        return is_reserved_path(value)
    return p.op == "prefix" and any(value.startswith(r) for r in RESERVED_PREFIXES)


def _has_evidence(t: Trap) -> bool:
    """A trap that claims a CVE must hold specific evidence (design 3.2, evidence rule)."""
    if any(strong_condition(c, t) for c in t.needles):
        return True
    if t.path is not None and t.path.op in ("exact", "prefix") and len(t.path.value) >= 12:
        return not is_reserved_path(t.path.value.decode("ascii").lower())
    return False


def trap_cost(t: Trap) -> int:
    """Estimated memory of one compiled trap (an upper bound, checked by a test)."""
    cost = 1024 + 64 * len(t.flags)
    if t.path is not None:
        cost += len(t.path.value) + 96
    cost += sum(len(k) + 80 for k in (*t.query_keys, *t.header_names))
    for c in t.needles:
        cost += 160 + sum(len(n) + 96 for n in c.any)
    if t.respond is not None:
        cost += 512
        cost += sum(_template_cost(v) for v in t.respond.variants)
        cost += sum(_template_cost(v) + 64 for _, v in t.respond.headers)
    return cost


def validate_pack(
    obj: object, *, engine: int = ENGINE, reserved_flags: frozenset[str] = WEB_BUILTIN_FLAGS
) -> Pack:
    """Validate one pack (parsed JSON) and return its compiled form. Raises PackError."""
    if not isinstance(obj, dict):
        raise _fail("schema", "a pack must be a mapping")
    if obj.get("schema") != SCHEMA:
        raise _fail("schema", f"schema must be {SCHEMA}")
    # The engine is checked before anything else, so a pack for a newer engine (with fields this
    # code does not know) is reported as such, not as a schema error.
    eng = _int(obj.get("engine"), "engine", 1, 255)
    if eng > engine:
        raise _fail("engine_too_new", f"needs engine {eng}, this is engine {engine}")
    d = _dict(obj, "pack", _PACK_REQUIRED, _PACK_OPTIONAL)
    pid = _slug(d["id"], "id", 3, 48)
    version = _int(d["version"], "version", 1, 65535)
    if d["sensor"] != "web":
        # Banner packs arrive with the banner sensor (phase 4).
        raise _fail("schema", "sensor: only web packs are supported by this engine")
    title = _printable(d["title"], "title", 1, 120)
    cves_raw = _list(d["cve"], "cve", 0, 8)
    if not all(is_cve(c) for c in cves_raw) or len(set(cves_raw)) != len(cves_raw):
        raise _fail("schema", "cve: distinct CVE-YYYY-NNNN ids")
    disclosed = _day(d["disclosed"], "disclosed")
    prod = _dict(d["product"], "product", {"vendor", "name"}, set())
    vendor = _printable(prod["vendor"], "product.vendor", 1, 40)
    name = _printable(prod["name"], "product.name", 1, 40)
    group = _slug(d["group"], "group", 3, 40) if "group" in d else None
    presence_raw = d.get("presence", 1.0)
    if not isinstance(presence_raw, int | float) or isinstance(presence_raw, bool):
        raise _fail("schema", "presence: a number")
    presence = float(presence_raw)
    if not 0.05 <= presence <= 1.0:
        raise _fail("schema", "presence: between 0.05 and 1.0")
    tag = _slug(d["tag"], "tag", 3, 40)
    if tag in EXPLOIT_TAGS or tag.startswith("cve-"):
        # These tags make a source's activity "exploit" on the network: a pack may not name one,
        # so its hits can only reach that through its CVE ids and gate G (M37, section 10).
        raise _fail("schema", "tag: exploit tags and cve-* are reserved")
    attack_raw = _list(d.get("attack", []), "attack", 0, 4)
    if not all(_is_technique(a) for a in attack_raw):
        raise _fail("schema", "attack: ATT&CK ids like T1190 or T1059.004")
    traps_raw = _list(d["traps"], "traps", 1, MAX_TRAPS_PER_PACK)
    traps = tuple(_trap(t, f"traps[{i}]", reserved_flags, pid) for i, t in enumerate(traps_raw))
    ids = [t.id for t in traps]
    if len(set(ids)) != len(ids):
        raise _fail("schema", "traps: ids must be unique in the pack")
    if cves_raw:
        for t in traps:
            if t.claim_cve and not _has_evidence(t):
                raise _fail(
                    "evidence",
                    f"trap {t.id} claims a CVE without specific evidence (a condition in the "
                    "query, body or headers whose needles all have 6 bytes or more and are "
                    "anchored as \\nname: value or &key=value, or an exact or prefix path of 12 "
                    "bytes or more that the site does not serve)",
                )
    for t in traps:
        if (
            t.respond is not None
            and t.path is not None
            and _only_reserved(t.path)
            and not may_answer_on_reserved_path(t)
        ):
            raise _fail(
                "schema",
                f"trap {t.id} answers on a page the site serves: it needs query_keys or a "
                "specific needle condition (query, body or headers, 6 bytes or more)",
            )
    size = len(canonical(d))
    if size > MAX_PACK_BYTES:
        raise _fail("limits", f"pack is {size} bytes, at most {MAX_PACK_BYTES}")
    cost = 512 + len(pid) + len(title) + sum(trap_cost(t) for t in traps)
    return Pack(
        pid,
        version,
        eng,
        "web",
        title,
        tuple(cves_raw),
        disclosed,
        vendor,
        name,
        group,
        presence,
        tag,
        tuple(attack_raw),
        traps,
        size,
        cost,
    )


# -- bundles ---------------------------------------------------------------------------------


def json_depth_ok(data: bytes, limit: int = MAX_JSON_DEPTH) -> bool:
    """Linear scan: False when arrays and objects nest deeper than ``limit``."""
    depth = 0
    in_str = False
    escaped = False
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
            if depth > limit:
                return False
        elif b in (0x5D, 0x7D):
            depth -= 1
    return True


def parse_bundle(data: bytes) -> dict[str, Any]:
    """Size, depth and shape checks of a bundle file. Raises PackError (the whole file fails)."""
    if len(data) > MAX_BUNDLE_BYTES:
        raise _fail("limits", f"bundle is {len(data)} bytes, at most {MAX_BUNDLE_BYTES}")
    if not json_depth_ok(data):
        raise _fail("schema", "bundle nests too deep")
    try:
        doc = json.loads(data)
    except ValueError, RecursionError:
        raise _fail("schema", "bundle is not JSON") from None
    d = _dict(
        doc, "bundle", {"schema", "seq", "packs"}, {"disabled", "issued_at", "bundled_seq_min"}
    )
    if d["schema"] != BUNDLE_SCHEMA:
        raise _fail("schema", f"bundle schema must be {BUNDLE_SCHEMA}")
    _int(d["seq"], "seq", 0, 2**53)
    if "bundled_seq_min" in d:
        _int(d["bundled_seq_min"], "bundled_seq_min", 0, 2**53)
    _list(d["packs"], "packs", 0, MAX_BUNDLE_ENTRIES)
    for i, item in enumerate(_list(d.get("disabled", []), "disabled", 0, MAX_BUNDLE_ENTRIES)):
        dd = _dict(item, f"disabled[{i}]", {"id", "reason"}, set())
        _slug(dd["id"], f"disabled[{i}].id", 3, 48)
        _printable(dd["reason"], f"disabled[{i}].reason", 1, 200)
    if "issued_at" in d:
        _printable(d["issued_at"], "issued_at", 1, 40, ascii_only=True)
    return d


def safe_id(raw: object) -> str:
    """A pack id fit for a log line, whatever the input."""
    raw = raw.get("id") if isinstance(raw, dict) else None
    if isinstance(raw, str):
        text = "".join(c for c in raw[:48] if c in _SLUG)
        if text:
            return text
    return "?"


def scan_bound(keys: set[tuple[str, bool, bytes]]) -> int:
    """Bytes searched per request, at most, for these distinct (area, case, needle) searches."""
    return sum(AREA_CAPS[area] for area, _, _ in keys)


def _needle_keys(traps: tuple[Trap, ...]) -> set[tuple[str, bool, bytes]]:
    return {(c.area, t.exact_case, n) for t in traps for c in t.needles for n in c.any}


@dataclass
class _Usage:
    packs: int = 0
    traps: int = 0
    unpathed: int = 0
    needles: set[tuple[str, bool, bytes]] = field(default_factory=set)  # unpathed, not core
    cost: int = 0
    core: set[tuple[str, bool, bytes]] = field(default_factory=set)  # every needle of core packs

    def plus(self, p: Pack) -> _Usage:
        un = tuple(t for t in p.traps if t.path is None)
        needles = set(self.needles)
        core = set(self.core)
        if p.id in CORE_PACKS:
            core |= _needle_keys(p.traps)
        else:
            needles |= _needle_keys(un)
        return _Usage(
            self.packs + 1,
            self.traps + len(p.traps),
            self.unpathed + len(un),
            needles,
            self.cost + p.cost,
            core,
        )

    def within(self, share: int, of: int) -> bool:
        """Within ``share/of`` of every limit."""
        return (
            self.packs * of <= MAX_PACKS * share
            and self.traps * of <= MAX_TRAPS * share
            and self.unpathed * of <= MAX_UNPATHED * share
            and len(self.needles) * of <= MAX_UNPATHED_NEEDLES * share
            and scan_bound(self.needles) * of <= MAX_SCAN_BYTES * share
            and scan_bound(self.core) * of <= CORE_SCAN_BYTES * share
            and self.cost * of <= MAX_COMPILED * share
        )


def select(packs: list[Pack], today: date) -> tuple[list[Pack], list[tuple[str, str]]]:
    """Apply the load limits: newest ``disclosed`` first; packs older than RECENT_DAYS may use
    only three quarters of each limit, so there is always room for a new one."""
    order = sorted(packs, key=lambda p: (-p.disclosed.toordinal(), p.id))
    total = _Usage()
    old = _Usage()
    kept: list[Pack] = []
    dropped: list[tuple[str, str]] = []
    for p in order:
        recent = (today - p.disclosed).days <= RECENT_DAYS
        nt = total.plus(p)
        no = old if recent else old.plus(p)
        if nt.within(1, 1) and no.within(RESERVED_SHARE - 1, RESERVED_SHARE):
            total, old = nt, no
            kept.append(p)
        else:
            dropped.append((p.id, "over_limit"))
    kept.sort(key=lambda p: p.id)
    return kept, dropped


def load_bundle(
    data: bytes,
    *,
    sensor: str = "web",
    today: date,
    engine: int = ENGINE,
    reserved_flags: frozenset[str] = WEB_BUILTIN_FLAGS,
    disabled: frozenset[str] = frozenset(),
) -> LoadResult:
    """Validate a bundle and pick the packs to load. A bad pack is rejected alone (its id and
    reason are in ``rejected``); a bad file raises PackError and nothing from it loads."""
    return load_docs(
        [parse_bundle(data)],
        sensor=sensor,
        today=today,
        engine=engine,
        reserved_flags=reserved_flags,
        disabled=disabled,
    )


def load_docs(
    docs: list[dict[str, Any]],
    *,
    sensor: str = "web",
    today: date,
    engine: int = ENGINE,
    reserved_flags: frozenset[str] = WEB_BUILTIN_FLAGS,
    disabled: frozenset[str] = frozenset(),
) -> LoadResult:
    """Pick the packs to load from several bundles already checked by ``parse_bundle`` (the
    image's bundled packs and the downloaded, verified bundle). Per pack id the higher
    ``version`` wins, whichever bundle holds it. The ``disabled`` lists of every bundle and the
    local ``disabled`` set apply to all packs, bundled ones included. ``seq`` is the highest."""
    result = LoadResult(seq=max((int(d["seq"]) for d in docs), default=0))
    off = set(disabled)
    for doc in docs:
        off |= {str(x["id"]) for x in doc.get("disabled", [])}
    best: dict[str, Pack] = {}
    for doc in docs:
        for raw in doc["packs"]:
            pid = safe_id(raw)
            if isinstance(raw, dict) and raw.get("sensor") not in (None, sensor):
                continue  # a pack for another sensor
            try:
                if len(canonical(raw)) > MAX_PACK_BYTES:
                    raise _fail("limits", "pack too large")
                pack = validate_pack(raw, engine=engine, reserved_flags=reserved_flags)
            except PackError as err:
                result.rejected.append((pid, err.reason))
                continue
            if pack.id in off:
                if pack.id not in result.disabled:
                    result.disabled.append(pack.id)
                continue
            if pack.id not in best or pack.version > best[pack.id].version:
                best[pack.id] = pack
    kept, dropped = select(list(best.values()), today)
    result.packs = kept
    result.rejected += dropped
    return result


def find_conflicts(packs: list[Pack]) -> list[str]:
    """Responding traps that tie on specificity with the same path condition (CI refuses)."""
    seen: dict[tuple[str, bytes, int, frozenset[str]], str] = {}
    out: list[str] = []
    for p in packs:
        for t in p.traps:
            if t.respond is None or t.path is None:
                continue
            key = (t.path.op, t.path.value.lower(), t.conditions, t.methods)
            name = f"{p.id}/{t.id}"
            if key in seen:
                out.append(f"{seen[key]} and {name} answer the same requests")
            seen.setdefault(key, name)
    return out


def build_bundle(
    packs: list[dict[str, Any]],
    seq: int = 0,
    *,
    disabled: list[dict[str, str]] | None = None,
    issued_at: str | None = None,
) -> bytes:
    """The bundle file for already validated packs: sorted by id, readable, deterministic.
    ``disabled`` and ``issued_at`` are written only when given (the distributed bundle)."""
    doc: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA,
        "seq": seq,
        "packs": sorted(packs, key=lambda p: str(p.get("id"))),
    }
    if disabled is not None:
        doc["disabled"] = sorted(disabled, key=lambda d: d["id"])
    if issued_at is not None:
        doc["issued_at"] = issued_at
    parse_bundle(json.dumps(doc).encode())  # the result must load
    return (json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode()
