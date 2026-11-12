"""File type and architecture identification from bounded header reads.

Only a handful of fields are read with `struct`; every offset is checked against the buffer.
"""

from __future__ import annotations

import json
import re
import struct

from .models import FileInfo

_MAX_HEADERS = 256

_ELF_MACHINES = {
    2: "sparc",
    3: "x86",
    4: "m68k",
    8: "mips",
    18: "sparc",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    42: "superh",
    43: "sparc",
    45: "arc",
    62: "x86-64",
    93: "arc",
    183: "aarch64",
}
_PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "arm", 0x1C4: "arm", 0xAA64: "aarch64"}
_MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "aarch64"}
_SHELL_HINT = re.compile(
    rb"\b(wget|curl|chmod|busybox|tftp|echo|cd\s+/|rm\s+-|sh\s|bash|export|nohup|crontab|pkill)\b"
)

# Web content. A file is given a web kind (see `WEB_KINDS`) only when it plausibly IS that format
# and nothing in the whole input says it does anything. The format is read from the opening
# `_SNIFF` bytes, never from a file name or a server header; it is then checked and the whole
# input is scanned for commands and active content. A file that fails keeps the `script` or
# `text` kind, whose links are followed.
_SNIFF = 4096
_JSON_PARSE_MAX = 2 * 1024 * 1024
_JSON_MAX_DEPTH = 64
_CSS_CHECK_MAX = 4 * 1024 * 1024
_CSS_MAX_DEPTH = 32
_HTML_OPEN = re.compile(
    rb"<!doctype\s+html|<(?:html|head|body|title|meta|base|div|span|p|a|b|i|pre|br|hr|img|ul|ol"
    rb"|nav|header|footer|main|section|article|noscript|script|style|link|h[1-6]|form|table"
    rb"|iframe|center|font)[\s>/]",
    re.IGNORECASE,
)
_XML_ROOT = re.compile(rb"<(?:svg|rss|feed|urlset|sitemapindex|plist|opml)[\s>]", re.IGNORECASE)
_JSON_START = re.compile(rb'[\[{]\s*(?:"[^"\n]{0,200}"\s*:|[\[{"\]}]|-?\d|true\b|false\b|null\b)')
_JS_SYNTAX = re.compile(
    rb"\bfunction\s*+[\w$]*+\s*+\(|\b(?:var|let|const)\s++[\w$]++\s*+="
    rb"|\bimport\s*+(?:[{*(]|[\w$]++\s++from\b)"
    rb"|\bexport\s++(?:default|const|function|class|\{)|\bmodule\.exports\b|\brequire\s*+\("
    rb"|\b(?:window|document)\.|\bwebpackChunk|[\"']use strict[\"']"
)
# Syntax that only JavaScript has. A shell, PowerShell or Perl script can hold two of the markers
# above (`let a=1`, `function f()`), never by accident one of these, so the `javascript` kind needs
# at least one: arrows, strict equality, prototypes, the browser globals, CommonJS and ES module
# syntax, strict mode, bundler runtimes.
_JS_ONLY = re.compile(
    rb"=>|[=!]==|\.prototype\b|\b(?:window|document)\.|\bmodule\.exports\b|[\"']use strict[\"']"
    rb"|\bexport\s++(?:default\b|\{)|\bimport\s*+[{*][^;\n]{0,200}?\bfrom\s*+[\"']"
    rb"|\bimport\s++[\w$]++\s++from\s*+[\"']|\bwebpackChunk|__webpack_require__"
)
# Syntax of other languages, which share a few words with JavaScript.
_NOT_JS = re.compile(
    rb"^[ \t]*+(?:import\s+[\w.]+\s*(?:,|$)|from\s+[\w.]+\s+import\b|def\s+\w+\s*\("
    rb"|use\s+[\w:]+\s*;|my\s+[$@%]|package\s+[\w:]+\s*;)",
    re.MULTILINE,
)
_CSS_AT_RULE = re.compile(
    rb"@(?:charset|import|font-face|media|keyframes|layer|supports|namespace|page|tailwind|property)\b",
    re.IGNORECASE,
)
_CSS_BLOCK = re.compile(rb"[^{}]{1,200}\{\s*[a-z-]+\s*:[^{}]{0,200}\}", re.IGNORECASE)
# Every pattern that runs over the WHOLE input is linear: a string, comment or `url(` that is never
# closed is consumed to the end of the input in one match, repeats are possessive or bounded, and
# no pattern rescans the rest of the input from every position.
#
# Strings, comments and `url(...)` of a style sheet or a JSON document, replaced by an empty
# placeholder (`""`, nothing, `url()`) so that only the structure is left. One that is never closed
# is kept as it is, to the end of the input, so the structure check refuses it.
_NEUTRAL = re.compile(
    # Each alternative starts after the one character of the leading set (a fast scan); the
    # lookbehinds tell which one it was, and capture it again where it must be kept.
    rb"[/\"'uU](?:"
    rb"(?<=/)\*.*?\*/|(?<=(?P<c0>/))(?P<c1>\*.*+)|(?<=(?P<c2>/))"
    rb'|(?<=")(?:[^"\\]++|\\.)*+(?P<d>")|(?<=\')(?:[^\'\\]++|\\.)*+(?P<s>\')'
    rb"|(?<=(?P<q0>[\"']))(?P<q1>.*+)"
    rb"|(?<=(?P<u0>[uU]))(?P<u1>[rR][lL]\()(?:[^)\\]++|\\.)*+(?P<u2>\))"
    rb"|(?<=(?P<u3>[uU]))(?P<u4>[rR][lL]\(.*+)|(?<=(?P<u5>[uU]))"
    rb")",
    re.DOTALL,
)
_NEUTRAL_KEEP = (
    rb"\g<c0>\g<c1>\g<c2>\g<d>\g<d>\g<s>\g<s>\g<q0>\g<q1>\g<u0>\g<u1>\g<u2>\g<u3>\g<u4>\g<u5>"
)
_JSON_BRACKETS = bytes(range(256)).translate(None, b"[]{}")  # every byte but brackets
_CSS_BLOCK_MARK = b"\x01"  # an inner block already checked; a style sheet never holds this byte
# The checks below run on the emptied sheet behind one `;`, so every statement starts after a
# `{`, `}` or `;` (a leading charset, which the regular expression engine scans for quickly).
# A `{` with no selector before it.
_CSS_EMPTY_SELECTOR = re.compile(rb"[{};]\s*+\{")
# A statement ending in `;` or `}` that is neither a declaration (no colon) nor an at-rule.
_CSS_NOT_DECLARATION = re.compile(rb"[{};]\s*+[^{};:@\s][^{};:]*+[;}]")
_CSS_INNER_BLOCK = re.compile(rb"\{[^{}]*+\}")
# Outside every block, a statement ending in `;` must be an at-rule.
_CSS_TOP_STATEMENT = re.compile(rb"[;\x01]\s*+[^;\x01@\s][^;\x01]*+;")


def _sign(literal: bytes, pattern: bytes | None = None) -> tuple[bytes, re.Pattern[bytes] | None]:
    return literal, None if pattern is None else re.compile(pattern)


# Signs that a file runs something: shell statements, downloaders, program calls, code runners
# and active content. Each sign is a lower-case literal that every match holds, and the pattern
# (if any) that confirms it; both run over the lower-cased input, and a pattern runs only when its
# literal is there, which keeps the scan of a large file fast. Single words that every page and ES
# module uses ("echo", "export", "bash") are not signs; shell statements made of them are.
_SIGNS: tuple[tuple[bytes, re.Pattern[bytes] | None], ...] = (
    # Shell statements, written the way a shell script writes them.
    _sign(b"export", rb"(?<![\w.$-])export[ \t]++[a-z_]\w*+="),
    _sign(b"sh", rb"\b(?:ba)?sh[ \t]++-c\b"),
    _sign(b"|", rb"[ \t\r\n]\|[ \t]*+(?:ba)?sh\b"),
    _sign(b"/bin/", rb"/bin/(?:ba)?sh\b"),
    _sign(b"sh", rb"(?m)^[ \t]*+(?:ba|da)?sh[ \t]++[\w./$-]"),
    _sign(b"./", rb"(?m)^[ \t]*+\./[\w.$-]|(?:;|&&)[ \t]*+\./\S"),
    _sign(b"/tmp", rb"\bcd[ \t]++/tmp\b"),
    _sign(b"/dev/shm"),
    _sign(b"/var/tmp"),
    _sign(b"/dev/tcp/"),
    _sign(b"nohup", rb"\bnohup[ \t]"),
    _sign(b"crontab", rb"\bcrontab\b"),
    _sign(b"busybox", rb"\bbusybox\b"),
    _sign(b"tftp", rb"\btftp\b"),
    _sign(b"rm", rb"\brm[ \t]++-[a-z]{0,8}[rf][a-z]{0,8}[ \t]++/"),
    _sign(b"-e", rb"\bnc[ \t]++-e\b"),
    _sign(b"/dev/udp/"),
    _sign(b"/inet/tcp/"),
    _sign(b"/inet/udp/"),
    # Process substitution, and a file sourced by path (`. /run/a`, `source ~/x`).
    _sign(b"<(", rb"(?:\bsource|(?<![\w.])\.|\b(?:ba|da|z)?sh)[ \t]++<\("),
    _sign(b". ", rb"(?m)(?:^|[;&|])[ \t]*+\.[ \t]++[/~$]"),
    _sign(b"source", rb"(?m)(?:^|[;&|])[ \t]*+source[ \t]++[/~$]"),
    # Downloaders and program calls.
    _sign(b"wget", rb"\bwget\b"),
    _sign(b"curl", rb"\bcurl\b"),
    _sign(b"pkill", rb"\bpkill\b"),
    _sign(b"chmod"),
    _sign(b"process", rb"child[\"'\s+.\[\]()]{0,12}_?process"),
    _sign(b"execsync"),
    _sign(b"execfile"),
    _sign(b"spawnsync"),
    _sign(b"spawn", rb"\bspawn\s*+\("),
    _sign(b"writefilesync"),
    _sign(b"appendfilesync"),
    _sign(b"os.system"),
    _sign(b"os.popen"),
    _sign(b"subprocess", rb"\bsubprocess\b"),
    _sign(b"system", rb"\bsystem\s*+\("),
    _sign(b"popen", rb"\bpopen\s*+\("),
    _sign(b"shell_exec"),
    _sign(b"passthru"),
    _sign(b"proc_open"),
    # Windows tools, PowerShell and .NET, one-line Python and Perl, shell `eval` and base64
    # decoding, BusyBox `ftpget`, Node file writes and code built from base64 text.
    _sign(b"certutil"),
    _sign(b"bitsadmin"),
    _sign(b"ftpget"),
    _sign(b"urlretrieve"),
    _sign(b"createwritestream"),
    _sign(b"frombase64string"),
    _sign(b"iex", rb"\biex\b"),
    _sign(b"iwr", rb"\biwr\b"),
    _sign(b"irm", rb"\birm\b"),
    _sign(b"invoke-expression"),
    _sign(b"invoke-webrequest"),
    _sign(b"invoke-restmethod"),
    _sign(b"start-process"),
    _sign(b"download", rb"\.\s*+download(?:string|file|data)\s*+\("),
    _sign(b"net.webclient"),
    _sign(b"lwp::"),
    _sign(b"base64", rb"\bbase64[ \t]++(?:-[a-z]{0,4}d|--decode)\b"),
    _sign(b"eval", rb"\beval[ \t]++[\"'$`]|=\s*+eval\s*+[;,)]"),
    _sign(b"python", rb"\bpython[23]?(?:\.[0-9]{1,2})?[ \t]++-[a-z]{0,4}c\b"),
    _sign(b"perl", rb"\bperl[ \t]++(?:-[a-z]{1,8}[ \t]++){0,3}-[a-z]{0,4}[em]"),
    _sign(b"php", rb"\bphp[0-9.]{0,4}[ \t]++(?:-[a-z]{1,8}[ \t]++){0,3}-[a-z]{0,4}r\b"),
    _sign(b"ruby", rb"\bruby[ \t]++(?:-[a-z]{1,8}[ \t]++){0,3}-[a-z]{0,4}e\b"),
    _sign(b"lua", rb"\blua[0-9.]{0,4}[ \t]++-e\b"),
    _sign(
        b"node",
        rb"\bnode(?:js)?[ \t]++(?:-[a-z-]{1,16}[ \t]++){0,3}-(?:-eval|-print|[a-z]{0,4}[ep]\b)",
    ),
    # JavaScript that runs text it was handed: eval of anything but one plain string, an
    # indirect eval.
    _sign(
        b"eval",
        rb"\beval\s*+\(\s*+(?![\"'][^\"'`\n]{0,200}+[\"']\s*+\))|[(,]\s*+eval\s*+\)\s*+\(",
    ),
    _sign(b"atob", rb"\b(?:function|eval)\s*+\(\s*+atob\s*+\("),
    _sign(b"function", rb"=\s*+function\s*+[;,)]"),
    # Active content that a browser, Windows or a server would run.
    _sign(b"<%"),
    _sign(b"<?", rb"<\?(?!xml)"),
    _sign(b"<jsp:"),
    _sign(b"hta:application"),
    _sign(b"<scriptlet"),
    _sign(b"<job", rb"<job\b"),
    _sign(b"<component", rb"<component\b"),
    _sign(b"<registration", rb"<registration\b"),
    _sign(b"msxsl:"),
    _sign(b"activexobject"),
    _sign(b"wscript"),
    _sign(b"vbscript"),
    _sign(b"powershell"),
    _sign(b"mshta"),
    _sign(b"regsvr32"),
    _sign(b"rundll32"),
    _sign(b"cmd", rb"cmd\s*+/c"),
    _sign(b"runat", rb"runat\s*+=\s*+[\"']?server"),
    _sign(b"getruntime"),
    _sign(b"processbuilder"),
    _sign(b"scripting.filesystemobject"),
    _sign(b"shell.application"),
    _sign(b"adodb.stream"),
)
# Node that reaches the system: a module load (`require` or `import()` of anything but one plain
# string, such as a variable, `Buffer.from(...)`, a name built from parts or a template; a Node
# module that reaches the network, the files or other programs; the module loader itself) used
# with a write, a pipe, a program run (`.exec(`, `.fork(`, `.spawn(`) or `eval(`. In a page,
# `.exec(` is the regular expression method of every bundle and `.write(` is `document.write`, so
# neither counts alone.
_NODE_MODULES = (
    rb"(?:node:|(?:child_process|fs|net|https?|os|vm|worker_threads|cluster|dgram|tls|module)"
    rb"[\"'`/])"
)
_NODE_LOAD = re.compile(
    rb"\b(?:require|import)\s*+\(\s*+(?:(?![\"'][^\"'`\n]{0,200}+[\"']\s*+\))|[\"']"
    + _NODE_MODULES
    + rb")|\bfrom\s*+[\"']"
    + _NODE_MODULES
    + rb"|\bprocess\s*+\.\s*+(?:mainmodule|binding|dlopen)\b|\bmodule\s*+\.\s*+constructor\b"
)
_NODE_ACTION = re.compile(
    rb"\.\s*+(?:exec|fork|spawn|write|pipe)\w*+\s*+\(|\b(?:writefile|appendfile)\w*+|\beval\s*+\("
)
# The Function constructor builds code from text (case matters: `function(` is a declaration). The
# one exception is the global object idiom of every polyfill, `Function("return this")`.
_FUNCTION_CTOR = re.compile(rb"(?<![\w$.])Function\s*+\(\s*+(?![\"']return this[\"']\s*+\))")


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...] | None:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        return None
    return struct.unpack_from(fmt, data, offset)


def _u(fmt: str, data: bytes, offset: int) -> int | None:
    values = _unpack(fmt, data, offset)
    return None if values is None else int(values[0])


def _identify_elf(data: bytes) -> FileInfo:
    is64 = data[4] == 2
    little = data[5] != 2
    e = "<" if little else ">"
    machine = _u(e + "H", data, 18)
    arch = _ELF_MACHINES.get(machine) if machine is not None else None
    linking: str | None = None
    stripped: bool | None = None
    if is64:
        phoff, shoff = _u(e + "Q", data, 32), _u(e + "Q", data, 40)
        phentsize, phnum = _u(e + "H", data, 54), _u(e + "H", data, 56)
        shentsize, shnum = _u(e + "H", data, 58), _u(e + "H", data, 60)
    else:
        phoff, shoff = _u(e + "I", data, 28), _u(e + "I", data, 32)
        phentsize, phnum = _u(e + "H", data, 42), _u(e + "H", data, 44)
        shentsize, shnum = _u(e + "H", data, 46), _u(e + "H", data, 48)
    min_ph = 56 if is64 else 32
    if phoff is not None and phentsize and phnum is not None and phentsize >= min_ph:
        count = min(phnum, _MAX_HEADERS)
        if phoff + count * phentsize <= len(data):
            linking = "static"
            for i in range(count):
                if _u(e + "I", data, phoff + i * phentsize) == 3:  # PT_INTERP
                    linking = "dynamic"
                    break
    min_sh = 64 if is64 else 40
    if shoff and shentsize and shnum is not None and shentsize >= min_sh:
        count = min(shnum, _MAX_HEADERS)
        if shoff + count * shentsize <= len(data):
            stripped = True
            for i in range(count):
                if _u(e + "I", data, shoff + i * shentsize + 4) == 2:  # SHT_SYMTAB
                    stripped = False
                    break
    elif shoff == 0 and shnum == 0:
        stripped = True  # no section headers at all
    return FileInfo(
        kind="elf",
        arch=arch,
        bits=64 if is64 else 32,
        endian="little" if little else "big",
        linking=linking,  # type: ignore[arg-type]
        stripped=stripped,
    )


def _identify_pe(data: bytes) -> FileInfo | None:
    lfanew = _u("<I", data, 0x3C)
    if lfanew is None or data[lfanew : lfanew + 4] != b"PE\x00\x00":
        return None
    machine = _u("<H", data, lfanew + 4)
    chars = _u("<H", data, lfanew + 22)
    magic = _u("<H", data, lfanew + 24)
    bits = {0x10B: 32, 0x20B: 64}.get(magic) if magic is not None else None
    return FileInfo(
        kind="pe",
        arch=_PE_MACHINES.get(machine) if machine is not None else None,
        bits=bits,
        endian="little",
        is_dll=bool(chars & 0x2000) if chars is not None else None,
    )


def _identify_macho(data: bytes) -> FileInfo | None:
    magic = data[:4]
    table = {
        b"\xcf\xfa\xed\xfe": ("<", 64),
        b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 64),
        b"\xfe\xed\xfa\xce": (">", 32),
    }
    if magic not in table:
        return None
    e, bits = table[magic]
    cpu = _u(e + "I", data, 4)
    return FileInfo(
        kind="macho",
        arch=_MACHO_CPUS.get(cpu) if cpu is not None else None,
        bits=bits,
        endian="little" if e == "<" else "big",
    )


def _packer(data: bytes) -> str | None:
    head = data[: 1024 * 1024]
    if b"UPX!" in head or b"UPX0" in head or b"$Info: This file is packed with the UPX" in head:
        return "upx"
    return None


def _looks_textual(head: bytes) -> bool:
    """No NUL and almost no control characters (any encoding with ASCII markup passes)."""
    if not head or b"\x00" in head:
        return False
    controls = sum(1 for b in head if (b < 32 and b not in (9, 10, 12, 13)) or b == 127)
    return controls / len(head) < 0.01


def _strip_css_comments(head: bytes) -> bytes:
    while head.startswith(b"/*"):
        end = head.find(b"*/", 2)
        if end < 0:
            return b""
        head = head[end + 2 :].lstrip()
    return head


def _skip_markup_prolog(lowered: bytes) -> bytes | None:
    """The text after any leading XML declaration, comments and plain document type, or None when
    one of them is unterminated or a document type has an internal subset (entity declarations)."""
    for _ in range(8):
        lowered = lowered.lstrip()
        if lowered.startswith(b"<?xml"):
            end, skip = lowered.find(b"?>"), 2
        elif lowered.startswith(b"<!--"):
            end, skip = lowered.find(b"-->", 4), 3
        elif lowered.startswith(b"<!doctype") and not lowered.startswith(b"<!doctype html"):
            end, skip = lowered.find(b">"), 1
            if end >= 0 and b"[" in lowered[:end]:
                return None
        else:
            return lowered
        if end < 0:
            return None
        lowered = lowered[end + skip :]
    return None


def _markup_kind(lowered: bytes) -> str | None:
    """`html`, `svg` or `xml` when the document OPENS like one (after its prolog), else None.

    The caller passes the opening bytes in lower case; the patterns are case-insensitive anyway.
    """
    body = _skip_markup_prolog(lowered)
    if body is None:
        return None
    if _HTML_OPEN.match(body):
        return "html"
    if _XML_ROOT.match(body):
        return "svg" if body.startswith(b"<svg") else "xml"
    return None


def _json_depth_ok(data: bytes) -> bool:
    """True when no bracket outside a string is nested deeper than `_JSON_MAX_DEPTH`.

    Strings are emptied first, then one pass over the brackets alone, so the check does not rely
    on the interpreter's recursion limit. A string that is never closed is left to the parser.
    """
    depth = 0
    for c in _NEUTRAL.sub(_NEUTRAL_KEEP, data).translate(None, _JSON_BRACKETS):
        if c in b"[{":
            depth += 1
            if depth > _JSON_MAX_DEPTH:
                return False
        else:
            depth -= 1
    return True


def _parses_as_json(data: bytes) -> bool:
    if len(data) > _JSON_PARSE_MAX:
        return False  # too big to check here: it keeps the text kind
    if not _json_depth_ok(data):
        return False
    try:
        json.loads(data)
    except ValueError, RecursionError:
        return False
    return True


def _css_shaped(data: bytes) -> bool:
    """True when the whole input is made of at-rules, rules and `property: value` declarations.

    Comments are dropped and strings and `url(...)` emptied (one that is never closed is kept, and
    fails below). On what is left: every `{` has a selector; every statement that ends in `;` or
    `}` is a declaration (it holds a colon) or an at-rule; the innermost blocks are folded away one
    level per pass, so braces must balance within `_CSS_MAX_DEPTH` levels; outside every block a
    `;` ends only an at-rule; nothing follows the last rule. Shell lines, code in another language
    and any text after the last rule fail. Every step is linear in the input.
    """
    if len(data) > _CSS_CHECK_MAX or _CSS_BLOCK_MARK in data:
        return False
    sheet = b";" + _NEUTRAL.sub(_NEUTRAL_KEEP, data)
    if _CSS_EMPTY_SELECTOR.search(sheet) or _CSS_NOT_DECLARATION.search(sheet):
        return False
    for _ in range(_CSS_MAX_DEPTH):
        sheet, folded = _CSS_INNER_BLOCK.subn(_CSS_BLOCK_MARK, sheet)
        if not folded:
            break
    if b"{" in sheet or b"}" in sheet or _CSS_TOP_STATEMENT.search(sheet):
        return False
    tail = sheet[max(sheet.rfind(b";"), sheet.rfind(_CSS_BLOCK_MARK)) + 1 :]
    return not tail.strip()


def _runs_something(data: bytes) -> bool:
    """True when the input holds a shell statement, a downloader, a code runner or active content
    (`_SIGNS`), the Function constructor, or a Node module load used to write or run something."""
    low = data.lower()
    for literal, pattern in _SIGNS:
        if literal in low and (pattern is None or pattern.search(low)):
            return True
    if b"Function" in data and _FUNCTION_CTOR.search(data):
        return True
    return bool(_NODE_ACTION.search(low) and _NODE_LOAD.search(low))


def _identify_web(data: bytes) -> str | None:
    """A web kind (see `WEB_KINDS`), or None to keep the `script` / `text` kind.

    1. The opening bytes name the format: a document that opens like HTML, SVG or XML (after its
       XML declaration, comments and plain document type), a JSON bracket, JavaScript syntax (two
       markers and at least one token only JavaScript has, none of another language) or a style
       sheet rule.
    2. The WHOLE input is scanned, whatever its size, for shell statements, downloaders, program
       calls and code runners (`wget`, `certutil`, `iex`, `python -c`, `perl -e`, shell `eval`,
       `base64 -d`, Node `child_process` in any spelling, `.exec(` next to a Node module load...)
       and for active content that a browser or a server would run (ASP and JSP tags, any `<?`
       other than the XML declaration, HTA, scriptlets, WSH, PowerShell, `runat="server"` and the
       like): see `_SIGNS`. One hit anywhere refuses every kind. Single words such as "echo",
       "export" or "bash" do not count.
    3. The format is checked: JSON must parse (up to 2 MiB) and a style sheet must be made only
       of rules and declarations (up to 4 MiB). A larger file of either keeps the text kind.

    A refused file keeps the `script` or `text` kind, so its links are followed. This guard is
    the second layer: the collector treats any file an attacker asked for (depth 0 or a typed URL)
    as attacker content whatever its kind, and only spares links found in other web content.
    Every pattern is linear in the input size.
    """
    head = data[:_SNIFF]
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    head = head.lstrip(b" \t\r\n\x0c")
    if not _looks_textual(head):
        return None
    kind: str | None
    if head.startswith(b"<"):
        kind = _markup_kind(head.lower())
    elif _JSON_START.match(head):
        kind = "json"
    elif len(_JS_SYNTAX.findall(head)) >= 2 and _JS_ONLY.search(head) and not _NOT_JS.search(head):
        kind = "javascript"
    else:
        css = _strip_css_comments(head)
        kind = "css" if _CSS_AT_RULE.match(css) or len(_CSS_BLOCK.findall(css)) >= 3 else None
    if kind is None:
        return None
    if _runs_something(data):
        return None
    if kind == "json" and not _parses_as_json(data):
        return None
    if kind == "css" and not _css_shaped(data):
        return None
    return kind


def _identify_text(data: bytes) -> FileInfo:
    head = data[:4096]
    if head.startswith(b"#!"):
        line = head[2:].split(b"\n", 1)[0].decode("ascii", errors="replace").strip()
        parts = line.split()
        if parts and parts[0].rsplit("/", 1)[-1] == "env" and len(parts) > 1:
            parts = parts[1:]
        interp = parts[0].rsplit("/", 1)[-1][:32] if parts else None
        return FileInfo(kind="script", interpreter=interp or None)
    if not head or b"\x00" in head:
        return FileInfo(kind="data")
    web = _identify_web(data)
    if web is not None:
        return FileInfo(kind=web)
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(head) < 0.95:
        return FileInfo(kind="data")
    if _SHELL_HINT.search(head):
        return FileInfo(kind="script", interpreter="sh")
    return FileInfo(kind="text")


def identify(data: bytes) -> FileInfo:
    """Return kind, arch, bits, endianness, linking and packer. Never raises."""
    try:
        info = _identify(data)
    except struct.error, IndexError, ValueError:  # defensive: parsers are bounds-checked
        info = FileInfo(kind="data")
    packer = _packer(data)
    if packer and info.kind in {"elf", "pe", "macho"}:
        info = info.model_copy(update={"packer": packer})
    return info


def _identify(data: bytes) -> FileInfo:
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        return _identify_elf(data)
    if data[:2] == b"MZ":
        pe = _identify_pe(data)
        if pe is not None:
            return pe
    macho = _identify_macho(data)
    if macho is not None:
        return macho
    if data[:2] == b"\x1f\x8b":
        return FileInfo(kind="gzip")
    if data[:4] == b"PK\x03\x04":
        return FileInfo(kind="zip")
    if data[:6] == b"\xfd7zXZ\x00":
        return FileInfo(kind="xz")
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return FileInfo(kind="7z")
    if data[:3] == b"BZh" and data[3:4] in {b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"}:
        return FileInfo(kind="bzip2")
    if data[257:262] == b"ustar":
        return FileInfo(kind="tar")
    return _identify_text(data)
