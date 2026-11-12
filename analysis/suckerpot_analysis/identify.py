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
_CSS_CHECK_MAX = 4 * 1024 * 1024
_CSS_MAX_DEPTH = 32
_HTML_OPEN = re.compile(
    rb"<!doctype\s+html|<(?:html|head|body|title|meta|base|div|span|p|a|b|i|pre|br|hr|img|ul|ol"
    rb"|nav|header|footer|main|section|article|noscript|script|style|link|h[1-6]|form|table"
    rb"|iframe|center|font)[\s>/]"
)
_XML_ROOT = re.compile(rb"<(?:svg|rss|feed|urlset|sitemapindex|plist|opml)[\s>]")
_JSON_START = re.compile(rb'[\[{]\s*(?:"[^"\n]{0,200}"\s*:|[\[{"\]}]|-?\d|true\b|false\b|null\b)')
_JS_SYNTAX = re.compile(
    rb"\bfunction\s*[\w$]*\s*\(|\b(?:var|let|const)\s+[\w$]+\s*=|\bimport\s*(?:[{*(]|[\w$]+\s+from\b)"
    rb"|\bexport\s+(?:default|const|function|class|\{)|\bmodule\.exports\b|\brequire\s*\("
    rb"|\b(?:window|document)\.|\bwebpackChunk|[\"']use strict[\"']"
)
# Syntax of other languages, which share a few words with JavaScript.
_NOT_JS = re.compile(
    rb"^\s*(?:import\s+[\w.]+\s*(?:,|$)|from\s+[\w.]+\s+import\b|def\s+\w+\s*\(|use\s+[\w:]+\s*;"
    rb"|my\s+[$@%]|package\s+[\w:]+\s*;)",
    re.MULTILINE,
)
_CSS_AT_RULE = re.compile(
    rb"@(?:charset|import|font-face|media|keyframes|layer|supports|namespace|page|tailwind|property)\b"
)
_CSS_BLOCK = re.compile(rb"[^{}]{1,200}\{\s*[a-z-]+\s*:[^{}]{0,200}\}")
_CSS_TOKEN = re.compile(
    rb"/\*.*?\*/|url\((?:[^)\\]|\\.)*\)|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[{};]"
    rb"|(?:(?!url\()[^{};\"'/])+|.",
    re.DOTALL | re.IGNORECASE,
)
# Run over the WHOLE input for every web kind: a command, a downloader or active content anywhere
# means the file is a program, not a page.
# Shell statements, written the way a shell script writes them. Narrower than `_SHELL_HINT`, whose
# single words ("export", "echo", "bash") are in every ES module and in many pages.
_SHELL_STATEMENT = re.compile(
    rb"^[ \t]*export[ \t]+[A-Za-z_]\w*="
    rb"|\b(?:ba)?sh[ \t]+-c\b|[ \t\r\n]\|[ \t]*(?:ba)?sh\b|/bin/(?:ba)?sh\b"
    rb"|\bcd[ \t]+/tmp\b|/(?:dev/shm|var/tmp)\b|\bnohup[ \t]|\bcrontab\b|\bbusybox\b|\btftp\b"
    rb"|\brm[ \t]+-[a-zA-Z]*[rf][a-zA-Z]*[ \t]+/|\bnc[ \t]+-e\b|/dev/tcp/"
    rb"|;[ \t]*\./\S|&&[ \t]*\./\S",
    re.MULTILINE,
)
_DROPPER_HINT = re.compile(
    rb"\b(?:wget|curl|busybox|tftp|nohup|crontab|pkill)\b|chmod|/bin/(?:ba)?sh\b|/dev/tcp/"
    rb"|child[\"'\s+.\[\]()]{0,12}_?process|\b(?:execSync|execFileSync|execFile|spawnSync|spawn\s*\()"
    rb"|\b(?:writeFileSync|appendFileSync)\b|\bos\.(?:system|popen)\b|\bsubprocess\b"
    rb"|\b(?:system|popen|shell_exec|passthru|proc_open)\s*\(",
    re.IGNORECASE,
)
_ACTIVE_CONTENT = re.compile(
    rb"<%|<\?(?!xml)|<jsp:|hta:application|<scriptlet|<job\b|<component\b|<registration\b"
    rb"|msxsl:|activexobject|wscript|vbscript|powershell|mshta|regsvr32|rundll32|cmd\s*/c"
    rb"|runat\s*=\s*[\"']?server|getruntime|processbuilder|scripting\.filesystemobject"
    rb"|shell\.application|adodb\.stream",
    re.IGNORECASE,
)


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
    """`html`, `svg` or `xml` when the document OPENS like one (after its prolog), else None."""
    body = _skip_markup_prolog(lowered)
    if body is None:
        return None
    if _HTML_OPEN.match(body):
        return "html"
    if _XML_ROOT.match(body):
        return "svg" if body.startswith(b"<svg") else "xml"
    return None


def _parses_as_json(data: bytes) -> bool:
    if len(data) > _JSON_PARSE_MAX:
        return False  # too big to check here: it keeps the text kind
    try:
        json.loads(data)
    except ValueError, RecursionError:
        return False
    return True


def _css_shaped(data: bytes) -> bool:
    """True when the whole input is made of at-rules, rules and `property: value` declarations.

    One tokenising pass over strings, comments and `url(...)`, with no backtracking. Text outside
    a block must be an at-rule ending in `;` or a selector ending in `{`; text inside a block must
    be a declaration (it holds a colon), an at-rule or a nested selector. Shell lines, code in
    another language and any text after the last rule fail.
    """
    if len(data) > _CSS_CHECK_MAX:
        return False
    depth = 0
    has = colon = False
    first = b""
    for m in _CSS_TOKEN.finditer(data):
        tok = m.group()
        if len(tok) >= 4 and tok.startswith(b"/*") and tok.endswith(b"*/"):
            continue
        if tok in (b"{", b"}", b";"):
            at_rule = first == b"@"
            if tok == b"{":
                depth += 1
                if not has or depth > _CSS_MAX_DEPTH:
                    return False
            elif tok == b";":
                if has and not at_rule and (depth == 0 or not colon):
                    return False
            else:  # a closing brace also ends a declaration that has no `;`
                depth -= 1
                if depth < 0 or (has and not at_rule and not colon):
                    return False
            has = colon = False
            first = b""
            continue
        stripped = tok.strip()
        if not stripped:
            continue
        if not has:
            first = stripped[:1]
        has = True
        if not tok.startswith((b'"', b"'")) and b":" in tok:
            colon = True
    return depth == 0 and not has


def _identify_web(data: bytes) -> str | None:
    """A web kind (see `WEB_KINDS`), or None to keep the `script` / `text` kind.

    1. The opening bytes name the format: a document that opens like HTML, SVG or XML (after its
       XML declaration, comments and plain document type), a JSON bracket, JavaScript syntax (two
       markers, none of another language) or a style sheet rule.
    2. The WHOLE input is scanned, whatever its size, for shell statements (`_SHELL_STATEMENT`),
       downloaders and program calls (`_DROPPER_HINT`) and for active content that a browser or a
       server would run (`_ACTIVE_CONTENT`: ASP and JSP tags, any `<?` other than the XML
       declaration, HTA, scriptlets, WSH, PowerShell, `runat="server"` and the like). One hit
       anywhere refuses every kind. Single words such as "echo", "export" or "bash" do not count.
    3. The format is checked: JSON must parse (up to 2 MiB) and a style sheet must be made only
       of rules and declarations (up to 4 MiB). A larger file of either keeps the text kind.

    A refused file keeps the `script` or `text` kind, so its links are followed.
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
    elif len(_JS_SYNTAX.findall(head)) >= 2 and not _NOT_JS.search(head):
        kind = "javascript"
    else:
        css = _strip_css_comments(head)
        kind = "css" if _CSS_AT_RULE.match(css) or len(_CSS_BLOCK.findall(css)) >= 3 else None
    if kind is None:
        return None
    if _SHELL_STATEMENT.search(data) or _DROPPER_HINT.search(data) or _ACTIVE_CONTENT.search(data):
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
