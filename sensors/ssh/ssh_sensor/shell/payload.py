"""Stand-in file contents: fake executables and downloaded files.

Nothing here is ever executed or fetched. A file is a short, believable header (stored) plus a
declared size (``Node.size``); the filler up to that size is generated on read, so a "700 KiB
binary" costs a few dozen bytes of memory. Everything is derived from a label (a file name or a
URL) with SHA-256, so the same label gives the same bytes on every run and nothing is shared
between unrelated files.
"""

from __future__ import annotations

import hashlib
import hmac
import posixpath
import struct
from dataclasses import dataclass
from urllib.parse import urlsplit


def _digest(key: bytes, label: str) -> bytes:
    """HMAC-SHA256 of ``label`` keyed with the install secret."""
    return hmac.new(key, label.encode("utf-8", "replace"), hashlib.sha256).digest()


def elf_header(key: bytes, label: str, size: int) -> bytes:
    """A valid 64-byte ELF64 header for a position-independent x86-64 executable.

    The entry point, the section header offset and the section count vary with ``label``;
    ``size`` is the size the file will be reported as, so the section table sits inside it."""
    d = _digest(key, "elf|" + label)
    shnum = 26 + d[0] % 6
    entry = 0x1000 + (int.from_bytes(d[1:3], "big") % 0x40) * 0x40
    shoff = max(64, size - shnum * 64 - (d[3] % 8) * 0x40)
    return struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF",
        2,  # ELFCLASS64
        1,  # little endian
        1,  # EV_CURRENT
        0,  # System V ABI
        0,
        3,  # ET_DYN (PIE)
        0x3E,  # EM_X86_64
        1,
        entry,
        64,  # program headers follow the ELF header
        shoff,
        0,
        64,  # e_ehsize
        56,  # e_phentsize
        13,  # e_phnum, typical for a PIE built by Ubuntu's toolchain
        64,  # e_shentsize
        shnum,
        shnum - 1,  # e_shstrndx
    )


# Approximate sizes of well-known binaries on Ubuntu 24.04 (bytes). Others get a size derived
# from their name.
_KNOWN_SIZES = {
    "bash": 1_446_024,
    "perl": 3_912_160,
    "python3": 8_027_792,
    "vim": 3_702_640,
    "gawk": 698_336,
    "git": 3_818_512,
    "ssh": 1_024_848,
    "openssl": 1_061_400,
    "systemctl": 297_056,
    "apt": 43_680,
    "curl": 273_976,
    "wget": 513_088,
    "sudo": 232_416,
    "sshd": 1_181_552,
}


def binary_size(key: bytes, name: str) -> int:
    """A plausible size for a system binary, stable for a given name."""
    known = _KNOWN_SIZES.get(name)
    if known is not None:
        return known
    u = int.from_bytes(_digest(key, "size|" + name)[:4], "big") / 2**32
    return int(14_000 * (30**u)) + _digest(key, "size2|" + name)[0] % 8 * 8


def system_binary(key: bytes, name: str) -> tuple[bytes, int]:
    """``(stored header, declared size)`` of ``/usr/bin/<name>``."""
    size = binary_size(key, name)
    return elf_header(key, name, size), size


@dataclass(frozen=True, slots=True)
class Payload:
    """What a fake download leaves on disk."""

    content: bytes
    size: int  # declared size (>= len(content))
    mime: str  # Content-Type the fake server "sent"
    tag: str  # "elf" or "script", as ``Node.tag``


_SCRIPT_EXT = {
    ".sh": ("application/x-sh", ("#!/bin/sh", "#!/bin/bash")),
    ".py": ("text/x-python", ("#!/usr/bin/env python3", "#!/usr/bin/python3")),
    ".pl": ("text/x-perl", ("#!/usr/bin/perl",)),
}
_TEXT_EXT = {
    ".txt": "text/plain",
    ".conf": "text/plain",
    ".cfg": "text/plain",
    ".json": "application/json",
    ".html": "text/html",
    ".htm": "text/html",
    ".php": "text/html",
}
_ARCHIVE_EXT = {
    ".gz": ("application/gzip", b"\x1f\x8b\x08\x00"),
    ".tgz": ("application/gzip", b"\x1f\x8b\x08\x00"),
    ".zip": ("application/zip", b"PK\x03\x04\x14\x00"),
}


def _filler_lines(d: bytes, size: int, prefix: str, suffix: str = "") -> str:
    """Comment-like lines of hex words, about ``size`` characters in all."""
    hexes = hashlib.shake_128(d).hexdigest(max(48, size))
    lines: list[str] = []
    total = 0
    pos = 0
    while total < size and pos + 48 <= len(hexes):
        words = " ".join(hexes[pos + k : pos + k + 8] for k in range(0, 48, 8))
        line = f"{prefix}{words}{suffix}"
        lines.append(line)
        total += len(line) + 1
        pos += 48
    return "\n".join(lines) + "\n" if lines else ""


def payload_for(key: bytes, url: str) -> Payload:
    """The file a download of ``url`` appears to produce: type from the extension, size and
    filler from the whole URL."""
    try:
        path = urlsplit(url).path
    except ValueError:  # e.g. an unterminated IPv6 literal
        path = ""
    name = posixpath.basename(path).lower()
    ext = posixpath.splitext(name)[1]
    d = _digest(key, "payload|" + url)
    u = int.from_bytes(d[:4], "big") / 2**32
    if ext in _SCRIPT_EXT:
        mime, shebangs = _SCRIPT_EXT[ext]
        text = shebangs[d[4] % len(shebangs)] + "\n\n"
        text += _filler_lines(d, 40 + int(1800 * u * u), "# ")
        if ext == ".sh":
            text += "exit 0\n"
        return Payload(text.encode("ascii"), len(text), mime, "script")
    if ext in _TEXT_EXT or not name:
        mime = _TEXT_EXT.get(ext, "text/html")
        n = 120 + int(2400 * u * u)
        if "html" in mime:
            text = (
                "<!DOCTYPE html>\n<html>\n<head><title>Index</title></head>\n<body>\n"
                + _filler_lines(d, n, "<!-- ", " -->")
                + "</body>\n</html>\n"
            )
        elif "json" in mime:
            text = '{"status":"ok","id":"' + d.hex()[:16] + '"}\n'
        else:
            text = _filler_lines(d, n, "# ")
        return Payload(text.encode("ascii"), len(text), mime, "")
    if ext in _ARCHIVE_EXT:
        mime, magic = _ARCHIVE_EXT[ext]
        size = int(9_000 * (60**u))
        return Payload(magic, size, mime, "")
    size = int(16_000 * (40**u))
    return Payload(elf_header(key, url, size), size, "application/octet-stream", "elf")
