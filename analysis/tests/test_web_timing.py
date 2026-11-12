"""Hostile inputs at the size caps classify in linear time.

Every input here used to make a pattern rescan the rest of the input from each position (an
unterminated comment, string or `url(` in a style sheet, an escaped quote in JSON, a long run of
flags after `rm -`), or floods the structure checks with tiny tokens. Each one is 4 MiB (the style
sheet check limit; JSON is checked up to 2 MiB) and must classify far below the analyzer child's
30 s CPU limit. The budget leaves room for a slow CI runner: on a busy two-core host each case
takes well under a second.
"""

from __future__ import annotations

import time

import pytest

from suckerpot_analysis import identify

BUDGET_S = 2.0
MIB4 = 4 * 1024 * 1024
MIB2 = 2 * 1024 * 1024 - 16


def fill(prefix: bytes, unit: bytes, size: int = MIB4) -> bytes:
    return prefix + unit * ((size - len(prefix)) // len(unit))


RULES = b"a{color:red}b{color:red}c{color:red}"
STRICT = b'"use strict";var a=1;'
CASES = {
    # Style sheets: unterminated comments, strings and url( after three rules, and floods.
    "css unterminated comments": fill(RULES, b"/*x"),
    "css unterminated url": fill(RULES, b"url(x"),
    "css unterminated strings": fill(RULES, b'"x'),
    "css unterminated single quotes": fill(RULES, b"'x"),
    "css escaped quotes": fill(RULES + b'"', b'\\"'),
    "css escaped url": fill(RULES, b"url(\\)"),
    "css star run": fill(RULES + b"/*", b"*"),
    "css semicolons": fill(RULES, b";"),
    "css empty rules": fill(RULES, b"a{}"),
    "css tiny rules": fill(RULES, b"a{b:c}"),
    "css open braces": fill(RULES, b"{"),
    "css close braces": fill(RULES, b"}"),
    "css deep nesting": RULES + (b"a{" * 32 + b"b:c" + b"}" * 32) * 20_000,
    "css real rules": fill(b"", b'.b{color:#fff;background:url("a.png") no-repeat}/* c */'),
    # JSON: escaped quotes in an unterminated string, nesting, tiny tokens.
    "json escaped quotes": fill(b'["', b'\\"', MIB2),
    "json unterminated strings": fill(b"[", b'"x\\', MIB2),
    "json open brackets": fill(b"", b"[", MIB2),
    "json nested objects": fill(b"", b'{"a":', MIB2),
    "json empty strings": fill(b"[", b'"",', MIB2) + b'""]',
    "json empty arrays": fill(b"[", b"[],", MIB2) + b"[]]",
    "json over the parse limit": fill(b'["', b'\\"'),
    # Pages: shell-like prefixes that never complete, and a plain large page.
    "html rm flags": fill(b"<html><body>rm -", b"r"),
    "html export name": fill(b"<html><body>\nexport ", b"a"),
    "html spaces after spawn": fill(b"<html><body>spawn", b" "),
    "html perl flags": fill(b"<html>", b"perl -a "),
    "html newlines": fill(b"<html>", b"\n"),
    "html failed redirects": fill(b"", b"<p x\n"),
    "html base64 dashes": fill(b"<html>", b"base64 -"),
    "html python dashes": fill(b"<html>", b"python3 -"),
    "html divs": fill(b"<!doctype html><html><body>", b"<div class='a'>x</div>"),
    # Scripts of a page: regular expression calls, module loads that are not, long runs.
    "js functions": fill(b'"use strict";', b"var a=function(){return 1};"),
    "js regexp exec": fill(STRICT, b"/x/.exec(a);"),
    "js open require": fill(STRICT, b"require("),
    "js open function of": fill(STRICT, b"Function( "),
    "js spaces after function": fill(STRICT + b"function", b" "),
    "js open import list": fill(STRICT + b"import{", b"a,"),
    "js open eval": fill(STRICT, b"eval( "),
    "js open Function": fill(STRICT, b"Function( "),
    "js writes without a module": fill(STRICT, b"document.write(a);x.pipe(b);"),
    "js open require of a string": fill(STRICT, b'require("'),
    "html node dashes": fill(b"<html>", b"node -x "),
    "html dot sources": fill(b"<html>\n", b". . "),
    "html process substitutions": fill(b"<html>", b"source <"),
    "html open attributes": fill(b"<html><body>", b'<a href="x'),
    "js every literal of a sign": fill(
        STRICT + b"var b=2;",
        b"sh rm perl python eval base64 iex download exec require( import( atob function cmd "
        b"runat <job <? | ./ /tmp -e process system popen spawn php ruby node lua source . <( "
        b"Function .write( .pipe( writefile ",
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_hostile_input_classifies_in_linear_time(name: str) -> None:
    data = CASES[name]
    start = time.monotonic()
    identify(data)
    elapsed = time.monotonic() - start
    assert elapsed < BUDGET_S, (name, len(data), round(elapsed, 3))


def test_asset_links_of_a_large_page_stay_fast() -> None:
    # The analysis reads the links of up to 1 MiB of a page, asset attributes included.
    from suckerpot_analysis.weblinks import asset_links

    page = fill(b"<html><body>", b'<a href="x"><img src=y style="u:url(z)">', 1024 * 1024)
    start = time.monotonic()
    asset_links(page.decode(), "html")
    assert time.monotonic() - start < BUDGET_S


def test_the_largest_input_stays_fast() -> None:
    # 16 MiB, the analyzer's input cap: the whole-input scans are linear and cheap.
    page = fill(b"<!doctype html><html><body>", b"<div class='a'>x</div>", 16 * 1024 * 1024)
    start = time.monotonic()
    assert identify(page).kind == "html"
    assert time.monotonic() - start < 2 * BUDGET_S
