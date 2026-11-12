"""Only the assets of a page or a style sheet are labelled `web_asset`; every other link is not."""

from __future__ import annotations

import time

from suckerpot_analysis import CompiledRules, analyze
from suckerpot_analysis.weblinks import asset_links

U = "http://192.0.2.1"
PAGE = (
    f'<!doctype html><html><head><link rel="stylesheet" href="{U}/site.css">'
    f"<style>body{{background:url({U}/bg.png)}}</style></head>"
    f'<body style="background:url(\'{U}/b2.png\')"><img src={U}/a.png srcset="{U}/a2.png 2x">'
    f'<form action="{U}/post"><video poster="{U}/p.jpg"></video><object data="{U}/o.swf">'
    f"<p>get it at {U}/text.js or {U}/both.js</p>"
    f'<script src="{U}/both.js"></script><script>fetch("{U}/inline.js");x.src="{U}/prop.js"'
    f"</script><!-- {U}/comment.js --></body></html>"
)


def names(urls: frozenset[str]) -> set[str]:
    return {u.rsplit("/", 1)[1] for u in urls}


def test_markup_assets() -> None:
    assert names(asset_links(PAGE, "html")) == {
        "site.css", "bg.png", "b2.png", "a.png", "a2.png", "post", "p.jpg", "o.swf",
    }  # fmt: skip


def test_a_link_in_the_text_or_a_script_is_never_an_asset() -> None:
    found = names(asset_links(PAGE, "html"))
    # In the text, in an inline script, a property set by a script, a comment, and a URL that is
    # both an asset and in the text.
    assert not found & {"text.js", "inline.js", "prop.js", "comment.js", "both.js"}


def test_style_sheet_assets() -> None:
    css = f"@import '{U}/a.css';body{{background:url({U}/bg.png)}}/* {U}/c.png */a{{color:red}}"
    assert names(asset_links(css, "css")) == {"a.css", "bg.png"}
    svg = f'<svg><image href="{U}/i.png"/><a xlink:href="{U}/l.svg"/><text>{U}/t.js</text></svg>'
    assert names(asset_links(svg, "svg")) == {"i.png", "l.svg"}


def test_only_real_start_tags_name_assets() -> None:
    page = (
        f'<!doctype html><html><body><p>src="{U}/text.js" href={U}/t2.js</p>'
        f'<!-- <img src="{U}/comment.png"> -->'
        f"<script>var h='<a href=\"{U}/in-script.js\">';</script>"
        f'<b src="{U}/not-loaded.js">x</b><span href="{U}/span.js">y</span>'
        f'<textarea><img src="{U}/textarea.png"></textarea>'
        f'<noscript><img src="{U}/noscript.png"></noscript>'
        f'<style>/* url({U}/css-comment.png) */ a{{content:"url({U}/css-string.png)";'
        f"background:url({U}/real.png)}}</style>"
        f"<img src=\"{U}/ok.png\"><a href='{U}/next.html'>n</a></body></html>"
    )
    assert names(asset_links(page, "html")) == {"real.png", "ok.png", "next.html"}


def test_the_polyglot_page_names_no_asset() -> None:
    # The first line opens a <b> tag; `src` is not an attribute a <b> loads.
    poly = f'<b x\nsrc="{U}/s2.js"\npython3 - "$src" <<\'E\'\nimport sys\nE\nnode /tmp/s\n'
    assert asset_links(poly, "html") == frozenset()


def test_a_letter_that_grows_when_lowered_does_not_shift_the_scan() -> None:
    # "İ".lower() is two characters: a lowered copy indexed against the original would land the
    # scan back inside the script body, and the URL used only by its code would become an asset.
    page = (
        "İ" * 100 + f'<script title="</script>">var u="{U}/code.js";</script><img src="{U}/i.png">'
    )
    assert names(asset_links(page, "html")) == {"i.png"}


def test_plaintext_template_and_unclosed_tags_name_no_asset() -> None:
    plaintext = f'<p>x</p><plaintext><img src="{U}/after.png">'
    assert asset_links(plaintext, "html") == frozenset()
    template = (
        f'<template><img src="{U}/t1.png"><template><img src="{U}/t2.png"></template>'
        f'<img src="{U}/t3.png"></template><img src="{U}/out.png">'
    )
    assert names(asset_links(template, "html")) == {"out.png"}
    assert asset_links(f'<template><img src="{U}/never.png">', "html") == frozenset()
    unclosed = f'<img src="{U}/a.png"><img src="{U}/unclosed.png" alt=x'
    assert names(asset_links(unclosed, "html")) == {"a.png"}


def test_other_kinds_have_no_assets() -> None:
    for kind in ("javascript", "json", "xml", "text", "script"):
        assert asset_links(PAGE, kind) == frozenset(), kind


def test_unterminated_markup_and_styles_stay_linear_and_safe() -> None:
    hostile = '<a href="' + "x" * 300_000 + "<style>" + "url(" * 50_000
    assert asset_links(hostile, "html") == frozenset()
    assert asset_links("url(" * 200_000, "css") == frozenset()
    for text, kind in (
        ("<a " + "x " * 500_000, "html"),  # one tag, many attributes, never closed
        ("<" * 1_000_000, "html"),
        ("<a href=x>" * 100_000, "html"),
        ("<style>" + '"x' * 400_000, "html"),
        ("<!--" * 250_000, "html"),
        ('"x\\' * 300_000, "css"),
        ("/*x" * 300_000, "css"),
    ):
        start = time.monotonic()
        asset_links(text, kind)
        assert time.monotonic() - start < 2.0, (text[:20], kind)


def test_the_analysis_labels_each_next_url(rules: CompiledRules) -> None:
    result = analyze(PAGE.encode(), rules=rules)
    assert result.file.kind == "html"
    labels = {i.value.rsplit("/", 1)[1]: i.source for i in result.iocs if i.kind == "next_url"}
    assert labels["site.css"] == labels["a.png"] == "web_asset"
    assert labels["text.js"] == labels["both.js"] == labels["inline.js"] == "script_url"
    script = analyze(f"#!/bin/sh\nwget {U}/site.css\n".encode(), rules=rules)
    assert [i.source for i in script.iocs if i.kind == "next_url"] == ["script_url"]
