"""Only the assets of a page or a style sheet are labelled `web_asset`; every other link is not."""

from __future__ import annotations

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


def test_other_kinds_have_no_assets() -> None:
    for kind in ("javascript", "json", "xml", "text", "script"):
        assert asset_links(PAGE, kind) == frozenset(), kind


def test_unterminated_markup_and_styles_stay_linear_and_safe() -> None:
    hostile = '<a href="' + "x" * 300_000 + "<style>" + "url(" * 50_000
    assert asset_links(hostile, "html") == frozenset()
    assert asset_links("url(" * 200_000, "css") == frozenset()


def test_the_analysis_labels_each_next_url(rules: CompiledRules) -> None:
    result = analyze(PAGE.encode(), rules=rules)
    assert result.file.kind == "html"
    labels = {i.value.rsplit("/", 1)[1]: i.source for i in result.iocs if i.kind == "next_url"}
    assert labels["site.css"] == labels["a.png"] == "web_asset"
    assert labels["text.js"] == labels["both.js"] == labels["inline.js"] == "script_url"
    script = analyze(f"#!/bin/sh\nwget {U}/site.css\n".encode(), rules=rules)
    assert [i.source for i in script.iocs if i.kind == "next_url"] == ["script_url"]
