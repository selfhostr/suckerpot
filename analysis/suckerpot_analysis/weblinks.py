"""Which links of a page or a style sheet are only its assets.

A URL is an asset of a page when a real start tag names it in an attribute that loads or points
at a resource for that element (``<img src>``, ``<link href>``, ``<form action>``, ``<video
poster>``, ``<object data>``...) or when a style sheet ``url(...)`` or ``@import`` names it (a
``<style>`` block, a ``style`` attribute, a CSS file). Anything else is not: the text of a page
(``src=...`` written as text), comments, the body of a ``<script>``, an attribute an element does
not load (``<b src>``), and in a style sheet a comment or a string. A URL that appears both as an
asset and anywhere else is not an asset either. Only the assets of web content can make the file
they point at "reached by crawling" (``suckerpot_db.sample_kinds``).

The markup is read by a small tokenizer that moves forward only (``find`` and anchored
``match``), and the style sheets by one ``finditer`` with possessive repeats, so the work is
linear in the input.
"""

from __future__ import annotations

import re

from .iocs import urls_in

ASSET_KINDS = frozenset({"html", "svg", "css"})

_LAZY = {"data-src", "data-srcset"}
# The attributes that load or point at a resource, per element (HTML and SVG).
_ASSET_ATTRS: dict[str, frozenset[str]] = {
    name: frozenset(attrs)
    for name, attrs in {
        "a": {"href", "xlink:href"},
        "area": {"href"},
        "link": {"href"},
        "base": {"href"},
        "img": {"src", "srcset", "longdesc", *_LAZY},
        "source": {"src", "srcset", *_LAZY},
        "script": {"src", "href", "xlink:href"},
        "iframe": {"src", *_LAZY},
        "frame": {"src", "longdesc"},
        "embed": {"src"},
        "audio": {"src"},
        "video": {"src", "poster", *_LAZY},
        "track": {"src"},
        "input": {"src", "formaction"},
        "button": {"formaction"},
        "form": {"action"},
        "object": {"data"},
        "body": {"background"},
        "table": {"background"},
        "td": {"background"},
        "th": {"background"},
        "blockquote": {"cite"},
        "q": {"cite"},
        "del": {"cite"},
        "ins": {"cite"},
        "html": {"manifest"},
        "image": {"href", "xlink:href"},
        "use": {"href", "xlink:href"},
        "feimage": {"href", "xlink:href"},
    }.items()
}
# Elements whose body is raw text, not markup: nothing inside is a tag or an attribute.
_RAW_TEXT = frozenset(
    {"script", "style", "textarea", "title", "xmp", "noembed", "noframes", "noscript", "iframe"}
)
_TAG_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9:_.-]{0,63}+")
# One attribute (or a stray `/`) inside a start tag. A quoted value that is never closed runs to
# the end of the input; the tag then never ends and the scan stops.
_TAG_ATTR = re.compile(
    r"[\s/]*+(?:(?P<name>[^\s\"'<>/=]++)(?:\s*+=\s*+(?:\"(?P<dq>[^\"]*+)(?P<dqe>\"?)"
    r"|'(?P<sq>[^']*+)(?P<sqe>'?)|(?P<uq>[^\s>]*+)))?)?"
)
# A style sheet: comments and strings are skipped whole, `url(...)` and `@import "..."` are kept.
_CSS = re.compile(
    r"/\*.*?(?:\*/|\Z)|\"(?:[^\"\\]++|\\.)*+(?:\"|\\?\Z)|'(?:[^'\\]++|\\.)*+(?:'|\\?\Z)"
    r"|(?P<url>(?i:url)\(\s*+(?:\"[^\"]*+\"?|'[^']*+'?|[^)\s\"']*+))"
    r"|(?P<imp>@(?i:import)\s*+(?:\"[^\"]*+\"?|'[^']*+'?))",
    re.DOTALL,
)


def _css_spans(text: str, start: int, end: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for m in _CSS.finditer(text, start, end):
        group = m.lastgroup
        if group is not None:
            spans.append(m.span(group))
    return spans


def _markup_spans(text: str) -> list[tuple[int, int]]:
    """Value spans of asset attributes of real start tags, and style sheet links."""
    low = text.lower()
    spans: list[tuple[int, int]] = []
    end = len(text)
    pos = 0
    while (lt := text.find("<", pos)) >= 0:
        if low.startswith("<!--", lt):
            close = low.find("-->", lt + 4)
            if close < 0:
                break
            pos = close + 3
            continue
        if low.startswith("<![cdata[", lt):
            close = low.find("]]>", lt + 9)
            if close < 0:
                break
            pos = close + 3
            continue
        if text.startswith(("</", "<!", "<?"), lt):
            close = text.find(">", lt + 2)
            if close < 0:
                break
            pos = close + 1
            continue
        tag = _TAG_NAME.match(text, lt + 1)
        if tag is None:
            pos = lt + 1  # a `<` in the text
            continue
        name = tag.group().lower()
        wanted = _ASSET_ATTRS.get(name, frozenset())
        p = tag.end()
        closed = False
        while p < end:
            if text.startswith(">", p):
                closed = True
                p += 1
                break
            m = _TAG_ATTR.match(text, p)
            if m is None or m.end() == p:
                p += 1  # a character no attribute can start with (a stray quote or `<`)
                continue
            p = m.end()
            if m.group("dq") is not None and not m.group("dqe"):
                break  # a value that is never closed: the tag never ends
            if m.group("sq") is not None and not m.group("sqe"):
                break
            attr = (m.group("name") or "").lower()
            group = next((g for g in ("dq", "sq", "uq") if m.group(g) is not None), None)
            if group is None:
                continue
            value = m.span(group)
            if attr == "style":
                spans.extend(_css_spans(text, *value))
            elif attr in wanted:
                spans.append(value)
        if not closed:
            break  # the input ends inside a tag
        pos = p
        if name in _RAW_TEXT:
            close = low.find("</" + name, pos)
            body_end = close if close >= 0 else end
            if name == "style":
                spans.extend(_css_spans(text, pos, body_end))
            if close < 0:
                break
            pos = close
    return spans


def asset_links(text: str, kind: str) -> frozenset[str]:
    """The URLs that `text` (a page or a style sheet of `kind`) names only as assets."""
    if kind not in ASSET_KINDS:
        return frozenset()
    spans = _css_spans(text, 0, len(text)) if kind == "css" else _markup_spans(text)
    assets: set[str] = set()
    rest: list[str] = []
    last = 0
    for start, end in sorted(spans):
        if start < last:
            continue  # overlapping (a style sheet link inside an attribute already taken)
        rest.append(text[last:start])
        assets.update(urls_in(text[start:end]))
        last = end
    rest.append(text[last:])
    return frozenset(assets.difference(urls_in(" ".join(rest))))
