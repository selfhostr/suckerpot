"""Which links of a page or a style sheet are only its assets.

A URL in a markup attribute that loads or points at a resource (``href``, ``src``, ``srcset``,
``action``, ``poster``, ``data``...) or in a style sheet ``url(...)`` or ``@import`` is an asset of
the page. A URL anywhere else (the text of a page, an inline script, a comment) is not, and a URL
that appears in both places is not either. Only the assets of web content can make the file they
point at "reached by crawling" (``suckerpot_db.sample_kinds``): a link in the text of a page, in
a web script or in JSON is followed like a link in a shell script.

Every pattern is linear: bounded, possessive repeats; ``<style>`` blocks are found with ``find``.
"""

from __future__ import annotations

import re

from .iocs import urls_in

ASSET_KINDS = frozenset({"html", "svg", "css"})
_ATTR = re.compile(
    r"(?<![\w:.-])(href|src|srcset|action|formaction|poster|data|background|cite|longdesc"
    r"|manifest|icon|xlink:href|data-src|data-srcset|style)\s*+=\s*+"
    r"(?:\"([^\"]{0,8192}+)\"|'([^']{0,8192}+)'|([^\s\"'<>`]{1,8192}+))",
    re.IGNORECASE,
)
_CSS_LINK = re.compile(
    r"url\(\s*+[\"']?[^\"')\s]{1,2048}+|@import\s++[\"'][^\"']{1,2048}+", re.IGNORECASE
)


def _css_spans(text: str, start: int, end: int) -> list[tuple[int, int]]:
    return [m.span() for m in _CSS_LINK.finditer(text, start, end)]


def _markup_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for m in _ATTR.finditer(text):
        group = next(g for g in (2, 3, 4) if m.group(g) is not None)
        start, end = m.span(group)
        if m.group(1).lower() == "style":
            spans.extend(_css_spans(text, start, end))
        else:
            spans.append((start, end))
    low = text.lower()
    pos = 0
    while (open_at := low.find("<style", pos)) >= 0:
        body = low.find(">", open_at)
        if body < 0:
            break
        close = low.find("</style", body)
        end = close if close >= 0 else len(text)
        spans.extend(_css_spans(text, body + 1, end))
        pos = end
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
            continue  # inside an attribute value already taken
        rest.append(text[last:start])
        assets.update(urls_in(text[start:end]))
        last = end
    rest.append(text[last:])
    return frozenset(assets.difference(urls_in(" ".join(rest))))
