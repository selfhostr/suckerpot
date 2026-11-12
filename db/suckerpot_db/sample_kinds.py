"""Which collected samples are plain web content, as SQL conditions shared by the services.

The analyzer gives a fetched page, image, style sheet, JSON document or web script one of the
``WEB_SAMPLE_KINDS`` (the same set as ``suckerpot_analysis.WEB_KINDS``, which the collector's tests
compare it with) and the lowest severity; a detection rule that matches it adds a family or a
higher severity. That is "web content" (``web_content``).

The kind alone never spares a file, because a program can be dressed as a page. A sample is
"plain web" (``plain_web_sample``) only when it is web content AND the collector reached it by
following asset links of other web content, never because an attacker asked for it
(``crawled_from_web``). Every one of its sources must be a crawl link (``_crawl_link``): a fetch
target that no attacker ever typed (``typed``, kept when the indicator is pruned), at depth 1 or
more, that at least one file links to, and that EVERY file linking to it (``sample_links`` rows
pointing at it, one per parent, not only the first parent) names as an asset (a markup attribute
or a style sheet ``url()`` / ``@import``, source ``web_asset``) and is web content. A link in the
text of a page, in a web script, in a shell script or in a binary makes the file attacker content
whatever its kind. Network verification fetches count neither way; a sample with no source is
attacker content.

A plain web sample is kept and shown, but it is not evidence of anything: its links are not
followed, it gets no hash indicator, and it never feeds a lookup, a blocklist, a report draft or
the network. ``samples.spared`` records that the analyzer did not act on a file, and
``reopened_sample`` finds one that an attacker has asked for since.

Everything returned here is constant text built from this module's own constants (or from an alias
that must be a plain identifier), never from input. Every subquery is bounded by one sample's
sources (``sample_sources`` primary key) and one target's links (``ix_sample_links_target``).
"""

from __future__ import annotations

import re
from typing import Final

WEB_SAMPLE_KINDS: Final[tuple[str, ...]] = ("html", "svg", "xml", "css", "json", "javascript")
# `sample_links.source` of a link that a page or a style sheet names only as an asset.
WEB_ASSET: Final = "web_asset"

_IDENT = re.compile(r"[a-z_][a-z0-9_]{0,30}")
_KINDS_SQL = ", ".join(f"'{k}'" for k in WEB_SAMPLE_KINDS)


def _ident(value: str) -> str:
    if not _IDENT.fullmatch(value):
        raise ValueError("not a plain SQL identifier")
    return value


def web_content(alias: str) -> str:
    """SQL condition on a ``samples`` row: a web kind that no rule matched (lowest severity, no
    family). Never NULL: a missing row (a ``LEFT JOIN`` without a match) or an unanalysed sample
    is false. The kind only: see ``plain_web_sample`` for what may be spared."""
    a = _ident(alias)
    return (
        f"COALESCE({a}.kind IN ({_KINDS_SQL}) AND {a}.severity = 'info' "
        f"AND {a}.family IS NULL, false)"
    )


def _crawl_link(t: str) -> str:
    """SQL condition on a ``fetch_targets`` row: only asset links of web content lead to it and
    no attacker typed it. Never NULL."""
    t = _ident(t)
    asset = f"{t}_l.source = '{WEB_ASSET}' AND {web_content(f'{t}_p')}"
    return f"""(NOT {t}.typed AND {t}.indicator_id IS NULL AND {t}.depth >= 1
        AND EXISTS (SELECT 1 FROM sample_links {t}_l
                    WHERE {t}_l.target_id = {t}.id AND {t}_l.kind = 'next_url')
        AND NOT EXISTS (SELECT 1 FROM sample_links {t}_l
                        LEFT JOIN samples {t}_p ON {t}_p.sha256 = {t}_l.sha256
                        WHERE {t}_l.target_id = {t}.id AND {t}_l.kind = 'next_url'
                          AND NOT ({asset})))"""  # noqa: S608  (identifiers checked above)


def _verify_only(t: str) -> str:
    return f"({t}.origin = 'network_verify' AND NOT {t}.typed AND {t}.indicator_id IS NULL)"


def _source_exists(alias: str, where: str) -> str:
    a = _ident(alias)
    return f"""EXISTS (SELECT 1 FROM sample_sources {a}_ss
        JOIN fetch_targets {a}_ft ON {a}_ft.id = {a}_ss.target_id
        WHERE {a}_ss.sha256 = {a}.sha256 AND {where})"""  # noqa: S608  (identifiers checked above)


def attacker_source(alias: str) -> str:
    """SQL condition on a ``samples`` row: one of its sources is something an attacker asked
    for, directly or through anything but the assets of web content: a typed URL, depth 0 (other
    than a network verification fetch), or a target that a link other than a web asset leads to."""
    a = _ident(alias)
    t = f"{a}_ft"
    return _source_exists(a, f"NOT {_crawl_link(t)} AND NOT {_verify_only(t)}")


def crawled_from_web(alias: str) -> str:
    """SQL condition on a ``samples`` row: reached only by following asset links of other web
    content (at least one such source, and no ``attacker_source``). Never NULL."""
    a = _ident(alias)
    return f"({_source_exists(a, _crawl_link(f'{a}_ft'))} AND NOT {attacker_source(a)})"


def plain_web_sample(alias: str) -> str:
    """SQL condition on a ``samples`` row: web content that no rule matched and that the collector
    reached only through asset links of other web content. Never NULL."""
    a = _ident(alias)
    return f"({web_content(a)} AND {crawled_from_web(a)})"


def web_parent_target(alias: str) -> str:
    """SQL condition on a ``fetch_targets`` row: no attacker typed it and every file that links
    to it (or queued it) is plain web content, so it is not fetched. Never NULL."""
    t = _ident(alias)
    parents = f"""SELECT {t}_l.sha256 FROM sample_links {t}_l
        WHERE {t}_l.target_id = {t}.id AND {t}_l.kind = 'next_url'
        UNION SELECT {t}.parent_sha256 WHERE {t}.parent_sha256 IS NOT NULL"""  # noqa: S608
    return f"""(NOT {t}.typed AND {t}.indicator_id IS NULL AND {t}.depth >= 1
        AND EXISTS ({parents})
        AND NOT EXISTS (SELECT 1 FROM ({parents}) {t}_pp (sha256)
                        LEFT JOIN samples {t}_ps ON {t}_ps.sha256 = {t}_pp.sha256
                        WHERE NOT {plain_web_sample(f"{t}_ps")}))"""  # noqa: S608


def reopened_sample(alias: str) -> str:
    """SQL condition on a ``samples`` row: a file the analyzer spared (``spared``: plain web
    content, or fetched only for a network verification) that an attacker has asked for since.
    Analysed again, it is treated as attacker content."""
    a = _ident(alias)
    return f"({a}.analysis_status = 'done' AND {a}.spared AND {attacker_source(a)})"


def is_plain_web_hash(value_sql: str) -> str:
    """SQL condition: the hash in ``value_sql`` is the sha256 of a plain web sample.

    ``value_sql`` is a column reference such as ``i.value``. Only a 64-character hash can match.
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?", value_sql):
        raise ValueError("not a column reference")
    return f"""EXISTS (SELECT 1 FROM samples pw WHERE pw.sha256 = lower({value_sql})
        AND {plain_web_sample("pw")})"""  # noqa: S608  (column reference checked above)
