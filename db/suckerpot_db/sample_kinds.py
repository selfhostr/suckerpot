"""Which collected samples are plain web content, as SQL conditions shared by the services.

The analyzer gives a fetched page, image, style sheet, JSON document or web script one of the
``WEB_SAMPLE_KINDS`` (the same set as ``suckerpot_analysis.WEB_KINDS``, which the collector's tests
compare it with) and the lowest severity; a detection rule that matches it adds a family or a
higher severity. That is "web content" (``web_content``).

The kind alone never spares a file, because a program can be dressed as a page. A sample is
"plain web" (``plain_web_sample``) only when it is web content AND the collector reached it by
following links found in other web content, never because an attacker asked for it
(``crawled_from_web``): every one of its sources is a fetch target that no attacker typed (no
indicator), at depth 1 or more, whose parent sample is web content. Network verification fetches
count neither way. A sample with no source, a parent not analysed yet, a source an attacker typed
(depth 0, or a URL that also has an indicator) or a link found in a script or a binary makes it
attacker content, whatever its kind.

A plain web sample is kept and shown, but it is not evidence of anything: its links are not
followed, it gets no hash indicator, and it never feeds a lookup, a blocklist, a report draft or
the network.

Everything returned here is constant text built from this module's own constants (or from an alias
that must be a plain identifier), never from input. Every subquery is bounded by one sample's
sources (``sample_sources`` primary key) and one parent row each.
"""

from __future__ import annotations

import re
from typing import Final

WEB_SAMPLE_KINDS: Final[tuple[str, ...]] = ("html", "svg", "xml", "css", "json", "javascript")

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


def _web_link(target: str, parent: str) -> str:
    """A fetch target found inside web content and never typed by an attacker. Never NULL."""
    return f"({target}.indicator_id IS NULL AND {target}.depth >= 1 AND {web_content(parent)})"


def _sources(alias: str, where: str, *, parent_join: str) -> str:
    a = _ident(alias)
    return f"""SELECT 1 FROM sample_sources {a}_ss
        JOIN fetch_targets {a}_ft ON {a}_ft.id = {a}_ss.target_id
        {parent_join} samples {a}_pa ON {a}_pa.sha256 = {a}_ft.parent_sha256
        WHERE {a}_ss.sha256 = {a}.sha256 AND {where}"""  # noqa: S608  (identifiers checked above)


def attacker_source(alias: str) -> str:
    """SQL condition on a ``samples`` row: one of its sources is something an attacker asked
    for, directly or through a script or a binary: a target with an indicator, at depth 0 (other
    than a network verification fetch), or found inside a sample that is not web content."""
    a = _ident(alias)
    verify = f"({a}_ft.origin = 'network_verify' AND {a}_ft.indicator_id IS NULL)"
    where = f"NOT {_web_link(f'{a}_ft', f'{a}_pa')} AND NOT {verify}"
    return f"EXISTS ({_sources(a, where, parent_join='LEFT JOIN')})"


def crawled_from_web(alias: str) -> str:
    """SQL condition on a ``samples`` row: reached only by following links found in other web
    content (at least one such source, and no ``attacker_source``). Never NULL."""
    a = _ident(alias)
    linked = f"EXISTS ({_sources(a, _web_link(f'{a}_ft', f'{a}_pa'), parent_join='JOIN')})"
    return f"({linked} AND NOT {attacker_source(a)})"


def plain_web_sample(alias: str) -> str:
    """SQL condition on a ``samples`` row: web content that no rule matched and that the collector
    reached only by following links in other web content. Never NULL."""
    a = _ident(alias)
    return f"({web_content(a)} AND {crawled_from_web(a)})"


def reopened_web_sample(alias: str) -> str:
    """SQL condition on a ``samples`` row: web content the analyzer spared (done, no hash
    indicator) that an attacker has asked for since. Analysed again, it is treated as attacker
    content. A sample fetched only for the network verification has no attacker source."""
    a = _ident(alias)
    return f"""({a}.analysis_status = 'done' AND {web_content(a)} AND {attacker_source(a)}
        AND NOT EXISTS (SELECT 1 FROM indicators {a}_hi
                        WHERE {a}_hi.type = 'hash' AND {a}_hi.value = {a}.sha256))"""  # noqa: S608


def is_plain_web_hash(value_sql: str) -> str:
    """SQL condition: the hash in ``value_sql`` is the sha256 of a plain web sample.

    ``value_sql`` is a column reference such as ``i.value``. Only a 64-character hash can match.
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?", value_sql):
        raise ValueError("not a column reference")
    return f"""EXISTS (SELECT 1 FROM samples pw WHERE pw.sha256 = lower({value_sql})
        AND {plain_web_sample("pw")})"""  # noqa: S608  (column reference checked above)
