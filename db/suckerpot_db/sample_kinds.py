"""Which collected samples are ordinary web content, as SQL conditions shared by the services.

The analyzer gives a fetched page, image, style sheet, JSON document or web script one of the
``WEB_SAMPLE_KINDS`` (the same set as ``suckerpot_analysis.WEB_KINDS``, which the collector's tests
compare it with) and the lowest severity, and a detection rule that matches it adds a family or a
higher severity. A sample that is web content and has neither is "benign web": it is kept and
shown, but it is not evidence of anything, so it never feeds a lookup, a blocklist, a report draft
or the network.

Everything returned here is constant text built from this module's own constants (or from an alias
that must be a plain identifier), never from input.
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


def benign_web_sample(alias: str) -> str:
    """SQL condition on a ``samples`` row: ordinary web content that no rule matched.

    Never NULL: a missing row (a ``LEFT JOIN`` without a match) or an unanalysed sample is false.
    """
    a = _ident(alias)
    return (
        f"COALESCE({a}.kind IN ({_KINDS_SQL}) AND {a}.severity = 'info' "
        f"AND {a}.family IS NULL, false)"
    )


def is_benign_web_hash(value_sql: str) -> str:
    """SQL condition: the hash in ``value_sql`` is the sha256 of a benign web sample.

    ``value_sql`` is a column reference such as ``i.value``. Only a 64-character hash can match.
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?", value_sql):
        raise ValueError("not a column reference")
    return f"""EXISTS (SELECT 1 FROM samples bw WHERE bw.sha256 = lower({value_sql})
        AND {benign_web_sample("bw")})"""  # noqa: S608  (column reference checked above)
