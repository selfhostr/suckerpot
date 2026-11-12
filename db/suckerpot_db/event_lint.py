"""Static check: no query on ``events`` by ``session_id`` without a ``ts`` bound.

``events`` is a hypertable on ``ts`` with compressed chunks, so a statement filtered on
``session_id`` alone opens and decompresses every chunk (see ``suckerpot_db.event_bounds``).
Both checks read source text only and are meant for the static tests of ``api`` and ``ingest``:

* raw SQL: a string constant that reads ``FROM events`` or ``JOIN events`` and filters on
  ``session_id`` must also compare ``ts`` (``ts >= ...``, ``e.ts < ...``);
* ORM: a function that filters ``EventRow.session_id`` (or an alias bound with ``e = EventRow``)
  must also use ``ts`` of the same name, or build its statement with an ``event_bounds`` helper
  (``group_events_*`` reads the events of a flood group, which have no session id of their own).

The check is deliberately simple. It cannot prove that a bound is narrow, only that one is there.
"""

from __future__ import annotations

import ast
import re

_RAW_EVENTS = re.compile(r"\b(?:FROM|JOIN)\s+events\b", re.IGNORECASE)
_RAW_SESSION_FILTER = re.compile(r"\bsession_id\s*(?:=|IN\b|<>|!=)", re.IGNORECASE)
_RAW_TS_BOUND = re.compile(r"(?<![\w.])(?:\w+\.)?ts\s*(?:>=|>|<=|<|BETWEEN\b)", re.IGNORECASE)
_HELPERS = frozenset(
    {
        "session_events_select",
        "session_events_where",
        "SQL_EVENT_TS_BOUND",
        # Flood groups: their events are found by source, sensor and port inside the group's
        # time range, not by a session id of their own.
        "group_events_select",
        "group_events_where",
        "SQL_GROUP_EVENT_BOUND",
    }
)


def _strings(node: ast.AST) -> list[tuple[int, str]]:
    """Every string literal with its line; an f-string counts as its constant parts joined."""
    out: list[tuple[int, str]] = []
    inside: set[int] = set()  # the pieces of an f-string are not statements of their own
    for sub in ast.walk(node):
        if isinstance(sub, ast.JoinedStr):
            inside.update(id(v) for v in sub.values)
            parts = "".join(str(v.value) for v in sub.values if isinstance(v, ast.Constant))
            out.append((sub.lineno, parts))
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) and id(sub) not in inside:
            out.append((sub.lineno, sub.value))
    return out


def raw_sql_problems(tree: ast.AST) -> list[int]:
    """Lines of raw SQL strings that read ``events`` by ``session_id`` with no ``ts`` bound."""
    bad: list[int] = []
    for line, text in _strings(tree):
        if (
            _RAW_EVENTS.search(text)
            and _RAW_SESSION_FILTER.search(text)
            and not _RAW_TS_BOUND.search(text)
        ):
            bad.append(line)
    return sorted(set(bad))


def _aliases(func: ast.AST) -> set[str]:
    names = {"EventRow"}
    for sub in ast.walk(func):
        if (
            isinstance(sub, ast.Assign)
            and isinstance(sub.value, ast.Name)
            and sub.value.id == "EventRow"
        ):
            names.update(t.id for t in sub.targets if isinstance(t, ast.Name))
    return names


def orm_problems(tree: ast.AST) -> list[int]:
    """Lines of functions that filter ``EventRow.session_id`` without any ``ts`` use."""
    bad: list[int] = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        names = _aliases(func)
        attrs = [n for n in ast.walk(func) if isinstance(n, ast.Attribute)]
        filtered = [
            a
            for a in attrs
            if a.attr == "session_id" and isinstance(a.value, ast.Name) and a.value.id in names
        ]
        if not filtered:
            continue
        has_ts = any(
            a.attr == "ts" and isinstance(a.value, ast.Name) and a.value.id in names for a in attrs
        )
        has_helper = any(
            (isinstance(n, ast.Name) and n.id in _HELPERS)
            or (isinstance(n, ast.Attribute) and n.attr in _HELPERS)
            for n in ast.walk(func)
        )
        if not (has_ts or has_helper):
            bad.append(filtered[0].lineno)
    return sorted(set(bad))


def find_unbounded_event_queries(source: str) -> list[int]:
    """Line numbers of event lookups by ``session_id`` that carry no ``ts`` bound."""
    tree = ast.parse(source)
    return sorted(set(raw_sql_problems(tree)) | set(orm_problems(tree)))
