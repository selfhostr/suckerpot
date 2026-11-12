"""Static check: a count of sessions must sum ``connections`` (see ``suckerpot_db.session_counts``).

A flood group is one ``sessions`` row for many connections, so ``count(*)`` over sessions
undercounts them. The check reads source text only and is run by the ``db`` tests over ``ingest``
and ``api``:

* raw SQL: a string constant that reads ``FROM sessions`` or ``JOIN sessions`` and uses
  ``count(*)``, ``count(1)`` or ``count(session_id)`` while never naming ``connections``;
* ORM: a function that mentions ``SessionRow`` and calls ``func.count()`` with no argument (or with
  a ``session_id`` column).

``count(DISTINCT ...)`` is fine, and so is any statement that names ``connections``. A deliberate
count of rows carries the comment ``# session-rows-ok: <why>`` on the statement or on the line
above it.

A site is reported as ``(function, line)``. ``function`` is the dotted name of the enclosing
function, the name a module level string is assigned to, or ``<module>``; ``find_sites_by_name``
gives the set of those names, which is what the checked-in allow-lists of the tests hold.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from suckerpot_db.session_counts import ROW_COUNT_MARKER

_RAW_SESSIONS = re.compile(r"\b(?:FROM|JOIN)\s+sessions\b", re.IGNORECASE)
_RAW_ROW_COUNT = re.compile(r"\bcount\s*\(\s*(?:\*|1|(?:\w+\.)?session_id)\s*\)", re.IGNORECASE)
_RAW_CONNECTIONS = re.compile(r"\bconnections\b", re.IGNORECASE)
_MARKER = re.compile(rf"#\s*{re.escape(ROW_COUNT_MARKER)}\b")


def _walk(
    node: ast.AST, scope: tuple[str, ...], stmt: ast.stmt | None
) -> Iterator[tuple[ast.AST, tuple[str, ...], ast.stmt | None]]:
    """Every node with its enclosing scope (class and function names) and nearest statement."""
    if isinstance(node, ast.stmt):
        stmt = node
    yield node, scope, stmt
    inner = scope
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        inner = (*scope, node.name)
    for child in ast.iter_child_nodes(node):
        yield from _walk(child, inner, stmt)


def _label(scope: tuple[str, ...], stmt: ast.stmt | None) -> str:
    if scope:
        return ".".join(scope)
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        target = stmt.targets[0]
        if isinstance(target, ast.Name):
            return target.id
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    return "<module>"


def _marked(lines: list[str], stmt: ast.stmt | None, node: ast.expr) -> bool:
    """The marker comment sits on the statement, on a line of the node, or just above."""
    first, last = node.lineno, node.end_lineno or node.lineno
    if stmt is not None:
        first, last = min(first, stmt.lineno), max(last, stmt.end_lineno or last)
    return any(_MARKER.search(line) for line in lines[max(first - 2, 0) : last])


def _strings(tree: ast.AST) -> dict[int, str]:
    """Every string literal by node id; an f-string counts as its constant parts joined."""
    out: dict[int, str] = {}
    inside: set[int] = set()  # the pieces of an f-string are not statements of their own
    for sub in ast.walk(tree):
        if isinstance(sub, ast.JoinedStr):
            inside.update(id(v) for v in sub.values)
            out[id(sub)] = "".join(str(v.value) for v in sub.values if isinstance(v, ast.Constant))
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) and id(sub) not in inside:
            out[id(sub)] = sub.value
    return out


def _func_count(node: ast.AST) -> ast.Call | None:
    """``func.count(...)`` (any arguments), or None."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "count"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "func"
    ):
        return node
    return None


def _counts_rows(call: ast.Call) -> bool:
    """No argument, or a ``session_id`` column: a count of rows."""
    if call.keywords:
        return False
    if not call.args:
        return True
    arg = call.args[0]
    return len(call.args) == 1 and isinstance(arg, ast.Attribute) and arg.attr == "session_id"


def find_row_counts(source: str) -> list[tuple[str, int]]:
    """``(function, line)`` of every count of ``sessions`` rows that is not marked deliberate."""
    tree = ast.parse(source)
    lines = source.splitlines()
    found: set[tuple[str, int]] = set()
    strings = _strings(tree)
    mentions: set[tuple[str, ...]] = {
        scope
        for node, scope, _stmt in _walk(tree, (), None)
        if isinstance(node, ast.Name) and node.id == "SessionRow"
    }

    for node, scope, stmt in _walk(tree, (), None):
        if not isinstance(node, ast.expr):
            continue
        text = strings.get(id(node))
        if text is not None:
            docstring = isinstance(stmt, ast.Expr) and stmt.value is node
            if (
                not docstring
                and _RAW_SESSIONS.search(text)
                and _RAW_ROW_COUNT.search(text)
                and not _RAW_CONNECTIONS.search(text)
                and not _marked(lines, stmt, node)
            ):
                found.add((_label(scope, stmt), node.lineno))
            continue
        call = _func_count(node)
        if (
            call is not None
            and _counts_rows(call)
            # SessionRow is named in this function, in one it is nested in, or at module level.
            and any(scope[:depth] in mentions for depth in range(len(scope) + 1))
            and not _marked(lines, stmt, call)
        ):
            found.add((_label(scope, stmt), call.lineno))
    return sorted(found, key=lambda site: (site[1], site[0]))


def find_sites_by_name(source: str) -> set[str]:
    """The distinct function names of ``find_row_counts`` (what an allow-list records)."""
    return {name for name, _line in find_row_counts(source)}
