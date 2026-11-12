"""How to count sessions now that a flood of connections can fold into one row.

A ``sessions`` row is one connection, or a flood group (``kind = 'burst'``) that stands for
``connections`` of them (migration 0034). So the number of sessions is never ``count(*)``: it is
``coalesce(sum(connections), 0)``. ``coalesce`` matters: ``sum`` over no rows is NULL, where
``count(*)`` gave 0. The FILTER forms follow the same rule.

What does not change: ``count(DISTINCT src_ip)`` and the other distinct counts (a group keeps its
source), and sums of ``event_count``, ``login_attempts`` and the other counters (a group holds the
sums of what it folded).

A deliberate count of rows (how many rows a table holds, a work queue, a page size) stays
``count(*)`` and carries the marker comment ``ROW_COUNT_MARKER`` on the statement or the line above
it. ``suckerpot_db.session_lint`` finds the counts that carry neither.

* ORM: ``sessions_count()``, ``sessions_count(SessionRow.login_success)``, or
  ``sessions_count(s.benign.is_(False), connections=s.connections)`` for an aliased row.
* Raw SQL (``text()``): ``sql_sessions_count()`` and ``sql_sessions_count("s", "s.login_success")``.
"""

from __future__ import annotations

from sqlalchemy import ColumnElement, func
from sqlalchemy.orm import QueryableAttribute

from suckerpot_db.models import SessionRow

ROW_COUNT_MARKER = "session-rows-ok"
"""Comment text (``# session-rows-ok: <why>``) that exempts a deliberate row count from the lint."""

SQL_SESSIONS_COUNT = "coalesce(sum(connections), 0)"
"""The count of sessions as a SQL fragment, for a statement with a single ``sessions`` table."""


def sessions_count(
    *where: ColumnElement[bool] | QueryableAttribute[bool],
    connections: QueryableAttribute[int] | ColumnElement[int] = SessionRow.connections,
) -> ColumnElement[int]:
    """``coalesce(sum(connections), 0)``, restricted to rows matching all of ``where`` (FILTER).

    Pass ``connections=alias.connections`` when the statement reads an aliased ``SessionRow``.
    """
    total = func.sum(connections)
    if where:
        return func.coalesce(total.filter(*where), 0)
    return func.coalesce(total, 0)


def sql_sessions_count(alias: str = "", *where: str) -> str:
    """The same count as a SQL fragment; ``alias`` qualifies ``connections`` (``"s"`` gives
    ``s.connections``) and each ``where`` is a SQL condition for the FILTER clause.

    Arguments are code constants (an alias and conditions), never request data.
    """
    column = f"{alias}.connections" if alias else "connections"
    if not where:
        return f"coalesce(sum({column}), 0)"
    return f"coalesce(sum({column}) FILTER (WHERE {' AND '.join(where)}), 0)"
