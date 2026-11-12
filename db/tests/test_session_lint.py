"""Counting sessions: the helpers, the static lint, and the checked-in lists of sites left to fix.

``ingest`` and ``api`` still count ``sessions`` rows in many places; once flood groups exist each of
those must sum ``connections`` instead. The lint finds them. The two lists in ``allowlists/`` hold
the sites that are known and not fixed yet: the tests fail on a NEW site (fix it, or mark a
deliberate row count with ``# session-rows-ok: <why>``) and on a site that was fixed but is still
listed (remove its line). So a list can only shrink, and ``ceiling`` makes growing it a visible
edit of two lines.
"""

from __future__ import annotations

# ruff: noqa: S608  (the SQL under test is built from constants)
import re
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import aliased

from suckerpot_db.models import SessionRow
from suckerpot_db.session_counts import (
    ROW_COUNT_MARKER,
    SQL_SESSIONS_COUNT,
    sessions_count,
    sql_sessions_count,
)
from suckerpot_db.session_lint import find_row_counts, find_sites_by_name

ROOT = Path(__file__).resolve().parents[2]
ALLOWLISTS = Path(__file__).resolve().parent / "allowlists"
TREES = {"ingest": ROOT / "ingest" / "ingest", "api": ROOT / "api" / "api"}


def _sql(expr: object) -> str:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    return str(expr.compile(dialect=dialect, compile_kwargs={"literal_binds": True}))  # type: ignore[attr-defined]


# ---- the helpers ----------------------------------------------------------------------------


def test_orm_count_sums_connections_and_never_yields_null() -> None:
    sql = _sql(select(sessions_count()))
    assert sql == "SELECT coalesce(sum(sessions.connections), 0) AS coalesce_1 \nFROM sessions"


def test_orm_filter_form() -> None:
    sql = _sql(select(sessions_count(SessionRow.login_success, SessionRow.sensor == "rdp")))
    assert "coalesce(sum(sessions.connections) FILTER (WHERE sessions.login_success" in sql
    assert "AND sessions.sensor = 'rdp'), 0)" in sql


def test_orm_count_of_an_alias() -> None:
    s = aliased(SessionRow, name="s")
    sql = _sql(select(sessions_count(s.benign.is_(False), connections=s.connections)))
    assert "sum(s.connections) FILTER (WHERE s.benign IS false)" in sql


def test_raw_sql_fragments() -> None:
    assert SQL_SESSIONS_COUNT == "coalesce(sum(connections), 0)"
    assert sql_sessions_count() == "coalesce(sum(connections), 0)"
    assert sql_sessions_count("s") == "coalesce(sum(s.connections), 0)"
    assert (
        sql_sessions_count("s", "s.login_success", "s.sensor = 'rdp'")
        == "coalesce(sum(s.connections) FILTER (WHERE s.login_success AND s.sensor = 'rdp'), 0)"
    )


# ---- the lint -------------------------------------------------------------------------------


def _names(source: str) -> set[str]:
    return find_sites_by_name(source)


def test_raw_sql_row_counts_are_found() -> None:
    src = (
        "from sqlalchemy import text\n"
        "async def a(db):\n"
        "    return await db.execute(text('SELECT count(*) FROM sessions WHERE benign'))\n"
        "async def b(db):\n"
        "    return await db.execute(text('SELECT count(1) AS n FROM events e JOIN sessions s'))\n"
        "async def c(db):\n"
        "    return await db.execute(text('SELECT COUNT( s.session_id ) FROM sessions s'))\n"
    )
    assert _names(src) == {"a", "b", "c"}
    assert [line for _name, line in find_row_counts(src)] == [3, 5, 7]


def test_raw_sql_that_sums_connections_or_counts_distinct_passes() -> None:
    src = (
        "from sqlalchemy import text\n"
        "async def a(db):\n"
        "    return await db.execute(text('SELECT sum(connections) FROM sessions'))\n"
        "async def b(db):\n"
        "    return await db.execute(text('SELECT count(DISTINCT src_ip) FROM sessions'))\n"
        "async def c(db):\n"
        "    return await db.execute(text('SELECT count(*) FROM events'))\n"
        "async def d(db):\n"
        "    return await db.execute(text('SELECT count(*), sum(connections) FROM sessions'))\n"
        "async def e(db):\n"
        "    return await db.execute(text('SELECT count(*) FROM sessions_daily'))\n"
    )
    assert _names(src) == set()


def test_fstrings_and_module_constants_are_found() -> None:
    src = (
        "from sqlalchemy import text\n"
        "_Q = 'SELECT count(*) FROM sessions'\n"
        "def f(db, where):\n"
        "    return db.execute(text(f'SELECT count(*) FROM sessions WHERE {where}'))\n"
    )
    assert _names(src) == {"_Q", "f"}


def test_docstrings_are_not_sql() -> None:
    src = '''
def f():
    """Counts rows: SELECT count(*) FROM sessions is wrong now."""
'''
    assert _names(src) == set()


def test_orm_row_counts_are_found_only_next_to_session_row() -> None:
    src = (
        "from sqlalchemy import func, select\n"
        "from suckerpot_db.models import EventRow, SessionRow\n"
        "def a():\n"
        "    return select(func.count()).select_from(SessionRow)\n"
        "def b():\n"
        "    return select(func.count(SessionRow.session_id))\n"
        "def c():\n"
        "    return select(func.count()).select_from(EventRow)\n"
        "def d():\n"
        "    return select(func.count(SessionRow.src_ip.distinct()))\n"
        "def e():\n"
        "    return select(func.count(SessionRow.country))\n"
        "class K:\n"
        "    def m(self):\n"
        "        s = SessionRow\n"
        "        return select(func.count()).select_from(s)\n"
        "    def n(self):\n"
        "        return select(func.count()).select_from(EventRow)\n"
    )
    assert _names(src) == {"a", "b", "K.m"}


def test_marker_exempts_a_deliberate_row_count() -> None:
    src = (
        "from sqlalchemy import func, select, text\n"
        "from suckerpot_db.models import SessionRow\n"
        "def a():\n"
        f"    # {ROW_COUNT_MARKER}: a work queue, one row is one thing to do\n"
        "    return select(func.count()).select_from(SessionRow)\n"
        "def b(db):\n"
        "    return db.execute(\n"
        "        text('SELECT count(*) FROM sessions')  # " + ROW_COUNT_MARKER + ": rows\n"
        "    )\n"
        "def c(db):\n"
        "    return db.execute(text('SELECT count(*) FROM sessions'))\n"
    )
    assert _names(src) == {"c"}


# ---- the sites that are still to fix ----------------------------------------------------------


def _listed(name: str) -> tuple[int, list[str]]:
    ceiling = 0
    entries: list[str] = []
    for raw in (ALLOWLISTS / f"{name}.txt").read_text().splitlines():
        line = raw.strip()
        if m := re.fullmatch(r"#\s*ceiling:\s*(\d+)", line):
            ceiling = int(m.group(1))
        elif line and not line.startswith("#"):
            entries.append(line)
    return ceiling, entries


def _found(tree: Path) -> set[str]:
    assert tree.is_dir(), f"{tree} is missing: the db tests read the whole repository"
    out: set[str] = set()
    for path in sorted(tree.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        out.update(f"{rel}::{name}" for name in find_sites_by_name(path.read_text()))
    return out


@pytest.mark.parametrize("name", sorted(TREES))
def test_no_new_session_row_count_and_none_left_listed(name: str) -> None:
    ceiling, entries = _listed(name)
    found = _found(TREES[name])
    new = sorted(found - set(entries))
    stale = sorted(set(entries) - found)
    assert not new, (
        f"{name}: a count of sessions rows that ignores connections (use "
        f"suckerpot_db.session_counts, or mark a deliberate row count with "
        f"'# {ROW_COUNT_MARKER}: <why>'): {new}"
    )
    assert not stale, f"{name}: fixed, remove these lines from allowlists/{name}.txt: {stale}"
    assert entries == sorted(entries) and len(entries) == len(set(entries))
    assert len(entries) <= ceiling, f"{name}: the list grew past its ceiling of {ceiling}"
    assert ceiling == len(entries), f"{name}: lower the ceiling to {len(entries)}"
