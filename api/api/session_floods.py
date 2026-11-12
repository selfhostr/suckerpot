"""Flood groups for the sessions endpoints: find the group of a folded id, and its credentials.

A source that opens many plain connections in one UTC hour has them merged into one ``sessions``
row (``kind = 'burst'``, migration 0034). The merged connections have no row of their own any
more, but their events are untouched. This module reads those events, always inside the time
range of the group (or of an ``at`` +- one hour window) so TimescaleDB only opens a few chunks and
the 5 second statement timeout holds.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import Select, case, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.event_bounds import SLACK, group_events_where, session_events_where
from suckerpot_db.models import EventRow, SessionRow

from api.analytics_queries import MAX_VALUE_LEN
from api.schemas import CredentialCount, CredentialPair, SessionCredentials

#: How far from ``at`` the events of a folded id are looked for.
AT_WINDOW = timedelta(hours=1)
#: Most events read to place a folded id (one connection holds a handful).
MAX_PROBE_EVENTS = 200
#: Most login attempts one credentials answer reads; ``truncated`` says when it was reached.
MAX_CREDENTIAL_EVENTS = 50_000
MAX_TOP = 50
#: "When was this last seen", for a statement over ``sessions`` alone. A plain connection is seen
#: when it started; a flood group stands for connections spread over its hour, so it is seen when
#: its last event arrived.
SQL_LAST_SEEN = "max(CASE WHEN kind = 'burst' THEN last_event_at ELSE started_at END)"


async def find_group_of(db: AsyncSession, session_id: str, at: datetime) -> SessionRow | None:
    """The flood group that holds the folded connection ``session_id``, or None.

    The connection's events are searched in ``at`` +- one hour. Several groups of the same source
    and hour (other tags or stage) cover the same events; the one that agrees on whether the
    connection tried to log in is returned.
    """
    probe = (
        select(EventRow.ts, EventRow.type, EventRow.src_ip, EventRow.sensor, EventRow.dst_port)
        .where(
            EventRow.session_id == session_id,
            EventRow.ts >= at - AT_WINDOW,
            EventRow.ts <= at + AT_WINDOW,
        )
        .order_by(EventRow.ts, EventRow.id)
        .limit(MAX_PROBE_EVENTS)
    )
    events = (await db.execute(probe)).all()
    if not events:
        return None
    first, last = events[0], events[-1]
    tried_login = any(e.type == "login_attempt" for e in events)
    stage_matches = (SessionRow.login_attempts > 0) == tried_login
    stmt = (
        select(SessionRow)
        .where(
            SessionRow.kind == "burst",
            SessionRow.src_ip == first.src_ip,
            SessionRow.sensor == first.sensor,
            SessionRow.dst_port == first.dst_port,
            # A group starts within its hour: the (src_ip, sensor, started_at) index makes this
            # a short range read.
            SessionRow.started_at <= first.ts + SLACK,
            SessionRow.started_at >= first.ts - timedelta(hours=1, minutes=1),
            SessionRow.last_event_at + SLACK >= last.ts,
        )
        .order_by(case((stage_matches, 0), else_=1), SessionRow.started_at, SessionRow.session_id)
        .limit(1)
    )
    return (await db.scalars(stmt)).first()


def _login_attempts(group_or_session: SessionRow) -> Select[tuple[str, str]]:
    """``(username, password)`` of the login attempts of one session or flood group, bounded."""
    where = (
        group_events_where(group_or_session)
        if group_or_session.kind == "burst"
        else session_events_where(group_or_session)
    )
    return (
        select(
            func.left(func.coalesce(EventRow.data["username"].astext, ""), MAX_VALUE_LEN).label(
                "u"
            ),
            func.left(func.coalesce(EventRow.data["password"].astext, ""), MAX_VALUE_LEN).label(
                "p"
            ),
        )
        .where(*where, EventRow.type == "login_attempt")
        .order_by(EventRow.ts, EventRow.id)
        .limit(MAX_CREDENTIAL_EVENTS)
    )


async def credentials_of(db: AsyncSession, row: SessionRow, top: int) -> SessionCredentials:
    """Top usernames, passwords and pairs tried, with the distinct counts, all bounded.

    The events of a group are those of its source, sensor and port in its time range, so a group
    that saw no login attempt (``login_attempts = 0``) answers empty without reading them: its
    sibling group of the same hour owns the attempts.
    """
    top = max(1, min(top, MAX_TOP))
    if row.login_attempts == 0:
        return SessionCredentials(
            attempts=0,
            distinct_usernames=0,
            distinct_passwords=0,
            distinct_pairs=0,
            truncated=False,
            usernames=[],
            passwords=[],
            pairs=[],
        )
    attempts = _login_attempts(row).subquery("a")
    pairs = (
        select(
            attempts.c.u.label("u"), attempts.c.p.label("p"), func.count(attempts.c.u).label("n")
        )
        .group_by(attempts.c.u, attempts.c.p)
        .cte("pairs")
    )
    totals = (
        await db.execute(
            select(
                func.coalesce(func.sum(pairs.c.n), 0),
                func.count(distinct(pairs.c.u)),
                func.count(distinct(pairs.c.p)),
                func.count(pairs.c.n),
            )
        )
    ).one()
    top_pairs = (
        await db.execute(
            select(pairs.c.u, pairs.c.p, pairs.c.n)
            .order_by(pairs.c.n.desc(), pairs.c.u, pairs.c.p)
            .limit(top)
        )
    ).all()
    users = (
        await db.execute(
            select(pairs.c.u, func.sum(pairs.c.n).label("n"))
            .group_by(pairs.c.u)
            .order_by(func.sum(pairs.c.n).desc(), pairs.c.u)
            .limit(top)
        )
    ).all()
    passwords = (
        await db.execute(
            select(pairs.c.p, func.sum(pairs.c.n).label("n"))
            .group_by(pairs.c.p)
            .order_by(func.sum(pairs.c.n).desc(), pairs.c.p)
            .limit(top)
        )
    ).all()
    total = int(totals[0])
    return SessionCredentials(
        attempts=total,
        distinct_usernames=int(totals[1]),
        distinct_passwords=int(totals[2]),
        distinct_pairs=int(totals[3]),
        truncated=total >= MAX_CREDENTIAL_EVENTS,
        usernames=[CredentialCount(value=u, count=int(n)) for u, n in users],
        passwords=[CredentialCount(value=p, count=int(n)) for p, n in passwords],
        pairs=[CredentialPair(username=u, password=p, count=int(n)) for u, p, n in top_pairs],
    )
