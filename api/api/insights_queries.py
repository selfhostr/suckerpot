"""SQL that gathers the facts for the insight rules (sessions-based, read-only)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Text, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import EventRow, SessionRow
from suckerpot_db.session_counts import sessions_count

from api.benign import visible_events, visible_sessions
from api.insights_rules import EXPLOIT_TAGS, Counts, Facts, NewValue
from api.trends import LOOKBACK, new_values

NEW_VALUE_FIELDS = ("username", "command", "url", "asn")
NEW_VALUE_FETCH = 5
BRUTE_FETCH = 20


async def _counts(
    db: AsyncSession,
    expr: Any,
    prev_since: datetime,
    since: datetime,
    until: datetime,
    include_benign: bool = True,
) -> Counts:
    """Sessions per key in the current and the previous window (one pass)."""
    inner = (
        select(
            expr.label("k"), SessionRow.started_at.label("ts"), SessionRow.connections.label("w")
        )
        .where(
            SessionRow.started_at >= prev_since,
            SessionRow.started_at < until,
            *visible_sessions(include_benign),
        )
        .subquery("c")
    )
    cur = sessions_count(inner.c.ts >= since, connections=inner.c.w)
    prev = sessions_count(inner.c.ts < since, connections=inner.c.w)
    stmt = (
        select(inner.c.k, cur.label("cur"), prev.label("prev"))
        .where(inner.c.k.is_not(None))
        .group_by(inner.c.k)
    )
    return {str(r.k): (r.cur, r.prev) for r in (await db.execute(stmt)).all()}


async def gather_facts(
    db: AsyncSession, since: datetime, until: datetime, include_benign: bool = True
) -> Facts:
    span = until - since
    prev_since = since - span
    facts = Facts(since=since, until=until)
    ses_ok = visible_sessions(include_benign)
    ev_ok = visible_events(include_benign)

    facts.tags = await _counts(
        db, func.unnest(SessionRow.tags), prev_since, since, until, include_benign
    )
    facts.sensors = await _counts(db, SessionRow.sensor, prev_since, since, until, include_benign)
    facts.countries = await _counts(
        db, SessionRow.country, prev_since, since, until, include_benign
    )
    facts.asns = await _counts(
        db, SessionRow.asn.cast(Text), prev_since, since, until, include_benign
    )
    facts.total = (
        sum(c for c, _ in facts.sensors.values()),
        sum(p for _, p in facts.sensors.values()),
    )

    success = (
        sessions_count(SessionRow.started_at >= since),
        sessions_count(SessionRow.started_at < since),
    )
    row = (
        await db.execute(
            select(*success).where(
                SessionRow.login_success.is_(True),
                SessionRow.started_at >= prev_since,
                SessionRow.started_at < until,
                *ses_ok,
            )
        )
    ).one()
    facts.success = (row[0], row[1])

    top_ip = (
        await db.execute(
            select(func.host(SessionRow.src_ip).label("ip"), sessions_count().label("n"))
            .where(SessionRow.started_at >= since, SessionRow.started_at < until, *ses_ok)
            .group_by(SessionRow.src_ip)
            .order_by(sessions_count().desc(), func.host(SessionRow.src_ip))
            .limit(1)
        )
    ).first()
    if top_ip is not None:
        facts.top_ip = (top_ip.ip, top_ip.n)

    brute = await db.execute(
        select(
            func.host(EventRow.src_ip).label("ip"),
            EventRow.sensor,
            func.count(EventRow.id).label("n"),
        )
        .where(
            EventRow.type == "login_attempt",
            EventRow.ts >= since,
            EventRow.ts < until,
            *ev_ok,
        )
        .group_by(EventRow.src_ip, EventRow.sensor)
        .order_by(func.count(EventRow.id).desc(), func.host(EventRow.src_ip), EventRow.sensor)
        .limit(BRUTE_FETCH)
    )
    facts.brute_force = [(r.ip, r.sensor, r.n) for r in brute]
    facts.brute_total = int(
        await db.scalar(
            select(func.count(EventRow.id)).where(
                EventRow.type == "login_attempt", EventRow.ts >= since, EventRow.ts < until, *ev_ok
            )
        )
        or 0
    )

    exploit_tags = list(EXPLOIT_TAGS)
    facts.exploit_current = {
        t: c for t, (c, _) in facts.tags.items() if t in EXPLOIT_TAGS and c > 0
    }
    if facts.exploit_current:
        tag_rows = (
            select(func.unnest(SessionRow.tags).label("t"))
            .where(
                SessionRow.started_at >= since - LOOKBACK,
                SessionRow.started_at < since,
                SessionRow.tags.overlap(exploit_tags),
                *ses_ok,
            )
            .subquery("s")
        )
        seen = await db.execute(select(tag_rows.c.t).distinct())
        facts.exploit_seen_before = {str(t) for (t,) in seen}

    for name in NEW_VALUE_FIELDS:
        items = await new_values(
            db, name, since, until, NEW_VALUE_FETCH, include_benign=include_benign
        )
        facts.new_values[name] = [NewValue(i.value, i.count) for i in items]
    asn_new = facts.new_values.get("asn", [])
    if asn_new:
        numbers = [int(v.value) for v in asn_new]
        rows = await db.execute(
            select(SessionRow.asn, func.max(SessionRow.org))
            .where(SessionRow.asn.in_(numbers))
            .group_by(SessionRow.asn)
        )
        facts.asn_orgs.update({str(a): o for a, o in rows if o})
    top_asn = max(facts.asns.items(), key=lambda kv: kv[1][0], default=None)
    if top_asn is not None and top_asn[0] not in facts.asn_orgs:
        org = await db.scalar(
            select(func.max(SessionRow.org)).where(SessionRow.asn == int(top_asn[0]))
        )
        if org:
            facts.asn_orgs[top_asn[0]] = org
    return facts
