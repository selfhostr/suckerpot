"""What came of the reports (M26): the outcome of one report, the owner's override, the summary.

Ingest derives ``auto_outcome`` from verified replies; the owner may set ``manual_outcome`` by
hand (this role cannot write the automatic columns, ingest cannot write the manual ones). The
effective outcome is ``COALESCE(manual_outcome, auto_outcome)``. "No answer" is not stored: it is
an outcome of ``none`` on a report sent more than ``ABUSE_NO_ANSWER_DAYS`` ago.

GET routes are open to both roles; writes are administrator only by the default-deny rule.
Demo reports are never counted.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final, Literal

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import AbuseReportOutcomeRow, AbuseReportRow

from api import audit as audit_db
from api.abuse_core import error
from api.auth import Principal, current_principal
from api.country_names import COUNTRY_NAMES
from api.deps import DbSession

router = APIRouter(tags=["abuse"])
log = logging.getLogger("api.abuse")

OUTCOMES: Final = (
    "none",
    "auto_ack",
    "ticket_opened",
    "resolved",
    "rejected",
    "bounce",
    "human_reply",
    "unknown",
)
Outcome = Literal[
    "none",
    "auto_ack",
    "ticket_opened",
    "resolved",
    "rejected",
    "bounce",
    "human_reply",
    "unknown",
]
KINDS: Final = ("attack_source", "payload_host", "c2")
MAX_RANGE_DAYS: Final = 730
DEFAULT_RANGE_DAYS: Final = 90
GRACE_DAYS: Final = 3  # a report younger than this is not expected to have an answer yet
MAX_GROUPS: Final = 200
FUTURE_SLACK: Final = timedelta(minutes=5)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def no_answer_days() -> int:
    try:
        value = int(os.environ.get("ABUSE_NO_ANSWER_DAYS", ""))
    except ValueError:
        return 14
    return value if 1 <= value <= 365 else 14


# ---- shapes --------------------------------------------------------------------------------


class OutcomeOut(BaseModel):
    """The outcome of one sent or closed report."""

    effective: str  # COALESCE(manual, auto); "none" may still be "no answer", see no_answer
    auto: str
    manual: str | None
    no_answer: bool  # nothing came back and the report is older than ABUSE_NO_ANSWER_DAYS
    needs_review: bool  # an unverified reply or a bounce waits for the owner
    reply_count: int
    first_reply_at: datetime | None
    first_human_at: datetime | None
    ticket_at: datetime | None
    resolved_at: datetime | None
    rejected_at: datetime | None
    bounced_at: datetime | None
    ticket_id: str | None
    first_reply_after_s: int | None  # seconds from sending to the first answer
    manual_at: datetime | None
    manual_by: str | None
    note: str | None


class OutcomeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Outcome
    at: AwareDatetime | None = None  # when it happened; default now, not before the send
    note: Annotated[str | None, Field(max_length=1000)] = None

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        if _CTRL.search(v):
            raise ValueError("control characters are not allowed")
        return v.strip()


class Totals(BaseModel):
    sent: int
    eligible: int  # sent at least 3 days before ``until``: the base of the answered rate
    answered: int  # among the eligible: effective outcome not in (none, bounce)
    no_answer: int
    by_outcome: dict[str, int]
    first_reply_p50_s: int | None
    first_reply_p90_s: int | None
    resolved_p50_s: int | None


class Group(BaseModel):
    key: str
    label: str
    sent: int
    eligible: int
    answered: int
    by_outcome: dict[str, int]
    first_reply_p50_s: int | None


class Summary(BaseModel):
    since: datetime
    until: datetime
    group: str
    totals: Totals
    groups: list[Group]


class Point(BaseModel):
    start: datetime
    sent: dict[str, int]  # per kind
    sent_total: int
    answered: int
    resolved: int


class Timeline(BaseModel):
    bucket: str
    since: datetime
    until: datetime
    points: list[Point]


# ---- the outcome of one report -------------------------------------------------------------


def to_out(row: Any | None, sent_at: datetime | None, now: datetime | None = None) -> OutcomeOut:
    """``row`` is an ``abuse_report_outcomes`` row (or None before ingest created it)."""
    now = now or datetime.now(UTC)

    def g(name: str) -> Any:
        return getattr(row, name, None)

    auto = g("auto_outcome") or "none"
    manual = g("manual_outcome")
    effective = manual or auto
    first = g("first_reply_at")
    after = (
        max(0, int((first - sent_at).total_seconds())) if first is not None and sent_at else None
    )
    stale = sent_at is not None and sent_at < now - timedelta(days=no_answer_days())
    return OutcomeOut(
        effective=effective,
        auto=auto,
        manual=manual,
        no_answer=effective == "none" and stale,
        needs_review=bool(g("needs_review")),
        reply_count=int(g("reply_count") or 0),
        first_reply_at=first,
        first_human_at=g("first_human_at"),
        ticket_at=g("ticket_at"),
        resolved_at=g("resolved_at"),
        rejected_at=g("rejected_at"),
        bounced_at=g("bounced_at"),
        ticket_id=g("ticket_id"),
        first_reply_after_s=after,
        manual_at=g("manual_at"),
        manual_by=g("manual_by"),
        note=g("note"),
    )


async def outcomes_for(
    db: AsyncSession, reports: list[tuple[int, str, datetime | None]]
) -> dict[int, OutcomeOut]:
    """Outcomes of the sent and closed reports among ``(id, status, sent_at)``."""
    sent = {rid: at for rid, status, at in reports if status in ("sent", "closed")}
    if not sent:
        return {}
    rows = (
        await db.scalars(
            select(AbuseReportOutcomeRow).where(AbuseReportOutcomeRow.report_id.in_(list(sent)))
        )
    ).all()
    by_id = {r.report_id: r for r in rows}
    now = datetime.now(UTC)
    return {rid: to_out(by_id.get(rid), at, now) for rid, at in sent.items()}


def _actor(principal: Principal | None) -> str:
    return principal.username if principal else "anonymous"


def _client_ip(request: Request) -> str | None:
    return request.app.state.auth.client_ip(request)  # type: ignore[no-any-return]


async def _report(db: AsyncSession, public_id: uuid.UUID) -> AbuseReportRow | None:
    return (
        await db.scalars(select(AbuseReportRow).where(AbuseReportRow.public_id == public_id))
    ).first()


async def _answer(db: AsyncSession, row: AbuseReportRow) -> OutcomeOut:
    found = (await outcomes_for(db, [(row.id, row.status, row.sent_at)])).get(row.id)
    return found or to_out(None, row.sent_at)


def _json(model: BaseModel, status: int = 200) -> Response:
    return JSONResponse(
        model.model_dump(mode="json"), status_code=status, headers={"Cache-Control": "no-store"}
    )


@router.put("/abuse/reports/{public_id}/outcome", response_model=OutcomeOut)
async def set_outcome(
    public_id: uuid.UUID, body: OutcomeBody, request: Request, db: DbSession
) -> Response:
    """The owner's own word on what came of the report ("they answered by phone")."""
    row = await _report(db, public_id)
    if row is None:
        return error(404, "Report not found.", "not_found")
    if row.status not in ("sent", "closed") or row.sent_at is None:
        return error(409, "Only a sent report has an outcome.", "not_sent")
    now = datetime.now(UTC)
    at = body.at.astimezone(UTC) if body.at else now
    if at > now + FUTURE_SLACK:
        return error(422, "The date is in the future.", "in_future")
    if at < row.sent_at:
        return error(422, "The date is before the report was sent.", "before_sent")
    principal = await current_principal(request)
    try:
        await db.execute(
            text(
                """
                INSERT INTO abuse_report_outcomes (report_id, manual_outcome, manual_at,
                    manual_by, note)
                VALUES (:r, :o, :at, :by, :n)
                ON CONFLICT (report_id) DO UPDATE SET manual_outcome = EXCLUDED.manual_outcome,
                    manual_at = EXCLUDED.manual_at, manual_by = EXCLUDED.manual_by,
                    note = EXCLUDED.note
                """
            ),
            {
                "r": row.id,
                "o": body.outcome,
                "at": at,
                "by": _actor(principal)[:120],
                "n": body.note,
            },
        )
    except DBAPIError:
        await db.rollback()
        return error(409, "The outcome could not be saved.", "not_sent")
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.outcome.set",
        target=str(row.public_id),
        ip=_client_ip(request),
        details={"outcome": body.outcome},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _json(await _answer(db, row))


@router.delete("/abuse/reports/{public_id}/outcome", response_model=OutcomeOut)
async def clear_outcome(public_id: uuid.UUID, request: Request, db: DbSession) -> Response:
    """Back to automatic: the owner's override is removed, ingest's reading stays."""
    row = await _report(db, public_id)
    if row is None:
        return error(404, "Report not found.", "not_found")
    if row.status not in ("sent", "closed"):
        return error(409, "Only a sent report has an outcome.", "not_sent")
    principal = await current_principal(request)
    await db.execute(
        text(
            "UPDATE abuse_report_outcomes SET manual_outcome = NULL, manual_at = NULL, "
            "manual_by = NULL, note = NULL WHERE report_id = :r"
        ),
        {"r": row.id},
    )
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.outcome.clear",
        target=str(row.public_id),
        ip=_client_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _json(await _answer(db, row))


# ---- the summary ---------------------------------------------------------------------------

# One row per sent or closed, non-demo report in the window, with its effective outcome and the
# time of the first answer and of the resolution (the owner's date when the owner set it).
BASE = """
base AS (
    SELECT r.id, r.kind, r.sent_at, r.recipient_id,
           COALESCE(o.manual_outcome, o.auto_outcome, 'none') AS eff,
           CASE WHEN o.manual_outcome IS NOT NULL
                THEN CASE WHEN o.manual_outcome NOT IN ('none', 'bounce') THEN o.manual_at END
                ELSE o.first_reply_at END AS reply_at,
           CASE WHEN o.manual_outcome IS NOT NULL
                THEN CASE WHEN o.manual_outcome = 'resolved' THEN o.manual_at END
                ELSE o.resolved_at END AS resolved_at
    FROM abuse_reports r LEFT JOIN abuse_report_outcomes o ON o.report_id = r.id
    WHERE r.status IN ('sent', 'closed') AND NOT r.demo AND r.sent_at IS NOT NULL
      AND r.sent_at >= :since AND r.sent_at <= :until
)
"""
ANSWERED = "eff NOT IN ('none', 'bounce')"
DELAY = "EXTRACT(EPOCH FROM (reply_at - sent_at))"
TOTALS = (
    "WITH "
    + BASE
    + f"""
SELECT count(*) AS sent,
       count(*) FILTER (WHERE sent_at <= :eligible) AS eligible,
       count(*) FILTER (WHERE sent_at <= :eligible AND {ANSWERED}) AS answered,
       count(*) FILTER (WHERE eff = 'none' AND sent_at < :stale) AS no_answer,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY {DELAY})
           FILTER (WHERE reply_at >= sent_at) AS p50,
       percentile_cont(0.9) WITHIN GROUP (ORDER BY {DELAY})
           FILTER (WHERE reply_at >= sent_at) AS p90,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (resolved_at - sent_at)))
           FILTER (WHERE resolved_at >= sent_at) AS resolved_p50
FROM base
"""  # noqa: S608 - fixed fragments, no user input
)
BY_OUTCOME = "WITH " + BASE + "SELECT eff, count(*) AS n FROM base GROUP BY eff"  # noqa: S608

# A report counts once per group: one row per (report, key).
GROUPS: dict[str, str] = {
    # A digest (M38) counts once under each kind of source it holds; older reports by kind.
    "kind": (
        "SELECT b.id AS report_id, b.kind AS key, b.kind AS label FROM base b "
        "WHERE b.kind <> 'digest' UNION "
        "SELECT DISTINCT b.id AS report_id, s.kind AS key, s.kind AS label FROM base b "
        "JOIN abuse_report_subjects s ON s.report_id = b.id WHERE b.kind = 'digest'"
    ),
    "recipient": (
        "SELECT b.id AS report_id, rec.id::text AS key, "
        "COALESCE(rec.name, rec.mailbox, 'Unknown') AS label "
        "FROM base b JOIN abuse_recipients rec ON rec.id = b.recipient_id"
    ),
    "asn": (
        "SELECT b.id AS report_id, n.asn::text AS key, max(n.name) AS label "
        "FROM base b JOIN abuse_report_subjects s ON s.report_id = b.id "
        "JOIN abuse_networks n ON n.id = s.network_id WHERE n.asn IS NOT NULL "
        "GROUP BY b.id, n.asn"
    ),
    "country": (
        "SELECT b.id AS report_id, n.country AS key, n.country AS label "
        "FROM base b JOIN abuse_report_subjects s ON s.report_id = b.id "
        "JOIN abuse_networks n ON n.id = s.network_id WHERE n.country IS NOT NULL "
        "GROUP BY b.id, n.country"
    ),
}


def _group_sql(group: str) -> tuple[str, str]:
    head = "WITH " + BASE + ", grp AS (" + GROUPS[group] + ") "
    totals = (
        head
        + f"""
SELECT g.key, max(g.label) AS label, count(*) AS sent,
       count(*) FILTER (WHERE b.sent_at <= :eligible) AS eligible,
       count(*) FILTER (WHERE b.sent_at <= :eligible AND b.{ANSWERED}) AS answered,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (b.reply_at - b.sent_at)))
           FILTER (WHERE b.reply_at >= b.sent_at) AS p50
FROM grp g JOIN base b ON b.id = g.report_id
GROUP BY g.key ORDER BY count(*) DESC, g.key LIMIT {MAX_GROUPS}
"""  # noqa: S608 - fixed fragments, no user input
    )
    outcomes = (
        head + "SELECT g.key, b.eff, count(*) AS n FROM grp g JOIN base b ON b.id = g.report_id "  # noqa: S608
        "GROUP BY g.key, b.eff"
    )
    return totals, outcomes


def _seconds(value: Any) -> int | None:
    return None if value is None else max(0, round(float(value)))


def _window(since: datetime | None, until: datetime | None) -> tuple[datetime, datetime] | None:
    end = until.astimezone(UTC) if until else datetime.now(UTC)
    start = since.astimezone(UTC) if since else end - timedelta(days=DEFAULT_RANGE_DAYS)
    if start >= end or end - start > timedelta(days=MAX_RANGE_DAYS):
        return None
    return start, end


Since = Annotated[AwareDatetime | None, Query()]


@router.get("/abuse/outcomes", response_model=Summary)
async def outcomes_summary(
    db: DbSession,
    since: Since = None,
    until: Since = None,
    group: Literal["kind", "asn", "country", "recipient"] = "kind",
) -> Response:
    window = _window(since, until)
    if window is None:
        return error(422, "The period must be between 1 and 730 days.", "bad_range")
    start, end = window
    params = {
        "since": start,
        "until": end,
        "eligible": end - timedelta(days=GRACE_DAYS),
        "stale": datetime.now(UTC) - timedelta(days=no_answer_days()),
    }
    t = (await db.execute(text(TOTALS), params)).one()
    by_outcome = dict.fromkeys(OUTCOMES, 0)
    for row in await db.execute(text(BY_OUTCOME), params):
        by_outcome[row.eff] = int(row.n)
    totals = Totals(
        sent=int(t.sent),
        eligible=int(t.eligible),
        answered=int(t.answered),
        no_answer=int(t.no_answer),
        by_outcome=by_outcome,
        first_reply_p50_s=_seconds(t.p50),
        first_reply_p90_s=_seconds(t.p90),
        resolved_p50_s=_seconds(t.resolved_p50),
    )
    group_sql, outcome_sql = _group_sql(group)
    per_group: dict[str, dict[str, int]] = {}
    for row in await db.execute(text(outcome_sql), params):
        per_group.setdefault(row.key, dict.fromkeys(OUTCOMES, 0))[row.eff] = int(row.n)
    groups = [
        Group(
            key=row.key,
            label=_label(group, row.key, row.label),
            sent=int(row.sent),
            eligible=int(row.eligible),
            answered=int(row.answered),
            by_outcome=per_group.get(row.key, dict.fromkeys(OUTCOMES, 0)),
            first_reply_p50_s=_seconds(row.p50),
        )
        for row in await db.execute(text(group_sql), params)
    ]
    return _json(Summary(since=start, until=end, group=group, totals=totals, groups=groups))


def _label(group: str, key: str, label: str | None) -> str:
    if group == "asn":
        return f"AS{key} {label}" if label else f"AS{key}"
    if group == "country":
        return COUNTRY_NAMES.get(key, key)
    return (label or key)[:200]


# ---- the timeline --------------------------------------------------------------------------

TIMELINE = (
    "WITH "
    + BASE
    + ", kinds AS ("
    + GROUPS["kind"]
    + """)
SELECT date_trunc(:bucket, b.sent_at AT TIME ZONE 'UTC') AS start, k.key AS kind,
       count(*) AS sent
FROM base b JOIN kinds k ON k.report_id = b.id GROUP BY 1, 2 ORDER BY 1
"""
)
TIMELINE_TOTALS = (
    "WITH "
    + BASE
    + f"""
SELECT date_trunc(:bucket, b.sent_at AT TIME ZONE 'UTC') AS start, count(*) AS sent,
       count(*) FILTER (WHERE b.{ANSWERED}) AS answered,
       count(*) FILTER (WHERE b.eff = 'resolved') AS resolved
FROM base b GROUP BY 1 ORDER BY 1
"""  # noqa: S608 - fixed fragments, no user input
)


def _bucket_start(value: datetime, bucket: str) -> datetime:
    day = value.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    if bucket == "month":
        return day.replace(day=1)
    return day - timedelta(days=day.weekday())


def _next_bucket(value: datetime, bucket: str) -> datetime:
    if bucket == "week":
        return value + timedelta(days=7)
    return (
        value.replace(year=value.year + 1, month=1)
        if value.month == 12
        else value.replace(month=value.month + 1)
    )


@router.get("/abuse/outcomes/timeline", response_model=Timeline)
async def outcomes_timeline(
    db: DbSession,
    bucket: Literal["week", "month"] = "week",
    since: Since = None,
    until: Since = None,
) -> Response:
    """Reports sent per kind in each bucket (a digest under each kind of source it holds), the
    number of mails, and how many of those were answered and resolved (counted in the bucket the
    report was sent in). Empty buckets are listed with zeros."""
    end = until.astimezone(UTC) if until else datetime.now(UTC)
    default_days = 182 if bucket == "week" else MAX_RANGE_DAYS
    start = since.astimezone(UTC) if since else end - timedelta(days=default_days)
    if start >= end or end - start > timedelta(days=MAX_RANGE_DAYS):
        return error(422, "The period must be between 1 and 730 days.", "bad_range")
    params: dict[str, Any] = {"since": start, "until": end, "bucket": bucket}
    found: dict[datetime, dict[str, Any]] = {}

    def empty() -> dict[str, Any]:
        return {"sent": dict.fromkeys(KINDS, 0), "total": 0, "answered": 0, "resolved": 0}

    for row in await db.execute(text(TIMELINE), params):
        slot = found.setdefault(row.start.replace(tzinfo=UTC), empty())
        if row.kind in slot["sent"]:
            slot["sent"][row.kind] = int(row.sent)
    # Totals per report: a digest with several kinds of sources is still one mail.
    for row in await db.execute(text(TIMELINE_TOTALS), params):
        slot = found.setdefault(row.start.replace(tzinfo=UTC), empty())
        slot["total"] = int(row.sent)
        slot["answered"] = int(row.answered)
        slot["resolved"] = int(row.resolved)
    points: list[Point] = []
    cursor = _bucket_start(start, bucket)
    while cursor <= end and len(points) < 400:
        slot = found.get(cursor, empty())
        points.append(
            Point(
                start=cursor,
                sent=slot["sent"],
                sent_total=slot["total"],
                answered=slot["answered"],
                resolved=slot["resolved"],
            )
        )
        cursor = _next_bucket(cursor, bucket)
    return _json(Timeline(bucket=bucket, since=start, until=end, points=points))
