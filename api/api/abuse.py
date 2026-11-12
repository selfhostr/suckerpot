"""Abuse reports (M22): the owner's review desk. Drafts come from ingest; this module reads them,
renders them on demand behind the identity guard, and records the owner's decisions.

Nothing here sends mail or contacts anyone (``api.abuse_smtp`` only queues requests that ingest
answers). GET routes are open to both roles; every other method
is administrator only by the default-deny rule (``api.authz``), and the two screens that hold the
owner's private choices (settings, self terms) are administrator only for GET as well. Rendered
text and downloads run the guard after rendering and before returning; a failure answers 409 with
reason codes only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import string
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import ColumnElement, delete, func, literal_column, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import (
    AbuseLookupRow,
    AbuseNetworkRow,
    AbuseRecipientRow,
    AbuseReportRequestRow,
    AbuseReportRow,
    AbuseReportSubjectRow,
    AbuseSendRequestRow,
    AuditLogRow,
    EnrichmentQuotaRow,
    EnrichmentStatusRow,
    ReportImapRow,
    ReportImapStateRow,
    ReportSelfTermRow,
    ReportSettingsRow,
)
from suckerpot_db.shared_mail import is_shared_domain
from suckerpot_reporting import (
    Evidence,
    GuardFailed,
    RenderUnavailable,
    guard,
    mask_value,
    render_csv,
    report_stem,
)

from api import audit as audit_db
from api.abuse_core import (
    EVIDENCE_CODES,
    MAILBOX_RE,
    SETTINGS_TEXT_FIELDS,
    EvidenceInvalidError,
    SettingsBundle,
    build_evidence,
    effective_options,
    error,
    guard_context,
    guard_failed_response,
    invalidate_terms,
    load_settings,
    load_terms,
    missing_for,
    release,
    render_checked,
    reply_args,
    self_address_fresh,
    settings_guard_failed_response,
    settings_incomplete_response,
    settings_issues,
)
from api.abuse_outcomes import OutcomeOut, outcomes_for
from api.abuse_replies import ReplyOut, replies_enabled, replies_of_report
from api.abuse_replies import counts as reply_counts
from api.abuse_smtp import SendState, send_state
from api.auth import Principal, current_principal
from api.authz import require_admin
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.network import network_states

router = APIRouter(tags=["abuse"])
log = logging.getLogger("api.abuse")

MAX_LIMIT = 100
MAX_TERMS = 500
TEMPLATE_FIELDS = frozenset({"value", "asn", "network", "count", "date", "ref"})
HISTORY_LIMIT = 50
STATUSES = ("draft", "reviewed", "sent", "closed", "discarded", "superseded")
ALLOWED = frozenset(
    {
        ("draft", "reviewed"),
        ("draft", "discarded"),
        ("reviewed", "draft"),
        ("reviewed", "sent"),
        ("reviewed", "discarded"),
        ("sent", "closed"),
    }
)
AdminOnly = Depends(require_admin)
# abuse_networks.recipient_id exists in migration 0019 but not on the ORM model (db/ is not mine).
_NETWORK_RECIPIENT: ColumnElement[int] = literal_column("abuse_networks.recipient_id")

PublicId = uuid.UUID
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
Cursor = Annotated[str | None, Query(max_length=512)]
StatusName = Literal["draft", "reviewed", "sent", "closed", "discarded", "superseded"]
KindName = Literal["attack_source", "payload_host", "c2"]
ReportFormat = Literal["text", "xarf", "eml"]
DownloadFormat = Literal["txt", "eml", "evidence_csv", "xarf_yaml"]

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# ---- output shapes (the contract with web/src/lib/abuse.ts) --------------------------------


class GuardOut(BaseModel):
    ok: bool
    codes: list[str]


class RecipientOut(BaseModel):
    id: int
    name: str
    mailbox: str | None
    source: str
    muted: bool


class AsnOut(BaseModel):
    asn: int
    name: str | None


class ReportItem(BaseModel):
    public_id: str
    kind: str
    status: str
    demo: bool
    recipient: RecipientOut
    asns: list[AsnOut]
    subject_count: int
    window_start: datetime
    window_end: datetime
    updated_at: datetime
    revision: int
    guard: GuardOut
    outcome: OutcomeOut | None = None  # sent and closed reports only (M26)


class ReportPage(BaseModel):
    items: list[ReportItem]
    next_cursor: str | None


class SubjectOut(BaseModel):
    subject_type: str
    value: str
    asn: int | None
    network: str | None
    handle: str | None
    sessions: int
    events: int
    first_ts: datetime
    last_ts: datetime
    link: str
    # confirmed | reported | taken_down when the SuckerPot network handles it (M29), else null
    network_state: str | None = None


class RedactionOut(BaseModel):
    masked: int
    removed: int


class OptionsOut(BaseModel):
    defang: bool
    time_precision: str
    include_usernames: bool
    include_reply_contact: bool
    show_redaction_counts: bool


class ReportDetail(ReportItem):
    send_state: SendState | None = None  # M25: scheduled time and last SMTP request
    subjects: list[SubjectOut]
    redaction: RedactionOut
    options: OptionsOut
    notes: str | None
    history: list[dict[str, Any]]
    missing: list[str]  # required settings still empty (only the reply contact)
    previously_reported: datetime | None
    reviewed_at: datetime | None
    sent_at: datetime | None
    closed_at: datetime | None
    replies: list[ReplyOut] = []  # the latest 20 (M26)
    reply_token: str | None = None  # administrators only


class AttachmentOut(BaseModel):
    name: str
    media_type: str
    content: str


class RenderOut(BaseModel):
    to: str
    subject: str
    body: str
    attachments: list[AttachmentOut]
    revision: int
    guard: GuardOut


class RdapQuota(BaseModel):
    used: int
    limit: int


class RepliesStatus(BaseModel):
    enabled: bool  # the server switch and the saved mailbox are both on
    configured: bool
    last_poll_at: datetime | None
    last_error: str | None
    unmatched: int
    needs_review: int


class BlockedDrafts(BaseModel):
    """Open drafts the identity check holds back, and how many carry each reason code."""

    count: int
    reasons: dict[str, int]


class StatusOut(BaseModel):
    enabled: bool
    gate: Literal["open", "closed"]
    rdap_quota: RdapQuota
    self_address_known: bool
    self_address_fresh: bool
    counts: dict[str, int]
    waiting_for_contact: int
    replies: RepliesStatus
    blocked_drafts: BlockedDrafts


class WaitingOut(BaseModel):
    id: int  # the recipient id: PATCH /abuse/recipients/{id} with override_mailbox
    name: str
    asns: list[AsnOut]
    subject_count: int


class RecipientRow(BaseModel):
    id: int
    name: str
    mailbox: str | None
    override_mailbox: str | None
    source: str
    muted: bool
    first_seen: datetime
    reply_domains: list[str] = []  # other domains this provider answers from (M26)
    # The contact is on a free or shared mail provider: its replies are trusted by exact address
    # only, never by domain.
    shared_mailbox: bool = False


class RecipientPage(BaseModel):
    items: list[RecipientRow]
    next_cursor: str | None


class DefaultOptions(BaseModel):
    defang: bool = True
    include_usernames: bool = True
    include_reply_contact: bool = True
    show_redaction_counts: bool = False


class SettingsOut(BaseModel):
    reply_contact: str | None
    signature: str | None
    intro: str | None
    outro: str | None
    note: str | None
    subject_template: str | None
    xarf_user_agent: str | None
    round_times: bool
    default_options: DefaultOptions
    default_tlp: Literal["clear", "green", "amber", "red"]
    reference_style: Literal["subject", "subject_and_body", "off"]
    revision: int
    # Field name to guard codes: the stored wording that would block every report (codes only).
    field_issues: dict[str, list[str]] = {}


class TermOut(BaseModel):
    id: int
    kind: str
    value: str
    source: str
    confirmed: bool
    distinct_sources: int


# ---- helpers -------------------------------------------------------------------------------


def _shared(mailbox: str | None) -> bool:
    return bool(mailbox) and is_shared_domain((mailbox or "").rpartition("@")[2])


async def _principal(request: Request) -> Principal | None:
    return await current_principal(request)


def _actor(principal: Principal | None) -> str:
    return principal.username if principal else "anonymous"


def _client_ip(request: Request) -> str | None:
    return request.app.state.auth.client_ip(request)  # type: ignore[no-any-return]


def _cursor_pair(cursor: str) -> tuple[datetime, int]:
    values = decode_cursor(cursor)
    try:
        ts, rid = values
        if not isinstance(ts, str) or not isinstance(rid, int):
            raise TypeError
        parsed = datetime.fromisoformat(ts)
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc
    if parsed.tzinfo is None:
        raise InvalidCursorError("malformed cursor")
    return parsed.astimezone(UTC), rid


def _recipient_out(r: AbuseRecipientRow) -> RecipientOut:
    return RecipientOut(
        id=r.id,
        name=r.name or r.mailbox or "Unknown network",
        mailbox=r.override_mailbox or r.mailbox,
        source=r.source,
        muted=r.muted,
    )


def _asns_of(evidence: dict[str, Any]) -> list[AsnOut]:
    seen: dict[int, str | None] = {}
    subjects = evidence.get("subjects")
    for s in subjects if isinstance(subjects, list) else []:
        if not isinstance(s, dict) or not isinstance(s.get("asn"), int):
            continue
        name = s.get("network")
        seen.setdefault(s["asn"], name if isinstance(name, str) else None)
    return [AsnOut(asn=a, name=n) for a, n in sorted(seen.items())][:20]


def _item(row: AbuseReportRow, rec: AbuseRecipientRow) -> ReportItem:
    return ReportItem(
        public_id=str(row.public_id),
        kind=row.kind,
        status=row.status,
        demo=row.demo,
        recipient=_recipient_out(rec),
        asns=_asns_of(row.evidence),
        subject_count=row.subject_count,
        window_start=row.window_start,
        window_end=row.window_end,
        updated_at=row.updated_at,
        revision=row.revision,
        guard=GuardOut(ok=row.guard_ok, codes=list(row.guard_codes)),
    )


async def _load(
    db: AsyncSession, public_id: uuid.UUID
) -> tuple[AbuseReportRow, AbuseRecipientRow] | None:
    found = (
        await db.execute(
            select(AbuseReportRow, AbuseRecipientRow)
            .join(AbuseRecipientRow, AbuseRecipientRow.id == AbuseReportRow.recipient_id)
            .where(AbuseReportRow.public_id == public_id)
        )
    ).first()
    return None if found is None else (found[0], found[1])


def _not_found() -> Response:
    return error(404, "Report not found", "not_found")


def _subject_link(subject_type: str, value: str) -> str:
    if subject_type == "ip":
        return f"/attacks?src_ip={value}"
    return f"/malware?q={_quote(value)}"


def _quote(value: str) -> str:
    return quote(value, safe="")


def _redaction_of(row: AbuseReportRow, evidence: Evidence | None) -> RedactionOut:
    if evidence is not None:
        masked = sum(s.redaction.addresses_masked for s in evidence.subjects)
        removed = sum(s.redaction.lines_dropped for s in evidence.subjects)
        if masked or removed:
            return RedactionOut(masked=masked, removed=removed)
    raw = row.redaction or {}

    def num(key: str) -> int:
        v = raw.get(key)
        return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0

    return RedactionOut(masked=num("addresses_masked"), removed=num("lines_dropped"))


async def _history(db: AsyncSession, public_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await db.scalars(
            select(AuditLogRow)
            .where(AuditLogRow.action == "abuse.status", AuditLogRow.target == str(public_id))
            .order_by(AuditLogRow.ts.asc(), AuditLogRow.id.asc())
            .limit(HISTORY_LIMIT)
        )
    ).all()
    return [
        {
            "ts": r.ts,
            "actor": r.actor,
            "from": r.details.get("from"),
            "to": r.details.get("to"),
        }
        for r in rows
    ]


async def _live_guard(
    db: AsyncSession, row: AbuseReportRow, evidence: Evidence, bundle: SettingsBundle
) -> GuardOut:
    """The identity check as it stands now (the deny set may have grown since the build)."""
    terms = await load_terms(db)
    ctx = await guard_context(db, row, evidence)
    try:
        rendered = await asyncio.to_thread(
            render_checked,
            evidence,
            bundle.settings,
            terms,
            ctx,
            "text",
            **reply_args(row, bundle),
        )
    except RenderUnavailable:
        return GuardOut(ok=row.guard_ok, codes=list(row.guard_codes))
    ok, codes = rendered.guard.ok, set(rendered.guard.codes)
    if row.status == "draft":
        # What the build found in the evidence stays until a rebuild finds it gone: this check
        # cannot replay the build's reads, so it never clears those codes.
        kept = EVIDENCE_CODES.intersection(row.guard_codes or ())
        if kept - codes:
            ok, codes = False, codes | kept
    return GuardOut(ok=ok, codes=sorted(codes))


async def _detail(
    db: AsyncSession,
    row: AbuseReportRow,
    rec: AbuseRecipientRow,
    bundle: SettingsBundle,
    *,
    admin: bool = False,
) -> ReportDetail:
    item = _item(row, rec)
    outcomes = await outcomes_for(db, [(row.id, row.status, row.sent_at)])
    item = item.model_copy(update={"outcome": outcomes.get(row.id)})
    evidence: Evidence | None
    try:
        evidence = build_evidence(row, rec, bundle)
    except EvidenceInvalidError:
        evidence = None
    if evidence is not None:
        item = item.model_copy(update={"guard": await _live_guard(db, row, evidence, bundle)})
    else:
        item = item.model_copy(update={"guard": GuardOut(ok=False, codes=["evidence_invalid"])})
    subs = (
        await db.execute(
            select(AbuseReportSubjectRow, AbuseNetworkRow)
            .join(
                AbuseNetworkRow,
                AbuseNetworkRow.id == AbuseReportSubjectRow.network_id,
                isouter=True,
            )
            .where(AbuseReportSubjectRow.report_id == row.id)
            .order_by(AbuseReportSubjectRow.first_ts, AbuseReportSubjectRow.value)
            .limit(MAX_LIMIT)
        )
    ).all()
    net_states = await network_states(db, [s.value for s, _n in subs])
    subjects = [
        SubjectOut(
            subject_type=s.subject_type,
            value=s.value,
            asn=n.asn if n else None,
            network=n.name if n else None,
            handle=n.handle if n else None,
            sessions=s.sessions,
            events=s.events,
            first_ts=s.first_ts,
            last_ts=s.last_ts,
            link=_subject_link(s.subject_type, s.value),
            network_state=net_states.get(s.value),
        )
        for s, n in subs
    ]
    opts = effective_options(row.options, bundle)
    prev = (
        max(
            (s.previously_reported for s in evidence.subjects if s.previously_reported),
            default=None,
        )
        if evidence
        else None
    )
    return ReportDetail(
        **item.model_dump(),
        subjects=subjects,
        redaction=_redaction_of(row, evidence),
        options=OptionsOut(**opts.model_dump()),
        notes=row.notes,
        history=await _history(db, row.public_id),
        missing=list(missing_for(bundle.settings)),
        previously_reported=prev,
        send_state=await send_state(db, row.id),
        reviewed_at=row.reviewed_at,
        sent_at=row.sent_at,
        closed_at=row.closed_at,
        replies=await replies_of_report(db, row.id, row.public_id, admin),
        reply_token=row.reply_token if admin else None,
    )


async def _answer(
    db: AsyncSession,
    public_id: uuid.UUID,
    bundle: SettingsBundle | None = None,
    *,
    admin: bool = False,
) -> Response | ReportDetail:
    loaded = await _load(db, public_id)
    if loaded is None:
        return _not_found()
    return await _detail(db, loaded[0], loaded[1], bundle or await load_settings(db), admin=admin)


# ---- status and lists ----------------------------------------------------------------------


@router.get("/abuse/status", response_model=StatusOut)
async def abuse_status(db: DbSession) -> StatusOut:
    """Worker state, gate, quota and counts. Never the monitored system's address."""
    details = {
        r.name: r.detail
        for r in await db.execute(
            select(EnrichmentStatusRow.name, EnrichmentStatusRow.detail).where(
                EnrichmentStatusRow.name.in_(("abuse", "egress"))
            )
        )
    }
    worker = details.get("abuse")
    enabled = isinstance(worker, dict) and worker.get("enabled", True) is not False
    gate = details.get("egress")
    used = await db.scalar(
        select(EnrichmentQuotaRow.used).where(
            EnrichmentQuotaRow.provider == "rdap",
            EnrichmentQuotaRow.day == datetime.now(UTC).date(),
        )
    )
    limit = _int_env("ABUSE_RDAP_DAILY_QUOTA", 1000)
    counts = dict.fromkeys(STATUSES, 0)
    for st, n in await db.execute(
        select(AbuseReportRow.status, func.count()).group_by(AbuseReportRow.status)
    ):
        counts[st] = n
    waiting = await db.scalar(
        select(func.count())
        .select_from(AbuseRecipientRow)
        .where(AbuseRecipientRow.mailbox.is_(None), AbuseRecipientRow.override_mailbox.is_(None))
    )
    blocked = await _blocked_drafts(db)
    terms = await load_terms(db)
    unmatched, needs_review = await reply_counts(db)
    imap = (
        await db.execute(
            select(ReportImapRow.enabled, ReportImapRow.password_set).where(ReportImapRow.id == 1)
        )
    ).first()
    imap_state = await db.get(ReportImapStateRow, 1)
    return StatusOut(
        enabled=enabled,
        gate="open" if isinstance(gate, dict) and gate.get("open") is True else "closed",
        rdap_quota=RdapQuota(used=int(used or 0), limit=limit),
        self_address_known=bool(terms and terms.has_self_address),
        self_address_fresh=await self_address_fresh(db),
        counts=counts,
        waiting_for_contact=int(waiting or 0),
        replies=RepliesStatus(
            enabled=bool(replies_enabled() and imap is not None and imap.enabled),
            configured=bool(imap is not None and imap.password_set),
            last_poll_at=imap_state.last_poll_at if imap_state else None,
            last_error=imap_state.last_error if imap_state else None,
            unmatched=unmatched,
            needs_review=needs_review,
        ),
        blocked_drafts=blocked,
    )


async def _blocked_drafts(db: AsyncSession) -> BlockedDrafts:
    """The stored identity result of the open drafts (ingest keeps it current), by reason code."""
    count = await db.scalar(
        select(func.count())
        .select_from(AbuseReportRow)
        .where(AbuseReportRow.status == "draft", AbuseReportRow.guard_ok.is_(False))
    )
    rows = await db.execute(
        text(
            "SELECT code, count(*) AS n FROM abuse_reports, unnest(guard_codes) AS code "
            "WHERE status = 'draft' AND NOT guard_ok GROUP BY code"
        )
    )
    return BlockedDrafts(count=int(count or 0), reasons={code: int(n) for code, n in rows})


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


@router.get("/abuse/reports", response_model=ReportPage)
async def list_reports(
    db: DbSession,
    limit: Limit = 50,
    cursor: Cursor = None,
    status: StatusName | None = None,
    kind: KindName | None = None,
    recipient: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    demo: bool | None = None,
) -> Response | ReportPage:
    stmt = select(AbuseReportRow, AbuseRecipientRow).join(
        AbuseRecipientRow, AbuseRecipientRow.id == AbuseReportRow.recipient_id
    )
    if status is not None:
        stmt = stmt.where(AbuseReportRow.status == status)
    else:
        stmt = stmt.where(AbuseReportRow.status != "superseded")
    if kind is not None:
        stmt = stmt.where(AbuseReportRow.kind == kind)
    if recipient is not None:
        stmt = stmt.where(AbuseReportRow.recipient_id == recipient)
    if demo is not None:
        stmt = stmt.where(AbuseReportRow.demo == demo)
    if cursor is not None:
        try:
            c_ts, c_id = _cursor_pair(cursor)
        except InvalidCursorError:
            return error(400, "invalid cursor", "invalid_cursor")
        stmt = stmt.where(
            (AbuseReportRow.updated_at < c_ts)
            | ((AbuseReportRow.updated_at == c_ts) & (AbuseReportRow.id < c_id))
        )
    stmt = stmt.order_by(AbuseReportRow.updated_at.desc(), AbuseReportRow.id.desc()).limit(
        limit + 1
    )
    rows = (await db.execute(stmt)).all()
    page, more = rows[:limit], len(rows) > limit
    outcomes = await outcomes_for(db, [(r.id, r.status, r.sent_at) for r, _ in page])
    return ReportPage(
        items=[_item(r, rec).model_copy(update={"outcome": outcomes.get(r.id)}) for r, rec in page],
        next_cursor=(
            encode_cursor([page[-1][0].updated_at.isoformat(), page[-1][0].id]) if more else None
        ),
    )


@router.get("/abuse/reports/{public_id}", response_model=ReportDetail)
async def get_report(
    public_id: PublicId, request: Request, db: DbSession
) -> Response | ReportDetail:
    principal = await _principal(request)
    return await _answer(db, public_id, admin=principal is not None and principal.is_admin)


# ---- render and download (guarded) ---------------------------------------------------------


@router.get("/abuse/reports/{public_id}/render", response_model=RenderOut)
async def render_report(
    public_id: PublicId,
    request: Request,
    db: DbSession,
    format: ReportFormat = "text",
    subject: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response | RenderOut:
    """The message for the owner's webmail. Guarded: 409 with reason codes if anything leaks."""
    loaded = await _load(db, public_id)
    if loaded is None:
        return _not_found()
    row, rec = loaded
    admin = (p := await _principal(request)) is not None and p.is_admin
    bundle = await load_settings(db)
    missing = missing_for(bundle.settings, xarf=format == "xarf")
    if missing:
        return settings_incomplete_response(missing)
    try:
        evidence = build_evidence(row, rec, bundle)
        ctx = await guard_context(db, row, evidence)
        terms = await load_terms(db)
        rendered = await asyncio.to_thread(
            render_checked,
            evidence,
            bundle.settings,
            terms,
            ctx,
            format,
            subject,
            **reply_args(row, bundle, admin=admin),
        )
        release(rendered.guard)
    except GuardFailed as exc:
        log.warning("abuse render blocked report=%s reasons=%s", row.id, ",".join(exc.codes))
        return guard_failed_response(exc.codes)
    except RenderUnavailable as exc:
        if exc.code == "settings_incomplete":
            return settings_incomplete_response(missing_for(bundle.settings))
        return error(409, "This format is not available for this report.", exc.code)
    except EvidenceInvalidError:
        return error(409, "The stored evidence is not valid.", "evidence_invalid")
    msg = rendered.message
    body = rendered.eml.decode("ascii") if rendered.eml is not None else msg.body
    attachments = () if rendered.eml is not None else msg.attachments
    return _no_store(
        RenderOut(
            to=msg.to,
            subject=msg.subject,
            body=body,
            attachments=[AttachmentOut(**a.__dict__) for a in attachments],
            revision=row.revision,
            guard=GuardOut(ok=True, codes=[]),
        )
    )


def _no_store(model: BaseModel) -> Response:
    return JSONResponse(model.model_dump(mode="json"), headers={"Cache-Control": "no-store"})


@router.get("/abuse/reports/{public_id}/download")
async def download_report(
    public_id: PublicId,
    request: Request,
    db: DbSession,
    format: DownloadFormat = "txt",
    subject: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    loaded = await _load(db, public_id)
    if loaded is None:
        return _not_found()
    row, rec = loaded
    admin = (p := await _principal(request)) is not None and p.is_admin
    bundle = await load_settings(db)
    missing = missing_for(bundle.settings, xarf=format == "xarf_yaml")
    if missing:
        return settings_incomplete_response(missing)
    stem = report_stem(row.public_id)
    try:
        evidence = build_evidence(row, rec, bundle)
        ctx = await guard_context(db, row, evidence)
        terms = await load_terms(db)
        fmt = {"txt": "text", "eml": "eml", "evidence_csv": "text", "xarf_yaml": "xarf"}[format]
        rendered = await asyncio.to_thread(
            render_checked,
            evidence,
            bundle.settings,
            terms,
            ctx,
            fmt,
            subject,
            **reply_args(row, bundle, admin=admin),
        )
        release(rendered.guard)
        name, media, data = _file_of(format, stem, rendered, evidence)
        # The guard looks at the exact bytes about to be sent, once more.
        final = await asyncio.to_thread(
            guard, data, terms, fmt="eml" if format == "eml" else "text", ctx=ctx
        )
        release(final)
    except GuardFailed as exc:
        log.warning("abuse download blocked report=%s reasons=%s", row.id, ",".join(exc.codes))
        return guard_failed_response(exc.codes)
    except RenderUnavailable as exc:
        if exc.code == "settings_incomplete":
            return settings_incomplete_response(missing_for(bundle.settings))
        return error(409, "This file is not available for this report.", exc.code)
    except EvidenceInvalidError:
        return error(409, "The stored evidence is not valid.", "evidence_invalid")
    principal = await _principal(request)
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.download",
        target=str(row.public_id),
        ip=_client_ip(request),
        details={"format": format},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Response(
        data,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


def _file_of(
    format: str,
    stem: str,
    rendered: Any,
    evidence: Evidence,
) -> tuple[str, str, bytes]:
    msg = rendered.message
    if format == "txt":
        return f"{stem}.txt", "text/plain; charset=us-ascii", msg.body.encode("ascii")
    if format == "eml":
        return f"{stem}.eml", "message/rfc822", rendered.eml
    if format == "evidence_csv":
        att = render_csv(evidence)
        return att.name, "text/csv; charset=us-ascii", att.content.encode("ascii")
    report = next((a for a in msg.attachments if a.name == "report.txt"), None)
    if report is None or not msg.xarf:
        raise RenderUnavailable("xarf_unavailable")
    return report.name, "text/plain; charset=us-ascii", report.content.encode("ascii")


# ---- workflow ------------------------------------------------------------------------------


class StatusBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: Literal["draft", "reviewed", "sent", "closed", "discarded"]
    revision: int = Field(ge=1)
    sent_at: AwareDatetime | None = None


@router.post("/abuse/reports/{public_id}/status", response_model=ReportDetail)
async def set_status(
    public_id: PublicId, body: StatusBody, request: Request, db: DbSession
) -> Response | ReportDetail:
    loaded = await _load(db, public_id)
    if loaded is None:
        return _not_found()
    row, rec = loaded
    if body.revision != row.revision:
        return error(409, "The draft changed while you were reading it.", "revision_mismatch")
    if (row.status, body.to) not in ALLOWED:
        return error(
            409, "That step is not possible from the current status.", "invalid_transition"
        )
    if body.to == "sent" and row.demo:
        return error(409, "A demo report cannot be sent.", "demo_report")
    bundle = await load_settings(db)
    now = datetime.now(UTC)
    before = row.status  # the UPDATE below refreshes the loaded row
    principal = await _principal(request)
    actor = _actor(principal)
    values: dict[str, Any] = {"status": body.to}
    if body.to == "reviewed":
        blocked = await _review_blocker(db, row, rec, bundle)
        if blocked is not None:
            return blocked
        values |= {"reviewed_at": now, "reviewed_by": actor, "reviewed_revision": row.revision}
    elif body.to == "draft":
        values |= {"reviewed_at": None, "reviewed_by": None, "reviewed_revision": None}
    elif body.to == "sent":
        when = body.sent_at or now
        if when > now + timedelta(minutes=5):
            return error(422, "The sent time cannot be in the future.", "sent_in_future")
        values |= {"sent_at": when.astimezone(UTC), "sent_by": actor, "sent_via": "manual"}
    elif body.to == "closed":
        values |= {"closed_at": now, "closed_by": actor}
    try:
        res = await db.execute(
            update(AbuseReportRow)
            .where(
                AbuseReportRow.id == row.id,
                AbuseReportRow.status == row.status,
                AbuseReportRow.revision == body.revision,
            )
            .values(**values)
        )
    except DBAPIError:
        await db.rollback()
        return error(
            409, "That step is not possible from the current status.", "invalid_transition"
        )
    if res.rowcount != 1:  # type: ignore[attr-defined]
        await db.rollback()
        return error(409, "The draft changed while you were reading it.", "revision_mismatch")
    if body.to == "sent":
        # Marked sent by hand: a send request still waiting for this report must not go out.
        # One that ingest already started (``sending``) cannot be stopped: say so.
        await db.execute(text("SET LOCAL lock_timeout = '2s'"))
        try:
            await db.execute(
                update(AbuseSendRequestRow)
                .where(
                    AbuseSendRequestRow.report_id == row.id,
                    AbuseSendRequestRow.status == "pending",
                )
                .values(status="cancelled")
            )
        except DBAPIError:
            await db.rollback()
            return error(409, "The report is being sent right now.", "already_sending")
        if await db.scalar(
            select(func.count())
            .select_from(AbuseSendRequestRow)
            .where(AbuseSendRequestRow.report_id == row.id, AbuseSendRequestRow.status == "sending")
        ):
            await db.rollback()
            return error(409, "The report is being sent right now.", "already_sending")
    await audit_db.record(
        db,
        actor=actor,
        action="abuse.status",
        target=str(row.public_id),
        ip=_client_ip(request),
        details={"from": before, "to": body.to},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    await db.refresh(row)
    return await _detail(db, row, rec, bundle, admin=True)


async def _review_blocker(
    db: AsyncSession, row: AbuseReportRow, rec: AbuseRecipientRow, bundle: SettingsBundle
) -> Response | None:
    """Review needs a reply contact, a mailbox and a passing identity check.

    The report wording is optional (design M22, changed on 2026-11-01).
    """
    missing = missing_for(bundle.settings)
    if missing:
        return settings_incomplete_response(missing)
    if not (rec.override_mailbox or rec.mailbox):
        return error(409, "There is no abuse mailbox for this provider yet.", "no_mailbox")
    try:
        evidence = build_evidence(row, rec, bundle)
    except EvidenceInvalidError:
        return error(409, "The stored evidence is not valid.", "evidence_invalid")
    result = await _live_guard(db, row, evidence, bundle)
    if not result.ok:
        return guard_failed_response(tuple(result.codes))
    return None


class PatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notes: Annotated[str | None, Field(max_length=4000)] = None
    options: dict[str, bool | Literal["second", "minute"]] | None = None

    @field_validator("options")
    @classmethod
    def _keys(
        cls, v: dict[str, bool | Literal["second", "minute"]] | None
    ) -> dict[str, bool | Literal["second", "minute"]] | None:
        if v is None:
            return v
        allowed = {
            "defang",
            "time_precision",
            "include_usernames",
            "include_reply_contact",
            "show_redaction_counts",
        }
        if not set(v) <= allowed:
            raise ValueError("unknown option")
        if "time_precision" in v and v["time_precision"] not in ("second", "minute"):
            raise ValueError("invalid time_precision")
        if any(k != "time_precision" and not isinstance(x, bool) for k, x in v.items()):
            raise ValueError("options must be booleans")
        return v


@router.patch("/abuse/reports/{public_id}", response_model=ReportDetail)
async def patch_report(
    public_id: PublicId, body: PatchBody, request: Request, db: DbSession
) -> Response | ReportDetail:
    loaded = await _load(db, public_id)
    if loaded is None:
        return _not_found()
    row, rec = loaded
    if row.status not in ("draft", "reviewed"):
        return error(409, "Only an open report can be edited.", "invalid_transition")
    sent = body.model_fields_set
    values: dict[str, Any] = {}
    changed: list[str] = []
    if "notes" in sent:
        values["notes"] = (body.notes or "").strip() or None
        changed.append("notes")
    if "options" in sent and body.options:
        values["options"] = {**(row.options or {}), **body.options}
        changed.append("options")
        if row.status == "reviewed":
            # What the owner read is no longer what would be sent: back to draft.
            values |= {
                "status": "draft",
                "reviewed_at": None,
                "reviewed_by": None,
                "reviewed_revision": None,
            }
    if not values:
        return await _detail(db, row, rec, await load_settings(db), admin=True)
    principal = await _principal(request)
    await db.execute(update(AbuseReportRow).where(AbuseReportRow.id == row.id).values(**values))
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.edit",
        target=str(row.public_id),
        ip=_client_ip(request),
        details={"changed": changed},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    await db.refresh(row)
    return await _detail(db, row, rec, await load_settings(db), admin=True)


class Accepted(BaseModel):
    requested: bool
    already_pending: bool


@router.post("/abuse/reports/{public_id}/regenerate", response_model=Accepted)
async def regenerate(public_id: PublicId, request: Request, db: DbSession) -> Response | Accepted:
    """Ask ingest to rebuild the draft. A reviewed report goes back to draft first."""
    loaded = await _load(db, public_id)
    if loaded is None:
        return _not_found()
    row, _rec = loaded
    if row.status not in ("draft", "reviewed"):
        return error(409, "Only an open report can be regenerated.", "invalid_transition")
    principal = await _principal(request)
    actor = _actor(principal)
    if row.status == "reviewed":
        try:
            await db.execute(
                update(AbuseReportRow)
                .where(AbuseReportRow.id == row.id, AbuseReportRow.status == "reviewed")
                .values(status="draft", reviewed_at=None, reviewed_by=None, reviewed_revision=None)
            )
        except DBAPIError:
            await db.rollback()
            return error(409, "That step is not possible.", "invalid_transition")
    pending = await db.scalar(
        select(func.count())
        .select_from(AbuseReportRequestRow)
        .where(
            AbuseReportRequestRow.report_id == row.id,
            AbuseReportRequestRow.action == "regenerate",
            AbuseReportRequestRow.done_at.is_(None),
        )
    )
    if not pending:
        db.add(
            AbuseReportRequestRow(report_id=row.id, action="regenerate", requested_by=actor[:120])
        )
    await audit_db.record(
        db,
        actor=actor,
        action="abuse.regenerate",
        target=str(row.public_id),
        ip=_client_ip(request),
        details={"reopened": row.status == "reviewed"},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Accepted(requested=True, already_pending=bool(pending))


# ---- recipients ----------------------------------------------------------------------------


def _mailbox(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not MAILBOX_RE.match(value):
        raise ValueError("not a valid mailbox")
    return value


@router.get("/abuse/recipients", response_model=None)
async def list_recipients(
    db: DbSession,
    limit: Limit = 50,
    cursor: Cursor = None,
    waiting: bool = False,
) -> Response | RecipientPage | list[WaitingOut]:
    if waiting:
        return await _waiting(db)
    stmt = select(AbuseRecipientRow)
    if cursor is not None:
        try:
            values = decode_cursor(cursor)
            after = values[0] if len(values) == 1 and isinstance(values[0], int) else None
        except InvalidCursorError:
            after = None
        if after is None:
            return error(400, "invalid cursor", "invalid_cursor")
        stmt = stmt.where(AbuseRecipientRow.id < after)
    rows = list(
        (await db.scalars(stmt.order_by(AbuseRecipientRow.id.desc()).limit(limit + 1))).all()
    )
    page, more = rows[:limit], len(rows) > limit
    return RecipientPage(
        items=[
            RecipientRow(
                id=r.id,
                name=r.name or r.mailbox or "Unknown network",
                mailbox=r.mailbox,
                override_mailbox=r.override_mailbox,
                source=r.source,
                muted=r.muted,
                first_seen=r.first_seen,
                reply_domains=list(r.reply_domains or []),
                shared_mailbox=_shared(r.override_mailbox or r.mailbox),
            )
            for r in page
        ],
        next_cursor=encode_cursor([page[-1].id]) if more else None,
    )


async def _waiting(db: AsyncSession) -> list[WaitingOut]:
    """Recipients without any mailbox (a network whose registry gave no contact) and how many
    subjects wait on each. The owner types a mailbox with PATCH ``override_mailbox``."""
    rows = (
        await db.execute(
            select(AbuseRecipientRow, AbuseNetworkRow)
            .join(AbuseNetworkRow, _NETWORK_RECIPIENT == AbuseRecipientRow.id)
            .where(
                AbuseRecipientRow.mailbox.is_(None), AbuseRecipientRow.override_mailbox.is_(None)
            )
            .order_by(AbuseRecipientRow.id)
            .limit(MAX_LIMIT)
        )
    ).all()
    ids = [n.id for _r, n in rows]
    counts: dict[int, int] = {}
    if ids:
        counts = {
            nid: int(c)
            for nid, c in await db.execute(
                select(AbuseLookupRow.network_id, func.count())
                .where(AbuseLookupRow.network_id.in_(ids), AbuseLookupRow.status == "no_contact")
                .group_by(AbuseLookupRow.network_id)
            )
            if nid is not None
        }
    return [
        WaitingOut(
            id=r.id,
            name=r.name or n.name or n.handle or "Unknown network",
            asns=[AsnOut(asn=n.asn, name=n.name)] if n.asn is not None else [],
            subject_count=counts.get(n.id, 0),
        )
        for r, n in rows
    ]


class RecipientPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    override_mailbox: str | None = None
    muted: bool | None = None

    @field_validator("override_mailbox")
    @classmethod
    def _box(cls, v: str | None) -> str | None:
        return None if v is None or not v.strip() else _mailbox(v)


@router.patch("/abuse/recipients/{recipient_id}", response_model=RecipientRow)
async def patch_recipient(
    recipient_id: Annotated[int, Path(ge=1, le=2**62)],
    body: RecipientPatch,
    request: Request,
    db: DbSession,
) -> Response | RecipientRow:
    rec = await db.get(AbuseRecipientRow, recipient_id)
    if rec is None:
        return error(404, "Recipient not found", "not_found")
    sent = body.model_fields_set
    values: dict[str, Any] = {}
    if "override_mailbox" in sent:
        values["override_mailbox"] = body.override_mailbox
    if "muted" in sent and body.muted is not None:
        values["muted"] = body.muted
    if values:
        principal = await _principal(request)
        await db.execute(
            update(AbuseRecipientRow).where(AbuseRecipientRow.id == rec.id).values(**values)
        )
        await audit_db.record(
            db,
            actor=_actor(principal),
            action="abuse.recipient",
            target=str(rec.id),
            ip=_client_ip(request),
            details={"changed": sorted(values)},
            actor_id=audit_db.actor_id_of(principal),
        )
        await db.commit()
        await db.refresh(rec)
    return RecipientRow(
        id=rec.id,
        name=rec.name or rec.mailbox or "Unknown network",
        mailbox=rec.mailbox,
        override_mailbox=rec.override_mailbox,
        source=rec.source,
        muted=rec.muted,
        first_seen=rec.first_seen,
        reply_domains=list(rec.reply_domains or []),
        shared_mailbox=_shared(rec.override_mailbox or rec.mailbox),
    )


# ---- settings (administrator only, also to read) -------------------------------------------


def _single_line(v: str | None) -> str | None:
    if v is None or not v.strip():
        return None
    if _CTRL.search(v) or "\n" in v or "\r" in v:
        raise ValueError("a single line without control characters is required")
    return v.strip()


def _block(v: str | None) -> str | None:
    if v is None or not v.strip():
        return None
    if _CTRL.search(v):
        raise ValueError("control characters are not allowed")
    return v.strip()


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reply_contact: Annotated[str | None, Field(max_length=254)] = None
    signature: Annotated[str | None, Field(max_length=200)] = None
    intro: Annotated[str | None, Field(max_length=1000)] = None
    outro: Annotated[str | None, Field(max_length=1000)] = None
    note: Annotated[str | None, Field(max_length=1000)] = None
    subject_template: Annotated[str | None, Field(max_length=200)] = None
    xarf_user_agent: Annotated[str | None, Field(max_length=64)] = None
    round_times: bool = True
    default_options: DefaultOptions = DefaultOptions()
    default_tlp: Literal["clear", "green", "amber", "red"] = "green"
    # Where the reply reference is printed; omitted keeps the stored choice.
    reference_style: Literal["subject", "subject_and_body", "off"] | None = None
    revision: int = Field(ge=0)

    @field_validator("reply_contact", "xarf_user_agent")
    @classmethod
    def _line(cls, v: str | None) -> str | None:
        return _single_line(v)

    @field_validator("signature", "intro", "outro", "note")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        return _block(v)

    @field_validator("subject_template")
    @classmethod
    def _template(cls, v: str | None) -> str | None:
        v = _single_line(v)
        if v is None:
            return None
        try:
            names = {n for _lit, n, _f, _c in string.Formatter().parse(v) if n is not None}
        except ValueError as exc:
            raise ValueError("invalid placeholder syntax") from exc
        if not names <= TEMPLATE_FIELDS:
            raise ValueError("unknown placeholder")
        return v


def _settings_out(
    bundle: SettingsBundle, issues: dict[str, list[str]] | None = None
) -> SettingsOut:
    s = bundle.settings
    return SettingsOut(
        reply_contact=s.reply_contact,
        signature=s.signature,
        intro=s.intro,
        outro=s.outro,
        note=s.note,
        subject_template=s.subject_template,
        xarf_user_agent=s.xarf_user_agent,
        round_times=bundle.round_times,
        default_options=DefaultOptions(**bundle.option_defaults()),
        default_tlp=bundle.tlp,  # type: ignore[arg-type]
        reference_style=bundle.reference_style,  # type: ignore[arg-type]
        revision=bundle.revision,
        field_issues=issues or {},
    )


@router.get("/abuse/settings", response_model=SettingsOut, dependencies=[AdminOnly])
async def get_settings(db: DbSession) -> SettingsOut:
    """The stored settings, and which of the texts would block every report today.

    The deny set grows over time (learned terms, new project words), so wording saved earlier
    can start to block drafts later. The answer names the fields, never the matched text."""
    bundle = await load_settings(db)
    stored = {name: getattr(bundle.settings, name) for name in SETTINGS_TEXT_FIELDS}
    return _settings_out(bundle, settings_issues(stored, await load_terms(db)))


@router.put("/abuse/settings", response_model=SettingsOut)
async def put_settings(
    body: SettingsBody, request: Request, db: DbSession
) -> Response | SettingsOut:
    """Every text field passes the identity guard first, and a refusal names the fields.

    A text that would block every report (an address on an owner domain, a name that gives the
    project away) is refused, because saving it would only leave every draft stuck."""
    issues = settings_issues(
        body.model_dump(include=set(SETTINGS_TEXT_FIELDS)), await load_terms(db)
    )
    if issues:
        return settings_guard_failed_response(issues)
    old = await load_settings(db)
    defaults = {
        **body.default_options.model_dump(),
        "round_times": body.round_times,
        "tlp": body.default_tlp,
    }
    fields = {
        "reply_contact": body.reply_contact,
        "signature": body.signature,
        "intro": body.intro,
        "outro": body.outro,
        "note": body.note,
        "subject_template": body.subject_template,
        "xarf_user_agent": body.xarf_user_agent,
        "reference_style": body.reference_style or old.reference_style,
    }
    principal = await _principal(request)
    row = await db.get(ReportSettingsRow, 1)
    now = datetime.now(UTC)
    if row is None:
        if body.revision != 0:
            return error(409, "Settings changed meanwhile.", "revision_mismatch")
        db.add(
            ReportSettingsRow(
                id=1,
                **fields,
                defaults=defaults,
                revision=1,
                updated_at=now,
                updated_by=_actor(principal)[:120],
            )
        )
    else:
        if body.revision != row.revision:
            return error(409, "Settings changed meanwhile.", "revision_mismatch")
        res = await db.execute(
            update(ReportSettingsRow)
            .where(ReportSettingsRow.id == 1, ReportSettingsRow.revision == body.revision)
            .values(
                **fields,
                defaults=defaults,
                revision=body.revision + 1,
                updated_at=now,
                updated_by=_actor(principal)[:120],
            )
        )
        if res.rowcount != 1:  # type: ignore[attr-defined]
            await db.rollback()
            return error(409, "Settings changed meanwhile.", "revision_mismatch")
    before = {
        "reply_contact": old.settings.reply_contact,
        "signature": old.settings.signature,
        "intro": old.settings.intro,
        "outro": old.settings.outro,
        "note": old.settings.note,
        "subject_template": old.settings.subject_template,
        "xarf_user_agent": old.settings.xarf_user_agent,
        "reference_style": old.reference_style,
        "defaults": {**old.option_defaults(), "round_times": old.round_times, "tlp": old.tlp},
    }
    changed = sorted(k for k, v in {**fields, "defaults": defaults}.items() if before[k] != v)
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.settings",
        ip=_client_ip(request),
        details={"changed": changed},  # field names only, never values
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    invalidate_terms()
    return _settings_out(await load_settings(db))


# ---- self terms (administrator only) -------------------------------------------------------


def _term_out(r: ReportSelfTermRow, reveal: bool) -> TermOut:
    return TermOut(
        id=r.id,
        kind=r.kind,
        value=r.value if reveal else mask_value(r.kind, r.value),
        source=r.source,
        confirmed=r.confirmed,
        distinct_sources=r.distinct_sources,
    )


@router.get("/abuse/self-terms", response_model=list[TermOut], dependencies=[AdminOnly])
async def list_terms(request: Request, db: DbSession, reveal: bool = False) -> list[TermOut]:
    """What must never appear in a report, masked unless ``reveal=true`` (audited)."""
    rows = (
        await db.scalars(
            select(ReportSelfTermRow)
            .order_by(ReportSelfTermRow.kind, ReportSelfTermRow.id)
            .limit(MAX_TERMS)
        )
    ).all()
    if reveal and rows:
        principal = await _principal(request)
        await audit_db.record(
            db,
            actor=_actor(principal),
            action="abuse.terms.reveal",
            ip=_client_ip(request),
            details={"count": len(rows)},
            actor_id=audit_db.actor_id_of(principal),
        )
        await db.commit()
    return [_term_out(r, reveal) for r in rows]


class TermBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["address", "cidr", "name", "text"]
    value: Annotated[str, Field(min_length=2, max_length=253)]

    @field_validator("value")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if _CTRL.search(v) or "\n" in v or "\r" in v:
            raise ValueError("control characters are not allowed")
        return v


def _valid_term(kind: str, value: str) -> str | None:
    """The normalised value, or None when it does not fit its kind."""
    try:
        if kind == "address":
            return str(ipaddress.ip_address(value.strip("[]")))
        if kind == "cidr":
            return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None
    if kind == "name":
        name = value.strip(".").lower()
        ok = re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*", name)
        return name if ok and len(name) >= 2 else None
    return value.casefold() if len(value) >= 2 else None


@router.post("/abuse/self-terms", response_model=TermOut, status_code=201)
async def add_term(body: TermBody, request: Request, db: DbSession) -> Response | TermOut:
    value = _valid_term(body.kind, body.value)
    if value is None:
        return error(422, "That value does not fit its kind.", "invalid_term")
    principal = await _principal(request)
    row = ReportSelfTermRow(kind=body.kind, value=value, source="manual", confirmed=True)
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return error(409, "That term already exists.", "duplicate")
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.terms.add",
        ip=_client_ip(request),
        details={"kind": body.kind},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    await db.refresh(row)
    invalidate_terms()
    return _term_out(row, reveal=False)


class TermPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed: bool


@router.patch("/abuse/self-terms/{term_id}", response_model=TermOut)
async def confirm_term(
    term_id: Annotated[int, Path(ge=1, le=2**62)],
    body: TermPatch,
    request: Request,
    db: DbSession,
) -> Response | TermOut:
    row = await db.get(ReportSelfTermRow, term_id)
    if row is None:
        return error(404, "Term not found", "not_found")
    principal = await _principal(request)
    await db.execute(
        update(ReportSelfTermRow)
        .where(ReportSelfTermRow.id == term_id)
        .values(confirmed=body.confirmed)
    )
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.terms.confirm",
        ip=_client_ip(request),
        details={"confirmed": body.confirmed},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    await db.refresh(row)
    invalidate_terms()
    return _term_out(row, reveal=False)


@router.delete("/abuse/self-terms/{term_id}", status_code=204)
async def delete_term(
    term_id: Annotated[int, Path(ge=1, le=2**62)], request: Request, db: DbSession
) -> Response:
    """A typed or learned term can be removed (a sensor-confirmed one is re-written by ingest)."""
    res = await db.execute(
        delete(ReportSelfTermRow).where(
            ReportSelfTermRow.id == term_id,
            ReportSelfTermRow.source.in_(("manual", "learned")),
        )
    )
    if res.rowcount != 1:  # type: ignore[attr-defined]
        await db.rollback()
        return error(404, "Term not found or not removable", "not_found")
    principal = await _principal(request)
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.terms.delete",
        ip=_client_ip(request),
        details={},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    invalidate_terms()
    return Response(status_code=204)
