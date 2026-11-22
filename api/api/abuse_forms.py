"""The form-only desks queue (design M38, section 6): the queue, the copy kit, "Submitted".

Some abuse desks take reports only through a web form. The node never submits a form (N1): the
owner opens the form, pastes each field of the copy kit, and records the submission here. A
submitted report counts as sent everywhere: the 14-day resend, takedown tracking, Results (channel
"Form"), the effect measure and the one-mail-per-day rule. It does not count against the SMTP
daily cap, which counts mails the node sent.

Every field of the kit and its evidence file pass the identity guard on their own and together
(``suckerpot_reporting.forms.guard_kit``) right before they are returned; a blocked kit answers
409 with reason codes only. A form link learned from a reply is untrusted: it is shown as a link
only when it is ``https`` on the provider's own domain with no query string, and nothing here
writes the shared directory. The browser warning is fixed: a form submitted from the owner's
browser does not leave through the VPN.

Administrators only (the kit holds the reply contact and the reply token).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import (
    AbuseRecipientRow,
    AbuseReportRow,
    AbuseReportSubjectRow,
    AbuseSendRequestRow,
)
from suckerpot_reporting import Evidence, GuardResult, RenderUnavailable
from suckerpot_reporting.forms import (
    Directory,
    DirectoryError,
    FormEntry,
    Kit,
    build_kit,
    bundled,
    guard_kit,
    in_domains,
    url_problem,
)

from api import audit as audit_db
from api.abuse import GuardOut, RecipientOut, _asns_of, _load, _recipient_out
from api.abuse_core import (
    EvidenceInvalidError,
    SettingsBundle,
    error,
    guard_context,
    guard_failed_response,
    held_evidence_codes,
    load_evidence,
    load_settings,
    load_terms,
    missing_for,
    settings_incomplete_response,
)
from api.auth import current_principal
from api.authz import require_admin
from api.deps import DbSession

router = APIRouter(tags=["abuse"], dependencies=[Depends(require_admin)])
log = logging.getLogger("api.abuse")

QUEUE_MAX = 200
FRESH_DAYS = 7
# Shown at the top of every kit. Mail leaves through the VPN; a browser does not, unless the
# owner makes it.
BROWSER_WARNING = (
    "The provider sees the address of the browser that submits the form. "
    "Open it through your VPN or the Tor Browser."
)
SubjectKind = Literal["attack_source", "payload_host", "c2"]


@lru_cache(maxsize=1)
def directory() -> Directory:
    """The shared directory shipped with the release; empty (and logged) when it is invalid."""
    try:
        return bundled()
    except (DirectoryError, OSError, ValueError) as exc:
        log.warning("abuse form directory refused (%s)", exc)
        return Directory()


# ---- shapes (the contract with web/src/lib/abuse-forms.ts) ---------------------------------


class FormLinkOut(BaseModel):
    url: str
    host: str
    origin: Literal["directory", "reply"]
    # A link only when https on an allowed host with no query string (else shown as text).
    clickable: bool
    checked_on: date | None = None  # directory links: the maintainers' last check
    stale: bool = False  # last checked over a year ago


class FormQueueItem(BaseModel):
    public_id: str
    revision: int
    status: str
    recipient: RecipientOut
    week: date | None
    subject_count: int
    stale_count: int  # sources older than 7 days
    window_start: datetime
    window_end: datetime
    updated_at: datetime
    guard: GuardOut
    form_host: str | None = None
    form_origin: Literal["directory", "reply"] | None = None


class FormQueue(BaseModel):
    items: list[FormQueueItem]
    missing: list[str]  # required settings still empty (the reply contact)


class KitSourceOut(BaseModel):
    kind: str
    subject_type: str
    value: str
    abuse_type: str
    first_seen: str
    last_seen: str
    description: str
    log_excerpt: str
    stale: bool


class KitFileOut(BaseModel):
    name: str
    media_type: str
    content: str


class KitOut(BaseModel):
    public_id: str
    revision: int
    status: str
    provider: str
    mailbox: str | None
    week: date | None
    warning: str
    links: list[FormLinkOut]
    links_differ: bool  # the directory and a reply point at different forms
    email: str
    name: str
    abuse_type: str
    addresses: str
    first_seen: str
    last_seen: str
    description: str
    log_excerpt: str
    evidence: KitFileOut
    sources: list[KitSourceOut]
    one_ip_per_submission: bool
    max_chars: int
    labels: dict[str, str]  # the form's own label per kit field (from the directory)
    guard: GuardOut


class SubjectRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: SubjectKind
    subject_type: Literal["ip", "url", "domain"]
    value: Annotated[str, Field(min_length=1, max_length=1024)]


class SubmittedBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int = Field(ge=1)
    # The sources the owner ticked; omitted means all of them.
    subjects: Annotated[list[SubjectRef] | None, Field(max_length=100)] = None


class SubmittedOut(BaseModel):
    public_id: str
    submitted: int
    left: int  # unticked sources: they wait for the next form report
    sent_at: datetime


# ---- helpers ---------------------------------------------------------------------------------


def _no_store(model: BaseModel, status: int = 200) -> Response:
    return JSONResponse(
        model.model_dump(mode="json"), status_code=status, headers={"Cache-Control": "no-store"}
    )


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().lower() or None


def own_domains(rec: AbuseRecipientRow) -> list[str]:
    """The provider's own domains: its mailbox domain and the domains it answers from."""
    out = [d for d in (_domain_of(rec.override_mailbox or rec.mailbox),) if d]
    out += [str(d).lower() for d in (rec.reply_domains or []) if d]
    return out


def entry_of(rec: AbuseRecipientRow, asns: list[int | None]) -> FormEntry | None:
    """The directory entry of a recipient: the one that routed it, else by mailbox and ASN."""
    d = directory()
    return d.by_id(rec.form_entry) or d.match(_domain_of(rec.override_mailbox or rec.mailbox), asns)


def _host(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].lower()[:255]


def links_of(rec: AbuseRecipientRow, entry: FormEntry | None) -> list[FormLinkOut]:
    """The form links to show: the directory's (reviewed) first, then a reply's (a hint)."""
    today = datetime.now(UTC).date()
    out: list[FormLinkOut] = []
    if entry is not None:
        out.append(
            FormLinkOut(
                url=entry.form_url,
                host=_host(entry.form_url),
                origin="directory",
                clickable=url_problem(entry.form_url, entry.official_domains) is None,
                checked_on=entry.verified_on,
                stale=entry.stale(today),
            )
        )
    reply = rec.form_url  # from a verified reply on the provider's domain (ingest), a hint
    if reply and (entry is None or reply != entry.form_url):
        domains = own_domains(rec)
        host = _host(reply)
        out.append(
            FormLinkOut(
                url=reply,
                host=host,
                origin="reply",
                clickable=url_problem(reply, domains, allow_lang=False) is None
                and in_domains(host, domains),
            )
        )
    return out


def _evidence_asns(evidence: Evidence) -> list[int | None]:
    return [s.asn for s in evidence.subjects]


async def _kit(
    db: AsyncSession, row: AbuseReportRow, rec: AbuseRecipientRow, bundle: SettingsBundle
) -> tuple[Kit, list[FormLinkOut], GuardResult]:
    """Build the kit and run the guard on all of it. Raises ``RenderUnavailable`` or
    ``EvidenceInvalidError``."""
    evidence = await load_evidence(db, row, rec, bundle)
    ctx = await guard_context(db, row, evidence)
    terms = await load_terms(db)
    entry = entry_of(rec, _evidence_asns(evidence))
    links = links_of(rec, entry)

    def run() -> tuple[Kit, GuardResult]:
        kit = build_kit(
            evidence,
            bundle.settings,
            entry=entry,
            form_name=bundle.form_name,
            reply_token=row.reply_token,
            reference_style=bundle.reference_style,  # type: ignore[arg-type]
        )
        return kit, guard_kit(kit, terms, ctx=ctx, links=[link.url for link in links])

    kit, result = await asyncio.to_thread(run)
    held = held_evidence_codes(row)
    if held:
        result = GuardResult(
            ok=False,
            codes=tuple(sorted({*result.codes, *held})),
            counts={**result.counts, **dict.fromkeys(held, 1)},
        )
    return kit, links, result


def _refuse_kit(exc: Exception, bundle: SettingsBundle) -> JSONResponse:
    if isinstance(exc, RenderUnavailable):
        if exc.code == "settings_incomplete":
            return settings_incomplete_response(missing_for(bundle.settings))
        if exc.code == "reply_contact_not_email":
            return error(409, "The reply contact must hold a mail address.", exc.code)
        return error(409, "The copy kit is not available for this report.", exc.code)
    return error(409, "The stored evidence is not valid.", "evidence_invalid")


def _not_form(row: AbuseReportRow) -> JSONResponse | None:
    if row.channel != "form":
        return error(409, "This report is not in the form queue.", "not_a_form_report")
    return None


# ---- the queue -------------------------------------------------------------------------------


@router.get("/abuse/forms", response_model=FormQueue)
async def form_queue(db: DbSession) -> Response:
    """Form reports still to submit, one per provider and week, oldest week first."""
    bundle = await load_settings(db)
    rows = (
        await db.execute(
            select(AbuseReportRow, AbuseRecipientRow)
            .join(AbuseRecipientRow, AbuseRecipientRow.id == AbuseReportRow.recipient_id)
            .where(
                AbuseReportRow.channel == "form",
                AbuseReportRow.status.in_(("draft", "reviewed")),
                AbuseReportRow.demo.is_(False),
                AbuseRecipientRow.muted.is_(False),
            )
            .order_by(AbuseReportRow.week, AbuseReportRow.id)
            .limit(QUEUE_MAX)
        )
    ).all()
    ids = [r.id for r, _ in rows]
    counts: dict[int, tuple[int, int]] = {}
    if ids:
        fresh_after = datetime.now(UTC) - timedelta(days=FRESH_DAYS)
        for rid, n, stale in await db.execute(
            select(
                AbuseReportSubjectRow.report_id,
                func.count(),
                func.count().filter(AbuseReportSubjectRow.last_ts <= fresh_after),
            )
            .where(AbuseReportSubjectRow.report_id.in_(ids))
            .group_by(AbuseReportSubjectRow.report_id)
        ):
            counts[rid] = (int(n), int(stale))
    items: list[FormQueueItem] = []
    for row, rec in rows:
        asns: list[int | None] = [a.asn for a in _asns_of(row.evidence)]
        links = links_of(rec, entry_of(rec, asns))
        first = links[0] if links else None
        n, stale = counts.get(row.id, (0, 0))
        if n == 0:
            continue
        items.append(
            FormQueueItem(
                public_id=str(row.public_id),
                revision=row.revision,
                status=row.status,
                recipient=_recipient_out(rec),
                week=row.week,
                subject_count=n,
                stale_count=stale,
                window_start=row.window_start,
                window_end=row.window_end,
                updated_at=row.updated_at,
                guard=GuardOut(ok=row.guard_ok, codes=list(row.guard_codes)),
                form_host=first.host if first else None,
                form_origin=first.origin if first else None,
            )
        )
    return _no_store(FormQueue(items=items, missing=list(missing_for(bundle.settings))))


# ---- the copy kit ----------------------------------------------------------------------------


@router.get("/abuse/reports/{public_id}/kit", response_model=KitOut)
async def get_kit(public_id: uuid.UUID, db: DbSession) -> Response:
    """Every field of the copy kit, after the identity guard. 409 with reason codes when blocked:
    nothing of a blocked kit is returned."""
    loaded = await _load(db, public_id)
    if loaded is None:
        return error(404, "Report not found", "not_found")
    row, rec = loaded
    if (refused := _not_form(row)) is not None:
        return refused
    bundle = await load_settings(db)
    missing = missing_for(bundle.settings)
    if missing:
        return settings_incomplete_response(missing)
    try:
        kit, links, result = await _kit(db, row, rec, bundle)
    except (RenderUnavailable, EvidenceInvalidError) as exc:
        return _refuse_kit(exc, bundle)
    if not result.ok:
        log.warning("abuse kit blocked report=%s reasons=%s", row.id, ",".join(result.codes))
        return guard_failed_response(tuple(result.codes))
    origins = {link.origin: link.url for link in links}
    return _no_store(
        KitOut(
            public_id=str(row.public_id),
            revision=row.revision,
            status=row.status,
            provider=rec.name or rec.mailbox or "Unknown network",
            mailbox=rec.override_mailbox or rec.mailbox,
            week=row.week,
            warning=BROWSER_WARNING,
            links=links,
            links_differ=len(origins) == 2 and origins["directory"] != origins["reply"],
            email=kit.email,
            name=kit.name,
            abuse_type=kit.abuse_type,
            addresses=kit.addresses,
            first_seen=kit.first_seen,
            last_seen=kit.last_seen,
            description=kit.description,
            log_excerpt=kit.log_excerpt,
            evidence=KitFileOut(
                name=kit.evidence.name,
                media_type=kit.evidence.media_type,
                content=kit.evidence.content,
            ),
            sources=[
                KitSourceOut(
                    kind=s.kind,
                    subject_type=s.type,
                    value=s.value,
                    abuse_type=s.abuse_type,
                    first_seen=s.first_seen,
                    last_seen=s.last_seen,
                    description=s.description,
                    log_excerpt=s.log_excerpt,
                    stale=s.stale,
                )
                for s in kit.sources
            ],
            one_ip_per_submission=kit.one_ip_per_submission,
            max_chars=kit.max_chars,
            labels=dict(kit.labels),
            guard=GuardOut(ok=True, codes=[]),
        )
    )


# ---- Submitted -------------------------------------------------------------------------------


@router.post("/abuse/reports/{public_id}/submitted", response_model=SubmittedOut)
async def mark_submitted(
    public_id: uuid.UUID, body: SubmittedBody, request: Request, db: DbSession
) -> Response:
    """The owner submitted the report through the provider's form. The ticked sources count as
    sent (``sent_via = 'form'``); the others leave the report and wait for the next one."""
    loaded = await _load(db, public_id)
    if loaded is None:
        return error(404, "Report not found", "not_found")
    row, rec = loaded
    if (refused := _not_form(row)) is not None:
        return refused
    if row.demo:
        return error(409, "A demo report cannot be sent.", "demo_report")
    if row.status not in ("draft", "reviewed"):
        return error(
            409, "That step is not possible from the current status.", "invalid_transition"
        )
    if body.revision != row.revision:
        return error(409, "The report changed while you were reading it.", "revision_mismatch")
    bundle = await load_settings(db)
    missing = missing_for(bundle.settings)
    if missing:
        return settings_incomplete_response(missing)
    try:
        _kit_unused, _links, result = await _kit(db, row, rec, bundle)
    except (RenderUnavailable, EvidenceInvalidError) as exc:
        return _refuse_kit(exc, bundle)
    if not result.ok:
        return guard_failed_response(tuple(result.codes))
    keys = {
        (s.kind, s.subject_type, s.value)
        for s in (
            await db.scalars(
                select(AbuseReportSubjectRow).where(AbuseReportSubjectRow.report_id == row.id)
            )
        ).all()
    }
    ticked = (
        set(keys)
        if body.subjects is None
        else {(s.kind, s.subject_type, s.value) for s in body.subjects}
    )
    if not ticked:
        return error(422, "Tick at least one address.", "no_subjects")
    if not ticked <= keys:
        return error(409, "The report changed while you were reading it.", "unknown_subject")
    principal = await current_principal(request)
    actor = principal.username if principal else "anonymous"
    now = datetime.now(UTC)
    # Lock the report: a rebuild that comes in now waits, then finds it no longer a draft.
    locked = (
        await db.execute(
            select(AbuseReportRow.status, AbuseReportRow.revision)
            .where(AbuseReportRow.id == row.id)
            .with_for_update()
        )
    ).first()
    if locked is None or locked.revision != body.revision:
        await db.rollback()
        return error(409, "The report changed while you were reading it.", "revision_mismatch")
    try:
        if locked.status == "draft":
            await db.execute(
                update(AbuseReportRow)
                .where(AbuseReportRow.id == row.id, AbuseReportRow.status == "draft")
                .values(
                    status="reviewed",
                    reviewed_at=now,
                    reviewed_by=actor[:120],
                    reviewed_revision=locked.revision,
                )
            )
        res = await db.execute(
            update(AbuseReportRow)
            .where(AbuseReportRow.id == row.id, AbuseReportRow.status == "reviewed")
            .values(status="sent", sent_at=now, sent_by=actor[:120], sent_via="form")
        )
    except DBAPIError:
        await db.rollback()
        return error(
            409, "That step is not possible from the current status.", "invalid_transition"
        )
    if res.rowcount != 1:  # type: ignore[attr-defined]
        await db.rollback()
        return error(
            409, "That step is not possible from the current status.", "invalid_transition"
        )
    # A send request still waiting for this report must not go out by mail as well.
    await db.execute(text("SET LOCAL lock_timeout = '2s'"))
    try:
        await db.execute(
            update(AbuseSendRequestRow)
            .where(AbuseSendRequestRow.report_id == row.id, AbuseSendRequestRow.status == "pending")
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
    for kind, stype, value in sorted(ticked):
        await db.execute(
            update(AbuseReportSubjectRow)
            .where(
                AbuseReportSubjectRow.report_id == row.id,
                AbuseReportSubjectRow.kind == kind,
                AbuseReportSubjectRow.subject_type == stype,
                AbuseReportSubjectRow.value == value,
            )
            .values(submitted_at=now)
        )
    left = len(keys) - len(ticked)
    if left:
        # Not submitted: not sent. They go into the next form report (trigger: only here).
        await db.execute(
            text("DELETE FROM abuse_report_subjects WHERE report_id = :i AND submitted_at IS NULL"),
            {"i": row.id},
        )
    await audit_db.record(
        db,
        actor=actor,
        action="abuse.form_submitted",
        target=str(row.public_id),
        ip=request.app.state.auth.client_ip(request),
        details={"sources": len(ticked), "left": left},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(
        SubmittedOut(public_id=str(row.public_id), submitted=len(ticked), left=left, sent_at=now)
    )
