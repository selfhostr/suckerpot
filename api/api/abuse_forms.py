"""The form-only desks queue (design M38, section 6): the queue, the copy kit, "Submitted".

Some abuse desks take reports only through a web form. The node never submits a form (N1): the
owner opens the form, pastes each field of the copy kit (or fills them with the browser helper,
which only fills and never submits), and records the submission here. A submitted report counts
as sent everywhere: the 14-day resend, takedown tracking, Results (channel "Form"), the effect
measure and the one-mail-per-day rule. It does not count against the SMTP daily cap, which counts
mails the node sent.

One kit per provider: the open form reports of one provider (its directory entry, else its
recipient) are shown as one card with one kit, and "Submitted" on it marks every report of the
group. The kit's reference (``ref <token>``) is the token of the group's first report.

Every field of the kit, its evidence file and the fill data of the browser helper pass the
identity guard on their own and together (``suckerpot_reporting.forms.guard_kit``) right before
they are returned; a blocked kit answers 409 with reason codes only. A form link learned from a
reply is untrusted: it is shown as a link only when it is ``https`` on the provider's own domain
with no query string, and nothing here writes the shared directory. The browser warning is fixed:
a form submitted from the owner's browser does not leave through the VPN.

Administrators only (the kit holds the reply contact and the reply token).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
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
from suckerpot_reporting import Evidence, GuardContext, GuardResult, RenderUnavailable
from suckerpot_reporting.evidence import MAX_SUBJECTS
from suckerpot_reporting.forms import (
    Directory,
    DirectoryError,
    FormEntry,
    Kit,
    build_kit,
    bundled,
    guard_kit,
    in_domains,
    merge_evidence,
    url_problem,
)

from api import audit as audit_db
from api.abuse import (
    GuardOut,
    RecipientOut,
    _asns_of,
    _domain_of,
    _load,
    _recipient_out,
    own_domains,
)
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
GROUP_MAX = 20  # open form reports in one provider's kit
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


class ReportRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    public_id: uuid.UUID
    revision: int = Field(ge=1)


class FormQueueItem(BaseModel):
    """One card of the queue: every open form report of one provider. ``public_id`` and
    ``revision`` are the first report's; ``reports`` lists them all."""

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
    provider: str = ""
    reports: list[ReportRef] = []


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
    type_key: str
    fill: str  # the browser helper's data for this source alone


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
    type_key: str
    # The browser helper's data (JSON): kit values, the form's labels and selectors. Guarded.
    fill: str
    # Every open form report of this provider the kit covers ("Submitted" marks them all).
    reports: list[ReportRef]
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
    subjects: Annotated[list[SubjectRef] | None, Field(max_length=MAX_SUBJECTS)] = None
    # The reports of the provider's kit as the owner saw them (``KitOut.reports``); omitted
    # means this report alone.
    reports: Annotated[list[ReportRef] | None, Field(min_length=1, max_length=GROUP_MAX)] = None


class SubmittedOut(BaseModel):
    public_id: str
    submitted: int
    left: int  # unticked sources: they wait for the next form report
    sent_at: datetime
    reports: int = 1  # form reports marked sent


# ---- helpers ---------------------------------------------------------------------------------


def _no_store(model: BaseModel, status: int = 200) -> Response:
    return JSONResponse(
        model.model_dump(mode="json"), status_code=status, headers={"Cache-Control": "no-store"}
    )


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


# ---- one kit per provider --------------------------------------------------------------------


@dataclass(frozen=True)
class Member:
    """One open form report in the queue, with its subject counts and directory entry."""

    row: AbuseReportRow
    rec: AbuseRecipientRow
    subjects: int
    stale: int
    entry: FormEntry | None

    @property
    def provider_key(self) -> str:
        """Reports of one directory entry share a kit (several mailboxes of one provider); a
        desk the directory does not know is its own provider."""
        return f"entry:{self.entry.id}" if self.entry is not None else f"recipient:{self.rec.id}"


def group_members(members: Sequence[Member]) -> list[list[Member]]:
    """The queue's cards: the members of one provider together, in queue order (oldest week
    first). A group holds at most ``GROUP_MAX`` reports and ``MAX_SUBJECTS`` sources (one kit);
    the rest of that provider starts a new card."""
    groups: list[list[Member]] = []
    current: dict[str, list[Member]] = {}
    for m in members:
        group = current.get(m.provider_key)
        if (
            group is None
            or len(group) >= GROUP_MAX
            or sum(g.subjects for g in group) + m.subjects > MAX_SUBJECTS
        ):
            group = []
            groups.append(group)
            current[m.provider_key] = group
        group.append(m)
    return groups


async def _members(db: AsyncSession) -> list[Member]:
    """The open form reports with at least one source, oldest week first."""
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
    out: list[Member] = []
    for row, rec in rows:
        n, stale = counts.get(row.id, (0, 0))
        if n == 0:
            continue
        asns: list[int | None] = [a.asn for a in _asns_of(row.evidence)]
        out.append(Member(row, rec, n, stale, entry_of(rec, asns)))
    return out


async def group_of(
    db: AsyncSession, row: AbuseReportRow, rec: AbuseRecipientRow
) -> list[tuple[AbuseReportRow, AbuseRecipientRow]]:
    """The reports of the provider's kit that holds this report, first report first. A report
    that is not in the queue (a demo, a muted desk) is a kit of its own."""
    if not row.demo:
        for group in group_members(await _members(db)):
            if any(m.row.id == row.id for m in group):
                return [(m.row, m.rec) for m in group]
    return [(row, rec)]


def _refs(group: Sequence[tuple[AbuseReportRow, AbuseRecipientRow]]) -> list[ReportRef]:
    return [ReportRef(public_id=r.public_id, revision=r.revision) for r, _ in group]


async def _kit(
    db: AsyncSession,
    group: Sequence[tuple[AbuseReportRow, AbuseRecipientRow]],
    bundle: SettingsBundle,
) -> tuple[Kit, list[FormLinkOut], GuardResult]:
    """Build the kit of a provider's reports and run the guard on all of it. The first report
    gives the reference token and the options. Raises ``RenderUnavailable`` or
    ``EvidenceInvalidError``."""
    lead, lead_rec = group[0]
    parts: list[Evidence] = []
    internal: set[str] = set()
    allow_documentation = True
    held: set[str] = set()
    for row, rec in group:
        evidence = await load_evidence(db, row, rec, bundle)
        ctx = await guard_context(db, row, evidence)
        parts.append(evidence)
        internal.update(ctx.internal_ids)
        allow_documentation = allow_documentation and ctx.allow_documentation
        held.update(held_evidence_codes(row))
    try:
        evidence = merge_evidence(parts)
    except ValueError as exc:
        raise EvidenceInvalidError("too many sources for one kit") from exc
    ctx = GuardContext(internal_ids=frozenset(internal), allow_documentation=allow_documentation)
    terms = await load_terms(db)
    entry = entry_of(lead_rec, _evidence_asns(evidence))
    links: list[FormLinkOut] = []
    for _row, rec in group:
        for link in links_of(rec, entry):
            if all((link.origin, link.url) != (x.origin, x.url) for x in links):
                links.append(link)
    links.sort(key=lambda link: link.origin != "directory")  # the reviewed link first

    def run() -> tuple[Kit, GuardResult]:
        kit = build_kit(
            evidence,
            bundle.settings,
            entry=entry,
            form_name=bundle.form_name,
            reply_token=lead.reply_token,
            reference_style=bundle.reference_style,  # type: ignore[arg-type]
        )
        return kit, guard_kit(kit, terms, ctx=ctx, links=[link.url for link in links])

    kit, result = await asyncio.to_thread(run)
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
    """Form reports still to submit, one card per provider, oldest week first."""
    bundle = await load_settings(db)
    items: list[FormQueueItem] = []
    for group in group_members(await _members(db)):
        lead = group[0]
        links = links_of(lead.rec, lead.entry)
        first = links[0] if links else None
        codes = sorted({c for m in group for c in (m.row.guard_codes or [])})
        items.append(
            FormQueueItem(
                public_id=str(lead.row.public_id),
                revision=lead.row.revision,
                status=lead.row.status,
                recipient=_recipient_out(lead.rec),
                week=max((m.row.week for m in group if m.row.week), default=None),
                subject_count=sum(m.subjects for m in group),
                stale_count=sum(m.stale for m in group),
                window_start=min(m.row.window_start for m in group),
                window_end=max(m.row.window_end for m in group),
                updated_at=max(m.row.updated_at for m in group),
                guard=GuardOut(ok=all(m.row.guard_ok for m in group), codes=codes),
                form_host=first.host if first else None,
                form_origin=first.origin if first else None,
                provider=(
                    lead.entry.provider
                    if lead.entry is not None and len({m.rec.id for m in group}) > 1
                    else lead.rec.name or lead.rec.mailbox or "Unknown network"
                ),
                reports=[
                    ReportRef(public_id=m.row.public_id, revision=m.row.revision) for m in group
                ],
            )
        )
    return _no_store(FormQueue(items=items, missing=list(missing_for(bundle.settings))))


# ---- the copy kit ----------------------------------------------------------------------------


@router.get("/abuse/reports/{public_id}/kit", response_model=KitOut)
async def get_kit(public_id: uuid.UUID, db: DbSession) -> Response:
    """Every field of the copy kit of this report's provider (all its open form reports), after
    the identity guard. 409 with reason codes when blocked: nothing of a blocked kit is
    returned."""
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
    group = await group_of(db, row, rec)
    try:
        kit, links, result = await _kit(db, group, bundle)
    except (RenderUnavailable, EvidenceInvalidError) as exc:
        return _refuse_kit(exc, bundle)
    if not result.ok:
        log.warning("abuse kit blocked report=%s reasons=%s", row.id, ",".join(result.codes))
        return guard_failed_response(tuple(result.codes))
    lead, lead_rec = group[0]
    directory_url = next((x.url for x in links if x.origin == "directory"), None)
    return _no_store(
        KitOut(
            public_id=str(lead.public_id),
            revision=lead.revision,
            status=lead.status,
            provider=lead_rec.name or lead_rec.mailbox or "Unknown network",
            mailbox=lead_rec.override_mailbox or lead_rec.mailbox,
            week=max((r.week for r, _ in group if r.week), default=None),
            warning=BROWSER_WARNING,
            links=links,
            links_differ=directory_url is not None
            and any(x.origin == "reply" and x.url != directory_url for x in links),
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
                    type_key=s.type_key,
                    fill=s.fill,
                )
                for s in kit.sources
            ],
            one_ip_per_submission=kit.one_ip_per_submission,
            max_chars=kit.max_chars,
            labels=dict(kit.labels),
            type_key=kit.type_key,
            fill=kit.fill,
            reports=_refs(group),
            guard=GuardOut(ok=True, codes=[]),
        )
    )


# ---- Submitted -------------------------------------------------------------------------------


def _changed() -> JSONResponse:
    return error(409, "The report changed while you were reading it.", "revision_mismatch")


def _bad_step() -> JSONResponse:
    return error(409, "That step is not possible from the current status.", "invalid_transition")


@router.post("/abuse/reports/{public_id}/submitted", response_model=SubmittedOut)
async def mark_submitted(
    public_id: uuid.UUID, body: SubmittedBody, request: Request, db: DbSession
) -> Response:
    """The owner submitted the provider's kit through its form. The ticked sources count as sent
    (``sent_via = 'form'``) in every report of the kit (``reports``, as the kit listed them);
    the others leave their report and wait for the next one. A report with no ticked source is
    left as it is. All or nothing: one transaction."""
    loaded = await _load(db, public_id)
    if loaded is None:
        return error(404, "Report not found", "not_found")
    row, rec = loaded
    if (refused := _not_form(row)) is not None:
        return refused
    if row.demo:
        return error(409, "A demo report cannot be sent.", "demo_report")
    if row.status not in ("draft", "reviewed"):
        return _bad_step()
    if body.reports is None:
        if body.revision != row.revision:
            return _changed()
        group = [(row, rec)]
    else:
        group = await group_of(db, row, rec)
        seen = {(r.public_id, r.revision) for r, _ in group}
        asked = {(r.public_id, r.revision) for r in body.reports}
        # The kit the owner submitted must still be this provider's kit, report for report.
        if seen != asked or len(asked) != len(body.reports) or body.revision != row.revision:
            return _changed()
    if any(r.status not in ("draft", "reviewed") or r.demo for r, _ in group):
        return _bad_step()
    bundle = await load_settings(db)
    missing = missing_for(bundle.settings)
    if missing:
        return settings_incomplete_response(missing)
    try:
        _kit_unused, _links, result = await _kit(db, group, bundle)
    except (RenderUnavailable, EvidenceInvalidError) as exc:
        return _refuse_kit(exc, bundle)
    if not result.ok:
        return guard_failed_response(tuple(result.codes))
    keys_of: dict[int, set[tuple[str, str, str]]] = {}
    for r, _rec in group:
        keys_of[r.id] = {
            (s.kind, s.subject_type, s.value)
            for s in (
                await db.scalars(
                    select(AbuseReportSubjectRow).where(AbuseReportSubjectRow.report_id == r.id)
                )
            ).all()
        }
    every = set().union(*keys_of.values())
    ticked = (
        set(every)
        if body.subjects is None
        else {(s.kind, s.subject_type, s.value) for s in body.subjects}
    )
    if not ticked:
        return error(422, "Tick at least one address.", "no_subjects")
    if not ticked <= every:
        return error(409, "The report changed while you were reading it.", "unknown_subject")
    principal = await current_principal(request)
    actor = principal.username if principal else "anonymous"
    now = datetime.now(UTC)
    revisions = {r.id: r.revision for r, _ in group}
    # Lock the reports (in id order): a rebuild that comes in now waits, then finds them no
    # longer drafts.
    locked = {
        lr.id: lr
        for lr in (
            await db.execute(
                select(AbuseReportRow.id, AbuseReportRow.status, AbuseReportRow.revision)
                .where(AbuseReportRow.id.in_(sorted(revisions)))
                .order_by(AbuseReportRow.id)
                .with_for_update()
            )
        ).all()
    }
    if any(rid not in locked or locked[rid].revision != rv for rid, rv in revisions.items()):
        await db.rollback()
        return _changed()
    submitted = 0
    sent_reports = 0
    # A reviewed report is sent before a draft of the same desk is reviewed: one reviewed report
    # per desk at a time (``ux_abuse_reports_reviewed``).
    order = sorted(group, key=lambda g: (locked[g[0].id].status != "reviewed", g[0].id))
    for r, _rec in order:
        mine = keys_of[r.id] & ticked
        if not mine:
            continue  # nothing of it was submitted: it stays in the queue as it is
        try:
            if locked[r.id].status == "draft":
                await db.execute(
                    update(AbuseReportRow)
                    .where(AbuseReportRow.id == r.id, AbuseReportRow.status == "draft")
                    .values(
                        status="reviewed",
                        reviewed_at=now,
                        reviewed_by=actor[:120],
                        reviewed_revision=locked[r.id].revision,
                    )
                )
            res = await db.execute(
                update(AbuseReportRow)
                .where(AbuseReportRow.id == r.id, AbuseReportRow.status == "reviewed")
                .values(status="sent", sent_at=now, sent_by=actor[:120], sent_via="form")
            )
        except DBAPIError:
            await db.rollback()
            return _bad_step()
        if res.rowcount != 1:  # type: ignore[attr-defined]
            await db.rollback()
            return _bad_step()
        # A send request still waiting for this report must not go out by mail as well.
        await db.execute(text("SET LOCAL lock_timeout = '2s'"))
        try:
            await db.execute(
                update(AbuseSendRequestRow)
                .where(
                    AbuseSendRequestRow.report_id == r.id, AbuseSendRequestRow.status == "pending"
                )
                .values(status="cancelled")
            )
        except DBAPIError:
            await db.rollback()
            return error(409, "The report is being sent right now.", "already_sending")
        if await db.scalar(
            select(func.count())
            .select_from(AbuseSendRequestRow)
            .where(AbuseSendRequestRow.report_id == r.id, AbuseSendRequestRow.status == "sending")
        ):
            await db.rollback()
            return error(409, "The report is being sent right now.", "already_sending")
        for kind, stype, value in sorted(mine):
            await db.execute(
                update(AbuseReportSubjectRow)
                .where(
                    AbuseReportSubjectRow.report_id == r.id,
                    AbuseReportSubjectRow.kind == kind,
                    AbuseReportSubjectRow.subject_type == stype,
                    AbuseReportSubjectRow.value == value,
                )
                .values(submitted_at=now)
            )
        left = len(keys_of[r.id]) - len(mine)
        if left:
            # Not submitted: not sent. They go into the next form report (trigger: only here).
            await db.execute(
                text(
                    "DELETE FROM abuse_report_subjects "
                    "WHERE report_id = :i AND submitted_at IS NULL"
                ),
                {"i": r.id},
            )
        await audit_db.record(
            db,
            actor=actor,
            action="abuse.form_submitted",
            target=str(r.public_id),
            ip=request.app.state.auth.client_ip(request),
            details={"sources": len(mine), "left": left, "kit_reports": len(group)},
            actor_id=audit_db.actor_id_of(principal),
        )
        submitted += len(mine)
        sent_reports += 1
    await db.commit()
    left_total = sum(len(k) for k in keys_of.values()) - submitted
    return _no_store(
        SubmittedOut(
            public_id=str(row.public_id),
            submitted=submitted,
            left=left_total,
            sent_at=now,
            reports=sent_reports,
        )
    )
