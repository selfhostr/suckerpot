"""Shared pieces of the abuse-report routes (M22): the deny set, settings, evidence and rendering.

Nothing here sends anything. Every artefact that leaves the API passes the identity guard of
``suckerpot_reporting`` immediately before it is returned, and a failure carries reason codes
only: never the matched text, never in an answer, a log line or an audit row.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Final

from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import (
    AbuseRecipientRow,
    AbuseReportRow,
    AbuseReportSubjectRow,
    EnrichmentStatusRow,
    IndicatorRow,
    IndicatorSessionRow,
    NetworkMembershipRow,
    ReportSelfTermRow,
    ReportSettingsRow,
    SessionRow,
)
from suckerpot_reporting import (
    REFERENCE_STYLES,
    Attachment,
    Evidence,
    GuardContext,
    GuardResult,
    ReferenceStyle,
    RenderedMessage,
    RenderUnavailable,
    ReportOptions,
    ReportSettings,
    SelfTermRow,
    SelfTerms,
    guard,
    guard_message,
    load_self_terms,
    missing_settings,
    render_csv,
    render_eml,
    render_mail,
    render_text,
    require_ok,
)
from suckerpot_reporting.message import JSON_TYPE
from suckerpot_reporting.xarf import dumps as xarf_dumps

log = logging.getLogger("api.abuse")

TERMS_TTL_S: Final = 60.0
MAX_CONTEXT_SESSIONS: Final = 5000
CONTEXT_LOOKBACK: Final = timedelta(days=90)  # ABUSE_LOOKBACK_DAYS is at most 90
# Reason codes that come from the evidence itself. The draft build sets them; a later check
# (here and in ingest.abuse.reguard) cannot replay the build's reads, so only the build clears them.
EVIDENCE_CODES: Final = frozenset({"internal_id", "private_address", "documentation_address"})


def held_evidence_codes(row: AbuseReportRow) -> tuple[str, ...]:
    """The evidence codes the build stored on an open draft (sorted), or an empty tuple.

    A draft that carries one is never rendered, downloaded or exported, and never reviewed: the
    live check works from a capped read of the sessions, so it cannot be trusted to clear them.
    Only a rebuild that reads the evidence again and finds it clean removes them."""
    if row.status != "draft":
        return ()
    return tuple(sorted(EVIDENCE_CODES.intersection(row.guard_codes or ())))


TRUE_VALUES: Final = frozenset({"1", "true", "yes", "on"})
MAILBOX_RE: Final = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")

OPTION_KEYS: Final = (
    "defang",
    "time_precision",
    "include_usernames",
    "include_reply_contact",
    "show_redaction_counts",
)
DEFAULT_TLP: Final = "green"
# The owner's own wording. Each part ends up in every report, so each one is guarded on its own.
SETTINGS_TEXT_FIELDS: Final = (
    "reply_contact",
    "signature",
    "intro",
    "outro",
    "note",
    "subject_template",
    "xarf_user_agent",
    "xarf_org",
)
# Report statuses that may still be sent (their XARF ids live on the subject rows).
OPEN_STATUSES: Final = frozenset({"draft", "reviewed"})

# Keyed by whether the node's network pseudonym is a deny term (outgoing reports only).
_terms_cache: dict[bool, tuple[float, SelfTerms]] = {}


def _term_row(r: ReportSelfTermRow) -> SelfTermRow:
    return SelfTermRow(
        kind=r.kind,  # type: ignore[arg-type]
        value=r.value,
        source=r.source,  # type: ignore[arg-type]
        distinct_sources=r.distinct_sources,
        confirmed=r.confirmed,
        last_seen=r.last_seen,
    )


def settings_incomplete_response(missing: Sequence[str]) -> JSONResponse:
    """409 naming the empty settings (field names only) so the UI can point at them."""
    return JSONResponse(
        {
            "detail": "Set a reply contact in Settings first.",
            "code": "settings_incomplete",
            "missing": list(missing),
        },
        status_code=409,
        headers={"Cache-Control": "no-store"},
    )


FRESH_SELF_ADDRESS_SQL = (
    "SELECT EXISTS (SELECT 1 FROM report_self_terms WHERE kind IN ('address', 'cidr') AND ("
    "source = 'manual' OR (last_seen >= now() - interval '72 hours' AND "
    "(source = 'sensor' OR (source = 'learned' AND confirmed)))))"
)


async def self_address_fresh(db: AsyncSession) -> bool:
    """A manual address, or a sensor-confirmed one seen in the last 72 hours."""
    try:
        return bool(await db.scalar(text(FRESH_SELF_ADDRESS_SQL)))
    except SQLAlchemyError:
        return False


def invalidate_terms() -> None:
    """Forget the cached deny set (called after any write to the self terms or settings)."""
    _terms_cache.clear()


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in TRUE_VALUES


def include_demo() -> bool:
    return env_flag("ABUSE_REPORTS_INCLUDE_DEMO", False)


async def load_terms(
    db: AsyncSession, *, fresh: bool = False, with_pseudonym: bool = True
) -> SelfTerms | None:
    """The deny set, cached for a minute. ``None`` when the table cannot be read (fail closed).

    ``with_pseudonym``: the node's network pseudonym is a deny term for what goes to abuse desks
    and CERTs (M38). It is never one where the pseudonym itself is checked or sent to the hub:
    the network routes pass False, or every pseudonym would match itself."""
    now = time.monotonic()
    cached = _terms_cache.get(with_pseudonym)
    if not fresh and cached is not None and now - cached[0] < TERMS_TTL_S:
        return cached[1]
    try:
        rows = (await db.scalars(select(ReportSelfTermRow))).all()
        gate = await db.scalar(
            select(EnrichmentStatusRow.detail).where(EnrichmentStatusRow.name == "egress")
        )
        pseudonyms: list[str] = []
        if with_pseudonym:
            pseudonyms = [
                p
                for row in (
                    await db.execute(
                        select(
                            NetworkMembershipRow.pseudonym, NetworkMembershipRow.synced_pseudonym
                        )
                    )
                ).all()
                for p in row
                if p
            ]
    except SQLAlchemyError:
        log.warning("abuse deny set unavailable")
        return None
    vpn = gate.get("egress_ip") if isinstance(gate, dict) else None
    terms = load_self_terms(
        [_term_row(r) for r in rows],
        dict(os.environ),
        vpn_exit=vpn if isinstance(vpn, str) else None,
        extra_texts=pseudonyms,
    )
    _terms_cache[with_pseudonym] = (now, terms)
    return terms


@dataclass(frozen=True)
class SettingsBundle:
    """``report_settings`` as the library wants it, plus the defaults and the row revision."""

    settings: ReportSettings
    defaults: dict[str, Any]
    revision: int
    reference_style: str = "subject"  # subject | subject_and_body | off (M26)
    digest_enabled: bool = True  # one mail per recipient per day (M38)

    @property
    def round_times(self) -> bool:
        value = self.defaults.get("round_times")
        return value if isinstance(value, bool) else env_flag("ABUSE_ROUND_TIMES", True)

    @property
    def tlp(self) -> str:
        value = self.defaults.get("tlp")
        return value if value in ("clear", "green", "amber", "red") else DEFAULT_TLP

    def option_defaults(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "defang": True,
            "include_usernames": True,
            "include_reply_contact": True,
            "show_redaction_counts": False,
        }
        for key in tuple(out):
            if isinstance(self.defaults.get(key), bool):
                out[key] = self.defaults[key]
        return out


async def load_settings(db: AsyncSession) -> SettingsBundle:
    row = await db.get(ReportSettingsRow, 1)
    if row is None:
        return SettingsBundle(ReportSettings(), {}, 0)
    return SettingsBundle(
        ReportSettings(
            reply_contact=row.reply_contact,
            signature=row.signature,
            intro=row.intro,
            outro=row.outro,
            note=row.note,
            subject_template=row.subject_template,
            xarf_user_agent=row.xarf_user_agent,
            xarf_org=row.xarf_org,
        ),
        dict(row.defaults or {}),
        row.revision,
        row.reference_style,
        row.digest_enabled,
    )


def reply_args(
    row: AbuseReportRow, bundle: SettingsBundle, *, admin: bool = True
) -> dict[str, Any]:
    """The reply token and where to print it, for every rendering that may be sent (M26).
    The token proves a reply belongs to the report: a viewer's preview or download never
    carries it."""
    if not admin:
        return {"reply_token": None, "reference_style": "off"}
    return {"reply_token": row.reply_token, "reference_style": bundle.reference_style}


def effective_options(stored: dict[str, Any] | None, bundle: SettingsBundle) -> ReportOptions:
    """Per-report options over the Settings defaults. Times are rounded unless exact is chosen."""
    data = bundle.option_defaults()
    data["time_precision"] = "minute" if bundle.round_times else "second"
    for key in OPTION_KEYS:
        if stored and key in stored:
            data[key] = stored[key]
    try:
        return ReportOptions.model_validate(data)
    except ValidationError:
        return ReportOptions()


class EvidenceInvalidError(Exception):
    """The stored evidence does not fit the model (a bug upstream; nothing is rendered)."""


SubjectKey = tuple[str, str, str]  # (kind, subject_type, value)


async def subject_rows(db: AsyncSession, report_id: int) -> list[AbuseReportSubjectRow]:
    return list(
        (
            await db.scalars(
                select(AbuseReportSubjectRow).where(AbuseReportSubjectRow.report_id == report_id)
            )
        ).all()
    )


def _with_subject_rows(
    data: dict[str, Any], report_kind: str, keys: Mapping[SubjectKey, uuid.UUID | None]
) -> dict[str, Any]:
    """The stored evidence plus each subject's kind and XARF id from its row (the row is the
    source of truth; ingest.abuse.build.with_subject_rows does the same)."""
    subjects = data.get("subjects")
    if not isinstance(subjects, list):
        return data
    out: list[Any] = []
    for item in subjects:
        if not isinstance(item, dict):
            out.append(item)
            continue
        sub = dict(item)
        if report_kind != "digest":
            sub["kind"] = report_kind
        kind = sub.get("kind")
        if sub.get("xarf_id") is None and kind is not None:
            found = keys.get((str(kind), str(sub.get("type")), str(sub.get("value"))))
            if found is not None:
                sub["xarf_id"] = str(found)
        out.append(sub)
    return {**data, "subjects": out}


def build_evidence(
    row: AbuseReportRow,
    recipient: AbuseRecipientRow,
    bundle: SettingsBundle,
    keys: Mapping[SubjectKey, uuid.UUID | None] | None = None,
) -> Evidence:
    """The evidence as the send path would render it. ``keys`` are the subject rows' XARF ids.
    For a sent or closed report only the sources that left are kept (the subject rows: an
    automatic digest leaves its old sources out). A report sent before 0040 has no XARF ids and
    is shown as "not sent with X-ARF v4" (``mail_inputs``), never with made-up ids."""
    data = _with_subject_rows(dict(row.evidence), row.kind, keys or {})
    subjects = data.get("subjects")
    if row.status not in OPEN_STATUSES and keys and isinstance(subjects, list):
        kept = [
            s
            for s in subjects
            if not isinstance(s, dict)
            or (str(s.get("kind")), str(s.get("type")), str(s.get("value"))) in keys
        ]
        if kept:
            data["subjects"] = kept
    data.update(
        kind=row.kind,
        recipient=recipient.override_mailbox or recipient.mailbox or data.get("recipient"),
        window_start=row.window_start,
        window_end=row.window_end,
        demo=row.demo,
        options=effective_options(row.options, bundle).model_dump(),
    )
    try:
        return Evidence.model_validate(data)
    except ValidationError as exc:
        raise EvidenceInvalidError from exc


async def load_evidence(
    db: AsyncSession, row: AbuseReportRow, recipient: AbuseRecipientRow, bundle: SettingsBundle
) -> Evidence:
    rows = await subject_rows(db, row.id)
    keys = {(r.kind, r.subject_type, r.value): r.xarf_id for r in rows}
    return build_evidence(row, recipient, bundle, keys)


@dataclass(frozen=True)
class MailInputs:
    """What a render of the mail needs besides the evidence (M38)."""

    sent_files: tuple[Attachment, ...] | None = None  # the XARF JSON that left (sent reports)
    legacy: bool = False  # sent before 0040: no XARF v4 left with it


def _hide_id(content: str) -> str:
    """A stored XARF report with its ``report_id`` replaced by a random one (viewers)."""
    try:
        report = json.loads(content)
    except ValueError:
        return content
    if isinstance(report, dict) and "report_id" in report:
        report["report_id"] = str(uuid.uuid4())
    return xarf_dumps(report)


def mail_inputs(
    row: AbuseReportRow, evidence: Evidence, *, admin: bool
) -> tuple[Evidence, MailInputs]:
    """The evidence and inputs of a mail render. For a sent report, the XARF files that left
    (``abuse_reports.sent_xarf``) replace freshly rendered ones; a report sent before 0040 has
    none. A viewer never sees a real XARF ``report_id``: a reply quoting one is matched to its
    report, so it is a proof like the reply token (``reply_args``)."""
    sent: tuple[Attachment, ...] | None = None
    stored = row.sent_xarf if isinstance(row.sent_xarf, list) else None
    if stored:
        sent = tuple(
            Attachment(str(f.get("name")), JSON_TYPE, str(f.get("content")))
            for f in stored
            if isinstance(f, dict)
        )
    legacy = (
        row.status not in OPEN_STATUSES
        and sent is None
        and any(s.xarf_id is None for s in evidence.subjects)
    )
    if not admin:
        evidence = evidence.model_copy(
            update={
                "subjects": tuple(
                    s.model_copy(update={"xarf_id": uuid.uuid4()}) if s.xarf_id else s
                    for s in evidence.subjects
                )
            }
        )
        if sent is not None:
            sent = tuple(Attachment(a.name, a.media_type, _hide_id(a.content)) for a in sent)
    return evidence, MailInputs(sent, legacy)


def _with_sent_files(msg: RenderedMessage, files: tuple[Attachment, ...]) -> RenderedMessage:
    """The rendered mail with the XARF files that actually left."""
    others = tuple(a for a in msg.attachments if a.media_type != JSON_TYPE)
    attachments = (*files, *others) if msg.layout == "report" else (*others, *files)
    return replace(msg, attachments=attachments)


async def guard_context(db: AsyncSession, row: AbuseReportRow, evidence: Evidence) -> GuardContext:
    """Internal identifiers that must not appear: the report's own session ids and its seed.

    The sessions are a superset of what the draft builder read (ingest.abuse.session_ids does the
    same on the ingest side): the sessions of the source addresses that were active since
    ``CONTEXT_LOOKBACK`` before the window, and for a payload host the sessions that named it."""
    ips = [s.value for s in evidence.subjects if s.type == "ip"]
    ids: set[str] = {row.id_seed.hex}  # the seed never leaves, and no token is built from it
    since = evidence.window_start - CONTEXT_LOOKBACK
    if ips:
        found = await db.scalars(
            select(SessionRow.session_id)
            .where(SessionRow.src_ip.in_(ips), SessionRow.last_event_at >= since)
            .order_by(SessionRow.last_event_at.desc())
            .limit(MAX_CONTEXT_SESSIONS)
        )
        ids.update(found.all())
    hosts = [s.value for s in evidence.subjects if evidence.kind_of(s) == "payload_host"]
    if hosts:
        named = await db.scalars(
            select(IndicatorSessionRow.session_id)
            .join(IndicatorRow, IndicatorRow.id == IndicatorSessionRow.indicator_id)
            .where(
                IndicatorRow.role == "download_host",
                IndicatorRow.host.in_(hosts),
                IndicatorSessionRow.seen_at >= since,
            )
            .group_by(IndicatorSessionRow.session_id)
            .order_by(func.max(IndicatorSessionRow.seen_at).desc())
            .limit(MAX_CONTEXT_SESSIONS)
        )
        ids.update(named.all())
    return GuardContext(internal_ids=frozenset(ids), allow_documentation=row.demo)


@dataclass(frozen=True)
class Rendered:
    message: RenderedMessage
    eml: bytes | None
    guard: GuardResult


def _text_message(
    evidence: Evidence,
    settings: ReportSettings,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
) -> RenderedMessage:
    body = render_text(evidence, settings, reply_token=reply_token, reference_style=reference_style)
    return replace(body, attachments=(render_csv(evidence),))


def render_checked(
    evidence: Evidence,
    settings: ReportSettings,
    terms: SelfTerms | None,
    ctx: GuardContext,
    fmt: str,
    subject: str | None = None,
    *,
    reply_token: str | None = None,
    reference_style: str = "subject",
    inputs: MailInputs | None = None,
) -> Rendered:
    """Render one format and run the guard on everything produced. Pure, so it runs in a thread.

    The caller decides what to do with a failed ``guard`` (``require_ok``): nothing is released.
    """
    eml: bytes | None = None
    style: ReferenceStyle = reference_style if reference_style in REFERENCE_STYLES else "subject"  # type: ignore[assignment]
    del subject  # every source has its own XARF file now (M38); kept for the callers
    if fmt == "text":
        msg = _text_message(evidence, settings, reply_token, style)
    elif fmt in ("xarf", "eml"):
        extra = inputs or MailInputs()
        if extra.legacy:
            # Sent before 0040: no XARF v4 left with it, and none is made up now.
            if fmt == "xarf":
                raise RenderUnavailable("not_sent_with_xarf_v4")
            msg = _text_message(evidence, settings, reply_token, style)
        else:
            # The mail exactly as SMTP sends it: text, evidence.csv and one XARF JSON per source.
            msg = render_mail(evidence, settings, reply_token=reply_token, reference_style=style)
            if extra.sent_files:
                msg = _with_sent_files(msg, extra.sent_files)
        if fmt == "eml":
            eml = render_eml(msg)
    else:
        raise RenderUnavailable("unknown_format")
    result = guard_message(msg, terms, ctx=ctx)
    if eml is not None:
        result = result.merge(guard(eml, terms, fmt="eml", ctx=ctx))
    return Rendered(msg, eml, result)


def missing_for(settings: ReportSettings, *, xarf: bool = False) -> tuple[str, ...]:
    return missing_settings(settings, xarf=xarf)


def release(result: GuardResult) -> None:
    """Raise ``GuardFailed`` (codes only) unless the guard passed."""
    require_ok(result)


def guard_failed_response(codes: tuple[str, ...]) -> JSONResponse:
    """409 with reason codes only. The matched value never reaches the answer."""
    return JSONResponse(
        {
            "detail": "The identity check blocked this content.",
            "code": "identity_guard_failed",
            "reasons": sorted(set(codes)),
        },
        status_code=409,
        headers={"Cache-Control": "no-store"},
    )


def settings_issues(
    values: Mapping[str, str | None], terms: SelfTerms | None
) -> dict[str, list[str]]:
    """Field by field, the guard codes the owner's own wording raises (codes only, never text).

    Anything listed here would block every report written with these settings. The monitored
    address may be unknown yet (``no_self_address``): that is not the wording's fault, so it is
    left out and the settings stay savable.
    """
    issues: dict[str, list[str]] = {}
    for name in SETTINGS_TEXT_FIELDS:
        value = values.get(name)
        if not value:
            continue
        codes = sorted(set(guard(value, terms, fmt="text").codes) - {"no_self_address"})
        if codes:
            issues[name] = codes
    return issues


def settings_guard_failed_response(issues: Mapping[str, Sequence[str]]) -> JSONResponse:
    """409 for a refused settings save: reason codes per field name, never the matched text."""
    fields = {name: sorted(set(codes)) for name, codes in issues.items()}
    return JSONResponse(
        {
            "detail": "These settings would block every report, so they were not saved.",
            "code": "identity_guard_failed",
            "reasons": sorted({c for codes in fields.values() for c in codes}),
            "fields": fields,
        },
        status_code=409,
        headers={"Cache-Control": "no-store"},
    )


def error(status: int, detail: str, code: str) -> JSONResponse:
    return JSONResponse({"detail": detail, "code": code}, status_code=status)


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
