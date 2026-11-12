"""Shared pieces of the abuse-report routes (M22): the deny set, settings, evidence and rendering.

Nothing here sends anything. Every artefact that leaves the API passes the identity guard of
``suckerpot_reporting`` immediately before it is returned, and a failure carries reason codes
only: never the matched text, never in an answer, a log line or an audit row.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Final

from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import (
    AbuseRecipientRow,
    AbuseReportRow,
    EnrichmentStatusRow,
    ReportSelfTermRow,
    ReportSettingsRow,
    SessionRow,
)
from suckerpot_reporting import (
    REFERENCE_STYLES,
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
    render_text,
    render_xarf,
    require_ok,
)

log = logging.getLogger("api.abuse")

TERMS_TTL_S: Final = 60.0
MAX_CONTEXT_SESSIONS: Final = 5000
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
)

_terms_cache: tuple[float, SelfTerms] | None = None


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
    global _terms_cache
    _terms_cache = None


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in TRUE_VALUES


def include_demo() -> bool:
    return env_flag("ABUSE_REPORTS_INCLUDE_DEMO", False)


async def load_terms(db: AsyncSession, *, fresh: bool = False) -> SelfTerms | None:
    """The deny set, cached for a minute. ``None`` when the table cannot be read (fail closed)."""
    global _terms_cache
    now = time.monotonic()
    if not fresh and _terms_cache is not None and now - _terms_cache[0] < TERMS_TTL_S:
        return _terms_cache[1]
    try:
        rows = (await db.scalars(select(ReportSelfTermRow))).all()
        gate = await db.scalar(
            select(EnrichmentStatusRow.detail).where(EnrichmentStatusRow.name == "egress")
        )
    except SQLAlchemyError:
        log.warning("abuse deny set unavailable")
        return None
    vpn = gate.get("egress_ip") if isinstance(gate, dict) else None
    terms = load_self_terms(
        [_term_row(r) for r in rows],
        dict(os.environ),
        vpn_exit=vpn if isinstance(vpn, str) else None,
    )
    _terms_cache = (now, terms)
    return terms


@dataclass(frozen=True)
class SettingsBundle:
    """``report_settings`` as the library wants it, plus the defaults and the row revision."""

    settings: ReportSettings
    defaults: dict[str, Any]
    revision: int
    reference_style: str = "subject"  # subject | subject_and_body | off (M26)

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
        ),
        dict(row.defaults or {}),
        row.revision,
        row.reference_style,
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


def build_evidence(
    row: AbuseReportRow, recipient: AbuseRecipientRow, bundle: SettingsBundle
) -> Evidence:
    data = dict(row.evidence)
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


async def guard_context(db: AsyncSession, row: AbuseReportRow, evidence: Evidence) -> GuardContext:
    """Internal identifiers that must not appear: the report's own session ids and its seed."""
    ips = [s.value for s in evidence.subjects if s.type == "ip"]
    ids: set[str] = {row.id_seed.hex}  # the seed never leaves, and no token is built from it
    if ips:
        found = await db.scalars(
            select(SessionRow.session_id)
            .where(
                SessionRow.src_ip.in_(ips),
                SessionRow.started_at >= evidence.window_start,
                SessionRow.started_at <= evidence.window_end,
            )
            .limit(MAX_CONTEXT_SESSIONS)
        )
        ids.update(found.all())
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
) -> Rendered:
    """Render one format and run the guard on everything produced. Pure, so it runs in a thread.

    The caller decides what to do with a failed ``guard`` (``require_ok``): nothing is released.
    """
    eml: bytes | None = None
    style: ReferenceStyle = reference_style if reference_style in REFERENCE_STYLES else "subject"  # type: ignore[assignment]
    if fmt == "text":
        msg = _text_message(evidence, settings, reply_token, style)
    elif fmt == "xarf":
        msg = render_xarf(
            evidence, settings, subject=subject, reply_token=reply_token, reference_style=style
        )
    elif fmt == "eml":
        try:
            msg = render_xarf(
                evidence, settings, subject=subject, reply_token=reply_token, reference_style=style
            )
        except RenderUnavailable:
            msg = _text_message(evidence, settings, reply_token, style)
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
