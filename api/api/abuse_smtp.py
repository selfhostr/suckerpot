"""Optional SMTP sending of abuse reports (M25): the profile, the send queue, send and cancel.

The API never talks SMTP (it has no route out). It stores the profile, writes
``abuse_send_requests`` rows, and ingest answers them. The password is AES-GCM ciphertext
(``suckerpot_db.secretbox``): this role may write it but its column grants cannot read it back,
and no answer, log line or audit row ever carries it, nor a message body.

Every route is administrator only (GET included: the profile holds the owner's sender address).
Writes ask for the account password again. Anything that names the owner is refused by the same
identity guard as the reports.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.locks import ABUSE_SMTP_PROFILE
from suckerpot_db.models import (
    AbuseRecipientRow,
    AbuseReportRow,
    AbuseSendRequestRow,
    ReportSettingsRow,
    ReportSmtpRow,
)
from suckerpot_db.secretbox import Credential, SecretBox
from suckerpot_reporting import GuardFailed, RenderUnavailable, guard

from api import audit as audit_db
from api import reauth
from api.abuse_core import (
    SettingsBundle,
    error,
    guard_context,
    guard_failed_response,
    load_evidence,
    load_settings,
    load_terms,
    missing_for,
    release,
    render_checked,
    reply_args,
    settings_incomplete_response,
)
from api.auth import Principal, current_principal
from api.authz import require_admin
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

router = APIRouter(tags=["abuse"], dependencies=[Depends(require_admin)])
log = logging.getLogger("api.abuse")

PASSWORD_AAD = "report_smtp"  # noqa: S105 - a label, not a secret; bound to the ciphertext; ingest decrypts with the same value
QUEUE_MAX = 25
FORBIDDEN_SUFFIXES = (
    "local", "internal", "lan", "localhost", "localdomain", "home", "corp", "intranet",
    "private", "arpa", "invalid",
)  # fmt: skip
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
_TLD = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9\-]{1,59})$")
_MAILBOX = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")
_NAME = re.compile(r"^[A-Za-z0-9 .,'()_\-]{0,100}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

PROFILE_LOCK_TIMEOUT = "70s"  # a send ends within 60 s
OPEN = ("pending", "sending")  # a request that has not finished
SmtpMode = Literal["off", "click", "auto"]
Security = Literal["starttls", "ssl"]


# ---- shapes --------------------------------------------------------------------------------


class RequestState(BaseModel):
    status: str
    error_code: str | None = None
    requested_at: datetime | None = None
    done_at: datetime | None = None


class SmtpOut(BaseModel):
    configured: bool
    password_set: bool
    host: str
    port: int
    security: Security
    username: str
    from_address: str
    from_name: str
    mode: SmtpMode
    auto_hold_minutes: int
    daily_cap: int
    sent_today: int
    last_test: RequestState | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None
    digest_minute: int | None = None  # minutes after 00:00 UTC (M38); None before the first save


class SmtpBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    security: Security
    username: str = Field(default="", max_length=254)
    from_address: str = Field(min_length=3, max_length=254)
    from_name: str = Field(default="", max_length=100)
    # The SMTP password: omitted keeps the stored one; the first save needs one.
    password: str | None = Field(default=None, max_length=256, repr=False)
    mode: SmtpMode = "off"
    auto_hold_minutes: int = Field(default=60, ge=10, le=1440)
    daily_cap: int = Field(default=20, ge=1, le=200)
    # The digest hour (M38), minutes after 00:00 UTC. Omitted keeps the stored one (a first save
    # gets a random minute between 06:00 and 09:00 UTC from the database).
    digest_minute: int | None = Field(default=None, ge=0, le=1439)
    current_password: str = Field(max_length=1024, repr=False)  # re-authentication


class PasswordBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(max_length=1024, repr=False)  # re-authentication


class SendBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int | None = Field(default=None, ge=1)
    # M38: a second mail to the same provider on the same UTC day needs this confirmation.
    confirm_same_day: bool = False


class DigestOut(BaseModel):
    """One mail per provider per day (M38): the switch and the digest hour."""

    enabled: bool
    minute: int | None  # minutes after 00:00 UTC; None while there is no SMTP profile


class DigestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    minute: int | None = Field(default=None, ge=0, le=1439)  # omitted keeps the stored one


class Accepted(BaseModel):
    id: int
    status: str = "pending"
    scheduled_at: datetime | None = None


class Cancelled(BaseModel):
    cancelled: int


class SendState(BaseModel):
    """Where a report stands in the send queue (also part of the report detail)."""

    scheduled_at: datetime | None = None
    last_request: RequestState | None = None


class QueueItem(BaseModel):
    id: uuid.UUID
    recipient: str
    subject: str
    body_text: str
    scheduled_at: datetime | None = None
    last_request: RequestState | None = None


class QueuePage(BaseModel):
    items: list[QueueItem]
    next_cursor: str | None = None
    mode: SmtpMode
    missing: list[str] = []


# ---- validation ----------------------------------------------------------------------------


def valid_host(value: str) -> bool:
    """A public DNS name: not an IP literal (any notation), not a single label, not an internal
    suffix. The proxy refuses private answers too; this is the first, readable line."""
    host = value.strip().lower().rstrip(".")
    if not host or len(host) > 253 or host != value.strip().lower():
        return False
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        return False
    if not _TLD.match(labels[-1]):
        return False  # an all-digit or hex-like last label is an IP in disguise
    return labels[-1] not in FORBIDDEN_SUFFIXES and ".".join(labels[-2:]) != "home.arpa"


def valid_mailbox(value: str) -> bool:
    return bool(_MAILBOX.match(value)) and valid_host(value.rpartition("@")[2])


def _refuse(status: int, detail: str, code: str) -> Response:
    return error(status, detail, code)


def _guard_failed_422(codes: set[str]) -> JSONResponse:
    return JSONResponse(
        {
            "detail": "The identity check blocked this value.",
            "code": "identity_guard_failed",
            "reasons": sorted(codes),
        },
        status_code=422,
        headers={"Cache-Control": "no-store"},
    )


# ---- helpers -------------------------------------------------------------------------------


def _actor(principal: Principal | None) -> str:
    return principal.username if principal else "anonymous"


def _client_ip(request: Request) -> str | None:
    return request.app.state.auth.client_ip(request)  # type: ignore[no-any-return]


def _state(row: Any) -> RequestState:
    return RequestState(
        status=row.status,
        error_code=row.error_code,
        requested_at=row.requested_at,
        done_at=row.done_at,
    )


_PROFILE_COLUMNS = (
    ReportSmtpRow.host,
    ReportSmtpRow.port,
    ReportSmtpRow.security,
    ReportSmtpRow.username,
    ReportSmtpRow.from_address,
    ReportSmtpRow.from_name,
    ReportSmtpRow.mode,
    ReportSmtpRow.auto_hold_minutes,
    ReportSmtpRow.daily_cap,
    ReportSmtpRow.password_set,
    ReportSmtpRow.updated_at,
    ReportSmtpRow.updated_by,
    ReportSmtpRow.digest_minute,
)


@dataclass(frozen=True)
class Profile:
    host: str
    port: int
    security: str
    username: str
    from_address: str
    from_name: str
    mode: str
    auto_hold_minutes: int
    daily_cap: int
    password_set: bool
    updated_at: datetime
    updated_by: str | None
    digest_minute: int = 420

    @property
    def configured(self) -> bool:
        return bool(self.host and self.from_address) and (self.password_set or not self.username)


async def load_profile(db: AsyncSession) -> Profile | None:
    """Everything but the password (the role cannot read it)."""
    row = (await db.execute(select(*_PROFILE_COLUMNS).where(ReportSmtpRow.id == 1))).first()
    # Same values; mypy cannot spread SQLAlchemy 2.1's variadic Row type into the dataclass.
    return None if row is None else Profile(*tuple(row))


SENT_TODAY_SQL = (
    "SELECT count(*) FROM abuse_send_requests WHERE kind = 'send' AND status = 'sent' "
    "AND done_at >= (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')"
)


async def sent_today(db: AsyncSession) -> int:
    return int(await db.scalar(text(SENT_TODAY_SQL)) or 0)


async def _lock_profile(db: AsyncSession) -> bool:
    """Wait for a report mail in flight (ingest holds this lock shared while it sends)."""
    await db.execute(text(f"SET LOCAL lock_timeout = '{PROFILE_LOCK_TIMEOUT}'"))
    try:
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ABUSE_SMTP_PROFILE})
    except DBAPIError:
        await db.rollback()
        return False
    return True


async def _profile_out(db: AsyncSession) -> SmtpOut:
    profile = await load_profile(db)
    last = (
        await db.execute(
            select(AbuseSendRequestRow)
            .where(AbuseSendRequestRow.kind == "test")
            .order_by(AbuseSendRequestRow.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    last_test = _state(last) if last is not None else None
    count = await sent_today(db)
    if profile is None:
        return SmtpOut(
            configured=False, password_set=False, host="", port=587, security="starttls",
            username="", from_address="", from_name="", mode="off", auto_hold_minutes=60,
            daily_cap=20, sent_today=count, last_test=last_test,
        )  # fmt: skip
    return SmtpOut(
        configured=profile.configured,
        password_set=profile.password_set,
        host=profile.host,
        port=profile.port,
        security=profile.security,  # type: ignore[arg-type]
        username=profile.username,
        from_address=profile.from_address,
        from_name=profile.from_name,
        mode=profile.mode,  # type: ignore[arg-type]
        auto_hold_minutes=profile.auto_hold_minutes,
        daily_cap=profile.daily_cap,
        sent_today=count,
        last_test=last_test,
        updated_at=profile.updated_at,
        updated_by=profile.updated_by,
        digest_minute=profile.digest_minute,
    )


def _no_store(model: BaseModel, status: int = 200) -> Response:
    return JSONResponse(
        model.model_dump(mode="json"), status_code=status, headers={"Cache-Control": "no-store"}
    )


# ---- the profile ---------------------------------------------------------------------------


@router.get("/abuse/smtp", response_model=SmtpOut)
async def get_smtp(db: DbSession) -> Response:
    return _no_store(await _profile_out(db))


@router.put("/abuse/smtp", response_model=SmtpOut)
async def put_smtp(body: SmtpBody, request: Request, db: DbSession) -> Response:
    host = body.host.strip().lower()
    if not valid_host(host):
        return _refuse(
            422, "Use the server's DNS name (no address, no internal name).", "invalid_host"
        )
    address = body.from_address.strip()
    if not valid_mailbox(address):
        return _refuse(422, "The sender address is not valid.", "invalid_from_address")
    name = body.from_name.strip()
    if not _NAME.fullmatch(name):
        return _refuse(
            422, "The sender name has characters that are not allowed.", "invalid_from_name"
        )
    username = body.username.strip()
    if _CTRL.search(username) or (body.password and _CTRL.search(body.password)):
        return _refuse(422, "Control characters are not allowed.", "invalid_credentials")
    # The identity guard on what appears in the From header (no_self_address is not a reason to
    # refuse a profile: the monitored address may still be unknown; sending re-checks).
    terms = await load_terms(db)
    codes: set[str] = set()
    for value in (name, address):
        if value:
            codes |= set(guard(value, terms, fmt="text").codes) - {"no_self_address"}
    if codes:
        return _guard_failed_422(codes)
    old = await load_profile(db)
    if body.password:
        box: SecretBox | None = request.app.state.secret_box
        if box is None:
            reason: str = request.app.state.secret_box_reason or "Password storage is disabled."
            return _refuse(503, reason, "editing_disabled")
    keeps = body.password is None and old is not None and old.password_set
    has_password = bool(body.password) or keeps
    if not has_password:
        return _refuse(422, "Enter the SMTP password.", "password_required")
    principal, refused = await reauth.guard(request, body.current_password, "smtp profile change")
    if refused is not None:
        return refused
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "host": host,
        "port": body.port,
        "security": body.security,
        "username": username,
        "from_address": address,
        "from_name": name,
        "mode": body.mode,
        "auto_hold_minutes": body.auto_hold_minutes,
        "daily_cap": body.daily_cap,
        "updated_at": now,
        "updated_by": _actor(principal)[:120],
    }
    changed = [
        k
        for k in ("host", "port", "security", "username", "from_address", "from_name", "mode",
                  "auto_hold_minutes", "daily_cap")
        if old is None or getattr(old, k) != values[k]
    ]  # fmt: skip
    if body.digest_minute is not None:
        values["digest_minute"] = body.digest_minute
        if old is None or old.digest_minute != body.digest_minute:
            changed.append("digest_minute")
    if body.password:
        box = request.app.state.secret_box
        ciphertext, nonce = box.encrypt(PASSWORD_AAD, Credential(key=body.password))
        values |= {"password_ciphertext": ciphertext, "password_nonce": nonce}
        changed.append("password")
    if not await _lock_profile(db):
        return _refuse(
            409, "A report is being sent right now. Try again in a minute.", "already_sending"
        )
    if old is None:
        await db.execute(insert(ReportSmtpRow).values(id=1, **values))
    else:
        await db.execute(update(ReportSmtpRow).where(ReportSmtpRow.id == 1).values(**values))
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.smtp.update",
        ip=_client_ip(request),
        details={"changed": changed, "mode": body.mode},  # names only, never values
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(await _profile_out(db))


@router.delete("/abuse/smtp", status_code=204)
async def delete_smtp(body: PasswordBody, request: Request, db: DbSession) -> Response:
    principal, refused = await reauth.guard(request, body.current_password, "smtp profile removal")
    if refused is not None:
        return refused
    if not await _lock_profile(db):
        return _refuse(
            409, "A report is being sent right now. Try again in a minute.", "already_sending"
        )
    await db.execute(delete(ReportSmtpRow).where(ReportSmtpRow.id == 1))
    # Nothing may leave after the profile is gone.
    await db.execute(
        update(AbuseSendRequestRow)
        .where(AbuseSendRequestRow.status == "pending")
        .values(status="cancelled")
    )
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.smtp.delete",
        ip=_client_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Response(status_code=204)


@router.post("/abuse/smtp/test", status_code=202, response_model=Accepted)
async def test_smtp(body: PasswordBody, request: Request, db: DbSession) -> Response:
    """Queue a short neutral message to the sender address itself. Ingest sends it."""
    profile = await load_profile(db)
    if profile is None or not profile.configured:
        return _refuse(409, "Save the SMTP settings first.", "smtp_not_configured")
    busy = await db.scalar(
        select(func.count())
        .select_from(AbuseSendRequestRow)
        .where(AbuseSendRequestRow.kind == "test", AbuseSendRequestRow.status.in_(OPEN))
    )
    if busy:
        return _refuse(409, "A test is already waiting to be sent.", "already_queued")
    principal, refused = await reauth.guard(request, body.current_password, "smtp test")
    if refused is not None:
        return refused
    new = AbuseSendRequestRow(kind="test", requested_by=_actor(principal)[:120])
    db.add(new)
    await db.flush()
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.smtp.test",
        ip=_client_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(Accepted(id=new.id), 202)


# ---- send and cancel -----------------------------------------------------------------------


async def _report(
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


def _mailbox(rec: AbuseRecipientRow) -> str | None:
    return (rec.override_mailbox or rec.mailbox) or None


def is_candidate(row: AbuseReportRow, rec: AbuseRecipientRow) -> str | None:
    """Why a report can never be sent right now (a code), or None. The live guard comes after."""
    if row.demo:
        return "demo_report"
    if row.status not in ("draft", "reviewed") or rec.muted or not _mailbox(rec):
        return "report_not_ready"
    if not row.guard_ok:
        return "identity_guard_failed"
    return None


async def _live(
    db: AsyncSession, row: AbuseReportRow, rec: AbuseRecipientRow, bundle: SettingsBundle, fmt: str
) -> Any:
    """Render and guard like a download would. Raises GuardFailed, RenderUnavailable."""
    evidence = await load_evidence(db, row, rec, bundle)
    ctx = await guard_context(db, row, evidence)
    terms = await load_terms(db)
    rendered = await asyncio.to_thread(
        render_checked,
        evidence,
        bundle.settings,
        terms,
        ctx,
        fmt,
        **reply_args(row, bundle),
    )
    release(rendered.guard)
    return rendered


@router.post("/abuse/reports/{public_id}/send", status_code=202, response_model=Accepted)
async def send_report(
    public_id: uuid.UUID, request: Request, db: DbSession, body: SendBody | None = None
) -> Response:
    loaded = await _report(db, public_id)
    if loaded is None:
        return _refuse(404, "Report not found.", "not_found")
    row, rec = loaded
    profile = await load_profile(db)
    if profile is None or not profile.configured:
        return _refuse(409, "SMTP sending is not set up.", "smtp_not_configured")
    if profile.mode not in ("click", "auto"):
        return _refuse(409, "Sending is switched off in Settings.", "smtp_off")
    if body is not None and body.revision is not None and body.revision != row.revision:
        return _refuse(409, "The draft changed while you were reading it.", "revision_mismatch")
    blocked = is_candidate(row, rec)
    if blocked == "identity_guard_failed":
        return guard_failed_response(tuple(row.guard_codes))
    if blocked is not None:
        detail = (
            "A demo report cannot be sent."
            if blocked == "demo_report"
            else ("This report is not ready to be sent.")
        )
        return _refuse(409, detail, blocked)
    if await db.scalar(
        select(func.count())
        .select_from(AbuseSendRequestRow)
        .where(AbuseSendRequestRow.report_id == row.id, AbuseSendRequestRow.status.in_(OPEN))
    ):
        return _refuse(409, "This report is already waiting to be sent.", "already_queued")
    if not (body is not None and body.confirm_same_day) and await sent_to_recipient_today(
        db, row, rec
    ):
        return same_day_response()
    bundle = await load_settings(db)
    missing = missing_for(bundle.settings)
    if missing:
        return settings_incomplete_response(missing)
    try:
        await _live(db, row, rec, bundle, "eml")
    except GuardFailed as exc:
        return guard_failed_response(exc.codes)
    except RenderUnavailable as exc:
        if exc.code == "settings_incomplete":
            return settings_incomplete_response(missing_for(bundle.settings))
        return _refuse(409, "This report cannot be rendered.", exc.code)
    except Exception:
        return _refuse(409, "The stored evidence is not valid.", "evidence_invalid")
    principal = await current_principal(request)
    new = AbuseSendRequestRow(report_id=row.id, kind="send", requested_by=_actor(principal)[:120])
    db.add(new)
    await db.flush()
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.send",
        target=str(row.public_id),
        ip=_client_ip(request),
        details={"mode": profile.mode},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(Accepted(id=new.id), 202)


@router.post("/abuse/reports/{public_id}/send/cancel", response_model=Cancelled)
async def cancel_send(public_id: uuid.UUID, request: Request, db: DbSession) -> Response:
    loaded = await _report(db, public_id)
    if loaded is None:
        return _refuse(404, "Report not found.", "not_found")
    row = loaded[0]
    # Only a request nobody started can be cancelled: ingest marks it ``sending`` (committed)
    # before it connects, and from then on the mail may be on the wire.
    await db.execute(text("SET LOCAL lock_timeout = '2s'"))
    try:
        res = await db.execute(
            update(AbuseSendRequestRow)
            .where(AbuseSendRequestRow.report_id == row.id, AbuseSendRequestRow.status == "pending")
            .values(status="cancelled")
        )
    except DBAPIError:
        await db.rollback()
        return _refuse(409, "The report is being sent right now.", "already_sending")
    count = int(res.rowcount or 0)  # type: ignore[attr-defined]
    if count == 0:
        if await db.scalar(
            select(func.count())
            .select_from(AbuseSendRequestRow)
            .where(AbuseSendRequestRow.report_id == row.id, AbuseSendRequestRow.status == "sending")
        ):
            await db.rollback()
            return _refuse(409, "The report is being sent right now.", "already_sending")
        await db.rollback()
        return _refuse(409, "Nothing is waiting to be sent for this report.", "nothing_to_cancel")
    principal = await current_principal(request)
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.send.cancel",
        target=str(row.public_id),
        ip=_client_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(Cancelled(cancelled=count))


# ---- one mail per provider per day (M38) ----------------------------------------------------


SENT_TO_RECIPIENT_TODAY = (
    "SELECT EXISTS (SELECT 1 FROM abuse_reports r JOIN abuse_recipients c "
    "ON c.id = r.recipient_id WHERE r.status IN ('sent', 'closed') AND NOT r.demo "
    "AND r.id <> :i AND r.sent_at >= (date_trunc('day', now() AT TIME ZONE 'UTC') "
    "AT TIME ZONE 'UTC') AND COALESCE(NULLIF(c.override_mailbox, ''), c.mailbox) = :a)"
)


async def sent_to_recipient_today(
    db: AsyncSession, row: AbuseReportRow, rec: AbuseRecipientRow
) -> bool:
    """Another report already went to this provider's address today (UTC)."""
    address = _mailbox(rec)
    if not address:
        return False
    return bool(await db.scalar(text(SENT_TO_RECIPIENT_TODAY), {"i": row.id, "a": address}))


def same_day_response() -> JSONResponse:
    return JSONResponse(
        {
            "detail": "This provider already got a report today.",
            "code": "recipient_sent_today",
        },
        status_code=409,
        headers={"Cache-Control": "no-store"},
    )


async def _digest_out(db: AsyncSession) -> DigestOut:
    bundle = await load_settings(db)
    profile = await load_profile(db)
    return DigestOut(
        enabled=bundle.digest_enabled,
        minute=profile.digest_minute if profile is not None else None,
    )


@router.get("/abuse/digest", response_model=DigestOut)
async def get_digest(db: DbSession) -> Response:
    return _no_store(await _digest_out(db))


@router.put("/abuse/digest", response_model=DigestOut)
async def put_digest(body: DigestBody, request: Request, db: DbSession) -> Response:
    """Switch daily digests and move the digest hour. The hour lives with the SMTP profile."""
    profile = await load_profile(db)
    if body.minute is not None and profile is None:
        return _refuse(409, "Set up SMTP sending first.", "smtp_not_configured")
    changed: list[str] = []
    bundle = await load_settings(db)
    if bundle.digest_enabled != body.enabled:
        res = await db.execute(
            update(ReportSettingsRow)
            .where(ReportSettingsRow.id == 1)
            .values(
                digest_enabled=body.enabled,
                revision=ReportSettingsRow.revision + 1,
                updated_at=datetime.now(UTC),
            )
        )
        if not res.rowcount:  # type: ignore[attr-defined]
            db.add(ReportSettingsRow(id=1, digest_enabled=body.enabled))
        changed.append("enabled")
    if body.minute is not None and profile is not None and profile.digest_minute != body.minute:
        if not await _lock_profile(db):
            return _refuse(
                409, "A report is being sent right now. Try again in a minute.", "already_sending"
            )
        await db.execute(
            update(ReportSmtpRow).where(ReportSmtpRow.id == 1).values(digest_minute=body.minute)
        )
        changed.append("minute")
    if changed:
        principal = await current_principal(request)
        await audit_db.record(
            db,
            actor=_actor(principal),
            action="abuse.digest",
            ip=_client_ip(request),
            details={"changed": changed, "enabled": body.enabled},
            actor_id=audit_db.actor_id_of(principal),
        )
        await db.commit()
    return _no_store(await _digest_out(db))


# ---- the queue -----------------------------------------------------------------------------


@router.get("/abuse/send-queue", response_model=QueuePage)
async def send_queue(
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=QUEUE_MAX)] = 10,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> Response:
    """Ready reports, oldest first, one page at a time. A report is ready when it is a draft or
    reviewed, not a demo, its recipient is known and the identity guard passes right now. The
    plain-text body is guarded like a download; a report that fails is left out."""
    after = 0
    if cursor:
        try:
            values = decode_cursor(cursor)
            if len(values) != 1 or not isinstance(values[0], int):
                raise InvalidCursorError("malformed cursor")
            after = values[0]
        except InvalidCursorError:
            return _refuse(400, "Invalid cursor.", "invalid_cursor")
    profile = await load_profile(db)
    mode: SmtpMode = profile.mode if profile is not None else "off"  # type: ignore[assignment]
    bundle = await load_settings(db)
    missing = list(missing_for(bundle.settings))
    if missing:
        return _no_store(QueuePage(items=[], mode=mode, missing=missing))
    found = (
        await db.execute(
            select(AbuseReportRow, AbuseRecipientRow)
            .join(AbuseRecipientRow, AbuseRecipientRow.id == AbuseReportRow.recipient_id)
            .where(
                AbuseReportRow.status.in_(("draft", "reviewed")),
                AbuseReportRow.demo.is_(False),
                AbuseReportRow.guard_ok.is_(True),
                AbuseRecipientRow.muted.is_(False),
                AbuseReportRow.id > after,
            )
            .order_by(AbuseReportRow.id)
            .limit(limit + 1)
        )
    ).all()
    more = len(found) > limit
    page = found[:limit]
    states = await _latest_requests(db, [r.id for r, _ in page])
    items: list[QueueItem] = []
    for row, rec in page:
        mailbox = _mailbox(rec)
        if not mailbox:
            continue
        try:
            rendered = await _live(db, row, rec, bundle, "text")
        except Exception as exc:  # guard failure, unusable evidence: not ready, so not listed
            log.info("send queue skips report %s (%s)", row.id, type(exc).__name__)
            continue
        msg = rendered.message
        state = states.get(row.id)
        items.append(
            QueueItem(
                id=row.public_id,
                recipient=msg.to,
                subject=msg.subject,
                body_text=msg.body,
                scheduled_at=state[1] if state else None,
                last_request=state[0] if state else None,
            )
        )
    nxt = encode_cursor([page[-1][0].id]) if more and page else None
    return _no_store(QueuePage(items=items, next_cursor=nxt, mode=mode))


async def _latest_requests(
    db: AsyncSession, ids: list[int]
) -> dict[int, tuple[RequestState, datetime | None]]:
    if not ids:
        return {}
    rows = (
        await db.execute(
            text(
                "SELECT DISTINCT ON (report_id) report_id, status, error_code, requested_at, "
                "done_at, scheduled_at FROM abuse_send_requests WHERE report_id = ANY(:ids) "
                "ORDER BY report_id, id DESC"
            ),
            {"ids": ids},
        )
    ).all()
    return {
        r.report_id: (_state(r), r.scheduled_at if r.status == "pending" else None) for r in rows
    }


async def send_state(db: AsyncSession, report_id: int) -> SendState:
    state = (await _latest_requests(db, [report_id])).get(report_id)
    return SendState(
        scheduled_at=state[1] if state else None, last_request=state[0] if state else None
    )
