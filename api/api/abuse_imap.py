"""The mailbox that receives replies to abuse reports (M26): the profile and its requests.

The API never talks IMAP (it has no route out). It stores the profile, and writes "Test
connection" and "Check now" requests that ingest answers. The password is AES-GCM ciphertext
(``suckerpot_db.secretbox``): this role may write it but its column grants cannot read it back,
and no answer, log line or audit row ever carries it.

Every route is administrator only (GET included: the profile names the owner's mailbox). Writes
that change or remove the profile ask for the account password again.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Annotated, Any, Final, Literal

from fastapi import APIRouter, Depends, Path, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.locks import ABUSE_IMAP_PROFILE
from suckerpot_db.models import ReportImapRequestRow, ReportImapRow, ReportImapStateRow
from suckerpot_db.secretbox import Credential, SecretBox
from suckerpot_db.shared_mail import is_shared_domain

from api import audit as audit_db
from api import reauth
from api.abuse_core import error
from api.abuse_replies import replies_enabled
from api.abuse_smtp import PasswordBody, valid_host
from api.auth import Principal, current_principal
from api.authz import require_admin
from api.deps import DbSession

router = APIRouter(tags=["abuse"], dependencies=[Depends(require_admin)])
log = logging.getLogger("api.abuse")

PASSWORD_AAD: Final = "report_imap"  # noqa: S105 - a label, not a secret; ingest decrypts with the same value
LOCK_TIMEOUT: Final = "150s"  # a poll ends within 120 s
TESTS_PER_HOUR: Final = 6
MAX_FOLDER: Final = 100
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_FOLDER_OK = re.compile(rf"^[ -~]{{1,{MAX_FOLDER}}}$")
_FOLDER_BAD = frozenset('"\\*%')
_AUTHSERV = re.compile(r"^[A-Za-z0-9.\-]{1,255}$")
Security = Literal["ssl", "starttls"]
Action = Literal["mark_read", "move"]


# ---- shapes --------------------------------------------------------------------------------


class RequestOut(BaseModel):
    id: int
    kind: Literal["test", "poll"]
    status: Literal["pending", "done", "failed"]
    error_code: str | None
    result: dict[str, Any]
    requested_at: datetime
    done_at: datetime | None


class AuthservHint(BaseModel):
    """The provider name ingest saw on the top-most Authentication-Results of recent mail."""

    id: str
    seen: int  # messages that carried it
    of: int  # messages read


class StateOut(BaseModel):
    last_poll_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_error: str | None = None
    move_supported: bool | None = None
    counters: dict[str, Any] = {}
    # Set by the poll while no trusted id is saved: a suggestion, never applied by itself.
    authserv_hint: AuthservHint | None = None


class ImapOut(BaseModel):
    configured: bool
    worker_enabled: bool  # ABUSE_REPLIES_ENABLED on this server
    enabled: bool
    password_set: bool
    host: str
    port: int
    security: Security
    username: str
    folder: str
    processed_action: Action
    move_folder: str | None
    poll_minutes: int
    since: date | None
    # The authserv-id of the Authentication-Results header your mailbox provider adds; without it
    # no mail counts as authenticated.
    trusted_authserv_id: str | None = None
    # True when the mailbox is on a free or shared mail provider: use a dedicated mailbox for abuse
    # reports, replies from that provider's own domain can never be trusted by domain.
    shared_mailbox: bool = False
    state: StateOut
    last_test: RequestOut | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None


class ImapBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    security: Security
    username: str = Field(min_length=1, max_length=254)
    # The password: omitted keeps the stored one; the first save needs one.
    password: str | None = Field(default=None, max_length=256, repr=False)
    folder: str = Field(default="INBOX", max_length=MAX_FOLDER)
    processed_action: Action = "mark_read"
    move_folder: str | None = Field(default=None, max_length=MAX_FOLDER)
    poll_minutes: int = Field(default=15, ge=5, le=1440)
    since: date | None = None  # mail received earlier is ignored; default: today (UTC)
    trusted_authserv_id: str | None = Field(default=None, max_length=255)
    current_password: str = Field(max_length=1024, repr=False)  # re-authentication


class Accepted(BaseModel):
    id: int
    status: str = "pending"


# ---- helpers -------------------------------------------------------------------------------


def valid_folder(name: str) -> bool:
    """Printable ASCII, 1 to 100 characters, none of the quote, backslash, ``*`` or ``%``.
    Always sent quoted, so a name can never carry a command."""
    return bool(_FOLDER_OK.match(name)) and not set(name) & _FOLDER_BAD


def mailbox_is_shared(host: str, username: str) -> bool:
    """The provider of the mailbox is a free or shared one (by its host or its address)."""
    return is_shared_domain(host) or (
        "@" in username and is_shared_domain(username.rpartition("@")[2])
    )


def _actor(principal: Principal | None) -> str:
    return principal.username if principal else "anonymous"


def _client_ip(request: Request) -> str | None:
    return request.app.state.auth.client_ip(request)  # type: ignore[no-any-return]


def _no_store(model: BaseModel, status: int = 200) -> Response:
    return JSONResponse(
        model.model_dump(mode="json"), status_code=status, headers={"Cache-Control": "no-store"}
    )


_PROFILE_COLUMNS = (
    ReportImapRow.enabled,
    ReportImapRow.host,
    ReportImapRow.port,
    ReportImapRow.security,
    ReportImapRow.username,
    ReportImapRow.password_set,
    ReportImapRow.folder,
    ReportImapRow.processed_action,
    ReportImapRow.move_folder,
    ReportImapRow.poll_minutes,
    ReportImapRow.since,
    ReportImapRow.trusted_authserv_id,
    ReportImapRow.updated_at,
    ReportImapRow.updated_by,
)


@dataclass(frozen=True)
class Profile:
    enabled: bool
    host: str
    port: int
    security: str
    username: str
    password_set: bool
    folder: str
    processed_action: str
    move_folder: str | None
    poll_minutes: int
    since: date
    trusted_authserv_id: str | None
    updated_at: datetime
    updated_by: str | None


async def load_profile(db: AsyncSession) -> Profile | None:
    """Everything but the password (the role cannot read it)."""
    row = (await db.execute(select(*_PROFILE_COLUMNS).where(ReportImapRow.id == 1))).first()
    # Same values; mypy cannot spread SQLAlchemy 2.1's variadic Row type into the dataclass.
    return None if row is None else Profile(*tuple(row))


def authserv_hint(value: Any) -> dict[str, Any] | None:
    """The hint ingest stored, only if it is a valid provider name (the rule of the field) with
    sane counts. Anything else is dropped: header text is never passed on."""
    if not isinstance(value, dict):
        return None
    name, seen, of = value.get("id"), value.get("seen"), value.get("of")
    if not (isinstance(name, str) and _AUTHSERV.match(name)):
        return None
    if not (isinstance(seen, int) and isinstance(of, int) and 0 < seen <= of <= 1000):
        return None
    return {"id": name.lower(), "seen": seen, "of": of}


def _request_out(row: ReportImapRequestRow) -> RequestOut:
    result = dict(row.result or {})
    if "authserv_hint" in result:
        result["authserv_hint"] = authserv_hint(result["authserv_hint"])
    return RequestOut(
        id=row.id,
        kind=row.kind,  # type: ignore[arg-type]
        status=row.status,  # type: ignore[arg-type]
        error_code=row.error_code,
        result=result,
        requested_at=row.requested_at,
        done_at=row.done_at,
    )


async def _state(db: AsyncSession) -> StateOut:
    row = await db.get(ReportImapStateRow, 1)
    if row is None:
        return StateOut()
    counters = dict(row.counters or {})
    hint = authserv_hint(counters.pop("authserv_hint", None))
    counters.pop("authserv_sample", None)  # ingest's own working data
    return StateOut(
        last_poll_at=row.last_poll_at,
        last_ok_at=row.last_ok_at,
        last_error=row.last_error,
        move_supported=row.move_supported,
        counters=counters,
        authserv_hint=AuthservHint(**hint) if hint else None,
    )


async def _profile_out(db: AsyncSession) -> ImapOut:
    profile = await load_profile(db)
    last = (
        await db.scalars(
            select(ReportImapRequestRow)
            .where(ReportImapRequestRow.kind == "test")
            .order_by(ReportImapRequestRow.id.desc())
            .limit(1)
        )
    ).first()
    common: dict[str, Any] = {
        "worker_enabled": replies_enabled(),
        "state": await _state(db),
        "last_test": _request_out(last) if last is not None else None,
    }
    if profile is None:
        return ImapOut(
            configured=False, enabled=False, password_set=False, host="", port=993,
            security="ssl", username="", folder="INBOX", processed_action="mark_read",
            move_folder=None, poll_minutes=15, since=None, **common,
        )  # fmt: skip
    return ImapOut(
        configured=bool(profile.host and profile.username and profile.password_set),
        enabled=profile.enabled,
        password_set=profile.password_set,
        host=profile.host,
        port=profile.port,
        security=profile.security,  # type: ignore[arg-type]
        username=profile.username,
        folder=profile.folder,
        processed_action=profile.processed_action,  # type: ignore[arg-type]
        move_folder=profile.move_folder,
        poll_minutes=profile.poll_minutes,
        since=profile.since,
        trusted_authserv_id=profile.trusted_authserv_id,
        shared_mailbox=mailbox_is_shared(profile.host, profile.username),
        updated_at=profile.updated_at,
        updated_by=profile.updated_by,
        **common,
    )


async def _lock_profile(db: AsyncSession) -> bool:
    """Wait for a poll in flight (ingest holds this lock shared while it reads the mailbox)."""
    await db.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
    try:
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ABUSE_IMAP_PROFILE})
    except DBAPIError:
        await db.rollback()
        return False
    return True


def _busy() -> Response:
    return error(409, "The mailbox is being read right now. Try again in a minute.", "polling")


# ---- the profile ---------------------------------------------------------------------------


@router.get("/abuse/imap", response_model=ImapOut)
async def get_imap(db: DbSession) -> Response:
    return _no_store(await _profile_out(db))


@router.put("/abuse/imap", response_model=ImapOut)
async def put_imap(body: ImapBody, request: Request, db: DbSession) -> Response:
    host = body.host.strip().lower()
    if not valid_host(host):
        return error(
            422, "Use the server's DNS name (no address, no internal name).", "invalid_host"
        )
    username = body.username.strip()
    if not username or _CTRL.search(username) or (body.password and _CTRL.search(body.password)):
        return error(
            422,
            "The user name or password has characters that are not allowed.",
            "invalid_credentials",
        )
    if not valid_folder(body.folder):
        return error(422, "The folder name is not valid.", "invalid_folder")
    move_folder = body.move_folder.strip() if body.move_folder else None
    if body.processed_action == "move":
        if not move_folder or not valid_folder(move_folder):
            return error(422, "Name the folder processed mail is moved to.", "invalid_move_folder")
        if move_folder == body.folder:
            return error(
                422, "The move folder must differ from the folder that is read.", "same_folder"
            )
    else:
        move_folder = move_folder if move_folder and valid_folder(move_folder) else None
    old = await load_profile(db)
    if body.password:
        box: SecretBox | None = request.app.state.secret_box
        if box is None:
            reason: str = request.app.state.secret_box_reason or "Password storage is disabled."
            return error(503, reason, "editing_disabled")
    authserv = (body.trusted_authserv_id or "").strip().lower() or None
    if authserv is not None and not _AUTHSERV.match(authserv):
        return error(422, "The authentication server name is not valid.", "invalid_authserv")
    # Pointing the profile at another server or account must not reuse the stored password:
    # it would be sent to whoever the new host is.
    retargeted = old is not None and (
        (old.host, old.port, old.username, old.security)
        != (host, body.port, username, body.security)
    )
    keeps = body.password is None and old is not None and old.password_set and not retargeted
    if not (bool(body.password) or keeps):
        return error(422, "Enter the mailbox password.", "password_required")
    principal, refused = await reauth.guard(request, body.current_password, "imap profile change")
    if refused is not None:
        return refused
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "enabled": body.enabled,
        "host": host,
        "port": body.port,
        "security": body.security,
        "username": username,
        "folder": body.folder,
        "processed_action": body.processed_action,
        "move_folder": move_folder if body.processed_action == "move" else None,
        "poll_minutes": body.poll_minutes,
        "trusted_authserv_id": authserv,
        "updated_at": now,
        "updated_by": _actor(principal)[:120],
    }
    since = body.since or (old.since if old is not None else now.date())
    values["since"] = since
    changed = [
        k
        for k in ("enabled", "host", "port", "security", "username", "folder", "processed_action",
                  "move_folder", "poll_minutes", "since", "trusted_authserv_id")
        if old is None or getattr(old, k) != values[k]
    ]  # fmt: skip
    if body.password:
        box = request.app.state.secret_box
        ciphertext, nonce = box.encrypt(PASSWORD_AAD, Credential(key=body.password))
        values |= {"password_ciphertext": ciphertext, "password_nonce": nonce}
        changed.append("password")
    if not await _lock_profile(db):
        return _busy()
    if old is None:
        await db.execute(insert(ReportImapRow).values(id=1, **values))
    else:
        await db.execute(update(ReportImapRow).where(ReportImapRow.id == 1).values(**values))
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.imap.update",
        ip=_client_ip(request),
        details={"changed": changed},  # names only, never values
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(await _profile_out(db))


@router.delete("/abuse/imap", status_code=204)
async def delete_imap(body: PasswordBody, request: Request, db: DbSession) -> Response:
    """Remove the profile. Replies already stored stay."""
    principal, refused = await reauth.guard(request, body.current_password, "imap profile removal")
    if refused is not None:
        return refused
    if not await _lock_profile(db):
        return _busy()
    await db.execute(delete(ReportImapRow).where(ReportImapRow.id == 1))
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.imap.delete",
        ip=_client_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Response(status_code=204)


# ---- requests ------------------------------------------------------------------------------


async def _queue(
    db: AsyncSession, request: Request, kind: Literal["test", "poll"], window_s: int, limit: int
) -> Response:
    if not replies_enabled():
        return error(409, "Reading replies is switched off on this server.", "replies_disabled")
    profile = await load_profile(db)
    if profile is None or not (profile.host and profile.username and profile.password_set):
        return error(409, "Save the mailbox settings first.", "imap_not_configured")
    pending = await db.scalar(
        text("SELECT count(*) FROM report_imap_requests WHERE kind = :k AND status = 'pending'"),
        {"k": kind},
    )
    if pending:
        return error(409, "A request is already waiting for the mailbox.", "already_queued")
    recent = await db.scalar(
        text(
            "SELECT count(*) FROM report_imap_requests WHERE kind = :k "
            "AND requested_at > now() - make_interval(secs => :s)"
        ),
        {"k": kind, "s": window_s},
    )
    if int(recent or 0) >= limit:
        return error(429, "Too many requests. Try again later.", "rate_limited")
    principal = await current_principal(request)
    new = ReportImapRequestRow(kind=kind, requested_by=_actor(principal)[:120])
    db.add(new)
    await db.flush()
    await audit_db.record(
        db,
        actor=_actor(principal),
        action=f"abuse.imap.{kind}",
        ip=_client_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(Accepted(id=new.id), 202)


@router.post("/abuse/imap/test", status_code=202, response_model=Accepted)
async def test_imap(request: Request, db: DbSession) -> Response:
    """Ask ingest to connect, log in and list the folders (six a hour)."""
    return await _queue(db, request, "test", 3600, TESTS_PER_HOUR)


@router.post("/abuse/imap/poll", status_code=202, response_model=Accepted)
async def poll_imap(request: Request, db: DbSession) -> Response:
    """ "Check now": ask ingest to read the mailbox at once (one a minute)."""
    return await _queue(db, request, "poll", 60, 1)


@router.get("/abuse/imap/requests/{request_id}", response_model=RequestOut)
async def get_request(request_id: Annotated[int, Path(ge=1, le=2**62)], db: DbSession) -> Response:
    row = await db.get(ReportImapRequestRow, request_id)
    if row is None:
        return error(404, "Not found.", "not_found")
    return _no_store(_request_out(row))
