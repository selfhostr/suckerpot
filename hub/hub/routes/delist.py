"""Public delisting (design M30 section 9): proof of work, then a request for operator review.

* ``POST /v1/delist/challenge``: a single-use challenge and its difficulty.
* ``POST /v1/delist``: ``sha256(challenge || pow_nonce)`` must start with ``difficulty`` zero bits.
* ``GET /v1/delist/{id}``: the status, with the ``Authorization: Bearer`` token shown once.

Privacy: no client address is stored or logged. The only reader of the address is the in-memory
rate limiter (``ratelimit.py``). A request holds days, never times. Only the SHA-256 of the status
token is kept. A request for a value that is not listed stores nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import text
from starlette.exceptions import HTTPException
from starlette.responses import Response
from suckerpot_netproto import ProtoError, pow, sign
from suckerpot_netproto.feeds.models import LIST_IDS

from ..auth import MAX_BODY_DEFAULT, read_body, record_failure, reply
from ..context import get_ctx
from .lookup import limit_unsigned, normalize_value

router = APIRouter()

SLA_HOURS = 72
CHALLENGE_TTL_S = 600
SUPPRESSIBLE = "inbound"
SUPPRESSIBLE_LISTS = frozenset({SUPPRESSIBLE})
ID_RE = re.compile(r"^d_[0-9a-f]{16}$")
OPEN_STATES = ("received", "suppressed")
# The nonce is bound to the challenge only: there is no key to bind it to.
POW_CONTEXT = b""

Category = Literal[
    "i_operate_this", "shared_infrastructure", "cleaned_up", "address_reassigned", "other"
]


def _no_nul(value: str | None) -> str | None:
    if value is not None and "\x00" in value:
        raise ValueError("NUL")
    return value


class ChallengeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DelistBody(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    challenge: str = Field(max_length=64)
    pow_nonce: str = Field(max_length=32)
    value: str = Field(max_length=253)
    list_id: str | None = Field(default=None, alias="list", max_length=32)
    category: Category
    evidence: str | None = Field(default=None, max_length=2000)
    contact: str | None = Field(default=None, max_length=254)

    _clean = field_validator("evidence", "contact", "value", mode="after")(_no_nul)

    @field_validator("contact")
    @classmethod
    def _contact(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        v = v.strip()
        if not re.fullmatch(r"[^@\s<>]{1,64}@[^@\s<>]{1,189}", v):
            raise ValueError("not an e-mail address")
        return v

    @field_validator("evidence")
    @classmethod
    def _evidence(cls, v: str | None) -> str | None:
        return v if v is None or v.strip() else None

    @field_validator("list_id")
    @classmethod
    def _list(cls, v: str | None) -> str | None:
        if v is not None and v not in LIST_IDS:
            raise ValueError("unknown list")
        # A tier ("-high") is a view of its base list; entries are stored per base list.
        return None if v is None else v.removesuffix("-high")


def _json(body: bytes) -> dict[str, Any]:
    try:
        data = json.loads(body or b"{}")
    except (ValueError, RecursionError) as exc:
        raise ProtoError("invalid_payload") from exc
    if not isinstance(data, dict):
        raise ProtoError("invalid_payload")
    return data


@router.post("/delist/challenge")
async def challenge(request: Request) -> Response:
    ctx = get_ctx(request)
    body = await read_body(request, MAX_BODY_DEFAULT)
    wait = (
        ctx.address_limiter.blocked(request)
        or ctx.address_limiter.check_unsigned(request)
        or ctx.address_limiter.check_challenge(request)
    )
    if wait:
        raise ProtoError("rate_limited", str(wait))
    try:
        ChallengeBody.model_validate(_json(body))
    except ValidationError as exc:
        raise ProtoError("invalid_payload") from exc
    now = ctx.now()
    difficulty = ctx.settings.delist_pow_difficulty
    raw = os.urandom(32)
    async with ctx.sessionmaker() as session:
        await session.execute(
            text("DELETE FROM delist_challenges WHERE expires_at < :now"), {"now": now}
        )
        pending = (
            await session.execute(text("SELECT count(*) FROM delist_challenges"))
        ).scalar_one()
        if pending >= ctx.settings.max_pending_challenges:
            raise ProtoError("rate_limited", "60")
        await session.execute(
            text(
                "INSERT INTO delist_challenges (challenge, difficulty, expires_at) "
                "VALUES (:c, :d, :e)"
            ),
            {"c": raw, "d": difficulty, "e": now + timedelta(seconds=CHALLENGE_TTL_S)},
        )
        await session.commit()
    return reply(
        request,
        ctx,
        200,
        {
            "challenge": sign.b64u_encode(raw),
            "difficulty": difficulty,
            "expires_in": CHALLENGE_TTL_S,
        },
    )


@router.post("/delist")
async def submit(request: Request) -> Response:
    ctx = get_ctx(request)
    s = ctx.settings
    body = await read_body(request, MAX_BODY_DEFAULT)
    limit_unsigned(request, ctx)
    try:
        req = DelistBody.model_validate(_json(body))
        raw_challenge = sign.b64u_decode(req.challenge)
        nonce = sign.b64u_decode(req.pow_nonce)
    except (ValidationError, ValueError) as exc:
        raise ProtoError("invalid_payload") from exc
    now = ctx.now()
    today = ctx.today()
    async with ctx.sessionmaker() as session:
        # The challenge is burned by every attempt, right or wrong: no grinding on one challenge.
        row = (
            await session.execute(
                text(
                    "DELETE FROM delist_challenges WHERE challenge = :c "
                    "RETURNING difficulty, expires_at"
                ),
                {"c": raw_challenge},
            )
        ).first()
        await session.commit()
        if row is None or row.expires_at < now:
            raise ProtoError("challenge_expired")
        if not pow.verify_pow(raw_challenge, POW_CONTEXT, nonce, int(row.difficulty)):
            raise ProtoError("pow_invalid")
        value = normalize_value(req.value, allow_documentation=s.allow_documentation)
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:v))"), {"v": value})
        # Every list the value is on, whatever list the requester named: whether a value may be
        # hidden at once depends on all of them (security review H1).
        on_lists = {
            str(r[0])
            for r in await session.execute(
                text(
                    "SELECT DISTINCT list FROM feed_entries WHERE value = :v AND state = 'listed'"
                ),
                {"v": value},
            )
        }
        listed = on_lists if req.list_id is None else on_lists & {req.list_id}
        if not listed:
            await session.rollback()
            return reply(request, ctx, 200, {"listed": False, "state": "not_listed"})
        counts = (
            await session.execute(
                text(
                    "SELECT count(*) FILTER (WHERE created_day = :t) AS today, "
                    "count(*) FILTER (WHERE created_day = :t AND state = 'suppressed') AS hidden, "
                    "count(*) FILTER (WHERE value = :v "
                    "AND state IN ('received', 'suppressed')) AS open "
                    "FROM delist_requests"
                ),
                {"t": today, "v": value},
            )
        ).one()
        if counts.today >= s.delist_daily_cap:
            await session.rollback()
            raise ProtoError("rate_limited", "3600")
        on_inbound_only = on_lists <= SUPPRESSIBLE_LISTS
        hide = on_inbound_only and counts.hidden < s.delist_auto_suppress_daily
        # The list a decision may act on: the one named, or ``inbound`` when that is the only
        # list holding the value. NULL (every list) only for a request about a value that is on
        # an outbound list too, which is never hidden before an operator looks at it.
        scope = req.list_id or (SUPPRESSIBLE if on_inbound_only else None)
        request_id = "d_" + secrets.token_hex(8)
        token = secrets.token_bytes(32)
        state = "suppressed" if hide else "received"
        answer = {
            "id": request_id,
            "status_token": sign.b64u_encode(token),
            "state": state,
            "listed": True,
            "sla_hours": SLA_HOURS,
        }
        if counts.open:
            # One open request per value. Say so plainly (the value is public, so is the fact that
            # someone asked about it) and issue no token: a token that leads nowhere would only
            # mislead, and polling it would count as failed authentication (security re-review
            # L1). Nothing is stored. The daily cap was checked first.
            await session.rollback()
            return reply(
                request,
                ctx,
                200,
                {"listed": True, "state": "already_open", "sla_hours": SLA_HOURS},
            )
        await session.execute(
            text(
                "INSERT INTO delist_requests (id, token_hash, value, list, scope, category, "
                "evidence, contact, state, created_day) "
                "VALUES (:id, :th, :v, :l, :sc, :cat, :ev, :co, :st, :d)"
            ),
            {
                "id": request_id,
                "th": hashlib.sha256(token).digest(),
                "v": value,
                "l": req.list_id,
                "sc": scope,
                "cat": req.category,
                "ev": req.evidence,
                "co": req.contact,
                "st": state,
                "d": today,
            },
        )
        await session.commit()
    return reply(request, ctx, 200, answer)


@router.get("/delist/{request_id}")
async def status(request: Request, request_id: str) -> Response:
    ctx = get_ctx(request)
    limit_unsigned(request, ctx)
    auth = request.headers.get("authorization", "")
    scheme, _, supplied = auth.partition(" ")
    token_hash = b""
    if scheme.lower() == "bearer" and len(supplied) <= 64:
        try:
            token_hash = hashlib.sha256(sign.b64u_decode(supplied.strip())).digest()
        except ValueError:
            token_hash = b""
    row = None
    if ID_RE.fullmatch(request_id):
        async with ctx.sessionmaker() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT id, token_hash, state, outcome, public_note, created_day, "
                        "decided_day FROM delist_requests WHERE id = :id"
                    ),
                    {"id": request_id},
                )
            ).first()
    # Same answer for an unknown id and a wrong token; a guess counts as an authentication failure.
    if row is None or not token_hash or not hmac.compare_digest(bytes(row.token_hash), token_hash):
        record_failure(ctx, request)
        raise HTTPException(404)
    return reply(
        request,
        ctx,
        200,
        {
            "id": row.id,
            "state": row.state,
            "outcome": row.outcome,
            "public_note": row.public_note,
            "created_day": row.created_day.isoformat(),
            "decided_day": row.decided_day.isoformat() if row.decided_day else None,
        },
    )
