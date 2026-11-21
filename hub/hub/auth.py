"""Signed request checks (spec section 5.2), nonce store and response signing.

Order of checks, before the body is parsed: size, header syntax, timestamp, signature (with the
key in the header), known key, nonce, rate limit. Replies carry ``X-SPN-Hub-Signature`` bound
to the request nonce.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import Response
from suckerpot_netproto import ProtoError, sign

from .context import AppContext
from .models import Node, Nonce

NONCE_TTL = timedelta(minutes=10)
MAX_BODY_DEFAULT = 64 * 1024
MAX_BODY_OBSERVATIONS = 1024 * 1024


@dataclass
class Caller:
    node_id: uuid.UUID
    pubkey: bytes
    standing: str
    reputation: float
    enrolled_day: Any
    nonce: str

    @property
    def suspended(self) -> bool:
        return self.standing == "soft_suspended"


def request_target(request: Request) -> str:
    """Path and query exactly as sent (what the client signed)."""
    raw = request.scope.get("raw_path")
    path = raw.decode("ascii", "replace") if isinstance(raw, bytes) else request.url.path
    query = request.scope.get("query_string", b"")
    return path + ("?" + query.decode("ascii", "replace") if query else "")


async def read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise ProtoError("too_large")
        except ValueError as exc:
            raise ProtoError("invalid_payload") from exc
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise ProtoError("too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _headers(request: Request) -> sign.ParsedHeaders:
    h = request.headers
    return sign.parse_request_headers(
        h.get(sign.H_KEY.lower()),
        h.get(sign.H_TIMESTAMP.lower()),
        h.get(sign.H_NONCE.lower()),
        h.get(sign.H_SIGNATURE.lower()),
    )


def record_failure(ctx: AppContext, request: Request) -> None:
    """An authentication failure: the address limiter counts it, and so does the day's counter
    (a day with many failures never counts as a pseudonym holder's silence, hub/hub/dormant.py)."""
    ctx.address_limiter.record_failure(request)
    ctx.served_days.auth_failure(ctx.now())


async def authenticate(
    request: Request,
    ctx: AppContext,
    session: AsyncSession,
    *,
    limit: int = MAX_BODY_DEFAULT,
) -> tuple[Caller, bytes]:
    """Run the seven checks for a signed request from an enrolled node."""
    wait = ctx.address_limiter.blocked(request)
    if wait:
        # The limiter stays first (no lookup, no signature check for a blocked address). The block
        # is counted instead: a day with many blocks never counts as a pseudonym holder's silence.
        try:
            await ctx.served_days.blocked(session, ctx.now())
        except Exception:  # the marker is best effort; the answer stays the same
            await session.rollback()
        raise ProtoError("rate_limited", str(wait))
    try:
        body = await read_body(request, limit)  # 1. size
        parsed = _headers(request)  # 2. headers
        sign.check_timestamp(parsed.timestamp, ctx.now().timestamp())  # 3. timestamp
        node = (
            await session.execute(select(Node).where(Node.pubkey == parsed.public))
        ).scalar_one_or_none()  # 4. key known
        if not sign.verify_request(  # 5. signature, with the key the header names
            parsed.public,
            parsed.signature,
            request.method,
            request_target(request),
            str(parsed.timestamp),
            parsed.nonce,
            body,
        ):
            raise ProtoError("bad_signature")
        _bind_signed(request, parsed)
        if node is None:  # 4. a proven key we do not know: the answer is signed (a node can tell)
            raise ProtoError("unknown_node")
    except ProtoError as exc:
        if exc.code not in ("too_large", "rate_limited"):
            record_failure(ctx, request)
        raise
    # 6. nonce: single use for NONCE_TTL. Committed right away so a failed request still burns it.
    nonce_raw = sign.b64u_decode(parsed.nonce)
    inserted = await session.execute(
        pg_insert(Nonce)
        .values(node_id=node.id, nonce=nonce_raw, expires_at=ctx.now() + NONCE_TTL)
        .on_conflict_do_nothing()
    )
    if cast(CursorResult[Any], inserted).rowcount == 0:
        await session.rollback()
        record_failure(ctx, request)
        raise ProtoError("replayed_nonce")
    await session.execute(
        update(Node)
        .where(Node.id == node.id, Node.last_active_day != ctx.today())
        .values(last_active_day=ctx.today())
    )
    await ctx.served_days.served(session, ctx.now())
    await session.commit()
    # 7. rate limit per node
    wait = ctx.node_limiter.hit(str(node.id))
    if wait:
        raise ProtoError("rate_limited", str(wait))
    return (
        Caller(
            node.id, node.pubkey, node.standing, node.reputation, node.enrolled_day, parsed.nonce
        ),
        body,
    )


async def authenticate_new_key(
    request: Request, ctx: AppContext, *, limit: int = MAX_BODY_DEFAULT
) -> tuple[bytes, str, bytes]:
    """Enrolment: the request is signed by the key being enrolled (no node exists yet).

    Returns (public key, nonce, body). Replay is stopped by the single-use challenge.
    """
    wait = ctx.address_limiter.blocked(request) or ctx.address_limiter.check_unsigned(request)
    if wait:
        raise ProtoError("rate_limited", str(wait))
    body = await read_body(request, limit)
    parsed = _headers(request)
    sign.check_timestamp(parsed.timestamp, ctx.now().timestamp())
    if not sign.verify_request(
        parsed.public,
        parsed.signature,
        request.method,
        request_target(request),
        str(parsed.timestamp),
        parsed.nonce,
        body,
    ):
        record_failure(ctx, request)
        raise ProtoError("bad_signature")
    _bind_signed(request, parsed)
    return parsed.public, parsed.nonce, body


# --- replies ---


def _bind_signed(request: Request, parsed: sign.ParsedHeaders) -> None:
    """From here on the request is authenticated: answers are signed and bound to it."""
    request.state.binding = sign.RequestBinding.signed(
        request.method, request_target(request), parsed.key, parsed.nonce, parsed.signature
    )


def bind_unsigned(request: Request, body: bytes = b"") -> None:
    """Unsigned endpoint: bind the answer to the request when the client sent a nonce."""
    nonce = request_nonce(request)
    if nonce is not None:
        request.state.binding = sign.RequestBinding.unsigned(
            request.method, request_target(request), nonce, body
        )


def request_nonce(request: Request) -> str | None:
    """The request nonce when it is well formed (it is what the reply signature is bound to)."""
    nonce = request.headers.get(sign.H_NONCE.lower())
    if not nonce:
        return None
    try:
        return nonce if len(sign.b64u_decode(nonce)) == sign.NONCE_BYTES else None
    except ValueError:
        return None


def reply(
    request: Request,
    ctx: AppContext,
    status: int,
    payload: Any,
    *,
    headers: dict[str, str] | None = None,
) -> Response:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    out = {"Content-Type": "application/json", "Cache-Control": "no-store", **(headers or {})}
    binding = getattr(request.state, "binding", None)
    if binding is not None:  # never for a request whose authentication failed
        out[sign.H_HUB_SIGNATURE] = sign.sign_response(ctx.hub_private, binding, status, body)
        if ctx.hub_private_alt is not None:  # key rollover: same canonical answer, second key
            out[sign.H_HUB_SIGNATURE_ALT] = sign.sign_response(
                ctx.hub_private_alt, binding, status, body
            )
    return Response(content=body, status_code=status, headers=out)


def error_reply(request: Request, ctx: AppContext, exc: ProtoError) -> Response:
    headers: dict[str, str] = {}
    if exc.code == "rate_limited":
        headers["Retry-After"] = exc.detail if exc.detail.isdigit() else "60"
    return reply(request, ctx, exc.status, {"error": exc.code}, headers=headers)
