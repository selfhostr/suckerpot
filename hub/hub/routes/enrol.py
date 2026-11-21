"""Enrolment: POST /v1/enrol/challenge (unsigned) and POST /v1/enrol (signed by the new key)."""

from __future__ import annotations

import os
from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import delete, func, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response
from suckerpot_netproto import ProtoError, models, pow, sign

from .. import dormant, pseudonym
from ..auth import MAX_BODY_DEFAULT, authenticate_new_key, bind_unsigned, read_body, reply
from ..context import AppContext, get_ctx
from ..models import EnrolChallenge, Node

router = APIRouter()


async def enrolments_today(ctx: AppContext, session: AsyncSession) -> int:
    return int(
        (
            await session.execute(
                select(func.count()).select_from(Node).where(Node.enrolled_day == ctx.today())
            )
        ).scalar_one()
    )


def current_difficulty(ctx: AppContext, request: Request, *, counted: bool = False) -> int:
    """Base difficulty plus extra bits driven by how many challenges THIS address prefix drew
    lately (above ``enrol_soft_cap`` one more bit, then one per ``enrol_step`` more; at most +10).

    The price rises for a flooding prefix only: a global counter would let one attacker make
    enrolment unaffordable for everyone. ``counted`` says the current request is already in the
    count.
    """
    s = ctx.settings
    drawn = ctx.address_limiter.challenge_pressure(request) - (1 if counted else 0)
    over = drawn - s.enrol_soft_cap
    if over <= 0:
        return s.pow_difficulty
    return min(s.pow_difficulty + 1 + (over - 1) // s.enrol_step, s.pow_difficulty + 10, 48)


@router.post("/enrol/challenge")
async def challenge(request: Request) -> Response:
    ctx = get_ctx(request)
    body = await read_body(request, MAX_BODY_DEFAULT)
    bind_unsigned(request, body)
    wait = (
        ctx.address_limiter.blocked(request)
        or ctx.address_limiter.check_unsigned(request)
        or ctx.address_limiter.check_challenge(request)
    )
    if wait:
        raise ProtoError("rate_limited", str(wait))
    req = models.parse_body(models.ChallengeRequest, body)
    pubkey = sign.parse_node_key(req.node_key)
    now = ctx.now()
    async with ctx.sessionmaker() as session:
        if await enrolments_today(ctx, session) >= ctx.settings.enrol_hard_cap:
            raise ProtoError("enrolment_closed")
        await session.execute(delete(EnrolChallenge).where(EnrolChallenge.expires_at < now))
        pending = (
            await session.execute(select(func.count()).select_from(EnrolChallenge))
        ).scalar_one()
        if pending >= ctx.settings.max_pending_challenges:
            raise ProtoError("rate_limited", "60")
        difficulty = current_difficulty(ctx, request, counted=True)
        raw = os.urandom(32)
        await session.execute(delete(EnrolChallenge).where(EnrolChallenge.pubkey == pubkey))
        await session.execute(
            insert(EnrolChallenge).values(
                challenge=raw,
                pubkey=pubkey,
                difficulty=difficulty,
                expires_at=now + timedelta(seconds=ctx.settings.challenge_ttl_s),
            )
        )
        await session.commit()
    out = models.ChallengeResponse(
        challenge=sign.b64u_encode(raw),
        difficulty=difficulty,
        expires_in=ctx.settings.challenge_ttl_s,
    )
    return reply(request, ctx, 200, out.model_dump(mode="json"))


@router.post("/enrol")
async def enrol(request: Request) -> Response:
    ctx = get_ctx(request)
    pubkey, _nonce, body = await authenticate_new_key(request, ctx)
    req = models.parse_body(models.EnrolRequest, body)
    raw_challenge = sign.b64u_decode(req.challenge)
    today = ctx.today()
    key = pseudonym.validate(req.pseudonym) if req.pseudonym is not None else None
    async with ctx.sessionmaker() as session:
        row = (
            await session.execute(
                select(EnrolChallenge).where(EnrolChallenge.challenge == raw_challenge)
            )
        ).scalar_one_or_none()
        if row is None or row.expires_at < ctx.now() or row.pubkey != pubkey:
            raise ProtoError("challenge_expired")
        if not pow.verify_pow(
            raw_challenge, pubkey, sign.b64u_decode(req.pow_nonce), row.difficulty
        ):
            raise ProtoError("pow_invalid")
        if await enrolments_today(ctx, session) >= ctx.settings.enrol_hard_cap:
            raise ProtoError("enrolment_closed")
        # A name held by an active node is refused; one held by a dormant ghost is freed.
        if key is not None and not await dormant.claim_pseudonym(session, key, today):
            raise ProtoError("pseudonym_taken")
        try:
            node_id = (
                await session.execute(
                    insert(Node)
                    .values(
                        pubkey=pubkey,
                        pseudonym=req.pseudonym,
                        pseudonym_key=key,
                        country=req.country,
                        show_country=req.show_country and req.country is not None,
                        enrolled_day=today,
                        last_active_day=today,
                        protocol=req.protocol,
                    )
                    .returning(Node.id)
                )
            ).scalar_one()
        except IntegrityError as exc:
            await session.rollback()
            text = str(exc.orig)
            if "pseudonym_key" in text:
                raise ProtoError("pseudonym_taken") from None
            raise ProtoError("invalid_payload", "already enrolled") from None
        await session.execute(
            delete(EnrolChallenge).where(EnrolChallenge.challenge == raw_challenge)
        )
        await session.commit()
    out = models.EnrolResponse(
        node_id=str(node_id),
        fingerprint=sign.fingerprint(pubkey),
        enrolled_day=today.isoformat(),
        eligible_from_day=(today + timedelta(days=ctx.settings.node_min_age_days)).isoformat(),
    )
    return reply(request, ctx, 200, out.model_dump(mode="json"))
