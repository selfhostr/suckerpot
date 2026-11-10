"""GET /v1/targets, POST /v1/reveals and POST /v1/rechecks.

Nothing here carries a node id, a fingerprint or a pseudonym (invariant H5): a target holds
bucketed counts only.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, cast

from fastapi import APIRouter, Request
from sqlalchemy import CursorResult, and_, exists, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from starlette.responses import Response
from suckerpot_netproto import ProtoError, blind, buckets, models
from suckerpot_netproto.models import parse_global_ip

from .. import verify
from ..auth import authenticate, reply
from ..context import get_ctx
from ..models import RecheckAssignment, TakedownVote, Target

router = APIRouter()

PUBLISHED = ("confirmed", "reported", "taken_down", "disputed", "expired")
OPEN_STATES = ("confirmed", "reported")
BLINDED = ("url", "domain", "c2_domain")
MAX_RECHECK_PER_PULL = 50
MAX_ASSIGNED_PER_DAY = 200  # per node: a few pulls a day, never the whole open list
MAX_REVEAL_PER_PULL = 1000
_CURSOR = re.compile(r"^c_(\d{1,18})$")


def _cursor(raw: str | None) -> int:
    if raw in (None, ""):
        return 0
    match = _CURSOR.fullmatch(raw or "")
    if match is None:
        raise ProtoError("invalid_payload", "cursor")
    return int(match.group(1))


def _limit(raw: str | None) -> int:
    if raw is None:
        return 200
    if not raw.isdigit() or not 1 <= int(raw) <= models.MAX_TARGETS_PER_PULL:
        raise ProtoError("invalid_payload", "limit")
    return int(raw)


def to_wire(row: Target) -> models.Target:
    first = row.first_day or row.confirmed_day or row.last_day
    last = row.last_day or first
    if first is None or last is None:
        raise ValueError("target without days")
    return models.Target(
        id=row.id,
        kind=row.kind,  # type: ignore[arg-type]
        value=row.value,
        value_b=row.value_b,
        state=row.state,  # type: ignore[arg-type]
        nodes=buckets.nodes_bucket(max(row.node_count, 5)),
        countries=buckets.countries_or_none(row.country_count),
        first_day=first.isoformat(),
        last_day=last.isoformat(),
        services=sorted(row.services or []),
        activity=sorted(row.activity or []),
        tags=sorted(row.tags or []),
        families=sorted(row.families or []),
        reported_day=row.reported_day.isoformat() if row.reported_day else None,
        taken_down_day=row.taken_down_day.isoformat() if row.taken_down_day else None,
    )


@router.get("/targets")
async def targets(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, _ = await authenticate(request, ctx, session)
        since = _cursor(request.query_params.get("since"))
        limit = _limit(request.query_params.get("limit"))
        rows = (
            (
                await session.execute(
                    select(Target)
                    .where(
                        Target.seq > since,
                        Target.state.in_(PUBLISHED),
                        Target.kind != "payload_ip",  # hub-internal: nodes reject unknown kinds
                    )
                    .order_by(Target.seq)
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        wire = [to_wire(r) for r in rows]
        cursor = f"c_{rows[-1].seq}" if rows else f"c_{since}"
        reveal_rows = (
            await session.execute(
                select(Target.kind, Target.value_b)
                .where(
                    Target.value.is_(None),
                    Target.kind.in_(BLINDED),
                    Target.state.in_(OPEN_STATES),
                )
                .order_by(Target.seq)
                .limit(MAX_REVEAL_PER_PULL)
            )
        ).all()
        reveal = [
            models.RevealRef(kind="url" if k == "url" else "domain", value_b=v)
            for k, v in reveal_rows
            if v is not None
        ]
        today = ctx.today()
        last_vote = (
            select(func.max(TakedownVote.day))
            .where(TakedownVote.target_id == Target.id)
            .correlate(Target)
            .scalar_subquery()
        )
        voted_today = exists().where(
            and_(
                TakedownVote.target_id == Target.id,
                TakedownVote.node_id == caller.node_id,
                TakedownVote.day == today,
            )
        )
        recheck_rows = (
            (
                await session.execute(
                    select(Target)
                    .where(
                        Target.state.in_(OPEN_STATES),
                        Target.value.is_not(None),
                        Target.kind.not_in(("sha256", "payload_ip")),
                        ~voted_today,
                    )
                    .order_by(last_vote.asc().nulls_first(), Target.seq)
                    .limit(MAX_RECHECK_PER_PULL)
                )
            )
            .scalars()
            .all()
        )
        # Only a target recorded here for this node and day can later be voted on.
        held = set(
            (
                await session.execute(
                    select(RecheckAssignment.target_id).where(
                        RecheckAssignment.node_id == caller.node_id,
                        RecheckAssignment.day == today,
                    )
                )
            )
            .scalars()
            .all()
        )
        room = MAX_ASSIGNED_PER_DAY - len(held)
        asked = []
        for r in recheck_rows:
            if r.id in held:
                asked.append(r)
            elif room > 0:
                room -= 1
                asked.append(r)
                await session.execute(
                    pg_insert(RecheckAssignment)
                    .values(target_id=r.id, node_id=caller.node_id, day=today)
                    .on_conflict_do_nothing()
                )
        await session.commit()
        recheck = [
            models.RecheckRef(id=r.id, kind=r.kind, value=r.value or "")  # type: ignore[arg-type]
            for r in asked
        ]
    out = models.TargetsResponse(cursor=cursor, targets=wire, reveal=reveal, recheck=recheck)
    return reply(request, ctx, 200, out.model_dump(mode="json"))


def _reveal_acceptable(kind: str, canonical: str, allow_documentation: bool) -> bool:
    """A revealed URL or domain must name a global address or a public-looking name."""
    if kind == "url":
        host = blind.url_host(canonical)
        if host.startswith("["):
            host = host[1:-1]
        try:
            parse_global_ip(host, allow_documentation=allow_documentation)
            return True
        except ValueError:
            pass
        return "." in host and not host.replace(".", "").isdigit()
    return "." in canonical


@router.post("/reveals")
async def reveals(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, body = await authenticate(request, ctx, session)
        req = models.parse_body(models.RevealsRequest, body)
        wait = ctx.reveal_limiter.hit(str(caller.node_id), cost=len(req.items))
        if wait:
            raise ProtoError("rate_limited", str(wait))
        never = await ctx.never.get(session)
        accepted = rejected = 0
        for item in req.items:
            canonical = blind.verify_reveal(item.kind, item.value, item.value_b)
            if canonical is None:
                rejected += 1
                continue
            listable = _reveal_acceptable(
                item.kind, canonical, ctx.settings.allow_documentation
            ) and not (
                (item.kind == "url" and never.has_url(canonical))
                or (item.kind == "domain" and never.has_domain(canonical))
            )
            if listable:
                if caller.suspended:
                    accepted += 1  # never told
                    continue
                kinds = ("url",) if item.kind == "url" else ("domain", "c2_domain")
                result = await session.execute(
                    update(Target)
                    .where(
                        Target.value_b == item.value_b,
                        Target.kind.in_(kinds),
                        Target.value.is_(None),
                        Target.state.in_(OPEN_STATES),
                    )
                    .values(value=canonical, updated_at=ctx.now())
                )
                if cast(CursorResult[Any], result).rowcount:
                    accepted += 1
                    continue
            # Early reveal (M32): a link this node reported that a verification task waits for. The
            # clear value goes to verify_tasks only, never into the candidate target (D10).
            if (
                item.kind == "url"
                and not caller.suspended
                and await verify.accept_reveal(
                    session,
                    ctx.settings,
                    caller.node_id,
                    item.value_b,
                    canonical,
                    ctx.today(),
                    never,
                )
            ):
                accepted += 1
            else:
                rejected += 1
        await session.commit()
    return reply(request, ctx, 200, {"accepted": accepted, "rejected": rejected})


@router.post("/rechecks")
async def rechecks(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, body = await authenticate(request, ctx, session)
        req = models.parse_body(models.RechecksRequest, body)
        today = ctx.today()
        day = buckets.parse_day(req.day)
        if day > today:
            raise ProtoError("invalid_payload", "day")
        if today - day > timedelta(days=2):
            raise ProtoError("day_too_old")
        accepted = 0
        answers = {i.id: i.state for i in req.items}  # the last answer per target wins
        for item, state in answers.items():
            # Consume the assignment for this node, target and day: no row, no vote. A replay,
            # an unassigned target and another day all land here and are dropped alike.
            claimed = await session.execute(
                update(RecheckAssignment)
                .where(
                    RecheckAssignment.node_id == caller.node_id,
                    RecheckAssignment.target_id == item,
                    RecheckAssignment.day == day,
                    RecheckAssignment.answered.is_(False),
                    RecheckAssignment.target_id.in_(
                        select(Target.id).where(Target.state.in_(OPEN_STATES))
                    ),
                )
                .values(answered=True)
            )
            if not cast(CursorResult[Any], claimed).rowcount:
                continue
            accepted += 1
            if caller.suspended:
                continue
            stmt = pg_insert(TakedownVote).values(
                target_id=item, node_id=caller.node_id, day=day, state=state
            )
            await session.execute(
                stmt.on_conflict_do_update(
                    index_elements=["target_id", "node_id", "day"], set_={"state": state}
                )
            )
        await session.commit()
    return reply(request, ctx, 200, {"accepted": accepted})
