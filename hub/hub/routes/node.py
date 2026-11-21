"""GET, PATCH and DELETE /v1/node."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response
from suckerpot_netproto import ProtoError, models, sign

from .. import dormant, pseudonym
from ..auth import authenticate, reply
from ..context import AppContext, get_ctx
from ..models import Batch, Node

router = APIRouter()
PSEUDONYM_CHANGE_DAYS = 7


async def node_info(ctx: AppContext, session: AsyncSession, node: Node) -> models.NodeInfo:
    today = ctx.today()
    active = (
        await session.execute(
            select(func.count())
            .select_from(Batch)
            .where(
                Batch.node_id == node.id,
                Batch.items > 0,
                Batch.day >= today - timedelta(days=14),
            )
        )
    ).scalar_one()
    eligible_from = node.enrolled_day + timedelta(days=ctx.settings.node_min_age_days)
    if node.standing == "soft_suspended" or node.reputation < ctx.settings.min_reputation:
        standing = "low"
    elif today < eligible_from:
        standing = "new"
    else:
        standing = "good"
    return models.NodeInfo(
        node_id=str(node.id),
        fingerprint=sign.fingerprint(node.pubkey),
        pseudonym=node.pseudonym,
        country=node.country.strip() if node.country else None,
        show_country=node.show_country,
        enrolled_day=node.enrolled_day.isoformat(),
        eligible_from_day=eligible_from.isoformat(),
        standing=standing,  # type: ignore[arg-type]
        active_days_14=min(int(active), 14),
    )


@router.get("/node")
async def get_node(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, _ = await authenticate(request, ctx, session)
        node = (await session.execute(select(Node).where(Node.id == caller.node_id))).scalar_one()
        out = await node_info(ctx, session, node)
    return reply(request, ctx, 200, out.model_dump(mode="json"))


@router.patch("/node")
async def patch_node(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, body = await authenticate(request, ctx, session)
        patch = models.parse_body(models.NodePatch, body)
        node = (await session.execute(select(Node).where(Node.id == caller.node_id))).scalar_one()
        today = ctx.today()
        values: dict[str, object] = {}
        claimed: str | None = None
        given = patch.model_fields_set
        if "pseudonym" in given:
            if patch.pseudonym is None:
                values.update(pseudonym=None, pseudonym_key=None)
            else:
                key = pseudonym.validate(patch.pseudonym)
                if key != node.pseudonym_key:
                    changed = node.pseudonym_changed_day
                    if changed is not None and today - changed < timedelta(
                        days=PSEUDONYM_CHANGE_DAYS
                    ):
                        raise ProtoError("rate_limited", str(86400))
                    claimed = key
                values.update(
                    pseudonym=patch.pseudonym,
                    pseudonym_key=key,
                    pseudonym_changed_day=today
                    if key != node.pseudonym_key
                    else node.pseudonym_changed_day,
                )
        if "country" in given:
            values["country"] = patch.country
        if "show_country" in given and patch.show_country is not None:
            values["show_country"] = patch.show_country
        new_country = values.get("country", node.country)
        if new_country is None:
            values["show_country"] = False
        if values:
            try:
                # A name is refused unless its holder is a silent ghost (hub/hub/dormant.py).
                if claimed is not None and not await dormant.claim_pseudonym(
                    session, claimed, today, node.id
                ):
                    raise ProtoError("pseudonym_taken")
                await session.execute(update(Node).where(Node.id == node.id).values(**values))
                await session.commit()
            except DBAPIError as exc:
                await session.rollback()
                if dormant.lost_race(exc):  # a concurrent claim of the same name
                    raise ProtoError("pseudonym_taken") from None
                raise
            node = (
                await session.execute(select(Node).where(Node.id == caller.node_id))
            ).scalar_one()
        out = await node_info(ctx, session, node)
    return reply(request, ctx, 200, out.model_dump(mode="json"))


@router.delete("/node")
async def delete_node(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, _ = await authenticate(request, ctx, session)
        # Foreign keys cascade to nonces, batches, observations, contributor links, votes, stats.
        await session.execute(delete(Node).where(Node.id == caller.node_id))
        await session.commit()
    ctx.node_limiter.forget(str(caller.node_id))
    return reply(request, ctx, 200, {"deleted": True})
