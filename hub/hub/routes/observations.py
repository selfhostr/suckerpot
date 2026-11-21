"""POST /v1/observations: one batch per node and day."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from starlette.responses import Response
from suckerpot_netproto import ProtoError, buckets, models, sign

from .. import consensus
from ..auth import MAX_BODY_OBSERVATIONS, authenticate, reply
from ..context import get_ctx
from ..models import Batch, Node, Observation, PayloadLink
from ..never import Never

router = APIRouter()
CHUNK = 2000


def _merge(into: dict[str, Any], row: dict[str, Any]) -> None:
    for key in ("services", "activity", "tags", "families"):
        into[key] = sorted(set(into.get(key) or []) | set(row.get(key) or []))
    into["fetched"] = bool(into.get("fetched")) or bool(row.get("fetched"))
    into["file_type"] = into.get("file_type") or row.get("file_type")
    into["via"] = into.get("via") or row.get("via")
    for key in ("sessions", "attempts"):
        values = [v for v in (into.get(key), row.get(key)) if v is not None]
        into[key] = max(values) if values else None


def c2_value(ip: str, port: int) -> str:
    """``ip:port``, with an IPv6 address in brackets so that the port is unambiguous."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def build_rows(
    batch: models.ObservationBatch, never: Never, links: set[tuple[str, str, str]] | None = None
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, int]]:
    """Observation rows for a batch, items accepted per list and rejections by reason.

    ``links`` (when given) collects ``(host_kind, host, url_b)`` of every accepted payload host.
    """
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    accepted = {"sources": 0, "payloads": 0, "c2": 0, "files": 0}
    rejected: dict[str, int] = {}

    def reject(reason: str) -> None:
        rejected[reason] = rejected.get(reason, 0) + 1

    def put(kind: str, value: str, **fields: Any) -> None:
        row = {
            "kind": kind,
            "value": value,
            "services": [],
            "activity": [],
            "tags": [],
            "families": [],
            "sessions": None,
            "attempts": None,
            "fetched": False,
            "file_type": None,
            "via": None,
            **fields,
        }
        existing = rows.get((kind, value))
        if existing is None:
            rows[(kind, value)] = row
        else:
            _merge(existing, row)

    for s in batch.sources:
        if never.has_ip(s.ip):
            reject("never_listed")
            continue
        put(
            "ip",
            s.ip,
            services=s.services,
            activity=s.activity,
            tags=s.tags,
            sessions=s.sessions,
            attempts=s.attempts,
        )
        accepted["sources"] += 1
    for p in batch.payloads:
        fam = [p.family] if p.family else []
        put(
            "url",
            p.url_b,
            activity=["download"],
            families=fam,
            fetched=p.fetched,
            file_type=p.file_type,
        )
        if p.host_ip is not None:
            if not never.has_ip(p.host_ip):
                # The host as a payload host, a hub-internal kind (never sent to nodes). It is NOT
                # folded into the ``ip`` row of the same address: that row is the address as an
                # attack source, and a URL typed into a honeypot says nothing about what its host
                # did (security review H3). M29 reports payload hosts from this kind.
                put(
                    "payload_ip",
                    p.host_ip,
                    activity=["download"],
                    families=fam,
                    fetched=p.fetched,
                )
                if links is not None:
                    links.add(("payload_ip", p.host_ip, p.url_b))
        elif p.host_b is not None:
            put("domain", p.host_b, activity=["download"], families=fam, fetched=p.fetched)
            if links is not None:
                links.add(("domain", p.host_b, p.url_b))
        if p.sha256 is not None:
            if never.has_hash(p.sha256):
                reject("never_listed")
                continue
            put(
                "sha256",
                p.sha256,
                activity=["download"],
                families=fam,
                fetched=p.fetched,
                file_type=p.file_type,
            )
        accepted["payloads"] += 1
    for c in batch.c2:
        fam = [c.family] if c.family else []
        if c.ip is not None:
            if never.has_ip(c.ip):
                reject("never_listed")
                continue
            put("c2_ip", c2_value(c.ip, c.port), families=fam, via=c.via_sha256)
        elif c.domain_b is not None:
            put("c2_domain", c.domain_b, families=fam, via=c.via_sha256)
        accepted["c2"] += 1
    for f in batch.files:
        if never.has_hash(f.sha256):
            reject("never_listed")
            continue
        put("sha256", f.sha256, families=[f.family] if f.family else [], file_type=f.file_type)
        accepted["files"] += 1
    return list(rows.values()), accepted, rejected


@router.post("/observations")
async def observations(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, body = await authenticate(request, ctx, session, limit=MAX_BODY_OBSERVATIONS)
        batch = models.parse_body(
            models.ObservationBatch,
            body,
            max_bytes=MAX_BODY_OBSERVATIONS,
            allow_documentation=ctx.settings.allow_documentation,
        )
        day = buckets.parse_day(batch.day)
        code = buckets.check_batch_day(day, ctx.today())
        if code is not None:
            raise ProtoError(code)
        batch_id = sign.b64u_decode(batch.batch_id)
        existing = (
            await session.execute(
                select(Batch.batch_id).where(Batch.node_id == caller.node_id, Batch.day == day)
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing == batch_id:
                return reply(
                    request,
                    ctx,
                    200,
                    {
                        "accepted": dict.fromkeys(("sources", "payloads", "c2", "files"), 0),
                        "rejected": {},
                        "duplicate": True,
                    },
                )
            raise ProtoError("invalid_payload", "day already submitted")
        # Payload links count only from eligible nodes (security review M3), checked before
        # this batch is stored so that it cannot make its own sender eligible.
        link_ok = not caller.suspended and await consensus.is_eligible(
            session, ctx.settings, ctx.today(), caller.node_id
        )
        never = await ctx.never.get(session)
        links: set[tuple[str, str, str]] = set()
        rows, accepted, rejected = build_rows(batch, never, links)
        cap = ctx.settings.new_values_per_day
        if len(rows) > cap:
            rejected["cap"] = len(rows) - cap
            rows = rows[:cap]
        try:
            # The marker is stored for a suspended node too, so suspension cannot be told apart
            # from the outside (a second batch for the day answers the same way).
            session.add(Batch(node_id=caller.node_id, day=day, batch_id=batch_id, items=len(rows)))
            await session.flush()
            # A dormant member counts again from its next batch (hub/hub/dormant.py).
            await session.execute(
                update(Node)
                .where(Node.id == caller.node_id)
                .values(last_batch_day=func.greatest(func.coalesce(Node.last_batch_day, day), day))
            )
            if not caller.suspended:
                for i in range(0, len(rows), CHUNK):
                    chunk = [
                        {**r, "node_id": caller.node_id, "day": day} for r in rows[i : i + CHUNK]
                    ]
                    await session.execute(
                        pg_insert(Observation).values(chunk).on_conflict_do_nothing()
                    )
                # Which URLs a payload host served, and how many eligible nodes said so that day
                # (no node reference; one batch per node and day): the feeds drop a host once
                # every URL it served is down, acting only on links that k nodes asserted.
                if links and link_ok:
                    stmt = pg_insert(PayloadLink).values(
                        [
                            {"day": day, "kind": k, "value": h, "url_b": u, "nodes": 1}
                            for k, h, u in sorted(links)
                        ]
                    )
                    await session.execute(
                        stmt.on_conflict_do_update(
                            index_elements=["day", "kind", "value", "url_b"],
                            set_={"nodes": PayloadLink.nodes + 1},
                        )
                    )
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise ProtoError("invalid_payload", "day already submitted") from None
    out = models.BatchAccepted(accepted=accepted, rejected=rejected, duplicate=False)
    return reply(request, ctx, 200, out.model_dump(mode="json"))
