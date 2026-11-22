"""Do reports make a difference? The node's effect measure (design M38 G1, section 3.6).

Read-only for both roles. The API reads the address-free views of migration 0039 only; it never
sees an address. The statistics and the sentences come from ``suckerpot_db.report_effect``, so the
Results card and ``just status`` say the same thing. Below the minimum (30 observed pairs and 10
discordant pairs) every share and bound is null: the dashboard has nothing to show but progress.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.report_effect import (
    HORIZONS,
    MIN_DISCORDANT,
    MIN_PAIRS,
    Cells,
    Effect,
    cells_sql,
    interval_text,
    sentence,
    summarize,
)

from api.deps import DbSession

router = APIRouter(tags=["takedown"])

DEFAULT_DAYS = 90


class EffectOut(BaseModel):
    horizon: int
    verdict: Literal["not_enough_data", "lower", "no_clear_difference", "higher"]
    pairs: int
    needed: int = MIN_PAIRS
    discordant: int
    needed_discordant: int = MIN_DISCORDANT
    # Shares 0 to 1 and the interval of the difference (-1 to 1); null below the minimum.
    seen_reported: float | None = None
    seen_control: float | None = None
    difference: float | None = None
    lo: float | None = None
    hi: float | None = None
    sentence: str
    interval: str | None = None


class MethodOut(BaseModel):
    """How this is measured: what was paired, and what was left out at this horizon."""

    pairs_made: int = 0
    tiers: dict[str, int] = {}
    waiting: int = 0  # the window is not over yet
    not_observed: int = 0
    control_reported: int = 0
    network_reported: int = 0
    unmatched: int = 0
    unmatched_reasons: dict[str, int] = {}
    holdout_pct: int = 0
    held_now: int = 0


class EffectResponse(BaseModel):
    since: datetime
    until: datetime
    available: bool  # the tables exist (migration 0039)
    running: bool  # the worker that runs the measure is on (with abuse reporting)
    effect: EffectOut
    method: MethodOut


def to_out(effect: Effect) -> EffectOut:
    return EffectOut(
        horizon=effect.horizon,
        verdict=effect.verdict,
        pairs=effect.pairs,
        discordant=effect.discordant,
        seen_reported=effect.seen_reported,
        seen_control=effect.seen_control,
        difference=effect.difference,
        lo=effect.lo,
        hi=effect.hi,
        sentence=sentence(effect),
        interval=interval_text(effect),
    )


async def _available(db: AsyncSession) -> bool:
    try:
        async with db.begin_nested():
            return bool(
                await db.scalar(
                    text("SELECT to_regclass('public.report_effect_summary') IS NOT NULL")
                )
            )
    except DBAPIError:
        return False


async def _worker(db: AsyncSession) -> tuple[bool, int]:
    """(measure worker on, holdout percentage) from the worker's published status."""
    row = (
        await db.execute(text("SELECT detail FROM enrichment_status WHERE name = 'report_effect'"))
    ).first()
    detail: dict[str, Any] = row.detail if row is not None and row.detail else {}
    try:
        pct = int(detail.get("holdout_pct") or 0)
    except TypeError, ValueError:
        pct = 0
    return bool(detail.get("enabled", False)), max(0, min(10, pct))


async def load_cells(db: AsyncSession, horizon: int, since: datetime, until: datetime) -> Cells:
    r = (await db.execute(text(cells_sql(horizon)), {"since": since, "until": until})).one()
    return Cells(int(r.a), int(r.b), int(r.c), int(r.d))


async def load_method(
    db: AsyncSession, horizon: int, since: datetime, until: datetime
) -> MethodOut:
    h = "30" if horizon == 30 else "7"
    out = MethodOut()
    rows = await db.execute(
        text(
            f"SELECT tier, frozen_{h}_at IS NULL AS waiting, excluded_{h} AS excluded, "  # noqa: S608
            "count(*) AS n FROM report_effect_summary "
            "WHERE index_at >= :since AND index_at < :until GROUP BY 1, 2, 3"
        ),
        {"since": since, "until": until},
    )
    tiers: dict[str, int] = {}
    for r in rows:
        n = int(r.n)
        out.pairs_made += n
        tiers[r.tier] = tiers.get(r.tier, 0) + n
        if r.waiting:
            out.waiting += n
        elif r.excluded == "not_observed":
            out.not_observed += n
        elif r.excluded == "control_reported":
            out.control_reported += n
        elif r.excluded == "network_reported":
            out.network_reported += n
    out.tiers = tiers
    reasons: dict[str, int] = {}
    for r in await db.execute(
        text(
            "SELECT reason, count(*) AS n FROM report_effect_unmatched_summary "
            "WHERE index_at >= :since AND index_at < :until GROUP BY reason"
        ),
        {"since": since, "until": until},
    ):
        reasons[r.reason] = int(r.n)
    out.unmatched_reasons = reasons
    out.unmatched = sum(reasons.values())
    out.held_now = int(
        await db.scalar(text("SELECT coalesce(held_now, 0) FROM abuse_holdout_summary")) or 0
    )
    return out


@router.get("/results/effect", response_model=EffectResponse)
async def results_effect(
    db: DbSession,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    horizon: Annotated[int, Query()] = 7,
) -> EffectResponse:
    """The effect at one horizon (7 or 30 days) for reports whose index time is in the period
    (default: the last 90 days). Only counts and shares: no address, ever."""
    if horizon not in HORIZONS:
        raise HTTPException(status_code=422, detail="horizon must be 7 or 30")
    end = _utc(until) or datetime.now(UTC)
    start = _utc(since) or end - timedelta(days=DEFAULT_DAYS)
    running, pct = await _worker(db)
    if not await _available(db):
        empty = summarize(Cells(), horizon)
        return EffectResponse(
            since=start, until=end, available=False, running=running,
            effect=to_out(empty), method=MethodOut(holdout_pct=pct),
        )  # fmt: skip
    cells = await load_cells(db, horizon, start, end)
    method = await load_method(db, horizon, start, end)
    method.holdout_pct = pct
    return EffectResponse(
        since=start,
        until=end,
        available=True,
        running=running,
        effect=to_out(summarize(cells, horizon)),
        method=method,
    )


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)
