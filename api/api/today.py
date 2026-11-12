"""The Today page and the hidden-scanner count (M19).

``GET /api/v1/today`` answers "what do I need to know right now?" in up to five cards. Every card
is one plain-English sentence, at most three items and one action (a UI route with its filters).
The sentences are built here by small pure functions, so they are unit tested and the web UI only
lays them out. The cards read tables other features fill (campaigns, blocklist entries, the
service inventory); while those are empty a card says so instead of disappearing, except
"your exposure", which only exists once an inventory does.

The response is cached for a minute per app and ``include_benign`` value, because the page is the
home screen and the queries behind it (first-seen values over 90 days) are not free.

``GET /api/v1/stats/benign`` counts what the "hide research scanners" switch hides.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import (
    BlocklistEntryRow,
    CampaignRow,
    IndicatorRow,
    InventoryServiceRow,
    SessionRow,
)
from suckerpot_db.session_counts import sessions_count

from api.benign import IncludeBenign, visible_sessions
from api.deps import DbSession
from api.indicators import defang
from api.insights_rules import TAG_LABELS, TAG_SEVERITY
from api.sensors import SENSOR_LABELS
from api.trends import new_values

router = APIRouter(tags=["today"])

WINDOW = timedelta(hours=24)
NEW_WINDOW = timedelta(days=7)
MAX_ITEMS = 3
CACHE_SECONDS = 60.0
BLOCK_SCORE = 70
# One source of truth for what is severe: the insight rules' tag table.
SEVERE_TAGS = sorted(t for t, level in TAG_SEVERITY.items() if level == "severe")
NEW_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("asn", "network", "networks"),
    ("url", "URL", "URLs"),
    ("command", "command", "commands"),
    ("username", "username", "usernames"),
)

CardId = Literal["happened", "campaigns", "act", "new_week", "exposure"]
ItemKind = Literal["sensor", "country", "tag", "campaign", "host", "session", "service", "new"]


class TodayItem(BaseModel):
    kind: ItemKind
    #: The raw value (sensor key, country code, tag, id...): the web UI may dress it up.
    value: str
    label: str
    detail: str | None = None
    count: int | None = None
    to: str


class TodayAction(BaseModel):
    label: str
    to: str


class TodayCard(BaseModel):
    id: CardId
    sentence: str
    items: list[TodayItem]
    action: TodayAction
    #: Nothing to report: the sentence says so and the items are empty.
    empty: bool = False


class TodayResponse(BaseModel):
    generated_at: datetime
    window_hours: int
    #: Research-scanner sessions in the window that are left out (0 when they are included).
    hidden_benign: int
    cards: list[TodayCard]


class BenignCount(BaseModel):
    window_hours: int
    sessions: int
    sources: int


# --------------------------------------------------------------------------- sentences


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def trend_phrase(current: int, previous: int) -> str:
    """ ", 38% more than the day before" once the change is big enough to mean something."""
    if previous < 10 or current < 10:
        return ""
    if current >= 2 * previous:
        return f", {round(current / previous):,} times as many as the day before"
    change = round((current - previous) / previous * 100)
    if change >= 25:
        return f", {change:,}% more than the day before"
    if change <= -25:
        return f", {-change}% fewer than the day before"
    return ""


def happened_sentence(sessions: int, sources: int, with_commands: int, previous: int) -> str:
    if sessions == 0:
        return "No attacks reached your sensors in the last 24 hours."
    head = (
        f"{plural(sessions, 'attack')} came from {plural(sources, 'address', 'addresses')} "
        f"in the last 24 hours{trend_phrase(sessions, previous)}."
    )
    if with_commands:
        return f"{head} {plural(with_commands, 'session')} ran commands on a fake shell."
    return f"{head} None of them got as far as a shell."


def campaigns_sentence(new: int, active: int) -> str:
    if new:
        return (
            f"{plural(new, 'new campaign')} formed in the last 24 hours: "
            "several addresses reusing the same tools or servers."
        )
    if active:
        are = "is" if active == 1 else "are"
        return f"No new campaigns today, but {plural(active, 'campaign')} {are} still active."
    return "No campaign has been spotted yet. They appear when several addresses reuse a script."


def act_sentence(hosts: int, severe: int, blocklist_ips: int) -> str:
    if hosts:
        base = (
            f"{plural(hosts, 'server')} tried to hand malware to your sensors today. "
            "Block them on your firewall or web proxy."
        )
        if blocklist_ips:
            more = plural(blocklist_ips, "address", "addresses")
            return f"{base} {more} also scored high enough to block."
        return base
    if blocklist_ips:
        return (
            f"{plural(blocklist_ips, 'address', 'addresses')} scored high enough to block today. "
            "Add them to your firewall."
        )
    if severe:
        return (
            f"{plural(severe, 'session')} sent an exploit or tried to download malware, "
            "but no download server was seen."
        )
    return "Nothing urgent today: no malware downloads and no exploit payloads."


def new_week_sentence(counts: dict[str, int]) -> str:
    parts = [
        plural(counts[field], one, many) for field, one, many in NEW_FIELDS if counts.get(field)
    ]
    if not parts:
        return "Nothing new this week: every network, URL and command has been seen before."
    total = sum(counts.values())
    joined = parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])} and {parts[-1]}"
    return f"{plural(total, 'thing')} showed up for the first time this week: {joined}."


def exposure_sentence(listed: int, targeted: int, attacks: int) -> str:
    if targeted == 0:
        return f"None of the {plural(listed, 'service')} you listed was targeted today."
    return (
        f"Attackers went after {targeted} of the {plural(listed, 'service')} you listed today, "
        f"{plural(attacks, 'attack')} in all."
    )


# --------------------------------------------------------------------------- routes helpers


def attacks_link(**params: str) -> str:
    return "/attacks?" + urlencode(params) if params else "/attacks"


# --------------------------------------------------------------------------- the cards


async def _happened(db: AsyncSession, now: datetime, include_benign: bool) -> TodayCard:
    s = SessionRow
    vis = visible_sessions(include_benign)
    since = now - WINDOW
    row = (
        await db.execute(
            select(
                sessions_count().label("n"),
                func.count(func.distinct(s.src_ip)).label("ips"),
                sessions_count(s.commands > 0).label("cmds"),
            ).where(s.started_at >= since, *vis)
        )
    ).one()
    previous = int(
        await db.scalar(
            select(sessions_count()).where(
                s.started_at >= since - WINDOW, s.started_at < since, *vis
            )
        )
        or 0
    )
    items: list[TodayItem] = []
    if row.n:
        sensor = (
            await db.execute(
                select(s.sensor, sessions_count().label("n"))
                .where(s.started_at >= since, *vis)
                .group_by(s.sensor)
                .order_by(sessions_count().desc(), s.sensor)
                .limit(1)
            )
        ).first()
        country = (
            await db.execute(
                select(s.country, sessions_count().label("n"))
                .where(s.started_at >= since, s.country.is_not(None), *vis)
                .group_by(s.country)
                .order_by(sessions_count().desc(), s.country)
                .limit(1)
            )
        ).first()
        tag = (
            await db.execute(
                select(func.unnest(s.tags).label("tag_name"), sessions_count().label("n"))
                .where(s.started_at >= since, *vis)
                .group_by(func.unnest(s.tags))
                .order_by(sessions_count().desc(), func.unnest(s.tags))
                .limit(1)
            )
        ).first()
        if sensor is not None:
            items.append(
                TodayItem(
                    kind="sensor",
                    value=sensor.sensor,
                    label=f"Most targeted: {SENSOR_LABELS.get(sensor.sensor, sensor.sensor)}",
                    count=sensor.n,
                    to=attacks_link(sensor=sensor.sensor),
                )
            )
        if country is not None:
            items.append(
                TodayItem(
                    kind="country",
                    value=country.country,
                    label=f"Most active country: {country.country}",
                    count=country.n,
                    to="/attackers?" + urlencode({"country": country.country}),
                )
            )
        if tag is not None:
            items.append(
                TodayItem(
                    kind="tag",
                    value=tag.tag_name,
                    label=f"Most common behaviour: {TAG_LABELS.get(tag.tag_name, tag.tag_name)}",
                    count=tag.n,
                    to=attacks_link(tag=tag.tag_name),
                )
            )
    return TodayCard(
        id="happened",
        sentence=happened_sentence(row.n, row.ips, row.cmds, previous),
        items=items[:MAX_ITEMS],
        action=TodayAction(label="See all attacks", to="/attacks"),
        empty=row.n == 0,
    )


async def _campaigns(db: AsyncSession, now: datetime) -> TodayCard:
    c = CampaignRow
    new_where = (c.first_seen >= now - WINDOW, c.status != "merged")
    new = int(await db.scalar(select(func.count()).where(*new_where)) or 0)
    active = 0
    if not new:
        active = int(await db.scalar(select(func.count()).where(c.status == "active")) or 0)
    rows = (
        (
            await db.execute(
                select(c.id, c.name, c.sessions, c.sources)
                .where(*new_where)
                .order_by(c.sessions.desc(), c.id.desc())
                .limit(MAX_ITEMS)
            )
        ).all()
        if new
        else []
    )
    items = [
        TodayItem(
            kind="campaign",
            value=str(r.id),
            label=r.name[:120],
            detail=f"{plural(r.sessions, 'session')} from {plural(r.sources, 'source')}",
            count=r.sessions,
            to=f"/campaigns/{r.id}",
        )
        for r in rows
    ]
    return TodayCard(
        id="campaigns",
        sentence=campaigns_sentence(new, active),
        items=items,
        action=TodayAction(label="See all campaigns", to="/campaigns"),
        empty=new == 0,
    )


async def _act(db: AsyncSession, now: datetime, include_benign: bool) -> TodayCard:
    i, s = IndicatorRow, SessionRow
    since = now - WINDOW
    host_where = (i.role == "download_host", i.type.in_(("domain", "ip")), i.last_seen >= since)
    hosts = int(await db.scalar(select(func.count(i.id)).where(*host_where)) or 0)
    blocklist_ips = int(
        await db.scalar(
            select(func.count(BlocklistEntryRow.value)).where(
                BlocklistEntryRow.kind == "ip",
                BlocklistEntryRow.score >= BLOCK_SCORE,
                BlocklistEntryRow.benign.is_(False),
                BlocklistEntryRow.last_seen >= since,
            )
        )
        or 0
    )
    severe_where = (
        s.started_at >= since,
        (s.downloads > 0) | s.tags.overlap(SEVERE_TAGS),
        *visible_sessions(include_benign),
    )
    severe = int(await db.scalar(select(sessions_count()).where(*severe_where)) or 0)
    items: list[TodayItem] = []
    if hosts:
        for r in (
            await db.execute(
                select(i.id, i.type, i.value, i.sightings)
                .where(*host_where)
                .order_by(i.sightings.desc(), i.id.desc())
                .limit(MAX_ITEMS)
            )
        ).all():
            items.append(
                TodayItem(
                    kind="host",
                    value=str(r.id),
                    label=defang(r.type, r.value)[:120],
                    detail="Serves malware downloads",
                    count=r.sightings,
                    to="/infrastructure?" + urlencode({"indicator": r.id}),
                )
            )
    elif severe:
        for r in (
            await db.execute(
                select(s.session_id, func.host(s.src_ip).label("ip"), s.sensor, s.tags)
                .where(*severe_where)
                .order_by(s.started_at.desc(), s.session_id.desc())
                .limit(MAX_ITEMS)
            )
        ).all():
            hit = next((t for t in r.tags if t in SEVERE_TAGS), None)
            items.append(
                TodayItem(
                    kind="session",
                    value=r.session_id,
                    label=f"{r.ip} on {SENSOR_LABELS.get(r.sensor, r.sensor)}",
                    detail=TAG_LABELS.get(hit, hit) if hit else "Tried to download a file",
                    to=f"/attacks/{r.session_id}",
                )
            )
    return TodayCard(
        id="act",
        sentence=act_sentence(hosts, severe, blocklist_ips),
        items=items,
        action=TodayAction(label="Open the blocklists", to="/defend/blocklists"),
        empty=not (hosts or severe or blocklist_ips),
    )


async def _new_week(db: AsyncSession, now: datetime, include_benign: bool) -> TodayCard:
    until = now + timedelta(minutes=1)
    since = until - NEW_WINDOW
    found: dict[str, list[Any]] = {}
    for field, _, _ in NEW_FIELDS:
        found[field] = await new_values(
            db, field, since, until, MAX_ITEMS, include_benign=include_benign
        )
    counts = {field: len(items) for field, items in found.items()}
    # One item per kind first (variety), then the runners-up, at most three in all.
    ordered: list[tuple[str, Any]] = []
    for rank in range(MAX_ITEMS):
        for field, _, _ in NEW_FIELDS:
            if rank < len(found[field]):
                ordered.append((field, found[field][rank]))
    nouns = {field: one for field, one, _ in NEW_FIELDS}
    items = [
        TodayItem(
            kind="new",
            value=f"{field}:{item.value}"[:160],
            label=(f"AS{item.value}" if field == "asn" else item.value)[:120],
            detail=f"New {nouns[field]}",
            count=item.count,
            to="/trends?" + urlencode({"field": field, "days": 7}),
        )
        for field, item in ordered[:MAX_ITEMS]
    ]
    return TodayCard(
        id="new_week",
        sentence=new_week_sentence(counts),
        items=items,
        action=TodayAction(label="See what is new", to="/trends?field=url&days=7"),
        empty=not any(counts.values()),
    )


async def _exposure(db: AsyncSession, now: datetime, include_benign: bool) -> TodayCard | None:
    inv = InventoryServiceRow
    services = (
        await db.execute(select(inv.name, inv.service, inv.product, inv.version, inv.exposure))
    ).all()
    if not services:
        return None
    s = SessionRow
    per_sensor = {
        r.sensor: r.n
        for r in (
            await db.execute(
                select(s.sensor, sessions_count().label("n"))
                .where(s.started_at >= now - WINDOW, *visible_sessions(include_benign))
                .group_by(s.sensor)
            )
        ).all()
    }
    hit = sorted(
        (x for x in services if per_sensor.get(x.service)),
        key=lambda x: (-per_sensor[x.service], x.name),
    )
    attacks = sum(per_sensor[x.service] for x in hit)
    items = [
        TodayItem(
            kind="service",
            value=x.service,
            label=x.name[:120],
            detail=" ".join(p for p in (x.product, x.version) if p) or x.exposure,
            count=per_sensor[x.service],
            to=attacks_link(sensor=x.service),
        )
        for x in hit[:MAX_ITEMS]
    ]
    return TodayCard(
        id="exposure",
        sentence=exposure_sentence(len(services), len(hit), attacks),
        items=items,
        action=TodayAction(label="Open your exposure", to="/defend/exposure"),
        empty=not hit,
    )


async def build_today(db: AsyncSession, now: datetime, *, include_benign: bool) -> TodayResponse:
    cards: list[TodayCard | None] = [
        await _happened(db, now, include_benign),
        await _campaigns(db, now),
        await _act(db, now, include_benign),
        await _new_week(db, now, include_benign),
        await _exposure(db, now, include_benign),
    ]
    hidden = 0
    if not include_benign:
        hidden = int(
            await db.scalar(
                select(sessions_count()).where(
                    SessionRow.started_at >= now - WINDOW, SessionRow.benign
                )
            )
            or 0
        )
    return TodayResponse(
        generated_at=now,
        window_hours=24,
        hidden_benign=hidden,
        cards=[c for c in cards if c is not None],
    )


def _cache(request: Request) -> dict[bool, tuple[float, TodayResponse]]:
    cache: dict[bool, tuple[float, TodayResponse]] | None = getattr(
        request.app.state, "today_cache", None
    )
    if cache is None:
        cache = {}
        request.app.state.today_cache = cache
    return cache


@router.get("/today", response_model=TodayResponse)
async def today(
    request: Request, db: DbSession, include_benign: IncludeBenign = False
) -> TodayResponse:
    cache = _cache(request)
    hit = cache.get(include_benign)
    if hit is not None and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    result = await build_today(db, datetime.now(UTC), include_benign=include_benign)
    cache[include_benign] = (time.monotonic(), result)
    return result


@router.get("/stats/benign", response_model=BenignCount)
async def benign_count(db: DbSession) -> BenignCount:
    """Research-scanner sessions and addresses in the last 24 hours (what the switch hides)."""
    s = SessionRow
    row = (
        await db.execute(
            select(sessions_count(), func.count(func.distinct(s.src_ip))).where(
                s.started_at >= datetime.now(UTC) - WINDOW, s.benign
            )
        )
    ).one()
    return BenignCount(window_hours=24, sessions=row[0], sources=row[1])


__all__ = ["build_today", "router"]
