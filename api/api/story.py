"""The home page's story: the last N hours in plain language, with the expert detail one click away.

``GET /api/v1/story`` returns a headline, a three-column funnel (where the visitors came from,
which door they knocked on, how far they got), a timeline for the scrubber and a handful of
notable sessions told step by step.

Every session counts once per column, in the deepest stage it reached, so the funnel conserves
its flows. Plain text (``headline``, ``label``, ``title``, ``summary``, ``plain``) is built from
templates and counts only. Strings an attacker controls (commands, URLs, usernames, passwords,
paths) appear only in ``technical`` fields, cut to 200 characters.

Every query is bounded: a ``started_at`` range on ``sessions`` (or a ``ts`` range on the events
hypertable), a GROUP BY and a LIMIT. The whole route reads one REPEATABLE READ snapshot under a
statement timeout, and the answer is cached for 30 seconds per variant.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from sqlalchemy import Integer, case, cast, func, or_, select, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.sqltypes import Text
from suckerpot_db.event_bounds import SLACK
from suckerpot_db.models import AttackTechniqueRow, CampaignRow, EventRow, SessionRow

from api.benign import IncludeBenign, visible_sessions
from api.country_names import country_name
from api.deps import DbSession
from api.sensors import SENSOR_LABELS
from api.today import plural

router = APIRouter(tags=["story"])

DEFAULT_HOURS = 24
MAX_HOURS = 168
STATEMENT_TIMEOUT_MS = 3000
CACHE_SECONDS = 30.0
MAX_CACHED = 64
CacheKey = tuple[int, bool]

TOP_ORIGINS = 6
MAX_STORIES = 5
MIN_STORIES = 3
MAX_STEPS = 12
MAX_CANDIDATES = 120
CANDIDATES_PER_GROUP = 3
MAX_EVENTS_PER_SESSION = 500
GUESS_PAIRS = 3
MAX_TECHNICAL = 200
SHORT_BUCKET_HOURS = 6
MAX_GROUP_ROWS = 20000

Stage = Literal["looked", "guessed", "got_in", "commands", "download", "exploit"]
#: From the shallowest to the deepest step a session can reach.
STAGES: tuple[Stage, ...] = ("looked", "guessed", "got_in", "commands", "download", "exploit")
STAGE_RANK: dict[str, int] = {s: i for i, s in enumerate(STAGES)}
#: Tags that mean an exploit payload arrived (CVE signatures, command-execution and ransom
#: attacks). ``bluekeep`` is left out on purpose: that probe sends no payload.
EXPLOIT_TAGS: tuple[str, ...] = (
    "php2shell",
    "sql-rce",
    "eternalblue",
    "container-escape",
    "redis-rogue-master",
    "db-ransom",
    "synology-exploit",
    "c3rb3r",
)
#: Tags that mean a program was fetched or pushed, besides the ``download_attempt`` events.
DOWNLOAD_TAGS: tuple[str, ...] = ("malware-drop",)
#: Stages that count as severe in the timeline.
SEVERE_STAGES = frozenset({"download", "exploit"})

STAGE_LABELS: dict[str, str] = {
    "looked": "Only looked around",
    "guessed": "Guessed passwords",
    "got_in": "Got in",
    "commands": "Ran commands",
    "download": "Tried to install a program",
    "exploit": "Sent an exploit",
}
STAGE_TECHNICAL: dict[str, str] = {
    "looked": "connect / scan / plain requests, no login attempt",
    "guessed": "login_attempt events, none succeeded",
    "got_in": "login succeeded, no command",
    "commands": "at least one command event",
    "download": "download_attempt event or malware-drop tag",
    "exploit": "exploit tag: " + ", ".join(EXPLOIT_TAGS),
}
SEVERITY_BY_STAGE: dict[str, str] = {
    "looked": "info",
    "guessed": "info",
    "got_in": "low",
    "commands": "medium",
    "download": "high",
    "exploit": "high",
}
#: How a tag names the visitor in a story title.
ACTOR_BY_TAG: tuple[tuple[str, str], ...] = (
    ("mirai", "A Mirai robot"),
    ("crypto-miner", "A crypto-miner robot"),
)
DEFAULT_ACTOR = "A robot"


# ---------------------------------------------------------------------------------- schemas


class FlowNode(BaseModel):
    id: str
    column: Literal["origin", "door", "stage"]
    key: str
    label: str
    technical: str
    sessions: int
    href: str


class FlowLink(BaseModel):
    source: str
    target: str
    value: int


class Flow(BaseModel):
    nodes: list[FlowNode]
    links: list[FlowLink]


class Totals(BaseModel):
    sessions: int
    sources: int
    countries: int
    guessed: int
    got_in: int
    ran_commands: int
    downloads: int
    exploits: int


class TimelineBucket(BaseModel):
    start: datetime
    sessions: int
    by_door: dict[str, int]
    by_stage: dict[str, int]
    severe: int


class StoryStep(BaseModel):
    ts: datetime
    kind: Literal[
        "connect", "scan", "guess", "login", "command", "download", "exploit", "disconnect"
    ]
    plain: str
    technical: str
    count: int


class StoryTechnique(BaseModel):
    id: str
    name: str


class StoryCampaign(BaseModel):
    id: int
    name: str


class StoryItem(BaseModel):
    session_id: str
    started_at: datetime
    ended_at: datetime
    src_ip: str
    country: str | None
    country_name: str | None
    asn: int | None
    org: str | None
    sensor: str
    stage: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    summary: str
    steps: list[StoryStep]
    tags: list[str]
    techniques: list[StoryTechnique]
    campaign: StoryCampaign | None
    href: str


class Story(BaseModel):
    as_of: datetime
    hours: int
    headline: str
    totals: Totals
    flow: Flow
    timeline: list[TimelineBucket]
    stories: list[StoryItem]


# ----------------------------------------------------------------------- pure: classification


def classify_stage(
    *,
    login_attempts: int,
    login_success: bool,
    commands: int,
    downloads: int,
    tags: Sequence[str],
) -> Stage:
    """The deepest step a session reached. Mirrors :func:`stage_expr`, the SQL version."""
    tagset = set(tags)
    if tagset & set(EXPLOIT_TAGS):
        return "exploit"
    if downloads > 0 or tagset & set(DOWNLOAD_TAGS):
        return "download"
    if commands > 0:
        return "commands"
    if login_success:
        return "got_in"
    if login_attempts > 0:
        return "guessed"
    return "looked"


def _tag_array(values: Sequence[str]) -> Any:
    return cast(list(values), ARRAY(Text))


def exploit_expr() -> Any:
    return SessionRow.tags.overlap(_tag_array(EXPLOIT_TAGS))


def download_expr() -> Any:
    return or_(SessionRow.downloads > 0, SessionRow.tags.overlap(_tag_array(DOWNLOAD_TAGS)))


def stage_expr() -> Any:
    """SQL twin of :func:`classify_stage`."""
    s = SessionRow
    return case(
        (exploit_expr(), "exploit"),
        (download_expr(), "download"),
        (s.commands > 0, "commands"),
        (s.login_success, "got_in"),
        (s.login_attempts > 0, "guessed"),
        else_="looked",
    )


def stage_rank_expr() -> Any:
    s = SessionRow
    return case(
        (exploit_expr(), 5),
        (download_expr(), 4),
        (s.commands > 0, 3),
        (s.login_success, 2),
        (s.login_attempts > 0, 1),
        else_=0,
    )


# --------------------------------------------------------------------------- pure: sentences


def clip(value: object, limit: int = MAX_TECHNICAL) -> str:
    """Attacker-controlled text, single-line and at most ``limit`` characters."""
    text_ = " ".join(str(value).split())
    return text_ if len(text_) <= limit else text_[: limit - 1] + "…"


def window_phrase(hours: int) -> str:
    if hours == 1:
        return "the last hour"
    return f"the last {hours} hours"


def mostly_phrase(stage_counts: dict[str, int]) -> str:
    """The second sentence of the headline: what most visitors did."""
    total = sum(stage_counts.values())
    if total == 0:
        return ""
    top = max(STAGES, key=lambda st: (stage_counts.get(st, 0), -STAGE_RANK[st]))
    if stage_counts.get(top, 0) * 2 < total:
        return "They did many different things."
    return {
        "looked": "Most only looked at the doors and left.",
        "guessed": "Most were robots guessing passwords.",
        "got_in": "Most guessed a password that worked, then left.",
        "commands": "Most got in and typed commands.",
        "download": "Most got in and tried to install a program.",
        "exploit": "Most tried to exploit a known flaw.",
    }[top]


def headline(hours: int, totals: Totals, stage_counts: dict[str, int]) -> str:
    window = window_phrase(hours)
    if totals.sessions == 0:
        return f"Nothing knocked on your doors in {window}."
    first = (
        f"In {window}, {plural(totals.sources, 'machine')} from "
        f"{plural(totals.countries, 'country', 'countries')} knocked on your doors "
        f"{totals.sessions:,} {'time' if totals.sessions == 1 else 'times'}."
    )
    parts = [first, mostly_phrase(stage_counts)]
    if totals.exploits:
        parts.append(f"{plural(totals.exploits, 'visitor')} sent an exploit.")
    if totals.downloads:
        parts.append(f"{totals.downloads:,} tried to install a program.")
    return " ".join(p for p in parts if p)


def duration_phrase(seconds: float) -> str:
    secs = max(0, round(seconds))
    if secs < 60:
        return f"{secs} second{'s' if secs != 1 else ''}"
    mins = round(secs / 60)
    if mins < 60:
        return f"{mins} minute{'s' if mins != 1 else ''}"
    hours = round(mins / 60)
    return f"{hours} hour{'s' if hours != 1 else ''}"


def actor_for(tags: Sequence[str]) -> str:
    for tag, actor in ACTOR_BY_TAG:
        if tag in tags:
            return actor
    return DEFAULT_ACTOR


def door_label(sensor: str) -> str:
    return SENSOR_LABELS.get(sensor, sensor.upper())


#: What a known attack was, as a verb phrase. Only templates, never attacker text.
WHAT_BY_TAG: tuple[tuple[str, str], ...] = (
    ("db-ransom", "tried to wipe a database and leave a ransom note"),
    ("sql-rce", "tried to make the database run its own commands"),
    ("php2shell", "tried to take over the web server through a flaw in PHP"),
    ("eternalblue", "tried to break in through EternalBlue, a Windows file-sharing flaw"),
    ("redis-rogue-master", "tried to make the Redis server load a malicious module"),
    ("container-escape", "tried to break out of a container"),
    ("synology-exploit", "tried to take over a Synology NAS through a flaw in its login"),
    ("c3rb3r", "tried to plant ransomware on a Synology NAS"),
)


def what_for(tags: Sequence[str]) -> str | None:
    for tag, what in WHAT_BY_TAG:
        if tag in tags:
            return what
    return None


def story_title(
    *, stage: str, sensor: str, tags: Sequence[str], login_success: bool, login_attempts: int
) -> str:
    actor = actor_for(tags)
    door = door_label(sensor)
    if stage == "exploit":
        what = what_for(tags)
        if what is not None:
            return f"{actor} {what} ({door} door)"
        return f"{actor} sent an exploit to the {door} door"
    if stage == "download":
        if login_success:
            return f"{actor} broke into the {door} door and tried to install a program"
        return f"{actor} tried to make the {door} door download a program"
    if stage == "commands":
        return f"{actor} got into the {door} door and ran commands"
    if stage == "got_in":
        return f"{actor} got into the {door} door but did nothing"
    if stage == "guessed":
        return f"{actor} tried {plural(login_attempts, 'password')} on the {door} door"
    return f"{actor} looked at the {door} door"


def story_summary(
    *,
    stage: str,
    country: str | None,
    login_attempts: int,
    login_success: bool,
    commands: int,
    downloads: int,
    seconds: float,
    tags: Sequence[str] = (),
) -> str:
    where = f"From {country_name(country)}. " if country else ""
    parts: list[str] = []
    if login_attempts:
        parts.append(f"guessed {plural(login_attempts, 'password')} in {duration_phrase(seconds)}")
    if login_success:
        parts.append("got in")
    if commands:
        parts.append(f"ran {plural(commands, 'command')}")
    if downloads or stage == "download":
        n = max(downloads, 1)
        parts.append(f"tried to download {plural(n, 'program')}")
    if stage == "exploit":
        parts.append(what_for(tags) or "sent an exploit")
    if not parts:
        return f"{where}It only looked around, then left."
    if len(parts) == 1:
        body = parts[0]
    else:
        body = ", ".join(parts[:-1]) + f", then {parts[-1]}"
    return f"{where}It {body}."


# --------------------------------------------------------------------------- pure: the steps


@dataclass
class RawEvent:
    ts: datetime
    type: str
    tags: Sequence[str] = ()
    username: str | None = None
    password: str | None = None
    success: bool = False
    command: str | None = None
    url: str | None = None
    path: str | None = None


@dataclass
class _Step:
    ts: datetime
    kind: str
    count: int = 0
    samples: Counter[str] = field(default_factory=Counter)
    ok: bool = False


STEP_KINDS = ("connect", "scan", "guess", "login", "command", "download", "exploit", "disconnect")
#: When a story has too many steps, the least telling kinds are dropped first.
DROP_ORDER = ("connect", "scan", "disconnect", "guess", "login", "command")


def step_kind(ev: RawEvent) -> str:
    if ev.type == "connect":
        return "connect"
    if ev.type == "disconnect":
        return "disconnect"
    if ev.type == "login_attempt":
        return "login" if ev.success else "guess"
    if ev.type == "command":
        return "command"
    if ev.type == "download_attempt":
        return "download"
    if ev.type == "http_request" and set(ev.tags) & set(EXPLOIT_TAGS):
        return "exploit"
    return "scan"


def _sample(ev: RawEvent, kind: str) -> str | None:
    if kind in ("guess", "login"):
        return clip(f"{ev.username or ''}/{ev.password or ''}", 80)
    if kind == "command":
        return clip(ev.command or "", 80) if ev.command else None
    if kind == "download":
        return clip(ev.url or ev.command or "", 120) if (ev.url or ev.command) else None
    if kind == "exploit":
        return clip(ev.path or "", 120) if ev.path else None
    if kind == "scan":
        return clip(ev.path or "", 80) if ev.path else None
    return None


def _plain(kind: str, n: int) -> str:
    one = n == 1
    return {
        "connect": "Knocked on the door",
        "scan": "Looked around" if one else f"Made {n:,} requests",
        "guess": "Tried a password" if one else f"Tried {n:,} passwords",
        "login": "Got in with a password that worked",
        "command": "Ran a command" if one else f"Ran {n:,} commands",
        "download": "Tried to download a program" if one else f"Tried to download {n:,} programs",
        "exploit": "Sent an exploit" if one else f"Sent {n:,} exploit requests",
        "disconnect": "Left",
    }[kind]


def _technical(step: _Step) -> str:
    event_name = {
        "connect": "connect",
        "scan": "http_request / scan",
        "guess": "login_attempt",
        "login": "login_attempt ok",
        "command": "command",
        "download": "download_attempt",
        "exploit": "http_request exploit",
        "disconnect": "disconnect",
    }[step.kind]
    base = f"{step.count:,} {event_name}"
    top = [s for s, _ in step.samples.most_common(3) if s]
    if not top:
        return base
    label = "top " if step.kind == "guess" else ""
    return clip(f"{base} · {label}{', '.join(top)}")


@dataclass
class GuessAggregate:
    """The failed login attempts of one session, summed up instead of listed."""

    count: int
    first_ts: datetime
    last_ts: datetime
    #: ``user/password`` pairs with how often they were tried (already truncated).
    top: Sequence[tuple[str, int]] = ()


def build_steps(
    events: Sequence[RawEvent], guesses: GuessAggregate | None = None
) -> list[StoryStep]:
    """Merge consecutive events of one kind, then keep at most ``MAX_STEPS`` steps.

    ``events`` holds everything but the failed login attempts, which come in as ``guesses`` and
    become one "guess" step placed at their first attempt.
    """
    steps: list[_Step] = []
    for ev in events:
        kind = step_kind(ev)
        if not steps or steps[-1].kind != kind:
            steps.append(_Step(ts=ev.ts, kind=kind))
        cur = steps[-1]
        cur.count += 1
        sample = _sample(ev, kind)
        if sample:
            cur.samples[sample] += 1
    if guesses is not None and guesses.count > 0:
        agg = _Step(ts=guesses.first_ts, kind="guess", count=guesses.count)
        for pair, n in guesses.top:
            agg.samples[pair] += n
        at = next((i for i, st in enumerate(steps) if st.ts > guesses.first_ts), len(steps))
        steps.insert(at, agg)
    for drop in DROP_ORDER:
        while len(steps) > MAX_STEPS and any(s.kind == drop for s in steps):
            steps.pop(next(i for i, s in enumerate(steps) if s.kind == drop))
    steps = steps[:MAX_STEPS]
    return [
        StoryStep(
            ts=s.ts,
            kind=s.kind,  # type: ignore[arg-type]
            plain=_plain(s.kind, s.count),
            technical=_technical(s),
            count=s.count,
        )
        for s in steps
    ]


# ------------------------------------------------------------------- pure: choosing the stories


@dataclass
class Candidate:
    session_id: str
    src_ip: str
    campaign_id: int | None
    stage_rank: int
    event_count: int
    started_at: datetime
    #: The door (sensor) the session knocked on.
    sensor: str = ""


MAX_PER_DOOR = 2


def _interest(c: Candidate) -> tuple[int, int, float]:
    return (-c.stage_rank, -c.event_count, -c.started_at.timestamp())


def select_stories(candidates: Sequence[Candidate], limit: int = MAX_STORIES) -> list[Candidate]:
    """A varied handful, the most interesting first.

    Deepest stage first, then most events, then most recent; one per address and campaign always.
    Variety comes first: one story per stage (deepest first), at most one per (door, stage) and
    two per door. Free slots are then filled in order of interest, relaxing the door and stage
    rules only when nothing else is left.
    """
    ordered = sorted(candidates, key=_interest)
    seen_ips: set[str] = set()
    seen_campaigns: set[int] = set()
    per_door: Counter[str] = Counter()
    door_stage: set[tuple[str, int]] = set()
    chosen: list[Candidate] = []

    def eligible(c: Candidate, strict: bool) -> bool:
        if c in chosen or c.src_ip in seen_ips:
            return False
        if c.campaign_id is not None and c.campaign_id in seen_campaigns:
            return False
        if strict and (
            per_door[c.sensor] >= MAX_PER_DOOR or (c.sensor, c.stage_rank) in door_stage
        ):
            return False
        return True

    def take(c: Candidate) -> None:
        chosen.append(c)
        seen_ips.add(c.src_ip)
        if c.campaign_id is not None:
            seen_campaigns.add(c.campaign_id)
        per_door[c.sensor] += 1
        door_stage.add((c.sensor, c.stage_rank))

    # 1. One story per stage, deepest first.
    for rank in sorted({c.stage_rank for c in ordered}, reverse=True):
        if len(chosen) == limit:
            break
        pick = next((c for c in ordered if c.stage_rank == rank and eligible(c, True)), None)
        if pick is not None:
            take(pick)
    # 2. Fill with the next most interesting, still varied; 3. then without the variety rules.
    for strict in (True, False):
        for c in ordered:
            if len(chosen) == limit:
                break
            if eligible(c, strict):
                take(c)
    return sorted(chosen, key=_interest)


def bucket_seconds(hours: int) -> int:
    return 900 if hours <= SHORT_BUCKET_HOURS else 3600


def bucket_starts(since: datetime, now: datetime, step: int) -> list[datetime]:
    first = int(since.timestamp()) // step * step
    last = int(now.timestamp()) // step * step
    return [datetime.fromtimestamp(t, UTC) for t in range(first, last + step, step)]


# ----------------------------------------------------------------------------- the route


def _cache(request: Request) -> dict[CacheKey, tuple[float, Story]]:
    cache: dict[CacheKey, tuple[float, Story]] | None = getattr(
        request.app.state, "story_cache", None
    )
    if cache is None:
        cache = {}
        request.app.state.story_cache = cache
    return cache


@router.get("/story", response_model=Story)
async def get_story(
    request: Request,
    session: DbSession,
    hours: Annotated[int, Query(ge=1, le=MAX_HOURS)] = DEFAULT_HOURS,
    include_benign: IncludeBenign = False,
) -> Story:
    """The page's story, computed at most once per 30 seconds per variant."""
    key: CacheKey = (hours, include_benign)
    cache = _cache(request)
    hit = cache.get(key)
    if hit is not None and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    # One snapshot and one time limit for the whole route (must be the first statements).
    await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
    await session.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))
    result = await _compute(session, hours, include_benign)
    now = time.monotonic()
    for k in [k for k, (t, _) in cache.items() if now - t >= CACHE_SECONDS]:
        del cache[k]
    if len(cache) < MAX_CACHED:
        cache[key] = (now, result)
    return result


async def _compute(session: AsyncSession, hours: int, include_benign: bool) -> Story:
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    s = SessionRow
    where = [s.started_at > since, s.started_at <= now, *visible_sessions(include_benign)]
    stage = stage_expr().label("stage")
    country = func.coalesce(s.country, "").label("country")

    # --- totals
    t = (
        await session.execute(
            select(
                func.count(),
                func.count(func.distinct(s.src_ip)),
                func.count(func.distinct(s.country)),
                func.count().filter(s.login_attempts > 0),
                func.count().filter(s.login_success),
                func.count().filter(s.commands > 0),
                func.count().filter(download_expr()),
                func.count().filter(exploit_expr()),
            ).where(*where)
        )
    ).one()
    totals = Totals(
        sessions=t[0],
        sources=t[1],
        countries=t[2],
        guessed=t[3],
        got_in=t[4],
        ran_commands=t[5],
        downloads=t[6],
        exploits=t[7],
    )

    # --- funnel rows: (country, sensor, stage) -> sessions
    groups = (
        await session.execute(
            select(country, s.sensor, stage, func.count())
            .where(*where)
            .group_by(country, s.sensor, stage)
            .limit(MAX_GROUP_ROWS)
        )
    ).all()
    by_country: Counter[str] = Counter()
    for c, _, _, n in groups:
        by_country[c] += n
    top = [c for c, _ in sorted(by_country.items(), key=lambda kv: (-kv[1], kv[0])) if c][
        :TOP_ORIGINS
    ]
    flow = await _flow(session, where, groups, by_country, top, totals)
    stage_counts: Counter[str] = Counter()
    for _, _, st, n in groups:
        stage_counts[st] += n

    # --- timeline
    timeline = await _timeline(session, where, since, now, hours)

    # --- stories
    stories = await _stories(session, where, now)

    return Story(
        as_of=now,
        hours=hours,
        headline=headline(hours, totals, dict(stage_counts)),
        totals=totals,
        flow=flow,
        timeline=timeline,
        stories=stories,
    )


async def _flow(
    session: AsyncSession,
    where: list[Any],
    groups: Sequence[Any],
    by_country: Counter[str],
    top: list[str],
    totals: Totals,
) -> Flow:
    s = SessionRow
    origin_of = {c: (f"origin:{c}" if c in top else "origin:other") for c in by_country}
    origin_links: Counter[tuple[str, str]] = Counter()
    door_links: Counter[tuple[str, str]] = Counter()
    door_counts: Counter[str] = Counter()
    stage_counts: Counter[str] = Counter()
    origin_counts: Counter[str] = Counter()
    for c, sensor, st, n in groups:
        origin_links[(origin_of[c], f"door:{sensor}")] += n
        door_links[(f"door:{sensor}", f"stage:{st}")] += n
        door_counts[sensor] += n
        stage_counts[st] += n
        origin_counts[origin_of[c]] += n

    # The expert line of each named origin: addresses and the busiest network.
    ips: dict[str, int] = {}
    best_asn: dict[str, tuple[int, int, str | None]] = {}
    if top:
        rows = (
            await session.execute(
                select(
                    s.country,
                    s.asn,
                    func.count(func.distinct(s.src_ip)),
                    func.count(),
                    func.max(s.org),
                )
                .where(*where, s.country.in_(top))
                .group_by(s.country, s.asn)
                .limit(MAX_GROUP_ROWS)
            )
        ).all()
        for c, asn, n_ips, n, org in rows:
            if c is None:  # country IN (...) never matches NULL; this narrows the type
                continue
            ips[c] = ips.get(c, 0) + n_ips
            if asn is not None and (c not in best_asn or n > best_asn[c][1]):
                best_asn[c] = (asn, n, org)

    nodes: list[FlowNode] = []
    for c in top:
        tech = f"ISO {c} · {plural(ips.get(c, 0), 'IP')}"
        if c in best_asn:
            asn, _, org = best_asn[c]
            tech += f" · top AS{asn}" + (f" {clip(org, 60)}" if org else "")
        nodes.append(
            FlowNode(
                id=f"origin:{c}",
                column="origin",
                key=c,
                label=country_name(c),
                technical=tech,
                sessions=origin_counts[f"origin:{c}"],
                href=f"/attacks?country={quote(c, safe='')}",
            )
        )
    if origin_counts.get("origin:other"):
        other_countries = max(totals.countries - len(top), 0)
        other_ips = max(totals.sources - sum(ips.values()), 0)
        nodes.append(
            FlowNode(
                id="origin:other",
                column="origin",
                key="other",
                label="Other places",
                technical=f"{plural(other_countries, 'country', 'countries')} · "
                f"{plural(other_ips, 'IP')}",
                sessions=origin_counts["origin:other"],
                href="/attacks",
            )
        )
    for sensor, n in sorted(door_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        nodes.append(
            FlowNode(
                id=f"door:{sensor}",
                column="door",
                key=sensor,
                label=door_label(sensor),
                technical=f"sensor {sensor} · {plural(n, 'session')}",
                sessions=n,
                href=f"/attacks?sensor={quote(sensor, safe='')}",
            )
        )
    for st in STAGES:
        if stage_counts.get(st):
            nodes.append(
                FlowNode(
                    id=f"stage:{st}",
                    column="stage",
                    key=st,
                    label=STAGE_LABELS[st],
                    technical=STAGE_TECHNICAL[st],
                    sessions=stage_counts[st],
                    href=f"/attacks?stage={st}",
                )
            )
    links = [
        FlowLink(source=a, target=b, value=v)
        for (a, b), v in sorted({**origin_links, **door_links}.items())
    ]
    return Flow(nodes=nodes, links=links)


async def _timeline(
    session: AsyncSession, where: list[Any], since: datetime, now: datetime, hours: int
) -> list[TimelineBucket]:
    s = SessionRow
    step = bucket_seconds(hours)
    bucket = (func.floor(func.extract("epoch", s.started_at) / step).cast(Integer) * step).label(
        "b"
    )
    rows = (
        await session.execute(
            select(bucket, s.sensor, stage_expr().label("stage"), func.count())
            .where(*where)
            .group_by(bucket, s.sensor, text("stage"))
            .limit(MAX_GROUP_ROWS)
        )
    ).all()
    doors: dict[int, Counter[str]] = defaultdict(Counter)
    stages: dict[int, Counter[str]] = defaultdict(Counter)
    for b, sensor, st, n in rows:
        doors[int(b)][sensor] += n
        stages[int(b)][st] += n
    out: list[TimelineBucket] = []
    for start in bucket_starts(since, now, step):
        key = int(start.timestamp())
        st_counts = stages.get(key, Counter())
        out.append(
            TimelineBucket(
                start=start,
                sessions=sum(st_counts.values()),
                by_door=dict(doors.get(key, {})),
                by_stage=dict(st_counts),
                severe=sum(n for st, n in st_counts.items() if st in SEVERE_STAGES),
            )
        )
    return out


async def _stories(session: AsyncSession, where: list[Any], now: datetime) -> list[StoryItem]:
    s = SessionRow
    rank = stage_rank_expr()
    pool = (
        select(
            s.session_id,
            func.host(s.src_ip).label("ip"),
            s.campaign_id,
            rank.label("rank"),
            s.event_count,
            s.started_at,
            s.ended_at,
            s.last_event_at,
            s.sensor,
            s.country,
            s.asn,
            s.org,
            s.login_attempts,
            s.login_success,
            s.commands,
            s.downloads,
            s.tags,
            s.techniques,
            func.row_number()
            .over(
                partition_by=(s.sensor, rank),
                order_by=(s.event_count.desc(), s.started_at.desc()),
            )
            .label("k"),
        )
        .where(*where)
        .subquery()
    )
    rows = (
        await session.execute(
            select(pool)
            .where(pool.c.k <= CANDIDATES_PER_GROUP)
            .order_by(pool.c.rank.desc(), pool.c.event_count.desc(), pool.c.started_at.desc())
            .limit(MAX_CANDIDATES)
        )
    ).all()
    chosen = select_stories(
        [
            Candidate(
                r.session_id, r.ip, r.campaign_id, r.rank, r.event_count, r.started_at, r.sensor
            )
            for r in rows
        ]
    )
    if not chosen:
        return []
    by_id = {r.session_id: r for r in rows}
    picked = [by_id[c.session_id] for c in chosen]
    events, guesses = await _events(session, picked, now)
    technique_ids = sorted({t for r in picked for t in r.techniques})
    names: dict[str, str] = {}
    if technique_ids:
        names = {
            i: n
            for i, n in (
                await session.execute(
                    select(AttackTechniqueRow.id, AttackTechniqueRow.name).where(
                        AttackTechniqueRow.id.in_(technique_ids)
                    )
                )
            ).all()
        }
    campaigns = await _campaigns(session, [r.campaign_id for r in picked if r.campaign_id])
    out: list[StoryItem] = []
    for r in picked:
        st = classify_stage(
            login_attempts=r.login_attempts,
            login_success=r.login_success,
            commands=r.commands,
            downloads=r.downloads,
            tags=r.tags,
        )
        ended = r.ended_at or r.last_event_at
        seconds = (ended - r.started_at).total_seconds()
        out.append(
            StoryItem(
                session_id=r.session_id,
                started_at=r.started_at,
                ended_at=ended,
                src_ip=r.ip,
                country=r.country,
                country_name=country_name(r.country) if r.country else None,
                asn=r.asn,
                org=clip(r.org, 60) if r.org else None,
                sensor=r.sensor,
                stage=st,
                severity=SEVERITY_BY_STAGE[st],  # type: ignore[arg-type]
                title=story_title(
                    stage=st,
                    sensor=r.sensor,
                    tags=r.tags,
                    login_success=r.login_success,
                    login_attempts=r.login_attempts,
                ),
                summary=story_summary(
                    stage=st,
                    country=r.country,
                    login_attempts=r.login_attempts,
                    login_success=r.login_success,
                    commands=r.commands,
                    downloads=r.downloads,
                    seconds=seconds,
                    tags=r.tags,
                ),
                steps=build_steps(events.get(r.session_id, []), guesses.get(r.session_id)),
                tags=list(r.tags),
                techniques=[
                    StoryTechnique(id=t, name=names[t]) for t in r.techniques if t in names
                ],
                campaign=campaigns.get(r.campaign_id) if r.campaign_id else None,
                href=f"/attacks/{quote(r.session_id, safe='')}",
            )
        )
    return out


async def _events(
    session: AsyncSession, picked: Sequence[Any], now: datetime
) -> tuple[dict[str, list[RawEvent]], dict[str, GuessAggregate]]:
    """Per chosen session: its events except failed logins, and those logins as an aggregate.

    A bot may try hundreds of passwords before the steps that matter, so the failed attempts are
    summed in SQL and never take room from the other events. When a session has more than
    ``MAX_EVENTS_PER_SESSION`` other events, the newest are kept (the deepest steps come last).
    """
    e = EventRow
    ids = [r.session_id for r in picked]
    first = min(r.started_at for r in picked) - timedelta(minutes=1)
    last = min(now, max(r.last_event_at for r in picked) + SLACK)
    window = (e.session_id.in_(ids), e.ts >= first, e.ts <= last)
    ok = e.data["success"].astext
    failed_login = (e.type == "login_attempt") & (ok.is_distinct_from("true"))
    rn = (
        func.row_number()
        .over(partition_by=e.session_id, order_by=(e.ts.desc(), e.id.desc()))
        .label("rn")
    )
    sub = (
        select(
            e.session_id,
            e.ts,
            e.type,
            e.tags,
            func.left(e.data["username"].astext, 80).label("username"),
            func.left(e.data["password"].astext, 80).label("password"),
            ok.label("success"),
            func.left(e.data["input"].astext, 120).label("command"),
            func.left(e.data["url"].astext, 200).label("url"),
            func.left(e.data["path"].astext, 200).label("path"),
            rn,
        )
        .where(*window, ~failed_login)
        .subquery()
    )
    rows = (
        await session.execute(
            select(sub)
            .where(sub.c.rn <= MAX_EVENTS_PER_SESSION)
            .order_by(sub.c.session_id, sub.c.ts)
            .limit(MAX_EVENTS_PER_SESSION * MAX_STORIES)
        )
    ).all()
    out: dict[str, list[RawEvent]] = defaultdict(list)
    for r in rows:
        out[r.session_id].append(
            RawEvent(
                ts=r.ts,
                type=r.type,
                tags=r.tags or [],
                username=r.username,
                password=r.password,
                success=r.success == "true",
                command=r.command,
                url=r.url,
                path=r.path,
            )
        )

    # The failed attempts: totals per session, then the most tried pairs.
    totals = (
        await session.execute(
            select(e.session_id, func.count(), func.min(e.ts), func.max(e.ts))
            .where(*window, failed_login)
            .group_by(e.session_id)
            .limit(MAX_STORIES * 2)
        )
    ).all()
    pairs = (
        select(
            e.session_id.label("sid"),
            func.left(e.data["username"].astext, 80).label("u"),
            func.left(e.data["password"].astext, 80).label("p"),
            func.count().label("n"),
        )
        .where(*window, failed_login)
        .group_by(e.session_id, text("u"), text("p"))
        .subquery()
    )
    ranked = select(
        pairs.c.sid,
        pairs.c.u,
        pairs.c.p,
        pairs.c.n,
        func.row_number()
        .over(partition_by=pairs.c.sid, order_by=(pairs.c.n.desc(), pairs.c.u, pairs.c.p))
        .label("k"),
    ).subquery()
    top_rows = (
        await session.execute(
            select(ranked.c.sid, ranked.c.u, ranked.c.p, ranked.c.n)
            .where(ranked.c.k <= GUESS_PAIRS)
            .order_by(ranked.c.sid, ranked.c.k)
        )
    ).all()
    top: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for sid, u, p, n in top_rows:
        top[sid].append((clip(f"{u or ''}/{p or ''}", 80), n))
    guesses = {
        sid: GuessAggregate(count=n, first_ts=lo, last_ts=hi, top=top.get(sid, []))
        for sid, n, lo, hi in totals
    }
    return out, guesses


async def _campaigns(session: AsyncSession, ids: list[int]) -> dict[int, StoryCampaign]:
    if not ids:
        return {}
    c = CampaignRow
    rows = (await session.execute(select(c.id, c.name).where(c.id.in_(ids)))).all()
    return {i: StoryCampaign(id=i, name=n) for i, n in rows}
