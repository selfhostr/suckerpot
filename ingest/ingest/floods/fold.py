"""Calling ``fold_session_buckets`` and ``restore_folded_sessions``: what the writer and the sweep
worker share.

The functions are created by migration 0034 (see its comments for what is folded and why it is
safe) and are the only way ingest merges ``sessions`` rows or gives one back: ingest holds EXECUTE
on them and still has no DELETE. This module picks the buckets worth asking about and makes the
calls; it decides nothing about what is plain, the function does.

Folding is housekeeping, so the writer bounds it: each call runs under a short statement timeout
inside a savepoint, a bucket is asked about at most once a minute, and after a timeout the writer
stops asking for a while (doubling up to a quarter of an hour).
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import OrderedDict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import ARRAY, DateTime, Integer, Text, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_common import Event

from ingest.aggregate import client_tool_of
from ingest.floods.config import FoldSettings
from ingest.floods.gate import FloodGate

if TYPE_CHECKING:
    from ingest.attack.mapping import AttackMap
    from ingest.tagging import RuleSet

log = logging.getLogger(__name__)

#: (source address, sensor, UTC hour): the unit the function folds.
Bucket = tuple[str, str, datetime]
BucketKey = tuple[str, str, int]

#: Rows folded per call from the writer. The function clamps any limit to 1..5000.
WRITER_LIMIT = 1000
#: Most buckets of one call (the function accepts 5000).
MAX_BUCKETS = 500
#: The writer's calls give up after this long; ingest's own statement timeout is 30 s.
WRITER_TIMEOUT_MS = 2000
#: The writer asks about one bucket at most once in this many seconds.
WRITER_EVERY_S = 60.0
#: Most buckets remembered as asked (older ones are forgotten first).
MAX_ASKED = 50_000
#: After a timeout the writer stops folding this long, doubling up to BACKOFF_MAX_S.
BACKOFF_S = 60.0
BACKOFF_MAX_S = 900.0
#: SQLSTATE of a statement cancelled by statement_timeout.
QUERY_CANCELED = "57014"
LOG_INTERVAL_S = 60.0
#: A session with this many login attempts or more is never plain (the credential-list campaign
#: threshold); the function checks it too.
MAX_PLAIN_LOGINS = 20
#: Events a plain connection may hold besides its login attempts (connect, disconnect, the
#: handshake recorded as a scan; SIP adds its first message and a summary). Migration 0034 checks
#: the same numbers.
EXTRA_EVENTS = 3
EXTRA_EVENTS_BY_SENSOR: Mapping[str, int] = {"sip": 4}

_FOLD = text(
    """
    SELECT fold_session_buckets(
        CAST(CAST(:src AS text[]) AS inet[]), :sensor, :hour, :min, :tags,
        make_interval(mins => :idle), :lim, :now)
    """
).bindparams(
    bindparam("src", type_=ARRAY(Text)),
    bindparam("sensor", type_=ARRAY(Text)),
    bindparam("hour", type_=ARRAY(DateTime(timezone=True))),
    bindparam("tags", type_=ARRAY(Text)),
    bindparam("now", type_=DateTime(timezone=True)),
)
_RESTORE = text("SELECT restore_folded_sessions(CAST(:conns AS jsonb))")
#: The events a connection had before its new row started: the same filters and limit as
#: restore_folded_sessions (one day back, at most 1000), so both read the same events.
_EARLY = text(
    """
    SELECT r.id AS session_id, e.ts, e.type, e.data, e.tags, e.techniques, e.known_scanner,
           e.abuse_score
    FROM unnest(CAST(:ids AS text[]), CAST(:sensors AS text[]),
                CAST(CAST(:ips AS text[]) AS inet[]), CAST(:ports AS integer[]),
                CAST(:starts AS timestamptz[])) AS r(id, sensor, ip, port, started)
    CROSS JOIN LATERAL (
        SELECT ev.ts, ev.type, ev.data, ev.tags, ev.techniques, ev.known_scanner, ev.abuse_score
        FROM events ev
        WHERE ev.session_id = r.id AND ev.sensor = r.sensor AND ev.src_ip = r.ip
          AND ev.dst_port = r.port
          AND ev.ts >= r.started - interval '1 day' AND ev.ts < r.started
          AND ev.ts >= CAST(:lo AS timestamptz) - interval '1 day'
          AND ev.ts < CAST(:hi AS timestamptz)
        ORDER BY ev.ts
        LIMIT 1000
    ) e
    ORDER BY r.id, e.ts
    """
).bindparams(
    bindparam("ids", type_=ARRAY(Text)),
    bindparam("sensors", type_=ARRAY(Text)),
    bindparam("ips", type_=ARRAY(Text)),
    bindparam("ports", type_=ARRAY(Integer)),
    bindparam("starts", type_=ARRAY(DateTime(timezone=True))),
    bindparam("lo", type_=DateTime(timezone=True)),
    bindparam("hi", type_=DateTime(timezone=True)),
)


def hour_of(ts: datetime) -> datetime:
    """The UTC hour that contains ``ts``."""
    return ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def is_demo(data: Mapping[str, Any]) -> bool:
    """The same flag the database function reads (``data.demo``), read the cautious way."""
    return str(data.get("demo")).lower() == "true"


def stored_until(events: Iterable[Event]) -> datetime | None:
    """How far a batch takes its stream: its newest event, never later than now."""
    newest = max((ev.ts for ev in events), default=None)
    return None if newest is None else min(newest, datetime.now(UTC))


def extra_events(sensor: str) -> int:
    return EXTRA_EVENTS_BY_SENSOR.get(sensor, EXTRA_EVENTS)


@dataclass(slots=True)
class FloodFold:
    """The fold settings, the plain tags, the in-memory gate and the writer's pacing."""

    settings: FoldSettings
    plain_tags: frozenset[str]
    gate: FloodGate = field(default_factory=FloodGate)
    calls: int = 0
    folded: int = 0
    timeouts: int = 0
    timeout_ms: int = WRITER_TIMEOUT_MS
    every_s: float = WRITER_EVERY_S
    clock: Callable[[], float] = time.monotonic
    _asked: OrderedDict[BucketKey, float] = field(default_factory=OrderedDict)
    _paused_until: float = -math.inf
    _backoff_s: float = BACKOFF_S

    @classmethod
    def build(
        cls,
        settings: FoldSettings,
        plain_tags: frozenset[str],
        clock: Callable[[], float] = time.monotonic,
    ) -> FloodFold:
        return cls(settings, plain_tags, FloodGate(threshold=settings.min_connections), clock=clock)

    def record(self, events: Iterable[Event]) -> set[BucketKey]:
        """Count the batch's connections in the gate. Returns the (address, sensor, hour) of every
        demo event: the function leaves a demo connection alone anyway, so such a bucket is not
        worth a call from this batch."""
        demo: set[BucketKey] = set()
        for ev in events:
            ip, sensor = str(ev.src_ip), str(ev.sensor)
            if is_demo(ev.data):
                demo.add((ip, sensor, int(hour_of(ev.ts).timestamp())))
            elif str(ev.type) == "connect":
                self.gate.record(ip, sensor, ev.ts)
        return demo

    def buckets(self, rows: Iterable[Any], demo: Collection[BucketKey] = ()) -> list[Bucket]:
        """The buckets of the upserted ``rows`` (the writer's RETURNING rows) worth a call: a
        closed connection that looks plain, from a source the gate calls hot, in a bucket not
        asked about in the last ``every_s`` seconds. Does not mark them asked."""
        found: dict[BucketKey, Bucket] = {}
        now = self.clock()
        for r in rows:
            if not looks_plain(r, self.plain_tags) or r.ended_at is None:
                continue
            ip, sensor = str(r.src_ip), str(r.sensor)
            hour = hour_of(r.started_at)
            key = (ip, sensor, int(hour.timestamp()))
            if key in found or key in demo or now - self._asked.get(key, -math.inf) < self.every_s:
                continue
            if not self.gate.is_hot(ip, sensor, r.last_event_at):
                continue
            found[key] = (ip, sensor, hour)
        return sorted(found.values(), key=lambda b: (b[2], b[0], b[1]))[:MAX_BUCKETS]

    def mark_asked(self, buckets: Iterable[Bucket]) -> None:
        now = self.clock()
        for ip, sensor, hour in buckets:
            key = (ip, sensor, int(hour.timestamp()))
            self._asked[key] = now
            self._asked.move_to_end(key)
        horizon = now - self.every_s
        while self._asked and (
            len(self._asked) > MAX_ASKED or next(iter(self._asked.values())) < horizon
        ):
            self._asked.popitem(last=False)

    def paused(self) -> bool:
        """True while the writer waits out a timeout."""
        return self.clock() < self._paused_until

    def timed_out(self) -> None:
        self.timeouts += 1
        self._paused_until = self.clock() + self._backoff_s
        self._backoff_s = min(self._backoff_s * 2, BACKOFF_MAX_S)

    def succeeded(self) -> None:
        self._backoff_s = BACKOFF_S


def looks_plain(row: Any, plain_tags: frozenset[str]) -> bool:
    """A cheap pre-check of one upserted row, mirroring the function's tests that the row itself
    answers (the rest, a campaign, an indicator link or a demo event, is read by the function)."""
    return (
        not row.benign
        and row.scanner_name is None
        and not row.login_success
        and row.commands == 0
        and row.downloads == 0
        and row.http_requests == 0
        and row.login_attempts < MAX_PLAIN_LOGINS
        and row.event_count <= row.login_attempts + extra_events(str(row.sensor))
        and set(row.tags or ()) <= plain_tags
    )


async def cap_statements(session: AsyncSession, timeout_ms: int) -> str:
    """Cap every statement of this transaction at ``timeout_ms``; returns the cap it replaced.

    Run it inside a savepoint: if a capped statement fails, rolling the savepoint back puts the
    old cap back too. On success the caller restores it with :func:`restore_cap`.
    """
    old = await session.scalar(text("SELECT current_setting('statement_timeout')"))
    await session.execute(
        text("SELECT set_config('statement_timeout', :v, true)"), {"v": f"{int(timeout_ms)}ms"}
    )
    return str(old)


async def restore_cap(session: AsyncSession, old: str) -> None:
    await session.execute(text("SELECT set_config('statement_timeout', :v, true)"), {"v": old})


async def fold_buckets(
    session: AsyncSession,
    buckets: Sequence[Bucket],
    settings: FoldSettings,
    plain_tags: Iterable[str],
    *,
    limit: int,
    as_of: datetime | None,
    timeout_ms: int | None = None,
) -> int:
    """Ask the database to fold ``buckets``; returns the connections folded (0 when the advisory
    lock is held by another caller). ``as_of`` is how far the streams are stored (None: unknown,
    only connections that ended fold). With ``timeout_ms`` the call is capped and the previous
    cap restored afterwards; run it in a savepoint."""
    if not buckets:
        return 0
    old = await cap_statements(session, timeout_ms) if timeout_ms is not None else None
    n = (
        await session.execute(
            _FOLD,
            {
                "src": [b[0] for b in buckets],
                "sensor": [b[1] for b in buckets],
                "hour": [b[2] for b in buckets],
                "min": settings.min_connections,
                "tags": sorted(plain_tags),
                "idle": settings.idle_minutes,
                "lim": limit,
                "now": as_of,
            },
        )
    ).scalar_one()
    if old is not None:
        await restore_cap(session, old)
    return int(n or 0)


def folded_key(
    sensor: str, early: Sequence[Any], rules: RuleSet, attack: AttackMap | None
) -> dict[str, Any]:
    """The tags, techniques and client tool a connection carried when it was folded, from its
    earlier events (``early``, oldest first): what its row held, which is part of its group's key.

    The event tags and techniques are stored with the events; the session rules are evaluated again
    on the counters those events add up to, as the writer did after each batch, and their tags
    bring their techniques. The client tool is the last one the events named.
    """
    tags: set[str] = set()
    techniques: set[str] = set()
    tool: str | None = None
    known: bool | None = None
    score: int | None = None
    counts = {"login_attempt": 0, "command": 0, "download_attempt": 0, "http_request": 0}
    success = False
    for e in early:
        tags.update(e.tags or ())
        techniques.update(e.techniques or ())
        data = e.data if isinstance(e.data, dict) else {}
        tool = client_tool_of(sensor, data) or tool
        known = e.known_scanner if e.known_scanner is not None else known
        score = e.abuse_score if e.abuse_score is not None else score
        if e.type in counts:
            counts[e.type] += 1
        success = success or (e.type == "login_attempt" and data.get("success") is True)
    facts = {
        "session.sensor": sensor,
        "session.event_count": len(early),
        "session.login_attempts": counts["login_attempt"],
        "session.login_success": success,
        "session.commands": counts["command"],
        "session.downloads": counts["download_attempt"],
        "session.http_requests": counts["http_request"],
        "session.known_scanner": known,
        "session.abuse_score": score,
        "session.tags": sorted(tags),
    }
    new = set(rules.tag_session(facts)) - tags
    if new and attack is not None:
        techniques.update(attack.for_tags(sorted(new)))
    return {"tags": sorted(tags | new), "techniques": sorted(techniques), "tool": tool}


async def folded_keys(
    session: AsyncSession, rows: Sequence[Any], rules: RuleSet, attack: AttackMap | None
) -> list[dict[str, Any]]:
    """For the fresh ``rows`` (upserted, needing session_id, sensor, src_ip, dst_port,
    started_at) that have events from before their start: the id and the group key of each, for
    :func:`restore_folded`. A row with no earlier event (the normal case) is left out."""
    if not rows:
        return []
    starts = [r.started_at for r in rows]
    found = await session.execute(
        _EARLY,
        {
            "ids": [r.session_id for r in rows],
            "sensors": [str(r.sensor) for r in rows],
            "ips": [str(r.src_ip) for r in rows],
            "ports": [int(r.dst_port) for r in rows],
            "starts": starts,
            "lo": min(starts),
            "hi": max(starts),
        },
    )
    early: dict[str, list[Any]] = {}
    for e in found:
        early.setdefault(e.session_id, []).append(e)
    return [
        {"id": r.session_id, **folded_key(str(r.sensor), early[r.session_id], rules, attack)}
        for r in rows
        if r.session_id in early
    ]


async def restore_folded(
    session: AsyncSession, conns: Sequence[Mapping[str, Any]], *, timeout_ms: int | None = None
) -> list[str]:
    """Give folded connections that just got a late event their row back; returns their ids.
    ``conns`` come from :func:`folded_keys`. With ``timeout_ms`` the call is capped; run it in a
    savepoint."""
    if not conns:
        return []
    old = await cap_statements(session, timeout_ms) if timeout_ms is not None else None
    ids = list((await session.scalars(_RESTORE, {"conns": json.dumps(list(conns))})).all())
    if old is not None:
        await restore_cap(session, old)
    return [str(i) for i in ids]


class SkipLog:
    """One WARNING per minute at most, with the number of skips since the last one."""

    def __init__(self, what: str) -> None:
        self.what = what
        self.skips = 0
        self._logged = -LOG_INTERVAL_S

    def skipped(self, sqlstate: str) -> None:
        self.skips += 1
        now = time.monotonic()
        if now - self._logged >= LOG_INTERVAL_S:
            log.warning(
                "%s skipped %d time(s) in the last minute (SQLSTATE %s)",
                self.what,
                self.skips,
                sqlstate,
            )
            self.skips, self._logged = 0, now
