"""Calling ``fold_session_buckets``: what the writer and the sweep worker share.

The function is created by migration 0034 (see its docstring for what is folded and why it is safe)
and is the only way ingest merges ``sessions`` rows: ingest holds EXECUTE on it and still has no
DELETE. This module picks the buckets worth asking about and makes the call; it decides nothing
about what is plain, the function does.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ARRAY, DateTime, Text, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_common import Event

from ingest.floods.config import FoldSettings
from ingest.floods.gate import FloodGate

log = logging.getLogger(__name__)

#: (source address, sensor, UTC hour): the unit the function folds.
Bucket = tuple[str, str, datetime]

#: Rows folded per call from the writer. The function clamps any limit to 1..5000.
WRITER_LIMIT = 1000
#: Most buckets of one call (the function accepts 5000).
MAX_BUCKETS = 500
LOG_INTERVAL_S = 60.0
#: A session with this many login attempts or more is never plain (the credential-list campaign
#: threshold); the function checks it too.
MAX_PLAIN_LOGINS = 20

_FOLD = text(
    """
    SELECT fold_session_buckets(
        CAST(CAST(:src AS text[]) AS inet[]), :sensor, :hour, :min, :tags,
        make_interval(mins => :idle), :lim)
    """
).bindparams(
    bindparam("src", type_=ARRAY(Text)),
    bindparam("sensor", type_=ARRAY(Text)),
    bindparam("hour", type_=ARRAY(DateTime(timezone=True))),
    bindparam("tags", type_=ARRAY(Text)),
)


def hour_of(ts: datetime) -> datetime:
    """The UTC hour that contains ``ts``."""
    return ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def is_demo(data: Mapping[str, Any]) -> bool:
    """The same flag the database function reads (``data.demo``), read the cautious way."""
    return str(data.get("demo")).lower() == "true"


@dataclass(slots=True)
class FloodFold:
    """The fold settings, the plain tags and the in-memory gate, shared by the writer."""

    settings: FoldSettings
    plain_tags: frozenset[str]
    gate: FloodGate = field(default_factory=FloodGate)
    calls: int = 0
    folded: int = 0

    @classmethod
    def build(cls, settings: FoldSettings, plain_tags: frozenset[str]) -> FloodFold:
        return cls(settings, plain_tags, FloodGate(threshold=settings.min_connections))

    def record(self, events: Iterable[Event]) -> set[tuple[str, str, int]]:
        """Count the batch's connections in the gate. Returns the (address, sensor, hour) of every
        demo event: such an hour never folds, so it is not worth a call."""
        demo: set[tuple[str, str, int]] = set()
        for ev in events:
            ip, sensor = str(ev.src_ip), str(ev.sensor)
            if is_demo(ev.data):
                demo.add((ip, sensor, int(hour_of(ev.ts).timestamp())))
            elif str(ev.type) == "connect":
                self.gate.record(ip, sensor, ev.ts)
        return demo

    def buckets(
        self, rows: Iterable[Any], demo: Collection[tuple[str, str, int]] = ()
    ) -> list[Bucket]:
        """The buckets of the upserted ``rows`` (the writer's RETURNING rows) worth a call: a
        closed connection that looks plain, from a source the gate calls hot."""
        found: dict[tuple[str, str, int], Bucket] = {}
        for r in rows:
            if not looks_plain(r, self.plain_tags) or r.ended_at is None:
                continue
            ip, sensor = str(r.src_ip), str(r.sensor)
            hour = hour_of(r.started_at)
            key = (ip, sensor, int(hour.timestamp()))
            if key in found or key in demo or not self.gate.is_hot(ip, sensor, r.last_event_at):
                continue
            found[key] = (ip, sensor, hour)
        return sorted(found.values(), key=lambda b: (b[2], b[0], b[1]))[:MAX_BUCKETS]


def looks_plain(row: Any, plain_tags: frozenset[str]) -> bool:
    """A cheap pre-check of one upserted row, mirroring the function's tests that the row itself
    answers (the rest, a campaign or an indicator link, is read by the function)."""
    return (
        not row.benign
        and row.scanner_name is None
        and not row.login_success
        and row.commands == 0
        and row.downloads == 0
        and row.http_requests == 0
        and row.login_attempts < MAX_PLAIN_LOGINS
        and set(row.tags or ()) <= plain_tags
    )


async def fold_buckets(
    session: AsyncSession,
    buckets: Sequence[Bucket],
    settings: FoldSettings,
    plain_tags: Iterable[str],
    *,
    limit: int,
) -> int:
    """Ask the database to fold ``buckets``; returns the connections folded (0 when the advisory
    lock is held by another caller)."""
    if not buckets:
        return 0
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
            },
        )
    ).scalar_one()
    return int(n or 0)


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
