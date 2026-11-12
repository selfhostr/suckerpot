"""The fold sweep: merges the plain connections the writer did not (a flood already under way when
ingest started, connections that never sent a disconnect, the history from before flood groups).

One cycle every 60 s, in two parts, each with its own time budget:

1. a recent pass over the last three hours (and the current one);
2. until it is done, the backfill: it walks backwards from there, six hours per step, and keeps its
   place (``cursor``), its totals and ``done`` in ``system_status`` under ``session_fold``, so a
   restart resumes instead of starting over.

For each window it lists the (address, sensor, hour) buckets that hold a flood or continue one,
page by page, and calls ``fold_session_buckets`` on a page until a call folds nothing: one call
never chains into the next hour (a group created by this call is only seen by the next one), and a
call folds at most a few thousand rows. The function takes an advisory lock without waiting; to
tell "nothing left" from "someone else holds the lock" the sweep takes the same lock first (it is
re-entrant inside one transaction), and when it cannot, it waits a moment and tries again, then
leaves the window for the next cycle without moving the cursor.

Every statement of the sweep is capped (``SWEEP_TIMEOUT_MS``, under ingest's 30 s). After a timeout
the window is left for later, the next calls fold fewer rows and fewer buckets, and the sweep sits
out a few cycles (doubling up to half an hour); a cycle that finishes without one grows them back.
A connection with no disconnect is idle against how far the consumer has stored the streams
(``progress``), not the clock: while the consumer lags, or before it caught up once, only
connections that ended fold.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.locks import SESSION_FOLD

from ingest.features import FeatureSettings, FeatureWorker
from ingest.floods.config import FoldSettings
from ingest.floods.fold import (
    MAX_BUCKETS,
    QUERY_CANCELED,
    Bucket,
    SkipLog,
    cap_statements,
    fold_buckets,
    hour_of,
)

log = logging.getLogger(__name__)

STATUS_KEY = "session_fold"
RECENT_HOURS = 3
STEP_HOURS = 6
RECENT_BUDGET_S = 20.0
BACKFILL_BUDGET_S = 20.0
CALL_LIMIT = 2000  # rows folded per call (the function clamps to 5000)
MIN_CALL_LIMIT = 50
BUSY_RETRIES = 5
BUSY_PAUSE_S = 0.5
SWEEP_TIMEOUT_MS = 10_000
BACKOFF_S = 120.0
BACKOFF_MAX_S = 1800.0

# The buckets of a window that hold a flood (the source has at least ``min`` connections in the
# hour, folded or not) or continue one (a group of the hour before), and still have a connection
# of their own to fold. Keyset paging on (hour, sensor, address).
_BUCKETS = text(
    """
    WITH b AS (
        SELECT src_ip, sensor, date_trunc('hour', started_at, 'UTC') AS hr,
               coalesce(sum(connections), 0) AS n, bool_or(kind = 'session') AS single
        FROM sessions
        WHERE started_at >= :lo AND started_at < :hi
        GROUP BY src_ip, sensor, date_trunc('hour', started_at, 'UTC')
    )
    SELECT host(b.src_ip) AS ip, b.sensor, b.hr
    FROM b
    WHERE b.single
      AND (b.n >= :min
           OR EXISTS (SELECT 1 FROM sessions g
                      WHERE g.kind = 'burst' AND g.src_ip = b.src_ip AND g.sensor = b.sensor
                        AND g.started_at >= b.hr - interval '1 hour' AND g.started_at < b.hr))
      AND (CAST(:a_hr AS timestamptz) IS NULL
           OR (b.hr, b.sensor, b.src_ip)
              > (CAST(:a_hr AS timestamptz), CAST(:a_sensor AS text), CAST(:a_ip AS inet)))
    ORDER BY b.hr, b.sensor, b.src_ip
    LIMIT :n
    """
)


@dataclass(slots=True)
class FoldState:
    """What the backfill remembers between cycles and restarts."""

    cursor: datetime | None = None  # the backfill has covered everything at or after this hour
    done: bool = False
    folded: int = 0  # connections the backfill folded
    recent_folded: int = 0  # connections the recent passes folded

    def to_json(self) -> str:
        return json.dumps(
            {
                "cursor": self.cursor.isoformat() if self.cursor else None,
                "done": self.done,
                "folded": self.folded,
                "recent_folded": self.recent_folded,
            }
        )

    @classmethod
    def from_json(cls, raw: Any) -> FoldState:
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                return cls()
        if not isinstance(raw, dict):
            return cls()
        try:
            cursor = datetime.fromisoformat(raw["cursor"]) if raw.get("cursor") else None
            if cursor is not None and cursor.tzinfo is None:
                cursor = cursor.replace(tzinfo=UTC)
            return cls(
                cursor=cursor,
                done=bool(raw.get("done", False)),
                folded=max(0, int(raw.get("folded", 0))),
                recent_folded=max(0, int(raw.get("recent_folded", 0))),
            )
        except KeyError, ValueError, TypeError:
            return cls()


def _utcnow() -> datetime:
    return datetime.now(UTC)


class FoldWorker(FeatureWorker):
    name = "session_fold"
    interval_s = 60.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        *,
        fold: FoldSettings | None = None,
        plain_tags: frozenset[str] = frozenset(),
        clock: Callable[[], datetime] = _utcnow,
        recent_budget_s: float = RECENT_BUDGET_S,
        backfill_budget_s: float = BACKFILL_BUDGET_S,
        step: timedelta = timedelta(hours=STEP_HOURS),
        busy_pause_s: float = BUSY_PAUSE_S,
        progress: Callable[[], datetime | None] | None = None,
        timeout_ms: int = SWEEP_TIMEOUT_MS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.fold = fold or FoldSettings.from_env()
        super().__init__(settings, enabled=self.fold.enabled)
        self.factory = factory
        self.plain_tags = plain_tags
        self._clock = clock
        self._recent_budget_s = recent_budget_s
        self._backfill_budget_s = backfill_budget_s
        self._step = step
        self._busy_pause_s = busy_pause_s
        self._progress = progress
        self._timeout_ms = timeout_ms
        self._monotonic = monotonic
        self._skips = SkipLog("session fold sweep")
        self.state = FoldState()
        self.calls = 0
        self.busy = 0
        self.timeouts = 0
        self.limit = CALL_LIMIT
        self.page_size = MAX_BUCKETS
        self._timed_out = False
        self._paused_until = -math.inf
        self._backoff_s = BACKOFF_S

    def _db(self) -> AsyncSession:
        if self.factory is None:
            raise RuntimeError("the fold worker has no database")
        return self.factory()

    # ---- one cycle ---------------------------------------------------------------------------
    async def run_once(self) -> None:
        if self.factory is None or self._monotonic() < self._paused_until:
            return
        self._timed_out = False
        now = self._clock()
        top = hour_of(now) - timedelta(hours=RECENT_HOURS)
        recent, _ = await self._sweep(top, hour_of(now) + timedelta(hours=1), self._deadline("r"))
        state = await self._load()
        state.recent_folded += recent
        if not state.done and not self._timed_out:
            await self._backfill(state, top)
        elif recent:
            await self._save(state)
        self.state = state
        if self._timed_out:
            self._paused_until = self._monotonic() + self._backoff_s
            self._backoff_s = min(self._backoff_s * 2, BACKOFF_MAX_S)
        else:
            self._backoff_s = BACKOFF_S
            self.limit = min(self.limit * 2, CALL_LIMIT)
            self.page_size = min(self.page_size * 2, MAX_BUCKETS)

    def _timeout(self) -> None:
        """A statement hit the cap: smaller calls from now on, and a pause after this cycle."""
        self.timeouts += 1
        self._timed_out = True
        self.limit = max(self.limit // 2, MIN_CALL_LIMIT)
        self.page_size = max(self.page_size // 2, 1)

    def _deadline(self, which: str) -> float:
        budget = self._recent_budget_s if which == "r" else self._backfill_budget_s
        return time.monotonic() + budget

    async def _backfill(self, state: FoldState, top: datetime) -> None:
        deadline = self._deadline("b")
        floor = await self._oldest_hour()
        cursor = state.cursor or top
        while time.monotonic() < deadline:
            if floor is None or cursor <= floor:
                state.done = True
                break
            lo = max(cursor - self._step, floor)
            folded, complete = await self._sweep(lo, cursor, deadline)
            state.folded += folded
            if not complete:
                break  # out of time, the lock is busy or a timeout: the same window next cycle
            cursor = lo
            state.cursor = cursor
            await self._save(state)
        state.cursor = cursor
        await self._save(state)

    # ---- one window --------------------------------------------------------------------------
    async def _sweep(self, lo: datetime, hi: datetime, deadline: float) -> tuple[int, bool]:
        """Fold every flood bucket of ``[lo, hi)``. Returns (connections folded, whole window
        done); not done means out of time or the advisory lock stayed busy."""
        total = 0
        after: Bucket | None = None
        while True:
            if time.monotonic() >= deadline:
                return total, False
            page = await self._page(lo, hi, after)
            if page is None:
                return total, False
            if not page:
                return total, True
            while True:
                n = await self._call(page)
                if n is None:
                    return total, False
                if n == 0:
                    break
                total += n
                if time.monotonic() >= deadline:
                    return total, False
            after = page[-1]

    async def _page(self, lo: datetime, hi: datetime, after: Bucket | None) -> list[Bucket] | None:
        """The next page of buckets, or None when the read hit the cap."""
        try:
            async with self._db() as session, session.begin():
                await cap_statements(session, self._timeout_ms)
                rows = await session.execute(
                    _BUCKETS,
                    {
                        "lo": lo,
                        "hi": hi,
                        "min": self.fold.min_connections,
                        "a_hr": after[2] if after else None,
                        "a_sensor": after[1] if after else None,
                        "a_ip": after[0] if after else None,
                        "n": self.page_size,
                    },
                )
                return [(r.ip, r.sensor, r.hr) for r in rows]
        except DBAPIError as exc:
            if exc.connection_invalidated or _sqlstate(exc) != QUERY_CANCELED:
                raise
            self._timeout()
            self._skips.skipped(QUERY_CANCELED)
            return None

    async def _call(self, page: list[Bucket]) -> int | None:
        """One fold call in its own transaction. None: the lock stayed busy, the call hit the cap
        or it failed, so a result of 0 could not be trusted."""
        as_of = self._progress() if self._progress is not None else None
        for attempt in range(BUSY_RETRIES):
            try:
                async with self._db() as session, session.begin():
                    got = await session.scalar(
                        text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": SESSION_FOLD}
                    )
                    if got:
                        n = await fold_buckets(
                            session,
                            page,
                            self.fold,
                            self.plain_tags,
                            limit=self.limit,
                            as_of=as_of,
                            timeout_ms=self._timeout_ms,
                        )
                        self.calls += 1
                        return n
            except DBAPIError as exc:
                if exc.connection_invalidated:
                    raise
                if _sqlstate(exc) == QUERY_CANCELED:
                    self._timeout()
                self._skips.skipped(_sqlstate(exc))
                return None
            self.busy += 1
            if attempt + 1 < BUSY_RETRIES:
                await asyncio.sleep(self._busy_pause_s)
        return None

    # ---- state -------------------------------------------------------------------------------
    async def _oldest_hour(self) -> datetime | None:
        async with self._db() as session:
            oldest = await session.scalar(text("SELECT min(started_at) FROM sessions"))
        return hour_of(oldest) if oldest is not None else None

    async def _load(self) -> FoldState:
        async with self._db() as session:
            raw = await session.scalar(
                text("SELECT value FROM system_status WHERE key = :k"), {"k": STATUS_KEY}
            )
        return FoldState.from_json(raw)

    async def _save(self, state: FoldState) -> None:
        async with self._db() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO system_status (key, value, updated_at)
                    VALUES (:k, CAST(:v AS jsonb), now())
                    ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS jsonb), updated_at = now()
                    """
                ),
                {"k": STATUS_KEY, "v": state.to_json()},
            )

    async def status(self) -> dict[str, Any]:
        out = await super().status()
        if not self.enabled:
            return out
        out[self.name].update(
            done=self.state.done,
            folded=self.state.folded,
            recent_folded=self.state.recent_folded,
            calls=self.calls,
            busy=self.busy,
            timeouts=self.timeouts,
        )
        return out


def _sqlstate(exc: DBAPIError) -> str:
    return str(getattr(exc.orig, "sqlstate", None) or "unknown")
