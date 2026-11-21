"""Dormant members and freed pseudonyms (2026-11-21 field report).

**Dormant (a counting rule only).** A node is dormant when it enrolled more than ``GHOST_DAYS``
ago and never sent a batch, or when its last accepted batch is more than ``DORMANT_DAYS`` old.
Dormant nodes are kept (nothing is deleted here; retention still drops a node with no request for
30 days) but they are left out of the member counts and lists: the network summary, the public
feed statistics and the observatory. The counted (non-dormant) set is a snapshot taken once per
ISO week, for ``count_ref`` (a Monday), and stored in ``hub_count_snapshot`` (hub-internal, kept
five weeks). Members and countries are counted from that snapshot all week, so a single node's
batches cannot move a published count (a country at the k = 3 edge) from one day to the next. A
node enrolled after the snapshot was taken counts as a new member, as before. A dormant node that
sends again counts again from the next snapshot.

The last batch day is the later of ``nodes.last_batch_day`` (kept beyond the 14 days of batch
markers) and the newest marker in ``batches``.

**Freed pseudonyms.** A pseudonym is unique among nodes. A node that ever sent an accepted batch
never loses its name. The name of a node that NEVER sent a batch (a reinstall leaves such a ghost
behind) is freed for a new or renaming node when that holder has been silent for
``NAME_SILENT_DAYS`` of the hub's served days: UTC days after its ``last_active_day`` (the day of
its last authenticated request) and before today on which the hub API served authenticated
requests and its address limiter did not block a large share of them (``hub_served_days``
counts both per day: ``clean_day``). A hub outage, or a day with many blocked requests (a shared
exit under a block, an attack), never counts as the holder's silence: it only delays the release.
"""

from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto import buckets

GHOST_DAYS = 7
DORMANT_DAYS = 30
# A batch day is settled (no batch for it can arrive any more) this many days later.
SETTLE_DAYS = buckets.MAX_BATCH_AGE_DAYS + 1
# Served hub days without any request from a never-batched holder before its name is freed.
NAME_SILENT_DAYS = 2
SERVED_DAYS_KEPT = 60
SNAPSHOT_WEEKS_KEPT = 5
SNAPSHOT_KEY = "count_snapshot"
# A served day is not "clean" (it does not count as silence) when the address limiter blocked at
# least this share of the authenticated requests, or at least this many.
BLOCKED_SHARE = 0.2
BLOCKED_MAX = 1000
# The API adds its per-day counters up in memory and writes them about once a minute.
FLUSH_S = 60

LAST_BATCH = "GREATEST(n.last_batch_day, (SELECT max(b.day) FROM batches b WHERE b.node_id = n.id))"
# The snapshot rule, on ``nodes n`` as of the reference Monday.
_COUNTED_AT_REF = (
    f"(({LAST_BATCH} IS NULL AND n.enrolled_day >= :ghost_since) OR {LAST_BATCH} >= :dormant_since)"
)
# SQL condition on ``nodes n``: the node counts as a member. Parameters from ``count_params``.
ACTIVE = (
    "(n.id IN (SELECT c.node_id FROM hub_count_snapshot c WHERE c.ref = :ref) "
    "OR n.enrolled_day > :taken)"
)
_CLEAN = f"s.served > 0 AND s.blocked < {BLOCKED_MAX} AND s.blocked < s.served * {BLOCKED_SHARE}"
# SQL condition on ``nodes n``: the node's pseudonym may be given to another node.
NAME_FREE = (
    f"({LAST_BATCH} IS NULL AND (SELECT count(*) FROM hub_served_days s "  # noqa: S608
    f"WHERE s.day > n.last_active_day AND s.day < :today AND {_CLEAN}) >= :silent_days)"
)


def count_ref(today: date) -> date:
    """The Monday the dormant set is counted for: it changes once a week, and every batch day
    before it is settled."""
    settled = today - timedelta(days=SETTLE_DAYS)
    return settled - timedelta(days=settled.weekday())


def _snapshot_params(ref: date) -> dict[str, date]:
    return {
        "ghost_since": ref - timedelta(days=GHOST_DAYS),
        "dormant_since": ref - timedelta(days=DORMANT_DAYS),
    }


async def count_params(session: AsyncSession, today: date) -> dict[str, date]:
    """Parameters of ``ACTIVE``. Takes this week's snapshot first if there is none yet (the worker
    and the admin tool; not committed here, the caller commits)."""
    ref = count_ref(today)
    raw = (
        await session.execute(
            text("SELECT value FROM worker_state WHERE key = :k"), {"k": SNAPSHOT_KEY}
        )
    ).scalar_one_or_none()
    state = json.loads(raw) if raw else {}
    if state.get("ref") == ref.isoformat():
        return {"ref": ref, "taken": date.fromisoformat(state["taken"])}
    await session.execute(text("DELETE FROM hub_count_snapshot WHERE ref = :ref"), {"ref": ref})
    await session.execute(
        text(
            "INSERT INTO hub_count_snapshot (ref, node_id) "  # noqa: S608
            f"SELECT :ref, n.id FROM nodes n WHERE {_COUNTED_AT_REF}"
        ),
        {"ref": ref, **_snapshot_params(ref)},
    )
    value = json.dumps({"ref": ref.isoformat(), "taken": today.isoformat()})
    await session.execute(
        text(
            "INSERT INTO worker_state (key, value) VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": SNAPSHOT_KEY, "v": value},
    )
    return {"ref": ref, "taken": today}


def name_params(today: date) -> dict[str, object]:
    """Parameters of ``NAME_FREE``."""
    return {"today": today, "silent_days": NAME_SILENT_DAYS}


def is_dormant(enrolled_day: date, last_batch_day: date | None, today: date) -> bool:
    """The snapshot rule, negated, in Python (tests)."""
    ref = count_ref(today)
    if last_batch_day is None:
        return enrolled_day < ref - timedelta(days=GHOST_DAYS)
    return last_batch_day < ref - timedelta(days=DORMANT_DAYS)


def clean_day(served: int, blocked: int) -> bool:
    """A served day that counts as silence: requests served, few of them blocked."""
    return served > 0 and blocked < BLOCKED_MAX and blocked < served * BLOCKED_SHARE


def name_free(ever_batched: bool, silent_served_days: int) -> bool:
    """The rule of ``NAME_FREE`` in Python."""
    return not ever_batched and silent_served_days >= NAME_SILENT_DAYS


def lost_race(exc: Exception) -> bool:
    """A concurrent claim of the same pseudonym: the unique key, a deadlock or a serialization
    failure. The caller answers ``pseudonym_taken``."""
    if isinstance(exc, IntegrityError):
        return "pseudonym_key" in str(exc.orig)
    if isinstance(exc, DBAPIError):
        orig = exc.orig
        code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
        if code is None and orig is not None:
            code = getattr(getattr(orig, "__cause__", None), "sqlstate", None)
        return code in ("40P01", "40001")
    return False


async def claim_pseudonym(
    session: AsyncSession, key: str, today: date, node_id: uuid.UUID | None = None
) -> bool:
    """Free ``key`` from a holder whose name may be given away. False when the holder keeps it
    (the caller answers ``pseudonym_taken``). True when the name is free now (not committed)."""
    holder = (
        await session.execute(
            text(
                f"SELECT n.id, {NAME_FREE} AS free FROM nodes n "  # noqa: S608
                "WHERE n.pseudonym_key = :key AND (CAST(:me AS uuid) IS NULL OR n.id <> :me) "
                "FOR UPDATE OF n"
            ),
            {"key": key, "me": node_id, **name_params(today)},
        )
    ).first()
    if holder is None:
        return True
    if not holder.free:
        return False
    # The holder may choose a new name at once when it comes back (no 7-day wait).
    await session.execute(
        text(
            "UPDATE nodes SET pseudonym = NULL, pseudonym_key = NULL, "
            "pseudonym_changed_day = NULL WHERE id = :id"
        ),
        {"id": holder.id},
    )
    return True


class ServedDays:
    """Per-day counters of the API: authenticated requests served and requests refused by the
    address limiter. Integers only, no node or address. Added up in memory and written at most
    about once a minute per process (and on shutdown)."""

    def __init__(self) -> None:
        self._pending: dict[date, list[int]] = {}
        self._flushed_at: datetime | None = None

    async def served(self, session: AsyncSession, now: datetime) -> None:
        """Count one served request; the caller commits."""
        self._add(now.date(), 1, 0)
        if self._due(now):
            await self.flush(session, now)

    async def blocked(self, session: AsyncSession, now: datetime) -> None:
        """Count one blocked request; commits when it writes."""
        self._add(now.date(), 0, 1)
        if self._due(now):
            await self.flush(session, now)
            await session.commit()

    def _add(self, day: date, served: int, blocked: int) -> None:
        row = self._pending.setdefault(day, [0, 0])
        row[0] += served
        row[1] += blocked

    def _due(self, now: datetime) -> bool:
        return self._flushed_at is None or (now - self._flushed_at).total_seconds() >= FLUSH_S

    async def flush(self, session: AsyncSession, now: datetime) -> None:
        """Write the pending counters (the caller commits)."""
        pending, self._pending = self._pending, {}
        self._flushed_at = now
        for day, (served, blocked) in sorted(pending.items()):
            await session.execute(
                text(
                    "INSERT INTO hub_served_days (day, served, blocked) VALUES (:d, :s, :b) "
                    "ON CONFLICT (day) DO UPDATE SET served = hub_served_days.served + "
                    "EXCLUDED.served, blocked = hub_served_days.blocked + EXCLUDED.blocked"
                ),
                {"d": day, "s": served, "b": blocked},
            )
