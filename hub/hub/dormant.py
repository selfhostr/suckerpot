"""Dormant members and freed pseudonyms (2026-11-21 field report).

**Dormant (a counting rule only).** A node is dormant when it enrolled more than ``GHOST_DAYS``
ago and never sent a batch, or when its last accepted batch is more than ``DORMANT_DAYS`` old.
Dormant nodes are kept (nothing is deleted here; retention still drops a node with no request for
30 days) but they are left out of the member counts and lists: the network summary, the public
feed statistics and the observatory. The state is computed, never stored. It is computed once per
ISO week, as of ``count_ref`` (a Monday), from settled batch days before that Monday only, so a
single node's batch history cannot move a published count (a country at the k = 3 edge) day by
day. A dormant node that sends again counts again from the next reference week.

The last batch day is the later of ``nodes.last_batch_day`` (kept beyond the 14 days of batch
markers) and the newest marker in ``batches``.

**Freed pseudonyms.** A pseudonym is unique among nodes. A node that ever sent an accepted batch
never loses its name. The name of a node that NEVER sent a batch (a reinstall leaves such a ghost
behind) is freed for a new or renaming node when that holder has been silent for
``NAME_SILENT_DAYS`` of the hub's served days: UTC days after its ``last_active_day`` (the day of
its last authenticated request) and before today on which the hub API served authenticated
requests and refused no request with its address limiter (``hub_served_days``). A hub outage, or
a day on which the address limiter blocked someone (a shared exit, an attack), never counts as
the holder's silence: such a day only delays the release.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta

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

LAST_BATCH = "GREATEST(n.last_batch_day, (SELECT max(b.day) FROM batches b WHERE b.node_id = n.id))"
# The last batch day before the reference Monday (settled data only).
_LAST_BATCH_REF = (
    "GREATEST(CASE WHEN n.last_batch_day < :ref THEN n.last_batch_day END, "
    "(SELECT max(b.day) FROM batches b WHERE b.node_id = n.id AND b.day < :ref))"
)
# SQL condition on ``nodes n``: the node counts as a member. Parameters from ``params``.
ACTIVE = (
    f"(({_LAST_BATCH_REF} IS NULL AND n.enrolled_day >= :ghost_since) "
    f"OR {_LAST_BATCH_REF} >= :dormant_since)"
)
# SQL condition on ``nodes n``: the node's pseudonym may be given to another node.
NAME_FREE = (
    f"({LAST_BATCH} IS NULL AND (SELECT count(*) FROM hub_served_days s "  # noqa: S608
    "WHERE s.day > n.last_active_day AND s.day < :today AND NOT s.blocked) >= :silent_days)"
)


def count_ref(today: date) -> date:
    """The Monday the dormant set is counted for: it changes once a week, and every batch day
    before it is settled."""
    settled = today - timedelta(days=SETTLE_DAYS)
    return settled - timedelta(days=settled.weekday())


def params(today: date) -> dict[str, date]:
    """Parameters of ``ACTIVE``."""
    ref = count_ref(today)
    return {
        "ref": ref,
        "ghost_since": ref - timedelta(days=GHOST_DAYS),
        "dormant_since": ref - timedelta(days=DORMANT_DAYS),
    }


def name_params(today: date) -> dict[str, object]:
    """Parameters of ``NAME_FREE``."""
    return {"today": today, "silent_days": NAME_SILENT_DAYS}


def is_dormant(enrolled_day: date, last_batch_before_ref: date | None, today: date) -> bool:
    """The rule of ``ACTIVE``, negated, in Python (tests)."""
    ref = count_ref(today)
    if last_batch_before_ref is None:
        return enrolled_day < ref - timedelta(days=GHOST_DAYS)
    return last_batch_before_ref < ref - timedelta(days=DORMANT_DAYS)


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
    """Records, once per process and day, that the API served an authenticated request
    (``blocked = false``) or that its address limiter refused one (``blocked = true``)."""

    def __init__(self) -> None:
        self._served: date | None = None
        self._blocked: date | None = None

    async def served(self, session: AsyncSession, today: date) -> None:
        if self._served == today:
            return
        await session.execute(
            text("INSERT INTO hub_served_days (day) VALUES (:d) ON CONFLICT (day) DO NOTHING"),
            {"d": today},
        )
        self._served = today

    async def blocked(self, session: AsyncSession, today: date) -> None:
        if self._blocked == today:
            return
        await session.execute(
            text(
                "INSERT INTO hub_served_days (day, blocked) VALUES (:d, true) "
                "ON CONFLICT (day) DO UPDATE SET blocked = true"
            ),
            {"d": today},
        )
        await session.commit()
        self._blocked = today
