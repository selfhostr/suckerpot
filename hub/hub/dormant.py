"""Dormant members and freed pseudonyms (2026-11-21 field report).

A node is dormant when it enrolled more than ``GHOST_DAYS`` ago and never sent a batch, or when
its last accepted batch is more than ``DORMANT_DAYS`` old. Dormant nodes are kept (nothing is
deleted here; retention still drops a node with no request for 30 days) but they are left out of
the member counts and lists: the network summary, the public feed statistics and the observatory.
The state is computed, never stored, so a dormant node that sends a batch again counts again at
the next daily summary.

The last batch day is the later of ``nodes.last_batch_day`` (kept beyond the 14 days of batch
markers) and the newest marker in ``batches``.

A pseudonym is unique among nodes. When a new or renaming node asks for a name held by a node
that is dormant, or that never sent a batch for at least one full UTC day after enrolling (a
reinstall leaves such a ghost behind), the name is freed from the holder first. A node that sends
batches never loses its name.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

GHOST_DAYS = 7
DORMANT_DAYS = 30
# A holder that never sent a batch frees its name once it enrolled before yesterday (24 to 48 h).
NAME_GHOST_DAYS = 2

LAST_BATCH = "GREATEST(n.last_batch_day, (SELECT max(b.day) FROM batches b WHERE b.node_id = n.id))"
# SQL condition on ``nodes n``: the node counts as a member. Parameters from ``params``.
ACTIVE = (
    f"(({LAST_BATCH} IS NULL AND n.enrolled_day >= :ghost_since) OR {LAST_BATCH} >= :dormant_since)"
)
# SQL condition on ``nodes n``: the node's pseudonym may be given to another node.
NAME_FREE = f"(({LAST_BATCH} IS NULL AND n.enrolled_day < :name_since) OR NOT ({ACTIVE}))"


def params(today: date) -> dict[str, date]:
    return {
        "ghost_since": today - timedelta(days=GHOST_DAYS),
        "dormant_since": today - timedelta(days=DORMANT_DAYS),
        "name_since": today - timedelta(days=NAME_GHOST_DAYS - 1),
    }


def is_dormant(enrolled_day: date, last_batch_day: date | None, today: date) -> bool:
    """The rule of ``ACTIVE``, negated, in Python (tests and the admin tool)."""
    if last_batch_day is None:
        return enrolled_day < today - timedelta(days=GHOST_DAYS)
    return last_batch_day < today - timedelta(days=DORMANT_DAYS)


def name_free(enrolled_day: date, last_batch_day: date | None, today: date) -> bool:
    """The rule of ``NAME_FREE`` in Python."""
    if last_batch_day is None and enrolled_day < today - timedelta(days=NAME_GHOST_DAYS - 1):
        return True
    return is_dormant(enrolled_day, last_batch_day, today)


async def claim_pseudonym(
    session: AsyncSession, key: str, today: date, node_id: uuid.UUID | None = None
) -> bool:
    """Free ``key`` from a holder whose name may be given away. False when an active node keeps
    it (the caller answers ``pseudonym_taken``). True when the name is free now (not committed)."""
    holder = (
        await session.execute(
            text(
                f"SELECT n.id, {NAME_FREE} AS free FROM nodes n "  # noqa: S608
                "WHERE n.pseudonym_key = :key AND (CAST(:me AS uuid) IS NULL OR n.id <> :me) "
                "FOR UPDATE OF n"
            ),
            {"key": key, "me": node_id, **params(today)},
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
