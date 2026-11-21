"""Dormant members and freed pseudonyms (2026-11-21 field report).

A node is dormant when it enrolled more than ``GHOST_DAYS`` ago and never sent a batch, or when
its last accepted batch is more than ``DORMANT_DAYS`` old. Dormant nodes are kept (nothing is
deleted here; retention still drops a node with no request for 30 days) but they are left out of
the member counts and lists: the network summary, the public feed statistics and the observatory.
The state is computed, never stored, so a dormant node that sends a batch again counts again at
the next daily summary.

The last batch day is the later of ``nodes.last_batch_day`` (kept beyond the 14 days of batch
markers) and the newest marker in ``batches``.

A pseudonym is unique among nodes. When a new or renaming node asks for a name held by another
node, the name is freed from the holder only when the holder made no authenticated request at all
(profile sync, pull, summary, batch) for ``NAME_SILENT_HOURS`` (48 h), or sent no batch for
``DORMANT_DAYS`` (30 days). A reinstall leaves such a silent ghost behind. A node that is alive
keeps its name even when it sends no batch (paused for its own address, no traffic, ...).
"Alive" is ``nodes.last_active_day``: the UTC day of the last authenticated request or of the
enrolment, written at most once a day by ``auth.authenticate``. Design invariant H4 keeps node
timestamps as dates, so the rule is "no request on the last two full days nor today": the holder
has been silent for at least 48 h (48 to 72 h).
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

GHOST_DAYS = 7
DORMANT_DAYS = 30
# A holder with no authenticated request for this long gives its name up to a new claimant.
NAME_SILENT_HOURS = 48

LAST_BATCH = "GREATEST(n.last_batch_day, (SELECT max(b.day) FROM batches b WHERE b.node_id = n.id))"
# SQL condition on ``nodes n``: the node counts as a member. Parameters from ``params``.
ACTIVE = (
    f"(({LAST_BATCH} IS NULL AND n.enrolled_day >= :ghost_since) OR {LAST_BATCH} >= :dormant_since)"
)
# SQL condition on ``nodes n``: the node's pseudonym may be given to another node.
NAME_FREE = f"(n.last_active_day < :silent_since OR {LAST_BATCH} < :dormant_since)"


def params(today: date) -> dict[str, date]:
    """Parameters of ``ACTIVE``."""
    return {
        "ghost_since": today - timedelta(days=GHOST_DAYS),
        "dormant_since": today - timedelta(days=DORMANT_DAYS),
    }


def _silent_since(today: date) -> date:
    # Free when the last request was on today - 3 or earlier: that day ended at least 48 h ago.
    return today - timedelta(days=NAME_SILENT_HOURS // 24)


def name_params(today: date) -> dict[str, date]:
    """Parameters of ``NAME_FREE``."""
    return {
        "silent_since": _silent_since(today),
        "dormant_since": today - timedelta(days=DORMANT_DAYS),
    }


def is_dormant(enrolled_day: date, last_batch_day: date | None, today: date) -> bool:
    """The rule of ``ACTIVE``, negated, in Python (tests and the admin tool)."""
    if last_batch_day is None:
        return enrolled_day < today - timedelta(days=GHOST_DAYS)
    return last_batch_day < today - timedelta(days=DORMANT_DAYS)


def name_free(last_active_day: date, last_batch_day: date | None, today: date) -> bool:
    """The rule of ``NAME_FREE`` in Python."""
    if last_active_day < _silent_since(today):
        return True
    return last_batch_day is not None and last_batch_day < today - timedelta(days=DORMANT_DAYS)


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
