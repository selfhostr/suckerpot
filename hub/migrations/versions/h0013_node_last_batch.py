"""Dormant members and freed pseudonyms (2026-11-21 field report).

Revision ID: h0013
Revises: h0012

``nodes.last_batch_day``: day of the newest accepted batch. It tells a dormant member apart (no
accepted batch for 30 days) after the 14 days of batch markers, and a node that ever sent a batch
keeps its pseudonym. Privacy-neutral: a day, like ``last_active_day``.

Backfill: the newest batch marker still held. A node enrolled more than 14 days ago without one has
an unknown history (its batches may be older than the markers): it gets ``today - 11``, so it is
never a never-batched ghost (it keeps its name) and counts as a member for about three more weeks.

``hub_served_days``: per UTC day, the authenticated requests the API served and the requests its
address limiter refused (integers only, no node or address). A pseudonym holder's silence is
counted on served days with few blocks only (hub/hub/dormant.py).

``hub_count_snapshot``: the nodes counted as members for one week (a Monday), taken once by the
worker. Hub-internal, never published, kept five weeks.
"""

from __future__ import annotations

from alembic import op

revision = "h0013"
down_revision = "h0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE nodes ADD COLUMN last_batch_day date")
    op.execute(
        """
        UPDATE nodes n SET last_batch_day = coalesce(
            (SELECT max(b.day) FROM batches b WHERE b.node_id = n.id),
            CASE WHEN n.enrolled_day < CAST(now() AT TIME ZONE 'UTC' AS date) - 14
                 THEN CAST(now() AT TIME ZONE 'UTC' AS date) - 11 END)
        """
    )
    op.execute(
        """
        CREATE TABLE hub_served_days (
            day date PRIMARY KEY,
            served bigint NOT NULL DEFAULT 0,
            blocked bigint NOT NULL DEFAULT 0
        )
        """
    )
    op.execute(
        """
        CREATE TABLE hub_count_snapshot (
            ref date NOT NULL,
            node_id uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
            PRIMARY KEY (ref, node_id)
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS hub_count_snapshot")
    op.execute("DROP TABLE IF EXISTS hub_served_days")
    op.execute("ALTER TABLE nodes DROP COLUMN IF EXISTS last_batch_day")
