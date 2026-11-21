"""Day of the newest accepted batch per node (dormant members, 2026-11-21 field report).

Revision ID: h0013
Revises: h0012

``nodes.last_batch_day`` lets the hub tell a dormant member apart (no accepted batch for 30 days)
after the 14 days of batch markers. Privacy-neutral: a day, like ``last_active_day``. Filled
from the batch markers still held.
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
        "UPDATE nodes n SET last_batch_day = "
        "(SELECT max(b.day) FROM batches b WHERE b.node_id = n.id)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE nodes DROP COLUMN IF EXISTS last_batch_day")
