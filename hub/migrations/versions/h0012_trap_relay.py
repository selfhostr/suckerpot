"""Trap pack relay state (design M37 section 5): the last bundle the hub copied to the feed site.

Revision ID: h0012
Revises: h0011

One row. ``seq`` is the highest relayed bundle sequence for the pack key ``key_id``; a lower one is
refused, and a new key starts a new sequence space. No node data, nothing from the bundle but its
sequence and hashes.
"""

from __future__ import annotations

from alembic import op

revision = "h0012"
down_revision = "h0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE trap_relay_state (
            id smallint PRIMARY KEY CHECK (id = 1),
            key_id text,
            seq bigint,
            sha256 text,
            sig_sha256 text,
            relayed_at timestamptz,
            checked_at timestamptz,
            error_code text,
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS trap_relay_state")
