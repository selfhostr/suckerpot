"""Recheck assignments: a takedown vote counts only for a target the hub handed to that node.

Revision ID: h0011
Revises: h0010

``GET /v1/targets`` records which targets it asks a node to recheck, per day. ``POST /v1/rechecks``
accepts a vote only against such a row, once. Rows are short lived (retention drops them) and
cascade with the node.
"""

from __future__ import annotations

from alembic import op

revision = "h0011"
down_revision = "h0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE recheck_assignments (
            target_id text NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
            day date NOT NULL,
            answered boolean NOT NULL DEFAULT false,
            PRIMARY KEY (target_id, node_id, day)
        )
        """
    )
    op.execute("CREATE INDEX recheck_assignments_node_day ON recheck_assignments (node_id, day)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS recheck_assignments")
