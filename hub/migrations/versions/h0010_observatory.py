"""Public network observatory: frozen network-wide daily aggregates (design M34).

Revision ID: h0010
Revises: h0009

Observations are deleted after 14 days, so a 90-day public series needs its own table. Each row
is network-wide: ``total`` counts distinct values (attacking addresses for most metrics) and
``nodes`` the distinct nodes behind them. No node id, no value, no address. A day is written once,
when it is final, and never updated.
"""

from __future__ import annotations

from alembic import op

revision = "h0010"
down_revision = "h0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE observatory_daily (
            day date NOT NULL,
            metric text NOT NULL CHECK (metric IN ('total', 'activity', 'service', 'tag',
                'family', 'kind')),
            key text NOT NULL,
            total int NOT NULL CHECK (total >= 0),
            nodes int NOT NULL CHECK (nodes >= 0),
            PRIMARY KEY (day, metric, key)
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS observatory_daily")
