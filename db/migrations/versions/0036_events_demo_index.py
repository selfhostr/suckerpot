"""A small partial index on the demo ``connect`` events, for the blocklist worker.

Revision ID: 0036
Revises: 0035

The blocklist worker marks an address as demo data when every ``connect`` event it sent in the
window carries ``data.demo = true``. It used to read every ``connect`` event of the window once per
2,000 candidate addresses: on a node with 2 million such events, each read took 8 s and pulled
1.4 GB from disk, and the cycle hit its 30 s statement timeout every time. It now first asks
which addresses sent a demo ``connect`` at all. ``ix_events_demo_connect_ts`` answers that from
the index alone; on a node that never ran ``just demo`` the index is empty.

``CREATE INDEX CONCURRENTLY`` is not supported on a TimescaleDB hypertable, and the migrations run
in one transaction. A plain ``CREATE INDEX`` takes a SHARE lock on the chunks while it builds:
reads go on, inserts wait. ``migrate`` runs before ingest starts, so nothing is inserting. The
build reads the uncompressed chunks once (about 1.6 GB on a 5 GB database); the compressed
chunks are skipped.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0036"
down_revision: str | None = "0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEMO_CONNECT = "type = 'connect' AND (data ->> 'demo') = 'true'"


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_events_demo_connect_ts ON events (ts DESC) "
        f"WHERE {DEMO_CONNECT}"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_events_demo_connect_ts")
