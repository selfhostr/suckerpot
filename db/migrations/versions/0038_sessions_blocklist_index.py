"""A covering index on ``sessions`` for the blocklist worker's per-address aggregate.

Revision ID: 0038
Revises: 0037

The blocklist worker sums the sessions of the window per source address. The only usable index was
``(src_ip, sensor, started_at)``: the plan walked it in address order and fetched one heap row
per session, scattered over a table that flood folding left mostly empty (637 MB for 210,000
rows on one node). That was 200,000 page reads, 5.6 s with a warm cache, and past the 30 s
statement timeout after a restart or under load.

``ix_sessions_blocklist`` has the window filter first (``started_at``) and carries every column
the aggregate reads, so the plan is an index-only scan (17 MB for 210,000 rows) and a sort. On a
copy of that shape it ran in 0.44 s from cold shared buffers, against 12 s before.

``sessions`` is a plain table, not a hypertable. ``CREATE INDEX CONCURRENTLY`` would work on it,
but the migrations run in one transaction, so this is a plain ``CREATE INDEX`` like 0034's: reads
go on, writes wait for the build (a few seconds on that node). ``migrate`` runs before ingest
starts, so nothing is writing.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0038"
down_revision: str | None = "0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Every column ``ingest.blocklist.worker._ip_rows`` reads, besides the key.
COVERED = (
    "src_ip, sensor, last_event_at, connections, login_attempts, login_success, commands, "
    "downloads, abuse_score, known_scanner, benign, campaign_id"
)


def upgrade() -> None:
    op.execute(
        f"CREATE INDEX IF NOT EXISTS ix_sessions_blocklist ON sessions (started_at) "
        f"INCLUDE ({COVERED})"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_sessions_blocklist")
