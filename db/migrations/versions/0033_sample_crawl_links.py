"""Record how the collector reached each file, durably.

Revision ID: 0033
Revises: 0032

A fetched file is spared as plain web content only when every link that led to it came from
other web content (``suckerpot_db.sample_kinds``). The links are the ``sample_links`` rows that
point at a fetch target, one per parent file, so every parent counts, not only the first one that
queued the URL: an index on ``target_id`` keeps that lookup bounded.

``fetch_targets.typed`` marks, for good, a URL that an attacker typed (an indicator from a sensor
event pointed at it). ``indicator_id`` alone is not enough: indicator pruning sets it to NULL.

``samples.spared`` says the analyzer did not act on a file (no hash indicator, links not
followed): plain web content, or a file fetched only for a network verification. Such a file is
analysed again once an attacker asks for it.

``suckerpot_revive_web_target`` lets the analyzer, which cannot change fetch targets, put back in
the queue a target refused as ``web_parent`` once a file that is attacker content links to it. It
changes nothing else.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE fetch_targets ADD COLUMN typed boolean NOT NULL DEFAULT false")
    op.execute("UPDATE fetch_targets SET typed = true WHERE indicator_id IS NOT NULL")
    op.execute("ALTER TABLE samples ADD COLUMN spared boolean NOT NULL DEFAULT false")
    op.execute(
        "CREATE INDEX ix_sample_links_target ON sample_links (target_id) "
        "WHERE target_id IS NOT NULL"
    )
    op.execute(
        """
        CREATE FUNCTION suckerpot_revive_web_target(target bigint, at timestamptz)
        RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
            UPDATE public.fetch_targets
               SET status = 'pending', last_error = NULL, attempts = 0, next_attempt_at = at
             WHERE id = target AND status = 'refused' AND last_error = 'web_parent'
        $$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION suckerpot_revive_web_target(bigint, timestamptz) FROM PUBLIC"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS suckerpot_revive_web_target(bigint, timestamptz)")
    op.execute("DROP INDEX IF EXISTS ix_sample_links_target")
    op.execute("ALTER TABLE samples DROP COLUMN IF EXISTS spared")
    op.execute("ALTER TABLE fetch_targets DROP COLUMN IF EXISTS typed")
