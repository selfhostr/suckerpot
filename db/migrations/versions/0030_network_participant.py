"""Participant and verifier mode of the Selfhostr network (M32, ``docs/dev/design/m32.md`` 8.5).

Revision ID: 0030
Revises: 0029

* ``network_membership.left_day``: the UTC day the node left the network (nullable).
* ``fetch_targets.origin``: ``local`` (an indicator of this node) or ``network_verify`` (a URL the
  hub asked this node to fetch). The default is a constant, so the add is metadata only and no
  row is rewritten; the CHECK scans the small ``fetch_targets`` table once.
* ``network_verify_tasks``: one row per verification task leased from the hub. It holds the clear
  URL only until the row is pruned, 30 days after ``reported_at``.
* ``suckerpot_network_prune`` also deletes reported verification tasks (``verify_days``, default
  30). The procedure keeps its 0028 behaviour for the other tables.

The migration does not touch ``events`` or ``sessions`` (hypertables): nothing is rewritten there.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRUNE_BASE = """
    payload_days integer := COALESCE((config ->> 'payload_days')::integer, 7);
    submission_days integer := COALESCE((config ->> 'submission_days')::integer, 90);
    target_days integer := COALESCE((config ->> 'target_days')::integer, 180);
"""
_PRUNE_BODY = """
    UPDATE network_submissions SET payload = NULL
    WHERE payload IS NOT NULL AND day < (now() AT TIME ZONE 'UTC')::date - payload_days;
    DELETE FROM network_submissions
    WHERE day < (now() AT TIME ZONE 'UTC')::date - submission_days;
    DELETE FROM network_targets WHERE updated_at < now() - make_interval(days => target_days);
"""
_PRUNE_VERIFY = """
    DELETE FROM network_verify_tasks
    WHERE reported_at IS NOT NULL
      AND reported_at < now() - make_interval(days => verify_days);
"""


def _prune(*, verify: bool) -> str:
    declare = _PRUNE_BASE + (
        "    verify_days integer := COALESCE((config ->> 'verify_days')::integer, 30);\n"
        if verify
        else ""
    )
    return (
        "CREATE OR REPLACE PROCEDURE suckerpot_network_prune(job_id integer, config jsonb)\n"
        f"LANGUAGE plpgsql AS $$\nDECLARE{declare}BEGIN{_PRUNE_BODY}"
        f"{_PRUNE_VERIFY if verify else ''}END\n$$"
    )


def upgrade() -> None:
    op.execute("ALTER TABLE network_membership ADD COLUMN left_day date NULL")
    op.execute(
        "ALTER TABLE fetch_targets ADD COLUMN origin text NOT NULL DEFAULT 'local' "
        "CHECK (origin IN ('local', 'network_verify'))"
    )
    op.execute(
        """
        CREATE TABLE network_verify_tasks (
            hub_id text PRIMARY KEY,
            url text NOT NULL,
            host text NOT NULL,
            state text NOT NULL
                CHECK (state IN ('received', 'queued', 'done', 'reported', 'refused', 'skipped')),
            fetch_target_id bigint NULL,
            outcome text NULL,
            sha256 text NULL,
            size int NULL,
            file_type text NULL,
            family text NULL,
            received_at timestamptz NOT NULL,
            lease_until timestamptz NOT NULL,
            reported_at timestamptz NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_network_verify_tasks_state ON network_verify_tasks (state)")
    op.execute(_prune(verify=True))


def downgrade() -> None:
    op.execute(_prune(verify=False))
    op.execute("DROP TABLE IF EXISTS network_verify_tasks")
    # Verification targets cannot exist under the old schema (no origin column).
    op.execute("DELETE FROM fetch_targets WHERE origin = 'network_verify'")
    op.execute("ALTER TABLE fetch_targets DROP COLUMN IF EXISTS origin")
    op.execute("ALTER TABLE network_membership DROP COLUMN IF EXISTS left_day")
