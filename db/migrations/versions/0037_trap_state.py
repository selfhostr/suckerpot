"""The signed trap pack bundle this node last accepted (M37 P2).

Revision ID: 0037
Revises: 0036

* ``trap_state``: one row (``CHECK id = 1``), written by the ingest trap pack worker (or by
  ``just trap-import``) once a bundle was verified with the pack key and written to the
  ``trap-packs`` volume. ``seq`` is the highest accepted sequence for ``key_id``: a lower one is
  refused (rollback). ``first_seen`` keeps, per pack id and version, the CVEs it names and when it
  first loaded here: the network batch holds back the ``exploit`` activity of those CVEs for 48 h
  (gate G). ``rejected`` lists the packs the shared validator refused, as (id, reason).

Public, signed data only: no pack content, never a credential or an event. The worker keeps the
JSON bounded (old versions that left the bundle are dropped after 7 days).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0037"
down_revision: str | None = "0036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE trap_state (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            key_id text CHECK (char_length(key_id) <= 64),
            seq bigint CHECK (seq >= 0),
            sha256 text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
            etag text CHECK (char_length(etag) <= 256),
            source text CHECK (source IN ('remote', 'import')),
            packs integer CHECK (packs BETWEEN 0 AND 1024),
            rejected jsonb NOT NULL DEFAULT '[]'::jsonb
                CHECK (pg_column_size(rejected) <= 65536),
            first_seen jsonb NOT NULL DEFAULT '{}'::jsonb
                CHECK (pg_column_size(first_seen) <= 262144),
            accepted_at timestamptz,
            last_check_at timestamptz,
            last_ok_at timestamptz,
            error_code text CHECK (char_length(error_code) <= 64),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS trap_state")
