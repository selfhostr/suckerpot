"""The public community blocklist feed, node side (M30, ``docs/dev/design/m30.md`` section 10.3).

Revision ID: 0029
Revises: 0028

* ``network_feed_state``: one row (``CHECK id = 1``), written by the ingest feed worker once a
  signed index was verified. No row means the feed was never fetched. Public data only.
* ``network_feed_entries``: the stored entries of each configured list, replaced list by list on
  every fetch. ``seen_here`` is computed by local SQL only.

Both tables hold public feed content, never a credential, a command or a raw event. There is no
prune job: entries are replaced on every fetch and wiped by the worker when the feed is turned
off. The migration does not touch ``events`` or ``sessions``.

It also lets ``feed_tokens`` carry the kind ``network`` (the local mirror of the community lists,
section 10.5): the kinds check of migration 0012 allowed four kinds and now allows five.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE network_feed_state (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            serial bigint CHECK (serial >= 0),
            generated_at timestamptz,
            valid_until timestamptz,
            key_id text CHECK (char_length(key_id) <= 64),
            index_sha256 text CHECK (index_sha256 ~ '^[0-9a-f]{64}$'),
            files jsonb NOT NULL DEFAULT '{}'::jsonb
                CHECK (pg_column_size(files) <= 65536),
            last_fetch_at timestamptz,
            last_ok_at timestamptz,
            error_code text CHECK (char_length(error_code) <= 64),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE network_feed_entries (
            list text NOT NULL CHECK (char_length(list) BETWEEN 1 AND 64),
            value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 255),
            family smallint CHECK (family IN (4, 6)),
            tier text CHECK (char_length(tier) <= 16),
            categories text[] NOT NULL DEFAULT '{}',
            services text[] NOT NULL DEFAULT '{}',
            tags text[] NOT NULL DEFAULT '{}',
            families text[] NOT NULL DEFAULT '{}',
            ports integer[] NOT NULL DEFAULT '{}',
            first_seen date,
            last_seen date,
            expires date,
            reported boolean,
            seen_here boolean NOT NULL DEFAULT false,
            PRIMARY KEY (list, value)
        )
        """
    )
    op.execute("CREATE INDEX ix_network_feed_entries_value ON network_feed_entries (value)")
    op.execute("ALTER TABLE feed_tokens DROP CONSTRAINT IF EXISTS feed_tokens_kinds_check")
    op.execute(
        "ALTER TABLE feed_tokens ADD CONSTRAINT feed_tokens_kinds_check CHECK ("
        "cardinality(kinds) BETWEEN 1 AND 5 "
        "AND kinds <@ ARRAY['ip', 'domain', 'url', 'hash', 'network'])"
    )


def downgrade() -> None:
    # Tokens of kind network cannot exist under the old check: drop them first.
    op.execute("DELETE FROM feed_tokens WHERE 'network' = ANY(kinds)")
    op.execute("ALTER TABLE feed_tokens DROP CONSTRAINT IF EXISTS feed_tokens_kinds_check")
    op.execute(
        "ALTER TABLE feed_tokens ADD CONSTRAINT feed_tokens_kinds_check CHECK ("
        "cardinality(kinds) BETWEEN 1 AND 4 AND kinds <@ ARRAY['ip', 'domain', 'url', 'hash'])"
    )
    # No retention job exists for these tables, so nothing can dangle.
    op.execute("DROP TABLE IF EXISTS network_feed_entries")
    op.execute("DROP TABLE IF EXISTS network_feed_state")
