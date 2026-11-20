"""The opt-in Selfhostr network, node side (M29, ``docs/dev/design/m29.md`` section 9.2).

Revision ID: 0028
Revises: 0027

* ``network_membership``: one row (``CHECK id = 1``, seeded here). ``desired`` is what the admin
  asked for (the API writes it), ``state`` is what ingest did. The node's private key is AES-GCM
  ciphertext in ``privkey_enc``: only ingest can read it (column grants in ``suckerpot_db.roles``).
  A trigger lets the API role change ``desired`` along ``off -> member -> leave`` only, so a
  compromised API cannot flip a node into the network without the explicit step, nor revive a
  node that is leaving.
* ``network_submissions``: one row per UTC day with the counts and, for seven days, the exact
  JSON that was sent (transparency; ``suckerpot_network_prune`` nulls it afterwards).
* ``network_targets``: what the hub confirmed. ``hub_id`` is the primary key (the design's
  composite key over ``coalesce(value, value_b)`` cannot be a primary key in PostgreSQL; the
  same uniqueness is a unique index).
* ``network_summary``: the hub's daily summary, one row.

The node never stores a credential, a command or a raw event here.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GUARD = """
CREATE OR REPLACE FUNCTION network_membership_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    -- The API role is the one that cannot read the private key column.
    api_mode boolean := NOT has_column_privilege(
        current_user, 'public.network_membership', 'privkey_enc', 'SELECT');
BEGIN
    NEW.updated_at := now();
    IF api_mode AND NEW.desired IS DISTINCT FROM OLD.desired THEN
        IF NOT (
            (OLD.desired = 'off' AND NEW.desired = 'member' AND OLD.state IN ('off', 'error'))
            OR (OLD.desired = 'member' AND NEW.desired = 'leave')
        ) THEN
            RAISE EXCEPTION 'invalid network membership change' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF api_mode AND OLD.desired = 'leave' AND (
        NEW.pseudonym IS DISTINCT FROM OLD.pseudonym
        OR NEW.country IS DISTINCT FROM OLD.country
        OR NEW.show_country IS DISTINCT FROM OLD.show_country) THEN
        RAISE EXCEPTION 'the node is leaving' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$
"""

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_network_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    payload_days integer := COALESCE((config ->> 'payload_days')::integer, 7);
    submission_days integer := COALESCE((config ->> 'submission_days')::integer, 90);
    target_days integer := COALESCE((config ->> 'target_days')::integer, 180);
BEGIN
    UPDATE network_submissions SET payload = NULL
    WHERE payload IS NOT NULL AND day < (now() AT TIME ZONE 'UTC')::date - payload_days;
    DELETE FROM network_submissions
    WHERE day < (now() AT TIME ZONE 'UTC')::date - submission_days;
    DELETE FROM network_targets WHERE updated_at < now() - make_interval(days => target_days);
END
$$
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE network_membership (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            desired text NOT NULL DEFAULT 'off' CHECK (desired IN ('off', 'member', 'leave')),
            state text NOT NULL DEFAULT 'off'
                CHECK (state IN ('off', 'enrolling', 'member', 'leaving', 'error')),
            pseudonym text CHECK (char_length(pseudonym) BETWEEN 3 AND 24),
            country char(2) CHECK (country ~ '^[A-Z]{2}$'),
            show_country boolean NOT NULL DEFAULT false,
            node_id uuid,
            fingerprint text CHECK (fingerprint ~ '^[0-9a-f]{8}$'),
            pubkey bytea CHECK (length(pubkey) = 32),
            privkey_enc bytea,
            privkey_nonce bytea,
            enrolled_day date,
            eligible_from_day date,
            standing text CHECK (standing IN ('new', 'good', 'low')),
            next_submit_at timestamptz,
            last_submit_day date,
            last_pull_at timestamptz,
            last_summary_at timestamptz,
            pull_cursor text CHECK (char_length(pull_cursor) <= 64),
            synced_pseudonym text,
            synced_country char(2),
            synced_show_country boolean,
            leave_requested_at timestamptz,
            last_error_code text CHECK (char_length(last_error_code) <= 64),
            requested_by text CHECK (char_length(requested_by) <= 120),
            requested_at timestamptz,
            updated_at timestamptz NOT NULL DEFAULT now(),
            CHECK ((privkey_enc IS NULL) = (privkey_nonce IS NULL))
        )
        """
    )
    op.execute("INSERT INTO network_membership (id) VALUES (1)")
    op.execute(_GUARD)
    op.execute(
        "CREATE TRIGGER network_membership_guard BEFORE UPDATE ON network_membership "
        "FOR EACH ROW EXECUTE FUNCTION network_membership_guard()"
    )
    op.execute(
        """
        CREATE TABLE network_submissions (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            day date NOT NULL UNIQUE,
            batch_id text NOT NULL CHECK (char_length(batch_id) <= 32),
            sent_at timestamptz,
            status text NOT NULL CHECK (status IN ('sent', 'failed', 'skipped')),
            counts jsonb NOT NULL DEFAULT '{}'::jsonb,
            dropped jsonb NOT NULL DEFAULT '{}'::jsonb,
            error_code text CHECK (char_length(error_code) <= 64),
            payload jsonb CHECK (payload IS NULL OR pg_column_size(payload) <= 262144)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE network_targets (
            hub_id text PRIMARY KEY CHECK (hub_id ~ '^t_[0-9a-f]{12}$'),
            kind text NOT NULL
                CHECK (kind IN ('ip', 'url', 'domain', 'sha256', 'c2_ip', 'c2_domain')),
            value text CHECK (char_length(value) <= 2048),
            value_b text CHECK (value_b ~ '^[0-9a-f]{64}$'),
            state text NOT NULL
                CHECK (state IN ('confirmed', 'reported', 'taken_down', 'disputed', 'expired')),
            nodes smallint NOT NULL CHECK (nodes BETWEEN 0 AND 2),
            countries smallint CHECK (countries >= 3),
            first_day date NOT NULL,
            last_day date NOT NULL,
            services text[] NOT NULL DEFAULT '{}',
            activity text[] NOT NULL DEFAULT '{}',
            tags text[] NOT NULL DEFAULT '{}',
            families text[] NOT NULL DEFAULT '{}',
            reported_day date,
            taken_down_day date,
            mine boolean NOT NULL DEFAULT false,
            updated_at timestamptz NOT NULL DEFAULT now(),
            CHECK (value IS NOT NULL OR value_b IS NOT NULL)
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX ix_network_targets_key ON network_targets "
        "(kind, (COALESCE(value, value_b)))"
    )
    op.execute("CREATE INDEX ix_network_targets_value ON network_targets (value)")
    op.execute("CREATE INDEX ix_network_targets_value_b ON network_targets (value_b)")
    op.execute(
        "CREATE INDEX ix_network_targets_listing ON network_targets (last_day DESC, hub_id DESC)"
    )
    op.execute(
        """
        CREATE TABLE network_summary (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            data jsonb NOT NULL,
            fetched_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(_PRUNE)


def downgrade() -> None:
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_network_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_network_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS network_summary")
    op.execute("DROP TABLE IF EXISTS network_targets")
    op.execute("DROP TABLE IF EXISTS network_submissions")
    op.execute("DROP TABLE IF EXISTS network_membership")
    op.execute("DROP FUNCTION IF EXISTS network_membership_guard()")
