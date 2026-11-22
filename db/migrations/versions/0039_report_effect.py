"""Do reports make a difference? The node's effect measure (design M38 G1, phase P2).

Revision ID: 0039
Revises: 0038

* ``report_effect_pairs``: one reported attacking address and one similar address that was not
  reported, with the strata they matched on and the outcome at 7 and 30 days. An outcome is frozen
  once (``frozen_7_at``, ``frozen_30_at``): the trigger refuses any later change to it. The two
  addresses are cleared to NULL 30 days after the 30-day outcome is frozen; the counts stay.
* ``report_effect_unmatched``: reported addresses with no comparable control (counted, never used).
* ``report_effect_days``: how many distinct addresses this node saw on each UTC day, the
  observation check (a day with fewer than 10 is a day the sensors were not really up).
* ``abuse_holdouts``: the opt-in random holdout (``ABUSE_EFFECT_HOLDOUT_PCT``). One row per new
  candidate decided while it is on; ``held`` ones are not reported until ``release_at``.
* ``report_effect_summary`` and ``report_effect_unmatched_summary``: what the API may read, without
  any address. ``abuse_holdout_summary``: how many sources are held right now.

Ingest owns the tables. The API reads the three views only (grants in ``suckerpot_db.roles``).
All tables are small: one row per reported attacking address (or per candidate while the holdout
is on), and one row per day.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0039"
down_revision: str | None = "0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GUARD = """
CREATE OR REPLACE FUNCTION report_effect_pairs_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.created_at <> OLD.created_at OR NEW.index_at <> OLD.index_at
       OR NEW.tier <> OLD.tier OR NEW.activity_class <> OLD.activity_class
       OR NEW.volume_bucket <> OLD.volume_bucket OR NEW.recency_bucket <> OLD.recency_bucket THEN
        RAISE EXCEPTION 'report effect pair identity columns are immutable' USING ERRCODE = '23514';
    END IF;
    -- The addresses may only be cleared, never changed or set again.
    IF (NEW.reported_value IS DISTINCT FROM OLD.reported_value AND NEW.reported_value IS NOT NULL)
       OR (NEW.control_value IS DISTINCT FROM OLD.control_value AND NEW.control_value IS NOT NULL)
    THEN
        RAISE EXCEPTION 'report effect addresses may only be cleared' USING ERRCODE = '23514';
    END IF;
    IF OLD.frozen_7_at IS NOT NULL AND (
        NEW.frozen_7_at IS DISTINCT FROM OLD.frozen_7_at
        OR NEW.seen_r_7 IS DISTINCT FROM OLD.seen_r_7 OR NEW.seen_c_7 IS DISTINCT FROM OLD.seen_c_7
        OR NEW.observed_7 IS DISTINCT FROM OLD.observed_7
        OR NEW.excluded_7 IS DISTINCT FROM OLD.excluded_7) THEN
        RAISE EXCEPTION 'the 7-day outcome is frozen' USING ERRCODE = '23514';
    END IF;
    IF OLD.frozen_30_at IS NOT NULL AND (
        NEW.frozen_30_at IS DISTINCT FROM OLD.frozen_30_at
        OR NEW.seen_r_30 IS DISTINCT FROM OLD.seen_r_30
        OR NEW.seen_c_30 IS DISTINCT FROM OLD.seen_c_30
        OR NEW.observed_30 IS DISTINCT FROM OLD.observed_30
        OR NEW.excluded_30 IS DISTINCT FROM OLD.excluded_30) THEN
        RAISE EXCEPTION 'the 30-day outcome is frozen' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$
"""

_EXCLUDED = "IN ('not_observed', 'control_reported', 'network_reported')"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE TABLE report_effect_pairs (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            created_at timestamptz NOT NULL DEFAULT now(),
            index_at timestamptz NOT NULL,
            reported_value inet,
            control_value inet,
            tier text NOT NULL CHECK (tier IN ('H', 'A', 'B', 'C')),
            activity_class text NOT NULL
                CHECK (activity_class IN ('login', 'login_commands', 'download', 'exploit',
                                          'other')),
            volume_bucket smallint NOT NULL CHECK (volume_bucket BETWEEN 0 AND 3),
            recency_bucket smallint NOT NULL CHECK (recency_bucket BETWEEN 0 AND 2),
            seen_r_7 boolean,
            seen_c_7 boolean,
            observed_7 boolean,
            excluded_7 text CHECK (excluded_7 {_EXCLUDED}),
            frozen_7_at timestamptz,
            seen_r_30 boolean,
            seen_c_30 boolean,
            observed_30 boolean,
            excluded_30 text CHECK (excluded_30 {_EXCLUDED}),
            frozen_30_at timestamptz,
            cleared_at timestamptz
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_report_effect_pairs_reported ON report_effect_pairs "
        "(reported_value) WHERE reported_value IS NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_report_effect_pairs_control ON report_effect_pairs "
        "(control_value) WHERE control_value IS NOT NULL"
    )
    op.execute("CREATE INDEX ix_report_effect_pairs_index_at ON report_effect_pairs (index_at)")
    op.execute(_GUARD)
    op.execute(
        "CREATE TRIGGER report_effect_pairs_guard BEFORE UPDATE ON report_effect_pairs "
        "FOR EACH ROW EXECUTE FUNCTION report_effect_pairs_guard()"
    )
    op.execute(
        """
        CREATE TABLE report_effect_unmatched (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            created_at timestamptz NOT NULL DEFAULT now(),
            index_at timestamptz NOT NULL,
            value inet,
            reason text NOT NULL
                CHECK (reason IN ('no_control', 'no_activity', 'network_reported'))
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_report_effect_unmatched_value ON report_effect_unmatched (value) "
        "WHERE value IS NOT NULL"
    )
    op.execute(
        "CREATE INDEX ix_report_effect_unmatched_index_at ON report_effect_unmatched (index_at)"
    )
    op.execute(
        """
        CREATE TABLE report_effect_days (
            day date PRIMARY KEY,
            addresses integer NOT NULL CHECK (addresses >= 0),
            computed_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE abuse_holdouts (
            value inet PRIMARY KEY,
            chosen_at timestamptz NOT NULL,
            release_at timestamptz NOT NULL,
            held boolean NOT NULL,
            CHECK (release_at >= chosen_at),
            CHECK (release_at <= chosen_at + interval '21 days')
        )
        """
    )
    op.execute("CREATE INDEX ix_abuse_holdouts_release_at ON abuse_holdouts (release_at)")
    op.execute(
        """
        CREATE VIEW report_effect_summary AS
        SELECT id, index_at, tier, activity_class, volume_bucket, recency_bucket,
               seen_r_7, seen_c_7, observed_7, excluded_7, frozen_7_at,
               seen_r_30, seen_c_30, observed_30, excluded_30, frozen_30_at
        FROM report_effect_pairs
        """
    )
    op.execute(
        """
        CREATE VIEW report_effect_unmatched_summary AS
        SELECT index_at, reason FROM report_effect_unmatched
        """
    )
    op.execute(
        """
        CREATE VIEW abuse_holdout_summary AS
        SELECT count(*) FILTER (WHERE held AND release_at > now()) AS held_now,
               max(chosen_at) AS last_chosen_at
        FROM abuse_holdouts
        """
    )


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS abuse_holdout_summary")
    op.execute("DROP VIEW IF EXISTS report_effect_unmatched_summary")
    op.execute("DROP VIEW IF EXISTS report_effect_summary")
    op.execute("DROP TABLE IF EXISTS abuse_holdouts")
    op.execute("DROP TABLE IF EXISTS report_effect_days")
    op.execute("DROP TABLE IF EXISTS report_effect_unmatched")
    op.execute("DROP TABLE IF EXISTS report_effect_pairs")
    op.execute("DROP FUNCTION IF EXISTS report_effect_pairs_guard()")
