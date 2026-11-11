"""Pipeline heartbeat row and a retract_benign that prunes chunks.

Revision ID: 0031
Revises: 0030

* ``retract_benign`` (0015) joined ``events`` to ``sessions`` on ``e.ts >= s.started_at``. That
  bound is not a constant, so the planner could not exclude chunks: once the oldest chunk was
  compressed, the UPDATE decompressed it and hit the ingest role's statement timeout, which
  stalled the whole pipeline. The new body reads the session bounds first and runs one UPDATE
  per session with constant ``sensor``, ``session_id`` and ``ts`` bounds (chunk exclusion
  works, and the compressed segmentby columns can be used). Owner and grants are unchanged.
* ``pipeline_state``: one row that ingest stamps every 30 s while it is healthy and annotates
  when a batch keeps failing. The dashboard reads it to show a "pipeline stalled" banner.
  Grants live in ``suckerpot_db/roles.py``.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW = """
CREATE OR REPLACE FUNCTION retract_benign(ids text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE r record;
BEGIN
    IF cardinality(ids) > 1000 THEN
        RAISE EXCEPTION 'retract_benign: too many sessions';
    END IF;
    FOR r IN SELECT s.session_id, s.sensor, s.started_at, s.last_event_at
             FROM public.sessions s WHERE s.session_id = ANY(ids)
    LOOP
        -- Values are parameters of a one-shot EXECUTE: the plan is made with them (chunks are
        -- excluded) and does not depend on the caller's DateStyle or TimeZone.
        EXECUTE 'UPDATE public.events SET benign = false WHERE sensor = $1 AND session_id = $2'
            ' AND ts >= $3 AND ts <= $4 AND benign IS TRUE'
            USING r.sensor, r.session_id, r.started_at, r.last_event_at + interval '1 minute';
    END LOOP;
END $$
"""

_OLD = """
CREATE OR REPLACE FUNCTION retract_benign(ids text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF cardinality(ids) > 1000 THEN
        RAISE EXCEPTION 'retract_benign: too many sessions';
    END IF;
    UPDATE events e SET benign = false FROM sessions s
    WHERE s.session_id = ANY(ids) AND e.session_id = s.session_id
      AND e.ts >= s.started_at AND e.benign IS TRUE;
END $$
"""


def upgrade() -> None:
    # CREATE OR REPLACE keeps the owner and the existing EXECUTE grants; restate the REVOKE anyway.
    op.execute(_NEW)
    op.execute("REVOKE ALL ON FUNCTION retract_benign(text[]) FROM PUBLIC")
    op.execute(
        """
        CREATE TABLE pipeline_state (
            id smallint PRIMARY KEY CHECK (id = 1),
            last_ok_at timestamptz NULL,
            last_error text NULL CHECK (last_error IS NULL OR char_length(last_error) <= 200),
            failing_since timestamptz NULL,
            parked_events bigint NOT NULL DEFAULT 0,
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("INSERT INTO pipeline_state (id) VALUES (1)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS pipeline_state")
    op.execute(_OLD)
    op.execute("REVOKE ALL ON FUNCTION retract_benign(text[]) FROM PUBLIC")
