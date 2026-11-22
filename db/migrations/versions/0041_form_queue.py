"""The form-only desks queue (M38 phase P3).

Revision ID: 0041
Revises: 0040

* ``abuse_reports.week``: the Monday (UTC) of the ISO week of a form report (``channel =
  'form'`` only). A recipient still has one draft: its sources go into a form report instead of
  a mail digest while it only takes a web form.
* ``abuse_reports.sent_via`` accepts ``form``: the owner submitted the report through the
  provider's web form ("Submitted" in the dashboard). Only a form report can be sent that way.
  The API sets it, in the same transaction that marks the report sent (transition trigger: the
  API may never write ``smtp``).
* ``abuse_reports_channel_guard``: ``channel`` and ``week`` change on a draft only (ingest moves
  a draft between mail and form when the recipient changes).
* ``abuse_report_subjects.submitted_at``: when a source was submitted by form. The API may set
  it once, and may delete the sources the owner did not tick, only on a report it just marked
  sent by form (``abuse_report_subjects_form_guard``). Those sources were not sent: they wait
  for the next form report, like the old sources of an automatic digest.
* ``abuse_recipients.form_source`` (``reply``, ``directory``, ``manual``, or ``cleared`` when the
  owner turned the flag off) and ``form_entry`` (the id of the shared directory entry that
  routed it). Recipients already marked form-only by a reply get ``reply``.
* ``report_settings.form_name``: the optional "Your name" of the copy kit.
* ``takedown_targets.channels`` and ``outcome_rollup_monthly.channel`` accept ``form``: Results
  shows submitted forms as their own channel.

Safe on a large database: only small tables are touched (reports, subjects, recipients,
settings, takedown targets and the monthly rollup). ``events`` and ``sessions`` are not touched.
Every new column is nullable with no default (no rewrite).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0041"
down_revision: str | None = "0040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FORM_SOURCES = "'reply', 'directory', 'manual', 'cleared'"

CHANNEL_GUARD = """
CREATE OR REPLACE FUNCTION abuse_reports_channel_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.channel IS DISTINCT FROM OLD.channel OR NEW.week IS DISTINCT FROM OLD.week)
       AND OLD.status <> 'draft' THEN
        RAISE EXCEPTION 'only a draft abuse report can change its channel'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$
"""

# The API (the role that may write notes) may touch the subjects of one report only: one it
# marked sent by form, never one sent by mail. A cascade from a deleted report (pg_trigger_depth
# above 1: the foreign key's own trigger), ingest and the table owner (migrations, maintenance)
# are not concerned.
SUBJECT_GUARD = """
CREATE OR REPLACE FUNCTION abuse_report_subjects_form_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    api_mode boolean := has_column_privilege(
        current_user, 'public.abuse_reports', 'notes', 'UPDATE');
    table_owner boolean := pg_has_role(
        current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER');
    report_ok boolean;
BEGIN
    IF NOT api_mode OR table_owner OR pg_trigger_depth() > 1 THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    SELECT channel = 'form' AND status = 'sent' AND sent_via = 'form' INTO report_ok
    FROM abuse_reports WHERE id = OLD.report_id;
    IF NOT COALESCE(report_ok, false) THEN
        RAISE EXCEPTION 'only the sources of a report submitted by form can change'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF OLD.submitted_at IS NOT NULL THEN
            RAISE EXCEPTION 'a submitted source stays' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.submitted_at IS NOT NULL OR NEW.submitted_at IS NULL
       OR (NEW.report_id, NEW.kind, NEW.subject_type, NEW.value, NEW.network_id, NEW.first_ts,
           NEW.last_ts, NEW.sessions, NEW.events, NEW.xarf_id)
          IS DISTINCT FROM
          (OLD.report_id, OLD.kind, OLD.subject_type, OLD.value, OLD.network_id, OLD.first_ts,
           OLD.last_ts, OLD.sessions, OLD.events, OLD.xarf_id) THEN
        RAISE EXCEPTION 'only submitted_at can be set, once' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$
"""


def _drop_checks(table: str, needle: str) -> str:
    """Drop the CHECK constraints of ``table`` whose definition contains ``needle``."""
    return f"""
    DO $$
    DECLARE c text;
    BEGIN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = '{table}'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%{needle}%'
        LOOP
            EXECUTE format('ALTER TABLE {table} DROP CONSTRAINT %I', c);
        END LOOP;
    END $$
    """


def upgrade() -> None:
    # -- reports: the week of a form report, sent by form ---------------------------------------
    op.execute(
        "ALTER TABLE abuse_reports ADD COLUMN week date "
        "CONSTRAINT ck_abuse_reports_week CHECK (week IS NULL OR "
        "(channel = 'form' AND extract(isodow FROM week) = 1))"
    )
    op.execute("ALTER TABLE abuse_reports DROP CONSTRAINT IF EXISTS ck_abuse_reports_sent_via")
    op.execute(
        "ALTER TABLE abuse_reports ADD CONSTRAINT ck_abuse_reports_sent_via "
        "CHECK (sent_via IS NULL OR (sent_via IN ('manual', 'smtp', 'form') "
        "AND status IN ('sent', 'closed') AND (sent_via <> 'form' OR channel = 'form')))"
    )
    op.execute(CHANNEL_GUARD)
    op.execute(
        "CREATE TRIGGER abuse_reports_channel_guard BEFORE UPDATE ON abuse_reports "
        "FOR EACH ROW EXECUTE FUNCTION abuse_reports_channel_guard()"
    )
    op.execute(
        "CREATE INDEX ix_abuse_reports_form_open ON abuse_reports (id) "
        "WHERE channel = 'form' AND status IN ('draft', 'reviewed')"
    )

    # -- subjects: submitted by form ----------------------------------------------------------
    op.execute("ALTER TABLE abuse_report_subjects ADD COLUMN submitted_at timestamptz")
    op.execute(SUBJECT_GUARD)
    op.execute(
        "CREATE TRIGGER abuse_report_subjects_form_guard BEFORE UPDATE OR DELETE "
        "ON abuse_report_subjects FOR EACH ROW EXECUTE FUNCTION abuse_report_subjects_form_guard()"
    )

    # -- recipients: where form_only came from ------------------------------------------------
    op.execute(
        "ALTER TABLE abuse_recipients ADD COLUMN form_source text "
        f"CONSTRAINT ck_abuse_recipients_form_source CHECK (form_source IN ({FORM_SOURCES}))"
    )
    op.execute(
        "ALTER TABLE abuse_recipients ADD COLUMN form_entry text "
        "CONSTRAINT ck_abuse_recipients_form_entry CHECK (form_entry ~ '^[a-z0-9][a-z0-9-]{1,62}$')"
    )
    op.execute("UPDATE abuse_recipients SET form_source = 'reply' WHERE form_only")

    # -- settings -------------------------------------------------------------------------------
    op.execute(
        "ALTER TABLE report_settings ADD COLUMN form_name text "
        "CONSTRAINT ck_report_settings_form_name CHECK (char_length(form_name) <= 100)"
    )

    # -- takedown and Results: the form channel -----------------------------------------------
    op.execute(_drop_checks("takedown_targets", "channels"))
    op.execute(
        "ALTER TABLE takedown_targets ADD CONSTRAINT ck_takedown_targets_channels "
        "CHECK (channels <@ ARRAY['mail', 'form', 'urlhaus', 'threatfox'])"
    )
    op.execute(_drop_checks("outcome_rollup_monthly", "channel"))
    op.execute(
        "ALTER TABLE outcome_rollup_monthly ADD CONSTRAINT ck_outcome_rollup_monthly_channel "
        "CHECK (channel IN ('mail', 'form', 'urlhaus', 'threatfox'))"
    )


def downgrade() -> None:
    # A report submitted by form cannot be expressed before 0041: refuse rather than lose it.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM abuse_reports WHERE sent_via = 'form') THEN
                RAISE EXCEPTION 'downgrade refused: reports were submitted by form '
                    '(abuse_reports.sent_via = form). Use just rollback, which restores the '
                    'database dump taken before the update.';
            END IF;
        END
        $$
        """
    )
    op.execute("DELETE FROM outcome_rollup_monthly WHERE channel = 'form'")
    op.execute(
        "ALTER TABLE outcome_rollup_monthly DROP CONSTRAINT IF EXISTS "
        "ck_outcome_rollup_monthly_channel"
    )
    op.execute(
        "ALTER TABLE outcome_rollup_monthly ADD CONSTRAINT outcome_rollup_monthly_channel_check "
        "CHECK (channel IN ('mail', 'urlhaus', 'threatfox'))"
    )
    op.execute("UPDATE takedown_targets SET channels = array_remove(channels, 'form')")
    op.execute(
        "ALTER TABLE takedown_targets DROP CONSTRAINT IF EXISTS ck_takedown_targets_channels"
    )
    op.execute(
        "ALTER TABLE takedown_targets ADD CONSTRAINT takedown_targets_channels_check "
        "CHECK (channels <@ ARRAY['mail', 'urlhaus', 'threatfox'])"
    )
    op.execute("ALTER TABLE report_settings DROP COLUMN IF EXISTS form_name")
    # A flag the shared directory set has no source to clear it once the column is gone: the
    # older code would keep that desk off mail for good. Mail is the default again.
    op.execute(
        "UPDATE abuse_recipients SET form_only = false WHERE form_only "
        "AND form_source = 'directory'"
    )
    op.execute("ALTER TABLE abuse_recipients DROP COLUMN IF EXISTS form_entry")
    op.execute("ALTER TABLE abuse_recipients DROP COLUMN IF EXISTS form_source")
    op.execute("DROP TRIGGER IF EXISTS abuse_report_subjects_form_guard ON abuse_report_subjects")
    op.execute("DROP FUNCTION IF EXISTS abuse_report_subjects_form_guard()")
    op.execute("ALTER TABLE abuse_report_subjects DROP COLUMN IF EXISTS submitted_at")
    op.execute("DROP INDEX IF EXISTS ix_abuse_reports_form_open")
    op.execute("DROP TRIGGER IF EXISTS abuse_reports_channel_guard ON abuse_reports")
    op.execute("DROP FUNCTION IF EXISTS abuse_reports_channel_guard()")
    op.execute("ALTER TABLE abuse_reports DROP CONSTRAINT IF EXISTS ck_abuse_reports_sent_via")
    op.execute(
        "ALTER TABLE abuse_reports ADD CONSTRAINT ck_abuse_reports_sent_via "
        "CHECK ((sent_via IN ('manual', 'smtp') AND status IN ('sent', 'closed')) "
        "OR sent_via IS NULL)"
    )
    op.execute("ALTER TABLE abuse_reports DROP COLUMN IF EXISTS week")
    # Open form reports go back to the mail channel; their recipient stays form-only, so no
    # automatic mail leaves.
    op.execute("UPDATE abuse_reports SET channel = 'mail' WHERE channel = 'form'")
