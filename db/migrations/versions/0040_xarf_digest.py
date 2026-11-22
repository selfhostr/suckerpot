"""XARF v4 and one daily digest per recipient (M38 phase P1).

Revision ID: 0040
Revises: 0039

* ``abuse_report_subjects.kind`` (``attack_source`` | ``payload_host`` | ``c2``), backfilled from
  the report. The primary key becomes ``(report_id, kind, subject_type, value)``: one address can be
  both an attacker and a payload host in one digest.
* ``abuse_report_subjects.xarf_id``: the random id of a subject's XARF report (unique). The subjects
  of open (draft and reviewed) reports get one now, so a reviewed report goes out with its XARF
  parts as it is.
* ``abuse_reports.kind`` accepts ``digest``; ``due_at`` (when a digest is due), ``part`` (its part
  number that day) and ``channel`` (``mail``, or ``form`` for M38 P3).
* ``ux_abuse_reports_open`` (one open report per recipient and kind) becomes two indexes: one
  ``draft`` and one ``reviewed`` per recipient and kind. The builder makes only ``digest`` drafts,
  so a recipient has one digest draft and at most one reviewed digest. The open drafts of the
  older kinds stay valid under the new indexes; the builder merges them into one digest on its
  first cycle and marks them ``superseded``.
* Pending automatic send requests of drafts are cancelled with ``digest_migration``: those drafts
  are about to be merged, and nothing may go out during the upgrade. Manual requests, and the
  requests of reviewed reports, are kept.
* ``abuse_replies.match_method`` accepts ``xarf_id`` (a reply that quotes a source's report id).
* ``abuse_subject_outcomes``: which replies speak about which source of a report. The outcome is
  read from the reply itself (classification, verified, still linked), so a reply the owner fixes
  by hand is never out of step.
* ``report_settings.xarf_org`` (``reporter.org``, at most 100 characters) and ``digest_enabled``
  (default true), ``report_smtp.digest_minute`` (minutes after 00:00 UTC, random between 06:00
  and 09:00 for each install), ``abuse_recipients.xarf_strict`` (one mail per source).

Safe on a large database: every table touched here is small (reports, subjects, replies, send
requests, settings; thousands of rows at most). ``events`` and ``sessions`` are not touched. The
new columns either have no default or a constant one (no rewrite), except ``report_smtp`` (one row).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0040"
down_revision: str | None = "0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = "'attack_source', 'payload_host', 'c2'"
OUTCOMES = "'auto_ack', 'ticket_opened', 'resolved', 'rejected', 'bounce', 'human_reply', 'unknown'"
OLD_METHODS = "'message_id', 'token', 'dsn', 'ticket', 'sender_domain', 'manual', 'none'"
NEW_METHODS = "'message_id', 'token', 'xarf_id', 'dsn', 'ticket', 'sender_domain', 'manual', 'none'"


def _drop_checks(table: str, needle: str) -> str:
    """Drop the CHECK constraints of ``table`` whose definition contains ``needle`` (the column
    constraints of 0019 and 0026 have generated names)."""
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
    # -- subjects: kind and the XARF report id ------------------------------------------------
    op.execute("ALTER TABLE abuse_report_subjects ADD COLUMN kind text")
    op.execute(
        "UPDATE abuse_report_subjects s SET kind = r.kind FROM abuse_reports r "
        "WHERE r.id = s.report_id"
    )
    op.execute("ALTER TABLE abuse_report_subjects ALTER COLUMN kind SET NOT NULL")
    op.execute(
        "ALTER TABLE abuse_report_subjects ADD CONSTRAINT ck_abuse_report_subjects_kind "
        f"CHECK (kind IN ({KINDS}))"
    )
    op.execute("ALTER TABLE abuse_report_subjects DROP CONSTRAINT abuse_report_subjects_pkey")
    op.execute(
        "ALTER TABLE abuse_report_subjects ADD CONSTRAINT abuse_report_subjects_pkey "
        "PRIMARY KEY (report_id, kind, subject_type, value)"
    )
    op.execute("ALTER TABLE abuse_report_subjects ADD COLUMN xarf_id uuid")
    op.execute(
        "UPDATE abuse_report_subjects SET xarf_id = gen_random_uuid() WHERE report_id IN "
        "(SELECT id FROM abuse_reports WHERE status IN ('draft', 'reviewed'))"
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_abuse_report_subjects_xarf_id ON abuse_report_subjects (xarf_id) "
        "WHERE xarf_id IS NOT NULL"
    )

    # -- reports: the digest kind, due time, part and channel ---------------------------------
    op.execute(_drop_checks("abuse_reports", "kind = ANY"))
    op.execute(
        "ALTER TABLE abuse_reports ADD CONSTRAINT ck_abuse_reports_kind "
        f"CHECK (kind IN ({KINDS}, 'digest'))"
    )
    op.execute("ALTER TABLE abuse_reports ADD COLUMN due_at timestamptz")
    op.execute(
        "ALTER TABLE abuse_reports ADD COLUMN part smallint NOT NULL DEFAULT 1 "
        "CONSTRAINT ck_abuse_reports_part CHECK (part BETWEEN 1 AND 100)"
    )
    op.execute(
        "ALTER TABLE abuse_reports ADD COLUMN channel text NOT NULL DEFAULT 'mail' "
        "CONSTRAINT ck_abuse_reports_channel CHECK (channel IN ('mail', 'form'))"
    )
    op.execute("DROP INDEX IF EXISTS ux_abuse_reports_open")
    op.execute(
        "CREATE UNIQUE INDEX ux_abuse_reports_draft ON abuse_reports (recipient_id, kind) "
        "WHERE status = 'draft'"
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_abuse_reports_reviewed ON abuse_reports (recipient_id, kind) "
        "WHERE status = 'reviewed'"
    )

    # -- nothing automatic leaves during the upgrade ------------------------------------------
    op.execute(
        "UPDATE abuse_send_requests SET status = 'cancelled', error_code = 'digest_migration', "
        "done_at = now() WHERE status = 'pending' AND auto AND kind = 'send' AND report_id IN "
        "(SELECT id FROM abuse_reports WHERE status = 'draft')"
    )

    # -- replies: the xarf_id match and per-source outcomes -----------------------------------
    op.execute(_drop_checks("abuse_replies", "match_method"))
    op.execute(
        "ALTER TABLE abuse_replies ADD CONSTRAINT ck_abuse_replies_match_method "
        f"CHECK (match_method IN ({NEW_METHODS}))"
    )
    op.execute(
        f"""
        CREATE TABLE abuse_subject_outcomes (
            report_id bigint NOT NULL,
            kind text NOT NULL CHECK (kind IN ({KINDS})),
            subject_type text NOT NULL CHECK (subject_type IN ('ip', 'url', 'domain')),
            value text NOT NULL CHECK (char_length(value) <= 1024),
            reply_id bigint NOT NULL REFERENCES abuse_replies (id) ON DELETE CASCADE,
            ticket_id text CHECK (char_length(ticket_id) <= 64),
            linked_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (report_id, kind, subject_type, value, reply_id),
            FOREIGN KEY (report_id, kind, subject_type, value)
                REFERENCES abuse_report_subjects (report_id, kind, subject_type, value)
                ON DELETE CASCADE
        )
        """
    )
    op.execute("CREATE INDEX ix_abuse_subject_outcomes_reply ON abuse_subject_outcomes (reply_id)")

    # -- settings ---------------------------------------------------------------------------
    op.execute(
        "ALTER TABLE report_settings ADD COLUMN xarf_org text "
        "CONSTRAINT ck_report_settings_xarf_org CHECK (char_length(xarf_org) <= 100)"
    )
    op.execute(
        "ALTER TABLE report_settings ADD COLUMN digest_enabled boolean NOT NULL DEFAULT true"
    )
    # Random per install (and per row on upgrade), so nodes do not all send at the same minute.
    op.execute(
        "ALTER TABLE report_smtp ADD COLUMN digest_minute smallint NOT NULL "
        "DEFAULT (360 + floor(random() * 180))::smallint "
        "CONSTRAINT ck_report_smtp_digest_minute CHECK (digest_minute BETWEEN 0 AND 1439)"
    )
    op.execute("ALTER TABLE abuse_recipients ADD COLUMN xarf_strict boolean NOT NULL DEFAULT false")


def downgrade() -> None:
    op.execute("ALTER TABLE abuse_recipients DROP COLUMN IF EXISTS xarf_strict")
    op.execute("ALTER TABLE report_smtp DROP COLUMN IF EXISTS digest_minute")
    op.execute("ALTER TABLE report_settings DROP COLUMN IF EXISTS digest_enabled")
    op.execute("ALTER TABLE report_settings DROP COLUMN IF EXISTS xarf_org")
    op.execute("DROP TABLE IF EXISTS abuse_subject_outcomes")
    op.execute("UPDATE abuse_replies SET match_method = 'token' WHERE match_method = 'xarf_id'")
    op.execute("ALTER TABLE abuse_replies DROP CONSTRAINT IF EXISTS ck_abuse_replies_match_method")
    op.execute(
        "ALTER TABLE abuse_replies ADD CONSTRAINT abuse_replies_match_method_check "
        f"CHECK (match_method IN ({OLD_METHODS}))"
    )
    # Digests cannot be expressed before 0040: they go, with their subjects (cascade). ``just
    # rollback`` restores the dump taken before the update instead.
    op.execute("DELETE FROM abuse_reports WHERE kind = 'digest'")
    op.execute("DROP INDEX IF EXISTS ux_abuse_reports_reviewed")
    op.execute("DROP INDEX IF EXISTS ux_abuse_reports_draft")
    op.execute(
        "CREATE UNIQUE INDEX ux_abuse_reports_open ON abuse_reports (recipient_id, kind) "
        "WHERE status IN ('draft', 'reviewed')"
    )
    op.execute("ALTER TABLE abuse_reports DROP COLUMN IF EXISTS channel")
    op.execute("ALTER TABLE abuse_reports DROP COLUMN IF EXISTS part")
    op.execute("ALTER TABLE abuse_reports DROP COLUMN IF EXISTS due_at")
    op.execute("ALTER TABLE abuse_reports DROP CONSTRAINT IF EXISTS ck_abuse_reports_kind")
    op.execute(
        "ALTER TABLE abuse_reports ADD CONSTRAINT abuse_reports_kind_check "
        f"CHECK (kind IN ({KINDS}))"
    )
    op.execute("DROP INDEX IF EXISTS ux_abuse_report_subjects_xarf_id")
    op.execute("ALTER TABLE abuse_report_subjects DROP COLUMN IF EXISTS xarf_id")
    # A digest could hold one value twice (as two kinds); those reports are gone above.
    op.execute("ALTER TABLE abuse_report_subjects DROP CONSTRAINT abuse_report_subjects_pkey")
    op.execute(
        "ALTER TABLE abuse_report_subjects ADD CONSTRAINT abuse_report_subjects_pkey "
        "PRIMARY KEY (report_id, subject_type, value)"
    )
    op.execute(
        "ALTER TABLE abuse_report_subjects DROP CONSTRAINT IF EXISTS ck_abuse_report_subjects_kind"
    )
    op.execute("ALTER TABLE abuse_report_subjects DROP COLUMN IF EXISTS kind")
