"""Least-privilege database roles, applied idempotently on every migrate run.

``suckerpot_ingest`` may read and write events/sessions; ``suckerpot_api`` is read-only, except
for the encrypted provider keys it manages (``provider_secrets``) and the dashboard accounts and
audit log (``users``, ``audit_log``); ingest has no access to those two. From M15 on, the
campaign, defend, script and alert tables follow the matrix in the migrations' docstrings.
Names and passwords come from POSTGRES_{INGEST,API,COLLECTOR,ANALYZER}_USER/PASSWORD.
M21 adds ``suckerpot_collector`` (downloads into quarantine) and ``suckerpot_analyzer`` (static
analysis, no network); both exist only when their password is set.

Passwords never reach the server as plain text: a SCRAM-SHA-256 verifier is computed here and
sent instead (PostgreSQL accepts pre-hashed passwords), so server logs and error CONTEXT
lines cannot contain the real password. Errors are re-raised without the original
exception chain for the same reason.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from collections.abc import Mapping

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

INGEST_DEFAULT = "suckerpot_ingest"
API_DEFAULT = "suckerpot_api"
COLLECTOR_DEFAULT = "suckerpot_collector"
ANALYZER_DEFAULT = "suckerpot_analyzer"
SCRAM_ITERATIONS = 4096


class RoleError(RuntimeError):
    """Raised with a sanitized message (never contains a password)."""


def scram_verifier(password: str, salt: bytes | None = None) -> str:
    """PostgreSQL SCRAM-SHA-256 verifier for ``password`` (ASCII only, no SASLprep needed)."""
    if not password.isascii():
        raise RoleError("database role passwords must be ASCII")
    salt = salt if salt is not None else os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, SCRAM_ITERATIONS)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = base64.b64encode
    return (
        f"SCRAM-SHA-256${SCRAM_ITERATIONS}:{b64(salt).decode()}$"
        f"{b64(stored_key).decode()}:{b64(server_key).decode()}"
    )


COLLECTOR_STATUS = "name IN (''collector'', ''egress_collector'', ''takedown_http'')"
COLLECTOR_QUOTA = "provider IN (''collector'', ''takedown_http'')"


def _rls(tag: str, status: str, quota: str) -> str:
    """Policies of one role on the two tables shared with other services (RLS is enabled by
    migration 0018; the table owner, used by migrate, is exempt). ``status`` and ``quota`` are
    SQL conditions already escaped for use inside a quoted format() argument."""
    lines = ["IF to_regclass('public.samples') IS NOT NULL THEN"]  # RLS exists from 0018 on
    for table, kind, cond in (
        ("enrichment_status", "status", status),
        ("enrichment_quota", "quota", quota),
    ):
        lines += [
            f"EXECUTE format('DROP POLICY IF EXISTS sp_{tag}_{kind} ON {table}');",
            f"EXECUTE format('CREATE POLICY sp_{tag}_{kind} ON {table} FOR ALL TO %I '",
            f"    'USING ({cond}) WITH CHECK ({cond})', r);",
        ]
    lines.append("END IF;")
    return "\n    ".join(lines)


def _policies(tag: str, rules: tuple[tuple[str, str, str], ...]) -> str:
    """Policies of one role on ``report_self_terms`` (RLS is enabled by migration 0019).
    Each rule is (command, USING condition, WITH CHECK condition), either condition may be
    empty. Policies are named sp_<tag>_terms_<command>."""
    lines = ["IF to_regclass('public.report_self_terms') IS NOT NULL THEN"]
    for cmd, using, check in rules:
        name = f"sp_{tag}_terms_{cmd.lower()}"
        clauses = ""
        if using:
            clauses += f" USING ({using})"
        if check:
            clauses += f" WITH CHECK ({check})"
        lines += [
            f"EXECUTE format('DROP POLICY IF EXISTS {name} ON report_self_terms');",
            f"EXECUTE format('CREATE POLICY {name} ON report_self_terms FOR {cmd} '",
            f"    'TO %I{clauses}', r);",
        ]
    lines.append("END IF;")
    return "\n    ".join(lines)


_UPSERT_ROLE = """
DO $$
DECLARE
    r text := current_setting('suckerpot.role_name');
    pw text := current_setting('suckerpot.role_verifier');
    t text := current_setting('suckerpot.role_timeout');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format(
            'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS', r, pw);
    ELSE
        EXECUTE format(
            'CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS', r, pw);
    END IF;
    EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', r, t);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), r);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
    -- Grants are explicit per table; earlier revisions used default privileges: remove them.
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', r);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', r);
END
$$
"""

_GRANTS_INGEST = """
DO $$
DECLARE
    r text := current_setting('suckerpot.role_name');
    _tables text := (
        SELECT string_agg(format('%I', c), ', ') FROM unnest(
            ARRAY['events', 'sessions', 'ip_reputation', 'enrichment_quota', 'enrichment_status',
                  'sessions_daily', 'events_hourly', 'events_daily_tags', 'events_daily_country',
                  'events_daily_ip', 'system_status', 'maintenance_log', 'provider_secrets',
                  'provider_test_requests', 'cve', 'cve_sync_state', 'indicators',
                  'indicator_sessions', 'indicator_intel', 'users', 'audit_log',
                  'attack_techniques', 'technique_daily', 'campaigns', 'campaign_keys',
                  'campaign_sessions', 'blocklist_entries', 'blocklist_overrides', 'feed_tokens',
                  'inventory_services', 'scripts', 'script_sessions', 'script_explanations',
                  'llm_requests', 'alert_channels', 'alert_rules', 'watched_cves',
                  'alert_outbox', 'alert_cursors', 'weekly_reports', 'alert_test_requests',
                  'indicator_contacts', 'indicator_contact_checks', 'fetch_targets',
                  'fetch_attempts', 'samples', 'sample_analysis', 'sample_sources',
                  'sample_links', 'rdap_bootstrap', 'abuse_networks', 'abuse_lookups',
                  'abuse_recipients', 'abuse_reports', 'abuse_report_subjects',
                  'abuse_report_requests', 'report_settings', 'report_self_terms',
                  'egress_trusted_exits', 'egress_check_requests', 'report_smtp',
                  'abuse_send_requests', 'setup_progress', 'report_imap',
                  'report_imap_state', 'report_imap_requests', 'abuse_replies',
                  'abuse_reply_imports', 'abuse_report_outcomes',
                  'takedown_targets', 'takedown_checks',
                  'takedown_target_links', 'abusech_submission', 'abusech_submissions',
                  'outcome_rollup_monthly', 'network_membership',
                  'network_submissions', 'network_targets', 'network_summary',
                  'network_feed_state', 'network_feed_entries',
                  'network_verify_tasks']
        ) AS c WHERE to_regclass('public.' || c) IS NOT NULL
    );
BEGIN
    EXECUTE format('REVOKE ALL ON %s FROM %I', _tables, r);
    EXECUTE format('GRANT SELECT, INSERT ON events TO %I', r);
    -- Ingest cannot UPDATE events. The one change it needs (a scanner that turns out to do more
    -- loses the benign flag on its earlier events) goes through a SECURITY DEFINER function.
    IF to_regprocedure('public.retract_benign(text[])') IS NOT NULL THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.retract_benign(text[]) TO %I', r);
    END IF;
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON sessions TO %I', r);
    IF to_regclass('public.ip_reputation') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON ip_reputation, enrichment_quota, enrichment_status '
            'TO %I', r);
    END IF;
    IF to_regclass('public.system_status') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON system_status TO %I', r);
    END IF;
    IF to_regclass('public.provider_secrets') IS NOT NULL THEN
        -- Keys are written by the API only; ingest reads them and answers test requests.
        EXECUTE format('GRANT SELECT ON provider_secrets TO %I', r);
        EXECUTE format('GRANT SELECT, UPDATE ON provider_test_requests TO %I', r);
    END IF;
    IF to_regclass('public.cve') IS NOT NULL THEN
        -- The CVE watch job is the only writer; it prunes old, irrelevant CVEs (retention).
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON cve, cve_sync_state TO %I', r);
        EXECUTE format('GRANT DELETE ON cve TO %I', r);
    END IF;
    IF to_regclass('public.indicators') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON indicators, indicator_sessions, indicator_intel '
            'TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I', pg_get_serial_sequence('public.indicators', 'id'),
            r);
    END IF;
    IF to_regclass('public.indicator_contacts') IS NOT NULL THEN
        -- Probable C2 addresses read from intel providers: ingest is the only writer.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON indicator_contacts, '
            'indicator_contact_checks TO %I', r);
    END IF;
    IF to_regclass('public.campaigns') IS NOT NULL THEN
        -- M15: ingest is the only writer of the ATT&CK catalogue, counters and campaigns.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON attack_techniques, technique_daily, campaigns, '
            'campaign_keys, campaign_sessions TO %I', r);
        EXECUTE format('GRANT DELETE ON campaign_keys TO %I', r);
    END IF;
    IF to_regclass('public.blocklist_entries') IS NOT NULL THEN
        -- M16: ingest recomputes the blocklist (stale rows are deleted); it only reads what
        -- the API manages. feed_tokens: no access at all.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON blocklist_entries TO %I', r);
        EXECUTE format('GRANT SELECT ON blocklist_overrides, inventory_services TO %I', r);
    END IF;
    IF to_regclass('public.scripts') IS NOT NULL THEN
        -- M17: the script library is written by ingest; LLM requests are inserted by the API.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON scripts, script_sessions, script_explanations '
            'TO %I', r);
        EXECUTE format('GRANT SELECT, UPDATE ON llm_requests TO %I', r);
    END IF;
    IF to_regclass('public.alert_channels') IS NOT NULL THEN
        -- M18: the API manages channels, rules and watched CVEs; ingest sends and records.
        EXECUTE format(
            'GRANT SELECT ON alert_channels, alert_rules, watched_cves TO %I', r);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON alert_outbox, alert_cursors, weekly_reports TO %I',
            r);
        EXECUTE format('GRANT SELECT, UPDATE ON alert_test_requests TO %I', r);
    END IF;
    IF to_regclass('public.samples') IS NOT NULL THEN
        -- M22: draft reports name fetched payloads (hashes) and C2 addresses found in samples.
        EXECUTE format(
            'GRANT SELECT ON fetch_targets, samples, sample_links, sample_sources TO %I', r);
    END IF;
    IF to_regclass('public.abuse_reports') IS NOT NULL THEN
        -- M22: ingest looks contacts up and builds drafts. It cannot review, send or close a
        -- report (column grants and the transition trigger), nor write the owner's notes.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON rdap_bootstrap, abuse_networks, '
            'abuse_lookups TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON abuse_recipients, abuse_reports TO %I', r);
        EXECUTE format('GRANT UPDATE (name) ON abuse_recipients TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (status, window_start, window_end, subject_count, evidence, '
            'content_sha256, guard_ok, guard_codes, redaction, options) '
            'ON abuse_reports TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, DELETE ON abuse_report_subjects TO %I', r);
        EXECUTE format('GRANT SELECT ON abuse_report_requests TO %I', r);
        EXECUTE format('GRANT UPDATE (done_at, outcome) ON abuse_report_requests TO %I', r);
        EXECUTE format('GRANT SELECT ON report_settings TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON report_self_terms TO %I', r);
        EXECUTE format('GRANT UPDATE (distinct_sources, last_seen) ON report_self_terms TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s, %s, %s, %s TO %I',
            pg_get_serial_sequence('public.abuse_networks', 'id'),
            pg_get_serial_sequence('public.abuse_recipients', 'id'),
            pg_get_serial_sequence('public.abuse_reports', 'id'),
            pg_get_serial_sequence('public.report_self_terms', 'id'), r);
        -- @TERMS
    END IF;
    IF to_regclass('public.report_smtp') IS NOT NULL THEN
        -- M25: ingest is the only role that reads the SMTP password and the only one that sends.
        -- It marks a report sent only with a matching pending request (transition trigger).
        EXECUTE format('GRANT SELECT ON report_smtp TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON abuse_send_requests TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (status, error_code, done_at, started_at) '
            'ON abuse_send_requests TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.abuse_send_requests', 'id'), r);
        EXECUTE format(
            'GRANT UPDATE (sent_at, sent_by, sent_via, reviewed_at, reviewed_by, '
            'reviewed_revision) ON abuse_reports TO %I', r);
    END IF;
    IF to_regclass('public.report_imap') IS NOT NULL THEN
        -- M26: ingest is the only role that reads the mailbox password and the only one that
        -- reads mail. It writes the automatic outcome columns; the owner's override (manual
        -- columns) is the API's. The Message-ID of an SMTP send is written by ingest, once.
        EXECUTE format('GRANT SELECT ON report_imap, abuse_report_outcomes TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON report_imap_state TO %I', r);
        EXECUTE format('GRANT SELECT ON report_imap_requests TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (status, error_code, result, done_at) ON report_imap_requests TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON abuse_replies TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (report_id, match_method, verified, excerpt, excerpt_purged_at) '
            'ON abuse_replies TO %I', r);
        EXECUTE format('GRANT SELECT ON abuse_reply_imports TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (raw, status, reply_id, error_code, done_at) '
            'ON abuse_reply_imports TO %I', r);
        EXECUTE format(
            'GRANT INSERT (report_id, auto_outcome, reply_count, first_reply_at, '
            'first_human_at, ticket_at, resolved_at, rejected_at, bounced_at, ticket_id, '
            'needs_review, auto_updated_at) ON abuse_report_outcomes TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (auto_outcome, reply_count, first_reply_at, first_human_at, '
            'ticket_at, resolved_at, rejected_at, bounced_at, ticket_id, needs_review, '
            'auto_updated_at) ON abuse_report_outcomes TO %I', r);
        EXECUTE format('GRANT UPDATE (message_id) ON abuse_send_requests TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.abuse_replies', 'id'), r);
    END IF;
    IF to_regclass('public.takedown_targets') IS NOT NULL THEN
        -- M27: ingest syncs targets and decides their state. The abuse.ch grants stay although
        -- submission was removed in v0.11.0. The collector columns (HTTP re-check progress) and the
        -- API columns stay out of its reach.
        -- http_eligible is shared: ingest turns it off for a host that attacks or runs C2.
        EXECUTE format('GRANT SELECT, INSERT, DELETE ON takedown_targets TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (parent_id, fetch_target_id, network_id, asn, country, provider_key, '
            'provider_name, reported_at, channels, tracking, track_until, stopped_at, '
            'stopped_by, state, state_source, state_since, state_updated_at, '
            'down_before_report, last_up_at, first_down_at, resurrections, listing_step, '
            'listing_next_at, baseline_sha256, http_eligible) ON takedown_targets TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON takedown_checks TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, DELETE ON takedown_target_links TO %I', r);
        EXECUTE format('GRANT SELECT ON abusech_submission TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON abusech_submissions TO %I', r);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON outcome_rollup_monthly TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s, %s, %s TO %I',
            pg_get_serial_sequence('public.takedown_targets', 'id'),
            pg_get_serial_sequence('public.takedown_checks', 'id'),
            pg_get_serial_sequence('public.abusech_submissions', 'id'), r);
    END IF;
    IF to_regclass('public.network_membership') IS NOT NULL THEN
        -- M29: ingest runs the network worker: it owns every network table. Only ingest reads
        -- the private key. The API never writes a submission, a target or the summary.
        EXECUTE format('GRANT SELECT, UPDATE ON network_membership TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON network_submissions TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON network_targets TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON network_summary TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.network_submissions', 'id'), r);
    END IF;
    IF to_regclass('public.network_verify_tasks') IS NOT NULL THEN
        -- M32: the verifier worker owns the task table. It also queues the verification fetches:
        -- an INSERT limited to the columns it needs (origin is set explicitly; the collector
        -- owns status, attempts and results).
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON network_verify_tasks TO %I', r);
        EXECUTE format(
            'GRANT INSERT (url, scheme, host, depth, status, first_seen, next_attempt_at, origin) '
            'ON fetch_targets TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.fetch_targets', 'id'), r);
    END IF;
    IF to_regclass('public.network_feed_state') IS NOT NULL THEN
        -- M30: the feed worker owns the public feed mirror (state row and entries).
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON network_feed_state TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON network_feed_entries TO %I', r);
    END IF;
    IF to_regclass('public.egress_trusted_exits') IS NOT NULL THEN
        -- M23: the gate reads the ranges the owner trusted; only the API changes them.
        EXECUTE format('GRANT SELECT ON egress_trusted_exits TO %I', r);
    END IF;
    IF to_regclass('public.egress_check_requests') IS NOT NULL THEN
        -- M24: ingest answers "Check now" by waking its gate and stamping done_at.
        EXECUTE format('GRANT SELECT ON egress_check_requests TO %I', r);
        EXECUTE format('GRANT UPDATE (done_at) ON egress_check_requests TO %I', r);
    END IF;
    -- @RLS
    EXECUTE format(
        'GRANT USAGE ON SEQUENCE %s TO %I', pg_get_serial_sequence('public.events', 'id'), r);
END
$$
""".replace("-- @RLS", _rls("ingest", "true", "true")).replace(
    "-- @TERMS",
    _policies(
        "ingest",
        (
            ("SELECT", "true", ""),
            # Learned rows are never confirmed here (only the owner confirms); sensor rows
            # are trusted and always confirmed.
            (
                "INSERT",
                "",
                "(source = ''learned'' AND NOT confirmed) OR (source = ''sensor'' AND confirmed)",
            ),
            (
                "UPDATE",
                "source IN (''learned'', ''sensor'')",
                "source IN (''learned'', ''sensor'')",
            ),
        ),
    ),
)

_GRANTS_API = """
DO $$
DECLARE
    r text := current_setting('suckerpot.role_name');
    _tables text := (
        SELECT string_agg(format('%I', c), ', ') FROM unnest(
            ARRAY['events', 'sessions', 'ip_reputation', 'enrichment_quota', 'enrichment_status',
                  'sessions_daily', 'events_hourly', 'events_daily_tags', 'events_daily_country',
                  'events_daily_ip', 'system_status', 'maintenance_log', 'provider_secrets',
                  'provider_test_requests', 'cve', 'cve_sync_state', 'indicators',
                  'indicator_sessions', 'indicator_intel', 'users', 'audit_log',
                  'attack_techniques', 'technique_daily', 'campaigns', 'campaign_keys',
                  'campaign_sessions', 'blocklist_entries', 'blocklist_overrides', 'feed_tokens',
                  'inventory_services', 'scripts', 'script_sessions', 'script_explanations',
                  'llm_requests', 'alert_channels', 'alert_rules', 'watched_cves',
                  'alert_outbox', 'alert_cursors', 'weekly_reports', 'alert_test_requests',
                  'indicator_contacts', 'indicator_contact_checks', 'fetch_targets',
                  'fetch_attempts', 'samples', 'sample_analysis', 'sample_sources',
                  'sample_links', 'rdap_bootstrap', 'abuse_networks', 'abuse_lookups',
                  'abuse_recipients', 'abuse_reports', 'abuse_report_subjects',
                  'abuse_report_requests', 'report_settings', 'report_self_terms',
                  'egress_trusted_exits', 'egress_check_requests', 'report_smtp',
                  'abuse_send_requests', 'setup_progress', 'report_imap',
                  'report_imap_state', 'report_imap_requests', 'abuse_replies',
                  'abuse_reply_imports', 'abuse_report_outcomes',
                  'takedown_targets', 'takedown_checks',
                  'takedown_target_links', 'abusech_submission', 'abusech_submissions',
                  'outcome_rollup_monthly', 'network_membership',
                  'network_submissions', 'network_targets', 'network_summary',
                  'network_feed_state', 'network_feed_entries',
                  'network_verify_tasks']
        ) AS c WHERE to_regclass('public.' || c) IS NOT NULL
    );
BEGIN
    EXECUTE format('REVOKE ALL ON %s FROM %I', _tables, r);
    EXECUTE format('GRANT SELECT ON events, sessions TO %I', r);
    IF to_regclass('public.ip_reputation') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT ON ip_reputation, enrichment_quota, enrichment_status TO %I', r);
    END IF;
    IF to_regclass('public.sessions_daily') IS NOT NULL THEN
        -- Rollups kept forever: the API reads them for windows beyond raw retention.
        EXECUTE format(
            'GRANT SELECT ON sessions_daily, events_hourly, events_daily_tags, '
            'events_daily_country, events_daily_ip TO %I', r);
    END IF;
    IF to_regclass('public.system_status') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON system_status, maintenance_log TO %I', r);
    END IF;
    IF to_regclass('public.provider_secrets') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON provider_secrets TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON provider_test_requests TO %I', r);
    END IF;
    IF to_regclass('public.cve') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON cve, cve_sync_state TO %I', r);
    END IF;
    IF to_regclass('public.indicators') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON indicators, indicator_sessions, indicator_intel TO %I', r);
    END IF;
    IF to_regclass('public.indicator_contacts') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON indicator_contacts TO %I', r);
    END IF;
    IF to_regclass('public.users') IS NOT NULL THEN
        -- Dashboard accounts: the API manages them (deleting a user is allowed). The audit log
        -- is append-only for the API; the retention job, owned by the migration role, prunes it.
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON users TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON audit_log TO %I', r);
    END IF;
    IF to_regclass('public.campaigns') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT ON attack_techniques, technique_daily, campaigns, campaign_keys, '
            'campaign_sessions TO %I', r);
    END IF;
    IF to_regclass('public.blocklist_entries') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON blocklist_entries TO %I', r);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON blocklist_overrides, inventory_services '
            'TO %I', r);
        -- Feed tokens are revoked (UPDATE), never deleted.
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON feed_tokens TO %I', r);
    END IF;
    IF to_regclass('public.scripts') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT ON scripts, script_sessions, script_explanations TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON llm_requests TO %I', r);
    END IF;
    IF to_regclass('public.alert_channels') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON alert_channels, watched_cves TO %I', r);
        EXECUTE format('GRANT SELECT, UPDATE ON alert_rules TO %I', r);
        EXECUTE format('GRANT SELECT ON alert_outbox, weekly_reports TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON alert_test_requests TO %I', r);
    END IF;
    IF to_regclass('public.samples') IS NOT NULL THEN
        -- M21: the collector and analyzer write, the API only reads.
        EXECUTE format(
            'GRANT SELECT ON fetch_targets, fetch_attempts, samples, sample_analysis, '
            'sample_sources, sample_links TO %I', r);
    END IF;
    IF to_regclass('public.abuse_reports') IS NOT NULL THEN
        -- M22: the owner reviews and marks reports by hand; the API cannot change evidence.
        EXECUTE format(
            'GRANT SELECT ON rdap_bootstrap, abuse_networks, abuse_lookups, '
            'abuse_report_subjects, abuse_reports TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON abuse_recipients TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (override_mailbox, muted, reply_domains) ON abuse_recipients TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (status, notes, options, reviewed_at, reviewed_by, reviewed_revision, '
            'sent_at, sent_by, closed_at, closed_by) ON abuse_reports TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON abuse_report_requests TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON report_settings TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, DELETE ON report_self_terms TO %I', r);
        EXECUTE format('GRANT UPDATE (confirmed) ON report_self_terms TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s, %s, %s TO %I',
            pg_get_serial_sequence('public.abuse_recipients', 'id'),
            pg_get_serial_sequence('public.abuse_report_requests', 'id'),
            pg_get_serial_sequence('public.report_self_terms', 'id'), r);
        -- @TERMS
    END IF;
    IF to_regclass('public.report_smtp') IS NOT NULL THEN
        -- M25: the owner edits the profile. The API writes the password columns but can never
        -- read them back: column grants leave them out of SELECT.
        EXECUTE format(
            'GRANT SELECT (id, host, port, security, username, from_address, from_name, mode, '
            'auto_hold_minutes, daily_cap, password_set, updated_at, updated_by) '
            'ON report_smtp TO %I', r);
        EXECUTE format('GRANT INSERT, UPDATE, DELETE ON report_smtp TO %I', r);
        -- A send request is a row; cancelling updates the status only (trigger: pending only).
        EXECUTE format('GRANT SELECT, INSERT ON abuse_send_requests TO %I', r);
        EXECUTE format('GRANT UPDATE (status) ON abuse_send_requests TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.abuse_send_requests', 'id'), r);
        EXECUTE format('GRANT UPDATE (sent_via) ON abuse_reports TO %I', r);
    END IF;
    IF to_regclass('public.report_imap') IS NOT NULL THEN
        -- M26: the owner edits the mailbox profile (the password is write-only: column grants
        -- leave it out of SELECT), reads replies, fixes a match by hand and overrides an
        -- outcome. The automatic outcome columns and the reply content are ingest's.
        EXECUTE format(
            'GRANT SELECT (id, enabled, host, port, security, username, password_set, folder, '
            'processed_action, move_folder, poll_minutes, since, trusted_authserv_id, '
            'updated_at, updated_by) '
            'ON report_imap TO %I', r);
        EXECUTE format('GRANT INSERT, UPDATE, DELETE ON report_imap TO %I', r);
        EXECUTE format('GRANT SELECT ON report_imap_state TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON report_imap_requests TO %I', r);
        EXECUTE format('GRANT SELECT ON abuse_replies TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (report_id, match_method, verified, classification, '
            'classification_source, ticket_id, reviewed_at, reviewed_by) '
            'ON abuse_replies TO %I', r);
        EXECUTE format('GRANT INSERT ON abuse_reply_imports TO %I', r);
        EXECUTE format(
            'GRANT SELECT (id, report_id, requested_by, requested_at, status, reply_id, '
            'error_code, done_at) ON abuse_reply_imports TO %I', r);
        EXECUTE format('GRANT SELECT ON abuse_report_outcomes TO %I', r);
        EXECUTE format(
            'GRANT INSERT (report_id, manual_outcome, manual_at, manual_by, note) '
            'ON abuse_report_outcomes TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (manual_outcome, manual_at, manual_by, note) '
            'ON abuse_report_outcomes TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s, %s TO %I',
            pg_get_serial_sequence('public.report_imap_requests', 'id'),
            pg_get_serial_sequence('public.abuse_reply_imports', 'id'), r);
    END IF;
    IF to_regclass('public.takedown_targets') IS NOT NULL THEN
        -- M27: the owner stops tracking or asks for an early re-check; nothing else changes.
        EXECUTE format('GRANT SELECT ON takedown_targets, takedown_checks TO %I', r);
        EXECUTE format('GRANT SELECT ON takedown_target_links, outcome_rollup_monthly TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (tracking, stopped_at, stopped_by, http_next_at, listing_next_at) '
            'ON takedown_targets TO %I', r);
        -- The Auth-Key columns are written but never read back (column grants leave them out).
        EXECUTE format(
            'GRANT SELECT (id, mode, threatfox_enabled, anonymous, auto_hold_minutes, '
            'daily_cap, key_set, key_last4, updated_at, updated_by) '
            'ON abusech_submission TO %I', r);
        EXECUTE format('GRANT INSERT, UPDATE, DELETE ON abusech_submission TO %I', r);
        EXECUTE format('GRANT SELECT ON abusech_submissions TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (status, approved_at, approved_by) ON abusech_submissions TO %I', r);
    END IF;
    IF to_regclass('public.network_membership') IS NOT NULL THEN
        -- M29: the API reads everything but the private key and writes only the owner's wishes
        -- (a trigger limits ``desired`` to off -> member -> leave).
        EXECUTE format(
            'GRANT SELECT (id, desired, state, pseudonym, country, show_country, node_id, '
            'fingerprint, pubkey, enrolled_day, eligible_from_day, standing, next_submit_at, '
            'last_submit_day, last_pull_at, last_summary_at, leave_requested_at, '
            'last_error_code, requested_by, requested_at, updated_at) '
            'ON network_membership TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (desired, pseudonym, country, show_country, requested_by, '
            'requested_at) ON network_membership TO %I', r);
        EXECUTE format(
            'GRANT SELECT ON network_submissions, network_targets, network_summary TO %I', r);
    END IF;
    IF to_regclass('public.network_verify_tasks') IS NOT NULL THEN
        -- M32: the dashboard shows verification counts; it never writes a task.
        EXECUTE format('GRANT SELECT ON network_verify_tasks TO %I', r);
    END IF;
    IF to_regclass('public.network_feed_state') IS NOT NULL THEN
        -- M30: the API serves the feed status, entries and the local mirror; it never writes them.
        EXECUTE format('GRANT SELECT ON network_feed_state, network_feed_entries TO %I', r);
    END IF;
    IF to_regclass('public.egress_trusted_exits') IS NOT NULL THEN
        -- M23: the owner trusts or removes a VPN exit range from the dashboard.
        EXECUTE format('GRANT SELECT, INSERT, DELETE ON egress_trusted_exits TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.egress_trusted_exits', 'id'), r);
    END IF;
    IF to_regclass('public.setup_progress') IS NOT NULL THEN
        -- M28: the first-run setup keeps its one row here; ingest never reads it.
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON setup_progress TO %I', r);
    END IF;
    IF to_regclass('public.egress_check_requests') IS NOT NULL THEN
        -- M24: "Check now" inserts a request; the table trims itself (SECURITY DEFINER trigger).
        EXECUTE format('GRANT SELECT, INSERT ON egress_check_requests TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.egress_check_requests', 'id'), r);
    END IF;
    -- @RLS
END
$$
""".replace("-- @RLS", _rls("api", "true", "true")).replace(
    "-- @TERMS",
    _policies(
        "api",
        (
            ("SELECT", "true", ""),
            ("INSERT", "", "source = ''manual''"),
            ("UPDATE", "true", "true"),
            ("DELETE", "source IN (''manual'', ''learned'')", ""),
        ),
    ),
)

_GRANTS_COLLECTOR = """
DO $$
DECLARE r text := current_setting('suckerpot.role_name');
BEGIN
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', r);
    IF to_regclass('public.samples') IS NOT NULL THEN
        -- M21: the collector downloads recorded URLs into quarantine and records the result.
        EXECUTE format('GRANT SELECT ON indicators TO %I', r);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON fetch_targets, fetch_attempts, samples, '
            'sample_sources TO %I', r);
        EXECUTE format('GRANT DELETE ON fetch_attempts TO %I', r);
        -- M32: the table grant above already covers fetch_targets.origin (verification rows).
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON enrichment_quota, enrichment_status TO %I', r);
        -- Only its own rows; the policies hide and refuse every other provider and status.
        -- @RLS
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s, %s TO %I',
            pg_get_serial_sequence('public.fetch_targets', 'id'),
            pg_get_serial_sequence('public.fetch_attempts', 'id'), r);
    END IF;
    IF to_regclass('public.takedown_targets') IS NOT NULL THEN
        -- M27: re-checks of URLs that already served malware. The collector reads the targets,
        -- moves its own progress columns and appends checks; the state is ingest's.
        EXECUTE format('GRANT SELECT ON takedown_targets TO %I', r);
        EXECUTE format(
            'GRANT UPDATE (http_step, http_next_at, http_last_at, last_sha256, http_eligible) '
            'ON takedown_targets TO %I', r);
        EXECUTE format('GRANT INSERT ON takedown_checks TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I',
            pg_get_serial_sequence('public.takedown_checks', 'id'), r);
    END IF;
    IF to_regclass('public.egress_trusted_exits') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON egress_trusted_exits TO %I', r);
    END IF;
END
$$
""".replace("-- @RLS", _rls("collector", COLLECTOR_STATUS, COLLECTOR_QUOTA))

_GRANTS_ANALYZER = """
DO $$
DECLARE r text := current_setting('suckerpot.role_name');
BEGIN
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', r);
    IF to_regclass('public.samples') IS NOT NULL THEN
        -- M21: the analyzer has no network; it reads samples and writes findings.
        EXECUTE format('GRANT SELECT, UPDATE ON samples TO %I', r);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON sample_analysis, sample_links TO %I', r);
        EXECUTE format('GRANT SELECT ON sample_sources TO %I', r);
        -- Next-stage URLs found in a script become fetch targets (the collector updates them).
        EXECUTE format('GRANT SELECT, INSERT ON fetch_targets TO %I', r);
        -- Rows it adds (c2, hash) may only have these columns changed afterwards.
        EXECUTE format('GRANT SELECT, INSERT ON indicators TO %I', r);
        EXECUTE format('GRANT UPDATE (last_seen, sightings, trusted) ON indicators TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s, %s TO %I',
            pg_get_serial_sequence('public.fetch_targets', 'id'),
            pg_get_serial_sequence('public.indicators', 'id'), r);
    END IF;
END
$$
"""

_DROP_ROLE = """
DO $$
DECLARE r text := current_setting('suckerpot.role_name');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format('DROP OWNED BY %I', r);
        EXECUTE format('DROP ROLE %I', r);
    END IF;
END
$$
"""


def _role(env: Mapping[str, str], kind: str, default_name: str) -> tuple[str, str]:
    return (
        env.get(f"POSTGRES_{kind}_USER", default_name),
        env.get(f"POSTGRES_{kind}_PASSWORD", ""),
    )


def _set(conn: Connection, name: str, verifier: str, timeout: str) -> None:
    # is_local=true: the settings vanish at the end of the transaction.
    for key, value in (
        ("suckerpot.role_name", name),
        ("suckerpot.role_verifier", verifier),
        ("suckerpot.role_timeout", timeout),
    ):
        conn.execute(text("SELECT set_config(:k, :v, true)"), {"k": key, "v": value})


def apply_roles(conn: Connection, env: Mapping[str, str] | None = None) -> None:
    """Create or update the roles (password, attributes, timeouts, grants). Idempotent.

    Ingest and API are always created. The collector and analyzer roles (M21) are created only
    when their password is set, so a stack without the ``egress`` profile does not need them.
    """
    e = os.environ if env is None else env
    owner = e.get("POSTGRES_USER", "")
    roles = {
        "INGEST": _role(e, "INGEST", INGEST_DEFAULT),
        "API": _role(e, "API", API_DEFAULT),
        "COLLECTOR": _role(e, "COLLECTOR", COLLECTOR_DEFAULT),
        "ANALYZER": _role(e, "ANALYZER", ANALYZER_DEFAULT),
    }
    required = ("INGEST", "API")
    optional = tuple(k for k in ("COLLECTOR", "ANALYZER") if roles[k][1])
    active = required + optional
    for kind in active:
        name, password = roles[kind]
        if not password:
            raise RoleError(f"POSTGRES_{kind}_PASSWORD must be set to create the {kind} role")
        if name == owner:
            raise RoleError(f"POSTGRES_{kind}_USER must differ from POSTGRES_USER")
    names = [roles[k][0] for k in active]
    if len(set(names)) != len(names):
        raise RoleError("the database role names must all differ")

    all_steps = (
        ("INGEST", "30s", _GRANTS_INGEST),
        ("API", "5s", _GRANTS_API),
        ("COLLECTOR", "30s", _GRANTS_COLLECTOR),
        ("ANALYZER", "30s", _GRANTS_ANALYZER),
    )
    steps = [step for step in all_steps if step[0] in active]
    try:
        for kind, timeout, grants in steps:
            name, password = roles[kind]
            _set(conn, name, scram_verifier(password), timeout)
            conn.execute(text(_UPSERT_ROLE))
            conn.execute(text(grants))
    except DBAPIError as exc:
        code = getattr(exc.orig, "sqlstate", None)
        raise RoleError(f"applying database roles failed (SQLSTATE {code})") from None


def drop_roles(conn: Connection, env: Mapping[str, str] | None = None) -> None:
    e = os.environ if env is None else env
    for kind, default in (
        ("INGEST", INGEST_DEFAULT),
        ("API", API_DEFAULT),
        ("COLLECTOR", COLLECTOR_DEFAULT),
        ("ANALYZER", ANALYZER_DEFAULT),
    ):
        name, _ = _role(e, kind, default)
        _set(conn, name, "", "")
        conn.execute(text(_DROP_ROLE))
