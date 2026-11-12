"""The migration files form one linear chain; the table and provider lists agree."""

import re
from pathlib import Path

import pytest

from suckerpot_db import models
from suckerpot_db.retention import (
    ABUSE_PRUNE_PROC,
    ALERT_PRUNE_PROC,
    CAMPAIGN_PRUNE_PROC,
    SCRIPT_PRUNE_PROC,
    RetentionError,
    abuse_reply_excerpt_days,
    abuse_report_retention_days,
    campaigns_max_rows,
    scripts_max_rows,
)
from suckerpot_db.roles import (
    _GRANTS_ANALYZER,
    _GRANTS_API,
    _GRANTS_COLLECTOR,
    _GRANTS_INGEST,
)
from suckerpot_db.secretbox import PROVIDERS

VERSIONS = Path(__file__).resolve().parents[1] / "migrations" / "versions"
NEW_TABLES = {
    "attack_techniques",
    "technique_daily",
    "campaigns",
    "campaign_keys",
    "campaign_sessions",
    "blocklist_entries",
    "blocklist_overrides",
    "feed_tokens",
    "inventory_services",
    "scripts",
    "script_sessions",
    "script_explanations",
    "llm_requests",
    "alert_channels",
    "alert_rules",
    "watched_cves",
    "alert_outbox",
    "alert_cursors",
    "weekly_reports",
    "alert_test_requests",
    "indicator_contacts",
    "indicator_contact_checks",
    "fetch_targets",
    "fetch_attempts",
    "samples",
    "sample_analysis",
    "sample_sources",
    "sample_links",
}
M21_TABLES = {
    "fetch_targets",
    "fetch_attempts",
    "samples",
    "sample_analysis",
    "sample_sources",
    "sample_links",
}


def revisions() -> dict[str, tuple[str | None, str]]:
    out: dict[str, tuple[str | None, str]] = {}
    for path in sorted(VERSIONS.glob("*.py")):
        src = path.read_text()
        rev = re.search(r'^revision: str = "(\w+)"', src, re.M)
        down = re.search(r'^down_revision: str \| None = (None|"(\w+)")', src, re.M)
        assert rev and down, path.name
        out[rev.group(1)] = (down.group(2), path.name)
    return out


def test_the_chain_is_linear_up_to_0034() -> None:
    revs = revisions()
    assert len(revs) == len({d for d, _ in revs.values()})  # no two revisions share a parent
    heads = set(revs) - {d for d, _ in revs.values() if d}
    assert heads == {"0034"}
    for n in range(11, 23):
        assert revs[f"{n:04d}"][0] == f"{n - 1:04d}"
    # 0023 and 0024 were never released; 0025 (M28) is chained on 0022.
    assert "0023" not in revs and "0024" not in revs
    assert revs["0025"][0] == "0022"
    assert revs["0026"][0] == "0025"
    assert revs["0027"][0] == "0026"
    # M29 (network, never deployed before 0027 went live) follows the deployed head.
    assert revs["0028"][0] == "0027"
    # M30 (community feed) follows 0028, which is deployed.
    assert revs["0029"][0] == "0028"
    # M32 (participant mode) follows 0029.
    assert revs["0030"][0] == "0029"
    # The ingest stall fix (pipeline heartbeat, chunk-pruning retract_benign) follows 0030.
    assert revs["0031"][0] == "0030"
    # Reputation answers are kept until refreshed (the 48 hour prune is gone) after 0031.
    assert revs["0032"][0] == "0031"
    # How the collector reached each file (typed marker, spared flag, link index) follows 0032.
    assert revs["0033"][0] == "0032"
    # Flood groups (kind, connections, fold_session_buckets) follow 0033.
    assert revs["0034"][0] == "0033"


def test_every_new_revision_has_a_downgrade() -> None:
    for name in (n for _, n in revisions().values() if int(n[:4]) >= 11):
        assert "def downgrade() -> None:" in (VERSIONS / name).read_text()


def test_models_cover_the_new_tables() -> None:
    assert NEW_TABLES <= set(models.Base.metadata.tables)


def test_the_role_scripts_name_every_new_table() -> None:
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in NEW_TABLES:
            assert f"'{table}'" in script, table


def test_feed_tokens_are_invisible_to_ingest() -> None:
    granted = re.findall(r"GRANT [A-Z, ]+ ON ([^']*?) TO", _GRANTS_INGEST.replace("\n", " "))
    assert not any("feed_tokens" in g for g in granted)
    assert not any(
        "alert_cursors" in g
        for g in re.findall(r"GRANT [A-Z, ]+ ON ([^']*?) TO", _GRANTS_API.replace("\n", " "))
    )


def test_the_provider_list_is_widened_everywhere() -> None:
    assert "smtp" in set(PROVIDERS) and "anthropic" not in set(PROVIDERS)
    src = (VERSIONS / "0013_scripts.py").read_text()
    new = re.search(r"_PROVIDERS_NEW = \((.*?)\)\n", src, re.S)
    assert new
    assert set(re.findall(r"'(\w+)'", new.group(1))) - {"anthropic"} == set(PROVIDERS)


def test_prune_procedures_are_created_by_their_migrations() -> None:
    for proc, name in (
        (CAMPAIGN_PRUNE_PROC, "0011_campaigns.py"),
        (SCRIPT_PRUNE_PROC, "0013_scripts.py"),
        (ALERT_PRUNE_PROC, "0014_alerts.py"),
        (ABUSE_PRUNE_PROC, "0019_abuse_reports.py"),
    ):
        assert f"PROCEDURE {proc}(" in (VERSIONS / name).read_text()


def test_max_rows_settings() -> None:
    assert campaigns_max_rows({}) == 50_000
    assert scripts_max_rows({"SCRIPTS_MAX_ROWS": " "}) == 100_000
    assert campaigns_max_rows({"CAMPAIGNS_MAX_ROWS": "2000"}) == 2000
    for bad in ("12", "x", "99999999999"):
        with pytest.raises(RetentionError, match="CAMPAIGNS_MAX_ROWS"):
            campaigns_max_rows({"CAMPAIGNS_MAX_ROWS": bad})


def _grants(script: str) -> dict[str, set[str]]:
    """Map each table to the privileges a role script grants on it."""
    joined = re.sub(r"'\s+'", "", script)  # adjacent SQL string literals form one statement
    out: dict[str, set[str]] = {}
    for privs, tables in re.findall(r"'GRANT ([A-Z, ]+) ON ([a-z_, ]+) TO %I'", joined):
        for table in (t.strip() for t in tables.split(",")):
            out.setdefault(table, set()).update(p.strip() for p in privs.split(","))
    return out


def test_the_api_only_reads_the_collector_tables() -> None:
    granted = _grants(_GRANTS_API)
    for table in M21_TABLES:
        assert granted[table] == {"SELECT"}, table


READ_ONLY_FOR_INGEST = ("fetch_targets", "samples", "sample_links", "sample_sources")


def test_ingest_only_reads_the_payload_tables() -> None:
    """M22 drafts name fetched payloads and C2 addresses: SELECT on four tables, nothing else."""
    granted = _grants(_GRANTS_INGEST)
    for table in M21_TABLES:
        if table in READ_ONLY_FOR_INGEST:
            assert granted[table] == {"SELECT"}, table
        else:
            assert table not in granted, table


def test_collector_grants() -> None:
    g = _grants(_GRANTS_COLLECTOR)
    assert g["indicators"] == {"SELECT"}
    for table in ("fetch_targets", "fetch_attempts", "samples", "sample_sources"):
        assert g[table] >= {"SELECT", "INSERT", "UPDATE"}, table
    assert g["fetch_attempts"] >= {"DELETE"}
    assert "DELETE" not in g["samples"] | g["fetch_targets"] | g["sample_sources"]
    assert g["enrichment_status"] >= {"SELECT", "INSERT", "UPDATE"}
    # 0033: it reads the links between files and targets (which targets only plain web content
    # leads to), and never writes them.
    assert g["sample_links"] == {"SELECT"}
    for table in ("sample_analysis", "users", "events", "sessions"):
        assert table not in g, table


def test_analyzer_grants() -> None:
    g = _grants(_GRANTS_ANALYZER)
    assert g["samples"] == {"SELECT", "UPDATE"}
    assert g["sample_analysis"] >= {"SELECT", "INSERT", "UPDATE"}
    assert g["sample_links"] >= {"SELECT", "INSERT", "UPDATE"}
    assert g["fetch_targets"] == {"SELECT", "INSERT"}
    assert g["indicators"] == {"SELECT", "INSERT"}  # UPDATE is column-level
    assert "UPDATE (last_seen, sightings, trusted) ON indicators" in _GRANTS_ANALYZER
    for table in (
        "enrichment_status",
        "enrichment_quota",
        "fetch_attempts",
        "events",
        "sessions",
        "users",
        "provider_secrets",
    ):
        assert table not in g, table
    assert not any("DELETE" in p for p in g.values())


def test_collector_is_confined_to_its_own_shared_rows() -> None:
    assert (
        "name IN ('collector', 'egress_collector', 'takedown_http')"
        in _GRANTS_COLLECTOR.replace("''", "'")
    )
    assert "provider IN ('collector', 'takedown_http')" in _GRANTS_COLLECTOR.replace("''", "'")
    assert "CREATE POLICY sp_collector_status" in _GRANTS_COLLECTOR
    assert "CREATE POLICY sp_collector_quota" in _GRANTS_COLLECTOR
    for script in (_GRANTS_INGEST, _GRANTS_API):
        assert "USING (true) WITH CHECK (true)" in script


M22_TABLES = {
    "rdap_bootstrap",
    "abuse_networks",
    "abuse_lookups",
    "abuse_recipients",
    "abuse_reports",
    "abuse_report_subjects",
    "abuse_report_requests",
    "report_settings",
    "report_self_terms",
}


def test_models_cover_the_m22_tables() -> None:
    assert M22_TABLES <= set(models.Base.metadata.tables)
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in M22_TABLES:
            assert f"'{table}'" in script, table


def test_abuse_report_retention_setting() -> None:
    assert abuse_report_retention_days({}) == 730
    assert abuse_report_retention_days({"ABUSE_REPORT_RETENTION_DAYS": "90"}) == 90
    for bad in ("1", "x", "99999"):
        with pytest.raises(RetentionError, match="ABUSE_REPORT_RETENTION_DAYS"):
            abuse_report_retention_days({"ABUSE_REPORT_RETENTION_DAYS": bad})


def _update_columns(script: str, table: str) -> set[str]:
    joined = re.sub(r"'\s+'", "", script)
    found = re.findall(rf"'GRANT UPDATE \(([a-z0-9_, ]+)\) ON {table} TO %I'", joined)
    return {c.strip() for cols in found for c in cols.split(",")}


def test_m22_column_grants() -> None:
    api = _update_columns(_GRANTS_API, "abuse_reports")
    ingest = _update_columns(_GRANTS_INGEST, "abuse_reports")
    assert {"status", "notes", "options", "sent_at", "reviewed_by", "closed_at"} <= api
    assert not api & {"evidence", "content_sha256", "guard_ok", "recipient_id", "demo"}
    assert {"evidence", "status", "guard_ok"} <= ingest
    # M25: ingest may stamp a report it sent by SMTP (trigger: pending request required).
    assert not ingest & {"notes", "closed_at", "closed_by"}
    assert {"sent_at", "sent_by", "sent_via"} <= ingest
    assert "sent_via" in api
    for script in (_GRANTS_API, _GRANTS_INGEST):
        assert not re.search(r"GRANT [A-Z, ]*UPDATE[A-Z, ]* ON abuse_reports", script)


def test_m25_grants_keep_the_password_away_from_the_api() -> None:
    api = _grants(_GRANTS_API)
    assert {"INSERT", "UPDATE", "DELETE"} <= api["report_smtp"]
    select = re.search(
        r"GRANT SELECT \(([a-z_, ]+)\)\s*'?\s*'?ON report_smtp", re.sub(r"'\s+'", "", _GRANTS_API)
    )
    assert select and "password_set" in select.group(1)
    assert "password_ciphertext" not in select.group(1) and "password_nonce" not in select.group(1)
    assert _grants(_GRANTS_INGEST)["report_smtp"] == {"SELECT"}
    assert "report_smtp" not in _grants(_GRANTS_COLLECTOR)
    assert _update_columns(_GRANTS_API, "abuse_send_requests") == {"status"}
    assert _update_columns(_GRANTS_INGEST, "abuse_send_requests") == {
        "status",
        "error_code",
        "done_at",
        "started_at",
        "message_id",  # M26: written once, when ingest claims the request
    }
    assert "DELETE" not in _grants(_GRANTS_API)["abuse_send_requests"]


def test_trusted_exit_grants() -> None:
    """M23: the API manages the ranges; ingest and the collector only read them."""
    assert _grants(_GRANTS_API)["egress_trusted_exits"] == {"SELECT", "INSERT", "DELETE"}
    assert _grants(_GRANTS_INGEST)["egress_trusted_exits"] == {"SELECT"}
    assert _grants(_GRANTS_COLLECTOR)["egress_trusted_exits"] == {"SELECT"}
    assert "egress_trusted_exits" not in _grants(_GRANTS_ANALYZER)


def test_check_request_grants() -> None:
    """M24: the API files "Check now" requests; ingest answers them. Nobody can delete."""
    assert _grants(_GRANTS_API)["egress_check_requests"] == {"SELECT", "INSERT"}
    assert _grants(_GRANTS_INGEST)["egress_check_requests"] == {"SELECT"}
    assert _update_columns(_GRANTS_INGEST, "egress_check_requests") == {"done_at"}
    assert not _update_columns(_GRANTS_API, "egress_check_requests")
    assert "egress_check_requests" not in _grants(_GRANTS_COLLECTOR)
    assert "egress_check_requests" not in _grants(_GRANTS_ANALYZER)


NETWORK_TABLES = ("network_membership", "network_submissions", "network_targets", "network_summary")


def test_network_tables_are_modelled_and_granted() -> None:
    assert set(NETWORK_TABLES) <= set(models.Base.metadata.tables)
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in NETWORK_TABLES:
            assert f"'{table}'" in script, table
    for script in (_GRANTS_COLLECTOR, _GRANTS_ANALYZER):
        assert not any(t in script for t in NETWORK_TABLES)


def test_network_grants_keep_the_private_key_away_from_the_api() -> None:
    api = re.sub(r"'\s+'", "", _GRANTS_API)
    select = re.search(r"GRANT SELECT \(([a-z_, ]+)\)\s*ON network_membership", api)
    assert select, "the API reads the membership by column"
    cols = {c.strip() for c in select.group(1).split(",")}
    assert {"desired", "state", "fingerprint", "pubkey"} <= cols
    assert not {"privkey_enc", "privkey_nonce"} & cols
    assert _update_columns(_GRANTS_API, "network_membership") == {
        "desired", "pseudonym", "country", "show_country", "requested_by", "requested_at",
    }  # fmt: skip
    g = _grants(_GRANTS_API)
    for table in ("network_submissions", "network_targets", "network_summary"):
        assert g[table] == {"SELECT"}
    ingest = _grants(_GRANTS_INGEST)
    assert ingest["network_membership"] == {"SELECT", "UPDATE"}
    assert "INSERT" not in ingest["network_membership"]  # the row is seeded by the migration


def test_the_network_prune_procedure_is_created_by_its_migration() -> None:
    from suckerpot_db.retention import NETWORK_PRUNE_PROC

    assert f"PROCEDURE {NETWORK_PRUNE_PROC}(" in (VERSIONS / "0028_network.py").read_text()


FEED_TABLES = ("network_feed_state", "network_feed_entries")


def test_feed_tables_are_modelled_and_least_privilege() -> None:
    assert set(FEED_TABLES) <= set(models.Base.metadata.tables)
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in FEED_TABLES:
            assert f"'{table}'" in script, table  # in the REVOKE list
    ingest = _grants(_GRANTS_INGEST)
    api = _grants(_GRANTS_API)
    for table in FEED_TABLES:
        assert ingest[table] == {"SELECT", "INSERT", "UPDATE", "DELETE"}, table
        assert api[table] == {"SELECT"}, table
    for script in (_GRANTS_COLLECTOR, _GRANTS_ANALYZER):
        assert not any(t in script for t in FEED_TABLES)
    for script in (_GRANTS_INGEST, _GRANTS_API):
        assert "TO PUBLIC" not in script.upper()


def test_the_feed_migration_leaves_the_hypertables_and_jobs_alone() -> None:
    script = (VERSIONS / "0029_network_feed.py").read_text()
    code = script.split("def upgrade", 1)[1]
    for hypertable in ("events", "sessions"):
        assert not re.search(rf"\b(TABLE|ON|INTO|FROM)\s+{hypertable}\b", code), hypertable
    assert "add_job" not in code and "CREATE PROCEDURE" not in code.upper()


M26_TABLES = {
    "report_imap",
    "report_imap_state",
    "report_imap_requests",
    "abuse_replies",
    "abuse_reply_imports",
    "abuse_report_outcomes",
}


def test_models_and_role_scripts_cover_the_m26_tables() -> None:
    assert M26_TABLES <= set(models.Base.metadata.tables)
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in M26_TABLES:
            assert f"'{table}'" in script, table
    for script in (_GRANTS_COLLECTOR, _GRANTS_ANALYZER):
        assert not M26_TABLES & set(_grants(script))


def _select_columns(script: str, table: str) -> set[str]:
    joined = re.sub(r"'\s+'", "", script)
    found = re.findall(rf"'GRANT SELECT \(([a-z0-9_, ]+)\) ON {table} TO %I'", joined)
    return {c.strip() for cols in found for c in cols.split(",")}


def test_m26_the_mailbox_password_never_reaches_the_api() -> None:
    cols = _select_columns(_GRANTS_API, "report_imap")
    assert "password_set" in cols
    assert not cols & {"password_ciphertext", "password_nonce"}
    assert _grants(_GRANTS_API)["report_imap"] >= {"INSERT", "UPDATE", "DELETE"}
    assert _grants(_GRANTS_INGEST)["report_imap"] == {"SELECT"}
    # Pasted mail: the API cannot read the raw bytes back.
    assert "raw" not in _select_columns(_GRANTS_API, "abuse_reply_imports")
    assert _grants(_GRANTS_API)["abuse_reply_imports"] == {"INSERT"}


def test_m26_outcome_columns_are_split_between_ingest_and_the_api() -> None:
    manual = {"manual_outcome", "manual_at", "manual_by", "note"}
    ingest_up = _update_columns(_GRANTS_INGEST, "abuse_report_outcomes")
    api_up = _update_columns(_GRANTS_API, "abuse_report_outcomes")
    assert api_up == manual
    assert not ingest_up & manual
    assert {"auto_outcome", "needs_review", "resolved_at"} <= ingest_up
    assert not api_up & ingest_up
    for table in ("abuse_report_outcomes", "abuse_replies", "report_imap_requests"):
        assert "DELETE" not in _grants(_GRANTS_API).get(table, set())
        assert "DELETE" not in _grants(_GRANTS_INGEST).get(table, set())


def test_m26_reply_columns() -> None:
    assert _update_columns(_GRANTS_INGEST, "abuse_replies") == {
        "report_id",
        "match_method",
        "verified",
        "excerpt",
        "excerpt_purged_at",
    }
    api = _update_columns(_GRANTS_API, "abuse_replies")
    assert {"report_id", "classification", "verified", "reviewed_by"} <= api
    assert not api & {"excerpt", "from_address", "message_id_sha256", "received_at"}
    assert "reply_domains" in _update_columns(_GRANTS_API, "abuse_recipients")
    assert not _update_columns(_GRANTS_INGEST, "abuse_recipients") - {"name"}


def test_m26_reply_excerpt_setting() -> None:
    assert abuse_reply_excerpt_days({}) == 180
    assert abuse_reply_excerpt_days({"ABUSE_REPLY_EXCERPT_DAYS": " 30 "}) == 30
    for bad in ("0", "x", "99999"):
        with pytest.raises(RetentionError, match="ABUSE_REPLY_EXCERPT_DAYS"):
            abuse_reply_excerpt_days({"ABUSE_REPLY_EXCERPT_DAYS": bad})


def test_m26_migration_text() -> None:
    src = (VERSIONS / "0026_report_outcomes.py").read_text()
    assert 'down_revision: str | None = "0025"' in src
    assert "NEW.reply_token <> OLD.reply_token" in src
    assert "PROCEDURE suckerpot_abuse_prune" in src
    assert "excerpt_days" in src


M27_TABLES = {
    "takedown_targets",
    "takedown_checks",
    "takedown_target_links",
    "abusech_submission",
    "abusech_submissions",
    "outcome_rollup_monthly",
}


def test_models_and_role_scripts_cover_the_m27_tables() -> None:
    assert M27_TABLES <= set(models.Base.metadata.tables)
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in M27_TABLES:
            assert f"'{table}'" in script, table


def test_m27_prune_procedure_and_setting() -> None:
    from suckerpot_db.retention import TAKEDOWN_PRUNE_PROC, takedown_check_retention_days

    src = (VERSIONS / "0027_takedown.py").read_text()
    assert f"PROCEDURE {TAKEDOWN_PRUNE_PROC}(" in src
    assert "DELETE FROM outcome_rollup_monthly" not in src  # the roll-up is kept forever
    assert takedown_check_retention_days({}) == 400
    assert takedown_check_retention_days({"TAKEDOWN_CHECK_RETENTION_DAYS": "60"}) == 60
    for bad in ("1", "x", "99999"):
        with pytest.raises(RetentionError, match="TAKEDOWN_CHECK_RETENTION_DAYS"):
            takedown_check_retention_days({"TAKEDOWN_CHECK_RETENTION_DAYS": bad})


def test_m27_column_grants() -> None:
    """The collector moves its own columns, the API only stops tracking, ingest owns the state."""
    collector = _update_columns(_GRANTS_COLLECTOR, "takedown_targets")
    assert collector == {
        "http_step",
        "http_next_at",
        "http_last_at",
        "last_sha256",
        "http_eligible",
    }
    assert _grants(_GRANTS_COLLECTOR)["takedown_targets"] == {"SELECT"}
    assert _grants(_GRANTS_COLLECTOR)["takedown_checks"] == {"INSERT"}
    assert "abusech_submission" not in _grants(_GRANTS_COLLECTOR)
    assert "abusech_submissions" not in _grants(_GRANTS_COLLECTOR)
    api = _update_columns(_GRANTS_API, "takedown_targets")
    assert api == {"tracking", "stopped_at", "stopped_by", "http_next_at", "listing_next_at"}
    ingest = _update_columns(_GRANTS_INGEST, "takedown_targets")
    assert {"state", "first_down_at", "baseline_sha256"} <= ingest
    # The one shared column: ingest switches re-checks off for an attacking or C2 host (T1).
    assert ingest & collector == {"http_eligible"}
    assert not ingest & {"kind", "role", "value", "target_key", "demo"}
    assert _update_columns(_GRANTS_API, "abusech_submissions") == {
        "status",
        "approved_at",
        "approved_by",
    }
    assert "result_code" not in _update_columns(_GRANTS_API, "abusech_submissions")
    assert _grants(_GRANTS_API)["takedown_checks"] == {"SELECT"}
    assert _grants(_GRANTS_API)["abusech_submissions"] == {"SELECT"}
    assert _grants(_GRANTS_INGEST)["abusech_submission"] == {"SELECT"}
    assert "DELETE" not in _grants(_GRANTS_INGEST)["abusech_submissions"]


def test_m27_api_cannot_read_the_auth_key() -> None:
    joined = re.sub(r"'\s+'", "", _GRANTS_API)
    select = re.search(r"GRANT SELECT \(([a-z0-9_, ]+)\)\s*ON abusech_submission TO", joined)
    assert select
    cols = select.group(1)
    assert "key_set" in cols and "key_last4" in cols
    assert "key_ciphertext" not in cols and "key_nonce" not in cols


def test_role_scripts_have_balanced_if_blocks() -> None:
    """A merge once dropped an END IF; the grants are only parsed by the database."""
    for script in (_GRANTS_INGEST, _GRANTS_API, _GRANTS_COLLECTOR, _GRANTS_ANALYZER):
        opened = len(re.findall(r"^\s*IF\b.*\bTHEN\s*$", script, re.M))
        closed = len(re.findall(r"^\s*END IF;", script, re.M))
        assert opened == closed


def test_m28_setup_progress_grants() -> None:
    assert _grants(_GRANTS_API)["setup_progress"] == {"SELECT", "INSERT", "UPDATE"}
    assert "setup_progress" not in _grants(_GRANTS_INGEST)
    assert "setup_progress" not in _grants(_GRANTS_COLLECTOR)


def test_the_participant_migration_is_additive_and_leaves_the_hypertables_alone() -> None:
    script = (VERSIONS / "0030_network_participant.py").read_text()
    assert "ADD COLUMN left_day date NULL" in script
    assert "ADD COLUMN origin text NOT NULL DEFAULT 'local'" in script
    assert "CREATE TABLE network_verify_tasks" in script
    for table in ("events", "sessions"):
        assert f"ALTER TABLE {table}" not in script
    assert "network_verify_tasks" in set(models.Base.metadata.tables)
    assert "origin" in models.Base.metadata.tables["fetch_targets"].columns
    assert "left_day" in models.Base.metadata.tables["network_membership"].columns


def test_pipeline_state_is_modelled_and_least_privilege() -> None:
    assert "pipeline_state" in set(models.Base.metadata.tables)
    assert _grants(_GRANTS_INGEST)["pipeline_state"] == {"SELECT", "UPDATE"}
    assert _grants(_GRANTS_API)["pipeline_state"] == {"SELECT"}
    assert "pipeline_state" not in _grants(_GRANTS_COLLECTOR)
    assert "pipeline_state" not in _grants(_GRANTS_ANALYZER)


def test_retract_benign_migration_prunes_chunks() -> None:
    script = (VERSIONS / "0031_pipeline_state.py").read_text()
    assert "FOR r IN SELECT s.session_id" in script
    assert "USING r.sensor, r.session_id, r.started_at" in script
    assert "SET search_path = pg_catalog, public, pg_temp" in script
    assert "public.events" in script and "public.sessions" in script
    assert "REVOKE ALL ON FUNCTION retract_benign(text[]) FROM PUBLIC" in script


def test_the_flood_migration_text() -> None:
    from suckerpot_db.locks import SESSION_FOLD

    script = (VERSIONS / "0034_session_floods.py").read_text()
    # Both functions: owner rights, every name schema-qualified, nothing from public on the path.
    assert script.count("SET search_path = pg_catalog, pg_temp") == 2
    assert "search_path = pg_catalog, public" not in script
    assert script.count("LANGUAGE plpgsql SECURITY DEFINER") == 2
    assert script.count("SET lock_timeout = '2s'") == 2
    assert "REVOKE ALL ON FUNCTION {SIGNATURE} FROM PUBLIC" in script
    assert "REVOKE ALL ON FUNCTION {RESTORE_SIGNATURE} FROM PUBLIC" in script
    assert "DROP FUNCTION IF EXISTS {RESTORE_SIGNATURE}" in script
    # The refused tags are checked in SQL, whatever list the caller passes.
    assert "lower(t) NOT LIKE 'cve-%'" in script and "ARRAY[{_REFUSED_SQL}]" in script
    # Bounded: the demo test reads only the row's own events, never the source's whole hour.
    assert "e.session_id = s.session_id" in script
    assert "e.src_ip = r.src" not in script
    assert "pg_try_advisory_xact_lock({SESSION_FOLD})" in script  # the key comes from locks.py
    assert SESSION_FOLD == 34_001
    assert "FOR UPDATE OF s SKIP LOCKED" in script
    assert "ON CONFLICT (session_id) DO UPDATE" in script and "WHERE t.kind = 'burst'" in script
    assert "ix_sessions_src_ip_sensor_started_at" in script
    assert "coalesce(sum(connections), 0)" in script
    assert "downgrade refused" in script


def test_sessions_model_matches_the_flood_columns() -> None:
    table = models.Base.metadata.tables["sessions"]
    assert {"kind", "connections"} <= set(table.columns.keys())
    assert not table.columns["kind"].nullable and not table.columns["connections"].nullable
    names = {i.name for i in table.indexes}
    assert "ix_sessions_src_ip_sensor_started_at" in names and "ix_sessions_src_ip" not in names
    checks = {c.name for c in table.constraints if c.name}
    assert {
        "sessions_kind_check",
        "sessions_burst_id_check",
        "sessions_connections_check",
    } <= checks


def test_ingest_may_execute_the_fold_function_but_never_delete_sessions() -> None:
    assert (
        "_fold text := 'public.fold_session_buckets(inet[], text[], timestamptz[]" in _GRANTS_INGEST
    )
    assert "'text[], interval, integer, timestamptz)'" in _GRANTS_INGEST
    assert "_restore text := 'public.restore_folded_sessions(text[])'" in _GRANTS_INGEST
    assert "IF to_regprocedure(_fold) IS NOT NULL THEN" in _GRANTS_INGEST
    assert "GRANT EXECUTE ON FUNCTION %s TO %I', _fold, r" in _GRANTS_INGEST
    assert "IF to_regprocedure(_restore) IS NOT NULL THEN" in _GRANTS_INGEST
    assert "GRANT EXECUTE ON FUNCTION %s TO %I', _restore, r" in _GRANTS_INGEST
    others = _GRANTS_API + _GRANTS_COLLECTOR + _GRANTS_ANALYZER
    assert "fold_session_buckets" not in others and "restore_folded_sessions" not in others
    assert _grants(_GRANTS_INGEST)["sessions"] == {"SELECT", "INSERT", "UPDATE"}
    assert _grants(_GRANTS_API)["sessions"] == {"SELECT"}
