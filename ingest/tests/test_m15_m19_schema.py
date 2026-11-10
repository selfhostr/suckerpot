"""Schema of migrations 0011 to 0015: grants per role, CHECK constraints, prune jobs.

Needs POSTGRES_HOST (owner credentials) like the other integration tests. The destructive
up/down test lives in ``test_zz_migrations_0011_0015.py`` and runs last.
"""

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from .db_fixtures import ROLE_ENV

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

S, INS, U, D = "SELECT", "INSERT", "UPDATE", "DELETE"
ALL_PRIVS = (S, INS, U, D)

# table -> (privileges of ingest, privileges of the API). Anything not listed is denied.
GRANTS: dict[str, tuple[set[str], set[str]]] = {
    "attack_techniques": ({S, INS, U}, {S}),
    "technique_daily": ({S, INS, U}, {S}),
    "campaigns": ({S, INS, U}, {S}),
    "campaign_keys": ({S, INS, U, D}, {S}),
    "campaign_sessions": ({S, INS, U}, {S}),
    "blocklist_entries": ({S, INS, U, D}, {S}),
    "blocklist_overrides": ({S}, {S, INS, U, D}),
    "feed_tokens": (set(), {S, INS, U}),
    "inventory_services": ({S}, {S, INS, U, D}),
    "scripts": ({S, INS, U}, {S}),
    "script_sessions": ({S, INS, U}, {S}),
    "script_explanations": ({S, INS, U}, {S}),
    "llm_requests": (set(), set()),  # retired table: nothing is granted
    "alert_channels": ({S}, {S, INS, U, D}),
    "alert_rules": ({S}, {S, U}),
    "watched_cves": ({S}, {S, INS, U, D}),
    "alert_outbox": ({S, INS, U}, {S}),
    "alert_cursors": ({S, INS, U}, set()),
    "weekly_reports": ({S, INS, U}, {S}),
    "alert_test_requests": ({S, U}, {S, INS}),
}


async def has_priv(engine: AsyncEngine, role: str, table: str, privilege: str) -> bool:
    async with engine.connect() as conn:
        return bool(
            await conn.scalar(
                text("SELECT has_table_privilege(:r, :t, :p)"),
                {"r": role, "t": table, "p": privilege},
            )
        )


@pytest.mark.parametrize("table", sorted(GRANTS))
async def test_grants_per_role(engine: AsyncEngine, table: str) -> None:
    ingest, api = ROLE_ENV["POSTGRES_INGEST_USER"], ROLE_ENV["POSTGRES_API_USER"]
    want_ingest, want_api = GRANTS[table]
    for priv in (*ALL_PRIVS, "TRUNCATE"):
        assert await has_priv(engine, ingest, table, priv) == (priv in want_ingest), (
            f"ingest {priv} on {table}"
        )
        assert await has_priv(engine, api, table, priv) == (priv in want_api), (
            f"api {priv} on {table}"
        )


async def test_the_new_session_and_event_columns_follow_the_existing_grants(
    engine: AsyncEngine,
) -> None:
    ingest, api = ROLE_ENV["POSTGRES_INGEST_USER"], ROLE_ENV["POSTGRES_API_USER"]
    assert await has_priv(engine, ingest, "sessions", U)
    assert await has_priv(engine, ingest, "events", INS)
    assert not await has_priv(engine, api, "sessions", U)
    assert not await has_priv(engine, api, "events", INS)


@pytest.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """An owner connection; whatever a test inserts is rolled back."""
    async with engine.connect() as c:
        tx = await c.begin()
        yield c
        await tx.rollback()


async def exec_(conn: AsyncConnection, sql: str, **params: Any) -> Any:
    return await conn.execute(text(sql), params)


async def rejected(conn: AsyncConnection, sql: str, **params: Any) -> bool:
    """True when the statement violates a constraint (the failure is rolled back to a savepoint)."""
    sp = await conn.begin_nested()
    try:
        await conn.execute(text(sql), params)
    except IntegrityError:
        await sp.rollback()
        return True
    await sp.rollback()
    return False


async def parents(conn: AsyncConnection) -> dict[str, int]:
    campaign = await exec_(
        conn,
        "INSERT INTO campaigns (name, first_seen, last_seen) VALUES ('c', now(), now()) "
        "RETURNING id",
    )
    script = await exec_(
        conn,
        "INSERT INTO scripts (fingerprint, normalized_text, sample_text, first_seen, last_seen) "
        "VALUES (decode(repeat('cd', 32), 'hex'), 'n', 's', now(), now()) RETURNING id",
    )
    channel = await exec_(
        conn,
        "INSERT INTO alert_channels (kind, name, target_ciphertext, created_by) "
        "VALUES ('discord', 'ops', decode(repeat('ab', 40), 'hex'), 'admin') RETURNING id",
    )
    return {
        "campaign": campaign.scalar_one(),
        "script": script.scalar_one(),
        "channel": channel.scalar_one(),
    }


BAD_ROWS: list[tuple[str, str]] = [
    ("attack_techniques", "INSERT INTO attack_techniques VALUES ('X1', 'n', 't', 'recon', 'u')"),
    (
        "attack_techniques",
        "INSERT INTO attack_techniques VALUES ('T1059.1', 'n', 't', 'recon', 'u')",
    ),
    ("attack_techniques", "INSERT INTO attack_techniques VALUES ('T1059', 'n', 't', 'bogus', 'u')"),
    ("attack_techniques", "INSERT INTO attack_techniques VALUES ('T1059', '', 't', 'recon', 'u')"),
    (
        "technique_daily",
        "INSERT INTO technique_daily (day, technique, sensor) VALUES (current_date, 'nope', 'ssh')",
    ),
    (
        "campaigns",
        "INSERT INTO campaigns (name, status, first_seen, last_seen) VALUES ('c', 'bogus', now(), now())",
    ),
    (
        "campaigns",
        "INSERT INTO campaigns (name, severity, first_seen, last_seen) VALUES ('c', 'bogus', now(), now())",
    ),
    ("campaigns", "INSERT INTO campaigns (name, first_seen, last_seen) VALUES ('', now(), now())"),
    (
        "campaigns",
        "INSERT INTO campaigns (name, first_seen, last_seen) VALUES (repeat('x', 129), now(), now())",
    ),
    (
        "campaign_keys",
        "INSERT INTO campaign_keys (kind, value, first_seen, last_seen) VALUES ('bogus', 'v', now(), now())",
    ),
    (
        "campaign_keys",
        "INSERT INTO campaign_keys (kind, value, first_seen, last_seen) VALUES ('hash', repeat('x', 129), now(), now())",
    ),
    (
        "blocklist_entries",
        "INSERT INTO blocklist_entries (kind, value, score, first_seen, last_seen) VALUES ('mac', 'v', 5, now(), now())",
    ),
    (
        "blocklist_entries",
        "INSERT INTO blocklist_entries (kind, value, score, first_seen, last_seen) VALUES ('ip', 'v', 101, now(), now())",
    ),
    (
        "blocklist_entries",
        "INSERT INTO blocklist_entries (kind, value, score, first_seen, last_seen) VALUES ('ip', repeat('x', 513), 5, now(), now())",
    ),
    (
        "blocklist_overrides",
        "INSERT INTO blocklist_overrides (kind, value, action, created_by) VALUES ('ip', 'v', 'maybe', 'a')",
    ),
    (
        "blocklist_overrides",
        "INSERT INTO blocklist_overrides (kind, value, action, note, created_by) VALUES ('ip', 'v', 'allow', repeat('x', 257), 'a')",
    ),
    (
        "feed_tokens",
        "INSERT INTO feed_tokens (name, token_hash, token_hint, created_by) VALUES ('n', decode('abcd', 'hex'), 'abc', 'a')",
    ),
    (
        "feed_tokens",
        "INSERT INTO feed_tokens (name, token_hash, token_hint, min_score, created_by) VALUES ('n', decode(repeat('ab', 32), 'hex'), 'abc', 101, 'a')",
    ),
    (
        "feed_tokens",
        "INSERT INTO feed_tokens (name, token_hash, token_hint, kinds, created_by) VALUES ('n', decode(repeat('ab', 32), 'hex'), 'abc', '{foo}', 'a')",
    ),
    (
        "inventory_services",
        "INSERT INTO inventory_services (name, service, created_by) VALUES ('n', 'ftp', 'a')",
    ),
    (
        "inventory_services",
        "INSERT INTO inventory_services (name, service, exposure, created_by) VALUES ('n', 'ssh', 'moon', 'a')",
    ),
    (
        "inventory_services",
        "INSERT INTO inventory_services (name, service, notes, created_by) VALUES ('n', 'ssh', repeat('x', 513), 'a')",
    ),
    (
        "scripts",
        "INSERT INTO scripts (fingerprint, normalized_text, sample_text, first_seen, last_seen) VALUES (decode('ab', 'hex'), 'n', 's', now(), now())",
    ),
    (
        "scripts",
        "INSERT INTO scripts (fingerprint, normalized_text, sample_text, first_seen, last_seen) VALUES (decode(repeat('ab', 32), 'hex'), repeat('x', 8193), 's', now(), now())",
    ),
    (
        "script_explanations",
        "INSERT INTO script_explanations (script_id, source, lines, summary) VALUES (:script, 'bogus', '[]', 's')",
    ),
    (
        "script_explanations",
        "INSERT INTO script_explanations (script_id, source, lines, summary) VALUES (:script, 'llm', '[]', repeat('x', 601))",
    ),
    (
        "script_explanations",
        "INSERT INTO script_explanations (script_id, source, lines, summary) VALUES (:script, 'llm', to_jsonb(repeat('x', 70000)), 's')",
    ),
    (
        "llm_requests",
        "INSERT INTO llm_requests (script_id, requested_by, state) VALUES (:script, 'a', 'bogus')",
    ),
    (
        "llm_requests",
        "INSERT INTO llm_requests (script_id, requested_by, detail) VALUES (:script, 'a', repeat('x', 129))",
    ),
    (
        "alert_channels",
        "INSERT INTO alert_channels (kind, name, target_ciphertext, created_by) VALUES ('sms', 'n', decode(repeat('ab', 40), 'hex'), 'a')",
    ),
    (
        "alert_channels",
        "INSERT INTO alert_channels (kind, name, target_ciphertext, created_by) VALUES ('discord', 'n', decode('abcd', 'hex'), 'a')",
    ),
    (
        "alert_channels",
        "INSERT INTO alert_channels (kind, name, target_ciphertext, target_hint, created_by) VALUES ('discord', 'n', decode(repeat('ab', 40), 'hex'), repeat('x', 33), 'a')",
    ),
    ("alert_rules", "INSERT INTO alert_rules (kind) VALUES ('bogus')"),
    ("alert_rules", "UPDATE alert_rules SET min_severity = 'bogus' WHERE kind = 'new_campaign'"),
    (
        "alert_rules",
        "UPDATE alert_rules SET settings = to_jsonb(repeat('x', 2100)) WHERE kind = 'new_campaign'",
    ),
    ("watched_cves", "INSERT INTO watched_cves (cve_id, added_by) VALUES ('CVE-1', 'a')"),
    (
        "alert_outbox",
        "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, state) VALUES ('new_campaign', 'k', :channel, '{}', 'bogus')",
    ),
    (
        "alert_outbox",
        "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload) VALUES ('bogus', 'k', :channel, '{}')",
    ),
    (
        "alert_outbox",
        "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload) VALUES ('new_campaign', 'k', :channel, to_jsonb(repeat('x', 17000)))",
    ),
    (
        "alert_outbox",
        "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, error_code) VALUES ('new_campaign', 'k', :channel, '{}', repeat('x', 65))",
    ),
    ("alert_cursors", "INSERT INTO alert_cursors (rule_kind) VALUES ('bogus')"),
    (
        "weekly_reports",
        "INSERT INTO weekly_reports (week_start, html, summary) VALUES (current_date, repeat('x', 524289), '{}')",
    ),
    (
        "weekly_reports",
        "INSERT INTO weekly_reports (week_start, html, summary) VALUES (current_date, 'x', to_jsonb(repeat('x', 17000)))",
    ),
    (
        "alert_test_requests",
        "INSERT INTO alert_test_requests (channel_id, requested_by, state) VALUES (:channel, 'a', 'bogus')",
    ),
    (
        "provider_secrets",
        "INSERT INTO provider_secrets (provider, ciphertext, nonce, last4, updated_by) VALUES ('bogus', 'x', decode(repeat('ab', 12), 'hex'), 'abcd', 'a')",
    ),
    (
        "provider_test_requests",
        "INSERT INTO provider_test_requests (provider, requested_by) VALUES ('bogus', 'a')",
    ),
]


@pytest.mark.parametrize(
    ("table", "sql"), BAD_ROWS, ids=[f"{t}-{i}" for i, (t, _) in enumerate(BAD_ROWS)]
)
async def test_check_constraints_refuse(conn: AsyncConnection, table: str, sql: str) -> None:
    ids = await parents(conn)
    params = {k: v for k, v in ids.items() if f":{k}" in sql}
    assert await rejected(conn, sql, **params), f"{table} accepted: {sql}"


async def test_valid_rows_are_accepted(conn: AsyncConnection) -> None:
    ids = await parents(conn)
    await exec_(
        conn,
        "INSERT INTO attack_techniques VALUES ('T1059', 'Command', 'execution', 'execution', 'u')",
    )
    await exec_(
        conn,
        "INSERT INTO attack_techniques VALUES ('T1059.004', 'Unix Shell', 'execution', 'execution', 'u')",
    )
    await exec_(
        conn,
        "INSERT INTO technique_daily (day, technique, sensor) VALUES (current_date, 'T1059', 'ssh')",
    )
    await exec_(
        conn,
        "INSERT INTO blocklist_entries (kind, value, score, first_seen, last_seen) VALUES ('ip', '203.0.113.9', 80, now(), now())",
    )
    await exec_(
        conn,
        "INSERT INTO feed_tokens (name, token_hash, token_hint, created_by) VALUES ('fw', decode(repeat('ab', 32), 'hex'), 'abcdef', 'a')",
    )
    await exec_(
        conn,
        "INSERT INTO inventory_services (name, service, created_by) VALUES ('web', 'web', 'a')",
    )
    await exec_(conn, "INSERT INTO watched_cves (cve_id, added_by) VALUES ('CVE-2026-109618', 'a')")
    await exec_(
        conn,
        "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload) "
        "VALUES ('new_campaign', 'k', :c, '{}')",
        c=ids["channel"],
    )
    # One alert per rule, key and channel: a second insert is a duplicate.
    assert await rejected(
        conn,
        "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload) "
        "VALUES ('new_campaign', 'k', :c, '{}')",
        c=ids["channel"],
    )
    for provider in ("anthropic", "smtp"):
        await exec_(
            conn,
            "INSERT INTO provider_secrets (provider, ciphertext, nonce, last4, updated_by) "
            "VALUES (:p, 'x', decode(repeat('ab', 12), 'hex'), 'abcd', 'a')",
            p=provider,
        )
        await exec_(
            conn,
            "INSERT INTO provider_test_requests (provider, requested_by) VALUES (:p, 'a')",
            p=provider,
        )


async def test_alert_rules_are_seeded_and_off(conn: AsyncConnection) -> None:
    rows = (await exec_(conn, "SELECT kind, enabled FROM alert_rules ORDER BY kind")).all()
    assert [r[0] for r in rows] == [
        "malware_drop",
        "new_campaign",
        "new_download_host",
        "watched_cve_seen",
        "weekly_report",
    ]
    assert not any(r[1] for r in rows)


async def test_campaign_deletion_cascades_and_unlinks(conn: AsyncConnection) -> None:
    ids = await parents(conn)
    cid = ids["campaign"]
    await exec_(
        conn,
        "INSERT INTO campaign_keys (kind, value, campaign_id, first_seen, last_seen) "
        "VALUES ('hash', 'h', :c, now(), now())",
        c=cid,
    )
    await exec_(
        conn,
        "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, "
        "last_event_at, campaign_id) VALUES ('s-m15', 'ssh', '198.51.100.7', 4000, 22, now(), "
        "now(), :c)",
        c=cid,
    )
    await exec_(conn, "DELETE FROM campaigns WHERE id = :c", c=cid)
    assert (
        await exec_(conn, "SELECT count(*) FROM campaign_keys WHERE campaign_id = :c", c=cid)
    ).scalar_one() == 0
    row = (
        await exec_(
            conn,
            "SELECT campaign_id, benign, techniques, clustered_at FROM sessions WHERE session_id = 's-m15'",
        )
    ).one()
    assert row[0] is None and row[1] is False and row[2] == [] and row[3] is None
    assert await rejected(
        conn,
        "UPDATE sessions SET scanner_name = repeat('x', 65) WHERE session_id = 's-m15'",
    )


async def test_prune_jobs_are_registered(conn: AsyncConnection) -> None:
    procs = {r[0] for r in await exec_(conn, "SELECT proc_name FROM timescaledb_information.jobs")}
    assert {
        "suckerpot_campaign_prune",
        "suckerpot_script_prune",
        "suckerpot_alert_prune",
    } <= procs


async def test_campaign_prune(conn: AsyncConnection) -> None:
    await exec_(conn, "DELETE FROM campaigns")
    for i in range(5):
        await exec_(
            conn,
            "INSERT INTO campaigns (name, status, sessions, sources, first_seen, last_seen) "
            "VALUES (:n, :s, :x, :y, now(), now() - make_interval(days => :i))",
            n=f"c{i}",
            s="quiet" if i % 2 else "active",
            x=i,
            y=1 if i % 2 else 3,
            i=i,
        )
    cid = (await exec_(conn, "SELECT id FROM campaigns ORDER BY id LIMIT 1")).scalar_one()
    await exec_(
        conn,
        "INSERT INTO campaign_sessions VALUES (:c, 'old', '198.51.100.7', 'ssh', now() - INTERVAL '100 days')",
        c=cid,
    )
    await exec_(
        conn,
        "INSERT INTO campaign_sessions VALUES (:c, 'new', '198.51.100.7', 'ssh', now())",
        c=cid,
    )
    await exec_(
        conn,
        'CALL suckerpot_campaign_prune(0, CAST(\'{"retention_days": 90, "max_rows": 3}\' AS jsonb))',
    )
    left = {r[0] for r in await exec_(conn, "SELECT name FROM campaigns")}
    assert len(left) == 3
    assert not {"c1", "c3"} & left  # quiet single-source campaigns go first
    links = {r[0] for r in await exec_(conn, "SELECT session_id FROM campaign_sessions")}
    assert "old" not in links


async def test_script_and_alert_prune(conn: AsyncConnection) -> None:
    ids = await parents(conn)
    await exec_(
        conn,
        "INSERT INTO script_sessions VALUES (:s, 'old', '198.51.100.7', 'ssh', now() - INTERVAL '100 days')",
        s=ids["script"],
    )
    await exec_(
        conn,
        "INSERT INTO script_sessions VALUES (:s, 'new', '198.51.100.7', 'ssh', now())",
        s=ids["script"],
    )
    await exec_(conn, "CALL suckerpot_script_prune(0, CAST('{\"retention_days\": 90}' AS jsonb))")
    links = {r[0] for r in await exec_(conn, "SELECT session_id FROM script_sessions")}
    assert links == {"new"}

    await exec_(
        conn,
        "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, created_at) "
        "VALUES ('new_campaign', 'old', :c, '{}', now() - INTERVAL '40 days'), "
        "('new_campaign', 'new', :c, '{}', now())",
        c=ids["channel"],
    )
    await exec_(
        conn,
        "INSERT INTO weekly_reports (week_start, html, summary) "
        "VALUES (current_date - 800, 'x', '{}'), (current_date - 7, 'x', '{}')",
    )
    await exec_(conn, "CALL suckerpot_alert_prune(0, CAST('{}' AS jsonb))")
    keys = {r[0] for r in await exec_(conn, "SELECT dedupe_key FROM alert_outbox")}
    assert keys == {"new"}
    assert (await exec_(conn, "SELECT count(*) FROM weekly_reports")).scalar_one() == 1


async def test_ingest_cannot_update_events_only_call_retract_benign(engine: AsyncEngine) -> None:
    ingest, api = ROLE_ENV["POSTGRES_INGEST_USER"], ROLE_ENV["POSTGRES_API_USER"]
    assert not await has_priv(engine, ingest, "events", "UPDATE")
    assert not await has_priv(engine, api, "events", "UPDATE")
    async with engine.connect() as conn:

        async def can_run(role: str) -> bool:
            return bool(
                await conn.scalar(
                    text("SELECT has_function_privilege(:r, 'retract_benign(text[])', 'EXECUTE')"),
                    {"r": role},
                )
            )

        assert await can_run(ingest)
        assert not await can_run(api)
        definer, path = (
            await conn.execute(
                text(
                    "SELECT prosecdef, proconfig::text FROM pg_proc "
                    "WHERE proname = 'retract_benign'"
                )
            )
        ).one()
        assert definer is True and "search_path=pg_catalog, public" in path
