"""Least-privilege database roles, applied on every migrate run.

``hub_api`` serves the signed API: it can enrol, authenticate, store observations and read the
published views, nothing else. ``hub_worker`` runs consensus, statistics, retention and reports:
it may change every table but never the schema. Passwords are sent as SCRAM-SHA-256 verifiers so
that server logs cannot contain them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from collections.abc import Mapping

from sqlalchemy import text
from sqlalchemy.engine import Connection

API_ROLE = "hub_api"
WORKER_ROLE = "hub_worker"
SCRAM_ITERATIONS = 4096
MIN_PASSWORD = 24


class RoleError(RuntimeError):
    """Sanitised message, never a password."""


def scram_verifier(password: str, salt: bytes | None = None) -> str:
    if not password.isascii():
        raise RoleError("role passwords must be ASCII")
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


# role -> list of GRANT statements (the role name is filled in with format %I)
API_GRANTS = (
    "SELECT, INSERT, DELETE ON nodes",
    "UPDATE (last_active_day, pseudonym, pseudonym_key, pseudonym_changed_day, country, "
    "show_country) ON nodes",
    "SELECT, INSERT, DELETE ON enrol_challenges",
    "SELECT, INSERT ON nonces",
    "SELECT, INSERT ON batches",
    "SELECT, INSERT ON observations",
    "USAGE ON SEQUENCE observations_id_seq, targets_seq",
    "SELECT ON targets",
    "UPDATE (value, updated_at) ON targets",
    "SELECT, INSERT, UPDATE ON takedown_votes",
    "SELECT ON network_summary, network_daily, node_stats_weekly, never_list",
    # Feeds: the API records which URLs a payload host served and answers lookups and delisting
    # requests; it never writes feed entries and cannot read the allow-list.
    "SELECT, INSERT ON payload_links",
    "UPDATE (nodes) ON payload_links",
    "SELECT ON feed_entries",
    "SELECT, INSERT, DELETE ON delist_challenges",
    "SELECT, INSERT ON delist_requests",
    # Link verification (M32): the API checks roles, reveals a link into a task, leases tasks and
    # stores attestations. Creation, counters and expiry belong to the worker.
    "SELECT ON node_roles",
    "SELECT ON verify_tasks",
    "UPDATE (url, site, state, refusal, revealed_day, release_at, lease_node, lease_until, "
    "attempts, ended_day) ON verify_tasks",
    "SELECT, INSERT ON verify_attestations",
)
WORKER_TABLES = (
    "nodes, enrol_challenges, nonces, batches, observations, targets, target_contributors, "
    "takedown_votes, reports, recipient_log, node_stats_weekly, network_daily, network_summary, "
    "never_list, hub_audit, worker_state, payload_links, target_hosts, feed_entries, feed_runs, "
    "feed_daily, feed_allow, feed_auto_ranges, delist_challenges, delist_requests, "
    "abusech_submissions, node_roles, verify_tasks, verify_attestations, verify_daily"
)
# Tables the worker may not change once written. observatory_daily: a frozen day is never updated
# (design M34), only inserted and, by retention, deleted.
WORKER_GRANTS = ("SELECT, INSERT, DELETE ON observatory_daily",)


def check_passwords(env: Mapping[str, str]) -> list[str]:
    problems: list[str] = []
    names = ("HUB_DB_PASSWORD", "HUB_API_DB_PASSWORD", "HUB_WORKER_DB_PASSWORD")
    for name in names:
        value = env.get(name, "")
        if not value:
            problems.append(f"{name} is not set")
        elif not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            problems.append(f"{name} may only hold letters, digits, - and _ (it goes into a URL)")
        elif len(value) < MIN_PASSWORD and env.get("HUB_ALLOW_DEFAULT_SECRETS") != "1":
            problems.append(f"{name} must be at least {MIN_PASSWORD} characters")
    values = [env.get(n, "") for n in names if env.get(n)]
    if len(set(values)) != len(values):
        problems.append("the three database passwords must be different")
    return problems


def apply_roles(conn: Connection, env: Mapping[str, str] | None = None) -> None:
    """Create or update both roles and their grants. Idempotent."""
    env = os.environ if env is None else env
    passwords = {
        API_ROLE: env.get("HUB_API_DB_PASSWORD", ""),
        WORKER_ROLE: env.get("HUB_WORKER_DB_PASSWORD", ""),
    }
    for role, password in passwords.items():
        if not password:
            raise RoleError(f"password for {role} is not set")
        verifier = scram_verifier(password)  # base64 and punctuation only: safe as a literal
        exists = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}
        ).scalar()
        if not exists:
            conn.execute(text(f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE'))
        # exec_driver_sql: the verifier holds colons that text() would read as bind parameters.
        conn.exec_driver_sql(f"ALTER ROLE \"{role}\" WITH LOGIN PASSWORD '{verifier}'")
        conn.exec_driver_sql(f"ALTER ROLE \"{role}\" SET statement_timeout = '30s'")
    for role in (API_ROLE, WORKER_ROLE):
        conn.execute(text(f'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "{role}"'))
        conn.execute(text(f'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "{role}"'))
        conn.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
    for grant in API_GRANTS:
        conn.execute(text(f'GRANT {grant} TO "{API_ROLE}"'))
    conn.execute(
        text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {WORKER_TABLES} TO "{WORKER_ROLE}"')
    )
    for grant in WORKER_GRANTS:
        conn.execute(text(f'GRANT {grant} TO "{WORKER_ROLE}"'))
    conn.execute(text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{WORKER_ROLE}"'))
