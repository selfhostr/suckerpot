"""M38 P1 migration: a database before P1 (0039) goes to 0040 and back (throwaway database only).

Open drafts and their send requests are what the upgrade must handle with care: subject kinds
are backfilled, the subjects of open reports get an XARF id, pending automatic sends of drafts
are cancelled (``digest_migration``) while manual ones and those of reviewed reports stay, and the
new indexes allow one digest draft plus one reviewed digest per recipient.
"""

import os
import subprocess
import sys
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.retention import apply_retention
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration

DB_DIR = os.environ.get("DB_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": "collector-test-password",
    "POSTGRES_ANALYZER_PASSWORD": "analyzer-test-password",
}
PRODUCTION = "0039"
HEAD = "0040"
EVIDENCE = '{"subjects": []}'


def _alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


async def _roles_and_jobs() -> None:
    engine = create_async_engine(database_url_from_env(ENV))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: apply_roles(c, ENV))
    finally:
        await engine.dispose()
    engine = create_async_engine(database_url_from_env(ENV), isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as conn:
            await conn.run_sync(lambda c: apply_retention(c, ENV))
    finally:
        await engine.dispose()


def _role_engine(user_key: str, password_key: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env(
            {**ENV, "POSTGRES_USER": ENV[user_key], "POSTGRES_PASSWORD": ENV[password_key]}
        )
    )


async def _refused(engine: AsyncEngine, sql: str) -> bool:
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql))
    except DBAPIError as exc:
        return "permission denied" in str(exc.orig).lower()
    return False


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    # Destructive: it downgrades the database it is pointed at. Only a throwaway project.
    if "-it-" not in os.environ.get("COMPOSE_PROJECT_NAME", ""):
        pytest.skip("destructive test: needs a throwaway COMPOSE_PROJECT_NAME containing '-it-'")
    _alembic("upgrade", "head")
    engine = create_async_engine(database_url_from_env(ENV))
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_send_requests"))
        await conn.execute(text("DELETE FROM abuse_reports"))
        await conn.execute(text("DELETE FROM abuse_recipients"))
        await conn.execute(text("DELETE FROM report_smtp"))
    yield engine
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_send_requests"))
        await conn.execute(text("DELETE FROM abuse_reports"))
        await conn.execute(text("DELETE FROM abuse_recipients"))
        await conn.execute(text("DELETE FROM report_smtp"))
    await engine.dispose()
    _alembic("upgrade", "head")
    await _roles_and_jobs()


async def _report(
    conn: object, rid: int, kind: str, status: str, n: int, *, upgraded: bool = False
) -> int:
    row = await conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, "
            "window_start, window_end, evidence, content_sha256, guard_ok) "
            "VALUES (gen_random_uuid(), gen_random_uuid(), :r, :k, :s, now() - interval '1 hour', "
            "now(), CAST(:e AS jsonb), 'x', true) RETURNING id"
        ),
        {"r": rid, "k": kind, "s": status, "e": EVIDENCE},
    )
    report_id = int(row.scalar_one())
    if upgraded:
        sql = (
            "INSERT INTO abuse_report_subjects (report_id, kind, subject_type, value, first_ts, "
            "last_ts, sessions, events) VALUES (:i, 'attack_source', 'ip', :v, now(), now(), 1, 1)"
        )
    else:
        sql = (
            "INSERT INTO abuse_report_subjects (report_id, subject_type, value, first_ts, "
            "last_ts, sessions, events) VALUES (:i, 'ip', :v, now(), now(), 1, 1)"
        )
    await conn.execute(text(sql), {"i": report_id, "v": f"198.51.100.{n}"})  # type: ignore[attr-defined]
    return report_id


async def test_v013_upgrades_to_head_and_rolls_back(owner: AsyncEngine) -> None:
    _alembic("downgrade", PRODUCTION)
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_smtp (id, host, port, security, from_address) "
                "VALUES (1, 'smtp.example.net', 587, 'starttls', 'reports@example.org')"
            )
        )
        rid = int(
            (
                await conn.execute(
                    text(
                        "INSERT INTO abuse_recipients (mailbox, source) "
                        "VALUES ('abuse@example.net', 'rdap') RETURNING id"
                    )
                )
            ).scalar_one()
        )
        attack = await _report(conn, rid, "attack_source", "draft", 1)
        payload = await _report(conn, rid, "payload_host", "draft", 2)
        reviewed = await _report(conn, rid, "c2", "reviewed", 3)
        sent = await _report(conn, rid, "attack_source", "sent", 4)
        for report_id in (attack, reviewed):  # the owner role counts as ingest here
            await conn.execute(
                text(
                    "INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by, "
                    "scheduled_at) VALUES (:i, 'send', true, 'auto', now())"
                ),
                {"i": report_id},
            )
    await _roles_and_jobs()
    api0 = _role_engine("POSTGRES_API_USER", "POSTGRES_API_PASSWORD")
    try:
        async with api0.begin() as conn:  # a manual request, as the API writes it
            await conn.execute(
                text(
                    "INSERT INTO abuse_send_requests (report_id, kind, requested_by) "
                    "VALUES (:i, 'send', 'owner')"
                ),
                {"i": payload},
            )
    finally:
        await api0.dispose()

    _alembic("upgrade", "head")
    await _roles_and_jobs()
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == HEAD
        kinds = dict(
            (r[0], r[1])
            for r in await conn.execute(text("SELECT report_id, kind FROM abuse_report_subjects"))
        )
        assert kinds == {
            attack: "attack_source",
            payload: "payload_host",
            reviewed: "c2",
            sent: "attack_source",
        }
        with_id = {
            r[0]
            for r in await conn.execute(
                text("SELECT report_id FROM abuse_report_subjects WHERE xarf_id IS NOT NULL")
            )
        }
        assert with_id == {attack, payload, reviewed}  # open reports only
        requests = {
            r[0]: (r[1], r[2])
            for r in await conn.execute(
                text("SELECT report_id, status, error_code FROM abuse_send_requests")
            )
        }
        assert requests[attack] == ("cancelled", "digest_migration")
        assert requests[payload] == ("pending", None)  # a manual request is kept
        assert requests[reviewed] == ("pending", None)  # reviewed reports go as they are
        minute = await conn.scalar(text("SELECT digest_minute FROM report_smtp"))
        assert 360 <= int(minute) < 540
        assert await conn.scalar(text("SELECT digest_enabled FROM report_settings")) is True
        assert await conn.scalar(text("SELECT xarf_strict FROM abuse_recipients")) is False

    # One digest draft and one reviewed digest per recipient; a second draft is refused.
    async with owner.begin() as conn:
        digest = await _report(conn, rid, "digest", "draft", 5, upgraded=True)
        await _report(conn, rid, "digest", "reviewed", 6, upgraded=True)
    with pytest.raises(IntegrityError):
        async with owner.begin() as conn:
            await _report(conn, rid, "digest", "draft", 7, upgraded=True)
    # The same address may be both an attacker and a payload host in one digest.
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_report_subjects (report_id, kind, subject_type, value, "
                "first_ts, last_ts, sessions, events, xarf_id) VALUES "
                "(:i, 'payload_host', 'ip', '198.51.100.5', now(), now(), 1, 1, "
                "gen_random_uuid())"
            ),
            {"i": digest},
        )
    with pytest.raises(DBAPIError):
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO abuse_replies (source, received_at, match_method, "
                    "classification, size_bytes) VALUES ('paste', now(), 'made_up', "
                    "'unknown', 1)"
                )
            )
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_replies (source, received_at, match_method, classification, "
                "size_bytes) VALUES ('paste', now(), 'xarf_id', 'unknown', 1)"
            )
        )

    # Grants: ingest may move a draft's due time and link replies to sources; the API reads.
    api = _role_engine("POSTGRES_API_USER", "POSTGRES_API_PASSWORD")
    ingest = _role_engine("POSTGRES_INGEST_USER", "POSTGRES_INGEST_PASSWORD")
    try:
        due = f"UPDATE abuse_reports SET due_at = now() WHERE id = {int(digest)}"  # noqa: S608
        assert not await _refused(ingest, due)
        assert await _refused(api, due)
        assert await _refused(api, "INSERT INTO abuse_subject_outcomes (report_id) VALUES (1)")
        assert await _refused(api, "DELETE FROM abuse_subject_outcomes")
        assert not await _refused(api, "SELECT count(*) FROM abuse_subject_outcomes")
        assert not await _refused(api, "UPDATE abuse_recipients SET xarf_strict = false")
        assert await _refused(ingest, "UPDATE abuse_recipients SET xarf_strict = true")
        assert not await _refused(api, "SELECT digest_minute FROM report_smtp")
        assert await _refused(ingest, "UPDATE report_smtp SET digest_minute = 1")
    finally:
        await api.dispose()
        await ingest.dispose()

    # A sent digest refuses the downgrade (just rollback restores the dump instead).
    async with owner.begin() as conn:
        sent_digest = await _report(conn, rid, "digest", "sent", 8, upgraded=True)
    refused = subprocess.run(  # noqa: S603, ASYNC221 - a one-off CLI run in a test
        [sys.executable, "-m", "alembic", "downgrade", PRODUCTION],
        cwd=DB_DIR, env=ENV, capture_output=True, text=True, timeout=180,
    )  # fmt: skip
    assert refused.returncode != 0 and "downgrade refused" in refused.stderr
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports WHERE id = :i"), {"i": sent_digest})
    # Back to 0039: the unsent digests go, everything else stays.
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_replies WHERE match_method = 'xarf_id'"))
    _alembic("downgrade", PRODUCTION)
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM abuse_reports")) == 4
        assert await conn.scalar(text("SELECT count(*) FROM abuse_report_subjects")) == 4
    _alembic("upgrade", "head")
