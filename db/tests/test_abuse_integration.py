"""M22 schema: the chain goes down and up, the workflow triggers hold and the roles are confined."""

import os
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from datetime import date
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration
# ruff: noqa: S608  (test SQL is built from constants)

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
TABLES = ("report_smtp", "abuse_send_requests", "rdap_bootstrap", "abuse_networks",
          "abuse_lookups", "abuse_recipients",
          "abuse_reports", "abuse_report_subjects", "abuse_report_requests", "report_settings",
          "report_self_terms")  # fmt: skip
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
}
NEW_REPORT = (
    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo, window_start, "
    "window_end, evidence, content_sha256, guard_ok, status) VALUES (gen_random_uuid(), "
    "gen_random_uuid(), (SELECT min(id) FROM abuse_recipients), :kind, :demo, now(), now(), "
    "'{}', 'x', true, :status)"
)


def _alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


def _as(user: str, password: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env({**ENV, "POSTGRES_USER": user, "POSTGRES_PASSWORD": password})
    )


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    engine = create_async_engine(database_url_from_env(ENV))
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: apply_roles(c, ENV))
        await conn.execute(text("TRUNCATE abuse_recipients, report_self_terms CASCADE"))
        await conn.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, source) "
                "VALUES ('abuse@example.net', 'rdap')"
            )
        )
    yield engine
    await engine.dispose()


async def _run(
    engine: AsyncEngine, sql: str, params: Mapping[str, object] | None = None
) -> int | None:
    """Row count of the statement, or None when it was refused (privilege, RLS or trigger)."""
    try:
        async with engine.begin() as conn:
            return (await conn.execute(text(sql), params or {})).rowcount
    except DBAPIError:
        return None


async def _report(owner: AsyncEngine, status: str = "draft", demo: bool = False) -> int:
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports"))
        await conn.execute(text(NEW_REPORT), {"kind": "c2", "demo": demo, "status": status})
        return int(await conn.scalar(text("SELECT id FROM abuse_reports")) or 0)


@pytest.fixture
async def roles() -> AsyncIterator[tuple[AsyncEngine, AsyncEngine]]:
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    ingest = _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"])
    yield api, ingest
    await api.dispose()
    await ingest.dispose()


async def test_down_and_up_again(owner: AsyncEngine) -> None:
    async def exists(table: str) -> bool:
        async with owner.connect() as conn:
            return bool(await conn.scalar(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table}))

    assert all([await exists(t) for t in TABLES])
    _alembic("downgrade", "0018")
    assert not any([await exists(t) for t in TABLES])
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "0018"
        assert await conn.scalar(text("SELECT to_regproc('abuse_reports_transition') IS NULL"))
    _alembic("upgrade", "head")
    assert all([await exists(t) for t in TABLES])
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM report_settings")) == 1


async def test_one_open_report_per_recipient_and_kind(owner: AsyncEngine) -> None:
    await _report(owner)
    assert await _run(owner, NEW_REPORT, {"kind": "c2", "demo": False, "status": "draft"}) is None
    assert await _run(owner, NEW_REPORT, {"kind": "payload_host", "demo": False, "status": "draft"})
    assert await _run(owner, "UPDATE abuse_reports SET status = 'discarded' WHERE kind = 'c2'")
    assert await _run(owner, NEW_REPORT, {"kind": "c2", "demo": False, "status": "draft"})


async def test_transitions_and_demo(owner: AsyncEngine) -> None:
    rid = await _report(owner)
    set_status = "UPDATE abuse_reports SET status = :s WHERE id = :i"
    assert await _run(owner, set_status, {"s": "sent", "i": rid}) is None  # draft -> sent
    assert await _run(owner, set_status, {"s": "closed", "i": rid}) is None
    assert await _run(owner, set_status, {"s": "reviewed", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "sent", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "reviewed", "i": rid}) is None  # sent is final
    assert await _run(owner, set_status, {"s": "closed", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "draft", "i": rid}) is None
    # A demo report can never be sent, neither by insert nor by update.
    assert await _run(owner, NEW_REPORT, {"kind": "c2", "demo": True, "status": "sent"}) is None
    rid = await _report(owner, demo=True)
    assert await _run(owner, set_status, {"s": "reviewed", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "sent", "i": rid}) is None
    # Identity columns and, after the draft state, the content are frozen.
    assert (
        await _run(owner, "UPDATE abuse_reports SET demo = false WHERE id = :i", {"i": rid}) is None
    )
    assert (
        await _run(owner, "UPDATE abuse_reports SET evidence = jsonb_build_object('a', 1)") is None
    )


async def test_touch_bumps_the_revision_with_the_evidence(owner: AsyncEngine) -> None:
    await _report(owner)
    async with owner.begin() as conn:
        await conn.execute(text("UPDATE abuse_reports SET notes = 'n'"))
        rev = await conn.scalar(text("SELECT revision FROM abuse_reports"))
        assert rev == 1
        await conn.execute(text("UPDATE abuse_reports SET evidence = jsonb_build_object('a', 1)"))
        assert await conn.scalar(text("SELECT revision FROM abuse_reports")) == 2
        assert await conn.scalar(text("SELECT updated_at >= created_at FROM abuse_reports"))


async def test_api_and_ingest_are_confined_on_reports(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    await _report(owner)
    # Ingest rebuilds drafts, but cannot review, send, close or touch the notes.
    assert await _run(
        ingest, "UPDATE abuse_reports SET evidence = jsonb_build_object('a', 2), guard_ok = false"
    )
    assert await _run(ingest, "UPDATE abuse_reports SET status = 'reviewed'") is None
    assert await _run(ingest, "UPDATE abuse_reports SET reviewed_by = 'x'") is None
    assert await _run(ingest, "UPDATE abuse_reports SET notes = 'x'") is None
    assert await _run(ingest, "UPDATE abuse_reports SET sent_at = now()") is None
    assert await _run(ingest, "DELETE FROM abuse_reports") is None
    assert await _run(ingest, "UPDATE abuse_reports SET status = 'superseded'") == 1
    rid = await _report(owner)
    # The API reviews and sends but cannot rewrite evidence or insert reports.
    assert await _run(api, "UPDATE abuse_reports SET evidence = '{}'") is None
    assert await _run(api, "UPDATE abuse_reports SET content_sha256 = 'y'") is None
    assert await _run(api, NEW_REPORT, {"kind": "c2", "demo": False, "status": "draft"}) is None
    assert await _run(
        api, "UPDATE abuse_reports SET status = 'reviewed', reviewed_by = 'a', notes = 'k'"
    )
    # Once reviewed, ingest may not touch the report at all.
    assert await _run(ingest, "UPDATE abuse_reports SET guard_ok = false") is None
    assert await _run(ingest, "UPDATE abuse_reports SET status = 'draft'") is None
    assert await _run(api, "UPDATE abuse_reports SET status = 'sent', sent_by = 'a'") == 1
    assert await _run(api, "UPDATE abuse_reports SET status = 'draft'") is None
    assert rid


async def test_other_tables(owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]) -> None:
    api, ingest = roles
    for table in TABLES:
        assert await _run(api, f"SELECT count(*) FROM {table}") is not None
        assert await _run(ingest, f"SELECT count(*) FROM {table}") is not None
    net = (
        "INSERT INTO abuse_networks (kind, cidr, source, fetched_at, expires_at) "
        "VALUES ('ip', '198.51.100.0/24', 'rdap', now(), now())"
    )
    assert await _run(api, net) is None
    assert await _run(ingest, net)
    assert await _run(ingest, "DELETE FROM abuse_networks")
    assert await _run(ingest, "UPDATE abuse_recipients SET name = 'N'")
    assert await _run(ingest, "UPDATE abuse_recipients SET muted = true") is None
    assert await _run(api, "UPDATE abuse_recipients SET muted = true, override_mailbox = 'a@b.cc'")
    assert await _run(api, "UPDATE abuse_recipients SET mailbox = 'x@y.zz'") is None
    assert await _run(
        api, "INSERT INTO abuse_recipients (mailbox, source) VALUES ('m@example.org', 'manual')"
    )
    req = "INSERT INTO abuse_report_requests (action, requested_by) VALUES ('lookup_again', 'a')"
    assert await _run(api, req)
    assert await _run(ingest, req) is None
    assert await _run(ingest, "UPDATE abuse_report_requests SET done_at = now(), outcome = 'ok'")
    assert await _run(api, "UPDATE abuse_report_requests SET outcome = 'x'") is None
    assert await _run(api, "UPDATE report_settings SET intro = 'hello', revision = revision + 1")
    assert await _run(ingest, "UPDATE report_settings SET intro = 'x'") is None


async def test_self_terms_row_level_security(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    ins = "INSERT INTO report_self_terms (kind, value, source) VALUES ('name', :v, :s)"
    sensor = (
        "INSERT INTO report_self_terms (kind, value, source, confirmed) "
        "VALUES ('name', :v, 'sensor', :c)"
    )
    assert await _run(ingest, ins, {"v": "learned-a", "s": "learned"})
    assert await _run(ingest, ins, {"v": "manual-b", "s": "manual"}) is None
    # Ingest never confirms a learned row; a sensor row is trusted and always confirmed.
    assert (
        await _run(
            ingest,
            "INSERT INTO report_self_terms (kind, value, source, confirmed) "
            "VALUES ('name', 'learned-ok', 'learned', true)",
        )
        is None
    )
    assert await _run(ingest, sensor, {"v": "srv-sensor", "c": False}) is None
    assert await _run(ingest, sensor, {"v": "srv-sensor", "c": True})
    assert await _run(api, ins, {"v": "manual-c", "s": "manual"})
    assert await _run(api, ins, {"v": "learned-d", "s": "learned"}) is None
    assert await _run(api, ins, {"v": "sensor-e", "s": "sensor"}) is None
    for eng in (api, ingest):
        async with eng.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM report_self_terms")) == 3
    # Ingest updates only the counters of learned and sensor terms.
    assert await _run(ingest, "UPDATE report_self_terms SET distinct_sources = 3") == 2
    assert await _run(ingest, "UPDATE report_self_terms SET last_seen = now()") == 2
    assert await _run(ingest, "UPDATE report_self_terms SET confirmed = true") is None
    assert await _run(ingest, "UPDATE report_self_terms SET source = 'manual'") is None
    assert await _run(ingest, "DELETE FROM report_self_terms") is None
    assert await _run(api, "UPDATE report_self_terms SET confirmed = true") == 3
    assert await _run(api, "UPDATE report_self_terms SET value = 'zz'") is None
    # The owner deletes manual and learned terms; a sensor's own name stays.
    assert await _run(api, "DELETE FROM report_self_terms") == 2
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT source FROM report_self_terms")) == "sensor"


async def test_ingest_reads_payload_tables_but_cannot_write_them(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    _, ingest = roles
    for table in ("fetch_targets", "samples", "sample_links", "sample_sources"):
        assert await _run(ingest, f"SELECT count(*) FROM {table}") is not None
        assert await _run(ingest, f"DELETE FROM {table}") is None
    assert await _run(ingest, "SELECT count(*) FROM fetch_attempts") is None


async def test_a_waiting_recipient_has_no_mailbox_until_the_owner_types_one(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    new = "INSERT INTO abuse_recipients (mailbox, name, source) VALUES (NULL, :n, 'rdap')"
    assert await _run(ingest, new, {"n": "net one"})
    assert await _run(ingest, new, {"n": "net two"})  # several waiting rows are allowed
    net = (
        "INSERT INTO abuse_networks (kind, cidr, source, fetched_at, expires_at, recipient_id) "
        "VALUES ('ip', '198.51.100.0/24', 'rdap', now(), now(), "
        "(SELECT min(id) FROM abuse_recipients WHERE mailbox IS NULL))"
    )
    assert await _run(ingest, net)
    assert await _run(
        api,
        "UPDATE abuse_recipients SET override_mailbox = 'abuse@example.org' WHERE mailbox IS NULL",
    )


# ---- M25: sending by SMTP -----------------------------------------------------------------

SEND_REQUEST = (
    "INSERT INTO abuse_send_requests (report_id, kind, requested_by{cols}) "
    "VALUES (:r, 'send', 'admin'{vals})"
)
MARK_SMTP = (
    "UPDATE abuse_reports SET status = 'sent', sent_via = :v, sent_at = now(), sent_by = 'x' "
    "WHERE id = :r"
)


async def _ask(api: AsyncEngine, report_id: int) -> int | None:
    return await _run(api, SEND_REQUEST.format(cols="", vals=""), {"r": report_id})


START = (
    "UPDATE abuse_send_requests SET status = 'sending', started_at = now() "
    "WHERE report_id = :r AND status = 'pending'"
)


async def _start(ingest: AsyncEngine, report_id: int) -> int | None:
    return await _run(ingest, START, {"r": report_id})


async def test_ingest_marks_a_report_sent_only_for_a_request_being_sent(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    rid = await _report(owner)
    assert await _run(ingest, MARK_SMTP, {"v": "smtp", "r": rid}) is None  # no request yet
    assert await _ask(api, rid) == 1
    assert await _run(ingest, MARK_SMTP, {"v": "smtp", "r": rid}) is None  # still only pending
    assert await _start(ingest, rid) == 1
    assert await _run(ingest, MARK_SMTP, {"v": "manual", "r": rid}) is None  # only smtp
    assert (
        await _run(
            ingest, "UPDATE abuse_reports SET status = 'sent', sent_via = 'smtp', notes = 'n'"
        )
        is None
    )  # no notes grant
    assert (
        await _run(
            ingest,
            "UPDATE abuse_reports SET status = 'sent', sent_via = 'smtp', reviewed_by = 'bob'",
        )
        is None
    )  # a review stamp is 'auto' or nothing
    assert await _run(ingest, MARK_SMTP, {"v": "smtp", "r": rid}) == 1  # draft -> sent
    async with owner.connect() as conn:
        row = (await conn.execute(text("SELECT status, sent_via FROM abuse_reports"))).one()
    assert (row.status, row.sent_via) == ("sent", "smtp")
    assert await _run(ingest, "UPDATE abuse_reports SET status = 'draft'") is None


async def test_an_automatic_send_may_stamp_the_review_as_auto(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    rid = await _report(owner)
    assert await _ask(api, rid) == 1
    assert await _start(ingest, rid) == 1
    assert (
        await _run(
            ingest,
            "UPDATE abuse_reports SET status = 'sent', sent_via = 'smtp', sent_at = now(), "
            "sent_by = 'auto', reviewed_by = 'auto', reviewed_at = now(), "
            "reviewed_revision = revision",
        )
        == 1
    )


async def test_demo_and_unguarded_reports_cannot_be_sent_by_ingest(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    rid = await _report(owner, demo=True)
    assert await _ask(api, rid) == 1
    assert await _start(ingest, rid) == 1
    assert await _run(ingest, MARK_SMTP, {"v": "smtp", "r": rid}) is None
    rid = await _report(owner)
    async with owner.begin() as conn:
        await conn.execute(text("UPDATE abuse_reports SET guard_ok = false"))
    assert await _ask(api, rid) == 1
    assert await _start(ingest, rid) == 1
    assert await _run(ingest, MARK_SMTP, {"v": "smtp", "r": rid}) is None


async def test_the_api_can_only_mark_sent_by_hand(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, _ = roles
    rid = await _report(owner, status="reviewed")
    assert await _run(api, MARK_SMTP, {"v": "smtp", "r": rid}) is None  # never smtp
    assert await _run(api, MARK_SMTP, {"v": "manual", "r": rid}) == 1
    assert await _run(api, "UPDATE abuse_reports SET sent_via = 'smtp'") is None
    assert await _run(api, "UPDATE abuse_reports SET sent_via = NULL") is None
    await _report(owner, status="reviewed")
    assert await _run(api, "UPDATE abuse_reports SET sent_via = 'manual'") is None  # not sent


async def test_send_request_rules(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    rid = await _report(owner)
    params = {"r": rid}
    assert await _run(api, SEND_REQUEST.format(cols=", auto", vals=", true"), params) is None
    assert (
        await _run(api, SEND_REQUEST.format(cols=", scheduled_at", vals=", now()"), params) is None
    )
    assert await _run(api, SEND_REQUEST.format(cols=", status", vals=", 'sent'"), params) is None
    assert (
        await _run(api, "INSERT INTO abuse_send_requests (kind, requested_by) VALUES ('send', 'a')")
        is None
    )  # a send needs a report
    assert (
        await _run(
            api,
            "INSERT INTO abuse_send_requests (report_id, kind, requested_by) "
            "VALUES (:r, 'test', 'a')",
            params,
        )
        is None
    )  # a test has none
    assert (
        await _run(api, "INSERT INTO abuse_send_requests (kind, requested_by) VALUES ('test', 'a')")
        == 1
    )
    assert await _ask(api, rid) == 1
    # The API may cancel a pending request and nothing else.
    assert await _run(api, "UPDATE abuse_send_requests SET status = 'sent'") is None
    assert await _run(api, "UPDATE abuse_send_requests SET error_code = 'x'") is None
    assert await _run(api, "UPDATE abuse_send_requests SET requested_by = 'x'") is None
    assert await _run(api, "DELETE FROM abuse_send_requests") is None
    assert await _run(api, "UPDATE abuse_send_requests SET status = 'cancelled'") == 2
    async with owner.connect() as conn:
        done = await conn.scalar(
            text("SELECT count(*) FROM abuse_send_requests WHERE done_at IS NOT NULL")
        )
    assert done == 2  # the trigger stamped it
    assert await _run(api, "UPDATE abuse_send_requests SET status = 'cancelled'") is None
    # Ingest schedules automatic sends only, and finishes a request once.
    assert await _run(ingest, SEND_REQUEST.format(cols="", vals=""), params) is None
    assert await _run(ingest, SEND_REQUEST.format(cols=", auto", vals=", true"), params) == 1
    assert (
        await _run(
            ingest,
            "INSERT INTO abuse_send_requests (kind, auto, requested_by) VALUES ('test', true, 'a')",
        )
        is None
    )
    done_sql = (
        "UPDATE abuse_send_requests SET status = 'failed', error_code = 'refused', "
        "done_at = now() WHERE auto"
    )
    assert await _run(ingest, "UPDATE abuse_send_requests SET requested_by = 'x'") is None
    assert await _run(ingest, "DELETE FROM abuse_send_requests") is None
    assert await _run(ingest, done_sql) == 1
    assert await _run(ingest, done_sql) is None  # finished is final


async def test_a_request_goes_through_sending_and_only_ingest_moves_it(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    rid = await _report(owner)
    assert await _ask(api, rid) == 1
    finish = "UPDATE abuse_send_requests SET status = 'sent', done_at = now()"
    assert await _run(ingest, finish) is None  # never straight from pending
    assert await _start(ingest, rid) == 1
    async with owner.connect() as conn:
        row = (
            await conn.execute(text("SELECT status, started_at, done_at FROM abuse_send_requests"))
        ).one()
    assert row.status == "sending" and row.started_at is not None and row.done_at is None
    # The mail may be on the wire: the owner can no longer cancel it, nor touch it.
    assert await _run(api, "UPDATE abuse_send_requests SET status = 'cancelled'") is None
    assert await _run(api, "UPDATE abuse_send_requests SET status = 'sent'") is None
    assert await _run(ingest, "UPDATE abuse_send_requests SET status = 'cancelled'") is None
    assert await _run(ingest, "UPDATE abuse_send_requests SET status = 'sending'") == 1
    # Nothing was connected (gate closed under it): back to pending, then started again.
    assert (
        await _run(ingest, "UPDATE abuse_send_requests SET status = 'pending', started_at = NULL")
        == 1
    )
    assert await _start(ingest, rid) == 1
    assert await _run(ingest, finish) == 1
    assert await _run(ingest, "UPDATE abuse_send_requests SET status = 'pending'") is None


async def test_the_api_writes_the_smtp_password_but_never_reads_it_back(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM report_smtp"))
    insert = (
        "INSERT INTO report_smtp (id, host, port, security, from_address, password_ciphertext, "
        "password_nonce) VALUES (1, 'smtp.example.org', 587, 'starttls', 'a@example.org', "
        "'\\x0102', '\\x0304')"
    )
    assert await _run(ingest, insert) is None  # ingest only reads
    assert await _run(api, insert) == 1
    assert await _run(api, "SELECT password_ciphertext FROM report_smtp") is None
    assert await _run(api, "SELECT password_nonce FROM report_smtp") is None
    assert await _run(api, "SELECT * FROM report_smtp") is None
    assert await _run(api, "SELECT host, port, from_address, password_set FROM report_smtp")
    async with api.connect() as conn:
        assert await conn.scalar(text("SELECT password_set FROM report_smtp")) is True
    clear = "UPDATE report_smtp SET password_ciphertext = NULL, password_nonce = NULL"
    assert await _run(api, clear) == 1
    async with api.connect() as conn:
        assert await conn.scalar(text("SELECT password_set FROM report_smtp")) is False
    async with ingest.connect() as conn:
        assert await conn.scalar(text("SELECT password_ciphertext FROM report_smtp")) is None
    assert await _run(ingest, "UPDATE report_smtp SET host = 'x.example.org'") is None
    assert await _run(ingest, "DELETE FROM report_smtp") is None
    for bad in (
        "UPDATE report_smtp SET mode = 'bogus'",
        "UPDATE report_smtp SET auto_hold_minutes = 5",
        "UPDATE report_smtp SET auto_hold_minutes = 2000",
        "UPDATE report_smtp SET daily_cap = 0",
        "UPDATE report_smtp SET daily_cap = 201",
        "UPDATE report_smtp SET security = 'plain'",
        "UPDATE report_smtp SET port = 0",
        "UPDATE report_smtp SET id = 2",
        "UPDATE report_smtp SET password_ciphertext = '\\x01'",  # nonce missing
    ):
        assert await _run(api, bad) is None, bad
    assert await _run(api, "DELETE FROM report_smtp") == 1


# -- M38 P3: the form-only desks queue ------------------------------------------------------

FORM_REPORT = (
    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo, window_start, "
    "window_end, evidence, content_sha256, guard_ok, status, channel, week) VALUES "
    "(gen_random_uuid(), gen_random_uuid(), (SELECT min(id) FROM abuse_recipients), 'digest', "
    "false, now(), now(), '{}', 'x', true, 'draft', :channel, CAST(:week AS date)) RETURNING id"
)
SUBJECT = (
    "INSERT INTO abuse_report_subjects (report_id, kind, subject_type, value, first_ts, last_ts, "
    "sessions, events) VALUES (:r, 'attack_source', 'ip', :v, now(), now(), 1, 1)"
)


async def _form_report(owner: AsyncEngine, channel: str = "form") -> int:
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports"))
        rid = int(
            await conn.scalar(
                text(FORM_REPORT),
                {"channel": channel, "week": date(2026, 11, 16) if channel == "form" else None},
            )
            or 0
        )
        for value in ("198.51.100.1", "198.51.100.2"):
            await conn.execute(text(SUBJECT), {"r": rid, "v": value})
        return rid


async def _mark(api: AsyncEngine, rid: int, via: str) -> int | None:
    """Review then send, as the API does in one transaction."""
    return await _run(
        api,
        "UPDATE abuse_reports SET status = 'sent', sent_at = now(), "
        "sent_by = 'owner', sent_via = :via WHERE id = :i AND status = 'reviewed'",
        {"i": rid, "via": via},
    )


async def _review(api: AsyncEngine, rid: int) -> None:
    assert await _run(
        api,
        "UPDATE abuse_reports SET status = 'reviewed', reviewed_by = 'owner', "
        "reviewed_at = now(), reviewed_revision = revision WHERE id = :i",
        {"i": rid},
    )


async def test_week_and_form_rules(owner: AsyncEngine) -> None:
    await _form_report(owner)
    # A week on a mail report, or a week that is not a Monday, is refused.
    bad = FORM_REPORT.replace("RETURNING id", "")
    assert await _run(owner, "DELETE FROM abuse_reports")
    assert await _run(owner, bad, {"channel": "mail", "week": date(2026, 11, 16)}) is None
    assert await _run(owner, bad, {"channel": "form", "week": date(2026, 11, 17)}) is None
    assert await _run(owner, bad, {"channel": "form", "week": date(2026, 11, 16)}) == 1


async def test_the_api_submits_a_form_report_and_drops_unticked_sources(
    owner: AsyncEngine,
    roles: tuple[AsyncEngine, AsyncEngine],
) -> None:
    api, ingest = roles
    rid = await _form_report(owner)
    # Before it is sent, the API may touch no source.
    tick_all = "UPDATE abuse_report_subjects SET submitted_at = now() WHERE report_id = :i"
    drop_all = "DELETE FROM abuse_report_subjects WHERE report_id = :i"
    assert await _run(api, tick_all, {"i": rid}) is None
    assert await _run(api, drop_all, {"i": rid}) is None
    await _review(api, rid)
    assert await _mark(api, rid, "form") == 1
    tick = (
        drop_all.replace("DELETE FROM", "UPDATE").replace("WHERE", "SET submitted_at = now() WHERE")
        + " AND value = '198.51.100.1'"
    )
    assert await _run(api, tick, {"i": rid}) == 1
    assert await _run(api, tick, {"i": rid}) is None  # once
    other = "UPDATE abuse_report_subjects SET sessions = 9 WHERE report_id = :i"
    assert await _run(api, other, {"i": rid}) is None
    # The submitted source stays; the unticked one may go.
    assert await _run(api, drop_all + " AND value = '198.51.100.1'", {"i": rid}) is None
    assert await _run(api, drop_all + " AND submitted_at IS NULL", {"i": rid}) == 1
    # Ingest never sets submitted_at.
    assert await _run(ingest, "UPDATE abuse_report_subjects SET submitted_at = now()") is None


async def test_only_a_form_report_is_sent_by_form_and_mail_sources_stay(
    owner: AsyncEngine,
    roles: tuple[AsyncEngine, AsyncEngine],
) -> None:
    api, _ingest = roles
    rid = await _form_report(owner, channel="mail")
    await _review(api, rid)
    assert await _mark(api, rid, "form") is None
    assert await _mark(api, rid, "manual") == 1
    # A report sent by hand keeps all its sources: the API may not drop any.
    assert (
        await _run(api, "DELETE FROM abuse_report_subjects WHERE report_id = :i", {"i": rid})
        is None
    )


async def test_the_channel_changes_on_a_draft_only(
    owner: AsyncEngine,
    roles: tuple[AsyncEngine, AsyncEngine],
) -> None:
    api, ingest = roles
    rid = await _form_report(owner)
    to_mail = "UPDATE abuse_reports SET channel = 'mail', week = NULL WHERE id = :i"
    assert await _run(ingest, to_mail, {"i": rid}) == 1
    assert await _run(api, to_mail, {"i": rid}) is None  # no grant
    await _review(api, rid)
    to_form = "UPDATE abuse_reports SET channel = 'form', week = '2026-11-16' WHERE id = :i"
    assert await _run(owner, to_form, {"i": rid}) is None  # reviewed: trigger


async def test_deleting_a_report_cascades_past_the_source_guard(
    owner: AsyncEngine,
) -> None:
    rid = await _form_report(owner)
    assert await _run(owner, "DELETE FROM abuse_reports WHERE id = :i", {"i": rid}) == 1


async def test_form_source_values(owner: AsyncEngine) -> None:
    upd = "UPDATE abuse_recipients SET form_source = :s"
    for ok in ("reply", "directory", "manual", "cleared", None):
        assert await _run(owner, upd, {"s": ok}) == 1
    assert await _run(owner, upd, {"s": "hub"}) is None
    assert await _run(owner, "UPDATE abuse_recipients SET form_entry = 'Bad Id'") is None
    assert await _run(owner, "UPDATE abuse_recipients SET form_entry = 'example-net'") == 1
