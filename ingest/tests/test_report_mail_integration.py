"""The M25 sender against a real database: requests, modes, the daily cap, auto scheduling and the
three owner requirements (a closed gate sends nothing, the whole message is guarded, a missing
self address fails closed). The SMTP client is a fake: no test opens a connection."""

from __future__ import annotations

import asyncio
import base64
import email
import email.policy
import json
import os
import smtplib
import threading
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db import create_engine
from suckerpot_db.locks import ABUSE_SMTP_PROFILE
from suckerpot_db.secretbox import Credential, SecretBox
from suckerpot_egress import EgressClosed

from ingest.abuse import AbuseSettings
from ingest.abuse.selfterms import TermsCache
from ingest.reportmail import outgoing
from ingest.reportmail.sender import ReportSender

from .db_fixtures import _role_url
from .helpers import fake_gate
from .test_report_mail import PASSWORD, FakeSMTP

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


Factory = async_sessionmaker[AsyncSession]
SELF = "203.0.113.77"
OWNER_DOMAIN = "dashboard.example.net"
ENV = {"API_ALLOWED_HOSTS": OWNER_DOMAIN}
BOX = SecretBox(bytes(range(32, 72)))
NOW = datetime.now(UTC).replace(microsecond=0)
STAMP = (NOW - timedelta(hours=2)).isoformat()


def evidence(cmd: str) -> dict[str, Any]:
    return {
        "kind": "attack_source",
        "recipient": "abuse@example.net",
        "subjects": [
            {
                "type": "ip", "value": "198.51.100.23", "asn": 64500, "network": "EXAMPLE-NET",
                "country": "NL", "first_ts": STAMP, "last_ts": STAMP, "sessions": 1, "events": 3,
                "activities": [
                    {
                        "ts": STAMP, "src_ip": "198.51.100.23", "src_port": 41022, "dst_port": 22,
                        "protocol": "tcp", "service": "ssh", "action": "command", "text": cmd,
                    }
                ],
                "redaction": {"addresses_masked": 0, "lines_dropped": 0},
            }
        ],
        "window_start": STAMP,
        "window_end": STAMP,
    }  # fmt: skip


class World:
    def __init__(self, owner: AsyncEngine, api: AsyncEngine, factory: Factory) -> None:
        self.owner, self.api, self.factory = owner, api, factory
        self.n = 0

    async def reset(self) -> None:
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "TRUNCATE abuse_send_requests, report_smtp, abuse_reports, abuse_recipients, "
                    "report_self_terms, report_settings, enrichment_status RESTART IDENTITY CASCADE"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO report_settings (id, reply_contact, signature, intro, outro, "
                    "note, subject_template, xarf_user_agent) VALUES (1, 'reports@example.org', "
                    "'Regards', 'Own intro.', 'Own outro.', 'Own note.', 'Notice from {value}', "
                    "'reporter/1.0')"
                )
            )

    async def self_address(self) -> None:
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO report_self_terms (kind, value, source, confirmed) "
                    "VALUES ('address', :a, 'manual', true)"
                ),
                {"a": SELF},
            )

    async def profile(self, *, box: SecretBox | None = BOX, **over: Any) -> None:
        values: dict[str, Any] = {
            "host": "smtp.example.org", "port": 587, "security": "starttls",
            "username": "reporter", "from_address": "sender@mail.example.org",
            "from_name": "Network Volunteer", "mode": "click", "hold": 60, "cap": 20,
        }  # fmt: skip
        values.update(over)
        cipher = nonce = None
        if box is not None:
            cipher, nonce = box.encrypt("report_smtp", Credential(key=PASSWORD))
        async with self.owner.begin() as conn:
            await conn.execute(text("DELETE FROM report_smtp"))
            await conn.execute(
                text(
                    "INSERT INTO report_smtp (id, host, port, security, username, from_address, "
                    "from_name, password_ciphertext, password_nonce, mode, auto_hold_minutes, "
                    "daily_cap) VALUES (1, :host, :port, :security, :username, :from_address, "
                    ":from_name, :c, :n, :mode, :hold, :cap)"
                ),
                {**values, "c": cipher, "n": nonce},
            )

    async def report(
        self, *, status: str = "draft", demo: bool = False, guard_ok: bool = True,
        cmd: str = "uname -a",
    ) -> int:  # fmt: skip
        self.n += 1
        async with self.owner.begin() as conn:
            rec = await conn.scalar(
                text(
                    "INSERT INTO abuse_recipients (mailbox, source) VALUES (:m, 'rdap') "
                    "RETURNING id"
                ),
                {"m": f"abuse{self.n}@example.net"},
            )
            ev = evidence(cmd)
            ev["recipient"] = f"abuse{self.n}@example.net"
            return int(
                await conn.scalar(
                    text(
                        "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, "
                        "status, demo, window_start, window_end, subject_count, evidence, "
                        "content_sha256, guard_ok) VALUES (gen_random_uuid(), gen_random_uuid(), "
                        ":r, 'attack_source', :s, :d, :t, :t, 1, CAST(:e AS jsonb), 'x', :g) "
                        "RETURNING id"
                    ),
                    {
                        "r": rec,
                        "s": status,
                        "d": demo,
                        "t": NOW,
                        "e": json.dumps(ev),
                        "g": guard_ok,
                    },
                )
                or 0
            )

    async def ask(self, report_id: int | None, kind: str = "send", by: str = "admin") -> int:
        """A request as the API role writes it."""
        async with self.api.begin() as conn:
            return int(
                await conn.scalar(
                    text(
                        "INSERT INTO abuse_send_requests (report_id, kind, requested_by) "
                        "VALUES (:r, :k, :b) RETURNING id"
                    ),
                    {"r": report_id, "k": kind, "b": by},
                )
                or 0
            )

    async def request(self, rid: int) -> Any:
        async with self.owner.connect() as conn:
            return (
                await conn.execute(
                    text("SELECT * FROM abuse_send_requests WHERE id = :i"), {"i": rid}
                )
            ).one()

    async def report_row(self, report_id: int) -> Any:
        async with self.owner.connect() as conn:
            return (
                await conn.execute(
                    text("SELECT * FROM abuse_reports WHERE id = :i"), {"i": report_id}
                )
            ).one()

    def sender(self, *, gate: Any = None, box: SecretBox | None = BOX) -> ReportSender:
        return ReportSender(
            self.factory,
            TermsCache(self.factory, ENV),
            AbuseSettings(),
            box=box,
            gate=gate or fake_gate(),
            allow_documentation=True,  # the fixtures use documentation addresses
        )


@pytest.fixture
async def world(engine: AsyncEngine, factory: Factory) -> AsyncIterator[World]:
    api = create_engine(_role_url_api(), pool_size=2)
    w = World(engine, api, factory)
    await w.reset()
    yield w
    await api.dispose()


def _role_url_api() -> str:
    return _role_url("API")


@pytest.fixture(autouse=True)
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.instances = []
    FakeSMTP.fail = {}
    FakeSMTP.hold = None
    FakeSMTP.entered = threading.Event()
    monkeypatch.setattr(outgoing, "TunnelSMTP", FakeSMTP)
    monkeypatch.setattr(outgoing, "TunnelSMTP_SSL", FakeSMTP)
    return FakeSMTP


def parsed(conn: FakeSMTP) -> Any:
    assert conn.sent is not None
    return email.message_from_bytes(conn.sent[2], policy=email.policy.SMTP)


# ---- the happy paths -------------------------------------------------------------------------


async def test_click_send_marks_the_report_sent_by_smtp(world: World) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    await world.sender().run(NOW)
    (conn,) = FakeSMTP.instances
    assert conn.sent is not None and conn.sent[0] == "sender@mail.example.org"
    assert conn.sent[1] == ["abuse1@example.net"]
    assert conn.kwargs["local_hostname"] == "mail.example.org"
    mail = parsed(conn)
    assert mail["To"] == "abuse1@example.net" and mail["From"].endswith("<sender@mail.example.org>")
    assert "X-Mailer" not in mail and "User-Agent" not in mail and "Bcc" not in mail
    assert mail["Message-ID"].endswith("@mail.example.org>")
    req, row = await world.request(rid), await world.report_row(report)
    assert req.status == "sent" and req.done_at is not None and req.error_code is None
    assert row.status == "sent" and row.sent_via == "smtp" and row.sent_by == "admin"
    assert row.sent_at is not None and row.reviewed_by is None


async def test_a_draft_can_be_sent_on_click_without_a_review_stamp(world: World) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="draft")
    await world.ask(report)
    await world.sender().run(NOW)
    row = await world.report_row(report)
    assert row.status == "sent" and row.sent_via == "smtp" and row.reviewed_by is None


async def test_a_test_goes_to_the_sender_address_itself(world: World) -> None:
    await world.self_address()
    await world.profile(mode="off")  # a test works in every mode
    rid = await world.ask(None, "test")
    await world.sender().run(NOW)
    (conn,) = FakeSMTP.instances
    assert conn.sent is not None and conn.sent[1] == ["sender@mail.example.org"]
    assert parsed(conn)["Subject"] == "Test message"
    assert (await world.request(rid)).status == "sent"


# ---- owner requirement 1: a closed gate sends nothing ----------------------------------------


async def test_closed_gate_attempts_no_connection_for_send_test_and_auto(world: World) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=10)
    sent_report = await world.report(status="reviewed")
    auto_report = await world.report(status="draft")
    click = await world.ask(sent_report)
    test = await world.ask(None, "test")
    old = NOW - timedelta(minutes=5)
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_send_requests SET requested_at = :t WHERE id = :i"),
            {"t": old, "i": test},
        )
    closed = world.sender(gate=fake_gate(open_=False, reason="tunnel_down"))
    # First cycle schedules the auto request; a later one is past its hold.
    await closed.run(NOW)
    await closed.run(NOW + timedelta(hours=2))
    assert FakeSMTP.instances == []  # not a single SMTP client, hence no socket or tunnel
    assert (await world.request(click)).status == "pending"  # a send waits for the VPN
    failed = await world.request(test)  # a test fails once it waited too long
    assert failed.status == "failed" and failed.error_code == "egress_closed"
    async with world.owner.connect() as conn:
        auto = (
            await conn.execute(
                text("SELECT status FROM abuse_send_requests WHERE auto AND report_id = :r"),
                {"r": auto_report},
            )
        ).all()
    assert [r.status for r in auto] == ["pending"]
    assert (await world.report_row(sent_report)).status == "reviewed"
    # The VPN comes back: the waiting requests go out.
    await world.sender().run(NOW + timedelta(hours=2))
    assert len(FakeSMTP.instances) == 2


async def test_a_gate_that_closes_under_the_send_leaves_it_pending(world: World) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    FakeSMTP.fail["connect"] = EgressClosed("tunnel_down")
    await world.sender().run(NOW)
    assert (await world.request(rid)).status == "pending"
    assert (await world.report_row(report)).status == "reviewed"


# ---- owner requirement 2: the whole message is guarded, and fails closed -----------------------


@pytest.mark.parametrize(
    "cmd",
    [
        f"ssh admin@{SELF}",
        f"GET /redirect?to=http://{SELF}/ HTTP/1.1",
        f"Host: {SELF}:8080",
        "curl http://3405803853/x",  # inet_aton: decimal integer
        "curl http://0xCB00714D/x",  # inet_aton: hex
        "ping 203.000.113.077",  # leading zeros
        f"wget hxxp://{SELF.rsplit('.', 1)[0]}[.]77/a",
        f"echo {base64.b64encode(f'go {SELF}/x'.encode()).decode()} | base64 -d | sh",
    ],
)
async def test_a_self_address_in_the_evidence_is_never_sent(world: World, cmd: str) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed", cmd=cmd)
    rid = await world.ask(report)
    await world.sender().run(NOW)
    assert FakeSMTP.instances == []  # the fake server received nothing
    req = await world.request(rid)
    assert req.status == "failed" and req.error_code.startswith("guard_failed:")
    assert "self_address" in req.error_code
    assert SELF not in req.error_code and "3405803853" not in req.error_code
    assert (await world.report_row(report)).status == "reviewed"


async def test_no_confirmed_self_address_means_nothing_is_sent(world: World) -> None:
    await world.profile()  # no report_self_terms row at all
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    test = await world.ask(None, "test")
    await world.sender().run(NOW)
    assert FakeSMTP.instances == []
    for request_id in (rid, test):
        req = await world.request(request_id)
        assert req.status == "failed" and "no_self_address" in req.error_code
        assert req.error_code.startswith("guard_failed:")
    assert (await world.report_row(report)).status == "reviewed"


async def test_a_stale_learned_address_does_not_count(world: World) -> None:
    await world.profile()
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source, confirmed, last_seen) "
                "VALUES ('address', :a, 'sensor', true, now() - interval '10 days')"
            ),
            {"a": SELF},
        )
    rid = await world.ask(await world.report(status="reviewed"))
    await world.sender().run(NOW)
    assert FakeSMTP.instances == []
    assert "no_self_address" in (await world.request(rid)).error_code


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"from_name": f"Host {SELF}"}, "self_address"),
        ({"from_address": f"ops@{OWNER_DOMAIN}"}, "owner_domain"),
        ({"username": f"user@{OWNER_DOMAIN}"}, "owner_domain"),
    ],
)
async def test_a_self_term_in_the_profile_headers_blocks_report_and_test(
    world: World, over: dict[str, Any], code: str
) -> None:
    await world.self_address()
    await world.profile(**over)
    rid = await world.ask(await world.report(status="reviewed"))
    test = await world.ask(None, "test")
    await world.sender().run(NOW)
    assert FakeSMTP.instances == []
    for request_id in (rid, test):
        req = await world.request(request_id)
        assert req.status == "failed" and code in req.error_code


# ---- modes, readiness, errors ----------------------------------------------------------------


async def test_mode_off_refuses_a_send_and_a_mode_change_cancels_auto(world: World) -> None:
    await world.self_address()
    await world.profile(mode="off")
    rid = await world.ask(await world.report(status="reviewed"))
    await world.sender().run(NOW)
    req = await world.request(rid)
    assert req.status == "failed" and req.error_code == "mode_off"
    await world.profile(mode="auto", hold=10)
    auto_report = await world.report(status="draft")
    s = world.sender()
    await s.run(NOW)
    await world.profile(mode="click", hold=10)  # the owner changes their mind
    await s.run(NOW + timedelta(hours=1))
    async with world.owner.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT status, error_code FROM abuse_send_requests WHERE report_id = :r"),
                {"r": auto_report},
            )
        ).one()
    assert (row.status, row.error_code) == ("cancelled", "mode_changed")
    assert FakeSMTP.instances == []


async def test_demo_and_unready_reports_are_never_sent(world: World) -> None:
    await world.self_address()
    await world.profile()
    demo = await world.ask(await world.report(demo=True))
    blocked = await world.ask(await world.report(guard_ok=False))
    done = await world.ask(await world.report(status="discarded"))
    await world.sender().run(NOW)
    assert FakeSMTP.instances == []
    for request_id in (demo, blocked, done):
        req = await world.request(request_id)
        assert req.status == "failed" and req.error_code == "not_ready"


async def test_an_unusable_profile_fails_the_request(world: World) -> None:
    await world.self_address()
    await world.profile()
    rid = await world.ask(await world.report(status="reviewed"))
    await world.sender(box=None).run(NOW)  # no key to decrypt the password
    assert (await world.request(rid)).error_code == "not_configured"
    assert FakeSMTP.instances == []


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (smtplib.SMTPAuthenticationError(535, b"nope"), "auth_failed"),
        (smtplib.SMTPRecipientsRefused({"x": (550, b"no")}), "refused:550"),
        (TimeoutError("slow"), "unknown_outcome"),  # in DATA: nobody knows
    ],
)
async def test_a_failed_send_keeps_the_report_ready(
    world: World, exc: BaseException, code: str
) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    FakeSMTP.fail["auth" if code == "auth_failed" else "send"] = exc
    await world.sender().run(NOW)
    req = await world.request(rid)
    assert req.status == "failed" and req.error_code == code
    assert (await world.report_row(report)).status == "reviewed"


async def test_a_cancelled_request_is_left_alone(world: World) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    async with world.api.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_send_requests SET status = 'cancelled' WHERE id = :i"), {"i": rid}
        )
    await world.sender().run(NOW)
    assert FakeSMTP.instances == []
    assert (await world.request(rid)).status == "cancelled"


# ---- auto mode -------------------------------------------------------------------------------


async def test_auto_waits_for_the_hold_respects_the_cap_and_skips_the_unsendable(
    world: World,
) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=10, cap=1)
    first = await world.report(status="draft")
    second = await world.report(status="reviewed")
    demo = await world.report(demo=True)
    blocked = await world.report(guard_ok=False)
    s = world.sender()
    await s.run(NOW)
    assert FakeSMTP.instances == []  # scheduled, not sent
    async with world.owner.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT report_id, scheduled_at, auto, requested_by FROM abuse_send_requests "
                    "ORDER BY report_id"
                )
            )
        ).all()
    assert [r.report_id for r in rows] == [first, second]  # not the demo, not the guard-failed
    assert all(r.auto and r.requested_by == "auto" for r in rows)
    assert all(r.scheduled_at - NOW == timedelta(minutes=10) for r in rows)
    await s.run(NOW)  # still within the hold: nothing, and no second schedule
    assert FakeSMTP.instances == []
    later = datetime.now(UTC) + timedelta(minutes=11)
    await s.run(later)
    assert len(FakeSMTP.instances) == 1  # the daily cap is one
    one = await world.report_row(first)
    assert one.status == "sent" and one.sent_via == "smtp" and one.sent_by == "auto"
    assert one.reviewed_by == "auto" and one.reviewed_at is not None  # a draft was sent
    assert (await world.report_row(second)).status == "reviewed"
    await s.run(later)
    assert len(FakeSMTP.instances) == 1  # still capped for today
    assert (await world.report_row(demo)).status == "draft"
    assert (await world.report_row(blocked)).status == "draft"


async def test_a_cancelled_auto_request_is_not_scheduled_again(world: World) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=10)
    report = await world.report(status="reviewed")
    s = world.sender()
    await s.run(NOW)
    async with world.api.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_send_requests SET status = 'cancelled' WHERE report_id = :r"),
            {"r": report},
        )
    await s.run(datetime.now(UTC) + timedelta(hours=1))
    await s.run(datetime.now(UTC) + timedelta(hours=2))
    async with world.owner.connect() as conn:
        count = await conn.scalar(text("SELECT count(*) FROM abuse_send_requests"))
    assert count == 1 and FakeSMTP.instances == []


async def _age_auto_requests(world: World, by: timedelta) -> None:
    """Moves the start and end of every automatic send back, as if ``by`` had passed."""
    async with world.owner.begin() as conn:
        await conn.execute(text("ALTER TABLE abuse_send_requests DISABLE TRIGGER USER"))
        await conn.execute(
            text(
                "UPDATE abuse_send_requests SET "
                "started_at = started_at - make_interval(secs => :d), "
                "done_at = done_at - make_interval(secs => :d) WHERE auto"
            ),
            {"d": by.total_seconds()},
        )
        await conn.execute(text("ALTER TABLE abuse_send_requests ENABLE TRIGGER USER"))


async def test_automatic_sends_are_spaced_out(world: World) -> None:
    """A burst from one mailbox looks like spam to its provider: one automatic mail at a time."""
    await world.self_address()
    await world.profile(mode="auto", hold=10, cap=20)
    first = await world.report(status="reviewed")
    second = await world.report(status="reviewed")
    s = world.sender()
    await s.run(NOW)
    later = datetime.now(UTC) + timedelta(minutes=11)
    await s.run(later)
    assert len(FakeSMTP.instances) == 1
    await s.run(later)  # less than the spacing since the first: still one
    assert len(FakeSMTP.instances) == 1
    assert (await world.report_row(first)).status == "sent"
    assert (await world.report_row(second)).status == "reviewed"
    await _age_auto_requests(world, timedelta(minutes=4))
    await s.run(later)
    assert len(FakeSMTP.instances) == 2
    assert (await world.report_row(second)).status == "sent"


async def test_a_click_send_is_not_held_back_by_the_spacing(world: World) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=10, cap=20)
    await world.report(status="reviewed")
    s = world.sender()
    await s.run(NOW)
    await s.run(datetime.now(UTC) + timedelta(minutes=11))
    assert len(FakeSMTP.instances) == 1
    clicked = await world.report(status="reviewed")
    rid = await world.ask(clicked)
    await s.run(datetime.now(UTC) + timedelta(minutes=11))
    assert (await world.request(rid)).status == "sent"


async def test_a_deferred_send_pauses_the_automatic_ones_and_is_tried_again(
    world: World,
) -> None:
    """A 4xx reply (a rate limit) is "not now": every automatic send waits, then the report is
    scheduled again by itself."""
    await world.self_address()
    await world.profile(mode="auto", hold=10, cap=20)
    first = await world.report(status="reviewed")
    second = await world.report(status="reviewed")
    s = world.sender()
    await s.run(NOW)
    FakeSMTP.fail["send"] = smtplib.SMTPDataError(451, b"too many messages")
    later = datetime.now(UTC) + timedelta(minutes=11)
    await s.run(later)
    async with world.owner.connect() as conn:
        failed = (
            await conn.execute(
                text("SELECT report_id, error_code FROM abuse_send_requests WHERE status='failed'")
            )
        ).all()
    assert [(r.report_id, r.error_code) for r in failed] == [(first, "deferred:451")]
    del FakeSMTP.fail["send"]
    # Past the spacing but within the pause: nothing goes out.
    await _age_auto_requests(world, timedelta(minutes=10))
    await s.run(later)
    assert all(c.sent is None for c in FakeSMTP.instances)
    assert (await world.report_row(second)).status == "reviewed"
    # The deferred report got a new automatic request.
    async with world.owner.connect() as conn:
        pending = await conn.scalar(
            text(
                "SELECT count(*) FROM abuse_send_requests WHERE report_id = :r "
                "AND status = 'pending' AND auto"
            ),
            {"r": first},
        )
    assert pending == 1
    # The pause is over: both reports go out, one at a time.
    await _age_auto_requests(world, timedelta(hours=1))
    for _ in range(2):
        await s.run(datetime.now(UTC) + timedelta(minutes=30))
        await _age_auto_requests(world, timedelta(minutes=4))
    assert (await world.report_row(first)).status == "sent"
    assert (await world.report_row(second)).status == "sent"


async def test_a_report_is_rescheduled_after_at_most_three_deferrals(world: World) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=10, cap=20)
    report = await world.report(status="reviewed")
    s = world.sender()
    FakeSMTP.fail["send"] = smtplib.SMTPRecipientsRefused({"abuse1@example.net": (450, b"later")})
    base = datetime.now(UTC)
    for i in range(6):  # the first run only schedules; each later one is past the hold
        await s.run(base + timedelta(hours=2 * (i + 1)))
        await _age_auto_requests(world, timedelta(hours=2))
    async with world.owner.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT status, error_code FROM abuse_send_requests WHERE report_id = :r"),
                {"r": report},
            )
        ).all()
    assert [(r.status, r.error_code) for r in rows] == [("failed", "deferred:450")] * 3
    assert (await world.report_row(report)).status == "reviewed"


async def test_a_refused_automatic_send_is_not_tried_again(world: World) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=10, cap=20)
    report = await world.report(status="reviewed")
    s = world.sender()
    await s.run(NOW)
    FakeSMTP.fail["send"] = smtplib.SMTPDataError(554, b"rejected")
    await s.run(datetime.now(UTC) + timedelta(minutes=11))
    await _age_auto_requests(world, timedelta(hours=2))
    await s.run(datetime.now(UTC) + timedelta(hours=1))
    async with world.owner.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT status, error_code FROM abuse_send_requests WHERE report_id = :r"),
                {"r": report},
            )
        ).all()
    assert [(r.status, r.error_code) for r in rows] == [("failed", "refused:554")]


# ---- at most once ----------------------------------------------------------------------------


async def _status(world: World, rid: int) -> Any:
    return await world.request(rid)


async def test_a_crash_after_the_delivery_never_sends_a_second_time(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The commit that would record the send is killed. The request was marked ``sending`` in its
    own earlier transaction, so no later cycle picks it again."""
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)

    async def killed(*_a: object, **_k: object) -> None:
        raise RuntimeError("process died before the commit")

    monkeypatch.setattr(ReportSender, "_mark_done", killed)
    with pytest.raises(RuntimeError):
        await world.sender().run(NOW)
    assert len(FakeSMTP.instances) == 1  # the mail went
    req = await world.request(rid)
    assert req.status == "sending" and req.started_at is not None and req.done_at is None
    assert (await world.report_row(report)).status == "reviewed"  # nothing recorded
    monkeypatch.undo()
    fresh = world.sender()
    await fresh.run(NOW)
    await fresh.run(NOW + timedelta(hours=3))
    assert len(FakeSMTP.instances) == 1  # a sending request is never picked again
    assert (await world.request(rid)).status == "sending"  # not yet past the deadline
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_send_requests SET started_at = now() - interval '10 minutes'")
        )
    await fresh.run(NOW)
    req = await world.request(rid)
    assert req.status == "failed" and req.error_code == "unknown_outcome" and req.done_at
    await fresh.run(NOW + timedelta(hours=3))
    assert len(FakeSMTP.instances) == 1
    assert (await world.report_row(report)).status == "reviewed"  # the owner decides


async def test_a_timeout_during_data_is_an_unknown_outcome_and_is_not_retried(
    world: World,
) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    FakeSMTP.fail["send"] = TimeoutError("slow")
    s = world.sender()
    await s.run(NOW)
    req = await world.request(rid)
    assert req.status == "failed" and req.error_code == "unknown_outcome"
    FakeSMTP.fail = {}
    await s.run(NOW + timedelta(hours=1))
    assert len(FakeSMTP.instances) == 1
    assert (await world.report_row(report)).status == "reviewed"


async def test_the_profile_is_locked_while_a_mail_is_in_flight(world: World) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    FakeSMTP.hold = threading.Event()
    task = asyncio.create_task(world.sender().run(NOW))
    try:
        for _ in range(100):
            if FakeSMTP.entered.is_set():
                break
            await asyncio.sleep(0.1)
        assert FakeSMTP.entered.is_set()
        assert (await world.request(rid)).status == "sending"
        async with world.api.connect() as conn:  # what the API takes to change the profile
            free = await conn.scalar(
                text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": ABUSE_SMTP_PROFILE}
            )
        assert free is False
    finally:
        assert FakeSMTP.hold is not None
        FakeSMTP.hold.set()
        await task
    async with world.api.connect() as conn:
        assert await conn.scalar(
            text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": ABUSE_SMTP_PROFILE}
        )
    assert (await world.request(rid)).status == "sent"


async def test_non_automatic_requests_go_first_and_a_reached_cap_skips_the_automatic(
    world: World,
) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=10, cap=1)
    auto_one = await world.report(status="reviewed")
    auto_two = await world.report(status="reviewed")
    click_report = await world.report(status="reviewed")
    s = world.sender()
    await s.run(NOW)  # schedules the three reports
    async with world.owner.begin() as conn:
        # the owner clicked Send on the last one: a plain request, due at once
        await conn.execute(
            text("DELETE FROM abuse_send_requests WHERE report_id = :r"), {"r": click_report}
        )
    await world.ask(click_report)
    later = datetime.now(UTC) + timedelta(minutes=11)
    await s.run(later)
    # The plain request goes first and spends the cap (1): the automatic ones stay pending.
    assert len(FakeSMTP.instances) == 1
    async with world.owner.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT report_id, status, auto FROM abuse_send_requests ORDER BY id")
            )
        ).all()
    assert [(r.report_id, r.status) for r in rows if not r.auto] == [(click_report, "sent")]
    assert {r.report_id for r in rows if r.auto and r.status == "pending"} == {auto_one, auto_two}


async def test_a_future_schedule_is_not_picked(world: World) -> None:
    await world.self_address()
    await world.profile(mode="auto", hold=60)
    await world.report(status="reviewed")
    s = world.sender()
    await s.run(NOW)
    await s.run(NOW + timedelta(minutes=30))
    assert FakeSMTP.instances == []


async def test_the_message_id_and_the_reply_token_are_recorded(world: World) -> None:
    """M26: a reply can be matched to a mail by our Message-ID or by the token in the subject."""
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    await world.sender().run(NOW)
    (conn,) = FakeSMTP.instances
    mail = parsed(conn)
    req, row = await world.request(rid), await world.report_row(report)
    assert req.status == "sent" and req.message_id == mail["Message-ID"]
    assert mail["Subject"].endswith(f"(ref {row.reply_token})")
    assert (
        conn.sent is not None and conn.sent[2].decode().count(row.reply_token) == 1
    )  # subject only
    assert row.reply_token not in row.id_seed.hex and row.reply_token != str(row.public_id)[:12]


async def test_the_reference_style_off_prints_no_token(world: World) -> None:
    await world.self_address()
    await world.profile()
    async with world.owner.begin() as conn:
        await conn.execute(text("UPDATE report_settings SET reference_style = 'off'"))
    report = await world.report(status="reviewed")
    await world.ask(report)
    await world.sender().run(NOW)
    (sent_conn,) = FakeSMTP.instances
    row = await world.report_row(report)
    assert sent_conn.sent is not None and row.reply_token not in sent_conn.sent[2].decode()
