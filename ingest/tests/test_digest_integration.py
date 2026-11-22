"""Daily digests in the sender (M38, section 5) against a real database: the due time and the
digest hour, one automatic mail per recipient address per UTC day plus the next parts (2 h apart),
a manual send counting for the day, the strict switch, freshness per source, the schema check
before the send, and the switch that turns digests off. The SMTP client is a fake."""

# ruff: noqa: F811  (the imported `world` fixture is requested by name)
from __future__ import annotations

import email
import email.policy
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text

from ingest.reportmail import sender as sender_module

from .test_report_mail import FakeSMTP
from .test_report_mail_integration import (  # noqa: F401 - fixtures
    NOW,
    World,
    _age_auto_requests,
    smtp,
    world,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PAST = NOW - timedelta(hours=1)


def minute_of(value: datetime) -> int:
    utc = value.astimezone(UTC)
    return utc.hour * 60 + utc.minute


async def digest_profile(world: World, *, minute: int | None = None, hold: int = 10) -> None:
    """Auto mode with the digest hour already passed today (unless ``minute`` is given)."""
    await world.self_address()
    await world.profile(mode="auto", hold=hold, cap=20)
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE report_smtp SET digest_minute = :m"),
            {"m": 0 if minute is None else minute},
        )


async def recipient_of(world: World, report: int) -> int:
    async with world.owner.connect() as conn:
        return int(
            await conn.scalar(
                text("SELECT recipient_id FROM abuse_reports WHERE id = :r"), {"r": report}
            )
            or 0
        )


async def requests(world: World) -> list[Any]:
    async with world.owner.connect() as conn:
        return list(
            (
                await conn.execute(
                    text(
                        "SELECT report_id, status, error_code, scheduled_at, auto "
                        "FROM abuse_send_requests ORDER BY id"
                    )
                )
            ).all()
        )


async def age_sent(world: World, report: int, by: timedelta) -> None:
    """As if ``by`` had passed since the report was sent (and its request, for the spacing)."""
    async with world.owner.begin() as conn:
        await conn.execute(text("ALTER TABLE abuse_reports DISABLE TRIGGER USER"))
        await conn.execute(
            text(
                "UPDATE abuse_reports SET sent_at = sent_at - make_interval(secs => :b) "
                "WHERE id = :r"
            ),
            {"b": by.total_seconds(), "r": report},
        )
        await conn.execute(text("ALTER TABLE abuse_reports ENABLE TRIGGER USER"))
    await _age_auto_requests(world, by)


def later(minutes: int = 11) -> datetime:
    return datetime.now(UTC) + timedelta(minutes=minutes)


async def test_one_automatic_digest_per_recipient_per_day(world: World) -> None:
    await digest_profile(world)
    first = await world.report(kind="digest", due=PAST)
    rec = await recipient_of(world, first)
    second = await world.report(kind="digest", status="reviewed", recipient=rec, due=PAST)
    s = world.sender()
    await s.run(NOW)
    assert len(await requests(world)) == 2
    await s.run(later())
    assert len(FakeSMTP.instances) == 1
    sent = [r for r in (first, second) if (await world.report_row(r)).status == "sent"]
    assert len(sent) == 1
    await _age_auto_requests(world, timedelta(minutes=10))  # past the 3 minute spacing
    await s.run(later(30))
    await s.run(later(200))
    assert len(FakeSMTP.instances) == 1  # the other one waits for tomorrow
    waiting = (await requests(world))[0 if sent[0] == second else 1]
    assert waiting.status == "pending"


async def test_the_next_part_goes_two_hours_after_the_first(world: World) -> None:
    await digest_profile(world)
    first = await world.report(kind="digest", status="reviewed", due=PAST)
    rec = await recipient_of(world, first)
    s = world.sender()
    await s.run(NOW)
    await s.run(later())
    assert (await world.report_row(first)).status == "sent"
    part2 = await world.report(kind="digest", recipient=rec, due=PAST, part=2)
    await s.run(later())  # scheduled
    await age_sent(world, first, timedelta(minutes=30))
    await s.run(later(30))
    assert len(FakeSMTP.instances) == 1  # less than two hours after part 1
    await age_sent(world, first, timedelta(hours=3))
    await s.run(later(30))
    assert len(FakeSMTP.instances) == 2
    assert (await world.report_row(part2)).status == "sent"


async def test_a_digest_waits_for_its_due_time_and_the_digest_hour(world: World) -> None:
    now = datetime.now(UTC)
    if minute_of(now) > 1300:
        pytest.skip("too close to midnight UTC for a same-day digest hour")
    await digest_profile(world, minute=minute_of(now) + 120)
    report = await world.report(kind="digest", due=PAST)
    s = world.sender()
    await s.run(now)
    await s.run(later())
    assert FakeSMTP.instances == []  # the digest hour of today is still ahead
    await s.run(now + timedelta(minutes=125))
    assert (await world.report_row(report)).status == "sent"


async def test_the_request_is_scheduled_at_the_due_time(world: World) -> None:
    await digest_profile(world)
    due = NOW + timedelta(hours=5)
    await world.report(kind="digest", due=due)
    await world.sender().run(NOW)
    (row,) = await requests(world)
    assert row.scheduled_at == due  # not now + hold: the digest hour wins


async def test_a_mail_marked_sent_by_hand_counts_for_the_day(world: World) -> None:
    await digest_profile(world)
    manual = await world.report(kind="digest", status="reviewed")
    rec = await recipient_of(world, manual)
    async with world.api.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = 'owner', "
                "sent_via = 'manual' WHERE id = :r"
            ),
            {"r": manual},
        )
    auto = await world.report(kind="digest", recipient=rec, due=PAST)
    s = world.sender()
    await s.run(NOW)
    await s.run(later())
    assert FakeSMTP.instances == []
    assert (await world.report_row(auto)).status == "draft"
    # The owner may still send it by hand (the API asks for a confirmation first).
    await world.ask(auto)
    await s.run(later())
    assert (await world.report_row(auto)).status == "sent"


async def test_a_strict_recipient_is_limited_by_the_cap_only(world: World) -> None:
    await digest_profile(world)
    first = await world.report(kind="digest", status="reviewed", due=PAST)
    rec = await recipient_of(world, first)
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_recipients SET xarf_strict = true WHERE id = :r"), {"r": rec}
        )
    second = await world.report(kind="digest", recipient=rec, due=PAST, part=2)
    s = world.sender()
    await s.run(NOW)
    await s.run(later())
    await _age_auto_requests(world, timedelta(minutes=10))  # the 3 minute spacing
    await s.run(later(15))
    assert len(FakeSMTP.instances) == 2
    assert (await world.report_row(first)).status == "sent"
    assert (await world.report_row(second)).status == "sent"


async def test_freshness_is_per_source(world: World) -> None:
    await digest_profile(world)
    old = NOW - timedelta(days=9)
    report = await world.report(
        kind="digest", due=PAST, at=NOW - timedelta(hours=2), extra=[("198.51.100.99", old)]
    )
    s = world.sender()
    await s.run(NOW)
    await s.run(later())
    (conn,) = FakeSMTP.instances
    assert conn.sent is not None
    mail = email.message_from_bytes(conn.sent[2], policy=email.policy.SMTP)
    reports = [
        json.loads(p.get_payload(decode=True))  # type: ignore[arg-type]
        for p in mail.walk()
        if p.get_content_type() == "application/json"
    ]
    assert [r["source_identifier"] for r in reports] == ["198.51.100.23"]
    assert mail.get_content_type() == "multipart/report"  # one source left: the spec shape
    assert b"198.51.100.99" not in conn.sent[2]
    async with world.owner.connect() as c:
        values = (
            (
                await c.execute(
                    text("SELECT value FROM abuse_report_subjects WHERE report_id = :r"),
                    {"r": report},
                )
            )
            .scalars()
            .all()
        )
    assert list(values) == ["198.51.100.23"]  # the old source was not sent
    assert (await world.report_row(report)).status == "sent"


async def test_an_old_source_still_goes_with_a_send_by_hand(world: World) -> None:
    await digest_profile(world)
    old = NOW - timedelta(days=9)
    report = await world.report(
        kind="digest", status="reviewed", at=NOW - timedelta(hours=2),
        extra=[("198.51.100.99", old)],
    )  # fmt: skip
    await world.ask(report)
    await world.sender().run(NOW)
    (conn,) = FakeSMTP.instances
    assert conn.sent is not None
    mail = email.message_from_bytes(conn.sent[2], policy=email.policy.SMTP)
    assert mail.get_content_type() == "multipart/mixed"
    names = [p.get_filename() for p in mail.walk() if p.get_filename()]
    assert names == ["evidence.csv", "xarf-001.json", "xarf-002.json"]


async def test_an_invalid_xarf_part_blocks_the_send(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    await world.self_address()
    await world.profile()
    report = await world.report(status="reviewed")
    rid = await world.ask(report)
    monkeypatch.setattr(sender_module, "xarf_parts_valid", lambda raw: False)
    await world.sender().run(NOW)
    assert FakeSMTP.instances == []
    row = await world.request(rid)
    assert (row.status, row.error_code) == ("failed", "xarf_invalid")
    assert (await world.report_row(report)).status == "reviewed"


async def test_digests_off_send_after_the_hold_as_before(world: World) -> None:
    await digest_profile(world)
    async with world.owner.begin() as conn:
        await conn.execute(text("UPDATE report_settings SET digest_enabled = false"))
    first = await world.report(kind="digest", status="reviewed", due=NOW + timedelta(days=1))
    rec = await recipient_of(world, first)
    await world.report(kind="digest", recipient=rec)
    s = world.sender()
    await s.run(NOW)
    await s.run(later(24 * 60 + 11))
    await _age_auto_requests(world, timedelta(minutes=10))  # the 3 minute spacing
    await s.run(later(24 * 60 + 20))
    assert len(FakeSMTP.instances) == 2  # no one-a-day rule when digests are off


async def test_a_verified_reply_is_linked_to_the_sources_it_names(world: World) -> None:
    from ingest.replies.match import Match, by_xarf_id
    from ingest.replies.parse import ParsedReply
    from ingest.replies.store import link_sources

    report = await world.report(
        kind="digest", status="reviewed", extra=[("198.51.100.99", NOW - timedelta(hours=1))]
    )
    async with world.api.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = 'o', "
                "sent_via = 'manual' WHERE id = :r"
            ),
            {"r": report},
        )
    async with world.owner.begin() as conn:
        xid = await conn.scalar(
            text(
                "SELECT xarf_id FROM abuse_report_subjects WHERE report_id = :r "
                "AND value = '198.51.100.99'"
            ),
            {"r": report},
        )
        reply_id = await conn.scalar(
            text(
                "INSERT INTO abuse_replies (source, received_at, report_id, match_method, "
                "verified, classification, size_bytes) VALUES ('paste', now(), :r, 'xarf_id', "
                "true, 'resolved', 1) RETURNING id"
            ),
            {"r": report},
        )
    async with world.factory() as session, session.begin():
        rid, subjects, seen = await by_xarf_id(session, [str(xid)])
        assert (rid, subjects, seen) == (report, (("attack_source", "ip", "198.51.100.99"),), True)
        body = "Ticket T-9: we suspended 198.51.100.23.\n\nOn Monday you wrote:\n> 198.51.100.99"
        n = await link_sources(
            session,
            reply_id=int(reply_id or 0),
            report_id=report,
            found=Match(report, "xarf_id", subjects=subjects),
            reply=ParsedReply(body=body),
            ticket="T-9",
        )
    assert n == 2  # the quoted source, and the one named in the reply's own text
    async with world.owner.connect() as conn:
        rows = {
            r.value: r.ticket_id
            for r in await conn.execute(
                text("SELECT value, ticket_id FROM abuse_subject_outcomes WHERE reply_id = :p"),
                {"p": reply_id},
            )
        }
    assert rows == {"198.51.100.23": "T-9", "198.51.100.99": None}
    # A draft's XARF id matches nothing.
    draft = await world.report(kind="digest")
    async with world.owner.connect() as conn:
        draft_id = await conn.scalar(
            text("SELECT xarf_id FROM abuse_report_subjects WHERE report_id = :r"), {"r": draft}
        )
    async with world.factory() as session:
        assert await by_xarf_id(session, [str(draft_id)]) == (None, (), True)


async def test_an_xarf_id_alone_does_not_make_a_mail_relevant(world: World) -> None:
    from ingest.replies.parse import HeaderView
    from ingest.replies.store import is_relevant

    report = await world.report(kind="digest", status="reviewed")
    async with world.owner.connect() as conn:
        xid = await conn.scalar(
            text("SELECT xarf_id FROM abuse_report_subjects WHERE report_id = :r"), {"r": report}
        )
    view = HeaderView(
        from_address="someone@unrelated.example.com",
        from_domain="unrelated.example.com",
        from_local="someone",
        subject=f"About {xid}",
        reference_ids=(),
        content_type="text/plain",
        looks_like_dsn=False,
    )
    async with world.factory() as session:
        assert await is_relevant(session, view, []) is False


async def ended_request(world: World, report: int, code: str, *, before_change: bool) -> None:
    """An automatic request of ``report`` that ended with ``code``, before (or after) the report
    last changed."""
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by, "
                "scheduled_at) VALUES (:r, 'send', true, 'auto', now())"
            ),
            {"r": report},
        )
        status = "failed" if code in ("xarf_invalid", "guard_failed:project_term", "refused:550",
                                      "unknown_outcome") else "cancelled"  # fmt: skip
        await conn.execute(
            text(
                "UPDATE abuse_send_requests SET status = :s, error_code = :c, "
                "done_at = now() - interval '1 hour' WHERE report_id = :r AND status = 'pending'"
            ),
            {"s": status, "c": code, "r": report},
        )
        when = "now() - interval '2 hours'" if not before_change else "now()"
        await conn.execute(text("ALTER TABLE abuse_reports DISABLE TRIGGER USER"))
        await conn.execute(
            text(f"UPDATE abuse_reports SET updated_at = {when} WHERE id = :r"),  # noqa: S608
            {"r": report},
        )
        await conn.execute(text("ALTER TABLE abuse_reports ENABLE TRIGGER USER"))


@pytest.mark.parametrize(
    "code",
    ["too_old", "shared_host", "xarf_invalid", "guard_failed:project_term", "not_ready",
     "mode_changed"],
)  # fmt: skip
async def test_a_terminal_end_is_rescheduled_once_the_report_changed(
    world: World, code: str
) -> None:
    await digest_profile(world)
    report = await world.report(kind="digest", due=PAST)
    await ended_request(world, report, code, before_change=False)
    await world.sender().schedule(NOW)
    assert len(await requests(world)) == 1  # nothing changed since: it stays ended
    await ended_request(world, report, code, before_change=True)
    async with world.owner.begin() as conn:  # keep only the newest ended request
        await conn.execute(
            text(
                "DELETE FROM abuse_send_requests WHERE id <> (SELECT max(id) FROM "
                "abuse_send_requests)"
            )
        )
    await world.sender().schedule(NOW)
    rows = await requests(world)
    assert [r.status for r in rows] == [rows[0].status, "pending"]


@pytest.mark.parametrize("flag", ["form_only", "undeliverable"])
async def test_a_desk_flag_end_is_rescheduled_once_the_flag_is_cleared(
    world: World, flag: str
) -> None:
    await digest_profile(world)
    report = await world.report(kind="digest", due=PAST)
    rec = await recipient_of(world, report)
    async with world.owner.begin() as conn:
        await conn.execute(
            text(f"UPDATE abuse_recipients SET {flag} = true WHERE id = :r"),  # noqa: S608
            {"r": rec},
        )
    await ended_request(world, report, flag, before_change=False)
    await world.sender().schedule(NOW)
    assert len(await requests(world)) == 1  # still flagged
    async with world.api.begin() as conn:
        await conn.execute(
            text(f"UPDATE abuse_recipients SET {flag} = false WHERE id = :r"),  # noqa: S608
            {"r": rec},
        )
    await world.sender().schedule(NOW)
    assert [r.status for r in await requests(world)][-1] == "pending"


@pytest.mark.parametrize("code", ["refused:550", "unknown_outcome", None])
async def test_a_refusal_an_unknown_outcome_or_the_owners_cancel_still_block(
    world: World, code: str | None
) -> None:
    await digest_profile(world)
    report = await world.report(kind="digest", due=PAST)
    if code is None:
        await world.sender().schedule(NOW)
        async with world.api.begin() as conn:
            await conn.execute(text("UPDATE abuse_send_requests SET status = 'cancelled'"))
        async with world.owner.begin() as conn:
            await conn.execute(text("ALTER TABLE abuse_reports DISABLE TRIGGER USER"))
            await conn.execute(text("UPDATE abuse_reports SET updated_at = now() + interval '1 s'"))
            await conn.execute(text("ALTER TABLE abuse_reports ENABLE TRIGGER USER"))
    else:
        await ended_request(world, report, code, before_change=True)
    await world.sender().schedule(NOW)
    assert len(await requests(world)) == 1


async def test_the_hold_runs_from_the_last_rebuild(world: World) -> None:
    await digest_profile(world, hold=30)
    report = await world.report(kind="digest", due=NOW - timedelta(hours=2))
    s = world.sender()
    await s.run(NOW)
    async with world.owner.begin() as conn:  # the request was queued long ago
        await conn.execute(text("ALTER TABLE abuse_send_requests DISABLE TRIGGER USER"))
        await conn.execute(
            text("UPDATE abuse_send_requests SET scheduled_at = now() - interval '1 hour'")
        )
        await conn.execute(text("ALTER TABLE abuse_send_requests ENABLE TRIGGER USER"))
    await s.run(datetime.now(UTC) + timedelta(minutes=5))
    assert FakeSMTP.instances == []  # rebuilt (created) less than the hold ago
    await s.run(datetime.now(UTC) + timedelta(minutes=31))
    assert (await world.report_row(report)).status == "sent"


async def test_the_xarf_files_that_left_are_stored(world: World) -> None:
    await digest_profile(world)
    report = await world.report(
        kind="digest", due=PAST, at=NOW - timedelta(hours=2),
        extra=[("198.51.100.98", NOW - timedelta(hours=1))],
    )  # fmt: skip
    s = world.sender()
    await s.run(NOW)
    await s.run(later())
    (conn,) = FakeSMTP.instances
    assert conn.sent is not None
    mail = email.message_from_bytes(conn.sent[2], policy=email.policy.SMTP)
    sent = {
        p.get_filename(): p.get_payload(decode=True).decode()  # type: ignore[union-attr]
        for p in mail.walk()
        if p.get_content_type() == "application/json"
    }
    stored = (await world.report_row(report)).sent_xarf
    assert {f["name"]: f["content"] for f in stored} == sent
    assert sorted(k or "" for k in sent) == ["xarf-001.json", "xarf-002.json"]
