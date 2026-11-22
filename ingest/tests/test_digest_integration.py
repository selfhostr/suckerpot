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
            text("UPDATE abuse_reports SET sent_at = sent_at - :b WHERE id = :r"),
            {"b": by, "r": report},
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
