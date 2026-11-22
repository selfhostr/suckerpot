"""The form-only desks queue in ingest (M38, section 6) against a real database: a form-only
recipient gets a weekly form report and never an automatic mail, the shared directory routes a
desk before any mail goes (D13) and lets it go when its entry goes, the owner's choice wins over
the directory, the kit is part of the identity check, and a report submitted meanwhile is never
rewritten by the builder."""

from datetime import date
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from suckerpot_reporting import GuardContext
from suckerpot_reporting.forms import SCHEMA, Directory, validate

from ingest.abuse import forms
from ingest.abuse.build import DEMO_MAILBOX, DraftBuilder
from ingest.abuse.selfterms import TermsCache

from .test_abuse_integration import (
    DEMO,
    NOW,
    SELF_ADDR,
    Factory,
    Wire,
    _owner_wording,  # noqa: F401 - autouse: the owner set a reply contact
    add_self_address,
    builder,
    real_origins,
    real_sender,
    resolver,
    rows,
    scalar,
    seed_attack,
    smtp_profile,
)
from .test_abuse_integration import pytestmark as _marks

pytestmark = _marks

ENTRY = {
    "id": "example-abuse",
    "provider": "Example Abuse",
    "match": {"mailbox_domains": ["example.org"], "asns": [64496]},
    "official_domains": ["example.org"],
    "form_url": "https://www.example.org/abuse/report",
    "accepts_mail": False,
    "source": "https://www.example.org/legal/abuse",
    "verified_on": "2026-11-01",
}


def directory(*entries: dict[str, Any]) -> Directory:
    return validate({"schema": SCHEMA, "entries": list(entries)}, date(2026, 11, 22))


async def form_only_demo_recipient(engine: AsyncEngine, source: str = "manual") -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, source, form_only, form_source) "
                "VALUES (:m, 'rdap', true, :s)"
            ),
            {"m": DEMO_MAILBOX, "s": source},
        )


async def test_a_form_only_recipient_gets_a_weekly_form_report_and_no_mail(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    await form_only_demo_recipient(engine)
    await smtp_profile(engine, mode="auto", minute=0)
    stats = await builder(factory, DEMO).run(NOW, allow_lookups=False)
    assert stats.created == 1
    rep = (await rows(engine, "SELECT * FROM abuse_reports"))[0]
    assert (rep.kind, rep.channel, rep.status) == ("digest", "form", "draft")
    assert rep.week == forms.week_of(NOW) and rep.week.isoweekday() == 1
    assert rep.due_at is None
    assert rep.guard_ok is True, rep.guard_codes
    # The sender never schedules a form report, even in automatic mode and even once the flag
    # is gone (until the next build moves the draft back to mail).
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE abuse_reports DISABLE TRIGGER USER"))
        await conn.execute(text("UPDATE abuse_reports SET demo = false"))
        await conn.execute(text("ALTER TABLE abuse_reports ENABLE TRIGGER USER"))
        await conn.execute(text("UPDATE abuse_recipients SET form_only = false"))
    sender = real_sender(factory)
    await sender.run(NOW)
    assert await scalar(engine, "SELECT count(*) FROM abuse_send_requests") == 0


async def test_clearing_the_flag_moves_the_same_draft_back_to_mail(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    await form_only_demo_recipient(engine)
    b = builder(factory, DEMO)
    await b.run(NOW, allow_lookups=False)
    first = (await rows(engine, "SELECT id, channel FROM abuse_reports"))[0]
    assert first.channel == "form"
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_recipients SET form_only = false, form_source = 'cleared'")
        )
    await b.run(NOW, allow_lookups=False)
    again = await rows(engine, "SELECT id, channel, week FROM abuse_reports")
    assert len(again) == 1 and again[0].id == first.id
    assert (again[0].channel, again[0].week) == ("mail", None)


async def test_the_directory_routes_a_desk_before_any_mail(
    engine: AsyncEngine, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_origins(monkeypatch, set())
    lenient_kit(monkeypatch)
    monkeypatch.setattr(forms, "directory", lambda: directory(ENTRY))
    await seed_attack(engine, ip="203.0.113.70")
    await add_self_address(engine)
    b = DraftBuilder(factory, DEMO, TermsCache(factory, {}), resolver(factory, Wire(), DEMO))
    await b.run(NOW, allow_lookups=True)
    rec = (await rows(engine, "SELECT * FROM abuse_recipients"))[0]
    assert rec.mailbox == "abuse@example.org"
    assert (rec.form_only, rec.form_source, rec.form_entry) == (True, "directory", "example-abuse")
    rep = (await rows(engine, "SELECT channel, guard_ok, guard_codes FROM abuse_reports"))[0]
    assert rep.channel == "form" and rep.guard_ok, rep.guard_codes
    # The entry goes: the flag the directory set goes with it, and the draft is mail again.
    monkeypatch.setattr(forms, "directory", lambda: directory())
    await seed_attack(engine, ip="203.0.113.70", ago_h=2)
    await b.run(NOW, allow_lookups=True)
    rec = (await rows(engine, "SELECT * FROM abuse_recipients"))[0]
    assert (rec.form_only, rec.form_source, rec.form_entry) == (False, None, None)
    assert await scalar(engine, "SELECT channel FROM abuse_reports") == "mail"


async def test_the_directory_never_overrides_the_owner(
    engine: AsyncEngine, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_origins(monkeypatch, set())
    lenient_kit(monkeypatch)
    monkeypatch.setattr(forms, "directory", lambda: directory(ENTRY))
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, source, form_source) "
                "VALUES ('abuse@example.org', 'rdap', 'cleared')"
            )
        )
    await seed_attack(engine, ip="203.0.113.70")
    await add_self_address(engine)
    b = DraftBuilder(factory, DEMO, TermsCache(factory, {}), resolver(factory, Wire(), DEMO))
    await b.run(NOW, allow_lookups=True)
    assert await scalar(engine, "SELECT form_only FROM abuse_recipients") is False
    assert await scalar(engine, "SELECT channel FROM abuse_reports") == "mail"
    # A reply's or the owner's flag is never cleared by the directory sweep.
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_recipients SET form_only = true, form_source = 'reply'")
        )
    monkeypatch.setattr(forms, "directory", lambda: directory())
    await b.run(NOW, allow_lookups=True)
    assert await scalar(engine, "SELECT form_only FROM abuse_recipients") is True


async def test_a_name_that_gives_the_node_away_blocks_the_form_report(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    await form_only_demo_recipient(engine)
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE report_settings SET form_name = :n"), {"n": SELF_ADDR})
    await builder(factory, DEMO).run(NOW, allow_lookups=False)
    rep = (await rows(engine, "SELECT guard_ok, guard_codes FROM abuse_reports"))[0]
    assert rep.guard_ok is False and "self_address" in rep.guard_codes


async def test_a_report_that_left_the_draft_state_is_never_rewritten(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    await form_only_demo_recipient(engine)
    b = builder(factory, DEMO)
    await b.run(NOW, allow_lookups=False)
    rid = await scalar(engine, "SELECT id FROM abuse_reports")
    # As if the owner reviewed it between the build's read and its write.
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'reviewed', reviewed_by = 'owner' WHERE id = :i"
            ),
            {"i": rid},
        )
    async with factory() as session, session.begin():
        evidence, sha, ok, codes, redaction = await _same_content(engine, rid)
        changed = await b._update(
            session, rid, evidence, sha, ok, codes, redaction, None, "form", forms.week_of(NOW)
        )
    assert changed is False
    assert await scalar(engine, "SELECT count(*) FROM abuse_report_subjects") == 1


async def _same_content(engine: AsyncEngine, rid: int) -> tuple[Any, str, bool, Any, Any]:
    from suckerpot_reporting import Evidence

    row = (await rows(engine, "SELECT * FROM abuse_reports WHERE id = :i", i=rid))[0]
    evidence = Evidence.model_validate(row.evidence)
    return (evidence, row.content_sha256, row.guard_ok, tuple(row.guard_codes), row.redaction)


def lenient_kit(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixtures use documentation addresses, which the kit check would refuse."""
    from suckerpot_reporting.forms import guard_kit as check

    def lenient(kit: Any, terms: Any, *, ctx: Any = None, links: Any = ()) -> Any:
        ctx = GuardContext(internal_ids=ctx.internal_ids, allow_documentation=True)
        return check(kit, terms, ctx=ctx, links=links)

    monkeypatch.setattr("ingest.abuse.build.guard_kit", lenient)


async def test_the_recheck_covers_the_kit_of_a_form_report(
    engine: AsyncEngine, factory: Factory
) -> None:
    from ingest.abuse.reguard import DraftReguard

    await seed_attack(engine)
    await add_self_address(engine)
    await form_only_demo_recipient(engine)
    await builder(factory, DEMO).run(NOW, allow_lookups=False)
    assert await scalar(engine, "SELECT guard_ok FROM abuse_reports") is True
    # The owner's name for forms starts to give the node away (written past the API's check).
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE report_settings SET form_name = :n"), {"n": SELF_ADDR})
    cache = TermsCache(factory, {})
    terms = await cache.get()
    assert terms is not None
    stats = await DraftReguard(factory, DEMO, cache).run(terms)
    assert stats.blocked == 1
    codes = await scalar(engine, "SELECT guard_codes FROM abuse_reports")
    assert "self_address" in codes


async def test_only_a_verified_reply_marks_again_a_desk_the_owner_cleared(
    engine: AsyncEngine, factory: Factory
) -> None:
    from ingest.replies.desk import learn
    from ingest.replies.parse import ParsedReply

    await seed_attack(engine)
    await add_self_address(engine)
    await builder(factory, DEMO).run(NOW, allow_lookups=False)
    rid = await scalar(engine, "SELECT id FROM abuse_reports")
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE abuse_recipients SET form_source = 'cleared'"))
    reply = ParsedReply(body="Please submit your report using our web form.")

    async def mark(verified: bool) -> None:
        async with factory() as session, session.begin():
            await learn(
                session,
                reply,
                report_id=rid,
                verified=verified,
                outcome="rejected",
                rule_id="form-required",
            )

    await mark(False)
    row = (await rows(engine, "SELECT form_only, form_source FROM abuse_recipients"))[0]
    assert (row.form_only, row.form_source) == (False, "cleared")
    await mark(True)
    row = (await rows(engine, "SELECT form_only, form_source FROM abuse_recipients"))[0]
    assert (row.form_only, row.form_source) == (True, "reply")
    # Any other state keeps the old rule: an unverified matched reply marks the desk.
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_recipients SET form_only = false, form_source = 'directory'")
        )
    await mark(False)
    assert await scalar(engine, "SELECT form_only FROM abuse_recipients") is True
