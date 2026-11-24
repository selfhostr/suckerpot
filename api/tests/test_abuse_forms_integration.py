"""M38 P3 in the API against a real TimescaleDB: the form queue, the copy kit behind the identity
guard, the form links (directory and reply), "Submitted" with ticked sources, the owner's form
switch and the form name. Ingest's side is in ``ingest/tests/test_form_queue_integration.py``."""

# ruff: noqa: F811  (the imported `client` fixture is requested by name)
import json
import os
import uuid
from datetime import date, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from suckerpot_reporting import GuardContext
from suckerpot_reporting.forms import SCHEMA, validate
from test_abuse_integration import (
    NOW,
    SELF,
    WORDING,
    client,  # noqa: F401  (the seeded, signed-in client of the M22 tests)
    evidence,
    set_intro,
)

import api.abuse_forms as forms_mod

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

FORM_ID = uuid.UUID("88888888-8888-4888-8888-888888888888")
MONDAY = NOW.date() - timedelta(days=NOW.weekday())
SOURCES = ("198.51.100.23", "198.51.100.24")
REPLY_FORM = "https://support.example.net/form"


async def run(sql: str, **params: Any) -> Any:
    async with owner_engine() as owner, owner.begin() as conn:
        result = await conn.execute(text(sql), params)
        return result.all() if "RETURNING" in sql else None


@pytest.fixture
def lenient(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixtures use documentation addresses, which a real report would refuse."""
    from api.abuse_core import guard_context as real

    async def guard_context(db: Any, row: Any, ev: Any) -> GuardContext:
        ctx = await real(db, row, ev)
        return GuardContext(internal_ids=ctx.internal_ids, allow_documentation=True)

    monkeypatch.setattr(forms_mod, "guard_context", guard_context)


async def seed_form(*, cmd: str = "uname -a", demo: bool = False) -> int:
    """A form report of this week for recipient 1, two attack sources, the desk form-only."""
    ev = evidence(cmd)
    first = ev["subjects"][0] | {"kind": "attack_source"}
    second = json.loads(json.dumps(first)) | {"value": SOURCES[1], "xarf_id": str(uuid.uuid4())}
    second["activities"][0]["src_ip"] = SOURCES[1]
    ev["kind"] = "digest"
    ev["subjects"] = [first, second]
    await run(
        "UPDATE abuse_recipients SET form_only = true, form_source = 'reply', form_url = :u "
        "WHERE id = 1",
        u=REPLY_FORM,
    )
    rows = await run(
        "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, demo, "
        "window_start, window_end, subject_count, evidence, content_sha256, guard_ok, channel, "
        "week) VALUES (:p, gen_random_uuid(), 1, 'digest', 'draft', :d, :t, :t, 2, "
        "CAST(:e AS jsonb), 'x', true, 'form', :w) RETURNING id",
        p=FORM_ID,
        d=demo,
        t=NOW,
        e=json.dumps(ev),
        w=MONDAY,
    )
    report = int(rows[0][0])
    for value, sub in zip(SOURCES, ev["subjects"], strict=True):
        await run(
            "INSERT INTO abuse_report_subjects (report_id, kind, subject_type, value, first_ts, "
            "last_ts, sessions, events, xarf_id) VALUES (:r, 'attack_source', 'ip', :v, :f, :f, "
            "1, 3, CAST(:x AS uuid))",
            r=report,
            v=value,
            f=NOW - timedelta(hours=2),
            x=sub["xarf_id"],
        )
    return report


async def test_the_queue_lists_form_reports_only(client: httpx.AsyncClient) -> None:
    await set_intro(client)
    await seed_form()
    page = (await client.get("/api/v1/abuse/forms")).json()
    assert [i["public_id"] for i in page["items"]] == [str(FORM_ID)]
    item = page["items"][0]
    assert item["week"] == MONDAY.isoformat() and item["subject_count"] == 2
    assert (item["form_host"], item["form_origin"]) == ("support.example.net", "reply")
    assert item["recipient"]["form_source"] == "reply"
    # The To send queue leaves it out: it waits here.
    sends = (await client.get("/api/v1/abuse/send-queue")).json()["items"]
    assert str(FORM_ID) not in {s["id"] for s in sends}
    detail = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}")).json()
    assert detail["channel"] == "form" and detail["week"] == MONDAY.isoformat()


async def test_the_kit_has_every_field_and_the_fixed_warning(
    client: httpx.AsyncClient, lenient: None
) -> None:
    await set_intro(client, form_name="A. Volunteer")
    await seed_form()
    r = await client.get(f"/api/v1/abuse/reports/{FORM_ID}/kit")
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    kit = r.json()
    assert "VPN" in kit["warning"] and "Tor Browser" in kit["warning"]
    assert kit["email"] == WORDING["reply_contact"] and kit["name"] == "A. Volunteer"
    assert set(kit["addresses"].splitlines()) == set(SOURCES)
    token = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}")).json()["reply_token"]
    assert kit["description"].endswith(f"ref {token}")
    assert kit["evidence"]["name"] == "evidence.csv"
    assert [s["value"] for s in kit["sources"]] and len(kit["sources"]) == 2
    link = kit["links"][0]
    assert link == {
        "url": REPLY_FORM,
        "host": "support.example.net",
        "origin": "reply",
        "clickable": True,
        "checked_on": None,
        "stale": False,
    }
    blob = json.dumps(kit)
    assert SELF not in blob and "learned.example.net" not in blob


async def test_a_reply_link_off_the_provider_domain_is_text_only(
    client: httpx.AsyncClient, lenient: None
) -> None:
    await set_intro(client)
    await seed_form()
    for url in ("https://forms.example.org/x", "https://support.example.net/x?session=1"):
        await run("UPDATE abuse_recipients SET form_url = :u WHERE id = 1", u=url)
        kit = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}/kit")).json()
        assert kit["links"][0]["clickable"] is False, url


async def test_the_directory_link_comes_first_and_a_differing_reply_is_flagged(
    client: httpx.AsyncClient, lenient: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = {
        "id": "example-net",
        "provider": "Example Net",
        "match": {"mailbox_domains": ["example.net"]},
        "official_domains": ["example.net"],
        "form_url": "https://www.example.net/abuse",
        "accepts_mail": False,
        "max_chars": 300,
        "fields": [{"key": "abuse_type", "label": "Category", "choices": {"exploit": "Hack"}}],
        "source": "https://www.example.net/legal",
        "verified_on": "2026-11-01",
    }
    d = validate({"schema": SCHEMA, "entries": [entry]}, date(2026, 11, 22))
    monkeypatch.setattr(forms_mod, "directory", lambda: d)
    await set_intro(client)
    await seed_form()
    kit = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}/kit")).json()
    assert [x["origin"] for x in kit["links"]] == ["directory", "reply"]
    assert kit["links"][0]["checked_on"] == "2026-11-01" and kit["links"][0]["clickable"]
    assert kit["links_differ"] is True
    assert kit["labels"] == {"abuse_type": "Category"} and kit["max_chars"] == 300
    assert len(kit["description"]) <= 300


async def test_a_planted_self_term_blocks_the_kit(client: httpx.AsyncClient) -> None:
    await set_intro(client)
    await seed_form(cmd=f"curl http://{SELF}/x")
    r = await client.get(f"/api/v1/abuse/reports/{FORM_ID}/kit")
    assert r.status_code == 409 and r.json()["code"] == "identity_guard_failed"
    assert SELF not in r.text
    rev = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}")).json()["revision"]
    sub = await client.post(f"/api/v1/abuse/reports/{FORM_ID}/submitted", json={"revision": rev})
    assert sub.status_code == 409 and sub.json()["code"] == "identity_guard_failed"


async def test_submitted_marks_only_the_ticked_sources_sent(
    client: httpx.AsyncClient, lenient: None
) -> None:
    await set_intro(client)
    report = await seed_form()
    await run(
        "INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by) "
        "VALUES (:r, 'send', true, 'auto')",
        r=report,
    )
    rev = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}")).json()["revision"]
    url = f"/api/v1/abuse/reports/{FORM_ID}/submitted"
    none = await client.post(url, json={"revision": rev, "subjects": []})
    assert none.status_code == 422
    stray = {"kind": "attack_source", "subject_type": "ip", "value": "192.0.2.1"}
    assert (await client.post(url, json={"revision": rev, "subjects": [stray]})).status_code == 409
    tick = {"kind": "attack_source", "subject_type": "ip", "value": SOURCES[0]}
    r = await client.post(url, json={"revision": rev, "subjects": [tick]})
    assert r.status_code == 200, r.text
    assert (r.json()["submitted"], r.json()["left"]) == (1, 1)
    async with owner_engine() as owner, owner.connect() as conn:
        rep = (
            await conn.execute(
                text("SELECT status, sent_via, sent_at FROM abuse_reports WHERE id = :i"),
                {"i": report},
            )
        ).one()
        subs = (
            await conn.execute(
                text("SELECT value, submitted_at FROM abuse_report_subjects WHERE report_id = :i"),
                {"i": report},
            )
        ).all()
        queued = await conn.scalar(
            text("SELECT status FROM abuse_send_requests WHERE report_id = :i"), {"i": report}
        )
        audit = await conn.scalar(
            text("SELECT count(*) FROM audit_log WHERE action = 'abuse.form_submitted'")
        )
    assert (rep.status, rep.sent_via) == ("sent", "form") and rep.sent_at is not None
    assert [(s.value, s.submitted_at is not None) for s in subs] == [(SOURCES[0], True)]
    assert queued == "cancelled" and audit == 1
    # It counts as sent: the same-day rule of a mail to this provider sees it, the queue drops it.
    page = (await client.get("/api/v1/abuse/forms")).json()
    assert page["items"] == []
    again = await client.post(url, json={"revision": rev})
    assert again.status_code == 409


async def test_a_mail_report_is_never_submitted_by_form(client: httpx.AsyncClient) -> None:
    from test_abuse_integration import DEMO_ID

    await set_intro(client)
    rev = (await client.get(f"/api/v1/abuse/reports/{DEMO_ID}")).json()["revision"]
    r = await client.post(f"/api/v1/abuse/reports/{DEMO_ID}/submitted", json={"revision": rev})
    assert r.status_code == 409 and r.json()["code"] == "not_a_form_report"
    kit = await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/kit")
    assert kit.status_code == 409 and kit.json()["code"] == "not_a_form_report"


async def test_a_demo_form_report_cannot_be_submitted(
    client: httpx.AsyncClient, lenient: None
) -> None:
    await set_intro(client)
    await seed_form(demo=True)
    rev = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}")).json()["revision"]
    r = await client.post(f"/api/v1/abuse/reports/{FORM_ID}/submitted", json={"revision": rev})
    assert r.status_code == 409 and r.json()["code"] == "demo_report"


async def test_the_owner_switches_a_desk_to_its_form_and_back(client: httpx.AsyncClient) -> None:
    on = await client.patch("/api/v1/abuse/recipients/1", json={"form_only": True})
    assert on.status_code == 200
    assert (on.json()["form_only"], on.json()["form_source"]) == (True, "manual")
    off = await client.patch("/api/v1/abuse/recipients/1", json={"form_only": False})
    assert (off.json()["form_only"], off.json()["form_source"]) == (False, "cleared")


async def test_the_form_name_is_guarded_and_kept(client: httpx.AsyncClient) -> None:
    await set_intro(client, form_name="A. Volunteer")
    got = (await client.get("/api/v1/abuse/settings")).json()
    assert got["form_name"] == "A. Volunteer"
    body = {k: got[k] for k in ("reply_contact", "round_times", "default_tlp")}
    body |= {
        "default_options": got["default_options"],
        "revision": got["revision"],
        "form_name": SELF,
    }
    r = await client.put("/api/v1/abuse/settings", json=body)
    assert r.status_code == 409 and "form_name" in r.json()["fields"]
    # Omitted keeps the stored value.
    body.pop("form_name")
    kept = (await client.put("/api/v1/abuse/settings", json=body)).json()
    assert kept["form_name"] == "A. Volunteer"


async def test_the_recipient_panel_uses_the_kit_rule_for_a_reply_link(
    client: httpx.AsyncClient,
) -> None:
    await set_intro(client)
    await seed_form()
    cases = {
        REPLY_FORM: True,
        "https://support.example.net/form?ticket=T-4711&email=me@example.org": False,
        "https://support.example.net:8443/form": False,
        "https://forms.example.org/form": False,
    }
    for url, clickable in cases.items():
        await run("UPDATE abuse_recipients SET form_url = :u WHERE id = 1", u=url)
        detail = (await client.get(f"/api/v1/abuse/reports/{FORM_ID}")).json()
        assert detail["recipient"]["form_url_clickable"] is clickable, url
        listed = (await client.get("/api/v1/abuse/recipients")).json()["items"]
        row = next(r for r in listed if r["id"] == 1)
        assert row["form_url_clickable"] is clickable, url


async def test_a_desk_that_prefers_its_form_shows_the_link_as_a_hint(
    client: httpx.AsyncClient,
) -> None:
    await run(
        "UPDATE abuse_recipients SET form_only = false, form_preferred = true, form_url = :u "
        "WHERE id = 1",
        u=REPLY_FORM,
    )
    row = next(
        r for r in (await client.get("/api/v1/abuse/recipients")).json()["items"] if r["id"] == 1
    )
    assert (row["form_only"], row["form_preferred"]) == (False, True)
    assert row["form_url"] == REPLY_FORM and row["form_url_clickable"] is True
    # Clearing a form-only flag keeps the hint of a desk that also prefers its form.
    await run("UPDATE abuse_recipients SET form_only = true, form_source = 'reply' WHERE id = 1")
    off = (await client.patch("/api/v1/abuse/recipients/1", json={"form_only": False})).json()
    assert (off["form_only"], off["form_preferred"], off["form_url"]) == (
        False,
        True,
        REPLY_FORM,
    )
    # Without the hint, the link of a plain desk stays hidden.
    await run("UPDATE abuse_recipients SET form_preferred = false WHERE id = 1")
    row = next(
        r for r in (await client.get("/api/v1/abuse/recipients")).json()["items"] if r["id"] == 1
    )
    assert row["form_url"] is None and row["form_url_clickable"] is False


async def test_today_counts_the_form_queue(client: httpx.AsyncClient) -> None:
    # The rest of Today is cached for a minute; the count is not, so each change shows at once.
    body = (await client.get("/api/v1/today")).json()
    assert body["form_queue"] is None and "forms" not in {c["id"] for c in body["cards"]}
    report = await seed_form()
    body = (await client.get("/api/v1/today")).json()
    assert body["form_queue"] == {"reports": 1, "providers": 1}
    card = next(c for c in body["cards"] if c["id"] == "forms")
    assert card["sentence"].startswith("1 report to submit by web form, for 1 provider.")
    assert card["action"]["to"] == "/abuse?status=forms"
    # A report to a muted desk, or a submitted one, no longer waits.
    await run("UPDATE abuse_recipients SET muted = true WHERE id = 1")
    assert (await client.get("/api/v1/today")).json()["form_queue"] is None
    await run("UPDATE abuse_recipients SET muted = false WHERE id = 1")
    await run("UPDATE abuse_reports SET status = 'sent' WHERE id = :r", r=report)
    assert (await client.get("/api/v1/today")).json()["form_queue"] is None


async def test_a_demo_form_report_is_not_counted(client: httpx.AsyncClient) -> None:
    await seed_form(demo=True)
    body = (await client.get("/api/v1/today")).json()
    assert body["form_queue"] is None
