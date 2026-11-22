"""M38 P1 in the API against a real TimescaleDB: the X-ARF tab and download, digest rows and
subjects, the strict switch, the digest hour, the same-day confirmation, the X-ARF organisation
and outcomes per source. Ingest's side is in ``ingest/tests/test_digest_integration.py``."""

# ruff: noqa: F811  (the imported `client` fixture is requested by name)
import base64
import json
import os
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from suckerpot_reporting import schema_errors
from test_abuse_integration import (
    DEMO_ID,
    NOW,
    SELF,
    SENT_ID,
    WORDING,
    client,  # noqa: F401  (the seeded, signed-in client of the M22 tests)
    evidence,
    set_intro,
    settings_body,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

DIGEST_ID = uuid.UUID("66666666-6666-4666-8666-666666666666")
XARF_A = uuid.UUID("7a7a7a7a-0000-4000-8000-00000000000a")
XARF_B = uuid.UUID("7a7a7a7a-0000-4000-8000-00000000000b")


async def run(sql: str, **params: Any) -> Any:
    async with owner_engine() as owner, owner.begin() as conn:
        result = await conn.execute(text(sql), params)
        return result.all() if "RETURNING" in sql else None


async def seed_digest(*, status: str = "draft", demo: bool = True) -> int:
    """A demo digest with two sources of two kinds for recipient 1 (subject rows and ids)."""
    ev = evidence("uname -a")
    first = ev["subjects"][0] | {"kind": "attack_source", "xarf_id": str(XARF_A)}
    second = json.loads(json.dumps(first)) | {
        "kind": "payload_host",
        "type": "domain",
        "value": "files.example.org",
        "xarf_id": str(XARF_B),
    }
    ev["kind"] = "digest"
    ev["subjects"] = [first, second]
    rows = await run(
        "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, demo, "
        "window_start, window_end, subject_count, evidence, content_sha256, guard_ok, due_at, "
        "part) VALUES (:p, gen_random_uuid(), 1, 'digest', :s, :d, :t, :t, 2, "
        "CAST(:e AS jsonb), 'x', true, :due, 2) RETURNING id",
        p=DIGEST_ID,
        s=status,
        d=demo,
        t=NOW,
        e=json.dumps(ev),
        due=NOW + timedelta(hours=3),
    )
    report = int(rows[0][0])
    for kind, stype, value, xid in (
        ("attack_source", "ip", "198.51.100.23", XARF_A),
        ("payload_host", "domain", "files.example.org", XARF_B),
    ):
        await run(
            "INSERT INTO abuse_report_subjects (report_id, kind, subject_type, value, first_ts, "
            "last_ts, sessions, events, xarf_id) VALUES (:r, :k, :t, :v, :f, :f, 1, 3, :x)",
            r=report,
            k=kind,
            t=stype,
            v=value,
            f=NOW - timedelta(hours=2) if kind == "attack_source" else NOW - timedelta(days=9),
            x=xid,
        )
    return report


async def test_the_xarf_tab_lists_one_valid_json_per_source(client: httpx.AsyncClient) -> None:
    await set_intro(client)
    await seed_digest()
    r = await client.get(f"/api/v1/abuse/reports/{DIGEST_ID}/render", params={"format": "xarf"})
    assert r.status_code == 200, r.text
    files = r.json()["attachments"]
    assert [f["name"] for f in files] == ["xarf-001.json", "xarf-002.json"]
    assert {f["media_type"] for f in files} == {"application/json"}
    reports = [json.loads(f["content"]) for f in files]
    assert [x["report_id"] for x in reports] == [str(XARF_A), str(XARF_B)]
    assert [(x["category"], x["type"]) for x in reports] == [
        ("connection", "login_attack"),
        ("content", "malware"),
    ]
    for report in reports:
        assert schema_errors(report) == []
        assert "destination_ip" not in report and SELF not in json.dumps(report)
    # The .eml carries the same JSON bytes, base64 parts.
    eml = await client.get(f"/api/v1/abuse/reports/{DIGEST_ID}/render", params={"format": "eml"})
    body = eml.json()["body"]
    assert "multipart/mixed" in body and "xarf-002.json" in body
    for f in files:
        assert base64.b64encode(f["content"].encode()).decode()[:60] in body.replace("\r\n", "")


async def test_the_xarf_download_needs_a_source_when_there_are_several(
    client: httpx.AsyncClient,
) -> None:
    await set_intro(client)
    await seed_digest()
    url = f"/api/v1/abuse/reports/{DIGEST_ID}/download"
    many = await client.get(url, params={"format": "xarf_json"})
    assert many.status_code == 409 and many.json()["code"] == "xarf_subject_required"
    one = await client.get(url, params={"format": "xarf_json", "subject": "files.example.org"})
    assert one.status_code == 200 and one.headers["content-type"].startswith("application/json")
    assert 'filename="xarf-002.json"' in one.headers["content-disposition"]
    assert json.loads(one.content)["source_identifier"] == "files.example.org"
    single = await client.get(
        f"/api/v1/abuse/reports/{DEMO_ID}/download", params={"format": "xarf_json"}
    )
    assert (
        single.status_code == 200
        and 'filename="xarf.json"' in single.headers["content-disposition"]
    )
    gone = await client.get(url, params={"format": "xarf_yaml"})
    assert gone.status_code == 422


async def test_digest_rows_and_grouped_sources(client: httpx.AsyncClient) -> None:
    await set_intro(client)
    await seed_digest()
    page = (await client.get("/api/v1/abuse/reports", params={"kind": "payload_host"})).json()
    row = next(i for i in page["items"] if i["public_id"] == str(DIGEST_ID))
    assert row["kind"] == "digest" and row["part"] == 2 and row["channel"] == "mail"
    assert row["kinds"] == {"attack_source": 1, "payload_host": 1}
    assert row["due_at"] is not None
    d = (await client.get(f"/api/v1/abuse/reports/{DIGEST_ID}")).json()
    subs = {s["value"]: s for s in d["subjects"]}
    assert subs["198.51.100.23"]["kind"] == "attack_source"
    assert subs["198.51.100.23"]["xarf_file"] == "xarf-001.json"
    assert subs["files.example.org"]["xarf_file"] == "xarf-002.json"
    assert subs["198.51.100.23"]["stale"] is False
    assert subs["files.example.org"]["stale"] is True  # older than 7 days
    assert subs["198.51.100.23"]["xarf_id"] == str(XARF_A)  # administrators only


async def test_outcomes_per_source_come_from_verified_replies_still_linked(
    client: httpx.AsyncClient,
) -> None:
    await set_intro(client)
    report = await seed_digest(status="draft", demo=False)
    await run(
        "UPDATE abuse_reports SET status = 'reviewed', reviewed_at = now(), reviewed_by = 'o', "
        "reviewed_revision = revision WHERE id = :r",
        r=report,
    )
    await run(
        "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = 'o', "
        "sent_via = 'manual' WHERE id = :r",
        r=report,
    )
    replies = []
    for verified, outcome in ((True, "resolved"), (False, "rejected")):
        rows = await run(
            "INSERT INTO abuse_replies (source, received_at, report_id, match_method, verified, "
            "classification, size_bytes) VALUES ('paste', now(), :r, 'xarf_id', :v, :c, 1) "
            "RETURNING id",
            r=report,
            v=verified,
            c=outcome,
        )
        replies.append(int(rows[0][0]))
    for reply, value, kind, stype in (
        (replies[0], "198.51.100.23", "attack_source", "ip"),
        (replies[1], "files.example.org", "payload_host", "domain"),
    ):
        await run(
            "INSERT INTO abuse_subject_outcomes (report_id, kind, subject_type, value, reply_id, "
            "ticket_id) VALUES (:r, :k, :t, :v, :p, 'T-1')",
            r=report,
            k=kind,
            t=stype,
            v=value,
            p=reply,
        )
    d = (await client.get(f"/api/v1/abuse/reports/{DIGEST_ID}")).json()
    subs = {s["value"]: s for s in d["subjects"]}
    assert subs["198.51.100.23"]["outcome"] == "resolved"
    assert subs["198.51.100.23"]["ticket_id"] == "T-1"
    assert subs["files.example.org"]["outcome"] is None  # an unverified reply never counts
    assert subs["198.51.100.23"]["stale"] is False  # a sent report has nothing left to send
    # A reply the owner links to another report no longer speaks for this one.
    await run("UPDATE abuse_replies SET report_id = NULL WHERE id = :p", p=replies[0])
    d = (await client.get(f"/api/v1/abuse/reports/{DIGEST_ID}")).json()
    assert {s["value"]: s["outcome"] for s in d["subjects"]}["198.51.100.23"] is None


async def test_the_strict_switch_on_a_recipient(client: httpx.AsyncClient) -> None:
    on = await client.patch("/api/v1/abuse/recipients/1", json={"xarf_strict": True})
    assert on.status_code == 200 and on.json()["xarf_strict"] is True
    listed = (await client.get("/api/v1/abuse/recipients")).json()["items"]
    assert next(r for r in listed if r["id"] == 1)["xarf_strict"] is True
    off = await client.patch("/api/v1/abuse/recipients/1", json={"xarf_strict": False})
    assert off.json()["xarf_strict"] is False


async def test_the_digest_switch_and_hour(client: httpx.AsyncClient) -> None:
    await run("DELETE FROM report_smtp")
    got = (await client.get("/api/v1/abuse/digest")).json()
    assert got == {"enabled": True, "minute": None}
    refused = await client.put("/api/v1/abuse/digest", json={"enabled": True, "minute": 600})
    assert refused.status_code == 409 and refused.json()["code"] == "smtp_not_configured"
    off = await client.put("/api/v1/abuse/digest", json={"enabled": False})
    assert off.status_code == 200 and off.json()["enabled"] is False
    settings = (await client.get("/api/v1/abuse/settings")).json()
    assert settings["digest_enabled"] is False
    await run(
        "INSERT INTO report_smtp (id, host, port, security, from_address) "
        "VALUES (1, 'smtp.example.org', 587, 'starttls', 'sender@mail.example.org')"
    )
    first = (await client.get("/api/v1/abuse/digest")).json()["minute"]
    assert 360 <= first < 540  # random between 06:00 and 09:00 UTC
    moved = await client.put("/api/v1/abuse/digest", json={"enabled": True, "minute": 1200})
    assert moved.json() == {"enabled": True, "minute": 1200}
    bad = await client.put("/api/v1/abuse/digest", json={"enabled": True, "minute": 1440})
    assert bad.status_code == 422
    async with owner_engine() as owner, owner.connect() as conn:
        actions = (
            (
                await conn.execute(
                    text("SELECT details FROM audit_log WHERE action = 'abuse.digest'")
                )
            )
            .scalars()
            .all()
        )
    assert actions and all("1200" not in json.dumps(a) for a in actions)


async def test_a_second_send_by_hand_on_the_same_day_needs_a_confirmation(
    client: httpx.AsyncClient,
) -> None:
    await set_intro(client)
    # Recipient 1 already got a report today (marked sent by hand).
    await run(
        "UPDATE abuse_reports SET reviewed_at = now(), reviewed_by = 'o', "
        "reviewed_revision = revision WHERE public_id = :p",
        p=SENT_ID,
    )
    d = (await client.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()
    first = await client.post(
        f"/api/v1/abuse/reports/{SENT_ID}/status", json={"to": "sent", "revision": d["revision"]}
    )
    assert first.status_code == 200, first.text
    report = await seed_digest(status="draft", demo=False)
    await run(
        "UPDATE abuse_reports SET status = 'reviewed', reviewed_at = now(), reviewed_by = 'o', "
        "reviewed_revision = revision WHERE id = :r",
        r=report,
    )
    d = (await client.get(f"/api/v1/abuse/reports/{DIGEST_ID}")).json()
    url = f"/api/v1/abuse/reports/{DIGEST_ID}/status"
    second = await client.post(url, json={"to": "sent", "revision": d["revision"]})
    assert second.status_code == 409 and second.json()["code"] == "recipient_sent_today"
    assert second.json()["detail"] == "This provider already got a report today."
    confirmed = await client.post(
        url, json={"to": "sent", "revision": d["revision"], "confirm_same_day": True}
    )
    assert confirmed.status_code == 200 and confirmed.json()["status"] == "sent"


async def test_the_xarf_org_setting_is_guarded_and_used(client: httpx.AsyncClient) -> None:
    body = settings_body(0, **(WORDING | {"reply_contact": "reports@example.org"}))
    refused = await client.put("/api/v1/abuse/settings", json=body | {"xarf_org": "Honeypot Watch"})
    assert refused.status_code == 409 and "xarf_org" in refused.json()["fields"]
    saved = await client.put("/api/v1/abuse/settings", json=body | {"xarf_org": "Example Watch"})
    assert saved.status_code == 200 and saved.json()["xarf_org"] == "Example Watch"
    await seed_digest()
    r = await client.get(f"/api/v1/abuse/reports/{DIGEST_ID}/render", params={"format": "xarf"})
    report = json.loads(r.json()["attachments"][0]["content"])
    assert report["reporter"]["org"] == "Example Watch"
    assert report["reporter"]["domain"] == "example.org"
