"""Abuse reports (M22) against a real TimescaleDB: workflow, guard, exports and the bundle."""

import hashlib
import io
import json
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import pyzipper  # type: ignore[import-untyped]
from analytics_seed import Seed, api_engine, owner_engine
from argon2 import PasswordHasher
from sqlalchemy import text
from suckerpot_db import create_session_factory

import api.abuse_core as core
import api.auth as auth_mod
import api.samples as samples_mod
from api import abuse_exports
from api.auth import AuthSettings
from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
ORIGIN = "https://testserver"
NOW = datetime.now(UTC).replace(microsecond=0)
SELF = "203.0.113.77"
DEMO_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
LEAK_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
SENT_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
CLEAN = b"#!/bin/sh\necho clean sample\n"
DIRTY = b"#!/bin/sh\nwget http://" + SELF.encode() + b"/x\n"
CLEAN_SHA, DIRTY_SHA = hashlib.sha256(CLEAN).hexdigest(), hashlib.sha256(DIRTY).hexdigest()


def evidence(cmd: str) -> dict[str, Any]:
    ts = (NOW - timedelta(hours=2)).isoformat()
    return {
        "kind": "attack_source",
        "recipient": "abuse@example.net",
        "subjects": [
            {
                "type": "ip", "value": "198.51.100.23", "asn": 64500, "network": "EXAMPLE-NET",
                "country": "NL", "first_ts": ts, "last_ts": ts, "sessions": 1, "events": 3,
                "activities": [
                    {
                        "ts": ts, "src_ip": "198.51.100.23", "src_port": 41022, "dst_port": 22,
                        "protocol": "tcp", "service": "ssh", "action": "command", "text": cmd,
                    }
                ],
                "redaction": {"addresses_masked": 2, "lines_dropped": 1},
            }
        ],
        "window_start": ts,
        "window_end": ts,
    }  # fmt: skip


async def seed() -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE abuse_report_requests, abuse_report_subjects, abuse_reports, "
                "abuse_recipients, report_self_terms, report_settings, audit_log, "
                "enrichment_status, enrichment_quota, samples, sample_sources, fetch_targets, "
                "indicators, indicator_sessions, sample_links, campaigns RESTART IDENTITY CASCADE"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, source) VALUES ('abuse@example.net','rdap')"
            )
        )
        await conn.execute(
            text("INSERT INTO abuse_recipients (name, source) VALUES ('Waiting Net', 'rdap')")
        )
        await conn.execute(
            text(
                "INSERT INTO abuse_networks (kind, cidr, asn, name, source, fetched_at, "
                "expires_at, recipient_id) VALUES ('ip', '198.51.100.0/24', 64500, 'EXAMPLE-NET', "
                "'rdap', now(), now() + interval '1 day', 2)"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source, confirmed) "
                "VALUES ('address', :a, 'manual', true)"
            ),
            {"a": SELF},
        )
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source, distinct_sources) "
                "VALUES ('name', 'learned.example.net', 'learned', 4)"
            )
        )
        for pid, status, demo, cmd, kind in (
            (DEMO_ID, "draft", True, "uname -a", "attack_source"),
            (LEAK_ID, "draft", True, f"curl {SELF}", "payload_host"),
            (SENT_ID, "reviewed", False, "id", "c2"),
        ):
            await conn.execute(
                text(
                    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, "
                    "demo, window_start, window_end, subject_count, evidence, content_sha256, "
                    "guard_ok) VALUES (:p, gen_random_uuid(), 1, :k, :s, :d, "
                    ":t, :t, 1, CAST(:e AS jsonb), 'x', true)"
                ),
                {
                    "p": pid,
                    "k": kind,
                    "s": status,
                    "d": demo,
                    "t": NOW,
                    "e": json.dumps(evidence(cmd)),
                },
            )
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail) VALUES "
                "('abuse', '{\"enabled\": true}'), ('egress', '{\"open\": true}')"
            )
        )
        for sha, data in ((CLEAN_SHA, CLEAN), (DIRTY_SHA, DIRTY)):
            await conn.execute(
                text(
                    "INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen, stored, "
                    "analysis_status) VALUES (:s, :a, :b, :z, :t, :t, true, 'done')"
                ),
                {"s": sha, "a": hashlib.sha1(data).hexdigest(), "b": hashlib.md5(data).hexdigest(),  # noqa: S324
                 "z": len(data), "t": NOW},
            )  # fmt: skip

    s = Seed()
    s.session("camp-s1", "ssh", "198.51.100.23", NOW - timedelta(hours=2),
              [(0.0, "command", {"input": "id"})])  # fmt: skip
    async with owner_engine() as owner:
        await s.write(owner)


@pytest.fixture
async def client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)
    monkeypatch.setenv(samples_mod.QUARANTINE_ENV, str(tmp_path))
    monkeypatch.setenv("ABUSE_REPORTS_INCLUDE_DEMO", "true")
    abuse_exports._bundles.clear()
    core.invalidate_terms()
    for sha, data in ((CLEAN_SHA, CLEAN), (DIRTY_SHA, DIRTY)):
        d = tmp_path / sha[:2] / sha[2:4]
        d.mkdir(parents=True, exist_ok=True)
        (d / sha).write_bytes(data)
    await seed()
    engine = api_engine()
    settings = AuthSettings(password_hash=HASH, secret=b"k" * 40, rate_per_ip=100)
    app = create_app(create_session_factory(engine), enable_live=False, auth_settings=settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as c,
    ):
        r = await c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert r.status_code == 204
        c.headers.update({"Origin": ORIGIN, "X-CSRF-Token": c.cookies["__Host-sp_csrf"]})
        yield c
    await engine.dispose()


WORDING = {
    "reply_contact": "reports@example.org",
    "intro": "Own intro.",
    "outro": "Own outro.",
    "note": "Own note.",
    "subject_template": "Notice, {count} from {value}",
}


async def set_intro(client: httpx.AsyncClient, **extra: Any) -> None:
    r = await client.put("/api/v1/abuse/settings", json=settings_body(0, **WORDING, **extra))
    assert r.status_code == 200


def settings_body(revision: int, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "reply_contact": None, "signature": None, "intro": None, "outro": None,
        "note": None, "subject_template": None, "xarf_user_agent": None,
        "round_times": True, "default_tlp": "green",
        "default_options": {"defang": True, "include_usernames": True,
                            "include_reply_contact": True},
        "revision": revision,
    }  # fmt: skip
    return base | kw


async def test_list_detail_status_and_pagination(client: httpx.AsyncClient) -> None:
    page = (await client.get("/api/v1/abuse/reports", params={"limit": 2})).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    rest = (
        await client.get("/api/v1/abuse/reports", params={"cursor": page["next_cursor"]})
    ).json()
    assert len(rest["items"]) == 1
    assert (await client.get("/api/v1/abuse/reports", params={"cursor": "zz"})).status_code == 400
    st = (await client.get("/api/v1/abuse/status")).json()
    assert st["enabled"] and st["gate"] == "open" and st["self_address_known"]
    assert st["counts"]["draft"] == 2 and st["counts"]["reviewed"] == 1
    d = (await client.get(f"/api/v1/abuse/reports/{DEMO_ID}")).json()
    assert d["guard"] == {"ok": True, "codes": []}
    assert d["redaction"] == {"masked": 2, "removed": 1}
    assert d["missing"] == ["reply_contact"] and d["subjects"] == []
    assert d["recipient"]["mailbox"] == "abuse@example.net"


async def test_review_needs_a_reply_contact_and_a_current_revision(
    client: httpx.AsyncClient,
) -> None:
    url = f"/api/v1/abuse/reports/{DEMO_ID}/status"
    rev = (await client.get(f"/api/v1/abuse/reports/{DEMO_ID}")).json()["revision"]
    no_contact = await client.post(url, json={"to": "reviewed", "revision": rev})
    assert no_contact.status_code == 409 and no_contact.json()["code"] == "settings_incomplete"
    assert no_contact.json()["missing"] == ["reply_contact"]
    # the wording alone does not unlock it, and no wording is needed once the contact is set
    part = await client.put("/api/v1/abuse/settings", json=settings_body(0, intro="Own intro."))
    assert part.status_code == 200
    still = await client.post(url, json={"to": "reviewed", "revision": rev})
    assert still.json()["code"] == "settings_incomplete"
    assert still.json()["missing"] == ["reply_contact"]
    contact_only = settings_body(1, reply_contact="reports@example.org")
    put = await client.put("/api/v1/abuse/settings", json=contact_only)
    assert put.status_code == 200 and put.json()["revision"] == 2
    assert put.json()["intro"] is None
    stale = await client.post(url, json={"to": "reviewed", "revision": rev + 5})
    assert stale.json()["code"] == "revision_mismatch"
    bad = await client.post(url, json={"to": "closed", "revision": rev})
    assert bad.json()["code"] == "invalid_transition"
    ok = await client.post(url, json={"to": "reviewed", "revision": rev})
    assert ok.status_code == 200 and ok.json()["status"] == "reviewed"
    assert ok.json()["missing"] == []
    demo_sent = await client.post(url, json={"to": "sent", "revision": rev})
    assert demo_sent.json()["code"] == "demo_report"
    back = await client.post(url, json={"to": "draft", "revision": rev})
    assert back.json()["status"] == "draft"
    hist = (await client.get(f"/api/v1/abuse/reports/{DEMO_ID}")).json()["history"]
    assert [(h["from"], h["to"]) for h in hist] == [("draft", "reviewed"), ("reviewed", "draft")]
    # a blocked report cannot be reviewed
    leak_rev = (await client.get(f"/api/v1/abuse/reports/{LEAK_ID}")).json()["revision"]
    blocked = await client.post(
        f"/api/v1/abuse/reports/{LEAK_ID}/status", json={"to": "reviewed", "revision": leak_rev}
    )
    assert blocked.status_code == 409 and blocked.json()["code"] == "identity_guard_failed"
    # a real (non-demo) report that was reviewed can be marked sent, then closed
    sent_rev = (await client.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()["revision"]
    sent = await client.post(
        f"/api/v1/abuse/reports/{SENT_ID}/status", json={"to": "sent", "revision": sent_rev}
    )
    assert sent.status_code == 200 and sent.json()["sent_at"]
    closed = await client.post(
        f"/api/v1/abuse/reports/{SENT_ID}/status", json={"to": "closed", "revision": sent_rev}
    )
    assert closed.json()["status"] == "closed"


async def test_nothing_is_released_without_a_reply_contact(
    client: httpx.AsyncClient,
) -> None:
    def refused(r: httpx.Response) -> bool:
        return r.status_code == 409 and r.json()["code"] == "settings_incomplete"

    assert refused(await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/render"))
    assert refused(await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/download"))
    assert refused(await client.get("/api/v1/abuse/exports/stix", params={"report": str(DEMO_ID)}))
    assert refused(await client.get("/api/v1/abuse/exports/misp", params={"report": str(DEMO_ID)}))
    bundle = await client.post(
        "/api/v1/abuse/exports/samples", json={"sha256": [CLEAN_SHA], "password": PASSWORD}
    )
    assert refused(bundle)
    st = (await client.get("/api/v1/abuse/status")).json()
    assert st["self_address_fresh"] is True
    got = (await client.get("/api/v1/abuse/settings")).json()
    assert got["intro"] is None and got["outro"] is None and got["note"] is None
    miss = (await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/render")).json()["missing"]
    assert miss == ["reply_contact"]


async def test_render_and_download_are_guarded_with_codes_only(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    await set_intro(client)
    ok = await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/render", params={"format": "text"})
    assert ok.status_code == 200 and ok.headers["cache-control"] == "no-store"
    body = ok.json()
    assert body["to"] == "abuse@example.net" and body["guard"]["ok"]
    assert [a["name"] for a in body["attachments"]] == ["evidence.csv"]
    eml = await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/render", params={"format": "eml"})
    assert eml.status_code == 200 and "Notice, 1 from" in eml.json()["body"]
    xarf = await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/render", params={"format": "xarf"})
    assert xarf.status_code == 200 and xarf.json()["guard"]["ok"]
    # the wording fields are optional: with only the reply contact the plain neutral subject is used
    bare = await client.put(
        "/api/v1/abuse/settings", json=settings_body(1, reply_contact="reports@example.org")
    )
    assert bare.status_code == 200
    plain = await client.get(f"/api/v1/abuse/reports/{DEMO_ID}/render", params={"format": "text"})
    assert plain.status_code == 200 and plain.json()["guard"]["ok"]
    assert "Abuse report for " in plain.json()["subject"]
    with caplog.at_level("DEBUG"):
        for path in ("render", "download"):
            r = await client.get(f"/api/v1/abuse/reports/{LEAK_ID}/{path}")
            assert r.status_code == 409
            j = r.json()
            assert j["code"] == "identity_guard_failed" and "self_address" in j["reasons"]
            assert SELF not in r.text
    assert SELF not in caplog.text
    dl = await client.get(
        f"/api/v1/abuse/reports/{DEMO_ID}/download", params={"format": "evidence_csv"}
    )
    assert dl.status_code == 200 and dl.headers["content-disposition"].endswith('evidence.csv"')
    assert dl.headers["x-content-type-options"] == "nosniff"
    assert (await client.get(f"/api/v1/abuse/reports/{uuid.uuid4()}/render")).status_code == 404


async def test_settings_are_guarded_and_audit_has_no_values(client: httpx.AsyncClient) -> None:
    os.environ["API_ALLOWED_HOSTS"] = "dashboard.example.net"
    core.invalidate_terms()
    try:
        r = await client.put(
            "/api/v1/abuse/settings",
            json=settings_body(0, reply_contact="alias@dashboard.example.net"),
        )
    finally:
        del os.environ["API_ALLOWED_HOSTS"]
        core.invalidate_terms()
    assert r.status_code == 409 and r.json()["reasons"] == ["owner_domain"]
    assert "dashboard.example.net" not in r.text
    ok = await client.put(
        "/api/v1/abuse/settings", json=settings_body(0, reply_contact="alias@example.org")
    )
    assert ok.status_code == 200
    assert (await client.put("/api/v1/abuse/settings", json=settings_body(0))).status_code == 409
    async with owner_engine() as owner, owner.connect() as conn:
        rows = (
            await conn.execute(text("SELECT details FROM audit_log WHERE action='abuse.settings'"))
        ).all()
    assert rows and "example.org" not in str(rows)
    assert rows[0].details["changed"] == ["reply_contact"]


async def test_a_refused_save_names_the_fields_and_a_stored_text_is_flagged(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    named = "reports@honeypot.example.net"  # a reply address that names the project
    with caplog.at_level("DEBUG"):
        refused = await client.put(
            "/api/v1/abuse/settings",
            json=settings_body(
                0, reply_contact=named, intro="Please investigate and stop this activity."
            ),
        )
    assert refused.status_code == 409
    body = refused.json()
    assert body["code"] == "identity_guard_failed"
    assert body["fields"] == {"reply_contact": ["project_term"], "intro": ["default_wording"]}
    assert body["reasons"] == ["default_wording", "project_term"]
    for private in ("honeypot", "investigate"):
        assert private not in refused.text and private not in caplog.text
    # nothing was saved
    got = (await client.get("/api/v1/abuse/settings")).json()
    assert got["reply_contact"] is None and got["field_issues"] == {}

    # Text saved before a rule existed (or before the deny set grew) is flagged when it is read.
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO report_settings (id, reply_contact, revision) VALUES (1, :c, 3)"),
            {"c": named},
        )
    stored = (await client.get("/api/v1/abuse/settings")).json()
    assert stored["reply_contact"] == named
    assert stored["field_issues"] == {"reply_contact": ["project_term"]}
    # Saving other changes around it is refused too, until the address is neutral.
    same = await client.put("/api/v1/abuse/settings", json=settings_body(3, reply_contact=named))
    assert same.status_code == 409 and same.json()["fields"] == {"reply_contact": ["project_term"]}
    fixed = await client.put(
        "/api/v1/abuse/settings", json=settings_body(3, reply_contact="reports@example.org")
    )
    assert fixed.status_code == 200 and fixed.json()["field_issues"] == {}
    assert (await client.get("/api/v1/abuse/settings")).json()["field_issues"] == {}


async def test_status_counts_the_blocked_drafts_by_reason(client: httpx.AsyncClient) -> None:
    clear = (await client.get("/api/v1/abuse/status")).json()["blocked_drafts"]
    assert clear == {"count": 0, "reasons": {}}
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET guard_ok = false, "
                "guard_codes = '{project_term,self_name}' WHERE public_id = :p"
            ),
            {"p": DEMO_ID},
        )
        await conn.execute(
            text(
                "UPDATE abuse_reports SET guard_ok = false, guard_codes = '{project_term}' "
                "WHERE public_id = :p"
            ),
            {"p": LEAK_ID},
        )
        # a reviewed report is not a draft: it is not counted
        await conn.execute(
            text("UPDATE abuse_reports SET guard_ok = false WHERE public_id = :p"), {"p": SENT_ID}
        )
    blocked = (await client.get("/api/v1/abuse/status")).json()["blocked_drafts"]
    assert blocked == {"count": 2, "reasons": {"project_term": 2, "self_name": 1}}


async def test_the_live_check_keeps_what_the_build_found_in_a_draft(
    client: httpx.AsyncClient,
) -> None:
    await set_intro(client)
    detail = f"/api/v1/abuse/reports/{DEMO_ID}"
    assert (await client.get(detail)).json()["guard"] == {"ok": True, "codes": []}
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET guard_ok = false, guard_codes = '{internal_id}' "
                "WHERE public_id IN (:d, :s)"
            ),
            {"d": DEMO_ID, "s": SENT_ID},
        )
    # The live check cannot replay the build's reads, so it never clears an evidence code of a
    # draft: the owner cannot review it until a rebuild finds the evidence clean.
    held = (await client.get(detail)).json()
    assert held["guard"] == {"ok": False, "codes": ["internal_id"]}
    rev = held["revision"]
    review = await client.post(f"{detail}/status", json={"to": "reviewed", "revision": rev})
    assert review.status_code == 409 and review.json()["code"] == "identity_guard_failed"
    # A reviewed report is no draft: its live result stands, whatever was stored.
    reviewed = (await client.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()
    assert "internal_id" not in reviewed["guard"]["codes"]


async def test_a_payload_host_draft_knows_the_attacker_sessions_behind_it(
    client: httpx.AsyncClient,
) -> None:
    sid = "attacker-sess-0001"  # an internal id typed into the evidence by an attacker
    async with owner_engine() as owner, owner.begin() as conn:
        indicator = (
            await conn.execute(
                text(
                    "INSERT INTO indicators (type, value, role, host, first_seen, last_seen) "
                    "VALUES ('url', 'http://198.51.100.23/x.sh', 'download_host', "
                    "'198.51.100.23', :t, :t) RETURNING id"
                ),
                {"t": NOW - timedelta(hours=1)},
            )
        ).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO indicator_sessions (indicator_id, session_id, src_ip, sensor, "
                "seen_at) VALUES (:i, :s, '203.0.113.60', 'ssh', :t)"
            ),
            {"i": indicator, "s": sid, "t": NOW - timedelta(hours=1)},
        )
        await conn.execute(
            text("UPDATE abuse_reports SET evidence = CAST(:e AS jsonb) WHERE public_id = :p"),
            {"e": json.dumps(evidence(f"echo {sid}")), "p": LEAK_ID},
        )
    await set_intro(client)
    guard = (await client.get(f"/api/v1/abuse/reports/{LEAK_ID}")).json()["guard"]
    assert guard == {"ok": False, "codes": ["internal_id"]}


async def test_self_terms_recipients_and_regenerate(client: httpx.AsyncClient) -> None:
    listed = (await client.get("/api/v1/abuse/self-terms")).json()
    assert listed[0]["value"] == "203.0.•••.•••" and listed[0]["source"] == "manual"
    shown = (await client.get("/api/v1/abuse/self-terms", params={"reveal": "true"})).json()
    assert shown[0]["value"] == SELF
    added = await client.post(
        "/api/v1/abuse/self-terms", json={"kind": "name", "value": "Me.Example.NET"}
    )
    assert added.status_code == 201
    assert (
        await client.post(
            "/api/v1/abuse/self-terms", json={"kind": "name", "value": "me.example.net"}
        )
    ).status_code == 409
    assert (
        await client.post("/api/v1/abuse/self-terms", json={"kind": "address", "value": "x"})
    ).status_code == 422
    assert (
        await client.delete(f"/api/v1/abuse/self-terms/{added.json()['id']}")
    ).status_code == 204
    rec = await client.patch(
        "/api/v1/abuse/recipients/1", json={"override_mailbox": "Other@Example.org"}
    )
    assert rec.json()["override_mailbox"] == "other@example.org"
    waiting = (await client.get("/api/v1/abuse/recipients", params={"waiting": "true"})).json()
    assert [(w["id"], w["name"]) for w in waiting] == [(2, "Waiting Net")]
    st = (await client.get("/api/v1/abuse/status")).json()
    assert st["waiting_for_contact"] == 1
    typed = await client.patch(
        "/api/v1/abuse/recipients/2", json={"override_mailbox": "abuse@example.org"}
    )
    assert typed.json()["override_mailbox"] == "abuse@example.org"
    waiting = (await client.get("/api/v1/abuse/recipients", params={"waiting": "true"})).json()
    assert waiting == []
    r1 = await client.post(f"/api/v1/abuse/reports/{DEMO_ID}/regenerate")
    r2 = await client.post(f"/api/v1/abuse/reports/{DEMO_ID}/regenerate")
    assert r1.json() == {"requested": True, "already_pending": False}
    assert r2.json()["already_pending"] is True
    patched = await client.patch(f"/api/v1/abuse/reports/{DEMO_ID}", json={"notes": "n"})
    assert patched.json()["notes"] == "n"


async def test_exports_stix_misp_and_scope_rules(client: httpx.AsyncClient) -> None:
    await set_intro(client)
    since = (NOW - timedelta(days=1)).isoformat()
    stix = await client.get("/api/v1/abuse/exports/stix", params={"since": since, "tlp": "amber"})
    assert stix.status_code == 200 and stix.headers["content-type"].startswith("application/stix")
    doc = stix.json()
    assert doc["type"] == "bundle" and "created_by_ref" not in stix.text
    assert any(o.get("definition", {}).get("tlp") == "amber" for o in doc["objects"])
    misp = await client.get(
        "/api/v1/abuse/exports/misp", params={"report": str(DEMO_ID), "description": "Indicators"}
    )
    assert misp.status_code == 200 and misp.json()["Event"]["Attribute"]
    bare = await client.get("/api/v1/abuse/exports/misp", params={"report": str(DEMO_ID)})
    assert bare.status_code == 409 and bare.json()["missing"] == ["description"]
    assert (await client.get("/api/v1/abuse/exports/stix")).status_code == 422
    far = (NOW - timedelta(days=40)).isoformat()
    assert (
        await client.get("/api/v1/abuse/exports/stix", params={"since": far})
    ).status_code == 422
    leak = await client.get("/api/v1/abuse/exports/stix", params={"report": str(LEAK_ID)})
    assert SELF not in leak.text
    assert (
        await client.get("/api/v1/abuse/exports/stix", params={"campaign": 999})
    ).status_code == 404


async def test_sample_bundle_needs_the_password_and_leaves_out_a_leaky_sample(
    client: httpx.AsyncClient,
) -> None:
    await set_intro(client)
    url = "/api/v1/abuse/exports/samples"
    assert (await client.post(url, json={"sha256": [CLEAN_SHA]})).status_code == 401
    wrong = await client.post(url, json={"sha256": [CLEAN_SHA], "password": "nope"})
    assert wrong.json()["code"] == "reauth_failed"
    assert (
        await client.post(url, json={"sha256": ["1" * 64], "password": PASSWORD})
    ).status_code == 404
    r = await client.post(url, json={"sha256": [CLEAN_SHA, DIRTY_SHA], "password": PASSWORD})
    assert r.status_code == 200 and r.headers["x-excluded"] == "1"
    assert r.headers["x-excluded-samples"] == DIRTY_SHA
    with pyzipper.AESZipFile(io.BytesIO(r.content)) as zf:
        assert zf.namelist() == ["hashes.csv", f"{CLEAN_SHA}.bin"]
        assert zf.read(f"{CLEAN_SHA}.bin", pwd=b"infected") == CLEAN
        assert {i.date_time for i in zf.infolist()} == {(1980, 1, 1, 0, 0, 0)}
        assert zf.comment == b""
    only = await client.post(url, json={"sha256": [DIRTY_SHA], "password": PASSWORD})
    assert only.status_code == 409 and only.json()["code"] == "all_excluded"
    async with owner_engine() as owner, owner.connect() as conn:
        rows = (
            await conn.execute(text("SELECT details FROM audit_log WHERE target='samples'"))
        ).all()
    assert len(rows) == 2 and "infected" not in str(rows)
