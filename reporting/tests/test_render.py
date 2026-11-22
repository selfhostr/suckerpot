"""Renderer golden tests and structural checks."""

from __future__ import annotations

import base64
import email
import email.policy
import hashlib
import json
import os
import uuid
from typing import Any

import pytest

from suckerpot_reporting import (
    DEFAULT_SUBJECT,
    DEFAULT_XARF_USER_AGENT,
    RenderUnavailable,
    ReportOptions,
    ReportSettings,
    export_from_evidence,
    missing_settings,
    new_boundary,
    render_csv,
    render_eml,
    render_mail,
    render_misp,
    render_stix,
    render_text,
    schema_errors,
    stix_dumps,
)
from tests.conftest import (
    EXPORT_ID,
    GOLDEN,
    SEED,
    SETTINGS,
    XARF_ID,
    make_evidence,
    make_export,
    t,
)


def golden(name: str, actual: str) -> None:
    path = GOLDEN / name
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(actual.encode("ascii"))
    assert actual.encode("ascii") == path.read_bytes(), f"golden mismatch: {name}"


def test_text_golden() -> None:
    golden("report.txt", render_text(make_evidence(), SETTINGS).body)


def test_text_minute_precision_and_options() -> None:
    ev = make_evidence(options=ReportOptions(defang=False, include_usernames=False))
    body = render_text(ev, SETTINGS).body
    assert "2026-10-30T15:39Z Commands" in body
    assert "http://203.0.113.9/bins/x86" in body
    assert "users:" not in body


def test_only_the_reply_contact_is_required() -> None:
    assert missing_settings(None) == ("reply_contact",)
    assert missing_settings(ReportSettings()) == ("reply_contact",)
    assert missing_settings(ReportSettings(), xarf=True) == ("reply_contact",)
    assert missing_settings(ReportSettings(reply_contact=" ")) == ("reply_contact",)
    assert missing_settings(ReportSettings(reply_contact="reports@example.org")) == ()
    with pytest.raises(RenderUnavailable) as exc:
        render_text(make_evidence())
    assert exc.value.code == "settings_incomplete"
    with pytest.raises(RenderUnavailable):
        render_text(make_evidence(), SETTINGS.model_copy(update={"reply_contact": None}))
    with pytest.raises(RenderUnavailable):
        render_mail(make_evidence(), SETTINGS.model_copy(update={"reply_contact": None}))
    # every other field is optional
    for field in ("intro", "outro", "note", "signature", "subject_template", "xarf_user_agent"):
        assert render_text(make_evidence(), SETTINGS.model_copy(update={field: " "})).body


BARE = ReportSettings(reply_contact="reports@example.org")


def test_text_with_every_optional_field_empty_has_no_blank_sections() -> None:
    msg = render_text(make_evidence(), BARE)
    assert msg.subject == "Abuse report for 198.51.100.23"
    body = msg.body
    assert body.endswith("Contact: reports@example.org\n")
    assert not body.startswith("\n") and "\n\n\n" not in body
    assert body.splitlines()[0].startswith("198.51.100.23")
    # no wording survives from the filled-in settings
    for text in ("Hello", "Please look", "Times are UTC", "Regards"):
        assert text not in body
    # same without the contact line when the owner switched it off
    ev = make_evidence(options=ReportOptions(time_precision="second", include_reply_contact=False))
    plain = render_text(ev, BARE).body
    assert "Contact:" not in plain and not plain.endswith("\n\n") and "\n\n\n" not in plain


def test_optional_parts_are_dropped_one_by_one() -> None:
    for field, text in (
        ("intro", "Hello,"),
        ("outro", "Please look into it."),
        ("note", "Times are UTC."),
        ("signature", "Regards, a network volunteer"),
    ):
        body = render_text(make_evidence(), SETTINGS.model_copy(update={field: None})).body
        assert text not in body
        assert "\n\n\n" not in body and not body.startswith("\n")


def test_default_subject_is_neutral_and_data_only() -> None:
    assert DEFAULT_SUBJECT == "Abuse report for {value}"
    for blank in (None, "", "  "):
        cfg = SETTINGS.model_copy(update={"subject_template": blank})
        assert render_text(make_evidence(), cfg).subject == "Abuse report for 198.51.100.23"
    demo = render_text(make_evidence(demo=True), BARE).subject
    assert demo == "DEMO, DO NOT SEND: Abuse report for 198.51.100.23"
    # the set template keeps winning
    assert render_text(make_evidence(), SETTINGS).subject == "Attack from 198.51.100.23 (AS64500)"
    lowered = (DEFAULT_SUBJECT + DEFAULT_XARF_USER_AGENT).casefold()
    assert "suckerpot" not in lowered and "honeypot" not in lowered


def test_mail_with_every_optional_field_empty_is_valid() -> None:
    msg = render_mail(make_evidence(), BARE)
    assert msg.layout == "report"
    assert msg.feedback == "Feedback-Type: xarf\nUser-Agent: Mozilla/5.0\nVersion: 1\n"
    data = json.loads(msg.attachments[0].content)
    assert data["reporter"] == {
        "org": "example.org",
        "contact": "reports@example.org",
        "domain": "example.org",
    }
    assert data["sender"] == data["reporter"]
    assert data["source_identifier"] == "198.51.100.23"
    assert msg.subject == "Abuse report for 198.51.100.23"
    assert "\n\n\n" not in msg.body
    eml = render_eml(msg, boundary="===============1234567890123456789==").decode("ascii")
    parsed = email.message_from_string(eml)
    assert parsed["Subject"] == "Abuse report for 198.51.100.23" and parsed["X-ARF"] is None
    assert parsed.get_content_type() == "multipart/report"
    assert parsed.get_param("report-type") == "feedback-report"
    assert [p.get_filename() for p in parsed.walk() if p.get_filename()] == [
        "xarf.json",
        "evidence.csv",
    ]


def test_digest_mail_with_every_optional_field_empty() -> None:
    ev = make_evidence()
    two = ev.model_copy(
        update={
            "subjects": (
                ev.subjects[0],
                ev.subjects[0].model_copy(
                    update={"value": "198.51.100.24", "xarf_id": uuid.uuid4()}
                ),
            )
        }
    )
    msg = render_mail(two, BARE)
    assert msg.layout == "digest" and msg.feedback is None
    assert [a.name for a in msg.attachments] == ["evidence.csv", "xarf-001.json", "xarf-002.json"]
    eml = render_eml(msg).decode("ascii")
    parsed = email.message_from_string(eml)
    assert parsed["Subject"] == "Abuse report for 198.51.100.23"
    assert parsed.get_content_type() == "multipart/mixed"
    plain = render_eml(render_text(ev, BARE)).decode("ascii")
    assert str(email.message_from_string(plain).get_payload()).startswith("198.51.100.23")


def test_demo_marking() -> None:
    msg = render_text(make_evidence(demo=True), SETTINGS)
    assert msg.subject.startswith("DEMO, DO NOT SEND: ")
    assert msg.body.startswith("DEMO DATA: DO NOT SEND")


def test_redaction_counts_line_is_opt_in() -> None:
    assert "lines removed" not in render_text(make_evidence(), SETTINGS).body
    assert "line removed" not in render_text(make_evidence(), SETTINGS).body
    on = make_evidence(options=ReportOptions(time_precision="second", show_redaction_counts=True))
    assert "(1 line removed, 2 addresses masked)" in render_text(on, SETTINGS).body


def test_subject_template_placeholders() -> None:
    cfg = SETTINGS.model_copy(
        update={"subject_template": "{count} from {value} {asn} {network} {date}"}
    )
    assert (
        render_text(make_evidence(), cfg).subject
        == "1 from 198.51.100.23 AS64500 EXAMPLE-NET 2026-10-30"
    )


def test_subject_line_is_single_bounded_line() -> None:
    msg = render_text(make_evidence(), SETTINGS)
    assert "\n" not in msg.subject and len(msg.subject) <= 150


def test_csv_golden_and_formula_guard() -> None:
    golden("evidence.csv", render_csv(make_evidence()).content)
    ev = make_evidence()
    evil = ev.subjects[0].model_copy(update={"network": "=cmd|' /C calc'!A0"})
    csv_text = render_csv(ev.model_copy(update={"subjects": (evil,)})).content
    assert ",'=cmd" in csv_text


def test_xarf_golden_and_schema_valid() -> None:
    msg = render_mail(make_evidence(), SETTINGS)
    assert msg.layout == "report"
    assert [a.name for a in msg.attachments] == ["xarf.json", "evidence.csv"]
    assert [a.media_type for a in msg.attachments] == ["application/json", "text/csv"]
    golden("xarf.json", msg.attachments[0].content)
    data = json.loads(msg.attachments[0].content)
    assert schema_errors(data) == []
    assert data["xarf_version"] == "4.2.0"
    assert data["category"] == "connection" and data["type"] == "login_attack"
    assert data["report_id"] == str(XARF_ID)
    assert data["source_port"] == 41022 and data["destination_port"] == 22
    assert data["protocol"] == "tcp"
    assert data["first_seen"] == "2026-10-30T14:02:11Z"
    assert data["tags"] == ["service:ssh"]
    assert "destination_ip" not in data and "evidence_source" not in data
    assert "confidence" not in data
    item = data["evidence"][0]
    csv_rows = base64.b64decode(item["payload"]).decode("ascii")
    assert csv_rows.startswith("source,asn,network,")
    assert item["hash"] == "sha256:" + hashlib.sha256(csv_rows.encode()).hexdigest()
    assert item["content_type"] == "text/csv" and item["size"] == len(csv_rows)
    assert msg.feedback is not None and "User-Agent: reporter/1.0" in msg.feedback


def test_mail_requires_reply_contact_as_a_mailbox() -> None:
    with pytest.raises(RenderUnavailable):
        render_mail(make_evidence(), ReportSettings(intro="x"))
    with pytest.raises(RenderUnavailable):
        render_mail(make_evidence(), SETTINGS.model_copy(update={"reply_contact": None}))
    with pytest.raises(RenderUnavailable) as exc:
        render_mail(make_evidence(), SETTINGS.model_copy(update={"reply_contact": "call us"}))
    assert exc.value.code == "reply_contact_not_email"
    named = SETTINGS.model_copy(update={"reply_contact": "Desk <desk@example.org>"})
    data = json.loads(render_mail(make_evidence(), named).attachments[0].content)
    assert data["reporter"]["contact"] == "desk@example.org"


def test_xarf_org_setting() -> None:
    cfg = SETTINGS.model_copy(update={"xarf_org": "Example Volunteers"})
    data = json.loads(render_mail(make_evidence(), cfg).attachments[0].content)
    assert data["reporter"]["org"] == "Example Volunteers"
    assert data["reporter"]["domain"] == "example.org"


def test_digest_names_each_file_in_the_text() -> None:
    ev = make_evidence()
    second = ev.subjects[0].model_copy(update={"value": "198.51.100.24", "xarf_id": uuid.uuid4()})
    msg = render_mail(ev.model_copy(update={"subjects": (ev.subjects[0], second)}), SETTINGS)
    assert msg.layout == "digest"
    assert "  Report file: xarf-001.json" in msg.body
    assert "  Report file: xarf-002.json" in msg.body
    sources = [json.loads(a.content)["source_identifier"] for a in msg.xarf_files]
    assert sources == ["198.51.100.23", "198.51.100.24"]
    assert msg.subject.startswith("Attack from 198.51.100.23")


def test_xarf_id_is_required() -> None:
    ev = make_evidence()
    bare = ev.subjects[0].model_copy(update={"xarf_id": None})
    with pytest.raises(RenderUnavailable) as exc:
        render_mail(ev.model_copy(update={"subjects": (bare,)}), SETTINGS)
    assert exc.value.code == "xarf_id_missing"


def test_eml_golden_and_headers() -> None:
    raw = render_eml(
        render_mail(make_evidence(), SETTINGS), boundary="===============1234567890123456789=="
    )
    golden("report.eml", raw.decode("ascii"))
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert parsed["To"] == "abuse@example.net" and parsed["X-ARF"] is None
    for forbidden in ("From", "Date", "Message-ID", "User-Agent", "X-Mailer", "Reply-To"):
        assert parsed[forbidden] is None
    kinds = [p.get_content_type() for p in parsed.iter_parts()]
    assert kinds == ["text/plain", "message/feedback-report", "application/json", "text/csv"]
    json_part = next(p for p in parsed.iter_parts() if p.get_content_type() == "application/json")
    assert json_part["Content-Transfer-Encoding"] == "base64"
    plain = email.message_from_bytes(render_eml(render_text(make_evidence(), SETTINGS)))
    assert plain["X-ARF"] is None and not plain.is_multipart()
    assert b"\r\n" in raw and raw.isascii()


def test_eml_boundary_is_random_and_standard() -> None:
    import re

    msg = render_mail(make_evidence(), SETTINGS)
    a, b = new_boundary(), new_boundary()
    assert a != b and re.fullmatch(r"={15}\d{19}==", a)
    assert render_eml(msg) != render_eml(msg)
    assert b"=_" not in render_eml(msg)


def test_eml_rejects_header_injection() -> None:
    msg = render_text(make_evidence(), SETTINGS)
    bad = type(msg)(to="a@example.net\r\nBcc: x@example.net", subject=msg.subject, body=msg.body)
    with pytest.raises(RenderUnavailable):
        render_eml(bad)
    sub = type(msg)(to=msg.to, subject="a\r\nBcc: x@example.net", body="b")
    assert b"\r\nBcc:" not in render_eml(sub)


# --- STIX / MISP -------------------------------------------------------------------------


def _walk(node: Any) -> Any:
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def test_stix_golden_and_valid() -> None:
    bundle = render_stix(make_export())
    golden("indicators.stix.json", stix_dumps(bundle))
    # stix2-validator ships without its 2.1 schemas on PyPI, so the OASIS library does the
    # structural check: it rejects missing properties, bad ids and custom (x_) properties.
    import stix2

    parsed = stix2.parse(bundle, allow_custom=False, version="2.1")
    assert parsed["type"] == "bundle" and len(parsed["objects"]) == len(bundle["objects"])
    types = {o["type"] for o in bundle["objects"]}
    assert "identity" not in types
    assert {
        "indicator",
        "malware",
        "relationship",
        "attack-pattern",
        "marking-definition",
        "campaign",
        "ipv4-addr",
        "url",
        "domain-name",
        "file",
    } <= types
    keys = set(_walk(bundle))
    assert "created_by_ref" not in keys and not [k for k in keys if str(k).startswith("x_")]
    text = stix_dumps(bundle)
    assert "monitored system" not in text and "Observed" not in text
    assert "campaign-17" not in text  # internal cluster key never exported
    assert any(o.get("name", "").startswith("Activity cluster ") for o in bundle["objects"])


def test_stix_ids_stable_per_seed_and_unlinkable() -> None:
    a = render_stix(make_export())
    b = render_stix(make_export())
    assert a == b
    other = make_export().model_copy(update={"id_seed": EXPORT_ID})
    ids_a = {o["id"] for o in a["objects"] if o["type"] != "marking-definition"}
    ids_b = {o["id"] for o in render_stix(other)["objects"] if o["type"] != "marking-definition"}
    assert ids_a.isdisjoint(ids_b)
    assert str(SEED) not in stix_dumps(a)


@pytest.mark.parametrize("tlp", ["clear", "green", "amber", "red"])
def test_stix_tlp_markings(tlp: str) -> None:
    bundle = render_stix(make_export(tlp=tlp))
    mark = bundle["objects"][0]
    assert mark["type"] == "marking-definition" and mark["definition_type"] == "tlp"
    assert all(
        mark["id"] in o["object_marking_refs"]
        for o in bundle["objects"][1:]
        if "object_marking_refs" in o
    )


def test_misp_needs_owner_description_and_stix_has_no_default() -> None:
    bare = make_export().model_copy(update={"description": ""})
    with pytest.raises(RenderUnavailable):
        render_misp(bare)
    assert all("description" not in o for o in render_stix(bare)["objects"])


def test_misp_golden_and_structure() -> None:
    event = render_misp(make_export())
    golden("indicators.misp.json", json.dumps(event, indent=2) + "\n")
    ev = event["Event"]
    assert set(ev) == {
        "uuid",
        "info",
        "date",
        "threat_level_id",
        "analysis",
        "distribution",
        "published",
        "timestamp",
        "Tag",
        "Attribute",
    }
    assert ev["published"] is False and ev["distribution"] == "0" and ev["analysis"] == "2"
    assert {"name": "tlp:green"} in ev["Tag"]
    for forbidden in ("Org", "Orgc", "event_creator_email", "sharing_group", "SharingGroup"):
        assert forbidden not in ev
    types = {a["type"] for a in ev["Attribute"]}
    assert {"ip-src", "url", "domain", "sha256", "sha1", "md5"} <= types
    for attr in ev["Attribute"]:
        assert {
            "uuid",
            "type",
            "category",
            "value",
            "to_ids",
            "first_seen",
            "last_seen",
        } <= attr.keys()
        assert attr["to_ids"] is True
    assert len({a["uuid"] for a in ev["Attribute"]}) == len(ev["Attribute"])
    assert "campaign-17" not in json.dumps(event)


def test_export_from_evidence() -> None:
    data = export_from_evidence(
        make_evidence(), export_id=EXPORT_ID, id_seed=SEED, created=t(18, 0, day=31)
    )
    assert data.items[0].role == "attack_source" and data.items[0].value == "198.51.100.23"
    bundle = render_stix(data)
    assert any(o["type"] == "indicator" for o in bundle["objects"])
