"""A complete daily digest as SMTP sends it (M38): golden bytes, MIME structure, the parts, every
JSON valid against the vendored XARF 4.2.0 schema, the guard, and the .eml/X-ARF tab equality.

No network, no database. Boundaries are the only random part of the message; they are replaced by
a fixed string before the golden comparison.
"""

from __future__ import annotations

import base64
import email
import email.message
import email.policy
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from suckerpot_netproto.enums import FAMILIES_V1
from suckerpot_reporting import (
    Activity,
    Evidence,
    GuardContext,
    ReportOptions,
    ReportSettings,
    SampleRef,
    SelfTermRow,
    Subject,
    guard,
    load_self_terms,
    render_eml,
    schema_errors,
)
from suckerpot_reporting.xarf import MALWARE_FAMILIES, SERVICE_TAGS

from ingest.abuse.build import render_mail
from ingest.abuse.ports import _SENSOR_SERVICE, _TABLE
from ingest.reportmail.outgoing import Profile, build_message, check_message, xarf_parts_valid

GOLDEN = Path(__file__).parent / "golden" / "digest.eml"
NOW = datetime(2026, 11, 21, 7, 42, tzinfo=UTC)
SELF = "203.0.113.77"
PROFILE = Profile(
    host="smtp.example.org",
    port=587,
    security="starttls",
    username="reporter",
    from_address="sender@mail.example.org",
    from_name="",
    mode="auto",
    auto_hold_minutes=60,
    daily_cap=20,
    password="pw-unit-test-0123456789",
    digest_minute=462,
)
SETTINGS = ReportSettings(reply_contact="reports@example.org", intro="Hello,")
TOKEN = "0a1b2c3d4e5f"  # gitleaks:allow (a sample reply token)
MESSAGE_ID = "<digest-golden@mail.example.org>"


def t(h: int, m: int) -> datetime:
    return datetime(2026, 11, 20, h, m, tzinfo=UTC)


def act(**kw: object) -> Activity:
    base: dict[str, object] = {
        "ts": t(8, 14),
        "src_ip": "198.51.100.23",
        "src_port": 41022,
        "dst_port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "action": "failed_logins",
        "count": 152,
    }
    base.update(kw)
    return Activity.model_validate(base)


def digest() -> Evidence:
    sample = SampleRef(sha256="ab" * 32, kind="elf", arch="arm", family="mirai")
    subjects = (
        Subject(
            type="ip",
            value="198.51.100.23",
            kind="attack_source",
            xarf_id=uuid.UUID("6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f601"),
            asn=64500,
            network="EXAMPLE-NET",
            first_ts=t(8, 14),
            last_ts=t(11, 2),
            sessions=4,
            events=152,
            activities=(act(),),
        ),
        Subject(
            type="ip",
            value="198.51.100.31",
            kind="attack_source",
            xarf_id=uuid.UUID("6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f602"),
            asn=64500,
            first_ts=t(9, 0),
            last_ts=t(9, 0),
            sessions=1,
            events=1,
            activities=(
                act(
                    ts=t(9, 0),
                    src_ip="198.51.100.31",
                    src_port=50111,
                    dst_port=80,
                    service="http",
                    action="exploit_attempt",
                    count=1,
                    text="GET /cgi-bin/luci",
                    user_agent="curl/8.0",
                    cves=("cve-2023-1389",),
                ),
            ),
        ),
        Subject(
            type="domain",
            value="files.example.org",
            kind="payload_host",
            xarf_id=uuid.UUID("6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f603"),
            first_ts=t(10, 5),
            last_ts=t(10, 5),
            sessions=1,
            events=1,
            activities=(
                act(
                    ts=t(10, 5),
                    action="download",
                    count=1,
                    text="http://files.example.org/bins/arm7",
                ),
            ),
            samples=(sample,),
        ),
        Subject(
            type="domain",
            value="c2.example.org",
            kind="c2",
            xarf_id=uuid.UUID("6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f604"),
            first_ts=t(10, 6),
            last_ts=t(10, 6),
            sessions=0,
            events=0,
            samples=(sample,),
        ),
    )
    return Evidence(
        kind="digest",
        recipient="abuse@example.net",
        subjects=subjects,
        window_start=t(8, 0),
        window_end=t(11, 2),
        options=ReportOptions(time_precision="minute"),
    )


def _payload(part: email.message.Message) -> bytes:
    data = part.get_payload(decode=True)
    assert isinstance(data, bytes)
    return data


def smtp_bytes() -> bytes:
    rendered = render_mail(digest(), SETTINGS, TOKEN, "subject")
    return build_message(PROFILE, rendered, now=NOW, message_id=MESSAGE_ID)


def normalized(raw: bytes) -> str:
    text = raw.decode("ascii")
    for boundary in set(re.findall(r'boundary="([^"]+)"', text)):
        text = text.replace(boundary, "BOUNDARY")
    return text


def test_digest_mail_golden() -> None:
    actual = normalized(smtp_bytes())
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_bytes(actual.encode("ascii"))
    assert actual.encode("ascii") == GOLDEN.read_bytes()


def test_digest_mime_structure_and_parts() -> None:
    msg = email.message_from_bytes(smtp_bytes(), policy=email.policy.SMTP)
    assert msg.get_content_type() == "multipart/mixed"
    assert "X-ARF" not in msg and "X-XARF" not in msg
    parts = list(msg.iter_parts())
    assert [p.get_content_type() for p in parts] == [
        "text/plain",
        "text/csv",
        "application/json",
        "application/json",
        "application/json",
        "application/json",
    ]
    assert [p.get_filename() for p in parts[1:]] == [
        "evidence.csv",
        "xarf-001.json",
        "xarf-002.json",
        "xarf-003.json",
        "xarf-004.json",
    ]
    for part in parts[2:]:
        assert part["Content-Transfer-Encoding"] == "base64"
        assert part.get_content_disposition() == "attachment"
    body = parts[0].get_content()
    assert "Attack sources (2)" in body and "Payload hosts (1)" in body
    assert "Command servers (1)" in body
    for name in ("xarf-001.json", "xarf-002.json", "xarf-003.json", "xarf-004.json"):
        assert f"Report file: {name}" in body
    assert TOKEN in msg["Subject"] and TOKEN not in body


def test_every_json_part_is_schema_valid_and_clean() -> None:
    raw = smtp_bytes()
    assert xarf_parts_valid(raw)
    msg = email.message_from_bytes(raw, policy=email.policy.SMTP)
    reports = [
        json.loads(_payload(p)) for p in msg.walk() if p.get_content_type() == "application/json"
    ]
    assert [(r["category"], r["type"]) for r in reports] == [
        ("connection", "login_attack"),
        ("connection", "vulnerability_scan"),
        ("content", "malware"),
        ("infrastructure", "botnet"),
    ]
    for report in reports:
        assert schema_errors(report) == []
        text = json.dumps(report)
        assert "destination_ip" not in text and "evidence_source" not in text
        assert "confidence" not in report and TOKEN not in text
        assert SELF not in text
    assert len({r["report_id"] for r in reports}) == 4


def test_a_tampered_json_part_fails_the_schema_check() -> None:
    raw = smtp_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.SMTP)
    part = next(p for p in msg.walk() if p.get_content_type() == "application/json")
    report = json.loads(_payload(part))
    report["destination_ip"] = SELF
    encoded = base64.b64encode(json.dumps(report).encode()).decode()
    original = part.get_payload()
    assert isinstance(original, str)
    assert not xarf_parts_valid(raw.replace(original.encode(), encoded.encode()))


def test_smtp_eml_and_tab_carry_the_same_json() -> None:
    rendered = render_mail(digest(), SETTINGS, TOKEN, "subject")
    tab = [a.content.encode("ascii") for a in rendered.xarf_files]
    sent = email.message_from_bytes(smtp_bytes(), policy=email.policy.SMTP)
    eml = email.message_from_bytes(render_eml(rendered), policy=email.policy.SMTP)
    for msg in (sent, eml):
        parts = [
            p.get_payload(decode=True)
            for p in msg.walk()
            if p.get_content_type() == "application/json"
        ]
        assert parts == tab


def test_the_digest_passes_the_complete_guard() -> None:
    terms = load_self_terms([SelfTermRow(kind="address", value=SELF, source="manual")], {})
    rendered = render_mail(digest(), SETTINGS, TOKEN, "subject")
    raw = smtp_bytes()
    ctx = GuardContext(allow_documentation=True)  # the fixture uses documentation ranges
    check_message(raw, PROFILE, "abuse@example.net", terms, ctx=ctx, rendered=rendered)
    assert guard(raw, terms, fmt="eml", ctx=ctx).ok
    assert guard(raw, terms, fmt="eml").codes == ("documentation_address",)


def test_one_source_is_spec_shaped() -> None:
    one = digest().model_copy(update={"subjects": digest().subjects[:1]})
    raw = build_message(
        PROFILE, render_mail(one, SETTINGS, TOKEN, "subject"), now=NOW, message_id=MESSAGE_ID
    )
    msg = email.message_from_bytes(raw, policy=email.policy.SMTP)
    assert msg.get_content_type() == "multipart/report"
    assert msg.get_param("report-type") == "feedback-report"
    assert [p.get_content_type() for p in msg.iter_parts()] == [
        "text/plain",
        "message/feedback-report",
        "application/json",
        "text/csv",
    ]
    assert xarf_parts_valid(raw)


def test_allow_lists_follow_the_protocol_and_the_ports() -> None:
    assert MALWARE_FAMILIES == FAMILIES_V1 - {"generic"}
    services = {v[2] for v in _TABLE.values()} | set(_SENSOR_SERVICE.values())
    assert services <= SERVICE_TAGS
