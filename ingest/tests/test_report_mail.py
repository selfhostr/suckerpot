"""Outgoing abuse mail (M25), unit level: no network, no database.

The SMTP client is a fake that records what it is asked to do. Three owner requirements are
proved here: nothing is attempted while the egress gate is closed (not even a socket), the
complete message passes the identity guard (and fails closed without a known self address), and
the headers are neutral.
"""

from __future__ import annotations

import base64
import email
import email.policy
import smtplib
import socket
import ssl
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml
from suckerpot_egress import EgressGate, EgressSettings
from suckerpot_reporting import (
    Attachment,
    GuardContext,
    RenderedMessage,
    SelfTermRow,
    SelfTerms,
    load_self_terms,
)

from ingest.mailname import sender_domain
from ingest.reportmail import outgoing
from ingest.reportmail.outgoing import (
    Profile,
    SendFailure,
    build_message,
    build_test_message,
    check_message,
    deliver,
)

from .helpers import fake_gate

SELF = "203.0.113.77"
OWNER_DOMAIN = "dashboard.example.net"
SESSION_ID = "9f3c2a71-5b0e-4d3a-8c21-77aa10bd2e55"
PASSWORD = "pw-unit-test-0123456789"
NOW = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)

PROFILE = Profile(
    host="smtp.example.org",
    port=587,
    security="starttls",
    username="reporter",
    from_address="sender@mail.example.org",
    from_name="Network Volunteer",
    mode="click",
    auto_hold_minutes=60,
    daily_cap=20,
    password=PASSWORD,
)
CSV = Attachment("evidence.csv", "text/csv", "ts,src\r\n2026-10-30T14:02:00Z,198.51.100.23\r\n")
MESSAGE = RenderedMessage(
    to="abuse@example.net",
    subject="Attack from 198.51.100.23 (AS64500)",
    body="Hello,\n\nThe address below attacked a monitored system.\n\nRegards",
    attachments=(CSV,),
)
XARF = RenderedMessage(
    to="abuse@example.net",
    subject="Attack from 198.51.100.23",
    body="Hello",
    attachments=(Attachment("xarf.json", "application/json", '{"xarf_version": "4.2.0"}\n'), CSV),
    layout="report",
    feedback="Feedback-Type: xarf\nUser-Agent: Mozilla/5.0\nVersion: 1\n",
)


def make_terms(*, self_address: bool = True) -> SelfTerms:
    rows = [
        SelfTermRow(kind="address", value=SELF, source="manual"),
        SelfTermRow(kind="address", value="2001:db8:1234::77", source="manual"),
    ]
    if not self_address:
        rows = []
    rows.append(
        SelfTermRow(
            kind="name", value="host-203-0-113-77.dyn.example.com", source="learned", confirmed=True
        )
    )
    return load_self_terms(
        rows,
        {
            "API_ALLOWED_HOSTS": f"{OWNER_DOMAIN},localhost",
            "VPN_WG_ENDPOINT_IP": "198.51.100.200",
            "WEB_HOSTNAME": "srv-web01",
        },
    )


TERMS = make_terms()
CTX = GuardContext(internal_ids=frozenset({SESSION_ID}), allow_documentation=True)


def parse(raw: bytes) -> email.message.EmailMessage:
    msg = email.message_from_bytes(raw, policy=email.policy.SMTP)
    assert isinstance(msg, email.message.EmailMessage)
    return msg


# ---- a fake SMTP client --------------------------------------------------------------------


class FakeSMTP:
    """Records every use. Class attributes script the failures."""

    instances: ClassVar[list[FakeSMTP]] = []
    fail: ClassVar[dict[str, BaseException]] = {}
    hold: ClassVar[threading.Event | None] = None  # sendmail waits for it (a send in flight)
    entered: ClassVar[threading.Event] = threading.Event()

    def __init__(self, gate: EgressGate, host: str, port: int, **kwargs: Any) -> None:
        self.gate, self.host, self.port, self.kwargs = gate, host, port, kwargs
        self.calls: list[str] = []
        self.sent: tuple[str, list[str], bytes] | None = None
        FakeSMTP.instances.append(self)

    def connect(self, host: str, port: int) -> None:
        if "connect" in FakeSMTP.fail:
            raise FakeSMTP.fail["connect"]
        self.host, self.port = host, port

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *_a: object) -> None:
        return None

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, context: ssl.SSLContext) -> None:
        if "tls" in FakeSMTP.fail:
            raise FakeSMTP.fail["tls"]
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        self.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.calls.append(f"login:{user}")
        assert password == PASSWORD
        if "auth" in FakeSMTP.fail:
            raise FakeSMTP.fail["auth"]

    def sendmail(self, sender: str, rcpts: list[str], raw: bytes) -> None:
        FakeSMTP.entered.set()
        if FakeSMTP.hold is not None:
            FakeSMTP.hold.wait(10)
        if "send" in FakeSMTP.fail:
            raise FakeSMTP.fail["send"]
        self.calls.append("send")
        self.sent = (sender, rcpts, raw)


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.instances = []
    FakeSMTP.fail = {}
    FakeSMTP.hold = None
    FakeSMTP.entered = threading.Event()
    monkeypatch.setattr(outgoing, "TunnelSMTP", FakeSMTP)
    monkeypatch.setattr(outgoing, "TunnelSMTP_SSL", FakeSMTP)
    return FakeSMTP


# ---- message hygiene -----------------------------------------------------------------------


def test_headers_are_neutral() -> None:
    msg = parse(build_message(PROFILE, MESSAGE, now=NOW))
    assert set(msg.keys()) == {
        "From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"
    }  # fmt: skip
    for forbidden in ("X-Mailer", "User-Agent", "Cc", "Bcc", "Reply-To", "X-Originating-IP"):
        assert forbidden not in msg
    assert msg["To"] == "abuse@example.net"
    assert msg["From"] == "Network Volunteer <sender@mail.example.org>"
    assert msg["Date"].endswith("+0000") and msg["Date"].startswith("Sun, 01 Nov 2026 10:00")
    assert msg.is_multipart() and [p.get_filename() for p in msg.iter_attachments()] == [
        "evidence.csv"
    ]


def test_an_xarf_report_has_the_rfc6522_shape_and_no_header() -> None:
    msg = parse(build_message(PROFILE, XARF, now=NOW))
    assert "X-ARF" not in msg and "X-XARF" not in msg
    assert msg.get_content_type() == "multipart/report"
    assert msg.get_param("report-type") == "feedback-report"
    parts = list(msg.iter_parts())
    assert [p.get_content_type() for p in parts] == [
        "text/plain",
        "message/feedback-report",
        "application/json",
        "text/csv",
    ]
    assert parts[2]["Content-Transfer-Encoding"] == "base64"
    assert parts[2].get_filename() == "xarf.json"
    assert parts[2].get_payload(decode=True) == b'{"xarf_version": "4.2.0"}\n'
    assert "MIME-Version" not in parts[2]
    assert "X-ARF" not in parse(build_message(PROFILE, MESSAGE, now=NOW))


def test_message_id_is_on_the_senders_domain_with_a_random_local_part() -> None:
    a = parse(build_message(PROFILE, MESSAGE))["Message-ID"]
    b = parse(build_message(PROFILE, MESSAGE))["Message-ID"]
    assert a != b
    assert a.startswith("<") and a.endswith("@mail.example.org>")
    assert len(a.partition("@")[0]) >= 20
    assert socket.gethostname().lower() not in a.lower()


def test_no_from_name_means_a_bare_address() -> None:
    profile = Profile(
        host=PROFILE.host, port=PROFILE.port, security="starttls", username="",
        from_address=PROFILE.from_address, from_name="", mode="click",
        auto_hold_minutes=60, daily_cap=20,
    )  # fmt: skip
    assert parse(build_message(profile, MESSAGE))["From"] == "sender@mail.example.org"


@pytest.mark.parametrize("to", ["abuse@example.net\r\nBcc: x@example.net", "a b@example.net", ""])
def test_a_bad_recipient_is_refused_before_building(to: str) -> None:
    with pytest.raises(SendFailure) as err:
        build_message(PROFILE, RenderedMessage(to=to, subject="s", body="b"))
    assert err.value.code == "not_ready"


def test_a_subject_cannot_inject_a_header() -> None:
    msg = parse(
        build_message(
            PROFILE, RenderedMessage(to="abuse@example.net", subject="a\r\nBcc: x", body="b")
        )
    )
    assert "Bcc" not in msg


def test_the_test_message_is_short_neutral_and_to_the_sender_itself() -> None:
    msg = parse(build_test_message(PROFILE))
    assert msg["To"] == PROFILE.from_address and msg["Subject"] == "Test message"
    assert not msg.is_multipart() and len(msg.get_content()) < 100
    assert "X-Mailer" not in msg and "User-Agent" not in msg


def test_ehlo_name_is_the_senders_domain() -> None:
    assert sender_domain("Name <ops@mail.example.org>") == "mail.example.org"
    assert sender_domain("") == "localhost" and sender_domain("no-at-sign") == "localhost"
    assert PROFILE.domain == "mail.example.org"


# ---- delivery: TLS, EHLO, proxy only ------------------------------------------------------


def test_starttls_login_and_send_in_order_with_the_senders_domain_as_ehlo(
    smtp: type[FakeSMTP],
) -> None:
    raw = build_message(PROFILE, MESSAGE, now=NOW)
    deliver(fake_gate(), PROFILE, raw, "abuse@example.net")
    (conn,) = smtp.instances
    assert conn.calls == ["ehlo", "starttls", "ehlo", "login:reporter", "send"]
    assert conn.kwargs["local_hostname"] == "mail.example.org"
    assert conn.kwargs["local_hostname"] != socket.gethostname()
    assert conn.sent == ("sender@mail.example.org", ["abuse@example.net"], raw)
    assert (conn.host, conn.port) == ("smtp.example.org", 587)


def test_implicit_tls_uses_the_ssl_client_with_a_verifying_context(
    smtp: type[FakeSMTP],
) -> None:
    profile = Profile(
        host="smtp.example.org", port=465, security="ssl", username="",
        from_address="sender@mail.example.org", from_name="", mode="click",
        auto_hold_minutes=60, daily_cap=20,
    )  # fmt: skip
    deliver(fake_gate(), profile, b"x", "abuse@example.net")
    (conn,) = smtp.instances
    assert conn.calls == ["send"]  # no STARTTLS dance, no login without a user
    ctx = conn.kwargs["context"]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


@pytest.mark.parametrize(
    ("stage", "exc", "code"),
    [
        ("connect", smtplib.SMTPServerDisconnected("gone"), "network"),
        ("connect", TimeoutError("slow"), "timeout"),
        ("connect", ssl.SSLCertVerificationError("bad cert"), "tls_failed"),
        ("connect", OSError("refused"), "network"),
        ("tls", smtplib.SMTPNotSupportedError("no starttls"), "tls_failed"),
        ("tls", ssl.SSLError("handshake"), "tls_failed"),
        ("auth", smtplib.SMTPAuthenticationError(535, b"bad credentials " + PASSWORD.encode()), "auth_failed"),
        ("auth", smtplib.SMTPNotSupportedError("no AUTH"), "auth_failed"),
        ("send", smtplib.SMTPRecipientsRefused({"abuse@example.net": (550, b"no")}), "refused"),
        ("send", smtplib.SMTPRecipientsRefused({"abuse@example.net": (450, b"later")}), "deferred"),
        ("send", smtplib.SMTPDataError(451, b"rejected: too many messages"), "deferred"),
        ("send", smtplib.SMTPSenderRefused(452, b"rejected", "sender@mail.example.org"), "deferred"),
        ("connect", smtplib.SMTPConnectError(421, b"rejected: too many connections"), "deferred"),
        ("send", smtplib.SMTPDataError(554, b"rejected"), "refused"),
        ("send", smtplib.SMTPSenderRefused(550, b"no", "sender@mail.example.org"), "refused"),
        ("send", TimeoutError("slow"), "unknown_outcome"),  # DATA may have started
        ("send", smtplib.SMTPServerDisconnected("gone"), "unknown_outcome"),
        ("send", OSError("reset"), "unknown_outcome"),
    ],
)  # fmt: skip
def test_errors_map_to_constant_codes_without_secrets(
    smtp: type[FakeSMTP], stage: str, exc: BaseException, code: str
) -> None:
    smtp.fail[stage] = exc
    with pytest.raises(SendFailure) as err:
        deliver(fake_gate(), PROFILE, b"x", "abuse@example.net")
    assert err.value.code == code
    shown = str(err.value) + repr(err.value) + err.value.stored
    assert PASSWORD not in shown and "rejected" not in shown
    assert err.value.__cause__ is None


@pytest.mark.parametrize(
    ("exc", "stored"),
    [
        (smtplib.SMTPDataError(554, b"rejected"), "refused:554"),
        (smtplib.SMTPRecipientsRefused({"abuse@example.net": (550, b"rejected")}), "refused:550"),
        (smtplib.SMTPDataError(451, b"rejected"), "deferred:451"),
        (smtplib.SMTPDataError(999, b"rejected"), "refused"),
    ],
)  # fmt: skip
def test_a_refusal_keeps_only_the_numeric_reply_code(
    smtp: type[FakeSMTP], exc: BaseException, stored: str
) -> None:
    smtp.fail["send"] = exc
    with pytest.raises(SendFailure) as err:
        deliver(fake_gate(), PROFILE, b"x", "abuse@example.net")
    assert err.value.stored == stored


# ---- the gate: nothing is attempted while it is closed ------------------------------------


def test_closed_gate_creates_no_smtp_client_at_all(smtp: type[FakeSMTP]) -> None:
    gate = fake_gate(open_=False, reason="tunnel_down")
    with pytest.raises(SendFailure) as err:
        deliver(gate, PROFILE, b"x", "abuse@example.net")
    assert err.value.code == "egress_closed"
    assert smtp.instances == []


class Listener:
    """Stands where the VPN proxy would be and counts connections."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.port: int = self.sock.getsockname()[1]
        self.connections = 0
        self.first_lines: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError, OSError:
                continue
            self.connections += 1
            conn.settimeout(1.0)
            try:
                self.first_lines.append(conn.recv(4096).split(b"\r\n", 1)[0])
            except OSError:
                pass
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(2)
        self.sock.close()


@pytest.fixture
def proxy() -> Any:
    listener = Listener()
    yield listener
    listener.close()


def gate_towards(listener: Any, *, open_: bool) -> EgressGate:
    gate = fake_gate(open_=open_)
    gate.settings = EgressSettings(
        proxy_url=f"http://127.0.0.1:{listener.port}", proxy_password="t" * 24
    )
    return gate


@pytest.mark.parametrize("security", ["starttls", "ssl"])
def test_closed_gate_never_reaches_the_proxy_or_the_server(proxy: Listener, security: str) -> None:
    """The real TunnelSMTP classes, a closed gate: zero connections, not even to the proxy."""
    profile = Profile(
        host="smtp.example.org", port=587, security=security, username="reporter",
        from_address="sender@mail.example.org", from_name="", mode="click",
        auto_hold_minutes=60, daily_cap=20, password=PASSWORD,
    )  # fmt: skip
    with pytest.raises(SendFailure) as err:
        deliver(gate_towards(proxy, open_=False), profile, b"x", "abuse@example.net")
    assert err.value.code == "egress_closed"
    assert proxy.connections == 0


def test_an_open_gate_only_ever_talks_to_the_proxy(proxy: Listener) -> None:
    """The only socket is the one to the proxy, carrying a CONNECT to the SMTP host."""
    with pytest.raises(SendFailure) as err:
        deliver(gate_towards(proxy, open_=True), PROFILE, b"x", "abuse@example.net")
    assert err.value.code == "network"  # the stand-in proxy hangs up
    assert proxy.connections == 1
    assert proxy.first_lines == [b"CONNECT smtp.example.org:587 HTTP/1.1"]


# ---- the identity guard on the complete message --------------------------------------------


def test_a_clean_message_passes_the_guard() -> None:
    raw = build_message(PROFILE, MESSAGE, now=NOW)
    check_message(raw, PROFILE, "abuse@example.net", TERMS, ctx=CTX, rendered=MESSAGE)


def test_without_a_known_self_address_nothing_is_sent() -> None:
    raw = build_message(PROFILE, MESSAGE, now=NOW)
    with pytest.raises(SendFailure) as err:
        check_message(raw, PROFILE, "abuse@example.net", make_terms(self_address=False))
    assert err.value.code == "guard_failed" and "no_self_address" in err.value.reasons
    assert err.value.stored.startswith("guard_failed:") and "no_self_address" in err.value.stored


def test_an_unreadable_deny_set_fails_closed() -> None:
    raw = build_message(PROFILE, MESSAGE, now=NOW)
    with pytest.raises(SendFailure) as err:
        check_message(raw, PROFILE, "abuse@example.net", None)
    assert "self_terms_unavailable" in err.value.reasons


def test_the_test_message_is_guarded_too() -> None:
    raw = build_test_message(PROFILE)
    check_message(raw, PROFILE, PROFILE.from_address, TERMS)
    with pytest.raises(SendFailure) as err:
        check_message(raw, PROFILE, PROFILE.from_address, make_terms(self_address=False))
    assert "no_self_address" in err.value.reasons
    owner_profile = Profile(
        host="smtp.example.org", port=587, security="starttls", username="",
        from_address=f"ops@{OWNER_DOMAIN}", from_name="", mode="click",
        auto_hold_minutes=60, daily_cap=20,
    )  # fmt: skip
    with pytest.raises(SendFailure) as err2:
        check_message(
            build_test_message(owner_profile), owner_profile, owner_profile.from_address, TERMS
        )
    assert "owner_domain" in err2.value.reasons


def test_the_envelope_and_ehlo_name_are_guarded() -> None:
    odd = Profile(
        host="smtp.example.org", port=587, security="starttls", username="",
        from_address="sender@mail.example.org", from_name="", mode="click",
        auto_hold_minutes=60, daily_cap=20,
    )  # fmt: skip
    raw = build_message(odd, MESSAGE, now=NOW)
    with pytest.raises(SendFailure) as err:  # a recipient that names the owner
        check_message(raw, odd, f"abuse@{OWNER_DOMAIN}", TERMS, ctx=CTX)
    assert "owner_domain" in err.value.reasons


CORPUS = Path(__file__).resolve().parents[2] / "reporting" / "tests" / "corpus" / "planted.yaml"
PLANTED: list[dict[str, Any]] = yaml.safe_load(CORPUS.read_text())["cases"]
B64_CASES = [
    {"id": f"b64_{k}", "text": f"echo {base64.b64encode(b'A' * k + SELF.encode() + b'/x').decode()}",
     "codes": ["self_address"]}
    for k in range(3)
]  # fmt: skip
ALL = PLANTED + B64_CASES
HEAD = (
    b"From: sender@mail.example.org\r\nTo: abuse@example.net\r\nSubject: Report\r\n"
    b"Date: Sun, 01 Nov 2026 10:00:00 +0000\r\nMessage-ID: <abc@mail.example.org>\r\n"
    b"MIME-Version: 1.0\r\n"
)


def plant(text: str, where: str) -> bytes:
    value = text.encode()
    if where == "subject":
        return HEAD.replace(b"Subject: Report", b"Subject: " + value) + (
            b"Content-Type: text/plain; charset=utf-8\r\n\r\nhi\r\n"
        )
    if where == "from_header":
        return HEAD.replace(b"sender@", value + b" <sender@") + (
            b"Content-Type: text/plain; charset=utf-8\r\n\r\nhi\r\n"
        )
    if where == "message_id":
        return HEAD.replace(b"abc@", value + b"@") + (
            b"Content-Type: text/plain; charset=utf-8\r\n\r\nhi\r\n"
        )
    if where == "x_header":
        return HEAD + b"X-Note: " + value + b"\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
    if where == "body":
        return HEAD + b"Content-Type: text/plain; charset=utf-8\r\n\r\n" + value + b"\r\n"
    if where == "body_base64":
        return (
            HEAD
            + b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode(value)
            + b"\r\n"
        )
    assert where == "attachment"
    return (
        HEAD
        + b'Content-Type: multipart/mixed; boundary="b1"\r\n\r\n--b1\r\n'
        + b"Content-Type: text/plain\r\n\r\nhi\r\n--b1\r\n"
        + b'Content-Type: text/csv; name="e.csv"\r\nContent-Disposition: attachment; '
        + b'filename="e.csv"\r\n\r\n'
        + value
        + b"\r\n--b1--\r\n"
    )


WHERES = ("subject", "from_header", "message_id", "x_header", "body", "body_base64", "attachment")


@pytest.mark.parametrize("where", WHERES)
@pytest.mark.parametrize("case", ALL, ids=lambda c: c["id"])
def test_every_planted_form_in_any_header_or_part_blocks_the_send(
    case: dict[str, Any], where: str
) -> None:
    """The M22 corpus (dotted, URL, base64, inet_aton integer and hex, v6, names...) planted in
    each header and each MIME part of the serialized message."""
    ctx = GuardContext(
        internal_ids=frozenset({SESSION_ID}), allow_documentation=not case.get("doc")
    )
    with pytest.raises(SendFailure) as err:
        check_message(plant(case["text"], where), PROFILE, "abuse@example.net", TERMS, ctx=ctx)
    assert err.value.code == "guard_failed"
    assert set(case["codes"]) <= set(err.value.reasons), (where, err.value.reasons)


# ---- the deadline lives in the delivery thread ---------------------------------------------


class Dripper:
    """A stand-in proxy that accepts the CONNECT, then drips the SMTP banner one byte at a time:
    no single socket operation ever times out, only the overall deadline can end it."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(0.05)
        self.port: int = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError, OSError:
                continue
            try:
                conn.settimeout(2.0)
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                for byte in b"220 smtp.example.org ESMTP ready\r\n" * 40:
                    if self._stop.is_set():
                        break
                    conn.sendall(bytes([byte]))
                    self._stop.wait(0.15)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(3)
        self.sock.close()


def test_a_dripping_server_cannot_outlive_the_deadline() -> None:
    import time

    drip = Dripper()
    try:
        started = time.monotonic()
        with pytest.raises(SendFailure) as err:
            deliver(
                gate_towards(drip, open_=True), PROFILE, b"x", "abuse@example.net", deadline_s=1.5
            )
        elapsed = time.monotonic() - started
    finally:
        drip.close()
    assert err.value.code == "timeout"  # still before the message: a plain timeout
    assert elapsed < 5.0


def test_a_stored_subject_is_read_as_a_host() -> None:
    from ingest.reportmail.sender import _host_of_subject

    assert _host_of_subject("www.youtube.com") == "www.youtube.com"
    assert _host_of_subject("https://is.gd/abc?x=1") == "is.gd"
    assert _host_of_subject("http://user@bit.ly:8080/x") == "bit.ly"
    assert _host_of_subject("198.51.100.7") == "198.51.100.7"
    assert _host_of_subject("2001:db8::7") == "2001:db8::7"
    assert _host_of_subject("[2001:db8::7]:443") == "2001:db8::7"


def test_the_new_cancel_codes_are_known_to_the_stack() -> None:
    from ingest.reportmail.outgoing import CODES

    assert {"shared_host", "form_only", "undeliverable"} <= set(CODES)
    assert {"xarf_invalid", "digest_migration", "superseded"} <= set(CODES)
