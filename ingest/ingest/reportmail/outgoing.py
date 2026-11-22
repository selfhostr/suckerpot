"""One outgoing abuse mail: build it, guard the COMPLETE serialized message, deliver it (M25).

The only SMTP code of the reporting feature (``reporting/`` stays free of ``smtplib``).

* The message has neutral headers: ``From``, ``To`` (the abuse mailbox only), ``Subject``,
  ``Date`` (UTC), a ``Message-ID`` on the sender's domain with a random local part, ``MIME-Version``
  and the content headers. No ``Cc``/``Bcc``, no ``X-Mailer``, no ``User-Agent``, no X-ARF header
  (XARF v4 has none).
* The body follows the rendered layout (M38): one source is an RFC 6522 ``multipart/report``
  (text, ``message/feedback-report``, ``xarf.json``, ``evidence.csv``); several sources are a
  ``multipart/mixed`` digest (text, ``evidence.csv``, ``xarf-001.json`` ...). JSON parts are
  base64, every other part 7bit ASCII.
* The identity guard runs on the serialized bytes (every header and every MIME part, decoded) and
  on the envelope, right before delivery. A failure, including ``no_self_address`` (nothing is
  known about the monitored system's address), sends nothing.
* Delivery goes through ``suckerpot_egress`` (``TunnelSMTP``, the VPN proxy) only. The gate is
  checked right before connecting; there is no direct socket and no fallback. TLS is mandatory
  with certificate and host name checks. The EHLO name is the domain of the sender address.

Errors are constant codes. The password, the message and the server's answers are never logged.
"""

from __future__ import annotations

import contextlib
import email
import email.policy
import json
import re
import secrets
import smtplib
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage, MIMEPart
from email.utils import format_datetime, formataddr
from typing import Final, cast

from suckerpot_egress import TunnelSMTP, TunnelSMTP_SSL
from suckerpot_reporting import (
    GuardContext,
    GuardResult,
    RenderedMessage,
    SelfTerms,
    guard,
    guard_message,
    guard_parts,
    schema_errors,
)
from suckerpot_reporting.normalize import to_ascii

from ingest.egress import EgressClosed, EgressGate
from ingest.mailname import sender_domain

SMTP_TIMEOUT_S: Final = 15.0
SMTP_DEADLINE_S: Final = 60.0  # the whole exchange, whatever the server drips
MAX_LINE: Final = 900

_MAILBOX: Final = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")

TEST_SUBJECT: Final = "Test message"
TEST_BODY: Final = "This is a short test message. No action is needed.\n"

# Error codes stored in ``abuse_send_requests.error_code`` (``guard_failed`` carries the guard's
# reason codes after a colon).
CODES: Final = (
    "auth_failed",
    "tls_failed",
    "refused",
    "deferred",
    "timeout",
    "unknown_outcome",
    "network",
    "egress_closed",
    "guard_failed",
    "not_configured",
    "mode_off",
    "mode_changed",
    "too_old",
    "shared_host",
    "form_only",
    "undeliverable",
    "not_ready",
    "internal",
    "xarf_invalid",
    "digest_migration",
    "digest_enabled",
)


class SendFailure(Exception):
    """A mail was not sent. ``code`` is a constant; nothing else is ever attached."""

    def __init__(self, code: str, *, reasons: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.reasons = reasons

    @property
    def stored(self) -> str:
        """The value for ``error_code`` (guard reason codes are constants, never matched text)."""
        if self.reasons:
            return f"{self.code}:{','.join(sorted(set(self.reasons)))}"[:120]
        return self.code


@dataclass(frozen=True, slots=True)
class Profile:
    """The ``report_smtp`` row with its password decrypted (ingest is the only reader)."""

    host: str
    port: int
    security: str
    username: str
    from_address: str
    from_name: str
    mode: str
    auto_hold_minutes: int
    daily_cap: int
    password: str = field(default="", repr=False)
    digest_minute: int = 420  # the digest hour, minutes after 00:00 UTC (M38)

    @property
    def domain(self) -> str:
        return sender_domain(self.from_address)


def _wrap(value: str) -> str:
    """ASCII text with lines short enough for a 7bit part, CRLF line ends."""
    out: list[str] = []
    for line in to_ascii(value).replace("\r", "").split("\n"):
        while len(line) > MAX_LINE:
            out.append(line[:MAX_LINE])
            line = line[MAX_LINE:]
        out.append(line)
    return "\r\n".join(out)


def new_message_id(profile: Profile) -> str:
    """A fresh ``<random@sender-domain>`` id. Random and unrelated to the reply token (O6)."""
    return f"<{secrets.token_urlsafe(18)}@{profile.domain}>"


def _display(profile: Profile) -> str:
    name = to_ascii(profile.from_name).strip()
    return formataddr((name, profile.from_address)) if name else profile.from_address


def build_message(
    profile: Profile,
    rendered: RenderedMessage,
    *,
    now: datetime | None = None,
    to: str | None = None,
    message_id: str | None = None,
) -> bytes:
    """The serialized message (CRLF, 7bit ASCII). ``to`` defaults to the rendered recipient."""
    recipient = (to or rendered.to).strip()
    if not _MAILBOX.match(recipient):
        raise SendFailure("not_ready")
    mail = EmailMessage(policy=email.policy.SMTP)
    mail["From"] = _display(profile)
    mail["To"] = recipient
    mail["Subject"] = re.sub(r"[\r\n]+", " ", to_ascii(rendered.subject))
    mail["Date"] = format_datetime((now or datetime.now(UTC)).astimezone(UTC))
    mail["Message-ID"] = message_id or new_message_id(profile)
    mail.set_content(_wrap(rendered.body), subtype="plain", charset="us-ascii", cte="7bit")
    parts: list[MIMEPart] = []
    if rendered.layout == "report" and rendered.feedback is not None:
        feedback = MIMEPart(policy=email.policy.SMTP)
        feedback["Content-Type"] = "message/feedback-report"
        feedback["Content-Transfer-Encoding"] = "7bit"
        feedback.set_payload(_wrap(rendered.feedback) + "\r\n")
        parts.append(feedback)
    for att in rendered.attachments:
        part = MIMEPart(policy=email.policy.SMTP)
        name = re.sub(r"[^A-Za-z0-9._-]", "_", att.name)
        if att.media_type == "application/json":
            # base64, as the XARF email transport asks (design M38, D16); the guard decodes it
            part.set_content(
                to_ascii(att.content).encode("ascii"),
                maintype="application",
                subtype="json",
                filename=name,
                disposition="attachment",
            )
        else:
            part.set_content(
                _wrap(att.content),
                subtype=att.media_type.partition("/")[2] or "plain",
                charset="us-ascii",
                cte="7bit",
                filename=name,
                disposition="attachment",
            )
        parts.append(part)
    if parts:
        mail.make_mixed()
        if rendered.layout == "report":
            mail.set_type("multipart/report")
            mail.set_param("report-type", "feedback-report")
        for part in parts:
            mail.attach(cast(EmailMessage, part))  # a plain part: no MIME-Version header
    return mail.as_bytes(policy=email.policy.SMTP)


def xarf_parts_valid(raw: bytes) -> bool:
    """Every JSON part of the serialized message, decoded, is a valid XARF 4.2.0 report and the
    message has the parts its layout promises (M38). Validates exactly what leaves."""
    msg = email.message_from_bytes(raw, policy=email.policy.SMTP)
    reports = 0
    for part in msg.walk():
        if part.get_content_type() != "application/json":
            continue
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            return False
        try:
            report = json.loads(payload.decode("ascii"))
        except UnicodeDecodeError, ValueError:
            return False
        if not isinstance(report, dict) or schema_errors(report):
            return False
        reports += 1
    return reports > 0


def build_test_message(profile: Profile) -> bytes:
    """A short neutral message from the profile to its own sender address."""
    plain = RenderedMessage(to=profile.from_address, subject=TEST_SUBJECT, body=TEST_BODY)
    return build_message(profile, plain)


def check_message(
    raw: bytes,
    profile: Profile,
    rcpt: str,
    terms: SelfTerms | None,
    *,
    ctx: GuardContext | None = None,
    rendered: RenderedMessage | None = None,
) -> None:
    """Guard everything that leaves: all headers and parts (decoded), then the envelope and the
    EHLO name. Raises ``SendFailure('guard_failed', reasons=...)``. ``terms=None`` (the deny set
    could not be read) and an unknown monitored address both fail closed."""
    result: GuardResult = guard(raw, terms, fmt="eml", ctx=ctx)
    envelope = (
        f"{profile.from_address}\n{rcpt}\n{profile.domain}\n{profile.host}\n{profile.username}"
    )
    result = result.merge(guard_parts([("envelope", envelope, "text")], terms, ctx=ctx))
    if rendered is not None:
        result = result.merge(guard_message(rendered, terms, ctx=ctx))
    if not result.ok:
        raise SendFailure("guard_failed", reasons=tuple(result.codes))


def _smtp_code(exc: Exception) -> int | None:
    """The numeric SMTP reply code of a refusal (a constant, never the server's text)."""
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        codes = [c for c, _ in exc.recipients.values() if isinstance(c, int)]
        return codes[0] if codes else None
    if isinstance(exc, smtplib.SMTPResponseException) and isinstance(exc.smtp_code, int):
        return exc.smtp_code
    return None


def _refusal(exc: Exception) -> SendFailure:
    """A clear refusal. A 4xx reply means "not now" (a rate limit, greylisting, a full queue):
    ``deferred``, which the sender retries later. Anything else is ``refused``. The reply code is
    kept after a colon (``refused:550``), so the owner can tell what the server meant."""
    code = _smtp_code(exc)
    reasons = (str(code),) if code is not None and 200 <= code <= 599 else ()
    if code is not None and 400 <= code < 500:
        return SendFailure("deferred", reasons=reasons)
    return SendFailure("refused", reasons=reasons)


def _map_error(exc: Exception, stage: str, expired: bool) -> SendFailure:
    """A constant code for what went wrong. In the ``send`` stage the message may already be on
    its way, so anything that is not a clear refusal is an unknown outcome (never retried)."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return SendFailure("auth_failed")
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return SendFailure("tls_failed" if stage == "tls" else "auth_failed")
    if isinstance(exc, ssl.SSLError) and not expired:
        return SendFailure("tls_failed")
    clear_refusal = isinstance(exc, smtplib.SMTPResponseException | smtplib.SMTPRecipientsRefused)
    if clear_refusal and not expired:
        return _refusal(exc)
    if stage == "send":
        return SendFailure("unknown_outcome")  # DATA may have started: we cannot know
    if isinstance(exc, TimeoutError) or expired:
        return SendFailure("timeout")
    if isinstance(exc, smtplib.SMTPException) and not isinstance(
        exc, smtplib.SMTPServerDisconnected
    ):
        return SendFailure("refused")
    return SendFailure("network")


def deliver(
    gate: EgressGate,
    profile: Profile,
    raw: bytes,
    rcpt: str,
    *,
    deadline_s: float = SMTP_DEADLINE_S,
) -> None:
    """Blocking (run it in a thread). The gate is checked immediately before connecting, and the
    connection is a CONNECT tunnel through the VPN proxy: ``TunnelSMTP`` is the only way out.

    The whole exchange ends within ``deadline_s`` whatever the server drips: every socket
    operation gets what is left of it, and a timer shuts the socket down as a backstop."""
    context = ssl.create_default_context()  # certificate chain and host name are verified
    helo = profile.domain
    stage = "connect"
    started = time.monotonic()
    expired = threading.Event()
    holder: list[smtplib.SMTP] = []

    def left() -> float:
        return max(0.5, deadline_s - (time.monotonic() - started))

    def expire() -> None:
        expired.set()
        sock = getattr(holder[0], "sock", None) if holder else None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()

    def arm(server: smtplib.SMTP) -> None:
        if expired.is_set():
            raise TimeoutError
        sock = getattr(server, "sock", None)
        if sock is not None:
            sock.settimeout(min(SMTP_TIMEOUT_S, left()))

    timer = threading.Timer(deadline_s, expire)
    timer.daemon = True
    try:
        gate.require_open()  # EgressClosed before any client, socket or tunnel is created
        timer.start()
        timeout = min(SMTP_TIMEOUT_S, left())
        # Created unconnected, so the timer can already reach the socket while it connects.
        if profile.security == "ssl":
            server: smtplib.SMTP = TunnelSMTP_SSL(
                gate, "", 0, timeout=timeout, context=context, local_hostname=helo
            )
        else:
            server = TunnelSMTP(gate, "", 0, timeout=timeout, local_hostname=helo)
        holder.append(server)
        server.connect(profile.host, profile.port)
        with server:
            if profile.security != "ssl":
                arm(server)
                server.ehlo()
                stage = "tls"
                arm(server)
                server.starttls(context=context)  # fails when the server cannot: no plain text
                stage = "connect"
                arm(server)
                server.ehlo()
            if profile.username:
                stage = "auth"
                arm(server)
                server.login(profile.username, profile.password)
            stage = "send"
            arm(server)
            server.sendmail(profile.from_address, [rcpt], raw)
    except EgressClosed:
        raise SendFailure("egress_closed") from None
    except Exception as exc:
        raise _map_error(exc, stage, expired.is_set()) from None
    finally:
        timer.cancel()
