"""Plain text, evidence CSV, X-ARF v0.2 and ``.eml`` renderers (design M22, section 8.1, 8.2).

All renderers are pure and deterministic for a given evidence object. They never emit a
destination address, a ``From``, ``Date``, ``Message-ID``, ``User-Agent`` or ``X-Mailer``
header. The caller runs ``guard_message`` (or ``guard`` on the ``.eml`` bytes) before
returning anything.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import Final, Literal
from urllib.parse import urlsplit

import yaml

from .errors import GuardFailed, RenderUnavailable
from .evidence import (
    DEFAULT_SUBJECT,
    DEFAULT_XARF_USER_AGENT,
    MAX_ACTIVITIES_BODY,
    MAX_ACTIVITIES_CSV,
    Activity,
    Evidence,
    ReportOptions,
    ReportSettings,
    Subject,
    missing_settings,
)
from .guard import ArtifactFormat, GuardContext, GuardResult, guard_parts
from .normalize import to_ascii
from .redact import defang
from .terms import SelfTerms

DEMO_PREFIX: Final = "DEMO, DO NOT SEND: "

ReferenceStyle = Literal["subject", "subject_and_body", "off"]
REFERENCE_STYLES: Final[tuple[str, ...]] = ("subject", "subject_and_body", "off")
_TOKEN: Final = re.compile(r"^[0-9a-f]{12}$")
SUBJECT_MAX: Final = 150

# One place for the X-ARF report types. Names follow the X-ARF 0.2 abuse and malware schemas.
XARF_TYPES: Final[dict[str, tuple[str, str]]] = {
    "login": ("abuse", "login-attack"),
    "exploit": ("abuse", "web-hack"),
    "malware": ("malware", "malware-distribution"),
}
XARF_SCHEMA_URL: Final = "http://www.x-arf.org/schema/{category}_{report_type}_0.1.2.json"

_MAILBOX: Final = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")


@dataclass(frozen=True)
class Attachment:
    name: str
    media_type: str
    content: str


@dataclass(frozen=True)
class RenderedMessage:
    to: str
    subject: str
    body: str
    attachments: tuple[Attachment, ...] = ()
    xarf: bool = False


def _require(settings: ReportSettings | None, *, xarf: bool = False) -> ReportSettings:
    """The only required setting is the reply contact; the wording is optional."""
    if settings is None or missing_settings(settings, xarf=xarf):
        raise RenderUnavailable("settings_incomplete")
    return settings


# --- small helpers -------------------------------------------------------------------------


def fmt_ts(value: datetime, options: ReportOptions) -> str:
    value = value.astimezone(UTC).replace(microsecond=0)
    if options.time_precision == "minute":
        return value.replace(second=0).strftime("%Y-%m-%dT%H:%MZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def port_label(act: Activity) -> str:
    return f"{act.protocol.upper()}/{act.dst_port} ({act.service})"


def _ports(subject: Subject) -> str:
    seen: list[str] = []
    for act in subject.activities:
        label = port_label(act)
        if label not in seen:
            seen.append(label)
    return ", ".join(seen)


def _heading(subject: Subject, options: ReportOptions) -> str:
    value = defang(subject.value) if (subject.type == "url" and options.defang) else subject.value
    extra: list[str] = []
    if subject.asn is not None:
        extra.append(f"AS{subject.asn}")
    if subject.network:
        extra.append(subject.network)
    return f"{value} ({', '.join(extra)})" if extra else value


def _text(value: str, options: ReportOptions) -> str:
    return defang(value) if options.defang else value


_LABELS: Final = {
    "failed_logins": "Login attempts",
    "login_then_commands": "Commands",
    "command": "Commands",
    "download": "Download URLs",
    "http_request": "Requests",
    "exploit_attempt": "Exploit attempts",
}


def _activity_lines(act: Activity, options: ReportOptions, multi_port: bool) -> list[str]:
    label = _LABELS[act.action]
    on = f" [{port_label(act)}]" if multi_port else ""
    indent = " " * 6
    if act.action == "failed_logins":
        line = f"  - {label}{on}: {act.count}"
        if options.include_usernames and act.usernames:
            line += f" (users: {', '.join(act.usernames)})"
        return [line]
    body = [_text(t, options) for t in act.text.split("\n")] if act.text else []
    lines = [f"  - {fmt_ts(act.ts, options)} {label}{on}:", *(indent + b for b in body)]
    if act.user_agent:
        lines.append(indent + f"User-Agent: {_text(act.user_agent, options)}")
    return lines


def _subject_block(subject: Subject, options: ReportOptions) -> list[str]:
    lines = [_heading(subject, options)]
    span = f"{fmt_ts(subject.first_ts, options)} to {fmt_ts(subject.last_ts, options)}"
    ports = _ports(subject)
    lines.append(f"  {span}, {ports}" if ports else f"  {span}")
    acts = sorted(subject.activities, key=lambda a: a.ts)
    multi_port = len({port_label(a) for a in acts}) > 1
    for act in acts[:MAX_ACTIVITIES_BODY]:
        lines.extend(_activity_lines(act, options, multi_port))
    if len(acts) > MAX_ACTIVITIES_BODY:
        # Not "more entries are listed in evidence.csv": that exact sentence is in LEGACY_PHRASES.
        lines.append(f"  ({len(acts) - MAX_ACTIVITIES_BODY} more in evidence.csv)")
    red = subject.redaction
    if options.show_redaction_counts and (red.lines_dropped or red.addresses_masked):
        parts = []
        if red.lines_dropped:
            parts.append(_plural(red.lines_dropped, "line removed", "lines removed"))
        if red.addresses_masked:
            parts.append(_plural(red.addresses_masked, "address masked", "addresses masked"))
        lines.append(f"  ({', '.join(parts)})")
    if subject.previously_reported is not None:
        lines.append(f"  (reported {subject.previously_reported:%Y-%m-%d})")
    return lines


_PLACEHOLDER = re.compile(r"\{(value|asn|network|count|date|ref)\}")


def _reference(token: str | None, style: str) -> str | None:
    """The token to print, or None when the style is ``off`` or there is no (valid) token."""
    if style not in REFERENCE_STYLES:
        raise RenderUnavailable("bad_reference_style")
    if token is None or style == "off":
        return None
    if not _TOKEN.match(token):
        raise RenderUnavailable("bad_reply_token")
    return token


def message_subject(
    evidence: Evidence,
    settings: ReportSettings | None = None,
    *,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
) -> str:
    """Subject line from the owner's template. ``{value}``, ``{asn}``, ``{network}`` come from
    the first subject; ``{count}`` is the number of subjects and ``{date}`` the window end.

    ``{ref}`` becomes ``ref <token>``. A template without it gets `` (ref <token>)`` appended
    (the token survives truncation). The style ``off`` or no token leaves the subject without."""
    cfg = _require(settings)
    token = _reference(reply_token, reference_style)
    first = evidence.subjects[0]
    fields = {
        "value": first.value,
        "asn": f"AS{first.asn}" if first.asn is not None else "",
        "network": first.network or "",
        "count": str(len(evidence.subjects)),
        "date": evidence.window_end.astimezone(UTC).strftime("%Y-%m-%d"),
        "ref": f"ref {token}" if token else "",
    }
    template = (cfg.subject_template or "").strip() or DEFAULT_SUBJECT
    text = _PLACEHOLDER.sub(lambda m: fields[m.group(1)], template)
    if evidence.demo:
        text = DEMO_PREFIX + text
    final = to_ascii(re.sub(r"[\r\n\t]+", " ", text)).strip()[:SUBJECT_MAX]
    if token and token not in final:
        suffix = f" (ref {token})"
        final = final[: SUBJECT_MAX - len(suffix)].rstrip() + suffix
    return final


def _clean_block(value: str) -> str:
    return to_ascii(value.replace("\r\n", "\n").replace("\r", "\n")).strip()


def render_text(
    evidence: Evidence,
    settings: ReportSettings | None = None,
    *,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
) -> RenderedMessage:
    """The plain-text report. Attachments are left to the caller (``render_csv``).

    The reply token goes into the subject, and into a last ``Ref:`` line only for the style
    ``subject_and_body``. It never goes into the CSV, the X-ARF part, STIX or MISP."""
    cfg = _require(settings)
    token = _reference(reply_token, reference_style)
    opts = evidence.options
    sections: list[list[str]] = []
    if evidence.demo:
        sections.append(["DEMO DATA: DO NOT SEND"])
    opening = [t for t in (_clean_block(cfg.intro or ""), _clean_block(cfg.note or "")) if t]
    if opening:
        sections.append(opening)
    for s in evidence.subjects:
        block = _subject_block(s, opts)
        while block and not block[-1].strip():
            block = block[:-1]
        if block:
            sections.append(block)
    outro = _clean_block(cfg.outro or "")
    if outro:
        sections.append([outro])
    if cfg.reply_contact and opts.include_reply_contact:
        sections.append([f"Contact: {to_ascii(cfg.reply_contact.strip())}"])
    signature = _clean_block(cfg.signature or "")
    if signature:
        sections.append([signature])
    if token and reference_style == "subject_and_body":
        sections.append([f"Ref: {token}"])
    lines: list[str] = []
    for section in sections:
        if lines:
            lines.append("")
        lines += section
    return RenderedMessage(
        to=evidence.recipient,
        subject=message_subject(
            evidence, cfg, reply_token=reply_token, reference_style=reference_style
        ),
        body="\n".join(lines) + "\n",
    )


# --- evidence.csv --------------------------------------------------------------------------

CSV_COLUMNS: Final = (
    "source",
    "asn",
    "network",
    "country",
    "time",
    "protocol",
    "src_port",
    "port",
    "count",
    "details",
    "sha256",
)


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def _details(a: Activity, options: ReportOptions) -> str:
    parts = [_LABELS[a.action]]
    if options.include_usernames and a.usernames:
        parts.append("users: " + ",".join(a.usernames))
    if a.text:
        parts.append(a.text)
    if a.user_agent:
        parts.append("UA: " + a.user_agent)
    return "; ".join(parts)


def render_csv(evidence: Evidence) -> Attachment:
    """``evidence.csv``: up to 200 activities per subject, one row each. Real values, no defang."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    opts = evidence.options
    for s in evidence.subjects:
        head = [s.value, s.asn, s.network, s.country]
        hashes = ";".join(x.sha256 for x in s.samples)
        rows = sorted(s.activities, key=lambda a: a.ts)[:MAX_ACTIVITIES_CSV]
        if not rows:
            line = (*head, fmt_ts(s.first_ts, opts), "", "", "", "", "", hashes)
            writer.writerow([_cell(c) for c in line])
        for a in rows:
            line = (
                *head,
                fmt_ts(a.ts, opts),
                a.protocol,
                a.src_port,
                a.dst_port,
                a.count,
                _details(a, opts),
                hashes,
            )
            writer.writerow([_cell(c) for c in line])
    return Attachment("evidence.csv", "text/csv", to_ascii(out.getvalue()))


# --- X-ARF v0.2 ----------------------------------------------------------------------------


def _xarf_type(evidence: Evidence, subject: Subject) -> tuple[str, str]:
    if evidence.kind != "attack_source":
        return XARF_TYPES["malware"]
    if subject.activities and all(
        a.action in ("failed_logins", "login_then_commands") for a in subject.activities
    ):
        return XARF_TYPES["login"]
    return XARF_TYPES["exploit"]


def _service_port(subject: Subject) -> tuple[str, int]:
    if subject.type == "url":
        parts = urlsplit(subject.value)
        scheme = parts.scheme.lower() or "http"
        return scheme, parts.port or (443 if scheme == "https" else 80)
    if subject.activities:
        first = min(subject.activities, key=lambda a: a.ts)
        return first.service, first.dst_port
    raise RenderUnavailable("xarf_no_activity")


def _source_type(subject: Subject) -> str:
    if subject.type == "ip":
        return "ipv6" if ipaddress.ip_address(subject.value).version == 6 else "ipv4"
    return "uri"


def render_xarf(
    evidence: Evidence,
    settings: ReportSettings | None = None,
    *,
    subject: str | None = None,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
) -> RenderedMessage:
    """X-ARF v0.2 has one ``Source`` per report. The reply token reaches the human part only.

    One subject (or ``subject`` given): a full X-ARF message. Several subjects: the human
    summary with ``evidence.csv``, which is what the review screen offers by default.
    """
    chosen = evidence.subjects
    if subject is not None:
        chosen = tuple(s for s in evidence.subjects if s.value == subject)
        if not chosen:
            raise RenderUnavailable("xarf_unknown_subject")
    if len(chosen) != 1:
        msg = render_text(
            evidence, settings, reply_token=reply_token, reference_style=reference_style
        )
        return RenderedMessage(msg.to, msg.subject, msg.body, (render_csv(evidence),), xarf=False)
    cfg = _require(settings, xarf=True)
    one = chosen[0]
    single = evidence.model_copy(update={"subjects": (one,)})
    human = render_text(single, cfg, reply_token=reply_token, reference_style=reference_style)
    category, report_type = _xarf_type(evidence, one)
    service, port = _service_port(one)
    when = one.first_ts.astimezone(UTC).replace(microsecond=0)
    if evidence.options.time_precision == "minute":
        when = when.replace(second=0)
    report = {
        "Reported-From": to_ascii((cfg.reply_contact or "").strip()),
        "Category": category,
        "Report-Type": report_type,
        "Service": service,
        "Port": port,
        "Version": 0.2,
        "User-Agent": to_ascii((cfg.xarf_user_agent or "").strip()) or DEFAULT_XARF_USER_AGENT,
        "Date": format_datetime(when),
        "Source-Type": _source_type(one),
        "Source": one.value,
        "Attachment": "text/plain",
        "Schema-URL": XARF_SCHEMA_URL.format(category=category, report_type=report_type),
        "Occurrences": max(1, one.events),
    }
    dumped = yaml.safe_dump(
        report, sort_keys=False, default_flow_style=False, allow_unicode=False, width=1000
    )
    evidence_part = render_csv(single)
    return RenderedMessage(
        to=human.to,
        subject=human.subject,
        body=human.body,
        attachments=(
            Attachment("report.txt", "text/plain", dumped),
            Attachment("evidence.txt", "text/plain", evidence_part.content),
        ),
        xarf=True,
    )


# --- .eml ----------------------------------------------------------------------------------


def _wrap(text: str, width: int = 900) -> str:
    out: list[str] = []
    for line in text.split("\n"):
        while len(line) > width:
            out.append(line[:width])
            line = line[width:]
        out.append(line)
    return "\r\n".join(out)


def new_boundary() -> str:
    """A random MIME boundary in the usual shape of Python's own mailers."""
    return f"{'=' * 15}{secrets.randbelow(sys.maxsize):019d}=="


def render_eml(message: RenderedMessage, *, boundary: str | None = None) -> bytes:
    """Headers ``To``, ``Subject``, ``X-ARF`` (X-ARF only), ``MIME-Version``, ``Content-Type``.

    Parts are 7bit ASCII so the guard reads exactly what a client would send. No ``From``,
    ``Date``, ``Message-ID``, ``User-Agent`` or ``X-Mailer``: the owner's webmail adds its own.
    """
    if not _MAILBOX.match(message.to):
        raise RenderUnavailable("eml_invalid_recipient")
    subject = re.sub(r"[\r\n]+", " ", message.subject)
    head = [f"To: {message.to}", f"Subject: {to_ascii(subject)}"]
    if message.xarf:
        head.append("X-ARF: YES")
    head.append("MIME-Version: 1.0")
    body = _wrap(to_ascii(message.body))
    if not message.attachments:
        head += ["Content-Type: text/plain; charset=us-ascii", "Content-Transfer-Encoding: 7bit"]
        return ("\r\n".join(head) + "\r\n\r\n" + body + "\r\n").encode("ascii")
    boundary = boundary or new_boundary()
    head.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
    parts = [
        f"--{boundary}\r\nContent-Type: text/plain; charset=us-ascii\r\n"
        f"Content-Transfer-Encoding: 7bit\r\n\r\n{body}\r\n"
    ]
    for att in message.attachments:
        name = re.sub(r"[^A-Za-z0-9._-]", "_", att.name)
        parts.append(
            f"--{boundary}\r\nContent-Type: {att.media_type}; charset=us-ascii; "
            f'name="{name}"\r\nContent-Transfer-Encoding: 7bit\r\n'
            f'Content-Disposition: attachment; filename="{name}"\r\n\r\n'
            f"{_wrap(to_ascii(att.content))}\r\n"
        )
    raw = "\r\n".join(head) + "\r\n\r\n" + "".join(parts) + f"--{boundary}--\r\n"
    return raw.encode("ascii")


# --- guard glue ----------------------------------------------------------------------------


def guard_message(
    message: RenderedMessage, terms: SelfTerms | None, *, ctx: GuardContext | None = None
) -> GuardResult:
    """Guard every piece of a message: recipient, subject, body and each attachment."""
    parts: list[tuple[str, str | bytes, ArtifactFormat]] = [
        ("to", message.to, "text"),
        ("subject", message.subject, "text"),
        ("body", message.body, "text"),
    ]
    parts += [
        (a.name, a.content, "csv" if a.media_type == "text/csv" else "xarf")
        for a in message.attachments
    ]
    return guard_parts(parts, terms, ctx=ctx)


def require_ok(result: GuardResult) -> None:
    """Raise ``GuardFailed`` (reason codes only) unless the guard passed."""
    if not result.ok:
        raise GuardFailed(result.codes)
