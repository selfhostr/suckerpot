"""Plain text, evidence CSV, the mail with its XARF v4 parts and ``.eml`` (M22 section 8, M38).

All renderers are pure and deterministic for a given evidence object. They never emit a
destination address, a ``From``, ``Date``, ``Message-ID``, ``User-Agent`` or ``X-Mailer``
header. The caller runs ``guard_message`` (or ``guard`` on the ``.eml`` bytes) before
returning anything.
"""

from __future__ import annotations

import base64
import csv
import io
import re
import secrets
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal

from .errors import GuardFailed, RenderUnavailable
from .evidence import (
    DEFAULT_SUBJECT,
    MAX_ACTIVITIES_BODY,
    MAX_ACTIVITIES_CSV,
    Activity,
    Evidence,
    ReportKind,
    ReportOptions,
    ReportSettings,
    Subject,
    missing_settings,
)
from .guard import ArtifactFormat, GuardContext, GuardResult, guard_parts
from .normalize import to_ascii
from .redact import defang
from .terms import SelfTerms
from .xarf import dumps as xarf_dumps
from .xarf import feedback_report, file_names, xarf_reports

DEMO_PREFIX: Final = "DEMO, DO NOT SEND: "

ReferenceStyle = Literal["subject", "subject_and_body", "off"]
REFERENCE_STYLES: Final[tuple[str, ...]] = ("subject", "subject_and_body", "off")
_TOKEN: Final = re.compile(r"^[0-9a-f]{12}$")
SUBJECT_MAX: Final = 150

# How a mail is laid out (design M38, section 4.2): ``plain`` text only (or text and CSV),
# ``report`` the RFC 6522 shape of one XARF report, ``digest`` one JSON file per subject.
Layout = Literal["plain", "report", "digest"]
JSON_TYPE: Final = "application/json"
KIND_HEADINGS: Final[dict[str, str]] = {
    "attack_source": "Attack sources",
    "payload_host": "Payload hosts",
    "c2": "Command servers",
}

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
    layout: Layout = "plain"
    feedback: str | None = None  # the message/feedback-report part (layout ``report`` only)

    @property
    def xarf_files(self) -> tuple[Attachment, ...]:
        return tuple(a for a in self.attachments if a.media_type == JSON_TYPE)


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


def _subject_block(
    subject: Subject, options: ReportOptions, file_name: str | None = None
) -> list[str]:
    lines = [_heading(subject, options)]
    if file_name:
        lines.append(f"  Report file: {file_name}")
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
    file_names: Mapping[int, str] | None = None,
) -> RenderedMessage:
    """The plain-text report. Attachments are left to the caller (``render_csv``).

    A digest has a section per kind (attack sources, payload hosts, command servers).
    ``file_names`` maps a subject's position to its XARF file, printed under its heading.

    The reply token goes into the subject, and into a last ``Ref:`` line only for the style
    ``subject_and_body``. It never goes into the CSV, the XARF parts, STIX or MISP."""
    cfg = _require(settings)
    token = _reference(reply_token, reference_style)
    opts = evidence.options
    sections: list[list[str]] = []
    if evidence.demo:
        sections.append(["DEMO DATA: DO NOT SEND"])
    opening = [t for t in (_clean_block(cfg.intro or ""), _clean_block(cfg.note or "")) if t]
    if opening:
        sections.append(opening)
    names = file_names or {}
    order = list(enumerate(evidence.subjects))
    if evidence.kind == "digest":
        rank = {k: i for i, k in enumerate(KIND_HEADINGS)}
        order.sort(key=lambda item: rank[evidence.kind_of(item[1])])
    current: ReportKind | None = None
    for index, s in order:
        if evidence.kind == "digest" and evidence.kind_of(s) != current:
            current = evidence.kind_of(s)
            count = sum(1 for x in evidence.subjects if evidence.kind_of(x) == current)
            sections.append([f"{KIND_HEADINGS[current]} ({count})"])
        block = _subject_block(s, opts, names.get(index))
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


# --- the mail (XARF v4) ----------------------------------------------------------------


def render_mail(
    evidence: Evidence,
    settings: ReportSettings | None = None,
    *,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
) -> RenderedMessage:
    """The complete abuse mail: the human text, ``evidence.csv`` and one XARF v4 JSON report per
    subject (design M38, section 4.2). One subject gives the RFC 6522 ``report`` layout
    (``xarf.json``); several give the ``digest`` layout (``xarf-001.json`` ...), each file named in
    the text. Every JSON is validated against the vendored schemas: ``xarf_invalid`` otherwise.

    The reply token reaches the human part only."""
    cfg = _require(settings)
    reports = xarf_reports(evidence, cfg)
    names = file_names(len(reports))
    files = tuple(
        Attachment(name, JSON_TYPE, xarf_dumps(report))
        for name, report in zip(names, reports, strict=True)
    )
    many = len(reports) > 1
    human = render_text(
        evidence,
        cfg,
        reply_token=reply_token,
        reference_style=reference_style,
        file_names=dict(enumerate(names)) if many else None,
    )
    csv_part = render_csv(evidence)
    if not many:
        return RenderedMessage(
            human.to,
            human.subject,
            human.body,
            (*files, csv_part),
            layout="report",
            feedback=feedback_report(cfg),
        )
    return RenderedMessage(human.to, human.subject, human.body, (csv_part, *files), layout="digest")


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


def _b64_lines(data: bytes) -> str:
    """Base64 in 76-character lines, as mail clients write it."""
    text = base64.b64encode(data).decode("ascii")
    return "\r\n".join(text[i : i + 76] for i in range(0, len(text), 76))


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _part(att: Attachment) -> str:
    name = _safe_name(att.name)
    if att.media_type == JSON_TYPE:
        # JSON parts are base64, as the XARF email transport asks (design M38, D16).
        return (
            f'Content-Type: {JSON_TYPE}; name="{name}"\r\n'
            "Content-Transfer-Encoding: base64\r\n"
            f'Content-Disposition: attachment; filename="{name}"\r\n\r\n'
            f"{_b64_lines(to_ascii(att.content).encode('ascii'))}\r\n"
        )
    return (
        f'Content-Type: {att.media_type}; charset=us-ascii; name="{name}"\r\n'
        "Content-Transfer-Encoding: 7bit\r\n"
        f'Content-Disposition: attachment; filename="{name}"\r\n\r\n'
        f"{_wrap(to_ascii(att.content))}\r\n"
    )


def render_eml(message: RenderedMessage, *, boundary: str | None = None) -> bytes:
    """Headers ``To``, ``Subject``, ``MIME-Version``, ``Content-Type``, then the same parts, in the
    same order and encodings, as the SMTP path sends (``layout``): XARF v4 has no mail header.

    Text parts are 7bit ASCII and JSON parts base64, so the guard reads exactly what a client
    would send once decoded. No ``From``, ``Date``, ``Message-ID``, ``User-Agent`` or
    ``X-Mailer``: the owner's webmail adds its own.
    """
    if not _MAILBOX.match(message.to):
        raise RenderUnavailable("eml_invalid_recipient")
    subject = re.sub(r"[\r\n]+", " ", message.subject)
    head = [f"To: {message.to}", f"Subject: {to_ascii(subject)}", "MIME-Version: 1.0"]
    body = _wrap(to_ascii(message.body))
    if not message.attachments:
        head += ["Content-Type: text/plain; charset=us-ascii", "Content-Transfer-Encoding: 7bit"]
        return ("\r\n".join(head) + "\r\n\r\n" + body + "\r\n").encode("ascii")
    boundary = boundary or new_boundary()
    if message.layout == "report":
        head.append(
            f'Content-Type: multipart/report; report-type=feedback-report; boundary="{boundary}"'
        )
    else:
        head.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
    parts = [
        "Content-Type: text/plain; charset=us-ascii\r\n"
        f"Content-Transfer-Encoding: 7bit\r\n\r\n{body}\r\n"
    ]
    if message.layout == "report" and message.feedback is not None:
        parts.append(
            "Content-Type: message/feedback-report\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"
            f"{_wrap(to_ascii(message.feedback))}\r\n"
        )
    parts += [_part(att) for att in message.attachments]
    raw = (
        "\r\n".join(head)
        + "\r\n\r\n"
        + "".join(f"--{boundary}\r\n{p}" for p in parts)
        + f"--{boundary}--\r\n"
    )
    return raw.encode("ascii")


# --- guard glue ----------------------------------------------------------------------------


def guard_message(
    message: RenderedMessage, terms: SelfTerms | None, *, ctx: GuardContext | None = None
) -> GuardResult:
    """Guard every piece of a message: recipient, subject, body, the feedback part and each
    attachment (a JSON report is walked and its base64 values decoded)."""
    parts: list[tuple[str, str | bytes, ArtifactFormat]] = [
        ("to", message.to, "text"),
        ("subject", message.subject, "text"),
        ("body", message.body, "text"),
    ]
    if message.feedback is not None:
        parts.append(("feedback", message.feedback, "text"))
    parts += [(a.name, a.content, _format_of(a)) for a in message.attachments]
    return guard_parts(parts, terms, ctx=ctx)


def _format_of(att: Attachment) -> ArtifactFormat:
    if att.media_type == "text/csv":
        return "csv"
    if att.media_type == JSON_TYPE:
        return "json"  # walked, and every base64 value decoded (``guard.artefact_strings``)
    return "text"


def require_ok(result: GuardResult) -> None:
    """Raise ``GuardFailed`` (reason codes only) unless the guard passed."""
    if not result.ok:
        raise GuardFailed(result.codes)
