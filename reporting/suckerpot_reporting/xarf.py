"""XARF v4 reports, one per subject (design M38, section 4).

``render_xarf_v4`` maps one subject of the evidence to one XARF 4.2.0 report (a plain dict).
``xarf_files`` turns every subject of a mail into a JSON attachment and validates each one
against the vendored schemas before it is returned: an invalid report is a bug and raises
``RenderUnavailable('xarf_invalid')``, never a silent fallback.

What a report never carries: our own address (``destination_ip``), ``evidence_source``,
``confidence``, ``_internal``, host or sensor names, trap pack ids or any local tag. Tags come
from three allow-lists only (services, CVE ids, malware families). Free text is limited to the
owner's own ``xarf_org`` and the reply contact; every other value is built from the evidence.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from typing import Any, Final
from urllib.parse import urlsplit

from .errors import RenderUnavailable
from .evidence import (
    DEFAULT_XARF_USER_AGENT,
    Activity,
    Evidence,
    ReportKind,
    ReportSettings,
    Subject,
)
from .normalize import to_ascii

XARF_VERSION: Final = "4.2.0"
SCHEMA_DIR: Final = "xarf-4.2.0"
MAX_DESCRIPTION: Final = 300
MAX_EVIDENCE_ROWS: Final = 50
MAX_TAGS: Final = 20

# Keys that must never appear in a report, at any depth.
FORBIDDEN_KEYS: Final = frozenset(
    {"destination_ip", "evidence_source", "confidence", "_internal", "legacy_version"}
)

# Allow-lists. Services are the protocol names ``ingest.abuse.ports`` gives an activity;
# families are the network protocol's ``FAMILIES_V1`` without ``generic`` (a test in ingest keeps
# both in step); CVE ids must also have the CVE spelling.
SERVICE_TAGS: Final = frozenset(
    "ssh telnet http https rdp redis docker mysql mssql adb smb sip".split()
)
MALWARE_FAMILIES: Final = frozenset(
    (
        "mirai gafgyt mozi hajime tsunami kaiten xorddos dvrhelper xmrig coinminer "
        "c3rb3r botenago shellbot ddosbot"
    ).split()
)
FILE_TYPES: Final = frozenset(
    (
        "elf-x86 elf-x86_64 elf-arm elf-aarch64 elf-mips elf-ppc elf-other "
        "pe script-sh script-py script-pl script-php archive"
    ).split()
)
_CVE: Final = re.compile(r"^cve-(\d{4})-(\d{4,7})$")
_TAG: Final = re.compile(r"^[a-z0-9][a-z0-9_+-]*:[a-z0-9][a-z0-9_+-]*$")
_MAILBOX: Final = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_DOMAIN: Final = re.compile(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$")
_HTTP_METHODS: Final = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
_WEB: Final = frozenset({"http", "https"})

# One XARF (category, type) per kind of evidence (design M38, section 4.3).
TYPES: Final[dict[str, tuple[str, str]]] = {
    "login": ("connection", "login_attack"),
    "exploit": ("connection", "vulnerability_scan"),
    "sqli": ("connection", "sql_injection"),
    "payload": ("content", "malware"),
    "c2": ("infrastructure", "botnet"),
}


# --- small helpers -------------------------------------------------------------------------


def iso(value: datetime, precision: str) -> str:
    """RFC 3339 in UTC with the report's precision (seconds are zero for ``minute``)."""
    value = value.astimezone(UTC).replace(microsecond=0)
    if precision == "minute":
        value = value.replace(second=0)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def contact_of(settings: ReportSettings) -> tuple[str, str]:
    """``(contact, domain)`` from the reply contact: its first mailbox, lower-case domain."""
    found = _MAILBOX.search(to_ascii((settings.reply_contact or "").strip()))
    if found is None:
        raise RenderUnavailable("reply_contact_not_email")
    contact = found.group(0)
    return contact, contact.rpartition("@")[2].lower()


def org_of(settings: ReportSettings, domain: str) -> str:
    org = to_ascii((settings.xarf_org or "").strip())
    return re.sub(r"[\r\n\t]+", " ", org)[:100] if org else domain


def user_agent_of(settings: ReportSettings) -> str:
    """The ``User-Agent`` of the feedback part: the owner's value, else ``Mozilla/5.0``."""
    value = re.sub(r"[\r\n\t]+", " ", to_ascii((settings.xarf_user_agent or "").strip()))
    return value[:64] or DEFAULT_XARF_USER_AGENT


def cve_id(tag: str) -> str | None:
    """``cve-2021-44228`` -> ``CVE-2021-44228`` (None for anything else)."""
    m = _CVE.fullmatch(tag)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _host_of(subject: Subject) -> str:
    if subject.type == "url":
        try:
            return (urlsplit(subject.value).hostname or subject.value).lower()
        except ValueError:
            return subject.value
    return subject.value.lower() if subject.type == "domain" else subject.value


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _span(subject: Subject) -> str:
    start = subject.first_ts.astimezone(UTC).strftime("%Y-%m-%d %H:%M")
    end = subject.last_ts.astimezone(UTC)
    same_day = end.date() == subject.first_ts.astimezone(UTC).date()
    return f"{start} to {end.strftime('%H:%M' if same_day else '%Y-%m-%d %H:%M')} UTC"


def _services(acts: tuple[Activity, ...]) -> list[str]:
    out: list[str] = []
    for a in sorted(acts, key=lambda x: x.ts):
        if a.service in SERVICE_TAGS and a.service not in out:
            out.append(a.service)
    return out


def _cves(acts: tuple[Activity, ...]) -> list[str]:
    out: list[str] = []
    for a in acts:
        for tag in a.cves:
            if _CVE.fullmatch(tag) and tag not in out:
                out.append(tag)
    return sorted(out)


def _families(subject: Subject) -> list[str]:
    out: list[str] = []
    for s in subject.samples:
        fam = (s.family or "").strip().lower()
        if fam in MALWARE_FAMILIES and fam not in out:
            out.append(fam)
    return out


def tags_of(subject: Subject) -> list[str]:
    """Tags from the allow-lists only, sorted, at most ``MAX_TAGS``."""
    tags = {f"service:{s}" for s in _services(subject.activities)}
    tags |= {f"cve:{c}" for c in _cves(subject.activities)}
    tags |= {f"malware:{f}" for f in _families(subject)}
    return sorted(t for t in tags if _TAG.fullmatch(t))[:MAX_TAGS]


def activity_class(kind: ReportKind, subject: Subject) -> str:
    """Which XARF type one subject gets. SQL injection, then exploit, win over login."""
    if kind == "payload_host":
        return "payload"
    if kind == "c2":
        return "c2"
    acts = subject.activities
    if any(a.sqli for a in acts):
        return "sqli"
    if any(a.action == "exploit_attempt" or a.cves for a in acts):
        return "exploit"
    return "login"


# --- the evidence item ---------------------------------------------------------------------


def evidence_item(csv_rows: str) -> dict[str, Any]:
    """The subject's own CSV rows as one base64 evidence item, with its hash and size."""
    data = csv_rows.encode("ascii")
    return {
        "content_type": "text/csv",
        "description": "Log lines (UTC)",
        "payload": base64.b64encode(data).decode("ascii"),
        "hash": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def _csv_of(evidence: Evidence, subject: Subject) -> str:
    from .message import render_csv  # late: message imports this module

    single = evidence.model_copy(update={"subjects": (subject,)})
    lines = render_csv(single).content.split("\r\n")
    head, rows = lines[0], [line for line in lines[1:] if line]
    return "\r\n".join([head, *rows[:MAX_EVIDENCE_ROWS]]) + "\r\n"


# --- the description -----------------------------------------------------------------------


def _count(acts: tuple[Activity, ...], *actions: str) -> int:
    return sum(a.count for a in acts if a.action in actions)


def description_of(kind: ReportKind, subject: Subject) -> str:
    acts = subject.activities
    services = ", ".join(s.upper() for s in _services(acts))
    on = f" on {services}" if services else ""
    if kind == "payload_host":
        n = _count(acts, "download")
        what = _plural(n, "download", "downloads") if n else "Downloads"
        text = f"{what} of a malware file from this host, {_span(subject)}"
    elif kind == "c2":
        n = len(subject.samples)
        head = (
            f"{n} malware samples use this address as their command server"
            if n > 1
            else "A malware sample uses this address as its command server"
        )
        text = f"{head}, {_span(subject)}"
    else:
        parts = []
        if logins := _count(acts, "failed_logins"):
            parts.append(_plural(logins, "login attempt", "login attempts"))
        if commands := _count(acts, "login_then_commands", "command"):
            parts.append(_plural(commands, "command", "commands"))
        if downloads := _count(acts, "download"):
            parts.append(_plural(downloads, "download command", "download commands"))
        if exploits := _count(acts, "exploit_attempt"):
            parts.append(_plural(exploits, "exploit attempt", "exploit attempts"))
        head = ", ".join(parts) or _plural(max(1, subject.events), "event", "events")
        text = f"{head[0].upper()}{head[1:]}{on}, {_span(subject)}"
    return to_ascii(text)[:MAX_DESCRIPTION]


# --- one report ----------------------------------------------------------------------------


def _first(acts: tuple[Activity, ...], pred: Any = None) -> Activity | None:
    for a in sorted(acts, key=lambda x: x.ts):
        if pred is None or pred(a):
            return a
    return None


def _protocol(acts: tuple[Activity, ...]) -> str:
    protos = {a.protocol for a in acts}
    return protos.pop() if len(protos) == 1 else "tcp"


def _payload_url(subject: Subject, host: str) -> str:
    """The URL that served the file: the first download line on this host, else ``http://host/``."""
    for a in sorted(subject.activities, key=lambda x: x.ts):
        if a.action != "download" or not a.text:
            continue
        candidate = a.text.strip().split()[0] if a.text.strip() else ""
        try:
            parts = urlsplit(candidate)
        except ValueError:
            continue
        if parts.scheme in _WEB and (parts.hostname or "").lower() == host.lower():
            return to_ascii(candidate)[:1024]
    shown = f"[{host}]" if ":" in host else host
    return f"http://{shown}/"


def render_xarf_v4(
    evidence: Evidence, settings: ReportSettings, subject: Subject
) -> dict[str, Any]:
    """One XARF 4.2.0 report for one subject. Pure and deterministic for a given evidence."""
    if subject.xarf_id is None:
        raise RenderUnavailable("xarf_id_missing")
    kind = evidence.kind_of(subject)
    contact, domain = contact_of(settings)
    party = {"org": org_of(settings, domain), "contact": contact, "domain": domain}
    precision = evidence.options.time_precision
    acts = subject.activities
    host = _host_of(subject)
    cls = activity_class(kind, subject)
    category, xarf_type = TYPES[cls]
    report: dict[str, Any] = {
        "xarf_version": XARF_VERSION,
        "report_id": str(subject.xarf_id),
        "timestamp": iso(subject.first_ts, precision),
        "reporter": dict(party),
        "sender": dict(party),
        "source_identifier": host,
        "category": category,
        "type": xarf_type,
    }
    if kind == "attack_source":
        first_port = _first(acts, lambda a: 1 <= a.src_port <= 65535)
        if first_port is not None:
            report["source_port"] = first_port.src_port
        report["protocol"] = _protocol(acts)
        report["first_seen"] = iso(subject.first_ts, precision)
        report["last_seen"] = iso(subject.last_ts, precision)
        if cls == "login":
            target = _first(acts, lambda a: 1 <= a.dst_port <= 65535)
            if target is not None:
                report["destination_port"] = target.dst_port
        elif cls == "sqli":
            hits = tuple(a for a in acts if a.sqli)
            target = _first(hits, lambda a: 1 <= a.dst_port <= 65535)
            if target is not None:
                report["destination_port"] = target.dst_port
            first_hit = _first(hits)
            method = (first_hit.text or "").split(" ", 1)[0].upper() if first_hit else ""
            if method in _HTTP_METHODS:
                report["http_method"] = method
            report["attempts_count"] = max(1, sum(a.count for a in hits))
        else:  # exploit
            hits = tuple(a for a in acts if a.action == "exploit_attempt" or a.cves) or acts
            web = all(a.service in _WEB for a in hits) if hits else False
            report["scan_type"] = "web_vuln_scan" if web else "mixed"
            protos = {a.protocol for a in acts}
            report["protocol"] = protos.pop() if len(protos) == 1 else "mixed"
            ports = sorted({a.dst_port for a in hits if 1 <= a.dst_port <= 65535})
            if ports:
                report["targeted_ports"] = ports[:20]
            cves = [c for c in (cve_id(t) for t in _cves(acts)) if c]
            if cves:
                report["vulnerabilities_probed"] = cves
            report["total_requests"] = max(1, sum(a.count for a in hits))
            agent = _first(hits, lambda a: bool(a.user_agent))
            if agent is not None and agent.user_agent:
                report["user_agent"] = to_ascii(agent.user_agent)
    elif kind == "payload_host":
        report["url"] = _payload_url(subject, host)
        if subject.type == "domain" and _DOMAIN.fullmatch(host):
            report["domain"] = host
        report["malware_type"] = "other"
        report["distribution_method"] = "direct_download"
        families = _families(subject)
        if families:
            report["malware_family"] = families[0]
        sample = subject.samples[0] if subject.samples else None
        if sample is not None:
            report["file_hashes"] = {"sha256": sample.sha256}
            ftype = (sample.kind or "").lower()
            if sample.arch and ftype == "elf":
                ftype = f"elf-{sample.arch.lower()}"
            if ftype in FILE_TYPES:
                report["file_metadata"] = {"file_type": ftype}
    else:  # c2
        sample = subject.samples[0] if subject.samples else None
        report["compromise_evidence"] = (
            f"A malware sample (sha256 {sample.sha256}) uses this address as its command server."
            if sample is not None
            else "A malware sample uses this address as its command server."
        )
        families = _families(subject)
        if families:
            report["malware_family"] = families[0]
    report["description"] = description_of(kind, subject)
    report["evidence"] = [evidence_item(_csv_of(evidence, subject))]
    tags = tags_of(subject)
    if tags:
        report["tags"] = tags
    _refuse_forbidden(report)
    return report


def _refuse_forbidden(node: object) -> None:
    if isinstance(node, Mapping):
        for k, v in node.items():
            if k in FORBIDDEN_KEYS:
                raise RenderUnavailable("xarf_invalid")
            _refuse_forbidden(v)
    elif isinstance(node, list):
        for item in node:
            _refuse_forbidden(item)


def dumps(report: Mapping[str, Any]) -> str:
    """The exact JSON text that is sent: ASCII, two-space indent, key order kept, LF ends."""
    return json.dumps(report, ensure_ascii=True, indent=2) + "\n"


def file_names(count: int) -> list[str]:
    """``xarf.json`` for one subject; ``xarf-001.json`` ... for several (design M38, D2)."""
    if count == 1:
        return ["xarf.json"]
    return [f"xarf-{i:03d}.json" for i in range(1, count + 1)]


# --- schema validation ---------------------------------------------------------------------


@lru_cache(maxsize=1)
def _validators() -> tuple[Any, dict[str, Any]]:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    root = resources.files(__package__).joinpath("schemas", SCHEMA_DIR)
    docs: list[dict[str, Any]] = [
        json.loads(root.joinpath("xarf-core.json").read_text("utf-8")),
        json.loads(root.joinpath("xarf-v4-master.json").read_text("utf-8")),
    ]
    types_dir = root.joinpath("types")
    for entry in sorted(types_dir.iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".json"):
            docs.append(json.loads(entry.read_text("utf-8")))
    registry: Registry[Any] = Registry().with_resources(
        (d["$id"], Resource.from_contents(d)) for d in docs
    )
    checker = Draft202012Validator.FORMAT_CHECKER
    by_id = {d["$id"]: d for d in docs}
    master = Draft202012Validator(
        by_id["https://xarf.org/schemas/v4/xarf-v4-master.json"],
        registry=registry,
        format_checker=checker,
    )
    typed = {
        doc_id.rsplit("/", 1)[1].removesuffix(".json"): Draft202012Validator(
            doc, registry=registry, format_checker=checker
        )
        for doc_id, doc in by_id.items()
        if "/types/" in doc_id
    }
    return master, typed


_TYPE_FILE: Final = {
    ("connection", "login_attack"): "connection-login-attack",
    ("connection", "vulnerability_scan"): "connection-vulnerability-scan",
    ("connection", "sql_injection"): "connection-sql-injection",
    ("content", "malware"): "content-malware",
    ("infrastructure", "botnet"): "infrastructure-botnet",
}
_UUID4: Final = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TIME: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def schema_errors(report: Mapping[str, Any]) -> list[str]:
    """Where a report breaks the vendored 4.2.0 schemas (JSON paths only, never values).

    The master schema and the type schema both apply, plus checks the format checker leaves
    out without optional packages: a UUID v4 ``report_id`` and UTC ``date-time`` values."""
    master, typed = _validators()
    errors = {"/".join(str(p) for p in e.absolute_path) or "$" for e in master.iter_errors(report)}
    name = _TYPE_FILE.get((str(report.get("category")), str(report.get("type"))))
    if name is None:
        errors.add("type")
    else:
        errors |= {
            "/".join(str(p) for p in e.absolute_path) or "$"
            for e in typed[name].iter_errors(report)
        }
    if not _UUID4.fullmatch(str(report.get("report_id", ""))):
        errors.add("report_id")
    for key in ("timestamp", "first_seen", "last_seen"):
        if key in report and not _TIME.fullmatch(str(report[key])):
            errors.add(key)
    try:
        _refuse_forbidden(report)
    except RenderUnavailable:
        errors.add("forbidden_key")
    return sorted(errors)


def xarf_reports(evidence: Evidence, settings: ReportSettings) -> list[dict[str, Any]]:
    """One validated report per subject, in subject order. Raises ``xarf_invalid``."""
    out: list[dict[str, Any]] = []
    for subject in evidence.subjects:
        report = render_xarf_v4(evidence, settings, subject)
        if schema_errors(report):
            raise RenderUnavailable("xarf_invalid")
        out.append(report)
    return out


def feedback_report(settings: ReportSettings) -> str:
    """The ``message/feedback-report`` part of a one-source mail (RFC 6522 with XARF)."""
    return f"Feedback-Type: xarf\nUser-Agent: {user_agent_of(settings)}\nVersion: 1\n"


def new_xarf_id() -> uuid.UUID:
    """A fresh random UUID v4 for one subject of one mail, unrelated to every other id."""
    return uuid.uuid4()
