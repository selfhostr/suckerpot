"""The shared directory of abuse forms and the copy kit (design M38, section 6).

Some abuse desks take reports only through a web form. The node never submits a form (N1): it
prepares a copy kit, one field at a time, and the owner pastes it in by hand.

**The directory** is data only. Its source is ``reporting/forms/abuse-forms.yaml``; a maintainer
compiles it to ``data/abuse-forms.json`` inside this package (``python -m
suckerpot_reporting.forms compile``), and the JSON ships with each release in the ingest and API
images. ``validate`` is strict, so a bad entry fails CI and is refused at load time:

* ``form_url`` is ``https``, on a host equal to or under one of the entry's ``official_domains``,
  with no IP literal, no user info, no port, no fragment, no ``;`` or ``=`` in the path, at most
  300 characters, and no query string except one allow-listed ``lang`` parameter. A link with a
  token or a session in it cannot pass.
* every text is short, single-line and free of ``<`` and ``>``; unknown keys are refused.

**The kit** is built from the stored evidence with the same labels as the mail, never from the
owner's intro. Every field passes the identity guard on its own and the whole kit once more
(``guard_kit``); a blocked kit is never returned.

A form link learned from a reply is untrusted: nothing here writes the directory, and the
directory only changes through a reviewed pull request.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from .evidence import MAX_ACTIVITIES_CSV, Activity, Evidence, ReportSettings, Subject
from .guard import ArtifactFormat, GuardContext, GuardResult, guard, guard_parts
from .message import (
    _LABELS,
    Attachment,
    ReferenceStyle,
    _activity_lines,
    _heading,
    _ports,
    _reference,
    _text,
    fmt_ts,
    port_label,
    render_csv,
)
from .normalize import to_ascii
from .terms import PROJECT_TERMS, SelfTerms
from .xarf import contact_of

# The project name lives in ``terms`` only (static test): the schema id is built from it.
SCHEMA: Final = f"{PROJECT_TERMS[0]}-abuse-forms/1"
BUNDLED: Final = "data/abuse-forms.json"
# The fields of the kit. A directory entry may give the form's own label for any of them.
KIT_FIELDS: Final = (
    "form",
    "email",
    "name",
    "abuse_type",
    "addresses",
    "first_seen",
    "last_seen",
    "description",
    "log_excerpt",
    "evidence",
)
# What a source did, in our words. A directory entry maps these to the form's own options.
AbuseType = Literal["login_attack", "exploit", "malware", "c2"]
ABUSE_TYPES: Final[tuple[AbuseType, ...]] = ("login_attack", "exploit", "malware", "c2")
TYPE_LABELS: Final[dict[str, str]] = {
    "login_attack": "Login attack",
    "exploit": "Exploit attempt",
    "malware": "Malware download",
    "c2": "Command server",
}
FILE_TYPES: Final = ("csv", "txt")
DEFAULT_MAX_CHARS: Final = 1000
MIN_MAX_CHARS: Final = 200
MAX_MAX_CHARS: Final = 10_000
MAX_URL: Final = 300
STALE_AFTER: Final = timedelta(days=365)
FRESH: Final = timedelta(days=7)
EXCERPT_LINES: Final = 20
SHORT_ACTIVITIES: Final = 3
MAX_ENTRIES: Final = 2000

_SLUG: Final = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_LABEL: Final = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TLD: Final = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_LANG: Final = re.compile(r"^lang=[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8})?$")
_PATH: Final = re.compile(r"^[A-Za-z0-9\-._~/%]*$")
_ENTRY_KEYS: Final = frozenset(
    {
        "id",
        "provider",
        "match",
        "official_domains",
        "form_url",
        "accepts_mail",
        "xarf",
        "one_ip_per_submission",
        "file_types",
        "max_chars",
        "fields",
        "source",
        "verified_on",
    }
)
_REQUIRED: Final = frozenset(
    {"id", "provider", "match", "official_domains", "form_url", "accepts_mail", "source"}
)
_MATCH_KEYS: Final = frozenset({"mailbox_domains", "asns"})
_FIELD_KEYS: Final = frozenset({"key", "label", "choices", "selector"})
# The kit fields the browser fill helper may write into a form (never the form link or a file).
FILL_KEYS: Final = (
    "email",
    "name",
    "abuse_type",
    "addresses",
    "first_seen",
    "last_seen",
    "description",
    "log_excerpt",
)
# A CSS selector of the form's own field, as a maintainer read it on the form (optional). Plain
# selector characters only: no quotes that could close an attribute, no braces, no backslash.
_SELECTOR: Final = re.compile(r"^[A-Za-z0-9_#.\[\]=:>+~*^$|(), -]{1,200}$")
# Marks the fill data the helper reads. Neutral on purpose: the provider's page can see it.
FILL_FORMAT: Final = "formfill/1"


class DirectoryError(ValueError):
    """The directory does not validate. ``problems`` names each problem (entry id and field)."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = tuple(problems)


# --- validation --------------------------------------------------------------------------


def valid_domain(value: object) -> bool:
    """A lower-case DNS name with at least two labels and an alphabetic top-level label."""
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.lower():
        return False
    labels = value.split(".")
    if len(labels) < 2 or not _TLD.match(labels[-1]):
        return False
    return all(_LABEL.match(label) for label in labels)


def in_domains(host: str, domains: Iterable[str]) -> bool:
    """``host`` is one of ``domains`` or a name below one of them."""
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def _ip_literal(host: str) -> bool:
    if host.startswith("["):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def url_problem(url: object, domains: Iterable[str], *, allow_lang: bool = True) -> str | None:
    """Why ``url`` may not be a form link for a provider with these official domains, or None.

    The rules of design M38, section 6.5: ``https``, the host equal to or under an official
    domain, no IP literal, no user info, at most 300 characters, and no query string except one
    allow-listed ``lang`` parameter. Also refused: a port, a fragment, and ``;`` or ``=`` in the
    path (where a session id would hide)."""
    if not isinstance(url, str):
        return "not_a_string"
    if len(url) > MAX_URL:
        return "too_long"
    if not url.isascii() or not url.isprintable() or any(c in url for c in " \\\"'<>`{}|^"):
        return "bad_characters"
    if not url.startswith("https://"):
        return "not_https"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "unparsable"
    netloc = parts.netloc
    if "@" in netloc:
        return "user_info"
    if ":" in netloc.lstrip("[").split("]")[-1] or netloc.startswith("["):
        return "ip_literal" if netloc.startswith("[") else "port"
    host = netloc
    if _ip_literal(host.lower()):
        return "ip_literal"
    if not valid_domain(host):
        return "bad_host"
    if not in_domains(host, domains):
        return "foreign_host"
    if parts.fragment or "#" in url:
        return "fragment"
    if not _PATH.match(parts.path):
        return "bad_path"
    if parts.query or "?" in url:
        if not (allow_lang and _LANG.match(parts.query)):
            return "query_string"
    return None


def _text_problem(value: object, *, low: int = 1, high: int = 80) -> str | None:
    if not isinstance(value, str):
        return "not_a_string"
    if not low <= len(value) <= high:
        return "length"
    if not value.isprintable() or any(c in value for c in "<>\r\n\t"):
        return "bad_characters"
    if value != value.strip():
        return "spaces"
    return None


@dataclass(frozen=True)
class FormField:
    key: str
    label: str
    choices: Mapping[str, str] = field(default_factory=dict)
    # The form's own field for this key, for the browser fill helper; None: found by its label.
    selector: str | None = None


@dataclass(frozen=True)
class FormEntry:
    id: str
    provider: str
    mailbox_domains: tuple[str, ...]
    asns: tuple[int, ...]
    official_domains: tuple[str, ...]
    form_url: str
    accepts_mail: bool | Literal["ignored"]
    source: str
    verified_on: date
    xarf: Literal["unknown", "accepted", "strict"] = "unknown"
    one_ip_per_submission: bool = False
    file_types: tuple[str, ...] = ("csv",)
    max_chars: int = DEFAULT_MAX_CHARS
    fields: tuple[FormField, ...] = ()

    @property
    def form_only(self) -> bool:
        """``accepts_mail: false`` or ``ignored``: the desk goes to the form queue (D13)."""
        return self.accepts_mail is not True

    def label_of(self, key: str) -> str | None:
        return next((f.label for f in self.fields if f.key == key), None)

    def choice_of(self, abuse_type: str) -> str | None:
        for f in self.fields:
            if f.key == "abuse_type" and abuse_type in f.choices:
                return f.choices[abuse_type]
        return None

    def stale(self, today: date) -> bool:
        """Last checked more than a year ago: the kit says so."""
        return today - self.verified_on > STALE_AFTER

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "provider": self.provider,
            "match": {"mailbox_domains": list(self.mailbox_domains), "asns": list(self.asns)},
            "official_domains": list(self.official_domains),
            "form_url": self.form_url,
            "accepts_mail": self.accepts_mail,
            "xarf": self.xarf,
            "one_ip_per_submission": self.one_ip_per_submission,
            "file_types": list(self.file_types),
            "max_chars": self.max_chars,
            "fields": [
                {"key": f.key, "label": f.label, "choices": dict(sorted(f.choices.items()))}
                | ({"selector": f.selector} if f.selector else {})
                for f in self.fields
            ],
            "source": self.source,
            "verified_on": self.verified_on.isoformat(),
        }
        return out


@dataclass(frozen=True)
class Directory:
    entries: tuple[FormEntry, ...] = ()

    def by_id(self, entry_id: str | None) -> FormEntry | None:
        return next((e for e in self.entries if e.id == entry_id), None)

    def match(
        self, mailbox_domain: str | None, asns: Iterable[int | None] = ()
    ) -> FormEntry | None:
        """The entry of a recipient: its exact mailbox domain first; else the ASN of a subject,
        but only for an entry whose official domains hold the mailbox domain (an ASN alone never
        routes a desk: a network can carry customers whose abuse desk is not the provider's)."""
        domain = (mailbox_domain or "").strip().lower()
        if not domain:
            return None
        for e in self.entries:
            if domain in e.mailbox_domains:
                return e
        wanted = {a for a in asns if isinstance(a, int)}
        if wanted:
            for e in self.entries:
                if wanted.intersection(e.asns) and in_domains(domain, e.official_domains):
                    return e
        return None

    def stale_entries(self, today: date) -> tuple[FormEntry, ...]:
        return tuple(e for e in self.entries if e.stale(today))

    def to_json(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "entries": [e.to_json() for e in self.entries]}


def _as_date(value: object) -> date | None:
    if isinstance(value, datetime):
        return None
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _entry(raw: object, index: int, today: date, problems: list[str]) -> FormEntry | None:
    where = f"entries[{index}]"
    if not isinstance(raw, dict):
        problems.append(f"{where}: not a mapping")
        return None
    entry_id = raw.get("id")
    if isinstance(entry_id, str) and _SLUG.match(entry_id):
        where = entry_id
    else:
        problems.append(f"{where}.id: not a slug")
    before = len(problems)
    unknown = sorted(str(k) for k in raw if k not in _ENTRY_KEYS)
    if unknown:
        problems.append(f"{where}: unknown keys {', '.join(unknown)}")
    missing = sorted(_REQUIRED - set(raw))
    if missing:
        problems.append(f"{where}: missing {', '.join(missing)}")
        return None
    if (p := _text_problem(raw["provider"])) is not None:
        problems.append(f"{where}.provider: {p}")
    official = raw["official_domains"]
    if (
        not isinstance(official, list)
        or not 1 <= len(official) <= 5
        or not all(valid_domain(d) for d in official)
        or len(set(official)) != len(official)
    ):
        problems.append(f"{where}.official_domains: 1 to 5 distinct lower-case domains")
        official = []
    match = raw["match"]
    boxes: list[str] = []
    asns: list[int] = []
    if not isinstance(match, dict) or set(match) - _MATCH_KEYS:
        problems.append(f"{where}.match: only mailbox_domains and asns")
    else:
        boxes = match.get("mailbox_domains") or []
        asns = match.get("asns") or []
        if (
            not isinstance(boxes, list)
            or len(boxes) > 10
            or not all(valid_domain(d) for d in boxes)
            or len(set(boxes)) != len(boxes)
        ):
            problems.append(f"{where}.match.mailbox_domains: 0 to 10 distinct domains")
            boxes = []
        if (
            not isinstance(asns, list)
            or len(asns) > 50
            or not all(
                isinstance(a, int) and not isinstance(a, bool) and 1 <= a <= 4_294_967_295
                for a in asns
            )
            or len(set(asns)) != len(asns)
        ):
            problems.append(f"{where}.match.asns: 0 to 50 distinct ASNs")
            asns = []
        if not boxes and not asns:
            problems.append(f"{where}.match: at least one mailbox domain or ASN")
    if (p := url_problem(raw["form_url"], official)) is not None:
        problems.append(f"{where}.form_url: {p}")
    accepts = raw["accepts_mail"]
    if not (accepts is True or accepts is False or accepts == "ignored"):
        problems.append(f"{where}.accepts_mail: true, false or ignored")
    xarf = raw.get("xarf", "unknown")
    if xarf not in ("unknown", "accepted", "strict"):
        problems.append(f"{where}.xarf: unknown, accepted or strict")
    one_ip = raw.get("one_ip_per_submission", False)
    if not isinstance(one_ip, bool):
        problems.append(f"{where}.one_ip_per_submission: a boolean")
    file_types = raw.get("file_types", ["csv"])
    if (
        not isinstance(file_types, list)
        or not file_types
        or not all(t in FILE_TYPES for t in file_types)
        or len(set(file_types)) != len(file_types)
    ):
        problems.append(f"{where}.file_types: a non-empty list of csv, txt")
        file_types = ["csv"]
    max_chars = raw.get("max_chars", DEFAULT_MAX_CHARS)
    if (
        not isinstance(max_chars, int)
        or isinstance(max_chars, bool)
        or not MIN_MAX_CHARS <= max_chars <= MAX_MAX_CHARS
    ):
        problems.append(f"{where}.max_chars: {MIN_MAX_CHARS} to {MAX_MAX_CHARS}")
    fields_raw = raw.get("fields", [])
    fields: list[FormField] = []
    if not isinstance(fields_raw, list) or len(fields_raw) > 20:
        problems.append(f"{where}.fields: at most 20")
        fields_raw = []
    for i, f in enumerate(fields_raw):
        at = f"{where}.fields[{i}]"
        if not isinstance(f, dict) or set(f) - _FIELD_KEYS or "key" not in f or "label" not in f:
            problems.append(f"{at}: key, label and optional choices")
            continue
        if f["key"] not in KIT_FIELDS:
            problems.append(f"{at}.key: one of {', '.join(KIT_FIELDS)}")
            continue
        if any(x.key == f["key"] for x in fields):
            problems.append(f"{at}.key: repeated")
            continue
        if (p := _text_problem(f["label"])) is not None:
            problems.append(f"{at}.label: {p}")
            continue
        choices = f.get("choices", {}) or {}
        if not isinstance(choices, dict) or (choices and f["key"] != "abuse_type"):
            problems.append(f"{at}.choices: a mapping, for abuse_type only")
            continue
        bad = [
            str(k)
            for k, v in choices.items()
            if k not in ABUSE_TYPES or _text_problem(v) is not None
        ]
        if bad:
            problems.append(f"{at}.choices: {', '.join(sorted(bad))}")
            continue
        selector = f.get("selector")
        if selector is not None and (
            f["key"] not in FILL_KEYS
            or not isinstance(selector, str)
            or not _SELECTOR.match(selector)
            or selector != selector.strip()
        ):
            problems.append(f"{at}.selector: a plain CSS selector, for a field the helper fills")
            continue
        fields.append(FormField(f["key"], f["label"], dict(choices), selector))
    source = raw["source"]
    if (p := url_problem(source, official, allow_lang=False)) is not None:
        problems.append(f"{where}.source: {p}")
    verified = _as_date(raw.get("verified_on"))
    if verified is None:
        problems.append(f"{where}.verified_on: a date (YYYY-MM-DD)")
    elif verified > today:
        problems.append(f"{where}.verified_on: in the future")
    if len(problems) > before or verified is None:
        return None
    return FormEntry(
        id=str(entry_id),
        provider=str(raw["provider"]),
        mailbox_domains=tuple(boxes),
        asns=tuple(asns),
        official_domains=tuple(official),
        form_url=str(raw["form_url"]),
        accepts_mail=accepts,
        source=str(source),
        verified_on=verified,
        xarf=xarf,
        one_ip_per_submission=bool(one_ip),
        file_types=tuple(file_types),
        max_chars=int(max_chars),
        fields=tuple(fields),
    )


def validate(doc: object, today: date | None = None) -> Directory:
    """The directory, or ``DirectoryError`` naming every problem. Nothing is accepted in part."""
    today = today or datetime.now(UTC).date()
    problems: list[str] = []
    if not isinstance(doc, dict) or set(doc) != {"schema", "entries"}:
        raise DirectoryError(["the document has exactly two keys: schema and entries"])
    if doc["schema"] != SCHEMA:
        raise DirectoryError([f"schema: {SCHEMA}"])
    raw = doc["entries"]
    if raw is None:
        raw = []
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise DirectoryError([f"entries: a list of at most {MAX_ENTRIES}"])
    entries = [e for i, item in enumerate(raw) if (e := _entry(item, i, today, problems))]
    seen_ids: set[str] = set()
    seen_boxes: dict[str, str] = {}
    for e in entries:
        if e.id in seen_ids:
            problems.append(f"{e.id}: repeated id")
        seen_ids.add(e.id)
        for box in e.mailbox_domains:
            if box in seen_boxes:
                problems.append(f"{e.id}: mailbox domain {box} also in {seen_boxes[box]}")
            seen_boxes[box] = e.id
    if problems:
        raise DirectoryError(problems)
    return Directory(tuple(entries))


def load_text(text: str, today: date | None = None) -> Directory:
    """A directory from the compiled JSON."""
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise DirectoryError(["not valid JSON"]) from exc
    return validate(doc, today)


@lru_cache(maxsize=1)
def bundled() -> Directory:
    """The directory shipped in this package (validated; ``DirectoryError`` when it does not)."""
    text = resources.files("suckerpot_reporting").joinpath(BUNDLED).read_text(encoding="utf-8")
    return load_text(text)


def dumps(directory: Directory) -> str:
    """The compiled JSON: stable bytes, so CI can compare it with the committed file."""
    return json.dumps(directory.to_json(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


# --- the copy kit ---------------------------------------------------------------------------


def abuse_type_of(evidence: Evidence, subject: Subject) -> AbuseType:
    kind = evidence.kind_of(subject)
    if kind == "payload_host":
        return "malware"
    if kind == "c2":
        return "c2"
    if any(a.sqli or a.cves or a.action == "exploit_attempt" for a in subject.activities):
        return "exploit"
    return "login_attack"


def _details(act: Activity, evidence: Evidence) -> str:
    opts = evidence.options
    parts = [_LABELS[act.action]]
    if act.action == "failed_logins":
        parts[0] += f": {act.count}"
    if opts.include_usernames and act.usernames:
        parts.append("users: " + ",".join(act.usernames))
    if act.text:
        parts.append(_text(act.text, opts).replace("\n", " "))
    if act.user_agent:
        parts.append("UA: " + _text(act.user_agent, opts))
    return "; ".join(parts)


def evidence_lines(evidence: Evidence, subject: Subject, limit: int) -> list[str]:
    """Evidence lines of one source, oldest first: time, source (and source port), our port and
    service, what happened. Never the destination address."""
    opts = evidence.options
    out: list[str] = []
    for act in sorted(subject.activities, key=lambda a: a.ts)[:limit]:
        src = subject.value if subject.type != "url" else _text(subject.value, opts)
        if subject.type == "ip" and 1 <= act.src_port <= 65535:
            src = f"[{src}]:{act.src_port}" if ":" in src else f"{src}:{act.src_port}"
        out.append(
            to_ascii(f"{fmt_ts(act.ts, opts)} {src} {port_label(act)} {_details(act, evidence)}")
        )
    if not out:
        out.append(to_ascii(f"{fmt_ts(subject.first_ts, opts)} {_text(subject.value, opts)}"))
    return out


def _short_block(evidence: Evidence, subject: Subject) -> list[str]:
    """The source as the mail shows it, with fewer lines: heading, span and ports, and its first
    activities (the same labels as the mail)."""
    opts = evidence.options
    lines = [_heading(subject, opts)]
    span = f"{fmt_ts(subject.first_ts, opts)} to {fmt_ts(subject.last_ts, opts)}"
    ports = _ports(subject)
    lines.append(f"  {span}, {ports}" if ports else f"  {span}")
    acts = sorted(subject.activities, key=lambda a: a.ts)
    multi = len({port_label(a) for a in acts}) > 1
    for act in acts[:SHORT_ACTIVITIES]:
        for line in _activity_lines(act, opts, multi)[:2]:
            lines.append(line[:200])
    return [to_ascii(line) for line in lines]


def _more(n: int, file_name: str) -> str:
    return f"({n} more in {file_name})"


def describe(
    evidence: Evidence,
    subjects: Sequence[Subject],
    *,
    max_chars: int,
    reference: str | None,
    file_name: str,
) -> str:
    """The short description of a form: each source as the mail shows it, as many as fit in
    ``max_chars``, a count of the others, and ``ref <token>`` as the last line so a reply can be
    matched."""
    tail = f"ref {reference}" if reference else None
    budget = max_chars - (len(tail) + 1 if tail else 0)
    out: list[str] = []
    shown = 0
    for subject in subjects:
        block = _short_block(evidence, subject)
        left = len(subjects) - shown - 1
        reserve = len(_more(left, file_name)) + 1 if left else 0
        if len("\n".join(out + block)) + reserve > budget:
            if not out:  # the first source alone is too long: its heading and time span
                out = [line[: budget // 3] for line in block[:2]]
                shown = 1
            break
        out.extend(block)
        shown += 1
    left = len(subjects) - shown
    if left:
        out.append(_more(left, file_name))
    text = "\n".join(out)[:budget].rstrip()
    return f"{text}\n{tail}" if tail else text


@dataclass(frozen=True)
class KitSource:
    kind: str
    type: str
    value: str
    abuse_type: str
    first_seen: str
    last_seen: str
    description: str
    log_excerpt: str
    stale: bool
    type_key: str = "login_attack"  # our abuse type (``ABUSE_TYPES``), for the fill helper
    fill: str = ""  # the fill data of this source alone (one address per submission)


@dataclass(frozen=True)
class Kit:
    email: str
    name: str
    abuse_type: str
    addresses: str
    first_seen: str
    last_seen: str
    description: str
    log_excerpt: str
    evidence: Attachment
    sources: tuple[KitSource, ...]
    one_ip_per_submission: bool
    max_chars: int
    labels: Mapping[str, str]
    type_key: str = "login_attack"  # the main abuse type, ours (``ABUSE_TYPES``)
    fill: str = ""  # the fill data of the whole kit (``fill_data``)

    def fills(self) -> list[tuple[str, str]]:
        """The fill data of the kit and of each source, by name (JSON)."""
        out = [("fill", self.fill)] if self.fill else []
        out += [(f"sources[{i}].fill", s.fill) for i, s in enumerate(self.sources) if s.fill]
        return out

    def texts(self) -> list[tuple[str, str]]:
        """Every text field of the kit, by name, as the owner can copy it."""
        out = [
            ("email", self.email),
            ("name", self.name),
            ("abuse_type", self.abuse_type),
            ("addresses", self.addresses),
            ("first_seen", self.first_seen),
            ("last_seen", self.last_seen),
            ("description", self.description),
            ("log_excerpt", self.log_excerpt),
        ]
        for i, s in enumerate(self.sources):
            out += [
                (f"sources[{i}].value", s.value),
                (f"sources[{i}].abuse_type", s.abuse_type),
                (f"sources[{i}].description", s.description),
                (f"sources[{i}].log_excerpt", s.log_excerpt),
            ]
        out += [(f"labels.{k}", v) for k, v in sorted(self.labels.items())]
        return out


def fill_data(values: Mapping[str, str], *, type_key: str, entry: FormEntry | None = None) -> str:
    """The data the browser fill helper reads (copied by the owner, pasted on the form page).

    Only kit values, already built for this kit, plus what the shared directory knows of the
    form: its own label and, when a maintainer recorded one, a CSS selector per field. Compact,
    ASCII-only JSON. Nothing in it names the node or the project: the provider's page sees it.
    The helper fills fields and never submits (N1)."""
    doc: dict[str, Any] = {
        "format": FILL_FORMAT,
        "type": type_key,
        "values": {k: values[k] for k in FILL_KEYS if values.get(k)},
    }
    if entry is not None:
        labels = {f.key: f.label for f in entry.fields if f.key in FILL_KEYS}
        selectors = {f.key: f.selector for f in entry.fields if f.selector}
        if labels:
            doc["labels"] = labels
        if selectors:
            doc["selectors"] = selectors
    return json.dumps(doc, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def merge_evidence(parts: Sequence[Evidence]) -> Evidence:
    """One evidence from the open form reports of one provider (one kit per provider): every
    source with its own kind, the widest window, the options of the first report. A source in
    two reports is kept once (the newest). ``ValueError`` when there are more than
    ``MAX_SUBJECTS`` sources or no part."""
    if not parts:
        raise ValueError("nothing to merge")
    if len(parts) == 1:
        return parts[0]
    seen: dict[tuple[str, str, str], Subject] = {}
    for ev in parts:
        for s in ev.subjects:
            kind = ev.kind_of(s)
            key = (kind, s.type, s.value)
            if key not in seen or s.last_ts > seen[key].last_ts:
                seen[key] = s if s.kind is not None else s.model_copy(update={"kind": kind})
    first = parts[0]
    return Evidence(
        kind="digest",
        recipient=first.recipient,
        subjects=tuple(seen.values()),
        window_start=min(ev.window_start for ev in parts),
        window_end=max(ev.window_end for ev in parts),
        demo=any(ev.demo for ev in parts),
        options=first.options,
    )


def build_kit(
    evidence: Evidence,
    settings: ReportSettings,
    *,
    entry: FormEntry | None = None,
    form_name: str | None = None,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
    now: datetime | None = None,
) -> Kit:
    """The copy kit of a form report. Pure; the caller guards it (``guard_kit``) before showing
    any of it. ``RenderUnavailable`` when the reply contact holds no mail address."""
    now = now or datetime.now(UTC)
    email, _domain = contact_of(settings)
    reference = _reference(reply_token, reference_style)
    max_chars = entry.max_chars if entry is not None else DEFAULT_MAX_CHARS
    txt = entry is not None and "csv" not in entry.file_types and "txt" in entry.file_types
    file_name = "evidence.txt" if txt else "evidence.csv"
    opts = evidence.options
    subjects = sorted(evidence.subjects, key=lambda s: (s.last_ts, s.value), reverse=True)

    def type_label(t: str) -> str:
        return (entry.choice_of(t) if entry is not None else None) or TYPE_LABELS[t]

    email_text = email
    name_text = to_ascii((form_name or "").strip())[:100]
    sources: list[KitSource] = []
    for s in subjects:
        lines = evidence_lines(evidence, s, EXCERPT_LINES)
        key = abuse_type_of(evidence, s)
        one = {
            "email": email_text,
            "name": name_text,
            "abuse_type": type_label(key),
            "addresses": s.value,
            "first_seen": fmt_ts(s.first_ts, opts),
            "last_seen": fmt_ts(s.last_ts, opts),
            "description": describe(
                evidence, [s], max_chars=max_chars, reference=reference, file_name=file_name
            ),
            "log_excerpt": "\n".join(lines),
        }
        sources.append(
            KitSource(
                kind=evidence.kind_of(s),
                type=s.type,
                value=s.value,
                abuse_type=one["abuse_type"],
                first_seen=one["first_seen"],
                last_seen=one["last_seen"],
                description=one["description"],
                log_excerpt=one["log_excerpt"],
                stale=s.last_ts <= now - FRESH,
                type_key=key,
                fill=fill_data(one, type_key=key, entry=entry),
            )
        )
    counts = Counter(abuse_type_of(evidence, s) for s in subjects)
    main = min(counts, key=lambda t: (-counts[t], ABUSE_TYPES.index(t)))
    if txt:
        body = "\n".join(
            line for s in subjects for line in evidence_lines(evidence, s, MAX_ACTIVITIES_CSV)
        )
        evidence_file = Attachment("evidence.txt", "text/plain", body + "\n")
    else:
        evidence_file = render_csv(evidence)
    labels = {f.key: f.label for f in entry.fields} if entry is not None else {}
    whole = {
        "email": email_text,
        "name": name_text,
        "abuse_type": type_label(main),
        "addresses": "\n".join(s.value for s in subjects),
        "first_seen": fmt_ts(min(s.first_ts for s in subjects), opts),
        "last_seen": fmt_ts(max(s.last_ts for s in subjects), opts),
        "description": describe(
            evidence, subjects, max_chars=max_chars, reference=reference, file_name=file_name
        ),
        "log_excerpt": "\n\n".join(s.log_excerpt for s in sources),
    }
    return Kit(
        email=whole["email"],
        name=whole["name"],
        abuse_type=whole["abuse_type"],
        addresses=whole["addresses"],
        first_seen=whole["first_seen"],
        last_seen=whole["last_seen"],
        description=whole["description"],
        log_excerpt=whole["log_excerpt"],
        evidence=evidence_file,
        sources=tuple(sources),
        one_ip_per_submission=entry.one_ip_per_submission if entry is not None else False,
        max_chars=max_chars,
        labels=labels,
        type_key=main,
        fill=fill_data(whole, type_key=main, entry=entry),
    )


def guard_kit(
    kit: Kit,
    terms: SelfTerms | None,
    *,
    ctx: GuardContext | None = None,
    links: Sequence[str] = (),
) -> GuardResult:
    """The identity check of a kit: every field on its own, the evidence file, the fill data of
    the browser helper, the form links, and everything together once more (a term split across
    two fields is still one text)."""
    file_fmt: ArtifactFormat = "csv" if kit.evidence.media_type == "text/csv" else "text"
    parts: list[tuple[str, str | bytes, ArtifactFormat]] = [
        (name, value, "text") for name, value in kit.texts()
    ]
    parts.append((kit.evidence.name, kit.evidence.content, file_fmt))
    parts += [(name, value, "json") for name, value in kit.fills()]
    parts += [(f"link[{i}]", url, "text") for i, url in enumerate(links)]
    result = guard_parts(parts, terms, ctx=ctx)
    fills = [v for _n, v in kit.fills()]
    whole = "\n".join([v for _n, v in kit.texts()] + [kit.evidence.content, *fills, *links])
    if terms is not None:
        result = result.merge(guard(whole, terms, fmt="text", ctx=ctx))
    return result


# --- command line: compile and check (maintainers and CI) -----------------------------------


def _load_yaml(path: Path) -> object:
    import yaml  # only the command line reads YAML

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    """``compile SRC DST`` writes the JSON; ``check SRC DST`` fails when the YAML does not
    validate or the committed JSON is not its compiled form. Both print a warning per entry
    last checked more than a year ago."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 3 or args[0] not in ("compile", "check"):
        print("usage: python -m suckerpot_reporting.forms compile|check SRC.yaml DST.json")
        return 2
    action, src, dst = args[0], Path(args[1]), Path(args[2])
    today = datetime.now(UTC).date()
    try:
        directory = validate(_load_yaml(src), today)
    except DirectoryError as exc:
        for problem in exc.problems:
            print(f"::error file={src}::{problem}")
        return 1
    except (OSError, ValueError) as exc:
        print(f"::error file={src}::{type(exc).__name__}")
        return 1
    for e in directory.stale_entries(today):
        print(f"::warning file={src}::{e.id}: last checked over a year ago ({e.verified_on})")
    text = dumps(directory)
    if action == "compile":
        dst.write_text(text, encoding="ascii")
        print(f"{len(directory.entries)} entries written to {dst}")
        return 0
    try:
        current = dst.read_text(encoding="ascii")
    except OSError:
        current = ""
    if current != text:
        print(f"::error file={dst}::out of date: run the compile command and commit the result")
        return 1
    print(f"{len(directory.entries)} entries, compiled file up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
