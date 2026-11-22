"""Evidence model (design M22, section 4.2): an allow-list of fields, frozen and bounded.

Nothing here is copied from a raw event. The builder (ingest) fills these fields one by one
and passes every free-text value through ``redact`` first; the validators below only enforce
the size limits as a second line of defence.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import UTC, datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ReportKind = Literal["attack_source", "payload_host", "c2"]
# A daily digest (M38) holds the subjects of every kind for one recipient; each subject then
# carries its own kind.
EvidenceKind = Literal["attack_source", "payload_host", "c2", "digest"]
ActionName = Literal[
    "failed_logins",
    "login_then_commands",
    "command",
    "download",
    "http_request",
    "exploit_attempt",
]

MAX_USERNAMES = 5
MAX_USERNAME_LEN = 32
MAX_TEXT_LEN = 200
MAX_UA_LEN = 120
MAX_SUBJECTS = 100
MAX_ACTIVITIES_BODY = 10
MAX_ACTIVITIES_CSV = 200
MAX_CVES = 20

_HEX = re.compile(r"^[0-9a-f]+$")
# A CVE as an event tag (``cve-2021-44228``): the only CVE spelling evidence may carry.
CVE_TAG = re.compile(r"^cve-\d{4}-\d{4,7}$")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("naive datetime")
    return value.astimezone(UTC)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class RedactionStats(_Frozen):
    addresses_masked: int = 0
    lines_dropped: int = 0

    def __add__(self, other: RedactionStats) -> RedactionStats:
        return RedactionStats(
            addresses_masked=self.addresses_masked + other.addresses_masked,
            lines_dropped=self.lines_dropped + other.lines_dropped,
        )


class SampleRef(_Frozen):
    sha256: str = Field(min_length=64, max_length=64)
    sha1: str | None = Field(default=None, max_length=40)
    md5: str | None = Field(default=None, max_length=32)
    tlsh: str | None = Field(default=None, max_length=72)
    size: int | None = Field(default=None, ge=0)
    kind: str | None = Field(default=None, max_length=32)
    arch: str | None = Field(default=None, max_length=32)
    family: str | None = Field(default=None, max_length=64)
    first_seen: datetime | None = None

    @field_validator("sha256", "sha1", "md5")
    @classmethod
    def _lower_hex(cls, v: str | None) -> str | None:
        if v is not None and not _HEX.match(v):
            raise ValueError("hash must be lower-case hex")
        return v


class Activity(_Frozen):
    """One line of evidence."""

    ts: datetime
    src_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp"]
    service: str = Field(max_length=32)
    action: ActionName
    count: int = Field(default=1, ge=1)
    usernames: tuple[str, ...] = ()
    text: str | None = None
    user_agent: str | None = None
    # M38: CVE tags of the request (allow-listed spelling only) and whether the web sensor saw
    # an SQL injection pattern. They pick the X-ARF type; neither is printed as is.
    cves: tuple[str, ...] = ()
    sqli: bool = False

    @field_validator("ts")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        return _utc(v)

    @field_validator("src_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return str(ipaddress.ip_address(v))

    @field_validator("usernames")
    @classmethod
    def _users(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if len(v) > MAX_USERNAMES or any(len(u) > MAX_USERNAME_LEN for u in v):
            raise ValueError("too many or too long usernames")
        return v

    @field_validator("text")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        if v is not None and len(v) > MAX_TEXT_LEN:
            raise ValueError("text too long")
        return v

    @field_validator("user_agent")
    @classmethod
    def _ua(cls, v: str | None) -> str | None:
        if v is not None and len(v) > MAX_UA_LEN:
            raise ValueError("user agent too long")
        return v

    @field_validator("cves")
    @classmethod
    def _cves(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if len(v) > MAX_CVES or any(not CVE_TAG.fullmatch(c) for c in v):
            raise ValueError("too many or malformed CVE tags")
        return v


class Subject(_Frozen):
    type: Literal["ip", "url", "domain"]
    # M38: the kind of this subject in a digest (None: the report's own kind) and the random id
    # of its X-ARF report, stored on the subject row and unrelated to every other id.
    kind: ReportKind | None = None
    xarf_id: uuid.UUID | None = None
    value: str = Field(min_length=1, max_length=1024)
    asn: int | None = Field(default=None, ge=0)
    network: str | None = Field(default=None, max_length=200)
    country: str | None = Field(default=None, max_length=2)
    first_ts: datetime
    last_ts: datetime
    sessions: int = Field(ge=0)
    events: int = Field(ge=0)
    activities: tuple[Activity, ...] = ()
    samples: tuple[SampleRef, ...] = ()
    redaction: RedactionStats = RedactionStats()
    previously_reported: datetime | None = None

    @field_validator("first_ts", "last_ts")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        return _utc(v)

    @field_validator("activities")
    @classmethod
    def _acts(cls, v: tuple[Activity, ...]) -> tuple[Activity, ...]:
        if len(v) > MAX_ACTIVITIES_CSV:
            raise ValueError("too many activities")
        return v

    @property
    def is_ip(self) -> bool:
        return self.type == "ip"


class ReportOptions(_Frozen):
    """Section 4.4. Times are rounded to the minute unless exact times are chosen."""

    defang: bool = True
    time_precision: Literal["second", "minute"] = "minute"
    include_usernames: bool = True
    include_reply_contact: bool = True
    show_redaction_counts: bool = False


class Evidence(_Frozen):
    kind: EvidenceKind
    recipient: str = Field(min_length=3, max_length=254)
    subjects: tuple[Subject, ...] = Field(min_length=1, max_length=MAX_SUBJECTS)
    window_start: datetime
    window_end: datetime
    demo: bool = False
    options: ReportOptions = ReportOptions()

    @field_validator("window_start", "window_end")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        return _utc(v)

    @model_validator(mode="after")
    def _window(self) -> Evidence:
        if self.window_end < self.window_start:
            raise ValueError("window ends before it starts")
        if self.kind == "digest" and any(s.kind is None for s in self.subjects):
            raise ValueError("a digest subject needs a kind")
        return self

    def kind_of(self, subject: Subject) -> ReportKind:
        """The kind of one subject: its own in a digest, else the report's."""
        if subject.kind is not None:
            return subject.kind
        if self.kind == "digest":
            raise ValueError("a digest subject needs a kind")
        return self.kind


class ReportSettings(_Frozen):
    """Owner-written wording and contact (``report_settings``). The package ships no prose.

    Every field defaults to empty. Only ``reply_contact`` is required to render a report (without
    it the recipient has no way to answer). ``intro``, ``outro``, ``note`` and ``signature`` are
    optional: an empty one is left out of every rendering. An empty ``subject_template`` falls
    back to ``DEFAULT_SUBJECT`` and an empty ``xarf_user_agent`` to ``DEFAULT_XARF_USER_AGENT``.
    ``subject_template`` may use ``{value}``, ``{asn}``, ``{network}``, ``{count}`` and
    ``{date}``.
    """

    reply_contact: str | None = Field(default=None, max_length=254)
    signature: str | None = Field(default=None, max_length=200)
    intro: str | None = Field(default=None, max_length=1000)
    outro: str | None = Field(default=None, max_length=1000)
    note: str | None = Field(default=None, max_length=1000)
    subject_template: str | None = Field(default=None, max_length=200)
    xarf_user_agent: str | None = Field(default=None, max_length=64)
    # M38: ``reporter.org`` of the X-ARF reports; empty means the domain of the reply contact.
    xarf_org: str | None = Field(default=None, max_length=100)


# One fixed, very common English phrase built from data only: no project or product wording.
DEFAULT_SUBJECT: Final = "Abuse report for {value}"
# The X-ARF specification does not define a generic agent string, so the fallback is the
# ubiquitous browser product token. Millions of clients send it; it says nothing about the sender.
DEFAULT_XARF_USER_AGENT: Final = "Mozilla/5.0"


def missing_settings(settings: ReportSettings | None, *, xarf: bool = False) -> tuple[str, ...]:
    """Names of the required settings that are empty (field names only).

    Only ``reply_contact`` is required, for every format. ``xarf`` is kept for callers that
    still pass it; it no longer changes the answer.
    """
    del xarf
    cfg = settings or ReportSettings()
    return tuple(n for n in ("reply_contact",) if not (getattr(cfg, n) or "").strip())


# --- export input (STIX, MISP) -------------------------------------------------------------


class Technique(_Frozen):
    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(max_length=100)


class ExportItem(_Frozen):
    """One indicator for a CERT export. ``cluster_key`` is internal and never exported."""

    role: Literal["attack_source", "payload_host", "c2", "sample"]
    type: Literal["ip", "url", "domain", "file"]
    value: str = Field(min_length=1, max_length=1024)  # for files: the sha256
    first_seen: datetime
    last_seen: datetime
    sightings: int = Field(default=1, ge=1)
    family: str | None = Field(default=None, max_length=64)
    techniques: tuple[Technique, ...] = ()
    sample: SampleRef | None = None
    cluster_key: str | None = None

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        return _utc(v)


TLP = Literal["clear", "green", "amber", "red"]


class ExportData(_Frozen):
    export_id: uuid.UUID
    id_seed: uuid.UUID
    created: datetime
    tlp: TLP = "green"
    demo: bool = False
    description: str = Field(default="", max_length=500)  # owner-provided; empty by default
    items: tuple[ExportItem, ...] = Field(min_length=1, max_length=5000)

    @field_validator("created")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        return _utc(v)


def export_from_evidence(
    evidence: Evidence,
    *,
    export_id: uuid.UUID,
    id_seed: uuid.UUID,
    created: datetime,
    tlp: TLP = "green",
) -> ExportData:
    """Indicators of one report: its subjects, and the samples they served."""
    items: list[ExportItem] = []
    for s in evidence.subjects:
        items.append(
            ExportItem(
                role=evidence.kind_of(s),
                type=s.type,
                value=s.value,
                first_seen=s.first_ts,
                last_seen=s.last_ts,
                sightings=max(1, s.events),
            )
        )
        items.extend(
            ExportItem(
                role="sample",
                type="file",
                value=smp.sha256,
                first_seen=smp.first_seen or s.first_ts,
                last_seen=s.last_ts,
                family=smp.family,
                sample=smp,
            )
            for smp in s.samples
        )
    return ExportData(
        export_id=export_id,
        id_seed=id_seed,
        created=created,
        tlp=tlp,
        demo=evidence.demo,
        items=tuple(items),
    )
