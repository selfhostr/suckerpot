"""Wire models of protocol spn/1 (spec sections 5.3 to 5.5 and 7.1).

Every model rejects unknown fields. Address validation can accept documentation ranges when the
validation context carries ``{"allow_documentation": True}`` (hub test overlay only).
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .buckets import MIN_COUNTRIES_SHOWN, MIN_MEMBERS_COUNTRY_SHOWN, parse_day
from .enums import (
    ACTIVITIES,
    FAMILIES_V1,
    FILE_TYPES_V1,
    PROTOCOL,
    RESERVED_FIELDS,
    SERVICES,
    is_valid_tag,
)
from .errors import ProtoError
from .sign import b64u_decode

MAX_BODY_OBSERVATIONS = 1024 * 1024
MAX_BODY_DEFAULT = 64 * 1024
MAX_JSON_DEPTH = 6
MAX_SOURCES = 5000
MAX_PAYLOADS = 1000
MAX_C2 = 1000
MAX_FILES = 1000
MAX_REVEALS = 200
MAX_RECHECKS = 500
MAX_TARGETS_PER_PULL = 1000
MAX_VERIFY_REVEALS = 200
MAX_VERIFY_TASKS = 20
MAX_VERIFY_RESULTS = 50
MAX_VERIFY_FILE_SIZE = 67_108_864  # 64 MiB

_DOC_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
# Prefixes that carry an IPv4 address inside an IPv6 one (NAT64, Teredo, 6to4): refused, so no
# never-list entry or reporting rule can be bypassed by wrapping an address.
_EMBEDDING_NETS = tuple(
    ipaddress.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16")
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_TARGET_ID = re.compile(r"^t_[0-9a-f]{12}$")
_VERIFY_ID = re.compile(r"^v_[0-9a-f]{12}$")
_UTC_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def parse_global_ip(value: str, *, allow_documentation: bool = False) -> str:
    """Normalised text of a global unicast address. Raises ValueError otherwise."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("not an IP address") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        raise ValueError("IPv4-mapped address")
    if isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _EMBEDDING_NETS):
        raise ValueError("address embeds an IPv4 address")
    if allow_documentation and any(ip in net for net in _DOC_NETS if net.version == ip.version):
        return str(ip)
    if not ip.is_global or ip.is_multicast:
        raise ValueError("not a global unicast address")
    return str(ip)


def _ctx_allows_docs(info: ValidationInfo) -> bool:
    ctx = info.context
    return bool(isinstance(ctx, dict) and ctx.get("allow_documentation"))


def _validate_ip(value: str, info: ValidationInfo) -> str:
    return parse_global_ip(value, allow_documentation=_ctx_allows_docs(info))


def _validate_hex64(value: str) -> str:
    if not _HEX64.fullmatch(value):
        raise ValueError("expected 64 lowercase hex characters")
    return value


def _validate_day(value: str) -> str:
    parse_day(value)
    return value


def _validate_b64u(length: int) -> Any:
    def check(value: str) -> str:
        if len(b64u_decode(value)) != length:
            raise ValueError(f"expected {length} bytes")
        return value

    return check


def _validate_pow_nonce(value: str) -> str:
    if not 1 <= len(b64u_decode(value)) <= 16:
        raise ValueError("pow_nonce must be 1 to 16 bytes")
    return value


def _validate_pad(value: str) -> str:
    if value.strip(" "):
        raise ValueError("pad may only hold spaces")
    return value


def _unique(values: list[str]) -> list[str]:
    if len(set(values)) != len(values):
        raise ValueError("duplicate entries")
    return values


def _filter_tags(value: Any) -> Any:
    """Tags outside the allow-list are dropped, not refused (spec section 4)."""
    if not isinstance(value, list):
        return value
    kept: list[str] = []
    for tag in value:
        if isinstance(tag, str) and is_valid_tag(tag) and tag not in kept:
            kept.append(tag)
    return kept


def _members_of(allowed: frozenset[str]) -> Any:
    def check(values: list[str]) -> list[str]:
        for v in values:
            if v not in allowed:
                raise ValueError("value outside the allowed list")
        return _unique(values)

    return check


IPText = Annotated[str, AfterValidator(_validate_ip)]
Hex64 = Annotated[str, Field(min_length=64, max_length=64), AfterValidator(_validate_hex64)]
Day = Annotated[str, Field(min_length=10, max_length=10), AfterValidator(_validate_day)]
Services = Annotated[
    list[str], Field(min_length=1, max_length=len(SERVICES)), AfterValidator(_members_of(SERVICES))
]
Activities = Annotated[
    list[str],
    Field(min_length=1, max_length=len(ACTIVITIES)),
    AfterValidator(_members_of(ACTIVITIES)),
]
Tags = Annotated[list[str], BeforeValidator(_filter_tags), Field(max_length=32)]
# Target lists come from the hub: bounded and held to the same closed vocabularies (may be empty).
TargetServices = Annotated[
    list[str], Field(max_length=len(SERVICES)), AfterValidator(_members_of(SERVICES))
]
TargetActivities = Annotated[
    list[str], Field(max_length=len(ACTIVITIES)), AfterValidator(_members_of(ACTIVITIES))
]
TargetFamilies = Annotated[
    list[str], Field(max_length=32), AfterValidator(_members_of(FAMILIES_V1))
]
Bucket = Annotated[int, Field(ge=0, le=4)]
Port = Annotated[int, Field(ge=1, le=65535)]
Nonce16 = Annotated[str, Field(min_length=22, max_length=22), AfterValidator(_validate_b64u(16))]
NodeKeyText = Annotated[
    str, Field(min_length=43, max_length=43), AfterValidator(_validate_b64u(32))
]
Pad = Annotated[str, Field(max_length=8192), AfterValidator(_validate_pad)]
Country = Annotated[str, Field(pattern=_COUNTRY.pattern)]
ProtocolField = Literal["spn/1"]


def _one_of(allowed: frozenset[str]) -> Any:
    def check(value: str) -> str:
        if value not in allowed:
            raise ValueError("value outside the allowed list")
        return value

    return check


FamilyText = Annotated[str, AfterValidator(_one_of(FAMILIES_V1))]
FileTypeText = Annotated[str, AfterValidator(_one_of(FILE_TYPES_V1))]


class ProtoModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @model_validator(mode="before")
    @classmethod
    def _no_reserved(cls, data: Any) -> Any:
        if isinstance(data, dict):
            hit = RESERVED_FIELDS.intersection(data)
            if hit:
                raise ValueError(f"reserved field not accepted in spn/1: {sorted(hit)[0]}")
        return data


# --- enrolment and node ---


class ChallengeRequest(ProtoModel):
    protocol: ProtocolField
    node_key: NodeKeyText
    pad: Pad = ""


class ChallengeResponse(ProtoModel):
    challenge: Annotated[str, Field(min_length=43, max_length=43)]
    difficulty: int = Field(ge=0, le=48)
    expires_in: int = Field(ge=1, le=3600)


_PSEUDONYM_FIELD = Annotated[str, Field(min_length=1, max_length=64)]


class EnrolRequest(ProtoModel):
    protocol: ProtocolField
    challenge: Annotated[str, Field(min_length=43, max_length=43)]
    pow_nonce: Annotated[
        str, Field(min_length=2, max_length=22), AfterValidator(_validate_pow_nonce)
    ]
    pseudonym: _PSEUDONYM_FIELD | None = None
    country: Country | None = None
    show_country: bool = False
    pad: Pad = ""

    @field_validator("challenge")
    @classmethod
    def _challenge(cls, value: str) -> str:
        if len(b64u_decode(value)) != 32:
            raise ValueError("challenge must be 32 bytes")
        return value


class EnrolResponse(ProtoModel):
    node_id: str
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{8}$")]
    enrolled_day: Day
    eligible_from_day: Day


class NodeInfo(ProtoModel):
    node_id: str
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{8}$")]
    pseudonym: str | None
    country: Country | None
    show_country: bool
    enrolled_day: Day
    eligible_from_day: Day
    standing: Literal["new", "good", "low"]
    active_days_14: int = Field(ge=0, le=14)


class NodePatch(ProtoModel):
    protocol: ProtocolField
    pseudonym: _PSEUDONYM_FIELD | None = None
    country: Country | None = None
    show_country: bool | None = None
    pad: Pad = ""


class Deleted(ProtoModel):
    deleted: Literal[True]


class ErrorBody(ProtoModel):
    error: str


class Limits(ProtoModel):
    max_observations_bytes: int
    max_body_bytes: int
    max_sources: int
    max_payloads: int
    max_c2: int
    max_files: int
    max_reveals: int
    max_rechecks: int


class PowInfo(ProtoModel):
    algorithm: Literal["sha256-leading-zero-bits"]
    difficulty: int = Field(ge=0, le=48)


class Thresholds(ProtoModel):
    min_nodes: int
    min_age_days: int


class InfoResponse(ProtoModel):
    protocols: list[str]
    hub_key: NodeKeyText
    pow: PowInfo
    limits: Limits
    thresholds: Thresholds
    today: Day


# --- observation batch ---


class SourceObs(ProtoModel):
    ip: IPText
    services: Services
    activity: Activities
    tags: Tags = Field(default_factory=list)
    sessions: Bucket
    attempts: Bucket


class PayloadObs(ProtoModel):
    url_b: Hex64
    host_ip: IPText | None = None
    host_b: Hex64 | None = None
    sha256: Hex64 | None = None
    family: FamilyText | None = None
    file_type: FileTypeText | None = None
    fetched: bool = False

    @model_validator(mode="after")
    def _shape(self) -> PayloadObs:
        if (self.host_ip is None) == (self.host_b is None):
            raise ValueError("exactly one of host_ip and host_b")
        if self.fetched and self.sha256 is None:
            raise ValueError("a fetched payload needs its sha256")
        return self


class C2Obs(ProtoModel):
    ip: IPText | None = None
    domain_b: Hex64 | None = None
    port: Port
    family: FamilyText | None = None
    via_sha256: Hex64 | None = None

    @model_validator(mode="after")
    def _shape(self) -> C2Obs:
        if (self.ip is None) == (self.domain_b is None):
            raise ValueError("exactly one of ip and domain_b")
        return self


class FileObs(ProtoModel):
    sha256: Hex64
    family: FamilyText | None = None
    file_type: FileTypeText | None = None


class ObservationBatch(ProtoModel):
    protocol: ProtocolField
    batch_id: Nonce16
    day: Day
    sources: Annotated[list[SourceObs], Field(max_length=MAX_SOURCES)] = Field(default_factory=list)
    payloads: Annotated[list[PayloadObs], Field(max_length=MAX_PAYLOADS)] = Field(
        default_factory=list
    )
    c2: Annotated[list[C2Obs], Field(max_length=MAX_C2)] = Field(default_factory=list)
    files: Annotated[list[FileObs], Field(max_length=MAX_FILES)] = Field(default_factory=list)
    pad: Pad = ""

    @model_validator(mode="after")
    def _unique_items(self) -> ObservationBatch:
        _unique([s.ip for s in self.sources])
        _unique([p.url_b for p in self.payloads])
        _unique([f"{c.ip or c.domain_b}:{c.port}" for c in self.c2])
        _unique([f.sha256 for f in self.files])
        return self


class BatchAccepted(ProtoModel):
    accepted: dict[str, int]
    rejected: dict[str, int]
    duplicate: bool


# --- targets, reveals, rechecks ---


class Target(ProtoModel):
    id: Annotated[str, Field(pattern=_TARGET_ID.pattern)]
    kind: Literal["ip", "url", "domain", "sha256", "c2_ip", "c2_domain"]
    value: Annotated[str, Field(max_length=2048)] | None
    value_b: Hex64 | None
    state: Literal["confirmed", "reported", "taken_down", "disputed", "expired"]
    nodes: Annotated[int, Field(ge=0, le=2)]
    countries: Annotated[int, Field(ge=MIN_COUNTRIES_SHOWN)] | None
    first_day: Day
    last_day: Day
    services: TargetServices
    activity: TargetActivities
    tags: Tags
    families: TargetFamilies
    reported_day: Day | None
    taken_down_day: Day | None


class RevealRef(ProtoModel):
    kind: Literal["url", "domain"]
    value_b: Hex64


class RecheckRef(ProtoModel):
    id: Annotated[str, Field(pattern=_TARGET_ID.pattern)]
    kind: Literal["ip", "url", "domain", "sha256", "c2_ip", "c2_domain"]
    value: str


class TargetsResponse(ProtoModel):
    cursor: Annotated[str, Field(max_length=64)]
    targets: Annotated[list[Target], Field(max_length=MAX_TARGETS_PER_PULL)]
    reveal: list[RevealRef] = Field(max_length=MAX_TARGETS_PER_PULL)
    recheck: list[RecheckRef] = Field(max_length=50)


class RevealItem(ProtoModel):
    kind: Literal["url", "domain"]
    value_b: Hex64
    value: Annotated[str, Field(min_length=1, max_length=2048)]


class RevealsRequest(ProtoModel):
    protocol: ProtocolField
    items: Annotated[list[RevealItem], Field(max_length=MAX_REVEALS)]
    pad: Pad = ""


class RecheckItem(ProtoModel):
    id: Annotated[str, Field(pattern=_TARGET_ID.pattern)]
    state: Literal["up", "down", "unknown"]


class RechecksRequest(ProtoModel):
    protocol: ProtocolField
    day: Day
    items: Annotated[list[RecheckItem], Field(max_length=MAX_RECHECKS)]
    pad: Pad = ""

    @model_validator(mode="after")
    def _unique_ids(self) -> RechecksRequest:
        _unique([i.id for i in self.items])
        return self


class AcceptedCount(ProtoModel):
    accepted: int
    rejected: int = 0


# --- verification (design M32 section 6.2) ---

VERIFY_OUTCOMES: tuple[str, ...] = (
    "fetched",
    "unreachable",
    "http_error",
    "too_large",
    "timeout",
    "refused",
    "skipped",
)
VerifyId = Annotated[str, Field(pattern=_VERIFY_ID.pattern)]


class VerifyRevealRef(ProtoModel):
    """A blinded link the caller reported and the hub waits to see in clear."""

    kind: Literal["url"]
    value_b: Hex64


class VerifyRevealsResponse(ProtoModel):
    items: Annotated[list[VerifyRevealRef], Field(max_length=MAX_VERIFY_REVEALS)]


class VerifyTask(ProtoModel):
    id: VerifyId
    url: Annotated[str, Field(min_length=1, max_length=2048)]
    lease_until: Annotated[str, Field(pattern=_UTC_STAMP.pattern)]


class VerifyTasksResponse(ProtoModel):
    tasks: Annotated[list[VerifyTask], Field(max_length=MAX_VERIFY_TASKS)]

    @model_validator(mode="after")
    def _unique_ids(self) -> VerifyTasksResponse:
        _unique([t.id for t in self.tasks])
        return self


class VerifyResult(ProtoModel):
    id: VerifyId
    outcome: Literal[
        "fetched", "unreachable", "http_error", "too_large", "timeout", "refused", "skipped"
    ]
    sha256: Hex64 | None = None
    size: Annotated[int, Field(ge=1, le=MAX_VERIFY_FILE_SIZE)] | None = None
    file_type: FileTypeText | None = None
    family: FamilyText | None = None

    @model_validator(mode="after")
    def _shape(self) -> VerifyResult:
        fetched = (self.sha256, self.size, self.file_type)
        if self.outcome == "fetched":
            if any(v is None for v in fetched):
                raise ValueError("a fetched result needs sha256, size and file_type")
        elif any(v is not None for v in fetched) or self.family is not None:
            raise ValueError("only a fetched result carries sha256, size, file_type or family")
        return self


class VerifyResultsRequest(ProtoModel):
    protocol: ProtocolField
    items: Annotated[list[VerifyResult], Field(max_length=MAX_VERIFY_RESULTS)]
    pad: Pad = ""

    @model_validator(mode="after")
    def _unique_ids(self) -> VerifyResultsRequest:
        _unique([i.id for i in self.items])
        return self


# --- network summary (section 7.1) ---


class NetworkTotals(ProtoModel):
    members: int
    active_7d: int
    countries: int
    confirmed_30d: int
    reported_30d: int
    taken_down_30d: int
    median_days_to_takedown: int | None


class NetworkWeek(ProtoModel):
    week: Day
    confirmed: int
    reported: int
    taken_down: int


class NetworkCountry(ProtoModel):
    cc: Country
    members: Annotated[int, Field(ge=MIN_MEMBERS_COUNTRY_SHOWN)]


class NetworkMember(ProtoModel):
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{8}$")]
    pseudonym: str | None
    country: Country | None
    member_since: Annotated[str, Field(pattern=r"^\d{4}-\d{2}$")]
    active_days: int = Field(ge=0, le=7)
    tier: Bucket


class NetworkSummary(ProtoModel):
    generated_day: Day
    totals: NetworkTotals
    weekly: list[NetworkWeek]
    countries: list[NetworkCountry]
    members: list[NetworkMember]


# --- parsing helpers ---


def _depth_ok(value: Any, limit: int) -> bool:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict | list):
            if depth > limit:
                return False
            children = node.values() if isinstance(node, dict) else node
            stack.extend((c, depth + 1) for c in children if isinstance(c, dict | list))
    return True


def parse_body[M: ProtoModel](
    model: type[M],
    raw: bytes,
    *,
    max_bytes: int = MAX_BODY_DEFAULT,
    allow_documentation: bool = False,
) -> M:
    """Parse and validate a request body. Raises ``ProtoError`` with a protocol code."""
    if len(raw) > max_bytes:
        raise ProtoError("too_large")
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ProtoError("invalid_payload", "not json") from exc
    if not isinstance(data, dict) or not _depth_ok(data, MAX_JSON_DEPTH):
        raise ProtoError("invalid_payload", "not an object or too deep")
    proto = data.get("protocol")
    if "protocol" in model.model_fields and proto != PROTOCOL:
        raise ProtoError("unsupported_protocol" if isinstance(proto, str) else "invalid_payload")
    try:
        return model.model_validate(data, context={"allow_documentation": allow_documentation})
    except ValidationError as exc:
        # Locations only: values may be attacker input and must not reach logs.
        where = ",".join(".".join(str(p) for p in e["loc"]) for e in exc.errors()[:3])
        raise ProtoError("invalid_payload", where) from exc


def parse_response[M: ProtoModel](model: type[M], raw: bytes) -> M:
    """Parse a hub answer on the node (unknown fields refused). Raises ``ProtoError``."""
    try:
        data = json.loads(raw)
        return model.model_validate(data)
    except (ValueError, RecursionError) as exc:
        raise ProtoError("invalid_payload", "bad hub answer") from exc
