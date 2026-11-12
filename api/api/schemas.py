"""Pydantic response models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict

# asyncpg returns ipaddress objects for inet columns.
IpStr = Annotated[str, BeforeValidator(str)]


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    sensor: str
    src_ip: IpStr
    src_port: int
    dst_port: int
    started_at: datetime
    ended_at: datetime | None
    last_event_at: datetime
    event_count: int
    login_attempts: int
    login_success: bool
    commands: int
    downloads: int
    http_requests: int
    country: str | None
    city: str | None
    asn: int | None
    org: str | None
    abuse_score: int | None
    known_scanner: bool | None
    tags: list[str]
    client_tool: str | None = None
    techniques: list[str] = []
    campaign_id: int | None = None
    #: A known research scanner (M19); ``scanner_name`` says which one.
    benign: bool = False
    scanner_name: str | None = None
    #: ``burst`` is a flood group: one row for ``connections`` plain connections of one source on
    #: one sensor and port in one UTC hour (``src_port`` is 0). A plain row stands for one.
    kind: Literal["session", "burst"] = "session"
    connections: int = 1


class SessionDetail(SessionOut):
    #: Set when the id asked for was folded into this group (``?at=`` found it there).
    folded_from: str | None = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    sensor: str
    session_id: str
    type: str
    src_ip: IpStr
    src_port: int
    dst_port: int
    data: dict[str, Any]
    country: str | None
    city: str | None
    asn: int | None
    org: str | None
    abuse_score: int | None
    known_scanner: bool | None
    tags: list[str]


class CredentialCount(BaseModel):
    value: str
    count: int


class CredentialPair(BaseModel):
    username: str
    password: str
    count: int


class SessionCredentials(BaseModel):
    """What a session or a flood group tried to log in with (values cut to 256 characters)."""

    attempts: int
    distinct_usernames: int
    distinct_passwords: int
    distinct_pairs: int
    #: The answer covers the first 50,000 attempts only (a very large group).
    truncated: bool = False
    usernames: list[CredentialCount]
    passwords: list[CredentialCount]
    pairs: list[CredentialPair]


class SessionPage(BaseModel):
    items: list[SessionOut]
    next_cursor: str | None


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None


class SensorCounts(BaseModel):
    events: int
    sessions: int


class StatsSummary(BaseModel):
    window_hours: int
    events: int
    sessions: int
    unique_ips: int
    sessions_with_commands: int
    download_attempts: int
    by_sensor: dict[str, SensorCounts]
    #: Of ``sessions``: the connections that sit in a flood group, and the sources that sent them.
    flood_sessions: int = 0
    flood_sources: int = 0


class Health(BaseModel):
    status: str
    db: str


class LiveEvent(BaseModel):
    """Compact event for the live feed (no raw ``data``; ``summary`` is a one-line story)."""

    id: int
    ts: datetime
    sensor: str
    session_id: str
    type: str
    src_ip: IpStr
    src_port: int
    dst_port: int
    summary: str
    country: str | None
    city: str | None
    asn: int | None
    org: str | None
    abuse_score: int | None
    known_scanner: bool | None
    tags: list[str]
    #: A known research scanner (M19). The feed hides these unless the client asked for them.
    benign: bool = False


class LiveStats(BaseModel):
    window_seconds: int
    events_last_minute: int
    sessions_last_minute: int
    by_sensor: dict[str, SensorCounts]


class RecentEvents(BaseModel):
    items: list[LiveEvent]


class GeoFile(BaseModel):
    file: str
    bytes: int
    updated_at: datetime
    age_days: float | None = None


class GeoipStatus(BaseModel):
    provider: str  # maxmind | dbip | off | unknown (ingest has not reported yet)
    available: bool
    files: dict[str, GeoFile]
    last_error: str | None
    refresh_days: int | None
    attribution: str | None


class KeyTest(BaseModel):
    ok: bool
    error: str | None  # no_key | quota_exhausted | auth | rate_limited | error
    checked_at: datetime | None


class KeyInfo(BaseModel):
    """Where a provider's key comes from. The key itself is never exposed."""

    configured: bool
    source: Literal["env", "settings"] | None
    last4: str | None  # only for keys set in Settings
    updated_at: datetime | None
    secret_error: str | None  # cannot_decrypt | no_encryption_key
    pending_apply: bool  # saved, but ingest has not picked it up yet
    test: KeyTest | None
    test_pending: bool
    test_requested_at: datetime | None


class ReputationProvider(KeyInfo):
    daily_quota: int | None
    used_today: int
    disabled: str | None
    paused: bool
    last_error: str | None


class KeyEditing(BaseModel):
    enabled: bool
    reason: str | None


class EnrichmentSettings(BaseModel):
    geoip: GeoipStatus
    abuseipdb: ReputationProvider
    greynoise: ReputationProvider
    abusech: ReputationProvider
    virustotal: ReputationProvider
    maxmind: KeyInfo
    nvd: KeyInfo
    github: KeyInfo
    key_editing: KeyEditing
    reported_at: datetime | None
