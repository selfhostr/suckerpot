"""SQLAlchemy 2 typed models for the ``events`` hypertable and ``sessions``."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Computed,
    Date,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base."""


class EventRow(Base):
    """One raw event. Hypertable partitioned on ``ts`` (1-day chunks)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=False), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    sensor: Mapped[str] = mapped_column(Text)
    session_id: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str] = mapped_column(INET)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    country: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    org: Mapped[str | None] = mapped_column(Text)
    abuse_score: Mapped[int | None] = mapped_column(SmallInteger)
    known_scanner: Mapped[bool | None] = mapped_column(Boolean)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    techniques: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # ATT&CK ids (M15)
    benign: Mapped[bool | None] = mapped_column(Boolean)  # research scanner (M19), new rows only

    __table_args__ = (
        Index("ix_events_session_id_ts", "session_id", "ts"),
        Index("ix_events_src_ip_ts", "src_ip", text("ts DESC")),
        Index("ix_events_sensor_ts", "sensor", text("ts DESC")),
        Index("ix_events_tags", "tags", postgresql_using="gin"),
        Index("ix_events_type_ts", "type", text("ts DESC")),
        Index(
            "ix_events_country_ts",
            "country",
            text("ts DESC"),
            postgresql_where=text("country IS NOT NULL"),
        ),
    )


class SessionRow(Base):
    """One attacker connection (a story made of events)."""

    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    sensor: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str] = mapped_column(INET)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    login_attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    login_success: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    commands: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    downloads: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    http_requests: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    country: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    org: Mapped[str | None] = mapped_column(Text)
    abuse_score: Mapped[int | None] = mapped_column(SmallInteger)
    known_scanner: Mapped[bool | None] = mapped_column(Boolean)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    client_tool: Mapped[str | None] = mapped_column(Text)
    techniques: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    campaign_id: Mapped[int | None] = mapped_column(BigInteger)
    clustered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    benign: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    scanner_name: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_sessions_started_at", text("started_at DESC")),
        Index("ix_sessions_sensor_started_at", "sensor", text("started_at DESC")),
        Index("ix_sessions_src_ip", "src_ip"),
        Index("ix_sessions_tags", "tags", postgresql_using="gin"),
        Index("ix_sessions_country", "country"),
        Index("ix_sessions_last_event_at", text("last_event_at DESC")),
        Index("ix_sessions_asn", "asn", postgresql_where=text("asn IS NOT NULL")),
        Index("ix_sessions_techniques", "techniques", postgresql_using="gin"),
        Index("ix_sessions_campaign_id", "campaign_id"),
        Index(
            "ix_sessions_unclustered",
            "last_event_at",
            postgresql_where=text("clustered_at IS NULL"),
        ),
        Index(
            "ix_sessions_not_benign", text("started_at DESC"), postgresql_where=text("NOT benign")
        ),
    )


class IpReputationRow(Base):
    """24 h cache of reputation lookups, one row per source IP."""

    __tablename__ = "ip_reputation"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    abuse_score: Mapped[int | None] = mapped_column(SmallInteger)
    abuse_reports: Mapped[int | None] = mapped_column(Integer)
    abuse_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    gn_noise: Mapped[bool | None] = mapped_column(Boolean)
    gn_riot: Mapped[bool | None] = mapped_column(Boolean)
    gn_classification: Mapped[str | None] = mapped_column(Text)
    gn_name: Mapped[str | None] = mapped_column(Text)
    gn_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class EnrichmentQuotaRow(Base):
    """Calls made to a provider per UTC day (survives restarts)."""

    __tablename__ = "enrichment_quota"

    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    used: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)


class EnrichmentStatusRow(Base):
    """Provider and database status published by ingest for the settings page."""

    __tablename__ = "enrichment_status"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class ProviderSecretRow(Base):
    """An enrichment API key set from the Settings page, encrypted with AES-256-GCM."""

    __tablename__ = "provider_secrets"

    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    last4: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    updated_by: Mapped[str] = mapped_column(Text, nullable=False)


class ProviderTestRequestRow(Base):
    """A "Test key" click: the API cannot reach the internet, so ingest performs the call."""

    __tablename__ = "provider_test_requests"

    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)
    handled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Daily cap on requested tests (the API refuses more, atomically, in one upsert).
    tests_day: Mapped[date] = mapped_column(
        Date, server_default=text("current_date"), nullable=False
    )
    tests_today: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)


class CveRow(Base):
    """A vulnerability from CISA KEV, NVD and/or GitHub advisories (one row per CVE id)."""

    __tablename__ = "cve"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_severity: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    ghsa_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    refs: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    in_kev: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    kev_added_at: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[bool | None] = mapped_column(Boolean)
    kev_action: Mapped[str | None] = mapped_column(Text)
    cpes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    relevance: Mapped[str] = mapped_column(Text, server_default=text("'none'"), nullable=False)
    matched_services: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    rank_score: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sources: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )

    __table_args__ = (
        Index("ix_cve_published_at", text("published_at DESC")),
        Index("ix_cve_kev_added_at", text("kev_added_at DESC"), postgresql_where=text("in_kev")),
        Index("ix_cve_cvss_score", text("cvss_score DESC")),
        Index("ix_cve_rank", text("rank_score DESC"), text("cve_id DESC")),
    )


class CveSyncStateRow(Base):
    """Per-source state of the CVE watch job (last run, outcome, row count)."""

    __tablename__ = "cve_sync_state"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    items_last_run: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)


class IndicatorRow(Base):
    """A URL, domain, IP address or file hash seen in recorded events (never contacted)."""

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    type: Mapped[str] = mapped_column(Text)  # url | domain | ip | hash
    value: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)  # download_host | contacted_host | hash | c2
    host: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sightings: Mapped[int] = mapped_column(BigInteger, server_default=text("1"), nullable=False)
    sensors: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    # A hash computed by a sensor (not just a string in a command).
    trusted: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    # Seen only in demo events: never sent to an intel service.
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)


class IndicatorSessionRow(Base):
    """A bounded link from an indicator to a session that showed it."""

    __tablename__ = "indicator_sessions"

    indicator_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET)
    sensor: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IndicatorIntelRow(Base):
    """One threat-intel answer per indicator and source (24 h cache)."""

    __tablename__ = "indicator_intel"

    indicator_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)  # urlhaus | threatfox | virustotal
    known: Mapped[bool] = mapped_column(Boolean)
    family: Mapped[str | None] = mapped_column(Text)
    threat_type: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    first_seen_ext: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reference: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class IndicatorContactRow(Base):
    """An address a hash's malware is said to contact (read from a provider, never contacted)."""

    __tablename__ = "indicator_contacts"

    hash_indicator_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    address: Mapped[str] = mapped_column(Text, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)  # virustotal | threatfox
    kind: Mapped[str] = mapped_column(Text)  # ip | domain
    port: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(Text)  # high | medium | low
    family: Mapped[str | None] = mapped_column(Text)
    provider_score: Mapped[int | None] = mapped_column(SmallInteger)
    reference: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class IndicatorContactCheckRow(Base):
    """The 24 h cache of contact lookups, one row per hash and source."""

    __tablename__ = "indicator_contact_checks"

    indicator_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class UserRow(Base):
    """An additional dashboard account. The owner account lives in ``.env`` and has no row."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, server_default=text("true"), nullable=False
    )
    disabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    prev_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_logins: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    session_version: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    known_sources: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )


class AuditLogRow(Base):
    """One administrative action. ``details`` is bounded and never holds a secret."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


def _now() -> Any:
    return text("now()")


def _empty_array() -> Any:
    return text("'{}'::text[]")


# ---- M15: campaigns and ATT&CK ---------------------------------------------------------------


class AttackTechniqueRow(Base):
    """The ATT&CK technique catalogue (upserted by ingest from YAML)."""

    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    tactic: Mapped[str] = mapped_column(Text)
    stage: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)


class TechniqueDailyRow(Base):
    """Per-day technique counters, kept forever."""

    __tablename__ = "technique_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    technique: Mapped[str] = mapped_column(Text, primary_key=True)
    sensor: Mapped[str] = mapped_column(Text, primary_key=True)
    sessions: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    events: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)


class CampaignRow(Base):
    """A group of sessions that share infrastructure, tooling or a script."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'active'"), nullable=False)
    merged_into: Mapped[int | None] = mapped_column(BigInteger)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    countries: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    asns: Mapped[list[int]] = mapped_column(
        ARRAY(Integer), server_default=text("'{}'::integer[]"), nullable=False
    )
    sensors: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    techniques: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    stages: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    families: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    severity: Mapped[str] = mapped_column(Text, server_default=text("'info'"), nullable=False)
    rep_session_id: Mapped[str | None] = mapped_column(Text)
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class CampaignKeyRow(Base):
    """A clustering key (script hash, payload host, ...) and the campaign it belongs to."""

    __tablename__ = "campaign_keys"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(BigInteger)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CampaignSessionRow(Base):
    """A bounded link from a campaign to one of its sessions."""

    __tablename__ = "campaign_sessions"

    campaign_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET)
    sensor: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# ---- M16: defend ------------------------------------------------------------------------------


class BlocklistEntryRow(Base):
    """A scored indicator for the blocklists, recomputed by ingest."""

    __tablename__ = "blocklist_entries"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    score: Mapped[int] = mapped_column(SmallInteger)
    reasons: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    campaign_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), server_default=text("'{}'::bigint[]"), nullable=False
    )
    benign: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class BlocklistOverrideRow(Base):
    """An admin decision to always allow or always block an indicator."""

    __tablename__ = "blocklist_overrides"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeedTokenRow(Base):
    """A bearer token for the feeds. Only its sha256 is stored."""

    __tablename__ = "feed_tokens"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary)
    token_hint: Mapped[str] = mapped_column(Text)
    kinds: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{ip}'::text[]"), nullable=False
    )
    min_score: Mapped[int] = mapped_column(SmallInteger, server_default=text("50"), nullable=False)
    include_benign: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_ip: Mapped[str | None] = mapped_column(Text)
    use_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)


class InventoryServiceRow(Base):
    """A service the owner runs, compared with what attackers target."""

    __tablename__ = "inventory_services"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    service: Mapped[str] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    exposure: Mapped[str] = mapped_column(Text, server_default=text("'internal'"), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


# ---- M17: script library ----------------------------------------------------------------------


class ScriptRow(Base):
    """One distinct normalised command sequence."""

    __tablename__ = "scripts"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    fingerprint: Mapped[bytes] = mapped_column(LargeBinary)
    normalized_text: Mapped[str] = mapped_column(Text)
    sample_text: Mapped[str] = mapped_column(Text)
    line_count: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sensors: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    campaign_id: Mapped[int | None] = mapped_column(BigInteger)
    techniques: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)


class ScriptSessionRow(Base):
    """A bounded link from a script to a session that ran it."""

    __tablename__ = "script_sessions"

    script_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET)
    sensor: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScriptExplanationRow(Base):
    """Per-line explanation of a script, from the annotations.

    Rows with source ``llm`` come from the retired LLM explainer: nothing writes or reads them.
    """

    __tablename__ = "script_explanations"

    script_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)  # annotations | llm
    prompt_version: Mapped[int] = mapped_column(
        SmallInteger, server_default=text("1"), nullable=False
    )
    model: Mapped[str | None] = mapped_column(Text)
    lines: Mapped[Any] = mapped_column(JSONB)
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class LlmRequestRow(Base):
    """Retired: the LLM explainer was removed, nothing writes or reads this table any more.

    Kept so the model still matches the schema (a later release can drop it).
    """

    __tablename__ = "llm_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    script_id: Mapped[int] = mapped_column(BigInteger)
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    state: Mapped[str] = mapped_column(Text, server_default=text("'queued'"), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)


# ---- M18: alerts and reports ------------------------------------------------------------------


class AlertChannelRow(Base):
    """Where alerts are sent. The target is encrypted (nonce followed by ciphertext)."""

    __tablename__ = "alert_channels"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    target_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    target_hint: Mapped[str] = mapped_column(Text, server_default=text("''"), nullable=False)
    mask_ips: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class AlertRuleRow(Base):
    """One row per alert rule kind (seeded, all disabled)."""

    __tablename__ = "alert_rules"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    channel_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), server_default=text("'{}'::bigint[]"), nullable=False
    )
    min_severity: Mapped[str] = mapped_column(
        Text, server_default=text("'warning'"), nullable=False
    )
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


class WatchedCveRow(Base):
    """A CVE the owner wants an alert for."""

    __tablename__ = "watched_cves"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    added_by: Mapped[str] = mapped_column(Text)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class AlertOutboxRow(Base):
    """A queued, sent, failed or suppressed alert. Unique per rule, key and channel."""

    __tablename__ = "alert_outbox"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    rule_kind: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(Text)
    channel_id: Mapped[int] = mapped_column(BigInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    state: Mapped[str] = mapped_column(Text, server_default=text("'pending'"), nullable=False)
    attempts: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(Text)


class AlertCursorRow(Base):
    """Ingest's progress per alert rule."""

    __tablename__ = "alert_cursors"

    rule_kind: Mapped[str] = mapped_column(Text, primary_key=True)
    cursor: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


class WeeklyReportRow(Base):
    """A rendered weekly report, kept for two years."""

    __tablename__ = "weekly_reports"

    week_start: Mapped[date] = mapped_column(Date, primary_key=True)
    html: Mapped[str] = mapped_column(Text)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class AlertTestRequestRow(Base):
    """A request to send a test message to a channel (the API inserts, ingest answers)."""

    __tablename__ = "alert_test_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    channel_id: Mapped[int] = mapped_column(BigInteger)
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    state: Mapped[str] = mapped_column(Text, server_default=text("'queued'"), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)


class FetchTargetRow(Base):
    """A URL the collector may download (from an indicator or found inside a fetched script)."""

    __tablename__ = "fetch_targets"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    url: Mapped[str] = mapped_column(Text, unique=True)
    scheme: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(Text)
    indicator_id: Mapped[int | None] = mapped_column(BigInteger)
    parent_sha256: Mapped[str | None] = mapped_column(Text)
    depth: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    # pending | fetched | failed | gone | refused | too_large | unsupported | quarantine_full
    status: Mapped[str] = mapped_column(Text, server_default=text("'pending'"), nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    fetches: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sha256: Mapped[str | None] = mapped_column(Text)
    # local | network_verify (M32, 0030): a verification fetch never spawns child targets.
    origin: Mapped[str] = mapped_column(Text, server_default=text("'local'"), nullable=False)


class FetchAttemptRow(Base):
    """One download attempt of a fetch target (pruned by the collector)."""

    __tablename__ = "fetch_attempts"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    target_id: Mapped[int] = mapped_column(BigInteger)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    http_status: Mapped[int | None] = mapped_column(SmallInteger)
    bytes: Mapped[int | None] = mapped_column(BigInteger)
    redirects: Mapped[int | None] = mapped_column(SmallInteger)
    outcome: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(Text)


class SampleRow(Base):
    """A file in quarantine, identified by its sha256 (metadata only, never the content)."""

    __tablename__ = "samples"

    sha256: Mapped[str] = mapped_column(Text, primary_key=True)
    sha1: Mapped[str] = mapped_column(Text)
    md5: Mapped[str] = mapped_column(Text)
    tlsh: Mapped[str | None] = mapped_column(Text)
    size: Mapped[int] = mapped_column(BigInteger)
    kind: Mapped[str | None] = mapped_column(Text)
    arch: Mapped[str | None] = mapped_column(Text)
    bits: Mapped[int | None] = mapped_column(SmallInteger)
    endian: Mapped[str | None] = mapped_column(Text)
    linking: Mapped[str | None] = mapped_column(Text)
    packer: Mapped[str | None] = mapped_column(Text)
    family: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, server_default=text("'notice'"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    stored: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    # pending | done | failed | timeout
    analysis_status: Mapped[str] = mapped_column(
        Text, server_default=text("'pending'"), nullable=False
    )
    analysis_version: Mapped[int] = mapped_column(
        SmallInteger, server_default=text("0"), nullable=False
    )


class SampleAnalysisRow(Base):
    """Static analysis findings of one sample (YARA hits, strings, deobfuscated script)."""

    __tablename__ = "sample_analysis"

    sha256: Mapped[str] = mapped_column(Text, primary_key=True)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    elapsed_ms: Mapped[int | None] = mapped_column(Integer)
    yara: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    strings: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    deobfuscated: Mapped[str | None] = mapped_column(Text)
    deob_steps: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    errors: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )


class SampleSourceRow(Base):
    """Which fetch target served which sample."""

    __tablename__ = "sample_sources"

    sha256: Mapped[str] = mapped_column(Text, primary_key=True)
    target_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    first_fetched: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_fetched: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SampleLinkRow(Base):
    """An edge out of a sample: the next URL to fetch or a command-and-control address."""

    __tablename__ = "sample_links"

    sha256: Mapped[str] = mapped_column(Text, primary_key=True)
    # next_url | c2_ip | c2_domain | c2_url
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    port: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(Text)
    target_id: Mapped[int | None] = mapped_column(BigInteger)
    indicator_id: Mapped[int | None] = mapped_column(BigInteger)


class RdapBootstrapRow(Base):
    """A cached IANA RDAP bootstrap file (ipv4, ipv6, asn or dns)."""

    __tablename__ = "rdap_bootstrap"

    # The attribute cannot be called ``registry`` (taken by DeclarativeBase).
    registry_name: Mapped[str] = mapped_column("registry", Text, primary_key=True)
    body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AbuseNetworkRow(Base):
    """The abuse contact of a network block or a registrar, from RDAP (cached until expiry)."""

    __tablename__ = "abuse_networks"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # ip | domain
    cidr: Mapped[str | None] = mapped_column(CIDR, unique=True)
    domain: Mapped[str | None] = mapped_column(Text, unique=True)
    handle: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(Text)
    country: Mapped[str | None] = mapped_column(Text)
    rir: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    mailboxes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    # rdap | rdap_remarks | ripestat | rdap_autnum | manual
    source: Mapped[str] = mapped_column(Text)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # The waiting recipient of a network with no contact.
    recipient_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_recipients.id", ondelete="SET NULL")
    )


class AbuseLookupRow(Base):
    """Outcome of the contact lookup of one subject (also the negative cache)."""

    __tablename__ = "abuse_lookups"

    subject: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # ip | domain
    network_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_networks.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(Text)  # found | no_contact | error | pending
    attempts: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AbuseRecipientRow(Base):
    """A mailbox that receives reports (from RDAP or typed by the owner)."""

    __tablename__ = "abuse_recipients"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    # NULL while the network has no known contact (a "waiting" recipient).
    mailbox: Mapped[str | None] = mapped_column(Text, unique=True)
    name: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)  # rdap | manual
    override_mailbox: Mapped[str | None] = mapped_column(Text)
    muted: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    # Other domains a provider answers from (M26), at most 5.
    reply_domains: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )


class AbuseReportRow(Base):
    """One report to one recipient. Drafts are built by ingest; the owner reviews and sends."""

    __tablename__ = "abuse_reports"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True)
    id_seed: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    recipient_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("abuse_recipients.id"))
    kind: Mapped[str] = mapped_column(Text)  # attack_source | payload_host | c2
    # draft | reviewed | sent | closed | discarded | superseded
    status: Mapped[str] = mapped_column(Text, server_default=text("'draft'"), nullable=False)
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    subject_count: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB)
    revision: Mapped[int] = mapped_column(Integer, server_default=text("1"), nullable=False)
    content_sha256: Mapped[str] = mapped_column(Text)
    guard_ok: Mapped[bool] = mapped_column(Boolean)
    guard_codes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    redaction: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    options: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[str | None] = mapped_column(Text)
    reviewed_revision: Mapped[int | None] = mapped_column(Integer)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_by: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[str | None] = mapped_column(Text)
    sent_via: Mapped[str | None] = mapped_column(Text)  # manual | smtp (NULL before M25)
    # 12 random hex digits, unrelated to every other id (M26); immutable.
    reply_token: Mapped[str] = mapped_column(
        Text, server_default=text("left(replace(gen_random_uuid()::text, '-', ''), 12)")
    )


class AbuseReportSubjectRow(Base):
    """An address, URL or domain reported in one report."""

    __tablename__ = "abuse_report_subjects"

    report_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("abuse_reports.id", ondelete="CASCADE"), primary_key=True
    )
    subject_type: Mapped[str] = mapped_column(Text, primary_key=True)  # ip | url | domain
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    network_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_networks.id", ondelete="SET NULL")
    )
    first_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[int] = mapped_column(Integer)
    events: Mapped[int] = mapped_column(Integer)


class AbuseReportRequestRow(Base):
    """A request from the API that ingest answers (regenerate a report, look a contact up again)."""

    __tablename__ = "abuse_report_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    report_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_reports.id", ondelete="CASCADE")
    )
    action: Mapped[str] = mapped_column(Text)  # regenerate | lookup_again
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str | None] = mapped_column(Text)


class ReportSettingsRow(Base):
    """The single row of report wording and defaults. Typed in Settings, never in ``.env``."""

    __tablename__ = "report_settings"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    reply_contact: Mapped[str | None] = mapped_column(Text)
    signature: Mapped[str | None] = mapped_column(Text)
    intro: Mapped[str | None] = mapped_column(Text)
    outro: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    subject_template: Mapped[str | None] = mapped_column(Text)
    # subject | subject_and_body | off (M26)
    reference_style: Mapped[str] = mapped_column(
        Text, server_default=text("'subject'"), nullable=False
    )
    xarf_user_agent: Mapped[str | None] = mapped_column(Text)
    defaults: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    revision: Mapped[int] = mapped_column(Integer, server_default=text("1"), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str | None] = mapped_column(Text)


class ReportSelfTermRow(Base):
    """Something that must never appear in a report (the monitored system's address, names)."""

    __tablename__ = "report_self_terms"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # address | cidr | name | text
    value: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)  # learned | manual
    distinct_sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    confirmed: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)


class EgressTrustedExitRow(Base):
    """A VPN exit range the owner trusts (M23). At most 8 rows (trigger in migration 0020)."""

    __tablename__ = "egress_trusted_exits"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    cidr: Mapped[str] = mapped_column(CIDR, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    created_by: Mapped[str | None] = mapped_column(Text)


class PipelineStateRow(Base):
    """One row (id 1): ingest's heartbeat and last failure (0031). Ingest updates it, the API reads
    it for the "pipeline stalled" banner."""

    __tablename__ = "pipeline_state"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    failing_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    parked_events: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class EgressCheckRequestRow(Base):
    """A "Check now" from the dashboard (M24). Ingest wakes its gate and stamps ``done_at``.
    The table keeps its last 100 rows (trigger in migration 0021)."""

    __tablename__ = "egress_check_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    requested_by: Mapped[str | None] = mapped_column(Text)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportSmtpRow(Base):
    """The one SMTP profile for abuse reports (M25). The API writes the password columns but its
    role cannot read them back; only ingest decrypts them."""

    __tablename__ = "report_smtp"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    host: Mapped[str] = mapped_column(Text)
    port: Mapped[int] = mapped_column(Integer)
    security: Mapped[str] = mapped_column(Text)  # starttls | ssl
    username: Mapped[str] = mapped_column(Text, server_default=text("''"))
    from_address: Mapped[str] = mapped_column(Text)
    from_name: Mapped[str] = mapped_column(Text, server_default=text("''"))
    password_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_set: Mapped[bool] = mapped_column(
        Boolean, Computed("password_ciphertext IS NOT NULL", persisted=True)
    )
    mode: Mapped[str] = mapped_column(Text, server_default=text("'off'"))  # off | click | auto
    auto_hold_minutes: Mapped[int] = mapped_column(Integer, server_default=text("60"))
    daily_cap: Mapped[int] = mapped_column(Integer, server_default=text("20"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_by: Mapped[str | None] = mapped_column(Text)


class AbuseSendRequestRow(Base):
    """A report (or a test) to send by SMTP, asked by the API or scheduled by ingest (M25)."""

    __tablename__ = "abuse_send_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    report_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_reports.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(Text)  # send | test
    auto: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # pending | sending | sent | failed | cancelled
    status: Mapped[str] = mapped_column(Text, server_default=text("'pending'"), nullable=False)
    error_code: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    message_id: Mapped[str | None] = mapped_column(Text)  # SMTP Message-ID, set once (M26)


class ReportImapRow(Base):
    """The one IMAP profile that receives replies to reports (M26). The API writes the password
    columns but its role cannot read them back; only ingest decrypts them."""

    __tablename__ = "report_imap"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    host: Mapped[str] = mapped_column(Text)
    port: Mapped[int] = mapped_column(Integer)
    security: Mapped[str] = mapped_column(Text)  # ssl | starttls
    username: Mapped[str] = mapped_column(Text)
    password_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_set: Mapped[bool] = mapped_column(
        Boolean, Computed("password_ciphertext IS NOT NULL", persisted=True)
    )
    folder: Mapped[str] = mapped_column(Text, server_default=text("'INBOX'"), nullable=False)
    processed_action: Mapped[str] = mapped_column(
        Text, server_default=text("'mark_read'"), nullable=False
    )  # mark_read | move
    move_folder: Mapped[str | None] = mapped_column(Text)
    poll_minutes: Mapped[int] = mapped_column(Integer, server_default=text("15"), nullable=False)
    since: Mapped[date] = mapped_column(
        Date, server_default=text("((now() AT TIME ZONE 'UTC')::date)"), nullable=False
    )
    # The authserv-id of the Authentication-Results header the owner's mailbox provider adds.
    trusted_authserv_id: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_by: Mapped[str | None] = mapped_column(Text)


class TakedownTargetRow(Base):
    """A reported target whose fate is tracked (M27). Ingest owns the state, the collector the HTTP
    re-check columns; ``reported_at`` only moves earlier."""

    __tablename__ = "takedown_targets"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # url | ip | domain
    role: Mapped[str] = mapped_column(Text)  # attack_source | payload_host | payload_url | c2
    value: Mapped[str] = mapped_column(Text)
    target_key: Mapped[str] = mapped_column(Text)  # sha256(kind || ':' || value)
    parent_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("takedown_targets.id", ondelete="CASCADE")
    )
    fetch_target_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("fetch_targets.id", ondelete="SET NULL")
    )
    network_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_networks.id", ondelete="SET NULL")
    )
    asn: Mapped[int | None] = mapped_column(Integer)
    country: Mapped[str | None] = mapped_column(Text)
    provider_key: Mapped[str] = mapped_column(Text)
    provider_name: Mapped[str | None] = mapped_column(Text)
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    channels: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    tracking: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    track_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_by: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text, server_default=text("'unknown'"), nullable=False)
    state_source: Mapped[str | None] = mapped_column(Text)
    state_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    down_before_report: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    last_up_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_down_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resurrections: Mapped[int] = mapped_column(
        SmallInteger, server_default=text("0"), nullable=False
    )
    listing_step: Mapped[int] = mapped_column(
        SmallInteger, server_default=text("0"), nullable=False
    )
    listing_next_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    http_eligible: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    baseline_sha256: Mapped[str | None] = mapped_column(Text)
    last_sha256: Mapped[str | None] = mapped_column(Text)
    http_step: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    http_next_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    http_last_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class TakedownCheckRow(Base):
    """One check of a target. ``detail`` holds constants and small numbers only."""

    __tablename__ = "takedown_checks"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    target_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("takedown_targets.id", ondelete="CASCADE")
    )
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    method: Mapped[str] = mapped_column(Text)  # http | urlhaus | threatfox | abuseipdb | ...
    outcome: Mapped[str] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(SmallInteger)
    sha256: Mapped[str | None] = mapped_column(Text)
    bytes: Mapped[int | None] = mapped_column(BigInteger)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


class AbusechSubmissionSettingsRow(Base):
    """The one abuse.ch submission profile (M27). The Auth-Key is AES-GCM ciphertext (AAD
    ``abusech_submission``); the API cannot read it back, only ingest decrypts it."""

    __tablename__ = "abusech_submission"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    mode: Mapped[str] = mapped_column(Text, server_default=text("'off'"))  # off | review | auto
    threatfox_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    anonymous: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    auto_hold_minutes: Mapped[int] = mapped_column(Integer, server_default=text("60"))
    daily_cap: Mapped[int] = mapped_column(Integer, server_default=text("20"))
    key_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_set: Mapped[bool] = mapped_column(
        Boolean, Computed("key_ciphertext IS NOT NULL", persisted=True)
    )
    key_last4: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_by: Mapped[str | None] = mapped_column(Text)


class ReportImapStateRow(Base):
    """What ingest remembers about the mailbox between polls (M26). Single row."""

    __tablename__ = "report_imap_state"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    profile_fingerprint: Mapped[str | None] = mapped_column(Text)
    uidvalidity: Mapped[int | None] = mapped_column(BigInteger)
    last_uid: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)
    move_supported: Mapped[bool | None] = mapped_column(Boolean)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    counters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


class ReportImapRequestRow(Base):
    """A test or a poll asked from Settings by the API and answered by ingest (M26)."""

    __tablename__ = "report_imap_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # test | poll
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, server_default=text("'pending'"), nullable=False)
    error_code: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AbuseReplyRow(Base):
    """One relevant incoming mail: metadata and a bounded plain-text excerpt (M26)."""

    __tablename__ = "abuse_replies"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    source: Mapped[str] = mapped_column(Text)  # imap | paste
    uidvalidity: Mapped[int | None] = mapped_column(BigInteger)
    uid: Mapped[int | None] = mapped_column(BigInteger)
    message_id_sha256: Mapped[str | None] = mapped_column(Text, unique=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    date_header: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    from_address: Mapped[str | None] = mapped_column(Text)
    from_domain: Mapped[str | None] = mapped_column(Text)
    subject: Mapped[str | None] = mapped_column(Text)
    auth: Mapped[str] = mapped_column(Text, server_default=text("'none'"), nullable=False)
    report_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_reports.id", ondelete="CASCADE")
    )
    # message_id | token | dsn | ticket | sender_domain | manual | none
    match_method: Mapped[str] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    # auto_ack | ticket_opened | resolved | rejected | bounce | human_reply | unknown
    classification: Mapped[str] = mapped_column(Text)
    classification_source: Mapped[str] = mapped_column(
        Text, server_default=text("'rule'"), nullable=False
    )  # rule | manual
    rule_id: Mapped[str | None] = mapped_column(Text)
    ticket_id: Mapped[str | None] = mapped_column(Text)
    dsn_status: Mapped[str | None] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    attachments: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
    excerpt: Mapped[str | None] = mapped_column(Text)
    excerpt_purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (UniqueConstraint("source", "uidvalidity", "uid"),)


class AbuseReplyImportRow(Base):
    """A pasted or uploaded reply waiting for ingest; the raw bytes are cleared once done."""

    __tablename__ = "abuse_reply_imports"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    report_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_reports.id", ondelete="CASCADE")
    )
    raw: Mapped[bytes] = mapped_column(LargeBinary)
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, server_default=text("'pending'"), nullable=False)
    reply_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_replies.id", ondelete="SET NULL")
    )
    error_code: Mapped[str | None] = mapped_column(Text)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AbuseReportOutcomeRow(Base):
    """What came of a sent report: derived columns (ingest) and the owner's override (API)."""

    __tablename__ = "abuse_report_outcomes"

    report_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("abuse_reports.id", ondelete="CASCADE"), primary_key=True
    )
    auto_outcome: Mapped[str] = mapped_column(Text, server_default=text("'none'"), nullable=False)
    reply_count: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    first_reply_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_human_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ticket_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    bounced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ticket_id: Mapped[str | None] = mapped_column(Text)
    needs_review: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    auto_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    manual_outcome: Mapped[str | None] = mapped_column(Text)
    manual_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    manual_by: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)


class AbusechSubmissionRow(Base):
    """A URL or C2 address submitted (or to be submitted) to URLhaus or ThreatFox; the audit log."""

    __tablename__ = "abusech_submissions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    platform: Mapped[str] = mapped_column(Text)  # urlhaus | threatfox
    ioc_type: Mapped[str] = mapped_column(Text)  # url | ip:port
    value: Mapped[str] = mapped_column(Text)
    threat: Mapped[str] = mapped_column(Text)  # malware_download | botnet_cc
    malware: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    sample_sha256: Mapped[str | None] = mapped_column(
        Text, ForeignKey("samples.sha256", ondelete="SET NULL")
    )
    fetch_target_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("fetch_targets.id", ondelete="SET NULL")
    )
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    lookup: Mapped[str] = mapped_column(Text, server_default=text("'pending'"), nullable=False)
    # candidate | pending | submitting | submitted | duplicate | rejected | failed | cancelled
    # | skipped_known | skipped_never_list | guard_failed
    status: Mapped[str] = mapped_column(Text, server_default=text("'candidate'"), nullable=False)
    result_code: Mapped[str | None] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(Text)
    auto: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[str | None] = mapped_column(Text)
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TakedownTargetLinkRow(Base):
    """Which report or submission put a target under tracking (the table has no primary key; the
    mapper identity is the whole row)."""

    __tablename__ = "takedown_target_links"

    target_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("takedown_targets.id", ondelete="CASCADE"), primary_key=True
    )
    report_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abuse_reports.id", ondelete="CASCADE"), primary_key=True
    )
    submission_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("abusech_submissions.id", ondelete="CASCADE"), primary_key=True
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class OutcomeRollupRow(Base):
    """Monthly aggregates per provider, kind and channel: no values, kept forever."""

    __tablename__ = "outcome_rollup_monthly"

    month: Mapped[date] = mapped_column(Date, primary_key=True)
    provider_key: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    channel: Mapped[str] = mapped_column(Text, primary_key=True)
    asn: Mapped[int | None] = mapped_column(Integer)
    country: Mapped[str | None] = mapped_column(Text)
    reports_sent: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    reports_answered: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    auto_ack: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    ticket_opened: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    resolved: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    rejected: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    bounced: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    human_reply: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    targets: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    targets_eligible_48h: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    targets_down_48h: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    targets_eligible_7d: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    targets_down_7d: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    targets_eligible_30d: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    targets_down_30d: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    ttd_p50_s: Mapped[int | None] = mapped_column(Integer)
    first_reply_p50_s: Mapped[int | None] = mapped_column(Integer)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class SetupProgressRow(Base):
    """The one row (``id = 1``) that remembers how far the first-run setup got (M28)."""

    __tablename__ = "setup_progress"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    skipped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_by: Mapped[str | None] = mapped_column(Text)
    steps: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


class NetworkMembershipRow(Base):
    """Membership of the opt-in SuckerPot network (M29): one row. ``desired`` is written by the
    API, everything else by ingest. ``privkey_enc`` is readable by ingest only."""

    __tablename__ = "network_membership"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    desired: Mapped[str] = mapped_column(Text, server_default=text("'off'"), nullable=False)
    state: Mapped[str] = mapped_column(Text, server_default=text("'off'"), nullable=False)
    pseudonym: Mapped[str | None] = mapped_column(Text)
    country: Mapped[str | None] = mapped_column(Text)
    show_country: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    fingerprint: Mapped[str | None] = mapped_column(Text)
    pubkey: Mapped[bytes | None] = mapped_column(LargeBinary)
    privkey_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    privkey_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    enrolled_day: Mapped[date | None] = mapped_column(Date)
    eligible_from_day: Mapped[date | None] = mapped_column(Date)
    standing: Mapped[str | None] = mapped_column(Text)
    next_submit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_submit_day: Mapped[date | None] = mapped_column(Date)
    last_pull_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_summary_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pull_cursor: Mapped[str | None] = mapped_column(Text)
    synced_pseudonym: Mapped[str | None] = mapped_column(Text)
    synced_country: Mapped[str | None] = mapped_column(Text)
    synced_show_country: Mapped[bool | None] = mapped_column(Boolean)
    leave_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    left_day: Mapped[date | None] = mapped_column(Date)  # M32 (0030): UTC day the node left
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class NetworkSubmissionRow(Base):
    """One daily batch sent to the hub, with the exact JSON for a week (M29)."""

    __tablename__ = "network_submissions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    day: Mapped[date] = mapped_column(Date, unique=True)
    batch_id: Mapped[str] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text)  # sent | failed | skipped
    counts: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    dropped: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    error_code: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class NetworkTargetRow(Base):
    """A target the network confirmed, as the hub published it (M29)."""

    __tablename__ = "network_targets"

    hub_id: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str | None] = mapped_column(Text)
    value_b: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    nodes: Mapped[int] = mapped_column(SmallInteger)
    countries: Mapped[int | None] = mapped_column(SmallInteger)
    first_day: Mapped[date] = mapped_column(Date)
    last_day: Mapped[date] = mapped_column(Date)
    services: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    activity: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    families: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    reported_day: Mapped[date | None] = mapped_column(Date)
    taken_down_day: Mapped[date | None] = mapped_column(Date)
    mine: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class NetworkVerifyTaskRow(Base):
    """A verification task leased from the hub (M32, 0030). Pruned 30 days after reporting."""

    __tablename__ = "network_verify_tasks"

    hub_id: Mapped[str] = mapped_column(Text, primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(Text)
    # received | queued | done | reported | refused | skipped
    state: Mapped[str] = mapped_column(Text)
    fetch_target_id: Mapped[int | None] = mapped_column(BigInteger)
    outcome: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(Text)
    size: Mapped[int | None] = mapped_column(Integer)
    file_type: Mapped[str | None] = mapped_column(Text)
    family: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NetworkSummaryRow(Base):
    """The hub's daily summary of the network, one row (M29)."""

    __tablename__ = "network_summary"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class NetworkFeedStateRow(Base):
    """What the feed worker last verified from the public blocklist feed (M30): one row."""

    __tablename__ = "network_feed_state"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, server_default=text("1"))
    serial: Mapped[int | None] = mapped_column(BigInteger)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_id: Mapped[str | None] = mapped_column(Text)
    index_sha256: Mapped[str | None] = mapped_column(Text)
    files: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    last_fetch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class NetworkFeedEntryRow(Base):
    """One entry of a stored public feed list (M30). Replaced list by list on every fetch."""

    __tablename__ = "network_feed_entries"
    __table_args__ = (Index("ix_network_feed_entries_value", "value"),)

    # The column is "list"; the attribute avoids shadowing the builtin inside the class body.
    list_name: Mapped[str] = mapped_column("list", Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    family: Mapped[int | None] = mapped_column(SmallInteger)
    tier: Mapped[str | None] = mapped_column(Text)
    categories: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    services: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    families: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    ports: Mapped[list[int]] = mapped_column(ARRAY(Integer), server_default=text("'{}'"))
    first_seen: Mapped[date | None] = mapped_column(Date)
    last_seen: Mapped[date | None] = mapped_column(Date)
    expires: Mapped[date | None] = mapped_column(Date)
    reported: Mapped[bool | None] = mapped_column(Boolean)
    seen_here: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
