"""Hub tables (design M29 section 6.3, migration ``h0001_initial``).

No table has an address column about a client. ``nodes.pubkey`` is the only node identifier.
Additions to the design DDL, all privacy-neutral: ``nodes.pseudonym_changed_day``,
``observations.fetched`` / ``file_type``, ``targets.seq`` (a change cursor kept by a trigger) and
the ``network_summary`` cache written once a day by the worker.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CHAR, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Node(Base):
    __tablename__ = "nodes"
    __table_args__ = (CheckConstraint("length(pubkey) = 32", name="nodes_pubkey_len"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    pubkey: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    pseudonym: Mapped[str | None] = mapped_column(Text)
    pseudonym_key: Mapped[str | None] = mapped_column(Text, unique=True)
    country: Mapped[str | None] = mapped_column(CHAR(2))
    show_country: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    enrolled_day: Mapped[date] = mapped_column(Date)
    last_active_day: Mapped[date] = mapped_column(Date)
    reputation: Mapped[float] = mapped_column(Float(24), server_default=text("0.6"))
    standing: Mapped[str] = mapped_column(Text, server_default=text("'active'"))
    protocol: Mapped[str] = mapped_column(Text)
    pseudonym_changed_day: Mapped[date | None] = mapped_column(Date)


class EnrolChallenge(Base):
    __tablename__ = "enrol_challenges"

    challenge: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    pubkey: Mapped[bytes] = mapped_column(LargeBinary, index=True)
    difficulty: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Nonce(Base):
    __tablename__ = "nonces"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    nonce: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Batch(Base):
    __tablename__ = "batches"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    batch_id: Mapped[bytes] = mapped_column(LargeBinary)
    items: Mapped[int] = mapped_column(Integer, server_default=text("0"))


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        Index("observations_node_day_kind_value", "node_id", "day", "kind", "value", unique=True),
        Index("observations_kind_value_day", "kind", "value", "day"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE")
    )
    day: Mapped[date] = mapped_column(Date, index=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    services: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    activity: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    families: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    sessions: Mapped[int | None] = mapped_column(SmallInteger)
    attempts: Mapped[int | None] = mapped_column(SmallInteger)
    fetched: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    file_type: Mapped[str | None] = mapped_column(Text)
    via: Mapped[str | None] = mapped_column(Text)


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (
        # The unique (kind, coalesce(value_b, value)) index is an expression index made by the
        # migration; the ORM does not need it.
        Index("targets_state", "state"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str | None] = mapped_column(Text)
    value_b: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    node_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    weight: Mapped[float] = mapped_column(Float(24), server_default=text("0"))
    country_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    first_day: Mapped[date | None] = mapped_column(Date)
    last_day: Mapped[date | None] = mapped_column(Date)
    services: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    activity: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    families: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    confirmed_day: Mapped[date | None] = mapped_column(Date)
    reported_day: Mapped[date | None] = mapped_column(Date)
    taken_down_day: Mapped[date | None] = mapped_column(Date)
    report_id: Mapped[int | None] = mapped_column(BigInteger)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Change cursor: a trigger assigns the next value of targets_seq on every insert and update.
    seq: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), index=True)


class TargetContributor(Base):
    __tablename__ = "target_contributors"

    target_id: Mapped[str] = mapped_column(
        Text, ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )


class TakedownVote(Base):
    __tablename__ = "takedown_votes"

    target_id: Mapped[str] = mapped_column(
        Text, ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    state: Mapped[str] = mapped_column(Text)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    recipient: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    target_ids: Mapped[list[str]] = mapped_column(ARRAY(Text))
    state: Mapped[str] = mapped_column(Text)  # queued|approved|sent|failed|cancelled
    body_text: Mapped[str] = mapped_column(Text)
    xarf: Mapped[str | None] = mapped_column(Text)
    created_day: Mapped[date] = mapped_column(Date)
    approved_by: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(Text)


class RecipientLog(Base):
    __tablename__ = "recipient_log"

    recipient: Mapped[str] = mapped_column(Text, primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    count: Mapped[int] = mapped_column(Integer)


class NodeStatsWeekly(Base):
    __tablename__ = "node_stats_weekly"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    week: Mapped[date] = mapped_column(Date, primary_key=True)
    active_days: Mapped[int] = mapped_column(SmallInteger)
    tier: Mapped[int] = mapped_column(SmallInteger)


class NetworkDaily(Base):
    __tablename__ = "network_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    active_nodes: Mapped[int] = mapped_column(Integer)
    members: Mapped[int] = mapped_column(Integer)
    confirmed: Mapped[int] = mapped_column(Integer)
    reported: Mapped[int] = mapped_column(Integer)
    taken_down: Mapped[int] = mapped_column(Integer)


class NetworkSummaryRow(Base):
    __tablename__ = "network_summary"
    __table_args__ = (CheckConstraint("id = 1", name="network_summary_single"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    generated_day: Mapped[date] = mapped_column(Date)
    data: Mapped[dict[str, object]] = mapped_column(JSONB)


class NeverList(Base):
    __tablename__ = "never_list"

    value: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # ip (address or cidr) | domain | asn | url
    note: Mapped[str | None] = mapped_column(String(200))


class HubAudit(Base):
    """Admin CLI actions. Never holds node data."""

    __tablename__ = "hub_audit"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict[str, object] | None] = mapped_column(JSONB)


class WorkerState(Base):
    """Job markers of the worker (migration h0002). No node data."""

    __tablename__ = "worker_state"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class PayloadLink(Base):
    """A payload host and a URL it served on a day (migration h0005). No node reference."""

    __tablename__ = "payload_links"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    kind: Mapped[str] = mapped_column(Text, primary_key=True)  # payload_ip | domain
    value: Mapped[str] = mapped_column(Text, primary_key=True)  # the host, as in observations
    url_b: Mapped[str] = mapped_column(Text, primary_key=True)
    # Eligible nodes that asserted the link on that day (one batch per node and day; h0007).
    nodes: Mapped[int] = mapped_column(Integer, server_default=text("1"))


class TargetHost(Base):
    __tablename__ = "target_hosts"

    url_target_id: Mapped[str] = mapped_column(
        Text, ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )
    payload_target_id: Mapped[str] = mapped_column(
        Text, ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )


class FeedEntry(Base):
    """One value of a published list and its lifecycle (pending, listed, removed)."""

    __tablename__ = "feed_entries"

    list_id: Mapped[str] = mapped_column("list", Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    family: Mapped[int | None] = mapped_column(SmallInteger)
    tier: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    categories: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    services: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    families: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    ports: Mapped[list[int]] = mapped_column(ARRAY(Integer), server_default=text("'{}'"))
    first_seen: Mapped[date] = mapped_column(Date)
    last_seen: Mapped[date] = mapped_column(Date)
    expires: Mapped[date] = mapped_column(Date)
    reported: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    eligible_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    listed_day: Mapped[date | None] = mapped_column(Date)
    removed_day: Mapped[date | None] = mapped_column(Date)
    removed_reason: Mapped[str | None] = mapped_column(Text)
    corroborated: Mapped[bool | None] = mapped_column(Boolean)
    corroborated_day: Mapped[date | None] = mapped_column(Date)
    target_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("targets.id", ondelete="SET NULL")
    )


class FeedRun(Base):
    __tablename__ = "feed_runs"

    serial: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(Text)  # published|held|discarded|failed|unchanged
    counts: Mapped[dict[str, object]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    diff: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(Text)


class FeedDaily(Base):
    __tablename__ = "feed_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    list_id: Mapped[str] = mapped_column("list", Text, primary_key=True)
    entries: Mapped[int] = mapped_column(Integer)
    added: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    removed_expired: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    removed_taken_down: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    removed_delisted: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    removed_excluded: Mapped[int] = mapped_column(Integer, server_default=text("0"))


class FeedAllow(Base):
    __tablename__ = "feed_allow"

    value: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # ip (address or cidr) | domain
    reason: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    added_day: Mapped[date] = mapped_column(Date)
    expires_day: Mapped[date | None] = mapped_column(Date)
    source: Mapped[str] = mapped_column(Text)  # admin | delist
    # The list the row applies to; NULL for every list (migration h0006).
    list_id: Mapped[str | None] = mapped_column("list", Text)


class FeedAutoRange(Base):
    __tablename__ = "feed_auto_ranges"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    prefix: Mapped[str] = mapped_column(Text, primary_key=True)
    fetched_day: Mapped[date] = mapped_column(Date)


class DelistChallenge(Base):
    __tablename__ = "delist_challenges"

    challenge: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    difficulty: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class DelistRequest(Base):
    __tablename__ = "delist_requests"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary)
    value: Mapped[str] = mapped_column(Text)
    list_id: Mapped[str | None] = mapped_column("list", Text)
    category: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    contact: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(Text)
    public_note: Mapped[str | None] = mapped_column(Text)
    created_day: Mapped[date] = mapped_column(Date)
    decided_day: Mapped[date | None] = mapped_column(Date)
    # The list an accepted decision applies to; NULL for every list (migration h0006).
    scope: Mapped[str | None] = mapped_column(Text)


class NodeRole(Base):
    """A role granted by an operator (``verifier``). Migration h0009."""

    __tablename__ = "node_roles"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(Text, primary_key=True)
    granted_day: Mapped[date] = mapped_column(Date)


class VerifyTask(Base):
    """A link a verifier fetches. ``url`` is the clear link (deleted with the task, H9); the only
    node reference is the live lease. ``site`` is the lower-cased host of ``url``."""

    __tablename__ = "verify_tasks"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    url_b: Mapped[str] = mapped_column(Text, unique=True)
    url: Mapped[str | None] = mapped_column(Text)
    site: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    refusal: Mapped[str | None] = mapped_column(Text)
    reporters: Mapped[int] = mapped_column(Integer)
    reporter_cohorts: Mapped[int] = mapped_column(Integer)
    last_report_day: Mapped[date] = mapped_column(Date)
    created_day: Mapped[date] = mapped_column(Date)
    revealed_day: Mapped[date | None] = mapped_column(Date)
    release_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_node: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="SET NULL")
    )
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    ended_day: Mapped[date | None] = mapped_column(Date)


class VerifyAttestation(Base):
    __tablename__ = "verify_attestations"

    task_id: Mapped[str] = mapped_column(
        Text, ForeignKey("verify_tasks.id", ondelete="CASCADE"), primary_key=True
    )
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date)
    outcome: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(Text)
    size: Mapped[int | None] = mapped_column(Integer)
    file_type: Mapped[str | None] = mapped_column(Text)
    family: Mapped[str | None] = mapped_column(Text)
    malware_like: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))


class VerifyDaily(Base):
    __tablename__ = "verify_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    created: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    revealed: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    refused: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    queued: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    attested: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    malware_like: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    expired: Mapped[int] = mapped_column(Integer, server_default=text("0"))


class ObservatoryDaily(Base):
    """Network-wide aggregates of one final day, frozen once (design M34, migration h0010).

    No node reference: ``nodes`` counts the distinct nodes behind a row, ``total`` the distinct
    values (attacking addresses for most metrics)."""

    __tablename__ = "observatory_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    metric: Mapped[str] = mapped_column(Text, primary_key=True)
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    total: Mapped[int] = mapped_column(Integer)
    nodes: Mapped[int] = mapped_column(Integer)
