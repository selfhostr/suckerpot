"""Draft reports: contact resolution, one digest per recipient, evidence, guard, storage.

Every source of every kind that shares an abuse recipient goes into one ``digest`` draft (M38,
section 5): one ``draft`` per recipient (``ux_abuse_reports_draft``), rebuilt in place every cycle
until it is sent. A ``reviewed`` digest is frozen; new sources wait in the next draft. The open
drafts of the older kinds (before 0040) are merged into the recipient's digest on the first cycle
and marked ``superseded``. Ingest only ever writes drafts: the database refuses anything else
(column grants and trigger).

A digest holds at most ``ABUSE_MAX_SUBJECTS`` sources (one for a recipient that asked for one mail
per source), newest first; the rest waits for the next part. Its due time follows the node's
digest hour (``report_smtp.digest_minute``): the next digest hour, or two hours after a full part
sent today (at most three parts a day). The sender enforces the same rules; ``due_at`` also tells
the owner when the digest goes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.blocklist_values import is_excluded_host
from suckerpot_reporting import (
    REFERENCE_STYLES,
    Activity,
    Evidence,
    GuardContext,
    GuardResult,
    RedactionContext,
    RedactionStats,
    ReferenceStyle,
    RenderUnavailable,
    ReportOptions,
    ReportSettings,
    SelfTerms,
    Subject,
    guard,
    guard_message,
    new_public_id,
    new_seed,
    new_xarf_id,
    render_csv,
    render_eml,
    render_text,
)
from suckerpot_reporting import render_mail as _render_mail
from suckerpot_reporting.evidence import MAX_SUBJECTS
from suckerpot_reporting.message import RenderedMessage

from ingest.egress import EgressClosed

from . import candidates as cand
from .candidates import Seed
from .config import AbuseSettings
from .contacts import ContactResolver, Outcome
from .evidence_build import (
    Collector,
    payload_activities,
    sample_refs,
    source_activities,
    window_start,
)
from .rdap import QuotaExhausted
from .selfterms import TermsCache

log = logging.getLogger(__name__)

DEMO_MAILBOX = "abuse@demo.example"
MAX_EVIDENCE_BYTES = 250_000
RESOLVE_PER_CYCLE = 150
OPTION_FIELDS = frozenset(ReportOptions.model_fields)
DIGEST: Final = "digest"
MAX_PARTS = 3
PART_GAP = timedelta(hours=2)
MAX_STRICT_PARTS = 100


class GateSource(Protocol):
    """Gate G (M37): the CVE tags held back on a day (None when unknown: none is named)."""

    async def gated_tags(self, day: Any) -> frozenset[str] | None: ...


@dataclass
class Recipient:
    id: int
    mailbox: str | None
    override: str | None
    strict: bool = False  # one spec-shaped mail per source (abuse_recipients.xarf_strict)

    @property
    def address(self) -> str | None:
        """What the owner chose, else what the registry said (COALESCE(override, mailbox))."""
        return self.override or self.mailbox


@dataclass
class CycleStats:
    selected: int = 0
    resolved: int = 0
    no_contact: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    guard_failed: int = 0
    waiting_egress: bool = False
    quota_exhausted: bool = False
    reasons: dict[str, int] = field(default_factory=dict)


@dataclass
class Resolved:
    seed: Seed
    outcome: Outcome


def evidence_bytes(evidence: Evidence) -> int:
    return len(evidence.model_dump_json().encode())


def has_port(act: Activity) -> bool:
    return 1 <= act.src_port <= 65535


def needs_source_port(acts: list[Activity] | tuple[Activity, ...]) -> bool:
    """Only the XARF ``login_attack`` type requires a source port (for an address source); a
    source with an exploit, a CVE or an SQL injection pattern is a scan or an injection report."""
    return not any(a.sqli or a.cves or a.action == "exploit_attempt" for a in acts)


def keep_activities(acts: tuple[Activity, ...], n: int) -> tuple[Activity, ...]:
    """The first ``n`` activities, with a port-bearing one among them whenever the source has
    one, so trimming never makes its XARF report fail the schema."""
    kept = acts[:n]
    if n <= 0 or any(has_port(a) for a in kept):
        return kept
    first = next((a for a in acts if has_port(a)), None)
    if first is None:
        return kept
    return tuple(sorted((first, *kept[: n - 1]), key=lambda a: a.ts))


def fit_evidence(evidence: Evidence) -> Evidence:
    """Trim until the stored document is under the table's size cap: activities first (each
    source keeps at least one line, its XARF report needs a source port), then the last sources,
    which are the oldest (a digest lists the newest first)."""
    for per_subject in (None, 50, 10, 1):
        subjects = evidence.subjects
        if per_subject is not None:
            subjects = tuple(
                s.model_copy(update={"activities": keep_activities(s.activities, per_subject)})
                for s in subjects
            )
        trimmed = evidence.model_copy(update={"subjects": subjects})
        while evidence_bytes(trimmed) > MAX_EVIDENCE_BYTES and len(trimmed.subjects) > 1:
            trimmed = trimmed.model_copy(update={"subjects": trimmed.subjects[:-1]})
        if evidence_bytes(trimmed) <= MAX_EVIDENCE_BYTES:
            return trimmed
    return trimmed


def sha256_of(evidence: Evidence) -> str:
    canonical = json.dumps(evidence.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def default_options(settings: AbuseSettings, defaults: dict[str, Any] | None) -> ReportOptions:
    base: dict[str, Any] = {"time_precision": "minute" if settings.round_times else "second"}
    for key, value in (defaults or {}).items():
        if key in OPTION_FIELDS:
            base[key] = value
    try:
        return ReportOptions.model_validate(base)
    except ValueError:
        return ReportOptions(time_precision=base["time_precision"])


def options_of(stored: Any, fallback: ReportOptions) -> ReportOptions:
    if isinstance(stored, dict) and stored:
        try:
            return ReportOptions.model_validate(
                {k: v for k, v in stored.items() if k in OPTION_FIELDS}
            )
        except ValueError:
            return fallback
    return fallback


SETTINGS_SQL = (
    "SELECT reply_contact, signature, intro, outro, note, subject_template, "
    "xarf_user_agent, xarf_org, defaults, reference_style FROM report_settings WHERE id = 1"
)


def report_settings_of(row: Any) -> ReportSettings:
    return ReportSettings(
        reply_contact=row.reply_contact,
        signature=row.signature,
        intro=row.intro,
        outro=row.outro,
        note=row.note,
        subject_template=row.subject_template,
        xarf_user_agent=row.xarf_user_agent,
        xarf_org=row.xarf_org,
    )


async def load_report_settings(
    session: AsyncSession,
) -> tuple[ReportSettings, dict[str, Any], ReferenceStyle]:
    """The owner's wording, the defaults for new drafts and where the reply reference is printed
    (empty wording and the subject style when never saved)."""
    row = (await session.execute(text(SETTINGS_SQL))).first()
    if row is None:
        return ReportSettings(), {}, "subject"
    style: ReferenceStyle = "subject"
    if row.reference_style in REFERENCE_STYLES:
        style = row.reference_style
    return report_settings_of(row), dict(row.defaults or {}), style


async def digest_config(session: AsyncSession) -> tuple[bool, int | None]:
    """Whether digests are on, and the digest minute (None without an SMTP profile)."""
    enabled = await session.scalar(text("SELECT digest_enabled FROM report_settings WHERE id = 1"))
    minute = await session.scalar(text("SELECT digest_minute FROM report_smtp WHERE id = 1"))
    return enabled is not False, None if minute is None else int(minute)


async def hold_of(session: AsyncSession) -> timedelta | None:
    """The hold of automatic sends (None without an SMTP profile)."""
    minutes = await session.scalar(text("SELECT auto_hold_minutes FROM report_smtp WHERE id = 1"))
    return None if minutes is None else timedelta(minutes=int(minutes))


def frozen(due: datetime | None, hold: timedelta | None, now: datetime, pending: bool) -> bool:
    """A digest with an automatic send waiting, and due within the hold (or with no due time),
    is no longer rebuilt: the hold runs from its last rebuild (the owner can still look and
    cancel), and a busy recipient would otherwise push it back every hour. New sources wait for
    the next digest. Without a waiting automatic send (assisted or manual mode, or after the
    send ended) the draft keeps collecting sources, whatever its due time. A draft without a due
    time is never frozen."""
    if not pending or due is None:
        # No due time (digests off, or switched on since): nothing to wait for, never stuck.
        return False
    return hold is None or now >= due - hold


async def auto_pending(session: AsyncSession, report_id: int) -> bool:
    """An automatic send of the report is waiting or under way."""
    return bool(
        await session.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM abuse_send_requests WHERE report_id = :i "
                "AND auto AND status IN ('pending', 'sending'))"
            ),
            {"i": report_id},
        )
    )


def utc_day(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def digest_due(
    now: datetime,
    minute: int,
    *,
    mails_today: int,
    last_mail: datetime | None,
    last_full: bool,
    strict: bool,
) -> tuple[datetime, int]:
    """``(due time, part)`` of a new digest draft (design M38, section 5.1).

    Nothing sent today: the next digest hour (today if it is still ahead, else tomorrow). After a
    full part today (fewer than three): two hours after it. Otherwise tomorrow's digest hour. A
    strict recipient gets one source per mail, without the part limit (the cap and pacing apply).
    """
    today_at = utc_day(now) + timedelta(minutes=minute)
    if strict:
        return now, min(mails_today + 1, MAX_STRICT_PARTS)
    if mails_today == 0:
        return (today_at if now <= today_at else today_at + timedelta(days=1)), 1
    if mails_today < MAX_PARTS and last_full and last_mail is not None:
        return max(now, last_mail + PART_GAP), mails_today + 1
    return today_at + timedelta(days=1), 1


def moved_due(stored: datetime, created: datetime, minute: int) -> datetime:
    """A part-one draft's due time after the owner moved the digest hour: same day, new minute,
    never before the draft existed."""
    due = utc_day(stored) + timedelta(minutes=minute)
    return due if due >= created else due + timedelta(days=1)


async def mails_today(
    session: AsyncSession, address: str, now: datetime
) -> tuple[int, datetime | None, int]:
    """Mails sent to ``address`` since 00:00 UTC (by SMTP or marked sent by hand), the time of the
    last one and its number of sources."""
    row = (
        await session.execute(
            text(
                """
                SELECT count(*) AS n, max(r.sent_at) AS last,
                       (array_agg(r.subject_count ORDER BY r.sent_at DESC))[1] AS last_count
                FROM abuse_reports r JOIN abuse_recipients c ON c.id = r.recipient_id
                WHERE r.status IN ('sent', 'closed') AND NOT r.demo AND r.sent_at >= :day0
                  AND COALESCE(NULLIF(c.override_mailbox, ''), c.mailbox) = :a
                """
            ),
            {"day0": utc_day(now), "a": address},
        )
    ).one()
    return int(row.n or 0), row.last, int(row.last_count or 0)


async def subject_keys(
    session: AsyncSession, report_id: int
) -> dict[tuple[str, str, str], uuid.UUID | None]:
    """``(kind, type, value)`` to the XARF id of each subject row of a report."""
    rows = await session.execute(
        text(
            "SELECT kind, subject_type, value, xarf_id FROM abuse_report_subjects "
            "WHERE report_id = :i"
        ),
        {"i": report_id},
    )
    return {(r.kind, r.subject_type, r.value): r.xarf_id for r in rows}


def with_subject_rows(
    data: dict[str, Any], report_kind: str, keys: dict[tuple[str, str, str], uuid.UUID | None]
) -> dict[str, Any]:
    """Stored evidence plus what lives on the subject rows: each subject's kind (older reports
    have one kind) and its XARF id (the row is the source of truth, 0040 gave older open reports
    one there)."""
    subjects = data.get("subjects")
    if not isinstance(subjects, list):
        return data
    out = []
    for item in subjects:
        if not isinstance(item, dict):
            out.append(item)
            continue
        sub = dict(item)
        kind = sub.get("kind") or (report_kind if report_kind != DIGEST else None)
        if kind is not None and report_kind != DIGEST:
            sub["kind"] = kind
        if sub.get("xarf_id") is None and kind is not None:
            found = keys.get((str(kind), str(sub.get("type")), str(sub.get("value"))))
            if found is not None:
                sub["xarf_id"] = str(found)
        out.append(sub)
    return {**data, "subjects": out}


class DraftBuilder:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: AbuseSettings,
        terms: TermsCache,
        resolver: ContactResolver,
        gate: GateSource | None = None,
    ) -> None:
        self.factory = factory
        self.settings = settings
        self.terms = terms
        self.resolver = resolver
        self.gate = gate

    # -- recipients and settings ---------------------------------------------------------

    async def _recipient(
        self, session: AsyncSession, mailbox: str, name: str | None
    ) -> Recipient | None:
        await session.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, name, source) VALUES (:m, :n, 'rdap') "
                "ON CONFLICT (mailbox) DO NOTHING"
            ),
            {"m": mailbox, "n": name},
        )
        row = (
            await session.execute(
                text(
                    "SELECT id, mailbox, override_mailbox, muted, xarf_strict "
                    "FROM abuse_recipients WHERE mailbox = :m"
                ),
                {"m": mailbox},
            )
        ).first()
        if row is None or row.muted:
            return None
        return Recipient(row.id, row.mailbox, row.override_mailbox, row.xarf_strict)

    async def _waiting(self, network_id: int | None) -> Recipient | None:
        """The recipient of a network without a registry contact, once the owner typed one."""
        if network_id is None:
            return None
        async with self.factory() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT r.id, r.mailbox, r.override_mailbox, r.muted, r.xarf_strict "
                        "FROM abuse_networks n JOIN abuse_recipients r ON r.id = n.recipient_id "
                        "WHERE n.id = :i"
                    ),
                    {"i": network_id},
                )
            ).first()
        if row is None or row.muted or not (row.override_mailbox or row.mailbox):
            return None
        return Recipient(row.id, row.mailbox, row.override_mailbox, row.xarf_strict)

    async def _report_settings(
        self, session: AsyncSession
    ) -> tuple[ReportSettings, dict[str, Any], ReferenceStyle]:
        return await load_report_settings(session)

    # -- cycle ---------------------------------------------------------------------------

    async def run(self, now: datetime, allow_lookups: bool) -> CycleStats:
        stats = CycleStats()
        terms = await self.terms.get()
        if terms is None:
            stats.reasons["self_terms_unavailable"] = 1
            return stats  # fail closed: nothing is built without the deny set
        async with self.factory() as session:
            seeds = [
                *await cand.attack_sources(session, self.settings, now),
                *await cand.payload_hosts(session, self.settings, now),
                *await cand.c2_subjects(session, self.settings, now),
            ]
            drafts = await self._draft_subjects(session)
        origins: dict[tuple[str, str, str], tuple[Seed, bool]] = {}
        for seed in seeds:
            origin = (
                cand.origin_of_ip(seed.value, terms, include_demo=self.settings.include_demo)
                if seed.type == "ip"
                else cand.origin_of_domain(seed.value, terms)
            )
            if origin is not None:
                origins[(seed.kind, seed.type, seed.value)] = (seed, origin == "demo")
        stats.selected = len(origins)
        # Subjects of open drafts stay in the report even when they aged out of the selection.
        for subs in drafts.values():
            for s in subs:
                origins.setdefault((s.kind, s.type, s.value), (s, s.demo))
        resolved: dict[tuple[int, bool], list[Resolved]] = defaultdict(list)
        recipients: dict[int, Recipient] = {}
        for count, (seed, demo) in enumerate(sorted(origins.values(), key=lambda x: -x[0].events)):
            if count >= RESOLVE_PER_CYCLE:
                break
            try:
                if demo:
                    outcome = Outcome("found", None, (DEMO_MAILBOX,))
                elif not allow_lookups:
                    stats.waiting_egress = True
                    outcome = await self._cached_only(seed)
                elif seed.type == "ip":
                    outcome = await self.resolver.resolve_ip(seed.value, seed.asn)
                else:
                    outcome = await self.resolver.resolve_domain(seed.value)
            except EgressClosed:
                stats.waiting_egress = True
                continue  # retryable: nothing was sent, no quota spent, nothing cached
            except QuotaExhausted:
                stats.quota_exhausted = True
                break
            chosen: Recipient | None = None
            if outcome.status == "no_contact":
                stats.no_contact += 1
                chosen = await self._waiting(outcome.network_id)
                if chosen is None:
                    continue  # waits for the owner to type a mailbox
            elif outcome.status != "found" or not outcome.mailboxes:
                continue
            else:
                async with self.factory() as session, session.begin():
                    for mailbox in outcome.mailboxes:
                        chosen = await self._recipient(session, mailbox, outcome.name)
                        if chosen is not None:
                            break
            stats.resolved += 1
            if chosen is None or chosen.address is None:
                continue  # every contact of that network is muted
            recipients[chosen.id] = chosen
            resolved[(chosen.id, demo)].append(Resolved(seed, outcome))
        gated = await self._gated(now)
        for (rid, demo), group in resolved.items():
            try:
                await self._build_group(recipients[rid], demo, group, terms, now, stats, gated)
            except Exception as exc:  # one bad group must not stop the others
                log.warning("abuse draft failed (%s)", type(exc).__name__)
                stats.skipped += 1
        return stats

    async def _gated(self, now: datetime) -> frozenset[str] | None:
        if self.gate is None:
            return frozenset()
        try:
            return await self.gate.gated_tags(now.astimezone(UTC).date())
        except Exception as exc:  # fail closed: no CVE is named
            log.warning("gate G unavailable for reports (%s)", type(exc).__name__)
            return None

    async def _cached_only(self, seed: Seed) -> Outcome:
        """Closed gate: use only what the cache already holds."""
        if seed.type == "ip":
            return await self.resolver.resolve_ip(seed.value, seed.asn, cache_only=True)
        return await self.resolver.resolve_domain(seed.value, cache_only=True)

    async def _draft_subjects(self, session: AsyncSession) -> dict[int, list[Seed]]:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT s.kind, r.recipient_id, r.demo, s.subject_type, s.value,
                           s.first_ts, s.last_ts, s.sessions, s.events
                    FROM abuse_reports r JOIN abuse_report_subjects s ON s.report_id = r.id
                    WHERE r.status = 'draft'
                    """
                )
            )
        ).all()
        out: dict[int, list[Seed]] = defaultdict(list)
        for r in rows:
            if r.subject_type in ("ip", "domain") and (r.demo or not is_excluded_host(r.value)):
                out[r.recipient_id].append(
                    Seed(
                        r.kind,
                        r.subject_type,
                        r.value,
                        r.first_ts,
                        r.last_ts,
                        r.sessions,
                        r.events,
                        demo=r.demo,
                    )
                )
        return out

    # -- one report ----------------------------------------------------------------------

    async def _prior(self, session: AsyncSession, rid: int, seed: Seed) -> Any:
        return (
            await session.execute(
                text(
                    """
                    SELECT max(r.window_end) AS any_end,
                           max(r.window_end)
                               FILTER (WHERE r.status IN ('sent', 'closed')) AS sent_end,
                           max(r.sent_at) FILTER (WHERE r.status IN ('sent', 'closed')) AS sent_at
                    FROM abuse_report_subjects s JOIN abuse_reports r ON r.id = s.report_id
                    WHERE r.recipient_id = :r AND s.kind = :k
                      AND r.status IN ('sent', 'closed', 'discarded')
                      AND s.subject_type = :t AND s.value = :v
                    """
                ),
                {"r": rid, "k": seed.kind, "t": seed.type, "v": seed.value},
            )
        ).one()

    async def _build_group(
        self,
        recipient: Recipient,
        demo: bool,
        group: list[Resolved],
        terms: SelfTerms,
        now: datetime,
        stats: CycleStats,
        gated: frozenset[str] | None = frozenset(),
    ) -> None:
        s = self.settings
        address = recipient.address
        if address is None:
            return  # a waiting recipient: no mailbox typed yet
        async with self.factory() as session:
            open_rows = (
                await session.execute(
                    text(
                        "SELECT id, kind, status, window_start, options, content_sha256, "
                        "guard_ok, guard_codes, id_seed, reply_token, due_at, part, created_at "
                        "FROM abuse_reports WHERE recipient_id = :r "
                        "AND status IN ('draft', 'reviewed') ORDER BY id"
                    ),
                    {"r": recipient.id},
                )
            ).all()
            existing = next(
                (r for r in open_rows if r.kind == DIGEST and r.status == "draft"), None
            )
            pending = existing is not None and await auto_pending(session, existing.id)
            if existing is not None and frozen(
                existing.due_at, await hold_of(session), now, pending
            ):
                return  # its automatic send waits: it goes as it is (design M38, section 5.3)
            # Drafts of the older kinds (before 0040): merged into this digest, then superseded.
            legacy = [r.id for r in open_rows if r.kind != DIGEST and r.status == "draft"]
            held = await self._reviewed_keys(
                session, [r.id for r in open_rows if r.status == "reviewed"]
            )
            # The draft limit does not hold back the merge of older drafts: the digest replaces
            # them (only on the first cycles after the upgrade to 0040).
            if existing is None and not legacy:
                count = (
                    await session.execute(
                        text(
                            "SELECT count(*) FROM abuse_reports "
                            "WHERE status IN ('draft', 'reviewed')"
                        )
                    )
                ).scalar_one()
                if count >= s.max_open_drafts:
                    stats.skipped += 1
                    return
            report_settings, defaults, style = await self._report_settings(session)
            stored_options = existing.options if existing is not None else None
            if stored_options is None and legacy:
                stored_options = next(r.options for r in open_rows if r.id == legacy[0])
            options = options_of(stored_options, default_options(s, defaults))
            kept: list[tuple[Resolved, datetime | None, datetime | None]] = []
            for item in group:
                if (item.seed.kind, item.seed.type, item.seed.value) in held:
                    continue  # waits in the reviewed digest
                prior = await self._prior(session, recipient.id, item.seed)
                if prior.any_end is not None and prior.any_end >= item.seed.last_ts:
                    continue  # nothing new since the last report or discard
                if prior.sent_at is not None and (now - prior.sent_at).days < s.resend_days:
                    continue  # cooldown
                kept.append((item, prior.sent_end, prior.sent_at))
            # Newest first: a full digest leaves the oldest sources for the next part.
            kept.sort(key=lambda x: (x[0].seed.last_ts, x[0].seed.value), reverse=True)
            cap = 1 if recipient.strict else min(s.max_subjects, MAX_SUBJECTS)
            if not kept:
                # Older drafts whose sources all wait (cooldown, reviewed) are retired anyway, so
                # no draft of an older kind outlives the upgrade to 0040.
                if legacy:
                    await self._supersede(legacy)
                return
            ips = frozenset(i.seed.value for i, _, _ in kept if i.seed.type == "ip")
            hosts = frozenset(i.seed.value for i, _, _ in kept if i.seed.type == "domain")
            ctx = RedactionContext(terms=terms, allowed_addresses=ips, allowed_hosts=hosts)
            col = Collector()
            ids = await subject_keys(session, existing.id) if existing is not None else {}
            subjects: list[Subject] = []
            chosen: list[Resolved] = []
            for item, sent_end, sent_at in kept:
                if len(subjects) >= cap:
                    break
                seed = item.seed
                start = window_start(
                    seed, now, s, sent_end, existing.window_start if existing else None
                )
                before = col.stats
                col.stats = RedactionStats()
                if seed.kind == "attack_source":
                    acts = await source_activities(session, seed, start, now, ctx, col, s, gated)
                    if needs_source_port(acts) and not any(has_port(a) for a in acts):
                        # An XARF login_attack from an address needs a source port: without one
                        # the source waits for a later cycle (counted, never silent).
                        col.stats = before
                        stats.skipped += 1
                        stats.reasons["no_source_port"] = stats.reasons.get("no_source_port", 0) + 1
                        continue
                elif seed.kind == "payload_host":
                    acts = await payload_activities(session, seed, start, now, ctx, col, s)
                else:
                    acts = []
                own = col.stats
                col.stats = before + own
                subjects.append(
                    Subject(
                        type=seed.type,
                        value=seed.value,
                        kind=seed.kind,
                        xarf_id=ids.get((seed.kind, seed.type, seed.value)) or new_xarf_id(),
                        asn=item.outcome.asn or seed.asn,
                        network=item.outcome.network_name,
                        country=item.outcome.country or seed.country,
                        first_ts=max(seed.first_ts, start),
                        last_ts=seed.last_ts,
                        sessions=seed.sessions,
                        events=seed.events,
                        activities=tuple(acts),
                        redaction=own,
                        samples=await sample_refs(session, seed),
                        previously_reported=sent_at,
                    )
                )
                chosen.append(item)
            if not subjects:
                if legacy:
                    await self._supersede(legacy)
                return
            due, part = await self._due(
                session, recipient, address, existing, now, cap, pending=pending
            )
        evidence = fit_evidence(
            Evidence(
                kind=DIGEST,
                recipient=address,
                subjects=tuple(subjects),
                window_start=min(x.first_ts for x in subjects),
                window_end=max(x.last_ts for x in subjects),
                demo=demo,
                options=options,
            )
        )
        report_seed = existing.id_seed if existing is not None else new_seed()
        gctx = GuardContext(
            internal_ids=frozenset(col.session_ids) | {report_seed.hex}, allow_documentation=demo
        )
        # A new draft has no reply token yet (the database makes it on insert): the re-check pass
        # (``ingest.abuse.reguard``) completes the picture on its next run.
        token = existing.reply_token if existing is not None else None
        result = check_evidence(
            evidence, report_settings, terms, gctx, reply_token=token, reference_style=style
        )
        if not result.ok:
            stats.guard_failed += 1
            for code in result.codes:
                stats.reasons[code] = stats.reasons.get(code, 0) + 1
        digest = sha256_of(evidence)
        redaction = {
            "addresses_masked": col.stats.addresses_masked,
            "lines_dropped": col.stats.lines_dropped,
        }
        async with self.factory() as session, session.begin():
            if existing is not None:
                if (
                    existing.content_sha256 == digest
                    and existing.guard_ok == result.ok
                    and list(existing.guard_codes or []) == list(result.codes)
                    and existing.due_at == due
                    and not legacy
                ):
                    return
                report_id: int | None = existing.id
                await self._update(
                    session, existing.id, evidence, digest, result.ok, result.codes, redaction, due
                )
                stats.updated += 1
            else:
                report_id = await self._insert(
                    session,
                    recipient.id,
                    demo,
                    evidence,
                    digest,
                    result.ok,
                    result.codes,
                    redaction,
                    report_seed,
                    due,
                    part,
                )
                if report_id is None:
                    stats.skipped += 1
                    return
                stats.created += 1
            if legacy:
                await session.execute(
                    text(
                        "UPDATE abuse_reports SET status = 'superseded' "
                        "WHERE id = ANY(:ids) AND status = 'draft'"
                    ),
                    {"ids": legacy},
                )
            await session.execute(
                text("DELETE FROM abuse_report_subjects WHERE report_id = :i"), {"i": report_id}
            )
            for item in chosen:
                seed = item.seed
                shown = next(
                    (x for x in evidence.subjects if x.value == seed.value and x.kind == seed.kind),
                    None,
                )
                if shown is None:
                    continue  # trimmed out to fit the size cap: queued for the next draft
                await session.execute(
                    text(
                        """
                        INSERT INTO abuse_report_subjects (report_id, kind, subject_type, value,
                            network_id, first_ts, last_ts, sessions, events, xarf_id)
                        VALUES (:i, :k, :t, :v, :n, :f, :l, :s, :e, :x)
                        """
                    ),
                    {
                        "i": report_id,
                        "k": seed.kind,
                        "t": seed.type,
                        "v": seed.value,
                        "n": item.outcome.network_id,
                        "f": shown.first_ts,
                        "l": shown.last_ts,
                        "s": seed.sessions,
                        "e": seed.events,
                        "x": shown.xarf_id,
                    },
                )

    async def _reviewed_keys(
        self, session: AsyncSession, report_ids: list[int]
    ) -> set[tuple[str, str, str]]:
        """Sources already in a reviewed report of this recipient: they go with it."""
        if not report_ids:
            return set()
        rows = await session.execute(
            text(
                "SELECT kind, subject_type, value FROM abuse_report_subjects "
                "WHERE report_id = ANY(:ids)"
            ),
            {"ids": report_ids},
        )
        return {(r.kind, r.subject_type, r.value) for r in rows}

    async def _supersede(self, ids: list[int]) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE abuse_reports SET status = 'superseded' "
                    "WHERE id = ANY(:ids) AND status = 'draft'"
                ),
                {"ids": ids},
            )

    async def _due(
        self,
        session: AsyncSession,
        recipient: Recipient,
        address: str,
        existing: Any,
        now: datetime,
        cap: int,
        *,
        pending: bool = False,
    ) -> tuple[datetime | None, int]:
        """The due time and part number of the recipient's draft. None when digests are off or
        there is no SMTP profile (the draft is then sent after the hold, as before 0040).

        A draft past its due time with no automatic send waiting missed its slot (its send was
        cancelled, or the node is not in automatic mode): it is due at the next digest hour."""
        enabled, minute = await digest_config(session)
        if not enabled or minute is None:
            return None, existing.part if existing is not None else 1
        # One build cycle of slack: a due time of "now" (strict, a next part) is not missed yet.
        slack = timedelta(seconds=self.settings.build_interval_s)
        missed = (
            existing is not None
            and existing.due_at is not None
            and existing.due_at < now - slack
            and not pending
        )
        if existing is not None and existing.due_at is not None and not missed:
            if existing.part == 1 and not recipient.strict:
                return moved_due(existing.due_at, existing.created_at, minute), 1
            return existing.due_at, existing.part
        n, last, last_count = await mails_today(session, address, now)
        due, part = digest_due(
            now,
            minute,
            mails_today=n,
            last_mail=last,
            last_full=last_count >= cap,
            strict=recipient.strict,
        )
        if existing is not None:
            return due, existing.part
        return due, part

    async def _insert(
        self,
        session: AsyncSession,
        rid: int,
        demo: bool,
        evidence: Evidence,
        digest: str,
        ok: bool,
        codes: tuple[str, ...],
        redaction: dict[str, int],
        seed: uuid.UUID,
        due: datetime | None,
        part: int,
    ) -> int | None:
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo,
                        window_start, window_end, subject_count, evidence, content_sha256,
                        guard_ok, guard_codes, redaction, options, due_at, part)
                    VALUES (:pid, :seed, :r, :k, :d, :ws, :we, :n, CAST(:ev AS jsonb), :sha, :ok,
                        :codes, CAST(:red AS jsonb), CAST(:opt AS jsonb), :due, :part)
                    ON CONFLICT (recipient_id, kind) WHERE status = 'draft' DO NOTHING
                    RETURNING id
                    """
                ),
                {
                    "pid": new_public_id(),
                    "seed": seed,
                    "r": rid,
                    "k": DIGEST,
                    "d": demo,
                    "ws": evidence.window_start,
                    "we": evidence.window_end,
                    "n": len(evidence.subjects),
                    "ev": evidence.model_dump_json(),
                    "sha": digest,
                    "ok": ok,
                    "codes": list(codes),
                    "red": json.dumps(redaction),
                    "opt": evidence.options.model_dump_json(),
                    "due": due,
                    "part": part,
                },
            )
        ).first()
        return None if row is None else int(row.id)

    async def _update(
        self,
        session: AsyncSession,
        report_id: int,
        evidence: Evidence,
        digest: str,
        ok: bool,
        codes: tuple[str, ...],
        redaction: dict[str, int],
        due: datetime | None,
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE abuse_reports SET window_start = :ws, window_end = :we, subject_count = :n,
                    evidence = CAST(:ev AS jsonb), content_sha256 = :sha, guard_ok = :ok,
                    guard_codes = :codes, redaction = CAST(:red AS jsonb), due_at = :due
                WHERE id = :i AND status = 'draft'
                """
            ),
            {
                "i": report_id,
                "ws": evidence.window_start,
                "we": evidence.window_end,
                "n": len(evidence.subjects),
                "ev": evidence.model_dump_json(),
                "sha": digest,
                "ok": ok,
                "codes": list(codes),
                "red": json.dumps(redaction),
                "due": due,
            },
        )


def _message(
    evidence: Evidence,
    settings: ReportSettings,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
) -> RenderedMessage:
    body = render_text(evidence, settings, reply_token=reply_token, reference_style=reference_style)
    return RenderedMessage(body.to, body.subject, body.body, (render_csv(evidence),))


def render_mail(
    evidence: Evidence,
    settings: ReportSettings,
    reply_token: str | None = None,
    style: ReferenceStyle = "subject",
) -> RenderedMessage:
    """What the owner would paste or the SMTP path would send: the text, ``evidence.csv`` and
    one XARF v4 report per source (``suckerpot_reporting.render_mail``). There is no fallback:
    a mail that cannot carry valid XARF parts is not rendered (``RenderUnavailable``). The reply
    token goes into the subject (and the body for ``subject_and_body``) only."""
    return _render_mail(evidence, settings, reply_token=reply_token, reference_style=style)


def check_evidence(
    evidence: Evidence,
    settings: ReportSettings,
    terms: SelfTerms,
    ctx: GuardContext,
    *,
    reply_token: str | None = None,
    reference_style: ReferenceStyle = "subject",
) -> GuardResult:
    """The identity check of a draft, on every artefact the owner can copy or the send path builds:
    the plain-text message with its CSV, the mail of ``render_mail`` with its XARF reports (each
    walked, base64 evidence decoded) and its ``.eml``. ``xarf_user_agent``, ``xarf_org`` and the
    reply reference only show up in the later two."""
    try:
        result = guard_message(
            _message(evidence, settings, reply_token, reference_style), terms, ctx=ctx
        )
        mail = render_mail(evidence, settings, reply_token, reference_style)
        result = result.merge(guard_message(mail, terms, ctx=ctx))
        return result.merge(guard(render_eml(mail), terms, fmt="eml", ctx=ctx))
    except RenderUnavailable as exc:
        # The owner has not set a reply contact yet: nothing can be rendered. The evidence
        # itself is still checked, and the draft is stored as blocked with a constant code.
        checked = guard(evidence.model_dump(mode="json"), terms, fmt="json", ctx=ctx)
        codes = tuple(sorted({*checked.codes, exc.code}))
        return GuardResult(ok=False, codes=codes, counts=dict(checked.counts))


def utc_now() -> datetime:
    return datetime.now(UTC)
