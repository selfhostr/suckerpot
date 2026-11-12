"""Draft reports: contact resolution, grouping per (recipient, kind), evidence, guard, storage.

One open report per recipient and kind (``ux_abuse_reports_open``). A ``draft`` is rebuilt in
place every cycle and accumulates new evidence; a ``reviewed`` report is never touched. Ingest
only ever writes drafts: the database refuses anything else (column grants and trigger).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_reporting import (
    Evidence,
    GuardContext,
    GuardResult,
    RedactionContext,
    RedactionStats,
    RenderUnavailable,
    ReportOptions,
    ReportSettings,
    SelfTerms,
    Subject,
    guard,
    guard_message,
    new_public_id,
    new_seed,
    render_csv,
    render_text,
)
from suckerpot_reporting.evidence import MAX_SUBJECTS
from suckerpot_reporting.message import RenderedMessage

from ingest.egress import EgressClosed

from . import candidates as cand
from .candidates import Kind, Seed
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


@dataclass
class Recipient:
    id: int
    mailbox: str | None
    override: str | None

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


def fit_evidence(evidence: Evidence) -> Evidence:
    """Trim until the stored document is under the table's size cap."""
    for per_subject in (None, 50, 10, 0):
        subjects = evidence.subjects
        if per_subject is not None:
            subjects = tuple(
                s.model_copy(update={"activities": s.activities[:per_subject]}) for s in subjects
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


async def load_report_settings(session: AsyncSession) -> tuple[ReportSettings, dict[str, Any]]:
    """The owner's wording and the defaults for new drafts (empty ones when never saved)."""
    row = (
        await session.execute(
            text(
                "SELECT reply_contact, signature, intro, outro, note, subject_template, "
                "xarf_user_agent, defaults "
                "FROM report_settings WHERE id = 1"
            )
        )
    ).first()
    if row is None:
        return ReportSettings(), {}
    return (
        ReportSettings(
            reply_contact=row.reply_contact,
            signature=row.signature,
            intro=row.intro,
            outro=row.outro,
            note=row.note,
            subject_template=row.subject_template,
            xarf_user_agent=row.xarf_user_agent,
        ),
        dict(row.defaults or {}),
    )


class DraftBuilder:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: AbuseSettings,
        terms: TermsCache,
        resolver: ContactResolver,
    ) -> None:
        self.factory = factory
        self.settings = settings
        self.terms = terms
        self.resolver = resolver

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
                    "SELECT id, mailbox, override_mailbox, muted "
                    "FROM abuse_recipients WHERE mailbox = :m"
                ),
                {"m": mailbox},
            )
        ).first()
        if row is None or row.muted:
            return None
        return Recipient(row.id, row.mailbox, row.override_mailbox)

    async def _waiting(self, network_id: int | None) -> Recipient | None:
        """The recipient of a network without a registry contact, once the owner typed one."""
        if network_id is None:
            return None
        async with self.factory() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT r.id, r.mailbox, r.override_mailbox, r.muted "
                        "FROM abuse_networks n JOIN abuse_recipients r ON r.id = n.recipient_id "
                        "WHERE n.id = :i"
                    ),
                    {"i": network_id},
                )
            ).first()
        if row is None or row.muted or not (row.override_mailbox or row.mailbox):
            return None
        return Recipient(row.id, row.mailbox, row.override_mailbox)

    async def _report_settings(
        self, session: AsyncSession
    ) -> tuple[ReportSettings, dict[str, Any]]:
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
        for (kind, _rid), subs in drafts.items():
            for s in subs:
                origins.setdefault((kind, s.type, s.value), (s, s.demo))
        resolved: dict[tuple[int, Kind, bool], list[Resolved]] = defaultdict(list)
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
            resolved[(chosen.id, seed.kind, demo)].append(Resolved(seed, outcome))
        for (rid, kind, demo), group in resolved.items():
            try:
                await self._build_group(recipients[rid], kind, demo, group, terms, now, stats)
            except Exception as exc:  # one bad group must not stop the others
                log.warning("abuse draft failed (%s)", type(exc).__name__)
                stats.skipped += 1
        return stats

    async def _cached_only(self, seed: Seed) -> Outcome:
        """Closed gate: use only what the cache already holds."""
        if seed.type == "ip":
            return await self.resolver.resolve_ip(seed.value, seed.asn, cache_only=True)
        return await self.resolver.resolve_domain(seed.value, cache_only=True)

    async def _draft_subjects(self, session: AsyncSession) -> dict[tuple[str, int], list[Seed]]:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT r.kind, r.recipient_id, r.demo, s.subject_type, s.value,
                           s.first_ts, s.last_ts, s.sessions, s.events
                    FROM abuse_reports r JOIN abuse_report_subjects s ON s.report_id = r.id
                    WHERE r.status = 'draft'
                    """
                )
            )
        ).all()
        out: dict[tuple[str, int], list[Seed]] = defaultdict(list)
        for r in rows:
            if r.subject_type in ("ip", "domain"):
                out[(r.kind, r.recipient_id)].append(
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

    async def _prior(self, session: AsyncSession, rid: int, kind: str, seed: Seed) -> Any:
        return (
            await session.execute(
                text(
                    """
                    SELECT max(r.window_end) AS any_end,
                           max(r.window_end)
                               FILTER (WHERE r.status IN ('sent', 'closed')) AS sent_end,
                           max(r.sent_at) FILTER (WHERE r.status IN ('sent', 'closed')) AS sent_at
                    FROM abuse_report_subjects s JOIN abuse_reports r ON r.id = s.report_id
                    WHERE r.recipient_id = :r AND r.kind = :k
                      AND r.status IN ('sent', 'closed', 'discarded')
                      AND s.subject_type = :t AND s.value = :v
                    """
                ),
                {"r": rid, "k": kind, "t": seed.type, "v": seed.value},
            )
        ).one()

    async def _build_group(
        self,
        recipient: Recipient,
        kind: Kind,
        demo: bool,
        group: list[Resolved],
        terms: SelfTerms,
        now: datetime,
        stats: CycleStats,
    ) -> None:
        s = self.settings
        address = recipient.address
        if address is None:
            return  # a waiting recipient: no mailbox typed yet
        async with self.factory() as session:
            open_rows = (
                await session.execute(
                    text(
                        "SELECT id, status, window_start, options, content_sha256, guard_ok, "
                        "guard_codes, id_seed FROM abuse_reports "
                        "WHERE recipient_id = :r AND kind = :k "
                        "AND status IN ('draft', 'reviewed')"
                    ),
                    {"r": recipient.id, "k": kind},
                )
            ).all()
            if any(r.status == "reviewed" for r in open_rows):
                stats.skipped += 1
                return  # waits for a new draft once the reviewed one is sent or discarded
            existing = open_rows[0] if open_rows else None
            if existing is None:
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
            report_settings, defaults = await self._report_settings(session)
            options = options_of(
                existing.options if existing else None, default_options(s, defaults)
            )
            kept: list[tuple[Resolved, datetime | None, datetime | None]] = []
            for item in group:
                prior = await self._prior(session, recipient.id, kind, item.seed)
                if prior.any_end is not None and prior.any_end >= item.seed.last_ts:
                    continue  # nothing new since the last report or discard
                if prior.sent_at is not None and (now - prior.sent_at).days < s.resend_days:
                    continue  # cooldown
                kept.append((item, prior.sent_end, prior.sent_at))
            kept.sort(key=lambda x: x[0].seed.first_ts)
            kept = kept[: min(s.max_subjects, MAX_SUBJECTS)]
            if not kept:
                return
            ips = frozenset(i.seed.value for i, _, _ in kept if i.seed.type == "ip")
            hosts = frozenset(i.seed.value for i, _, _ in kept if i.seed.type == "domain")
            ctx = RedactionContext(terms=terms, allowed_addresses=ips, allowed_hosts=hosts)
            col = Collector()
            subjects: list[Subject] = []
            for item, sent_end, sent_at in kept:
                seed = item.seed
                start = window_start(
                    seed, now, s, sent_end, existing.window_start if existing else None
                )
                before = col.stats
                col.stats = RedactionStats()
                if seed.kind == "attack_source":
                    acts = await source_activities(session, seed, start, now, ctx, col, s)
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
        evidence = fit_evidence(
            Evidence(
                kind=kind,
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
        result = check_evidence(evidence, report_settings, terms, gctx)
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
                ):
                    return
                report_id: int | None = existing.id
                await self._update(
                    session, existing.id, evidence, digest, result.ok, result.codes, redaction
                )
                stats.updated += 1
            else:
                report_id = await self._insert(
                    session,
                    recipient.id,
                    kind,
                    demo,
                    evidence,
                    digest,
                    result.ok,
                    result.codes,
                    redaction,
                    report_seed,
                )
                if report_id is None:
                    stats.skipped += 1
                    return
                stats.created += 1
            await session.execute(
                text("DELETE FROM abuse_report_subjects WHERE report_id = :i"), {"i": report_id}
            )
            for item, _, _ in kept:
                seed = item.seed
                shown = next((x for x in evidence.subjects if x.value == seed.value), None)
                if shown is None:
                    continue  # trimmed out to fit the size cap: queued for the next draft
                await session.execute(
                    text(
                        """
                        INSERT INTO abuse_report_subjects (report_id, subject_type, value,
                            network_id,
                            first_ts, last_ts, sessions, events)
                        VALUES (:i, :t, :v, :n, :f, :l, :s, :e)
                        """
                    ),
                    {
                        "i": report_id,
                        "t": seed.type,
                        "v": seed.value,
                        "n": item.outcome.network_id,
                        "f": shown.first_ts,
                        "l": shown.last_ts,
                        "s": seed.sessions,
                        "e": seed.events,
                    },
                )

    async def _insert(
        self,
        session: AsyncSession,
        rid: int,
        kind: str,
        demo: bool,
        evidence: Evidence,
        digest: str,
        ok: bool,
        codes: tuple[str, ...],
        redaction: dict[str, int],
        seed: uuid.UUID,
    ) -> int | None:
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo,
                        window_start, window_end, subject_count, evidence, content_sha256,
                        guard_ok, guard_codes, redaction, options)
                    VALUES (:pid, :seed, :r, :k, :d, :ws, :we, :n, CAST(:ev AS jsonb), :sha, :ok,
                        :codes, CAST(:red AS jsonb), CAST(:opt AS jsonb))
                    ON CONFLICT (recipient_id, kind)
                        WHERE status IN ('draft', 'reviewed') DO NOTHING
                    RETURNING id
                    """
                ),
                {
                    "pid": new_public_id(),
                    "seed": seed,
                    "r": rid,
                    "k": kind,
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
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE abuse_reports SET window_start = :ws, window_end = :we, subject_count = :n,
                    evidence = CAST(:ev AS jsonb), content_sha256 = :sha, guard_ok = :ok,
                    guard_codes = :codes, redaction = CAST(:red AS jsonb)
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
            },
        )


def _message(evidence: Evidence, settings: ReportSettings) -> RenderedMessage:
    body = render_text(evidence, settings)
    return RenderedMessage(body.to, body.subject, body.body, (render_csv(evidence),))


def check_evidence(
    evidence: Evidence, settings: ReportSettings, terms: SelfTerms, ctx: GuardContext
) -> GuardResult:
    """The identity check of a draft: the plain-text message and its CSV, as they would be sent."""
    try:
        return guard_message(_message(evidence, settings), terms, ctx=ctx)
    except RenderUnavailable as exc:
        # The owner has not set a reply contact yet: nothing can be rendered. The evidence
        # itself is still checked, and the draft is stored as blocked with a constant code.
        checked = guard(evidence.model_dump(mode="json"), terms, fmt="json", ctx=ctx)
        codes = tuple(sorted({*checked.codes, exc.code}))
        return GuardResult(ok=False, codes=codes, counts=dict(checked.counts))


def utc_now() -> datetime:
    return datetime.now(UTC)
