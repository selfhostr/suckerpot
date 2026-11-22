"""Sending abuse reports by SMTP, the ingest side of M25 (design doc M25, section 2.3).

The API writes ``abuse_send_requests`` rows; this module answers them. In auto mode it also
schedules the ready reports after the hold. Nothing is sent unless the owner configured the
profile and chose a mode; demo reports and reports that fail the identity guard are never sent.

Order of a send, each step stopping the whole thing:

1. the request is still pending (row locked, so a cancel waits and a late cancel is refused);
2. the profile is complete, the mode allows it, the daily cap (auto) is not reached;
3. the egress gate is open. If not, the request STAYS pending (a test fails with
   ``egress_closed`` after two minutes): nothing is attempted, no socket is created;
4. the report is re-rendered from the stored evidence and the complete serialized message is
   guarded (``guard_failed:<codes>``, including ``no_self_address``);
5. delivery through the VPN proxy (``outgoing.deliver``), gate checked again right before connect;
6. the report becomes ``sent`` (``sent_via = 'smtp'``) and the request ``sent``, in one commit.

Automatic sends are paced: at most one every ``AUTO_SPACING`` (a burst of mails from one mailbox
looks like spam to its provider), and none for ``AUTO_PAUSE`` after the server answered "not now"
(a 4xx reply, ``deferred``). A report whose automatic send was deferred is scheduled again, at
most ``MAX_DEFERRALS`` times; a refused, cancelled or unknown send is never retried by itself.

Automatic sends only carry fresh evidence: a report whose last activity (``window_end``) is older
than ``AUTO_MAX_AGE`` is never scheduled, and a queued one that aged past it is cancelled
(``too_old``). Providers check the reported host when the mail arrives; weeks later it is usually
cleaned or reassigned and the report "cannot be substantiated". The owner can still send it by
hand. The newest reports are scheduled and sent first.

Before any send, whoever asked for it, the subjects are checked against the never list and the
shared services (``suckerpot_db.blocklist_values``): a report that names one is cancelled
(``shared_host``), also a draft made before the list grew. An automatic send is also cancelled
when its recipient only takes a web form (``form_only``) or its address is dead
(``undeliverable``).

Daily digests (M38, section 5). With ``report_settings.digest_enabled`` an automatic digest waits
for its ``due_at`` and for the node's digest hour, and a recipient address gets at most one
automatic mail per UTC day, plus the next parts of a full digest (at most three a day, two hours
apart). A mail sent or marked sent by hand counts as the recipient's digest for the day. A
recipient that asked for one mail per source (``xarf_strict``) is limited by the cap and pacing
only. Freshness is per source: an automatic digest carries only the sources active in the last
``AUTO_MAX_AGE``; the older ones stay out of the mail and are taken off the sent report's subjects.
Every XARF part of the serialized message is validated against the vendored schema before the
send (``xarf_invalid`` otherwise, never a fallback).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.blocklist_values import is_excluded_host
from suckerpot_db.locks import ABUSE_SMTP_PROFILE
from suckerpot_db.network_names import host_of_target
from suckerpot_db.secretbox import SecretBox, SecretError
from suckerpot_reporting import (
    Evidence,
    GuardContext,
    ReferenceStyle,
    RenderedMessage,
    RenderUnavailable,
    ReportSettings,
)

from ingest.abuse.build import (
    SETTINGS_SQL,
    default_options,
    options_of,
    render_mail,
    report_settings_of,
    subject_keys,
    utc_day,
    with_subject_rows,
)
from ingest.abuse.config import AbuseSettings
from ingest.abuse.selfterms import TermsCache
from ingest.abuse.session_ids import internal_session_ids
from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate
from ingest.reportmail.outgoing import (
    SMTP_DEADLINE_S,
    Profile,
    SendFailure,
    build_message,
    build_test_message,
    check_message,
    deliver,
    new_message_id,
    xarf_parts_valid,
)

log = logging.getLogger(__name__)

MAX_PER_CYCLE = 10
MAX_SCHEDULE = 50
AUTO_SPACING = timedelta(minutes=3)
AUTO_PAUSE = timedelta(hours=1)
MAX_DEFERRALS = 3
AUTO_MAX_AGE = timedelta(days=7)
MAX_PARTS = 3
TEST_EGRESS_WAIT = timedelta(minutes=2)
PASSWORD_AAD = "report_smtp"  # noqa: S105 - a label, not a secret; bound to the ciphertext, see api.abuse_smtp


MARK_SENT = (
    "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = :by, sent_via = 'smtp', "
    "sent_xarf = CAST(:x AS jsonb) WHERE id = :i AND status IN ('draft', 'reviewed')"
)
# An automatic send of a draft is stamped as reviewed by 'auto' (the trigger allows nothing else).
MARK_AUTO = (
    "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = :by, sent_via = 'smtp', "
    "reviewed_at = now(), reviewed_by = 'auto', reviewed_revision = revision, "
    "sent_xarf = CAST(:x AS jsonb) WHERE id = :i AND status IN ('draft', 'reviewed')"
)


# Sends that left today (UTC), as an SQL scalar for the daily cap.
SENT_TODAY = (
    "SELECT count(*) FROM abuse_send_requests s WHERE s.kind = 'send' AND s.status = 'sent' "
    "AND s.done_at >= (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')"
)
STALE_SENDING_S = SMTP_DEADLINE_S + 30

# Mails that went to the report's recipient address since 00:00 UTC (another report, sent by SMTP
# or marked sent by hand). Aliases: ``r`` the report, ``rec`` its recipient.
_TODAY = (
    "FROM abuse_reports r2 JOIN abuse_recipients c2 ON c2.id = r2.recipient_id "
    "WHERE r2.status IN ('sent', 'closed') AND NOT r2.demo AND r2.id <> r.id "
    "AND r2.sent_at >= CAST(:day0 AS timestamptz) "
    "AND COALESCE(NULLIF(c2.override_mailbox, ''), c2.mailbox) "
    "= COALESCE(NULLIF(rec.override_mailbox, ''), rec.mailbox)"
)
_HOUR_PASSED = "CAST(:minute AS integer) >= CAST(:digest_minute AS integer)"
# True when an automatic send of report ``r`` may go now under the one-digest-a-day rule.
RECIPIENT_FREE = (
    # The hold runs from the last rebuild for every digest (strict and digests off included).
    "((r.kind <> 'digest' "
    "OR r.updated_at <= CAST(:now AS timestamptz) - make_interval(mins => CAST(:hold AS integer))) "
    "AND (NOT CAST(:digest AS boolean) OR r.kind <> 'digest' OR rec.xarf_strict "
    "OR (r.due_at IS NOT NULL AND r.due_at <= CAST(:now AS timestamptz) AND ("
    f"((SELECT count(*) {_TODAY}) = 0 AND {_HOUR_PASSED}) "
    f"OR (r.part > 1 AND (SELECT count(*) {_TODAY}) BETWEEN 1 AND {MAX_PARTS - 1} "
    f"AND (SELECT max(r2.sent_at) {_TODAY}) <= CAST(:now AS timestamptz) - interval '2 hours'))) "
    "OR (r.due_at IS NULL AND r.status = 'reviewed' "
    f"AND (SELECT count(*) {_TODAY}) = 0 AND {_HOUR_PASSED})))"
)

# An automatic request that ended for a reason that may be gone does not block a new one (M38):
# ``form_only`` and ``undeliverable`` once the owner cleared the flag (schedule() checks the flags),
# ``mode_changed`` and ``mode_off`` once the profile was saved again (schedule() runs in auto only),
# the others once the report changed after the request ended (a rebuild with new evidence, a
# shared service left out, the identity check passing again). A refusal (5xx), an unknown outcome
# and the owner's own cancel still block: a second mail would be worse, or the owner decided.
TERMINAL_CODES = ("too_old", "shared_host", "xarf_invalid", "not_ready", "internal")
RESCHEDULABLE = (  # COALESCE: an owner's cancel has no error code, and NULL must block
    "COALESCE(q.auto AND q.status IN ('cancelled', 'failed') AND ("  # noqa: S608 - constants
    "q.error_code IN ('form_only', 'undeliverable') "
    # parked by a mode change: armed again once the profile was saved after it (auto again)
    "OR (q.error_code IN ('mode_changed', 'mode_off') "
    "AND q.done_at < (SELECT p.updated_at FROM report_smtp p WHERE p.id = 1)) "
    "OR ((q.error_code IN (" + ", ".join(f"'{c}'" for c in TERMINAL_CODES) + ") "
    "OR q.error_code LIKE 'guard_failed%') AND q.done_at < r.updated_at)), false)"
)

_SCHEDULE_HEAD = """
                    INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by,
                                                     scheduled_at)
                    SELECT r.id, 'send', true, 'auto',
                           GREATEST(COALESCE(r.due_at, CAST(:at AS timestamptz)),
                                    CAST(:at AS timestamptz))
                    FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id
                    WHERE r.status IN ('draft', 'reviewed') AND NOT r.demo AND r.guard_ok
                      AND NOT rec.muted AND NOT rec.form_only AND NOT rec.undeliverable
                      AND COALESCE(NULLIF(rec.override_mailbox, ''), rec.mailbox) IS NOT NULL
                      AND r.window_end > now() - make_interval(secs => :max_age)
                      -- never had a request, or only automatic sends that the server deferred,
                      -- or that ended for a reason that is gone (see RESCHEDULABLE)
                      AND NOT EXISTS (
                          SELECT 1 FROM abuse_send_requests q WHERE q.report_id = r.id
                            AND NOT (q.auto AND q.status = 'failed'
                                     AND q.error_code LIKE 'deferred%')
                            AND NOT ("""
_SCHEDULE_TAIL = """))
                      AND (SELECT count(*) FROM abuse_send_requests q
                           WHERE q.report_id = r.id AND q.auto
                             AND q.error_code LIKE 'deferred%') < :deferrals
                    ORDER BY r.window_end DESC, r.id LIMIT :n
                    """
SCHEDULE_SQL = _SCHEDULE_HEAD + RESCHEDULABLE + _SCHEDULE_TAIL

# True while automatic sends must wait: one started less than :spacing ago, or the server deferred
# one less than :pause ago. Database time on both sides, like ``started_at`` and ``done_at``.
AUTO_PACED = (
    "SELECT EXISTS (SELECT 1 FROM abuse_send_requests s WHERE s.kind = 'send' AND s.auto "
    "AND s.started_at > now() - make_interval(secs => :spacing)) "
    "OR EXISTS (SELECT 1 FROM abuse_send_requests s WHERE s.kind = 'send' AND s.auto "
    "AND s.status = 'failed' AND s.error_code LIKE 'deferred%' "
    "AND s.done_at > now() - make_interval(secs => :pause))"
)


def _host_of_subject(value: str) -> str:
    """The host of a stored subject: a bare host or address, or a URL."""
    rest = value.partition("://")[2] or value
    return host_of_target(rest.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1])


@dataclass(frozen=True, slots=True)
class Prepared:
    raw: bytes
    rcpt: str
    report: dict[str, Any] | None
    message_id: str | None = None
    # Sources left out of an automatic digest (older than AUTO_MAX_AGE): (kind, type, value)
    stale: tuple[tuple[str, str, str], ...] = ()
    # The XARF files exactly as they left: [{"name", "content"}], stored on the report.
    xarf: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class Request:
    id: int
    report_id: int | None
    kind: str
    auto: bool
    requested_by: str
    requested_at: datetime
    scheduled_at: datetime | None
    message_id: str | None = None


class ReportSender:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        terms: TermsCache,
        abuse: AbuseSettings,
        *,
        box: SecretBox | None = None,
        gate: EgressGate | None = None,
        allow_documentation: bool = False,
    ) -> None:
        self.factory = factory
        self.terms = terms
        self.abuse = abuse
        self.box = box
        self._gate = gate
        # Tests only: their evidence uses documentation addresses. Production keeps False, so a
        # report that names a documentation range is never sent.
        self._allow_documentation = allow_documentation

    @property
    def gate(self) -> EgressGate:
        return self._gate or get_gate()

    # -- profile -------------------------------------------------------------------------

    async def load_profile(self, session: AsyncSession) -> Profile | None:
        row = (
            await session.execute(
                text(
                    "SELECT host, port, security, username, from_address, from_name, mode, "
                    "auto_hold_minutes, daily_cap, password_ciphertext, password_nonce, "
                    "digest_minute FROM report_smtp WHERE id = 1"
                )
            )
        ).first()
        if row is None:
            return None
        password = ""
        if row.password_ciphertext is not None:
            if self.box is None:
                return None  # no key to decrypt with: the profile is unusable
            try:
                password = self.box.decrypt(
                    PASSWORD_AAD, bytes(row.password_ciphertext), bytes(row.password_nonce)
                ).key
            except SecretError:
                return None
        elif row.username:
            return None  # a login without a password
        return Profile(
            host=row.host,
            port=row.port,
            security=row.security,
            username=row.username,
            from_address=row.from_address,
            from_name=row.from_name,
            mode=row.mode,
            auto_hold_minutes=row.auto_hold_minutes,
            daily_cap=row.daily_cap,
            password=password,
            digest_minute=row.digest_minute,
        )

    # -- one cycle -----------------------------------------------------------------------

    async def digest_params(
        self, session: AsyncSession, profile: Profile | None, now: datetime
    ) -> dict[str, Any]:
        """The parameters of ``RECIPIENT_FREE`` for this moment."""
        enabled = await session.scalar(
            text("SELECT digest_enabled FROM report_settings WHERE id = 1")
        )
        utc = now.astimezone(UTC)
        return {
            "digest": enabled is not False and profile is not None,
            "digest_minute": profile.digest_minute if profile is not None else 0,
            "hold": profile.auto_hold_minutes if profile is not None else 0,
            "minute": utc.hour * 60 + utc.minute,
            "day0": utc_day(now),
            "now": now,
        }

    async def run(self, now: datetime) -> None:
        await self._sweep()
        async with self.factory() as session:
            profile = await self.load_profile(session)
            params = await self.digest_params(session, profile, now)
            ids = (
                (
                    await session.execute(
                        text(
                            "SELECT q.id FROM abuse_send_requests q "  # noqa: S608
                            "LEFT JOIN abuse_reports r ON r.id = q.report_id "
                            "LEFT JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                            "WHERE q.status = 'pending' "
                            "AND (q.scheduled_at IS NULL OR q.scheduled_at <= :now) "
                            "AND (NOT q.auto OR (" + SENT_TODAY + ") < :cap) "
                            "AND (NOT q.auto OR q.report_id IS NULL OR " + RECIPIENT_FREE + ") "
                            # manual first, then the freshest evidence
                            "ORDER BY q.auto, r.window_end DESC NULLS LAST, q.id LIMIT :n"
                        ),
                        {
                            **params,
                            "cap": profile.daily_cap if profile is not None else 0,
                            "n": MAX_PER_CYCLE,
                        },
                    )
                )
                .scalars()
                .all()
            )
        for rid in ids:
            await self._handle(rid, now)
        await self.schedule(now)

    async def _sweep(self) -> None:
        """A request left in ``sending`` (ingest died around the delivery) ended in an outcome
        nobody knows. It is failed, never retried: a second mail would be worse."""
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE abuse_send_requests SET status = 'failed', "
                    "error_code = 'unknown_outcome', done_at = now() "
                    "WHERE status = 'sending' AND started_at < now() - make_interval(secs => :s)"
                ),
                {"s": STALE_SENDING_S},
            )

    async def schedule(self, now: datetime) -> int:
        """Auto mode: a pending request, ``auto_hold_minutes`` ahead (and not before a digest's
        ``due_at``), for each ready report that never had one, or whose automatic sends were only
        deferred (at most ``MAX_DEFERRALS``), and whose evidence is younger than ``AUTO_MAX_AGE``,
        newest first. An owner's cancel, a refusal and an unknown outcome are not rescheduled; a
        request that ended for a reason that may be gone is, once that reason is gone
        (``RESCHEDULABLE``). The one-digest-a-day rule and the hold from the last rebuild are
        checked when the request is picked."""
        async with self.factory() as session, session.begin():
            profile = await self.load_profile(session)
            if profile is None or profile.mode != "auto":
                return 0
            result = await session.execute(
                text(SCHEDULE_SQL),
                {
                    "at": now + timedelta(minutes=profile.auto_hold_minutes),
                    "n": MAX_SCHEDULE,
                    "deferrals": MAX_DEFERRALS,
                    "max_age": AUTO_MAX_AGE.total_seconds(),
                },
            )
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    async def _finish(
        self, session: AsyncSession, rid: int, status: str, code: str | None = None
    ) -> None:
        await session.execute(
            text(
                "UPDATE abuse_send_requests SET status = :s, error_code = :c, done_at = now() "
                "WHERE id = :i AND status IN ('pending', 'sending')"
            ),
            {"s": status, "c": code, "i": rid},
        )

    async def _claim(self, rid: int, message_id: str | None = None) -> bool:
        """``sending`` is committed on its own BEFORE anything is connected. From here on the
        request is never picked again: a crash leaves it ``sending`` and the sweep fails it.
        The Message-ID of the mail is stored in the same update (once; the database refuses a
        change), so a reply can be matched to this request later (M26)."""
        async with self.factory() as session, session.begin():
            claimed = await session.execute(
                text(
                    "UPDATE abuse_send_requests SET status = 'sending', started_at = now(), "
                    "message_id = COALESCE(message_id, CAST(:m AS text)) "
                    "WHERE id = :i AND status = 'pending'"
                ),
                {"i": rid, "m": message_id},
            )
            return claimed.rowcount == 1  # type: ignore[attr-defined,no-any-return]

    # -- one request ---------------------------------------------------------------------

    async def _handle(self, rid: int, now: datetime) -> None:
        # One transaction for the whole mail. Its shared advisory lock makes the API wait when
        # the owner edits or deletes the profile while a mail is in flight.
        async with self.factory() as session, session.begin():
            await session.execute(
                text("SELECT pg_advisory_xact_lock_shared(:k)"), {"k": ABUSE_SMTP_PROFILE}
            )
            row = (
                await session.execute(
                    text(
                        "SELECT id, report_id, kind, auto, requested_by, requested_at, "
                        "scheduled_at, message_id FROM abuse_send_requests "
                        "WHERE id = :i AND status = 'pending'"
                    ),
                    {"i": rid},
                )
            ).first()
            if row is None:
                return  # cancelled meanwhile
            req = Request(*row)
            profile = await self.load_profile(session)
            if profile is None:
                await self._finish(session, rid, "failed", "not_configured")
                return
            if req.kind == "send":
                refused = self._mode_refusal(req, profile)
                if refused is not None:
                    await self._finish(session, rid, refused[0], refused[1])
                    return
            if (
                req.auto
                and req.kind == "send"
                and int(await session.scalar(text(SENT_TODAY)) or 0) >= profile.daily_cap
            ):
                return  # the cap is per UTC day: it stays pending until tomorrow
            if req.kind == "send":
                refusal = await self._desk_refusal(session, req)
                if refusal is not None:
                    await self._finish(session, rid, "cancelled", refusal)
                    log.info("abuse mail request %s cancelled (%s)", rid, refusal)
                    return
            if req.auto and req.kind == "send" and await self._too_old(session, req):
                await self._finish(session, rid, "cancelled", "too_old")
                log.info("abuse mail request %s cancelled (too_old)", rid)
                return
            if (
                req.auto
                and req.kind == "send"
                and await session.scalar(
                    text(AUTO_PACED),
                    {
                        "spacing": AUTO_SPACING.total_seconds(),
                        "pause": AUTO_PAUSE.total_seconds(),
                    },
                )
            ):
                return  # paced: it stays pending for a later cycle
            if (
                req.auto
                and req.kind == "send"
                and not await self._recipient_free(session, req, profile, now)
            ):
                return  # the recipient had its digest today: it waits for the next one
            if not gate_open(self.gate):
                # Nothing is attempted: no socket, no tunnel. A send waits for the VPN.
                if req.kind == "test" and now - req.requested_at > TEST_EGRESS_WAIT:
                    await self._finish(session, rid, "failed", "egress_closed")
                return
            try:
                prepared = await self._prepare(session, req, profile, now)
            except SendFailure as exc:  # nothing was sent: the guard or the report said no
                await self._finish(session, rid, "failed", exc.stored)
                log.info("abuse mail request %s failed (%s)", rid, exc.code)
                return
            except Exception as exc:  # never let a message text escape
                log.warning("abuse mail request %s failed (%s)", rid, type(exc).__name__)
                await self._finish(session, rid, "failed", "internal")
                return
            if not await self._claim(rid, prepared.message_id):
                return  # the owner cancelled it in the meantime
            await self._deliver_and_record(session, req, profile, prepared)

    async def _deliver_and_record(
        self, session: AsyncSession, req: Request, profile: Profile, prepared: Prepared
    ) -> None:
        try:
            await self._deliver(profile, prepared.raw, prepared.rcpt)
        except SendFailure as exc:
            if exc.code == "egress_closed" and req.kind == "send":
                # Raised before any connection existed: nothing was sent, so it may wait.
                await session.execute(
                    text(
                        "UPDATE abuse_send_requests SET status = 'pending', started_at = NULL "
                        "WHERE id = :i AND status = 'sending'"
                    ),
                    {"i": req.id},
                )
                return
            await self._finish(session, req.id, "failed", exc.stored)
            log.info("abuse mail request %s failed (%s)", req.id, exc.stored)
            return
        except Exception as exc:  # after the claim an unexpected error leaves the outcome unknown
            log.warning("abuse mail request %s failed (%s)", req.id, type(exc).__name__)
            await self._finish(session, req.id, "failed", "unknown_outcome")
            return
        await self._mark_done(session, req, prepared)

    async def _mark_done(self, session: AsyncSession, req: Request, prepared: Prepared) -> None:
        """The mail is gone. A failure to mark the report must not stop the request ending as
        sent; if even the commit fails the request stays ``sending`` and is never sent again."""
        if prepared.report is not None:
            stamp: dict[str, Any] = {
                "i": prepared.report["id"],
                "by": req.requested_by[:120],
                "x": json.dumps(list(prepared.xarf)),
            }
            auto_review = req.auto and prepared.report["status"] == "draft"
            try:
                async with session.begin_nested():
                    await session.execute(text(MARK_AUTO if auto_review else MARK_SENT), stamp)
                    # Older sources stayed out of the automatic digest: they were not sent.
                    for kind, stype, value in prepared.stale:
                        await session.execute(
                            text(
                                "DELETE FROM abuse_report_subjects WHERE report_id = :i "
                                "AND kind = :k AND subject_type = :t AND value = :v"
                            ),
                            {"i": stamp["i"], "k": kind, "t": stype, "v": value},
                        )
            except DBAPIError:
                log.warning("abuse report %s was sent but could not be marked", stamp["i"])
        await self._finish(session, req.id, "sent")

    @staticmethod
    async def _desk_refusal(session: AsyncSession, req: Request) -> str | None:
        """A cancel code when the report must not go out: a subject is a shared service or on
        the never list (always, a draft made before the list grew included), or the desk takes
        only its web form or its address is dead (automatic sends only)."""
        subjects = (
            await session.execute(
                text(
                    "SELECT s.value FROM abuse_report_subjects s JOIN abuse_reports r "
                    "ON r.id = s.report_id WHERE s.report_id = :i AND NOT r.demo"
                ),
                {"i": req.report_id},
            )
        ).scalars()
        if any(is_excluded_host(_host_of_subject(v)) for v in subjects):
            return "shared_host"
        if not req.auto:
            return None
        flags = (
            await session.execute(
                text(
                    "SELECT rec.form_only, rec.undeliverable FROM abuse_reports r "
                    "JOIN abuse_recipients rec ON rec.id = r.recipient_id WHERE r.id = :i"
                ),
                {"i": req.report_id},
            )
        ).first()
        if flags is not None and flags.form_only:
            return "form_only"
        if flags is not None and flags.undeliverable:
            return "undeliverable"
        return None

    async def _recipient_free(
        self, session: AsyncSession, req: Request, profile: Profile, now: datetime
    ) -> bool:
        params = await self.digest_params(session, profile, now)
        return bool(
            await session.scalar(
                text(
                    "SELECT " + RECIPIENT_FREE + " FROM abuse_reports r "  # noqa: S608
                    "JOIN abuse_recipients rec ON rec.id = r.recipient_id WHERE r.id = :i"
                ),
                {**params, "i": req.report_id},
            )
        )

    @staticmethod
    async def _too_old(session: AsyncSession, req: Request) -> bool:
        """The report's last activity is older than ``AUTO_MAX_AGE`` (database time)."""
        return bool(
            await session.scalar(
                text(
                    "SELECT window_end <= now() - make_interval(secs => :a) "
                    "FROM abuse_reports WHERE id = :i"
                ),
                {"i": req.report_id, "a": AUTO_MAX_AGE.total_seconds()},
            )
        )

    @staticmethod
    def _mode_refusal(req: Request, profile: Profile) -> tuple[str, str] | None:
        if profile.mode == "off":
            return ("failed", "mode_off")
        if req.auto and profile.mode != "auto":
            return ("cancelled", "mode_changed")
        return None

    async def _prepare(
        self, session: AsyncSession, req: Request, profile: Profile, now: datetime
    ) -> Prepared:
        """Build and guard the complete message. Raises before anything is claimed or sent."""
        terms = await self.terms.get()
        if req.kind == "test":
            raw = build_test_message(profile)
            check_message(raw, profile, profile.from_address, terms)
            return Prepared(raw, profile.from_address, None)
        if req.report_id is None:
            raise SendFailure("not_ready")
        report = await self._load_report(session, req.report_id)
        if report is None:
            raise SendFailure("not_ready")
        rendered, ctx, stale = await self._render(session, report, fresh_only=req.auto, now=now)
        message_id = req.message_id or new_message_id(profile)  # kept when a request is retried
        raw = build_message(profile, rendered, now=now, message_id=message_id)
        if not await asyncio.to_thread(xarf_parts_valid, raw):
            raise SendFailure("xarf_invalid")
        check_message(raw, profile, rendered.to, terms, ctx=ctx, rendered=rendered)
        files = tuple({"name": a.name, "content": a.content} for a in rendered.xarf_files)
        return Prepared(raw, rendered.to, report, message_id, stale, files)

    async def _deliver(self, profile: Profile, raw: bytes, rcpt: str) -> None:
        try:
            self.gate.require_open()  # before any thread, socket or tunnel exists
            # The thread enforces the deadline itself; this is only a backstop.
            await asyncio.wait_for(
                asyncio.to_thread(deliver, self.gate, profile, raw, rcpt),
                SMTP_DEADLINE_S + 10,
            )
        except EgressClosed:
            raise SendFailure("egress_closed") from None
        except TimeoutError:
            raise SendFailure("unknown_outcome") from None

    # -- the report ----------------------------------------------------------------------

    async def _load_report(self, session: AsyncSession, report_id: int) -> dict[str, Any] | None:
        row = (
            await session.execute(
                text(
                    "SELECT r.id, r.status, r.demo, r.kind, r.guard_ok, r.evidence, r.options, "
                    "r.reply_token, r.id_seed, "
                    "r.window_start, r.window_end, rec.muted, rec.mailbox, rec.override_mailbox "
                    "FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                    "WHERE r.id = :i"
                ),
                {"i": report_id},
            )
        ).first()
        if row is None:
            return None
        report = dict(row._mapping)
        mailbox = report["override_mailbox"] or report["mailbox"]
        if (
            report["status"] not in ("draft", "reviewed")
            or report["demo"]
            or not report["guard_ok"]
            or report["muted"]
            or not mailbox
        ):
            return None
        report["recipient"] = mailbox
        return report

    async def _render(
        self,
        session: AsyncSession,
        report: dict[str, Any],
        *,
        fresh_only: bool = False,
        now: datetime | None = None,
    ) -> tuple[RenderedMessage, GuardContext, tuple[tuple[str, str, str], ...]]:
        settings_row = (await session.execute(text(SETTINGS_SQL))).first()
        settings = ReportSettings()
        style: ReferenceStyle = "subject"
        defaults: dict[str, Any] = {}
        if settings_row is not None:
            settings = report_settings_of(settings_row)
            defaults = dict(settings_row.defaults or {})
            if settings_row.reference_style in ("subject", "subject_and_body", "off"):
                style = settings_row.reference_style
        options = options_of(report["options"], default_options(self.abuse, defaults))
        keys = await subject_keys(session, report["id"])
        data = with_subject_rows(dict(report["evidence"]), report["kind"], keys)
        data.update(
            kind=report["kind"],
            recipient=report["recipient"],
            window_start=report["window_start"],
            window_end=report["window_end"],
            demo=False,
            options=options.model_dump(),
        )
        try:
            evidence = Evidence.model_validate(data)
        except ValueError:
            raise SendFailure("not_ready") from None
        stale: tuple[tuple[str, str, str], ...] = ()
        if fresh_only:
            # Per source: an automatic mail carries only sources active in the last 7 days.
            cutoff = (now or datetime.now(UTC)) - AUTO_MAX_AGE
            fresh = tuple(x for x in evidence.subjects if x.last_ts > cutoff)
            if not fresh:
                raise SendFailure("too_old")
            stale = tuple(
                (evidence.kind_of(x), x.type, x.value)
                for x in evidence.subjects
                if x.last_ts <= cutoff
            )
            if stale:
                evidence = evidence.model_copy(
                    update={
                        "subjects": fresh,
                        "window_start": min(x.first_ts for x in fresh),
                        "window_end": max(x.last_ts for x in fresh),
                    }
                )
        try:
            rendered = await asyncio.to_thread(
                render_mail, evidence, settings, report["reply_token"], style
            )
        except RenderUnavailable as exc:
            if exc.code == "xarf_invalid":
                raise SendFailure("xarf_invalid") from None
            raise SendFailure("guard_failed", reasons=(exc.code,)) from None
        except ValueError:
            raise SendFailure("not_ready") from None
        # The seed never leaves: a token built from it (or the seed itself) is caught (M26). The
        # sessions behind the subjects are the superset the re-check of the drafts uses.
        ids = {report["id_seed"].hex} | await internal_session_ids(session, evidence)
        return (
            rendered,
            GuardContext(
                internal_ids=frozenset(ids), allow_documentation=self._allow_documentation
            ),
            stale,
        )
