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
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.locks import ABUSE_SMTP_PROFILE
from suckerpot_db.secretbox import SecretBox, SecretError
from suckerpot_reporting import (
    Evidence,
    GuardContext,
    ReferenceStyle,
    RenderedMessage,
    RenderUnavailable,
    ReportSettings,
)

from ingest.abuse.build import default_options, options_of, render_mail
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
)

log = logging.getLogger(__name__)

MAX_PER_CYCLE = 10
MAX_SCHEDULE = 50
TEST_EGRESS_WAIT = timedelta(minutes=2)
PASSWORD_AAD = "report_smtp"  # noqa: S105 - a label, not a secret; bound to the ciphertext, see api.abuse_smtp


MARK_SENT = (
    "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = :by, sent_via = 'smtp' "
    "WHERE id = :i AND status IN ('draft', 'reviewed')"
)
# An automatic send of a draft is stamped as reviewed by 'auto' (the trigger allows nothing else).
MARK_AUTO = (
    "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = :by, sent_via = 'smtp', "
    "reviewed_at = now(), reviewed_by = 'auto', reviewed_revision = revision "
    "WHERE id = :i AND status IN ('draft', 'reviewed')"
)


# Sends that left today (UTC), as an SQL scalar for the daily cap.
SENT_TODAY = (
    "SELECT count(*) FROM abuse_send_requests s WHERE s.kind = 'send' AND s.status = 'sent' "
    "AND s.done_at >= (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')"
)
STALE_SENDING_S = SMTP_DEADLINE_S + 30


@dataclass(frozen=True, slots=True)
class Prepared:
    raw: bytes
    rcpt: str
    report: dict[str, Any] | None
    message_id: str | None = None


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
                    "auto_hold_minutes, daily_cap, password_ciphertext, password_nonce "
                    "FROM report_smtp WHERE id = 1"
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
        )

    # -- one cycle -----------------------------------------------------------------------

    async def run(self, now: datetime) -> None:
        await self._sweep()
        async with self.factory() as session:
            profile = await self.load_profile(session)
            ids = (
                (
                    await session.execute(
                        text(
                            "SELECT id FROM abuse_send_requests q WHERE q.status = 'pending' "  # noqa: S608
                            "AND (q.scheduled_at IS NULL OR q.scheduled_at <= :now) "
                            "AND (NOT q.auto OR (" + SENT_TODAY + ") < :cap) "
                            "ORDER BY q.auto, q.id LIMIT :n"
                        ),
                        {
                            "now": now,
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
        """Auto mode: a pending request, ``auto_hold_minutes`` ahead, for each ready report that
        never had one. Cancelled and failed requests are not rescheduled (the owner decided or
        can press Send)."""
        async with self.factory() as session, session.begin():
            profile = await self.load_profile(session)
            if profile is None or profile.mode != "auto":
                return 0
            result = await session.execute(
                text(
                    """
                    INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by,
                                                     scheduled_at)
                    SELECT r.id, 'send', true, 'auto', :at
                    FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id
                    WHERE r.status IN ('draft', 'reviewed') AND NOT r.demo AND r.guard_ok
                      AND NOT rec.muted
                      AND COALESCE(NULLIF(rec.override_mailbox, ''), rec.mailbox) IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1 FROM abuse_send_requests q WHERE q.report_id = r.id)
                    ORDER BY r.id LIMIT :n
                    """
                ),
                {"at": now + timedelta(minutes=profile.auto_hold_minutes), "n": MAX_SCHEDULE},
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
            log.info("abuse mail request %s failed (%s)", req.id, exc.code)
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
            stamp: dict[str, Any] = {"i": prepared.report["id"], "by": req.requested_by[:120]}
            auto_review = req.auto and prepared.report["status"] == "draft"
            try:
                async with session.begin_nested():
                    await session.execute(text(MARK_AUTO if auto_review else MARK_SENT), stamp)
            except DBAPIError:
                log.warning("abuse report %s was sent but could not be marked", stamp["i"])
        await self._finish(session, req.id, "sent")

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
        rendered, ctx = await self._render(session, report)
        message_id = req.message_id or new_message_id(profile)  # kept when a request is retried
        raw = build_message(profile, rendered, now=now, message_id=message_id)
        check_message(raw, profile, rendered.to, terms, ctx=ctx, rendered=rendered)
        return Prepared(raw, rendered.to, report, message_id)

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
        self, session: AsyncSession, report: dict[str, Any]
    ) -> tuple[RenderedMessage, GuardContext]:
        settings_row = (
            await session.execute(
                text(
                    "SELECT reply_contact, signature, intro, outro, note, subject_template, "
                    "xarf_user_agent, defaults, reference_style FROM report_settings WHERE id = 1"
                )
            )
        ).first()
        settings = ReportSettings()
        style: ReferenceStyle = "subject"
        defaults: dict[str, Any] = {}
        if settings_row is not None:
            settings = ReportSettings(
                reply_contact=settings_row.reply_contact,
                signature=settings_row.signature,
                intro=settings_row.intro,
                outro=settings_row.outro,
                note=settings_row.note,
                subject_template=settings_row.subject_template,
                xarf_user_agent=settings_row.xarf_user_agent,
            )
            defaults = dict(settings_row.defaults or {})
            if settings_row.reference_style in ("subject", "subject_and_body", "off"):
                style = settings_row.reference_style
        options = options_of(report["options"], default_options(self.abuse, defaults))
        data = dict(report["evidence"])
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
            rendered = await asyncio.to_thread(
                render_mail, evidence, settings, report["reply_token"], style
            )
        except RenderUnavailable as exc:
            raise SendFailure("guard_failed", reasons=(exc.code,)) from None
        except ValueError:
            raise SendFailure("not_ready") from None
        # The seed never leaves: a token built from it (or the seed itself) is caught (M26). The
        # sessions behind the subjects are the superset the re-check of the drafts uses.
        ids = {report["id_seed"].hex} | await internal_session_ids(session, evidence)
        return rendered, GuardContext(
            internal_ids=frozenset(ids), allow_documentation=self._allow_documentation
        )
