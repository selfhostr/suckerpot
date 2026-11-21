"""The replies worker (design M26, section 4). Off until ``ABUSE_REPLIES_ENABLED``.

Each cycle (a minute) it
1. creates the outcome rows of sent reports,
2. processes pasted replies (no mailbox needed),
3. answers "Test connection" and "Check now" requests from the API,
4. polls the mailbox when the owner enabled it and the interval has passed,
5. refreshes the automatic outcome of the reports whose replies changed.

The mailbox is only ever reached through ``SafeMailbox`` (and the VPN tunnel): with the gate
closed nothing is attempted. Incoming mail is hostile, see ``parse``. Nothing is written back
to the mailbox except the "seen" flag or a move to the owner's folder, after the reply is
committed. Error codes are constants; server answers and mail content never reach a log.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any, TypeVar

from sqlalchemy import text
from sqlalchemy.exc import DataError, IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.locks import ABUSE_IMAP_PROFILE
from suckerpot_db.secretbox import SecretBox, SecretError

from ingest.egress import EgressGate, gate_open, get_gate
from ingest.features import FeatureSettings, FeatureWorker

from . import outcome
from .config import RepliesSettings
from .imap import ImapProfile, Mailbox, MailboxError, SafeMailbox
from .match import recent_reports
from .parse import authserv_hint, authserv_sample, parse_headers, parse_message
from .rules import ReplyRules, load_reply_rules
from .store import is_relevant, store_reply

log = logging.getLogger(__name__)

PASSWORD_AAD = "report_imap"  # noqa: S105 - a label, not a secret; bound to the ciphertext
MAX_IMPORTS = 10
MAX_REQUESTS = 5
HINT_MESSAGES = 20  # "Test connection" reads the headers of this many recent messages
HINT_KEY = "authserv_hint"  # kept inside the counters column, carried over from day to day
SAMPLE_KEY = "authserv_sample"  # the poll's rolling (name, sender domain) sample, same column
COUNTER_KEYS = ("fetched", "relevant", "matched", "ignored", "oversize", "failed")
# A broken connection or database: nothing more can be done in this poll. A mail that cannot be
# stored (its own data is the problem) is counted as failed and skipped, never fatal: it must not
# stop the replies behind it.
FATAL = frozenset({"timeout", "network", "egress_closed", "tls_failed", "auth_failed", "internal"})
BAD_DATA = (DataError, IntegrityError)

MailboxFactory = Callable[[ImapProfile, EgressGate, float], Mailbox]
T = TypeVar("T")


def default_mailbox(profile: ImapProfile, gate: EgressGate, deadline_s: float) -> Mailbox:
    return SafeMailbox(gate, profile, deadline_s=deadline_s)


def fingerprint(profile: ImapProfile) -> str:
    """Changes when the owner points the worker at another mailbox or folder."""
    key = f"{profile.host}|{profile.port}|{profile.username}|{profile.folder}"
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass(slots=True)
class State:
    fingerprint: str | None = None
    uidvalidity: int | None = None
    last_uid: int = 0
    move_supported: bool | None = None
    last_poll_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_error: str | None = None
    counters: dict[str, Any] = field(default_factory=dict)
    # The most common top-most authserv-id seen while no trusted id is set: {id, seen, of}.
    authserv_hint: dict[str, Any] | None = None
    # The last (top-most authserv-id, sender domain) pairs the poll read, at most HINT_MESSAGES.
    authserv_sample: list[tuple[str, str]] = field(default_factory=list)


def fresh_counters(day: date) -> dict[str, Any]:
    return {"day": day.isoformat(), **dict.fromkeys(COUNTER_KEYS, 0)}


class ReplyWorker(FeatureWorker):
    name = "replies"
    interval_s = 60.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        *,
        replies: RepliesSettings | None = None,
        env: Mapping[str, str] | None = None,
        gate: EgressGate | None = None,
        box: SecretBox | None = None,
        rules: ReplyRules | None = None,
        rules_dir: Path | None = None,
        mailbox_factory: MailboxFactory = default_mailbox,
    ) -> None:
        super().__init__(settings, enabled=settings.replies_enabled)
        self.factory = factory
        self.cfg = replies or RepliesSettings.from_env(env)
        self._gate = gate
        self.box = box
        self.mailbox_factory = mailbox_factory
        self.rules: ReplyRules | None = rules
        if self.enabled and rules is None and rules_dir is not None:
            self.rules = load_reply_rules(rules_dir)  # a broken rule file stops the start
        self.poll_state = "idle"

    @property
    def gate(self) -> EgressGate:
        return self._gate or get_gate()

    # -- the profile and the state -------------------------------------------------------

    async def load_profile(self, session: AsyncSession) -> ImapProfile | None:
        row = (
            await session.execute(
                text(
                    "SELECT enabled, host, port, security, username, password_ciphertext, "
                    "password_nonce, folder, processed_action, move_folder, poll_minutes, since, "
                    "trusted_authserv_id "
                    "FROM report_imap WHERE id = 1"
                )
            )
        ).first()
        if row is None or row.password_ciphertext is None or self.box is None:
            return None  # no profile, or nothing to decrypt it with
        try:
            password = self.box.decrypt(
                PASSWORD_AAD, bytes(row.password_ciphertext), bytes(row.password_nonce)
            ).key
        except SecretError:
            return None
        return ImapProfile(
            host=row.host,
            port=row.port,
            security=row.security,
            username=row.username,
            folder=row.folder,
            processed_action=row.processed_action,
            move_folder=row.move_folder,
            poll_minutes=row.poll_minutes,
            since=row.since,
            enabled=row.enabled,
            password=password,
            trusted_authserv_id=row.trusted_authserv_id,
        )

    async def load_state(self) -> State:
        assert self.factory is not None  # noqa: S101
        async with self.factory() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT profile_fingerprint, uidvalidity, last_uid, move_supported, "
                        "last_poll_at, last_ok_at, last_error, counters "
                        "FROM report_imap_state WHERE id = 1"
                    )
                )
            ).first()
        if row is None:
            return State()
        counters = dict(row.counters or {})
        hint = counters.pop(HINT_KEY, None)
        raw_sample = counters.pop(SAMPLE_KEY, None)
        sample = [
            (str(e[0]), str(e[1]))
            for e in (raw_sample if isinstance(raw_sample, list) else [])
            if isinstance(e, list) and len(e) == 2
        ][-HINT_MESSAGES:]
        return State(
            row.profile_fingerprint,
            row.uidvalidity,
            row.last_uid,
            row.move_supported,
            row.last_poll_at,
            row.last_ok_at,
            row.last_error,
            counters,
            hint if isinstance(hint, dict) else None,
            sample,
        )

    async def save_state(self, state: State) -> None:
        assert self.factory is not None  # noqa: S101
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO report_imap_state (id, profile_fingerprint, uidvalidity, last_uid,
                        move_supported, last_poll_at, last_ok_at, last_error, counters)
                    VALUES (1, :fp, :uv, :uid, :ms, :poll, :ok, :err, CAST(:c AS jsonb))
                    ON CONFLICT (id) DO UPDATE SET profile_fingerprint = :fp, uidvalidity = :uv,
                        last_uid = :uid, move_supported = :ms, last_poll_at = :poll,
                        last_ok_at = :ok, last_error = :err, counters = CAST(:c AS jsonb)
                    """
                ),
                {
                    "fp": state.fingerprint,
                    "uv": state.uidvalidity,
                    "uid": state.last_uid,
                    "ms": state.move_supported,
                    "poll": state.last_poll_at,
                    "ok": state.last_ok_at,
                    "err": state.last_error,
                    "c": json.dumps(
                        state.counters
                        | ({HINT_KEY: state.authserv_hint} if state.authserv_hint else {})
                        | (
                            {SAMPLE_KEY: [list(e) for e in state.authserv_sample]}
                            if state.authserv_sample
                            else {}
                        )
                    ),
                },
            )

    async def _locked(self, work: Callable[[ImapProfile | None], Awaitable[T]]) -> T:
        """Run ``work`` with the profile, holding the profile lock SHARED: the API waits for
        it before it changes or deletes the profile, so a poll never uses a half-changed one."""
        assert self.factory is not None  # noqa: S101
        async with self.factory() as session, session.begin():
            await session.execute(
                text("SELECT pg_advisory_xact_lock_shared(:k)"), {"k": ABUSE_IMAP_PROFILE}
            )
            profile = await self.load_profile(session)
            return await work(profile)

    # -- one cycle -----------------------------------------------------------------------

    async def run_once(self) -> None:
        if self.factory is None or self.rules is None:
            return
        now = datetime.now(UTC)
        factory = self.factory
        steps: tuple[Callable[[], Awaitable[object]], ...] = (
            lambda: outcome.ensure_rows(factory),
            lambda: self.process_imports(now),
            lambda: self.handle_requests(now),
            lambda: self.maybe_poll(now),
            lambda: outcome.recompute(factory),
        )
        for step in steps:
            try:
                await step()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # one step failing never stops the others
                self.last_error = type(exc).__name__
                log.warning("replies step failed (%s)", type(exc).__name__)

    # -- pasted replies ------------------------------------------------------------------

    async def process_imports(self, now: datetime) -> int:
        assert self.factory is not None and self.rules is not None  # noqa: S101
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT id, report_id, raw, requested_by FROM abuse_reply_imports "
                        "WHERE status = 'pending' ORDER BY id LIMIT :n"
                    ),
                    {"n": MAX_IMPORTS},
                )
            ).all()
            recent = await recent_reports(session, self.cfg.match_days)
            trusted_id = await session.scalar(
                text("SELECT trusted_authserv_id FROM report_imap WHERE id = 1")
            )
        for row in rows:
            status, code, reply_id = "done", None, None
            try:
                parsed = await asyncio.to_thread(
                    parse_message,
                    bytes(row.raw),
                    max_bytes=self.cfg.max_bytes,
                    excerpt_chars=self.cfg.excerpt_chars,
                    trusted_authserv_id=trusted_id,
                )
                async with self.factory() as session, session.begin():
                    stored = await store_reply(
                        session,
                        self.rules,
                        parsed,
                        source="paste",
                        received_at=now,
                        recent=recent,
                        hint_report_id=row.report_id,
                        owner=row.requested_by,
                    )
                    if stored.status != "stored":
                        status, code = "failed", stored.status
                    reply_id = stored.reply_id
                    await self._finish_import(session, row.id, status, code, reply_id, now)
            except Exception as exc:  # one bad paste never blocks the ones behind it
                log.warning("pasted reply %s failed (%s)", row.id, type(exc).__name__)
                try:
                    async with self.factory() as session, session.begin():
                        await self._finish_import(session, row.id, "failed", "internal", None, now)
                except Exception as inner:  # the database itself is gone: try again next cycle
                    log.warning("pasted reply %s not closed (%s)", row.id, type(inner).__name__)
        return len(rows)

    @staticmethod
    async def _finish_import(
        session: AsyncSession,
        import_id: int,
        status: str,
        code: str | None,
        reply_id: int | None,
        now: datetime,
    ) -> None:
        await session.execute(
            text(
                "UPDATE abuse_reply_imports SET raw = CAST('' AS bytea), status = :s, "
                "error_code = :c, reply_id = :r, done_at = :t WHERE id = :i AND status = 'pending'"
            ),
            {"s": status, "c": code, "r": reply_id, "t": now, "i": import_id},
        )

    # -- requests from the API -----------------------------------------------------------

    async def handle_requests(self, now: datetime) -> int:
        assert self.factory is not None  # noqa: S101
        async with self.factory() as session:
            pending = (
                await session.execute(
                    text(
                        "SELECT id, kind FROM report_imap_requests WHERE status = 'pending' "
                        "ORDER BY id LIMIT :n"
                    ),
                    {"n": MAX_REQUESTS},
                )
            ).all()
        for req in pending:
            result: dict[str, Any] = {"ok": False}
            code: str | None = None
            try:
                result, code = await self._locked(partial(self._answer, req.kind, now=now))
            except SQLAlchemyError as exc:
                log.warning("imap request %s failed (%s)", req.id, type(exc).__name__)
                code = "internal"
            async with self.factory() as session, session.begin():
                await session.execute(
                    text(
                        "UPDATE report_imap_requests SET status = :s, error_code = :c, "
                        "result = CAST(:r AS jsonb), done_at = now() "
                        "WHERE id = :i AND status = 'pending'"
                    ),
                    {
                        "s": "failed" if code else "done",
                        "c": code,
                        "r": json.dumps(result),
                        "i": req.id,
                    },
                )
        return len(pending)

    async def _answer(
        self, kind: str, profile: ImapProfile | None, *, now: datetime
    ) -> tuple[dict[str, Any], str | None]:
        if profile is None:
            return {"ok": False}, "not_configured"
        if not gate_open(self.gate):
            return {"ok": False}, "egress_closed"
        if kind == "test":
            return await self._test(profile)
        if not profile.enabled:
            return {"ok": False}, "paused"
        state = await self.load_state()
        state, error = await self._poll(profile, state, now)
        await self.save_state(state)
        return {"ok": error is None, "counters": state.counters}, error

    async def _test(self, profile: ImapProfile) -> tuple[dict[str, Any], str | None]:
        mailbox = self.mailbox_factory(profile, self.gate, float(self.cfg.poll_deadline_s))
        try:
            await asyncio.to_thread(mailbox.connect)
            await asyncio.to_thread(mailbox.login)
            selected = await asyncio.to_thread(mailbox.select, profile.folder, readonly=True)
            folders = await asyncio.to_thread(mailbox.list_folders)
            hint = await self._hint(mailbox, selected.exists)
        except MailboxError as exc:
            return {"ok": False}, exc.code
        finally:
            await asyncio.to_thread(mailbox.logout)
        result: dict[str, Any] = {
            "ok": True,
            "messages": selected.exists,
            "move_supported": mailbox.move_supported,
            "folders": folders,
            "authserv_hint": hint,
        }
        if profile.processed_action == "move" and profile.move_folder not in folders:
            result["ok"] = False
            return result, "no_move_folder"
        return result, None

    @staticmethod
    async def _hint(mailbox: Mailbox, exists: int) -> dict[str, Any] | None:
        """Read the headers of the last messages (BODY.PEEK, the folder opened read-only) and
        name the provider that signs them. Best effort: a failure here only drops the hint."""
        try:
            uids = await asyncio.to_thread(mailbox.search_last, exists, HINT_MESSAGES)
            items = await asyncio.to_thread(mailbox.fetch_headers, uids) if uids else []
        except MailboxError:
            return None
        return authserv_hint(authserv_sample(i.headers) for i in items)

    # -- polling -------------------------------------------------------------------------

    async def maybe_poll(self, now: datetime) -> None:
        await self._locked(lambda p: self._maybe_poll(p, now))

    async def _maybe_poll(self, profile: ImapProfile | None, now: datetime) -> None:
        if profile is None:
            self.poll_state = "not_configured"
            return
        if not profile.enabled:
            self.poll_state = "paused"
            return
        state = await self.load_state()
        due = state.last_poll_at is None or now - state.last_poll_at >= timedelta(
            minutes=profile.poll_minutes
        )
        if not due:
            return
        if not gate_open(self.gate):
            self.poll_state = "egress_closed"  # nothing attempted: no row, no socket
            if state.last_error != "egress_closed":
                state.last_error = "egress_closed"
                await self.save_state(state)
            return
        state, _ = await self._poll(profile, state, now)
        await self.save_state(state)

    async def _poll(
        self, profile: ImapProfile, state: State, now: datetime
    ) -> tuple[State, str | None]:
        """One poll. Returns the new state and the error code (None when it went well)."""
        assert self.factory is not None and self.rules is not None  # noqa: S101
        cfg = self.cfg
        fp = fingerprint(profile)
        last_uid, validity = state.last_uid, state.uidvalidity
        if state.fingerprint != fp:  # another mailbox or folder: start from scratch
            last_uid, validity = 0, None
        today = now.astimezone(UTC).date()
        counters = (
            dict(state.counters)
            if state.counters.get("day") == today.isoformat()
            else fresh_counters(today)
        )
        budget = min(cfg.max_per_poll, cfg.daily_cap - int(counters.get("fetched", 0)))
        move_supported = state.move_supported
        sample = list(state.authserv_sample) if state.fingerprint == fp else []
        if profile.trusted_authserv_id:
            sample = []  # the owner chose: nothing to suggest
        mailbox = self.mailbox_factory(profile, self.gate, float(cfg.poll_deadline_s))
        error: str | None = None
        try:
            await asyncio.to_thread(mailbox.connect)
            await asyncio.to_thread(mailbox.login)
            selected = await asyncio.to_thread(mailbox.select, profile.folder)
            if validity is not None and selected.uidvalidity != validity:
                last_uid = 0  # the server renumbered the folder
            validity = selected.uidvalidity
            if budget > 0:
                uids = await asyncio.to_thread(mailbox.search_new, last_uid, profile.since, budget)
                items = await asyncio.to_thread(mailbox.fetch_headers, uids) if uids else []
                counters["fetched"] = int(counters.get("fetched", 0)) + len(items)
                if not profile.trusted_authserv_id:
                    sample = (sample + [authserv_sample(i.headers) for i in items])[-HINT_MESSAGES:]
                async with self.factory() as session:
                    recent = await recent_reports(session, cfg.match_days)
                for item in items:
                    try:
                        code, moved = await self._one(
                            mailbox, profile, item, validity, recent, counters, now
                        )
                    except MailboxError, SQLAlchemyError, asyncio.CancelledError:
                        raise
                    except Exception as exc:  # a bug on one mail must not stall the others
                        log.warning("reply skipped (%s)", type(exc).__name__)
                        counters["failed"] = int(counters.get("failed", 0)) + 1
                        code, moved = None, None
                    if moved is not None:
                        move_supported = moved
                    if code is not None:
                        error = code
                        if code in FATAL:
                            break
                    last_uid = max(last_uid, item.uid)
                else:
                    last_uid = max([last_uid, *uids])
        except MailboxError as exc:
            error = exc.code
        except SQLAlchemyError as exc:
            log.warning("replies poll database error (%s)", type(exc).__name__)
            error = "internal"
        except Exception as exc:  # never let a message text escape
            log.warning("replies poll failed (%s)", type(exc).__name__)
            error = "internal"
        finally:
            await asyncio.to_thread(mailbox.logout)
        if mailbox.move_supported is False and profile.processed_action == "move":
            move_supported = False
        return (
            State(
                fingerprint=fp,
                uidvalidity=validity,
                last_uid=last_uid,
                move_supported=move_supported,
                last_poll_at=now,
                last_ok_at=now if error is None else state.last_ok_at,
                last_error=error,
                counters=counters,
                authserv_hint=authserv_hint(sample),
                authserv_sample=sample,
            ),
            error,
        )

    async def _one(
        self,
        mailbox: Mailbox,
        profile: ImapProfile,
        item: Any,
        validity: int,
        recent: list[Any],
        counters: dict[str, Any],
        now: datetime,
    ) -> tuple[str | None, bool | None]:
        """One message. Returns (error code or None, move_supported if a move was tried)."""
        assert self.factory is not None and self.rules is not None  # noqa: S101
        cfg = self.cfg

        def count(key: str) -> None:
            counters[key] = int(counters.get(key, 0)) + 1

        if item.oversize:
            count("oversize")
            count("ignored")
            return None, None
        view = parse_headers(item.headers)
        try:
            async with self.factory() as session:
                relevant = await is_relevant(session, view, recent)
        except SQLAlchemyError:
            return "internal", None
        if not relevant:
            count("ignored")  # nothing stored, nothing flagged
            return None, None
        count("relevant")
        want = min(item.size or cfg.max_bytes, cfg.max_bytes)
        raw = await asyncio.to_thread(mailbox.fetch_partial, item.uid, want)
        parsed = await asyncio.to_thread(
            parse_message,
            raw,
            max_bytes=cfg.max_bytes,
            excerpt_chars=cfg.excerpt_chars,
            trusted_authserv_id=profile.trusted_authserv_id,
        )
        parsed = replace(
            parsed, size_bytes=item.size or len(raw), truncated=item.size > cfg.max_bytes
        )
        try:
            async with self.factory() as session, session.begin():
                stored = await store_reply(
                    session,
                    self.rules,
                    parsed,
                    source="imap",
                    received_at=item.internal_date or now,
                    recent=recent,
                    uidvalidity=validity,
                    uid=item.uid,
                )
        except BAD_DATA as exc:
            # This mail's own data broke a constraint (the transaction rolled back): count it and
            # let the poll move past it. Anything else (connection, lock) stays fatal.
            log.warning("reply could not be stored (%s)", type(exc).__name__)
            count("failed")
            return None, None
        except SQLAlchemyError as exc:
            log.warning("reply could not be stored (%s)", type(exc).__name__)
            return "internal", None
        if stored.status == "dropped":
            count("ignored")  # matched nothing: not stored, not flagged
            return None, None
        if stored.matched:
            count("matched")
        # The reply is committed. Only now is the mail marked or moved; a failure here leaves
        # the stored reply alone.
        try:
            if profile.processed_action == "move" and profile.move_folder:
                moved = await asyncio.to_thread(mailbox.move, item.uid, profile.move_folder)
                return None, moved
            await asyncio.to_thread(mailbox.mark_seen, item.uid)
        except MailboxError as exc:
            return exc.code, None
        return None, None

    # -- status --------------------------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        base = (await super().status())[self.name]
        base["poll"] = self.poll_state
        return {self.name: base}
