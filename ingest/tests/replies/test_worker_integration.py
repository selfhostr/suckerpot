"""The replies worker against a real database and a fake mailbox: no connection is ever opened.

Covers the invariants of M26: a closed gate attempts nothing, unrelated mail is never stored or
flagged, a relevant reply is stored before the mail is marked or moved, a forged reply never
changes an outcome, caps and UIDVALIDITY changes behave, and a pasted reply works without a
mailbox.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db import create_engine
from suckerpot_db.secretbox import Credential, SecretBox

from ingest.features import FeatureSettings
from ingest.replies import outcome
from ingest.replies.config import RepliesSettings
from ingest.replies.imap import HeaderItem, ImapProfile, MailboxError, Selected
from ingest.replies.rules import load_reply_rules
from ingest.replies.worker import ReplyWorker, fingerprint

from ..db_fixtures import _role_url
from ..helpers import fake_gate
from . import mails
from .mails import OUR_ID, mail

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

Factory = async_sessionmaker[AsyncSession]
RULES = load_reply_rules(Path(__file__).resolve().parents[2] / "rules" / "replies")
BOX = SecretBox(bytes(range(32, 72)))
NOW = datetime.now(UTC).replace(microsecond=0)
SETTINGS = FeatureSettings(replies_enabled=True)


@dataclass
class FakeMailbox:
    """The ``Mailbox`` protocol over a dict of raw messages (uid to bytes)."""

    messages: dict[int, bytes]
    uidvalidity: int = 1
    move_supported: bool = True
    log: list[str] = field(default_factory=list)
    seen: list[int] = field(default_factory=list)
    moved: list[tuple[int, str]] = field(default_factory=list)
    fail: dict[str, str] = field(default_factory=dict)

    def _go(self, name: str) -> None:
        self.log.append(name)
        if name in self.fail:
            raise MailboxError(self.fail[name])

    def connect(self) -> None:
        self._go("connect")

    def login(self) -> None:
        self._go("login")

    def select(self, folder: str, *, readonly: bool = False) -> Selected:
        self._go("select")
        return Selected(self.uidvalidity, len(self.messages))

    def search_new(self, last_uid: int, since: date, limit: int) -> list[int]:
        self._go("search")
        return sorted(u for u in self.messages if u > last_uid)[:limit]

    def fetch_headers(self, uids: list[int]) -> list[HeaderItem]:
        self._go("fetch_headers")
        out = []
        for uid in uids:
            raw = self.messages[uid]
            head = raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
            out.append(HeaderItem(uid, len(raw), NOW, head, False))
        return out

    def fetch_partial(self, uid: int, size: int) -> bytes:
        self._go("fetch_partial")
        return self.messages[uid][:size]

    def mark_seen(self, uid: int) -> None:
        self._go("mark_seen")
        self.seen.append(uid)

    def move(self, uid: int, folder: str) -> bool:
        self._go("move")
        if not self.move_supported:
            self.seen.append(uid)
            return False
        self.moved.append((uid, folder))
        return True

    def list_folders(self) -> list[str]:
        self._go("list")
        return ["INBOX", "Done"]

    def logout(self) -> None:
        self.log.append("logout")


class World:
    def __init__(self, owner: AsyncEngine, api: AsyncEngine, factory: Factory) -> None:
        self.owner, self.api, self.factory = owner, api, factory
        self.n = 0

    async def reset(self) -> None:
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "TRUNCATE report_imap, report_imap_state, report_imap_requests, abuse_replies, "
                    "abuse_reply_imports, abuse_report_outcomes, abuse_send_requests, "
                    "abuse_reports, abuse_recipients RESTART IDENTITY CASCADE"
                )
            )

    async def profile(self, **over: Any) -> None:
        values: dict[str, Any] = {
            "host": "imap.example.org", "port": 993, "security": "ssl", "username": "reports",
            "folder": "INBOX", "action": "mark_read", "move_folder": None, "enabled": True,
            "trusted": None,
        }  # fmt: skip
        values.update(over)
        cipher, nonce = BOX.encrypt("report_imap", Credential(key="sample-password"))
        async with self.owner.begin() as conn:
            await conn.execute(text("DELETE FROM report_imap"))
            await conn.execute(
                text(
                    "INSERT INTO report_imap (id, enabled, host, port, security, username, "
                    "password_ciphertext, password_nonce, folder, processed_action, move_folder, "
                    "since, trusted_authserv_id) VALUES (1, :enabled, :host, :port, :security, "
                    ":username, :c, :n, :folder, :action, :move_folder, '2026-01-01', :trusted)"
                ),
                values | {"c": cipher, "n": nonce},
            )

    async def sent_report(
        self, mailbox: str | None = None, *, status: str = "sent", kind: str = "attack_source",
        message_id: str | None = None, reply_domains: list[str] | None = None,
    ) -> tuple[int, str]:  # fmt: skip
        """A report to its own provider, sent two days ago. Returns (id, reply token)."""
        self.n += 1
        mailbox = mailbox or f"abuse{self.n}@example.net"
        async with self.owner.begin() as conn:
            rec = await conn.scalar(
                text(
                    "INSERT INTO abuse_recipients (mailbox, source) VALUES (:m, 'rdap') RETURNING id"
                ),
                {"m": mailbox},
            )
            if reply_domains:
                await conn.execute(
                    text("UPDATE abuse_recipients SET reply_domains = :d WHERE id = :i"),
                    {"d": reply_domains, "i": rec},
                )
            rid = int(
                await conn.scalar(
                    text(
                        "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, demo, window_start, window_end, subject_count, evidence, content_sha256, guard_ok) "
                        "VALUES (gen_random_uuid(), gen_random_uuid(), :r, :k, 'reviewed', false, now(), now(), 1, '{}', 'x', true) RETURNING id"
                    ),
                    {"r": rec, "k": kind},
                )
                or 0
            )
            if status in ("sent", "closed"):
                await conn.execute(
                    text(
                        "UPDATE abuse_reports SET status = 'sent', sent_at = now() - interval '2 days', sent_by = 'x', sent_via = 'manual' WHERE id = :i"
                    ),
                    {"i": rid},
                )
            if status == "draft":
                await conn.execute(
                    text("UPDATE abuse_reports SET status = 'draft' WHERE id = :i"), {"i": rid}
                )
            token = await conn.scalar(
                text("SELECT reply_token FROM abuse_reports WHERE id = :i"), {"i": rid}
            )
        if message_id is not None:
            async with self.api.begin() as conn:
                req = await conn.scalar(
                    text(
                        "INSERT INTO abuse_send_requests (report_id, kind, requested_by) VALUES (:r, 'send', 'admin') RETURNING id"
                    ),
                    {"r": rid},
                )
            async with self.owner.begin() as conn:
                await conn.execute(
                    text(
                        "UPDATE abuse_send_requests SET status = 'sending', started_at = now(), message_id = :m WHERE id = :i"
                    ),
                    {"m": message_id, "i": req},
                )
                await conn.execute(
                    text(
                        "UPDATE abuse_send_requests SET status = 'sent', done_at = now() WHERE id = :i"
                    ),
                    {"i": req},
                )
        return rid, str(token)

    def worker(
        self, box: FakeMailbox, *, gate: Any = None, cfg: RepliesSettings | None = None
    ) -> ReplyWorker:
        return ReplyWorker(
            SETTINGS,
            self.factory,
            replies=cfg or RepliesSettings(),
            gate=gate or fake_gate(),
            box=BOX,
            rules=RULES,
            mailbox_factory=lambda profile, gate, deadline: box,
        )

    async def replies(self) -> list[Any]:
        async with self.owner.connect() as conn:
            return list((await conn.execute(text("SELECT * FROM abuse_replies ORDER BY id"))).all())

    async def state(self) -> Any:
        async with self.owner.connect() as conn:
            return (await conn.execute(text("SELECT * FROM report_imap_state"))).first()

    async def outcome(self, report_id: int) -> Any:
        async with self.owner.connect() as conn:
            return (
                await conn.execute(
                    text("SELECT * FROM abuse_report_outcomes WHERE report_id = :i"),
                    {"i": report_id},
                )
            ).first()


@pytest.fixture
async def world(engine: AsyncEngine, factory: Factory) -> AsyncIterator[World]:
    api = create_engine(_role_url("API"), pool_size=2)
    w = World(engine, api, factory)
    await w.reset()
    yield w
    await api.dispose()


async def poll(world: World, box: FakeMailbox, **kw: Any) -> ReplyWorker:
    worker = world.worker(box, **kw)
    await worker.run_once()
    return worker


# ---- the gate and the cap ----------------------------------------------------------------------


async def test_a_closed_gate_attempts_nothing(world: World) -> None:
    await world.profile()
    box = FakeMailbox({1: mail()})
    await poll(world, box, gate=fake_gate(open_=False))
    assert box.log == []  # not even a client
    state = await world.state()
    assert state.last_error == "egress_closed" and state.last_poll_at is None
    assert await world.replies() == []


async def test_no_profile_and_a_paused_profile_do_nothing(world: World) -> None:
    box = FakeMailbox({1: mail()})
    worker = await poll(world, box)
    assert box.log == [] and worker.poll_state == "not_configured"
    await world.profile(enabled=False)
    worker = await poll(world, box)
    assert box.log == [] and worker.poll_state == "paused"


# ---- what is stored, what is flagged -----------------------------------------------------------


async def test_unrelated_mail_is_never_stored_or_flagged(world: World) -> None:
    await world.profile()
    await world.sent_report()
    stranger = mail(
        from_="Newsletter <news@other.example.org>", subject="Weekly digest", in_reply_to=None
    )
    box = FakeMailbox({1: stranger})
    await poll(world, box)
    assert (
        box.seen == [] and box.moved == [] and "fetch_partial" not in box.log
    )  # the body is not even fetched
    assert await world.replies() == []
    state = await world.state()
    assert (
        state.counters["ignored"] == 1 and state.counters["relevant"] == 0 and state.last_uid == 1
    )
    assert state.last_error is None and state.last_poll_at is not None


async def test_a_reply_to_our_message_is_stored_then_marked_read(world: World) -> None:
    await world.profile()
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    raw = mail(body="Hello,\r\n\r\nThe server has been suspended.\r\n")
    box = FakeMailbox({1: raw})
    await poll(world, box)
    (row,) = await world.replies()
    assert row.report_id == rid and row.match_method == "message_id" and row.verified
    assert row.classification == "resolved" and row.rule_id == "resolved-action-taken"
    assert row.source == "imap" and row.uid == 1 and row.uidvalidity == 1
    assert row.from_domain == "example.net" and "suspended" in row.excerpt
    assert row.message_id_sha256 and len(row.message_id_sha256) == 64
    assert box.seen == [1]
    # The mail itself is never stored: only metadata and the bounded excerpt.
    assert "Hello" not in "".join(str(v) for k, v in row._mapping.items() if k not in ("excerpt",))
    out = await world.outcome(rid)  # created and refreshed in the same cycle
    assert out.auto_outcome == "resolved" and out.reply_count == 1 and not out.needs_review
    assert out.resolved_at is not None and out.first_reply_at is not None
    state = await world.state()
    assert (
        state.counters["relevant"] == 1 and state.counters["matched"] == 1 and state.last_uid == 1
    )


async def test_the_reply_is_committed_before_the_flag(world: World) -> None:
    await world.profile()
    await world.sent_report("abuse@example.net", message_id=OUR_ID)

    loop = asyncio.get_running_loop()
    rows_when_marked: list[int] = []

    class Checking(FakeMailbox):
        def mark_seen(self, uid: int) -> None:  # runs in a thread: ask the test's loop
            future = asyncio.run_coroutine_threadsafe(world.replies(), loop)
            rows_when_marked.append(len(future.result(10)))
            super().mark_seen(uid)

    await poll(world, Checking({1: mail()}))
    assert rows_when_marked == [1]


async def test_a_mail_that_matches_nothing_is_not_stored_even_from_a_known_domain_with_two_reports(
    world: World,
) -> None:
    await world.profile()
    await world.sent_report("abuse@example.net")
    await world.sent_report(
        "noc@example.net", kind="c2"
    )  # two recent reports to example.net: ambiguous
    box = FakeMailbox({1: mail(in_reply_to=None, subject="Hello there")})
    await poll(world, box)
    (row,) = await world.replies()  # from a known recipient: kept for the owner to check
    assert row.report_id is None and row.match_method == "none" and not row.verified
    assert box.seen == [1]


async def test_a_token_in_the_subject_matches(world: World) -> None:
    await world.profile()
    rid, token = await world.sent_report()
    box = FakeMailbox(
        {
            1: mail(
                from_="Desk <desk@tickets.example.org>",
                in_reply_to=None,
                subject=f"Re: Abuse report (ref {token})",
            )
        }
    )
    await poll(world, box)
    (row,) = await world.replies()
    assert row.report_id == rid and row.match_method == "token"
    assert not row.verified  # a stranger's domain cannot vouch for itself


async def test_the_token_of_a_draft_matches_nothing(world: World) -> None:
    await world.profile()
    _, token = await world.sent_report(status="draft")
    box = FakeMailbox(
        {
            1: mail(
                from_="Desk <desk@other.example.org>",
                in_reply_to=None,
                subject=f"Re: (ref {token})",
            )
        }
    )
    await poll(world, box)
    assert await world.replies() == []  # relevant by the token, matched to nothing, not stored


async def test_a_forged_reply_is_stored_but_changes_nothing(world: World) -> None:
    await world.profile()
    rid, token = await world.sent_report("abuse@example.net")
    forged = mail(
        from_="Anyone <someone@evil.example.org>",
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        body="The account has been terminated. Thank you.\r\n",
    )
    await poll(world, FakeMailbox({1: forged}))
    (row,) = await world.replies()
    assert row.report_id == rid and row.classification == "resolved" and row.verified is False
    await outcome.ensure_rows(world.factory)
    await outcome.recompute(world.factory)
    out = await world.outcome(rid)
    assert out.auto_outcome == "none" and out.needs_review is True and out.resolved_at is None


async def test_authenticated_mail_from_the_recipient_is_verified(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, token = await world.sent_report("abuse@example.net")
    good = mail(
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        body="We have taken action.\r\n",
        extra={
            "Authentication-Results": "mx.example.org; dkim=pass header.d=example.net; dmarc=pass header.from=example.net"
        },
    )
    await poll(world, FakeMailbox({1: good}))
    (row,) = await world.replies()
    assert row.auth == "pass" and row.verified and row.match_method == "token"
    await outcome.ensure_rows(world.factory)
    await outcome.recompute(world.factory)
    assert (await world.outcome(rid)).auto_outcome == "resolved"


async def test_a_bounce_is_stored_and_needs_review(world: World) -> None:
    await world.profile()
    rid, _ = await world.sent_report(message_id=OUR_ID)
    await poll(world, FakeMailbox({1: mails.dsn()}))
    (row,) = await world.replies()
    assert row.classification == "bounce" and row.report_id == rid and row.dsn_status == "5.1.1"
    await outcome.ensure_rows(world.factory)
    await outcome.recompute(world.factory)
    out = await world.outcome(rid)
    # Quoting our Message-ID proves nothing about the sender: an unauthenticated bounce from a
    # mail system we never wrote to waits for the owner and sets no date.
    assert not row.verified
    assert out.auto_outcome == "none" and out.needs_review and out.bounced_at is None


async def test_an_unmatched_dsn_is_kept_for_the_owner(world: World) -> None:
    await world.profile()
    await poll(world, FakeMailbox({1: mails.dsn(original_id="<unknown@example.org>")}))
    (row,) = await world.replies()
    assert row.report_id is None and row.classification == "bounce"


async def test_a_ticket_number_links_a_later_reply(world: World) -> None:
    await world.profile()
    rid, token = await world.sent_report("abuse@example.net")
    first = mail(
        in_reply_to=None,
        subject=f"[#48213] We received your report (ref {token})",
        extra={"Auto-Submitted": "auto-replied"},
        body="Your ticket has been created.\r\n",
    )
    follow_up = mail(
        message_id="<later@example.net>",
        in_reply_to=None,
        subject="Update on case",
        from_="Desk <desk@example.net>",
        body="Ticket #48213: the customer was contacted.\r\n",
    )
    box = FakeMailbox({1: first, 2: follow_up})
    await poll(world, box)
    rows = await world.replies()
    assert [r.report_id for r in rows] == [rid, rid]
    assert rows[0].classification == "ticket_opened" and rows[0].ticket_id == "48213"
    assert rows[1].match_method in ("ticket", "sender_domain")


# ---- moving, caps, renumbering -----------------------------------------------------------------


async def test_move_without_the_capability_marks_read_and_remembers(world: World) -> None:
    await world.profile(action="move", move_folder="Done")
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    box = FakeMailbox({1: mail()}, move_supported=False)
    await poll(world, box)
    assert box.moved == [] and box.seen == [1]
    assert (await world.state()).move_supported is False


async def test_move_with_the_capability(world: World) -> None:
    await world.profile(action="move", move_folder="Done")
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    box = FakeMailbox({1: mail()})
    await poll(world, box)
    assert box.moved == [(1, "Done")] and box.seen == []
    assert (await world.state()).move_supported is True


async def test_a_failed_flag_keeps_the_reply(world: World) -> None:
    await world.profile()
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    box = FakeMailbox({1: mail()}, fail={"mark_seen": "protocol"})
    await poll(world, box)
    assert len(await world.replies()) == 1
    assert (await world.state()).last_error == "protocol"


async def test_login_failure_is_a_constant_code(world: World) -> None:
    await world.profile()
    box = FakeMailbox({1: mail()}, fail={"login": "auth_failed"})
    await poll(world, box)
    state = await world.state()
    assert state.last_error == "auth_failed" and state.last_poll_at is not None
    assert "logout" in box.log  # always


async def test_a_new_uidvalidity_starts_over(world: World) -> None:
    await world.profile()
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    box = FakeMailbox({1: mail(message_id="<a@example.net>")}, uidvalidity=1)
    worker = await poll(world, box)
    assert (await world.state()).last_uid == 1
    # The server renumbers the folder: the same UID now names another mail.
    box.uidvalidity = 2
    box.messages = {1: mail(message_id="<b@example.net>")}
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE report_imap_state SET last_poll_at = now() - interval '1 hour'")
        )
    await worker.run_once()
    rows = await world.replies()
    assert [(r.uidvalidity, r.uid) for r in rows] == [(1, 1), (2, 1)]
    assert (await world.state()).uidvalidity == 2


async def test_another_mailbox_resets_the_position(world: World) -> None:
    await world.profile()
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_imap_state (id, profile_fingerprint, uidvalidity, last_uid) VALUES (1, :f, 1, 99)"
            ),
            {"f": "0" * 64},
        )
    box = FakeMailbox({1: mail()})
    await poll(world, box)
    assert len(await world.replies()) == 1  # UID 1 was read although last_uid said 99
    state = await world.state()
    assert state.last_uid == 1 and state.profile_fingerprint != "0" * 64


async def test_the_daily_cap_defers_the_rest(world: World) -> None:
    await world.profile()
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    messages = {n: mail(message_id=f"<m{n}@example.net>") for n in (1, 2, 3)}
    box = FakeMailbox(messages)
    cfg = RepliesSettings(daily_cap=2, max_per_poll=50)
    worker = await poll(world, box, cfg=cfg)
    assert len(await world.replies()) == 2 and (await world.state()).counters["fetched"] == 2
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE report_imap_state SET last_poll_at = now() - interval '1 hour'")
        )
    await worker.run_once()
    assert len(await world.replies()) == 2  # the cap holds for the rest of the UTC day


async def test_at_most_max_per_poll(world: World) -> None:
    await world.profile()
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    box = FakeMailbox({n: mail(message_id=f"<m{n}@example.net>") for n in range(1, 8)})
    await poll(world, box, cfg=RepliesSettings(max_per_poll=3))
    assert len(await world.replies()) == 3 and (await world.state()).last_uid == 3


async def test_a_poll_waits_for_its_interval(world: World) -> None:
    await world.profile()
    box = FakeMailbox({})
    worker = await poll(world, box)
    first = len(box.log)
    await worker.run_once()
    assert len(box.log) == first  # fifteen minutes have not passed


# ---- pasted replies and requests ---------------------------------------------------------------


async def test_a_pasted_reply_needs_no_mailbox(world: World) -> None:
    rid, token = await world.sent_report("abuse@example.net")
    raw = mail(
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        body="The account has been suspended.\r\n",
        from_="Desk <desk@gmail.example.com>",
    )
    async with world.api.begin() as conn:
        pid = await conn.scalar(
            text(
                "INSERT INTO abuse_reply_imports (raw, requested_by) VALUES (:r, 'admin') RETURNING id"
            ),
            {"r": raw},
        )
    box = FakeMailbox({})
    await poll(world, box)
    assert box.log == []  # no mailbox was touched
    (row,) = await world.replies()
    assert (
        row.source == "paste"
        and row.report_id == rid
        and row.verified
        and row.reviewed_by == "admin"
    )
    async with world.owner.connect() as conn:
        imp = (
            await conn.execute(text("SELECT * FROM abuse_reply_imports WHERE id = :i"), {"i": pid})
        ).one()
    assert imp.status == "done" and bytes(imp.raw) == b"" and imp.reply_id == row.id
    out = await world.outcome(rid)
    assert out is not None and out.auto_outcome == "resolved"


async def test_a_pasted_reply_with_the_owners_hint(world: World) -> None:
    rid, _ = await world.sent_report()
    async with world.api.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_reply_imports (raw, report_id, requested_by) VALUES (:r, :i, 'admin')"
            ),
            {"r": b"Subject: hi\r\n\r\nPlease use our web form.\r\n", "i": rid},
        )
    await poll(world, FakeMailbox({}))
    (row,) = await world.replies()
    assert (
        row.report_id == rid and row.match_method == "manual" and row.classification == "rejected"
    )


async def test_a_pasted_duplicate_fails_cleanly(world: World) -> None:
    await world.sent_report("abuse@example.net", message_id=OUR_ID)
    raw = mail()
    async with world.api.begin() as conn:
        for _ in range(2):
            await conn.execute(
                text("INSERT INTO abuse_reply_imports (raw, requested_by) VALUES (:r, 'admin')"),
                {"r": raw},
            )
    await poll(world, FakeMailbox({}))
    async with world.owner.connect() as conn:
        statuses = [
            r.status
            for r in (
                await conn.execute(
                    text("SELECT status, error_code FROM abuse_reply_imports ORDER BY id")
                )
            ).all()
        ]
    assert statuses == ["done", "failed"]


async def test_test_and_poll_requests_are_answered(world: World) -> None:
    await world.profile()
    async with world.api.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_imap_requests (kind, requested_by) VALUES ('test', 'admin'), ('poll', 'admin')"
            )
        )
    box = FakeMailbox({})
    await poll(world, box)
    async with world.owner.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT kind, status, error_code, result FROM report_imap_requests ORDER BY id"
                )
            )
        ).all()
    assert [r.status for r in rows] == ["done", "done"]
    assert rows[0].result["ok"] is True and rows[0].result["folders"] == ["INBOX", "Done"]
    assert rows[1].result["ok"] is True


async def test_requests_fail_with_a_code_when_the_gate_is_closed_or_nothing_is_saved(
    world: World,
) -> None:
    async with world.api.begin() as conn:
        await conn.execute(
            text("INSERT INTO report_imap_requests (kind, requested_by) VALUES ('test', 'admin')")
        )
    await poll(world, FakeMailbox({}))
    async with world.owner.connect() as conn:
        row = (
            await conn.execute(text("SELECT status, error_code FROM report_imap_requests"))
        ).one()
    assert (row.status, row.error_code) == ("failed", "not_configured")
    await world.profile()
    async with world.api.begin() as conn:
        await conn.execute(
            text("INSERT INTO report_imap_requests (kind, requested_by) VALUES ('poll', 'admin')")
        )
    box = FakeMailbox({})
    await poll(world, box, gate=fake_gate(open_=False))
    async with world.owner.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT status, error_code FROM report_imap_requests WHERE kind = 'poll'")
            )
        ).one()
    assert (row.status, row.error_code) == ("failed", "egress_closed") and box.log == []


async def test_a_mailbox_test_reports_a_missing_move_folder(world: World) -> None:
    await world.profile(action="move", move_folder="Nowhere")
    async with world.api.begin() as conn:
        await conn.execute(
            text("INSERT INTO report_imap_requests (kind, requested_by) VALUES ('test', 'admin')")
        )
    await poll(world, FakeMailbox({}))
    async with world.owner.connect() as conn:
        row = (
            await conn.execute(text("SELECT status, error_code, result FROM report_imap_requests"))
        ).one()
    assert row.error_code == "no_move_folder" and row.result["folders"] == ["INBOX", "Done"]


async def test_the_profile_lock_is_held_shared_during_a_poll(world: World) -> None:
    """The API takes the same key exclusively (with a timeout) to change the profile."""
    from suckerpot_db.locks import ABUSE_IMAP_PROFILE

    await world.profile()
    seen: list[bool] = []
    loop = asyncio.get_running_loop()

    async def try_exclusive() -> bool:
        async with world.owner.begin() as conn:
            got = await conn.scalar(
                text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": ABUSE_IMAP_PROFILE}
            )
        return bool(got)

    class Probe(FakeMailbox):
        def select(self, folder: str, *, readonly: bool = False) -> Selected:  # in a thread
            seen.append(asyncio.run_coroutine_threadsafe(try_exclusive(), loop).result(10))
            return super().select(folder, readonly=readonly)

    await poll(world, Probe({}))
    assert seen == [False]  # an exclusive lock could not be taken while the poll ran


def test_the_fingerprint_changes_with_the_mailbox() -> None:
    base = ImapProfile(
        "h.example.org", 993, "ssl", "u", "INBOX", "mark_read", None, 15, date(2026, 1, 1)
    )
    other = ImapProfile(
        "h.example.org", 993, "ssl", "u", "Abuse", "mark_read", None, 15, date(2026, 1, 1)
    )
    assert fingerprint(base) != fingerprint(other) and len(fingerprint(base)) == 64
    assert fingerprint(base) == fingerprint(
        ImapProfile("h.example.org", 993, "ssl", "u", "INBOX", "move", "Done", 30, date(2026, 5, 5))
    )


# ---- poison pills and forged replies (security review of M26/M27) -----------------------------


async def test_a_mail_that_breaks_a_column_does_not_stop_the_ones_behind_it(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.exc import IntegrityError

    from ingest.replies import store as store_module

    await world.profile()
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    real = store_module.store_reply

    async def flaky(session: AsyncSession, rules: Any, parsed: Any, **kw: Any) -> Any:
        if kw.get("uid") == 1:
            raise IntegrityError("INSERT", {}, Exception("check constraint"))
        return await real(session, rules, parsed, **kw)

    monkeypatch.setattr("ingest.replies.worker.store_reply", flaky)
    box = FakeMailbox({1: mail(message_id="<poison@example.net>"), 2: mail()})
    await poll(world, box)
    (row,) = await world.replies()
    assert row.uid == 2 and row.report_id == rid  # the valid reply behind the poison was stored
    state = await world.state()
    assert state.last_uid == 2 and state.last_error is None
    assert state.counters["failed"] == 1


async def test_a_database_outage_is_still_fatal_and_keeps_the_position(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.exc import OperationalError

    await world.profile()
    await world.sent_report("abuse@example.net", message_id=OUR_ID)

    async def down(*a: Any, **kw: Any) -> Any:
        raise OperationalError("INSERT", {}, Exception("connection lost"))

    monkeypatch.setattr("ingest.replies.worker.store_reply", down)
    await poll(world, FakeMailbox({1: mail()}))
    state = await world.state()
    assert state.last_uid == 0 and state.last_error == "internal"  # retried next poll


async def test_an_overlong_sender_domain_is_harmless(world: World) -> None:
    await world.profile()
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    long_domain = ".".join(["a" * 60] * 5) + ".example.net"
    poison = mail(from_=f"postmaster@{long_domain}", message_id="<poison@example.net>")
    await poll(world, FakeMailbox({1: poison, 2: mail()}))
    replies = await world.replies()
    assert [r.uid for r in replies if r.report_id == rid] == [1, 2]
    assert replies[0].from_domain is None and replies[0].verified is False
    state = await world.state()
    assert state.last_uid == 2 and state.last_error is None


async def test_many_parts_with_long_non_ascii_types_are_stored(world: World) -> None:
    await world.profile()
    _, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    parts = [("text/plain; charset=utf-8", "", b"The server was suspended.")]
    parts += [(f"application/{'\u00e9' * 90}{i}", "", b"x") for i in range(12)]
    raw = mails.multipart(parts)
    await poll(world, FakeMailbox({1: raw, 2: mail(message_id="<next@example.net>")}))
    stored = await world.replies()
    assert {r.uid for r in stored} == {1, 2}
    assert all(len(str(r.attachments)) <= 2048 for r in stored)


async def test_quoting_our_message_id_from_a_stranger_verifies_nothing(world: World) -> None:
    await world.profile()
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    forged = mail(
        from_="Anyone <someone@evil.example.org>",
        body="The account was terminated.\r\n",
        message_id="<forged@evil.example.org>",
    )
    await poll(world, FakeMailbox({1: forged}))
    (row,) = await world.replies()
    assert row.report_id == rid and row.match_method == "message_id" and row.verified is False
    await outcome.ensure_rows(world.factory)
    await outcome.recompute(world.factory)
    out = await world.outcome(rid)
    assert out.auto_outcome == "none" and out.needs_review and out.resolved_at is None


async def test_a_forged_authentication_results_header_does_not_verify(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    _, token = await world.sent_report("abuse@example.net")
    forged = mail(
        from_="Anyone <someone@example.net>",
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        extra={"Authentication-Results": "attacker; dmarc=pass header.from=example.net"},
    )
    await poll(world, FakeMailbox({1: forged}))
    (row,) = await world.replies()
    assert row.auth == "none" and row.verified is False


async def test_no_trusted_authserv_id_means_no_mail_is_authenticated(world: World) -> None:
    await world.profile()  # nothing trusted
    _, token = await world.sent_report("abuse@example.net")
    good = mail(
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        extra={"Authentication-Results": "mx.example.org; dmarc=pass header.from=example.net"},
    )
    await poll(world, FakeMailbox({1: good}))
    (row,) = await world.replies()
    assert row.auth == "none" and row.verified is False


async def test_a_bounce_verifies_with_authentication_or_from_a_domain_we_wrote_to(
    world: World,
) -> None:
    await world.profile(trusted="mx.example.org")
    _, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    authed = mails.dsn(
        extra={"Authentication-Results": "mx.example.org; dmarc=pass header.from=example.org"}
    )
    await poll(world, FakeMailbox({1: authed}))
    (row,) = await world.replies()
    assert row.classification == "bounce" and row.auth == "pass" and row.verified


async def test_subdomains_do_not_inherit_trust(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, token = await world.sent_report("abuse@zendesk.example.net")
    mailbox = mail(
        from_="Desk <acme@acme.zendesk.example.net>",
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        extra={
            "Authentication-Results": "mx.example.org; dmarc=pass header.from=acme.zendesk.example.net"
        },
    )
    await poll(world, FakeMailbox({1: mailbox}))
    (row,) = await world.replies()
    assert row.report_id == rid and row.auth == "pass" and row.verified is False


async def test_a_listed_reply_domain_is_trusted_exactly(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    _, token = await world.sent_report(
        "abuse@zendesk.example.net", reply_domains=["acme.zendesk.example.net"]
    )
    mailbox = mail(
        from_="Desk <acme@acme.zendesk.example.net>",
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        extra={
            "Authentication-Results": "mx.example.org; dmarc=pass header.from=acme.zendesk.example.net"
        },
    )
    await poll(world, FakeMailbox({1: mailbox}))
    (row,) = await world.replies()
    assert row.verified is True


async def test_a_free_mail_recipient_makes_no_domain_relevant(world: World) -> None:
    await world.profile()
    await world.sent_report("abuse-desk@gmail.com")
    stranger = mail(from_="Someone <random.person@gmail.com>", in_reply_to=None, subject="Hi")
    box = FakeMailbox({1: stranger})
    await poll(world, box)
    assert await world.replies() == []
    assert "fetch_partial" not in box.log  # the body was not even fetched
    state = await world.state()
    assert state.counters["ignored"] == 1 and state.counters["relevant"] == 0


async def test_a_free_mail_recipient_is_trusted_by_exact_address_only(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, token = await world.sent_report("abuse-desk@gmail.com")
    auth = "mx.example.org; dmarc=pass header.from=gmail.com"
    other = mail(
        from_="Someone <random.person@gmail.com>",
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        extra={"Authentication-Results": auth},
        message_id="<other@gmail.com>",
    )
    exact = mail(
        from_="Desk <abuse-desk@gmail.com>",
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        extra={"Authentication-Results": auth},
        message_id="<exact@gmail.com>",
    )
    await poll(world, FakeMailbox({1: other, 2: exact}))
    by_uid = {r.uid: r for r in await world.replies()}
    assert by_uid[1].report_id == rid and by_uid[1].verified is False
    assert by_uid[2].report_id == rid and by_uid[2].verified is True


async def test_a_reply_that_changed_is_recomputed_even_behind_500_older_reports(
    world: World,
) -> None:
    """Candidates are the reports whose replies changed, least recently computed first."""
    await world.profile()
    rid, token = await world.sent_report("abuse@example.net")
    await outcome.ensure_rows(world.factory)
    await outcome.recompute(world.factory)
    assert (await world.outcome(rid)).reply_count == 0
    mailbox = mail(in_reply_to=None, subject=f"Re: report (ref {token})", body="Done, suspended.")
    await poll(world, FakeMailbox({1: mailbox}))
    assert (await world.outcome(rid)).reply_count == 1
    # Nothing changed since: the next cycle has no candidate left.
    assert await outcome.recompute(world.factory) == 0
    async with world.owner.connect() as conn:
        left = await conn.scalar(
            text(
                "SELECT count(*) FROM abuse_report_outcomes o WHERE EXISTS (SELECT 1 FROM "
                "abuse_replies p WHERE p.report_id = o.report_id AND p.processed_at > "
                "o.auto_updated_at)"
            )
        )
    assert left == 0


async def test_one_failing_pasted_reply_does_not_block_the_next(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ingest.replies import parse as parse_module

    _, token = await world.sent_report("abuse@example.net")
    good = mail(in_reply_to=None, subject=f"Re: report (ref {token})", body="Suspended.\r\n")
    async with world.api.begin() as conn:
        for raw in (b"first", good):
            await conn.execute(
                text("INSERT INTO abuse_reply_imports (raw, requested_by) VALUES (:r, 'admin')"),
                {"r": raw},
            )
    real = parse_module.parse_message
    calls = {"n": 0}

    def boom(raw: bytes, **kw: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("parser bug")
        return real(raw, **kw)

    monkeypatch.setattr("ingest.replies.worker.parse_message", boom)
    await poll(world, FakeMailbox({}))
    async with world.owner.connect() as conn:
        status = [
            r[0]
            for r in await conn.execute(text("SELECT status FROM abuse_reply_imports ORDER BY id"))
        ]
    assert status == ["failed", "done"]


AUTHED = {
    "Authentication-Results": "mx.example.org; dkim=pass header.d=example.net; dmarc=pass header.from=example.net"
}


async def _desk(world: World, rid: int) -> Any:
    async with world.owner.connect() as conn:
        return (
            await conn.execute(
                text(
                    "SELECT rec.form_only, rec.form_url, rec.undeliverable, rec.hard_bounces "
                    "FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                    "WHERE r.id = :i"
                ),
                {"i": rid},
            )
        ).one()


async def test_a_verified_web_form_reply_marks_the_desk_form_only(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, token = await world.sent_report("abuse@example.net")
    reply = mail(
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        body=(
            "Reports sent to this email address will not be processed.\r\n"
            "Please submit your report using webform at https://support.example.net/abuse/new.\r\n"
        ),
        extra=AUTHED,
    )
    await poll(world, FakeMailbox({1: reply}))
    (row,) = await world.replies()
    assert row.classification == "rejected" and row.rule_id == "form-required" and row.verified
    desk = await _desk(world, rid)
    assert desk.form_only is True and desk.form_url == "https://support.example.net/abuse/new"


async def test_a_matched_reply_nobody_vouched_for_still_marks_the_desk(world: World) -> None:
    await world.profile()
    rid, token = await world.sent_report("abuse@example.net")
    unvouched = mail(
        from_="Someone <x@example.com>",
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        body="This email inbox is not monitored. Use https://support.example.com/f\r\n",
    )
    await poll(world, FakeMailbox({1: unvouched}))
    (row,) = await world.replies()
    assert row.classification == "rejected" and not row.verified and row.report_id == rid
    desk = await _desk(world, rid)
    # The link of a reply nobody vouched for is never kept: it could be an attacker's.
    assert desk.form_only is True and desk.form_url is None


async def test_an_unmatched_reply_never_marks_a_desk(world: World) -> None:
    await world.profile()
    rid, _ = await world.sent_report("abuse@example.net")
    stranger = mail(
        from_="Stranger <x@example.com>",
        in_reply_to=None,
        subject="Re: something else",
        body="This email inbox is not monitored.\r\n",
    )
    await poll(world, FakeMailbox({1: stranger}))
    desk = await _desk(world, rid)
    assert desk.form_only is False


async def test_a_form_reply_without_a_link_still_marks_the_desk(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, token = await world.sent_report("abuse@example.net")
    reply = mail(
        in_reply_to=None,
        subject=f"Re: report (ref {token})",
        body="This email inbox is not monitored.\r\n",
        extra=AUTHED,
    )
    await poll(world, FakeMailbox({1: reply}))
    desk = await _desk(world, rid)
    assert desk.form_only is True and desk.form_url is None


def _bounce(n: int, status: str) -> bytes:
    return mails.dsn(
        status=status,
        extra={
            "Message-ID": f"<bounce-{n}@mx.example.org>",
            "Authentication-Results": "mx.example.org; dmarc=pass header.from=example.org",
        },
    )


async def test_one_user_unknown_bounce_makes_the_address_undeliverable(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    await poll(world, FakeMailbox({1: _bounce(1, "5.1.1")}))
    desk = await _desk(world, rid)
    assert desk.undeliverable is True and desk.hard_bounces == 1


async def test_other_hard_bounces_need_two(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    await poll(world, FakeMailbox({1: _bounce(1, "5.7.1")}))
    desk = await _desk(world, rid)
    assert desk.undeliverable is False and desk.hard_bounces == 1
    # Both again in one later poll (a poll waits for its interval): the second one is the 2nd.
    async with world.owner.begin() as conn:
        await conn.execute(text("DELETE FROM report_imap_state"))
    await poll(world, FakeMailbox({2: _bounce(2, "5.7.1")}))
    desk = await _desk(world, rid)
    assert desk.undeliverable is True and desk.hard_bounces == 2


async def test_a_soft_bounce_counts_for_nothing_and_an_unauthenticated_hard_one_counts(
    world: World,
) -> None:
    await world.profile(trusted="mx.example.org")
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    soft = mails.dsn(status="4.2.2", extra={"Message-ID": "<soft@mx.example.org>"})
    plain = mails.dsn(status="5.1.1", extra={"Message-ID": "<plain@mx.example.org>"})
    await poll(world, FakeMailbox({1: soft, 2: plain}))
    desk = await _desk(world, rid)
    assert desk.undeliverable is True and desk.hard_bounces == 1  # only the hard one counted


async def test_a_delayed_notice_is_not_stored(world: World) -> None:
    await world.profile(trusted="mx.example.org")
    rid, _ = await world.sent_report("abuse@example.net", message_id=OUR_ID)
    delayed = mails.dsn(action="delayed", status="4.4.1", extra={"Auto-Submitted": "auto-replied"})
    await poll(world, FakeMailbox({1: delayed}))
    assert await world.replies() == []
    await outcome.ensure_rows(world.factory)
    await outcome.recompute(world.factory)
    assert (await world.outcome(rid)).auto_outcome == "none"


async def test_the_form_link_needs_a_verified_reply_on_the_providers_own_domain(
    world: World,
) -> None:
    await world.profile(trusted="mx.example.org")
    rid, token = await world.sent_report("abuse@example.net")
    off = mail(
        in_reply_to=None,
        message_id="<f1@example.net>",
        subject=f"Re: report (ref {token})",
        body="Please submit your report using webform at https://evil.example.com/f.\r\n",
        extra=AUTHED,
    )
    await poll(world, FakeMailbox({1: off}))
    desk = await _desk(world, rid)
    assert desk.form_only is True and desk.form_url is None  # off-domain: ignored
    async with world.owner.begin() as conn:
        await conn.execute(text("DELETE FROM report_imap_state"))
    first = mail(
        in_reply_to=None,
        message_id="<f2@example.net>",
        subject=f"Re: report (ref {token})",
        body="Please submit your report using webform at https://help.example.net/one.\r\n",
        extra=AUTHED,
    )
    await poll(world, FakeMailbox({2: first}))
    assert (await _desk(world, rid)).form_url == "https://help.example.net/one"
    async with world.owner.begin() as conn:
        await conn.execute(text("DELETE FROM report_imap_state"))
    second = mail(
        in_reply_to=None,
        message_id="<f3@example.net>",
        subject=f"Re: report (ref {token})",
        body="Please submit your report using webform at https://help.example.net/two.\r\n",
        extra=AUTHED,
    )
    await poll(world, FakeMailbox({3: second}))
    assert (await _desk(world, rid)).form_url == "https://help.example.net/one"  # kept


async def test_an_acknowledgement_that_says_not_monitored_does_not_pause_the_desk(
    world: World,
) -> None:
    await world.profile(trusted="mx.example.org")
    rid, token = await world.sent_report("abuse@example.net")
    ack = mail(
        in_reply_to=None,
        subject=f"[#123] Re: report (ref {token})",
        extra={**AUTHED, "Auto-Submitted": "auto-replied"},
        body="This mailbox is not monitored, ticket #123 created.\r\n",
    )
    await poll(world, FakeMailbox({1: ack}))
    (row,) = await world.replies()
    assert row.classification == "auto_ack"
    assert (await _desk(world, rid)).form_only is False
