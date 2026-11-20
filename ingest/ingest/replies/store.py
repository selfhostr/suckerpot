"""Relevance from headers, then matching, classifying and storing one reply (design M26, 4.3).

Mail unrelated to a report is never stored and never flagged (O4): the body is fetched only
after the headers show a link to a report or a delivery status notification, and a mail that
matches nothing is stored only if it is such a notification or comes from a known recipient.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .desk import learn
from .match import (
    Match,
    RecentReport,
    Trust,
    by_message_id,
    by_token,
    find_match,
    find_tokens,
    from_known_recipient,
    is_verified,
    report_trust,
)
from .parse import HeaderView, ParsedReply
from .rules import ReplyRules

DELAYED_RULE = "delayed-dsn"
INSERT_REPLY = """
INSERT INTO abuse_replies (source, uidvalidity, uid, message_id_sha256, received_at, date_header,
    from_address, from_domain, subject, auth, report_id, match_method, verified, classification,
    classification_source, rule_id, ticket_id, dsn_status, size_bytes, truncated, attachments,
    excerpt, reviewed_at, reviewed_by)
VALUES (:source, :uidvalidity, :uid, :mid, :received, :sent, :from_address, :from_domain,
    :subject, :auth, :report_id, :method, :verified, :classification, 'rule', :rule_id, :ticket,
    :dsn_status, :size, :truncated, CAST(:attachments AS jsonb), :excerpt, :reviewed_at,
    :reviewed_by)
ON CONFLICT DO NOTHING
RETURNING id
"""


@dataclass(frozen=True, slots=True)
class Stored:
    status: str  # stored | duplicate | dropped | not_sent
    reply_id: int | None = None
    report_id: int | None = None
    matched: bool = False


async def is_relevant(session: AsyncSession, view: HeaderView, recent: list[RecentReport]) -> bool:
    """From the headers alone: does this mail link to a report, look like a delivery status
    notification, or come from a recipient we wrote to?"""
    if view.looks_like_dsn or _known(view, recent):
        return True
    if await by_message_id(session, view.reference_ids) is not None:
        return True
    rid, seen = await by_token(session, find_tokens(view.subject))
    return rid is not None or seen


def _known(view: HeaderView, recent: list[RecentReport]) -> bool:
    return from_known_recipient(
        ParsedReply(from_address=view.from_address, from_domain=view.from_domain),
        recent,  # only the sender is read
    )


def _is_dsn(reply: ParsedReply) -> bool:
    return (
        reply.content_type == "multipart/report"
        or reply.from_local in ("mailer-daemon", "postmaster")
        or reply.dsn_action is not None
    )


async def store_reply(
    session: AsyncSession,
    rules: ReplyRules,
    reply: ParsedReply,
    *,
    source: str,
    received_at: datetime,
    recent: list[RecentReport],
    uidvalidity: int | None = None,
    uid: int | None = None,
    hint_report_id: int | None = None,
    owner: str | None = None,
) -> Stored:
    """Match, classify and insert, inside the caller's transaction.

    ``source='paste'`` is the owner's own act: the reply is stored even when nothing matches,
    a report hint from the owner links it, and a linked reply counts as confirmed by them."""
    ticket = rules.extract_ticket(reply)
    found = await find_match(session, reply, ticket=ticket, recent=recent)
    if found.report_id is None and hint_report_id is not None:
        found = Match(hint_report_id, "manual")
    if found.report_id is None and source == "imap":
        if not (_is_dsn(reply) or from_known_recipient(reply, recent)):
            return Stored("dropped")
    if found.report_id is not None and found.method == "manual":
        state = (
            await session.execute(
                text("SELECT status FROM abuse_reports WHERE id = :i"), {"i": found.report_id}
            )
        ).first()
        if state is None or state.status not in ("sent", "closed"):
            return Stored("not_sent")
    verdict = rules.classify(reply, matched=found.report_id is not None)
    if verdict.rule_id == DELAYED_RULE and source == "imap":
        return Stored("dropped")  # still being retried: no answer, no bounce, nothing to keep
    trust = await report_trust(session, found.report_id) if found.report_id is not None else Trust()
    by_owner = source == "paste" and found.report_id is not None
    verified = by_owner or is_verified(found, reply, trust, verdict.outcome)
    row = (
        await session.execute(
            text(INSERT_REPLY),
            {
                "source": source,
                "uidvalidity": uidvalidity,
                "uid": uid,
                "mid": reply.message_id_sha256,
                "received": received_at,
                "sent": reply.sent_at,
                "from_address": reply.from_address,
                "from_domain": reply.from_domain,
                "subject": reply.subject or None,
                "auth": reply.auth,
                "report_id": found.report_id,
                "method": found.method,
                "verified": verified,
                "classification": verdict.outcome,
                "rule_id": verdict.rule_id,
                "ticket": verdict.ticket_id,
                "dsn_status": reply.dsn_status,
                "size": reply.size_bytes,
                "truncated": reply.truncated,
                "attachments": json.dumps(reply.attachments),
                "excerpt": reply.excerpt or None,
                "reviewed_at": received_at if by_owner else None,
                "reviewed_by": (owner or "")[:120] or None if by_owner else None,
            },
        )
    ).first()
    if row is None:
        return Stored("duplicate")
    await learn(
        session,
        reply,
        report_id=found.report_id,
        outcome=verdict.outcome,
        rule_id=verdict.rule_id,
    )
    return Stored("stored", int(row.id), found.report_id, found.report_id is not None)
