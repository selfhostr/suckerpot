"""Which report does a reply belong to, and can we vouch for it (design M26, section 7).

First hit wins: our own Message-ID, the reply token, the XARF ``report_id`` of one source (M38),
a delivery status notification that returns one of those, a ticket id we have seen from the same
sender, and last the sender's domain (only when exactly one recent report went to that domain).
The answer to "may this reply change an outcome" is separate: ``is_verified``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.shared_mail import is_shared_domain

from .parse import BODY_FOR_RULES, ParsedReply

# A token comes right after "ref", "ref:", "ref#" or "(ref". Bounded text, no nested repeats.
TOKEN: Final = re.compile(r"(?<![a-z0-9])ref[ :#]{0,3}([0-9a-f]{12})(?![0-9a-z])")
# The XARF report id of one source (a UUID v4), as a desk quotes it.
XARF_ID: Final = re.compile(
    r"(?<![0-9a-f])([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?![0-9a-f])"
)
MAX_TOKENS: Final = 5
MAX_RECENT: Final = 5000
METHODS: Final = (
    "message_id",
    "token",
    "xarf_id",
    "dsn",
    "ticket",
    "sender_domain",
    "manual",
    "none",
)

SubjectKey = tuple[str, str, str]  # (kind, subject_type, value)


@dataclass(frozen=True, slots=True)
class Match:
    report_id: int | None
    method: str = "none"
    via_message_id: bool = False
    subject: SubjectKey | None = None  # the one source an ``xarf_id`` match names


@dataclass(frozen=True, slots=True)
class Trust:
    """Who may speak for the recipient of a report. Domains are compared exactly (a subdomain is
    another party). A shared or free mail domain never counts as a domain: only the exact
    address of a mailbox on it does."""

    domains: frozenset[str] = frozenset()
    addresses: frozenset[str] = frozenset()

    def covers(self, address: str | None, domain: str | None) -> bool:
        d = (domain or "").lower()
        if address and address.lower() in self.addresses:
            return True
        return bool(d) and d in self.domains and not is_shared_domain(d)


@dataclass(frozen=True, slots=True)
class RecentReport:
    id: int
    trust: Trust


NO_MATCH: Final = Match(None, "none")


def trust_of(*mailboxes: str | None, extra: Iterable[str] = ()) -> Trust:
    """The trust of a recipient: the domain of each mailbox (the exact address when the domain
    is shared) and the owner's reply domains (an entry with ``@`` is an exact address)."""
    domains: set[str] = set()
    addresses: set[str] = set()
    for value in mailboxes:
        if not value or not value.strip():
            continue
        address = value.strip().lower()
        domain = address.rpartition("@")[2]
        if "@" in address and is_shared_domain(domain):
            addresses.add(address)
        elif domain:
            domains.add(domain.strip("."))
    for entry in extra:
        item = (entry or "").strip().lower()
        if "@" in item:
            addresses.add(item)
        elif item and not is_shared_domain(item):
            domains.add(item.strip("."))
    return Trust(frozenset(domains), frozenset(addresses))


def find_tokens(*texts: str) -> list[str]:
    """Reply tokens named in the texts, in order, at most five."""
    found: list[str] = []
    for value in texts:
        for token in TOKEN.findall(value[:BODY_FOR_RULES].lower()):
            if token not in found:
                found.append(token)
    return found[:MAX_TOKENS]


def find_xarf_ids(*texts: str) -> list[str]:
    """XARF report ids named in the texts, in order, at most five."""
    found: list[str] = []
    for value in texts:
        for xid in XARF_ID.findall(value[:BODY_FOR_RULES].lower()):
            if xid not in found:
                found.append(xid)
    return found[:MAX_TOKENS]


async def by_xarf_id(
    session: AsyncSession, ids: list[str]
) -> tuple[int | None, SubjectKey | None, bool]:
    """``(report id, the source, an id was found at all)``. Only a sent or closed report counts,
    like a reply token."""
    if not ids:
        return None, None, False
    rows = (
        await session.execute(
            text(
                "SELECT s.report_id, s.kind, s.subject_type, s.value, r.status "
                "FROM abuse_report_subjects s JOIN abuse_reports r ON r.id = s.report_id "
                "WHERE s.xarf_id = ANY(CAST(:ids AS uuid[])) ORDER BY s.report_id"
            ),
            {"ids": ids},
        )
    ).all()
    for row in rows:
        if row.status in ("sent", "closed"):
            return int(row.report_id), (row.kind, row.subject_type, row.value), True
    return None, None, bool(rows)


async def recent_reports(session: AsyncSession, days: int) -> list[RecentReport]:
    """Reports sent in the last ``days`` days with the domains their recipient can answer from."""
    rows = (
        await session.execute(
            text(
                "SELECT r.id, rec.mailbox, rec.override_mailbox, rec.reply_domains "
                "FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                "WHERE r.status IN ('sent', 'closed') AND NOT r.demo "
                "AND r.sent_at >= now() - make_interval(days => :d) "
                "ORDER BY r.id DESC LIMIT :n"
            ),
            {"d": days, "n": MAX_RECENT},
        )
    ).all()
    return [
        RecentReport(r.id, trust_of(r.mailbox, r.override_mailbox, extra=r.reply_domains or ()))
        for r in rows
    ]


async def report_trust(session: AsyncSession, report_id: int) -> Trust:
    row = (
        await session.execute(
            text(
                "SELECT rec.mailbox, rec.override_mailbox, rec.reply_domains "
                "FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                "WHERE r.id = :i"
            ),
            {"i": report_id},
        )
    ).first()
    if row is None:
        return Trust()
    return trust_of(row.mailbox, row.override_mailbox, extra=row.reply_domains or ())


async def by_message_id(session: AsyncSession, ids: tuple[str, ...]) -> int | None:
    if not ids:
        return None
    row = (
        await session.execute(
            text(
                "SELECT report_id FROM abuse_send_requests WHERE message_id = ANY(:ids) "
                "AND status = 'sent' AND report_id IS NOT NULL ORDER BY id LIMIT 1"
            ),
            {"ids": list(ids)},
        )
    ).first()
    return None if row is None else int(row.report_id)


async def by_token(session: AsyncSession, tokens: list[str]) -> tuple[int | None, bool]:
    """``(report id, a token was found at all)``. A token of a report that is not sent or
    closed (a draft, a discarded one) is not a match."""
    if not tokens:
        return None, False
    rows = (
        await session.execute(
            text("SELECT id, status FROM abuse_reports WHERE reply_token = ANY(:t)"),
            {"t": tokens},
        )
    ).all()
    for row in rows:
        if row.status in ("sent", "closed"):
            return int(row.id), True
    return None, bool(rows)


async def find_match(
    session: AsyncSession,
    reply: ParsedReply,
    *,
    ticket: str | None,
    recent: list[RecentReport],
) -> Match:
    rid = await by_message_id(session, reply.reference_ids)
    if rid is not None:
        return Match(rid, "message_id", True)
    rid, seen = await by_token(session, find_tokens(reply.subject, reply.body))
    if rid is not None:
        return Match(rid, "token")
    if seen:
        return NO_MATCH  # the token names a report that was never sent: nothing to link
    rid, subject, seen = await by_xarf_id(session, find_xarf_ids(reply.subject, reply.body))
    if rid is not None:
        return Match(rid, "xarf_id", subject=subject)
    if seen:
        return NO_MATCH  # the id names a source of a report that was never sent
    if reply.dsn_message_id:
        rid = await by_message_id(session, (reply.dsn_message_id,))
        if rid is not None:
            return Match(rid, "dsn", True)
    if reply.dsn_subject:
        rid, _ = await by_token(session, find_tokens(reply.dsn_subject))
        if rid is not None:
            return Match(rid, "dsn")
    if ticket and reply.from_domain:
        rows = (
            await session.execute(
                text(
                    "SELECT DISTINCT report_id FROM abuse_replies WHERE from_domain = :d "
                    "AND ticket_id = :t AND report_id IS NOT NULL LIMIT 2"
                ),
                {"d": reply.from_domain, "t": ticket},
            )
        ).all()
        if len(rows) == 1:
            return Match(int(rows[0].report_id), "ticket")
    if reply.from_domain:
        hits = [r.id for r in recent if r.trust.covers(reply.from_address, reply.from_domain)]
        if len(hits) == 1:
            return Match(hits[0], "sender_domain")
    return NO_MATCH


def from_known_recipient(reply: ParsedReply, recent: list[RecentReport]) -> bool:
    """A mail from a party we wrote to. A shared mail domain alone is never enough."""
    if not reply.from_domain:
        return False
    return any(r.trust.covers(reply.from_address, reply.from_domain) for r in recent)


def is_verified(found: Match, reply: ParsedReply, trust: Trust, outcome: str | None = None) -> bool:
    """Vouched for. Quoting our Message-ID proves nothing about the sender (anyone who saw the
    mail can), so it counts only from a party we wrote to; a delivery status notification
    also counts when its mail system authenticated; the rest needs both."""
    if found.report_id is None:
        return False
    speaks = trust.covers(reply.from_address, reply.from_domain)
    # A bounce usually answers our Message-ID (In-Reply-To) or quotes it: the mail system that
    # wrote it is rarely the recipient, so authentication alone also vouches for it.
    if reply.content_type == "multipart/report" or reply.dsn_action is not None:
        if found.method in ("message_id", "dsn") and found.via_message_id:
            # Authentication alone vouches only for a genuine bounce: any other reading of the
            # mail (resolved, rejected...) is a claim that needs a party we wrote to.
            return speaks or (reply.auth == "pass" and outcome == "bounce")
    if found.method == "message_id":
        return speaks
    return reply.auth == "pass" and speaks
