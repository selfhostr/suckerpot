"""What a reply teaches the node about the desk that sent it (the recipient of the report).

Two facts are remembered on the recipient, so automatic sending stops there and the owner can
act by hand:

* the desk takes reports only through a web form (rule ``form-required``), with the form link
  when the reply carries one;
* the address bounced for good: one hard bounce for "user unknown", two for any other 5.x.x.

Any reply matched to a report counts, verified or not; an unmatched one never does. The
effect is small: it only stops automatic sends, the report page shows it, and the owner can
clear it. Mail text is hostile: the link is the first ``https`` URL of the excerpt, checked and
bounded, and no regular expression reads it.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.blocklist_values import valid_domain

from .parse import ParsedReply

FORM_RULE: Final = "form-required"
MAX_FORM_URL: Final = 500
URL_END: Final = frozenset(" \t\r\n<>\"'`\\^{}|[]")
TRAILING: Final = ".,;:!?)("
# Texts of "no such mailbox": one such hard bounce is enough.
UNKNOWN_USER: Final = (
    "user not found",
    "user unknown",
    "unknown user",
    "no such user",
    "no such mailbox",
    "mailbox not found",
    "recipient not found",
    "recipient address rejected: user unknown",
    "unknown recipient",
)
PLAIN_CODES: Final = ("550 ", "551 ", "552 ", "553 ", "554 ")
HARD_AT: Final = 2

MARK_FORM = (
    "UPDATE abuse_recipients SET form_only = true, form_url = COALESCE(:url, form_url) "
    "WHERE id = (SELECT recipient_id FROM abuse_reports WHERE id = :r)"
)
MARK_BOUNCE = (
    "UPDATE abuse_recipients SET hard_bounces = LEAST(hard_bounces + 1, 100), "
    "undeliverable = undeliverable OR :unknown OR hard_bounces + 1 >= :at "
    "WHERE id = (SELECT recipient_id FROM abuse_reports WHERE id = :r)"
)


def form_url_of(excerpt: str) -> str | None:
    """The first ``https://`` link of the text, when it is a plain host name with no login."""
    low = excerpt.lower()
    start = low.find("https://")
    while start != -1:
        end = start
        while end < len(excerpt) and excerpt[end] not in URL_END:
            end += 1
        url = excerpt[start:end].rstrip(TRAILING)
        rest = url[len("https://") :]
        authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
        port_ok = authority == host or authority[len(host) + 1 :].isdigit()
        clean = url.isascii() and url.isprintable() and "@" not in authority
        if clean and port_ok and valid_domain(host) and len(url) <= MAX_FORM_URL:
            return "https://" + rest
        start = low.find("https://", end)
    return None


def hard_bounce(reply: ParsedReply) -> bool:
    """A permanent failure (5.x.x), from the status of the notification or, without one, from
    a plain SMTP code in its text."""
    if reply.dsn_status is not None:
        return reply.dsn_status.startswith("5.")
    head = reply.body[:2000].lower()
    return any(code in head for code in PLAIN_CODES)


def user_unknown(reply: ParsedReply) -> bool:
    if reply.dsn_status == "5.1.1":
        return True
    return any(phrase in reply.body[:2000].lower() for phrase in UNKNOWN_USER)


async def learn(
    session: AsyncSession,
    reply: ParsedReply,
    *,
    report_id: int | None,
    outcome: str,
    rule_id: str | None,
) -> None:
    """Remember a form-only desk or a dead address on the report's recipient."""
    if report_id is None:
        return
    if rule_id == FORM_RULE:
        await session.execute(
            text(MARK_FORM), {"r": report_id, "url": form_url_of(reply.excerpt or reply.body)}
        )
    elif outcome == "bounce" and hard_bounce(reply):
        await session.execute(
            text(MARK_BOUNCE), {"r": report_id, "unknown": user_unknown(reply), "at": HARD_AT}
        )
