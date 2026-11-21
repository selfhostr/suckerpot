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

from .parse import ParsedReply, strip_quoted

FORM_RULES: Final = frozenset(
    {"form-required", "form-required-portal", "form-required-unmonitored"}
)
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
PLAIN_CODES: Final = ("550", "551", "552", "553", "554")
HARD_AT: Final = 2

MARK_FORM = (
    "UPDATE abuse_recipients SET form_only = true, form_url = COALESCE(form_url, :url) "
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


def _smtp_code_at_line_start(text_: str) -> bool:
    """A reply code (550 to 554 followed by a space) at the start of a line, or right after
    ``said:`` or a colon (qmail: "Remote host said: 550 5.1.1 ..."), in what the sender wrote.
    A number inside a sentence ("1550 sessions") or in the quoted report does not count."""
    for line in strip_quoted(text_)[:2000].lower().split("\n"):
        line = line.strip()
        starts = [0]
        pos = line.find(": ")
        while pos != -1:
            starts.append(pos + 2)
            pos = line.find(": ", pos + 1)
        for at in starts:
            rest = line[at:].lstrip()
            if rest[:3] in PLAIN_CODES and rest[3:4] == " ":
                return True
    return False


def hard_bounce(reply: ParsedReply) -> bool:
    """A permanent failure (5.x.x), from the status of the notification or, without one, from
    a plain SMTP code at the start of a line of its text."""
    if reply.dsn_status is not None:
        return reply.dsn_status.startswith("5.")
    return _smtp_code_at_line_start(reply.body)


def user_unknown(reply: ParsedReply) -> bool:
    if reply.dsn_status == "5.1.1":
        return True
    return any(phrase in strip_quoted(reply.body)[:2000].lower() for phrase in UNKNOWN_USER)


def host_of_url(url: str) -> str:
    authority = url[len("https://") :].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority


def _in_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


async def _own_domains(session: AsyncSession, report_id: int) -> set[str]:
    """The mailbox domain and the reply domains of the report's recipient."""
    row = (
        await session.execute(
            text(
                "SELECT COALESCE(NULLIF(rec.override_mailbox, ''), rec.mailbox) AS box, "
                "rec.reply_domains FROM abuse_reports r "
                "JOIN abuse_recipients rec ON rec.id = r.recipient_id WHERE r.id = :r"
            ),
            {"r": report_id},
        )
    ).first()
    if row is None:
        return set()
    domains = {str(d).lower() for d in (row.reply_domains or [])}
    if row.box and "@" in row.box:
        domains.add(row.box.rsplit("@", 1)[1].lower())
    return domains


async def learn(
    session: AsyncSession,
    reply: ParsedReply,
    *,
    report_id: int | None,
    verified: bool,
    outcome: str,
    rule_id: str | None,
) -> None:
    """Remember a form-only desk or a dead address on the report's recipient.

    ``form_only`` and the bounce count follow any matched reply. The form link is stricter: an
    attacker can forge a matched reply, so the link is kept only from a verified reply, only
    when it points at the provider's own domain (mailbox or reply domains, or below), and only
    the first one is kept."""
    if report_id is None:
        return
    if rule_id in FORM_RULES:
        url = form_url_of(reply.excerpt or reply.body) if verified else None
        if url is not None:
            host = host_of_url(url).lower()
            if not any(_in_domain(host, d) for d in await _own_domains(session, report_id)):
                url = None
        await session.execute(text(MARK_FORM), {"r": report_id, "url": url})
    elif outcome == "bounce" and hard_bounce(reply):
        await session.execute(
            text(MARK_BOUNCE), {"r": report_id, "unknown": user_unknown(reply), "at": HARD_AT}
        )
