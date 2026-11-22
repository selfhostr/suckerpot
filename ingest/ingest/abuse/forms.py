"""The form-only desks (design M38, section 6): the shared directory, routing, the weekly report.

A recipient goes to the form queue when a reply marked it ``form_only`` (``form_source =
'reply'``), when the owner switched it by hand (``manual``), or when the shared directory of
abuse forms has an entry for it with ``accepts_mail: false`` or ``ignored`` (``directory``,
decision D13). Such a recipient gets no automatic mail at all: its sources go into one form
report per ISO week, which the owner submits by hand from the copy kit.

The directory ships in the release (``suckerpot_reporting.forms.bundled``). It is loaded and
validated once; an invalid file routes nothing (fail safe: mail stays the default and the
problem is logged). A flag the directory set is cleared when its entry goes or starts to take
mail. The directory never overrides the owner: a flag the owner cleared (``cleared``) is left
alone, and a reply or manual flag is never touched.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_reporting.forms import Directory, DirectoryError, FormEntry, bundled

log = logging.getLogger(__name__)

ROUTE = (
    "UPDATE abuse_recipients SET form_only = true, form_source = 'directory', form_entry = :e "
    "WHERE id = :i AND NOT form_only AND form_source IS DISTINCT FROM 'cleared'"
)
# Directory flags whose entry is gone or takes mail again: mail is the default once more.
UNROUTE = (
    "UPDATE abuse_recipients SET form_only = false, form_source = NULL, form_entry = NULL "
    "WHERE form_only AND form_source = 'directory' "
    "AND NOT (form_entry = ANY(CAST(:keep AS text[])))"
)


@lru_cache(maxsize=1)
def directory() -> Directory:
    """The bundled directory, or an empty one when it does not validate (logged once)."""
    try:
        return bundled()
    except (DirectoryError, OSError, ValueError) as exc:
        log.warning("abuse form directory refused (%s): no desk is routed by it", exc)
        return Directory()


def week_of(now: datetime) -> date:
    """Monday (UTC) of the ISO week of ``now``."""
    day = now.astimezone(UTC).date()
    return day - timedelta(days=day.weekday())


def mailbox_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().lower() or None


def entry_for(
    directory_: Directory, address: str | None, asns: Iterable[int | None]
) -> FormEntry | None:
    """The directory entry of a recipient: exact mailbox domain first, then a subject's ASN."""
    return directory_.match(mailbox_domain(address), asns)


async def route(
    session: AsyncSession,
    recipient_id: int,
    address: str | None,
    asns: Iterable[int | None],
    directory_: Directory | None = None,
) -> bool:
    """Mark the recipient form-only when the directory says its desk takes no mail. True when
    this call routed it (before any mail went there, D13)."""
    found = entry_for(directory_ or directory(), address, asns)
    if found is None or not found.form_only:
        return False
    res = await session.execute(text(ROUTE), {"i": recipient_id, "e": found.id})
    return bool(getattr(res, "rowcount", 0))


async def sweep(session: AsyncSession, directory_: Directory | None = None) -> int:
    """Clear the directory flags whose entry is gone or takes mail again."""
    keep = [e.id for e in (directory_ or directory()).entries if e.form_only]
    res = await session.execute(text(UNROUTE), {"keep": keep})
    return int(getattr(res, "rowcount", 0) or 0)


async def form_flags(session: AsyncSession, recipient_id: int) -> Any:
    return (
        await session.execute(
            text(
                "SELECT form_only, form_source, form_entry, form_url FROM abuse_recipients "
                "WHERE id = :i"
            ),
            {"i": recipient_id},
        )
    ).first()
