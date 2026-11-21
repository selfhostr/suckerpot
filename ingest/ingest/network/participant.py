"""Participant mode: the consent record and the automatic join (design M32 D4, N1').

The installer writes ``NETWORK_CONSENT`` to ``.env`` after showing the consent screen (always
in participant mode, where there is no dashboard; in full mode when the owner accepts the
"Join the network?" question, M33). Ingest joins by itself from a valid record, once: a
leave stores ``network_membership.left_day`` and a restart never re-joins. A record older than
``MAX_AGE_DAYS`` never joins (``consent_stale``), so a restored database cannot undo a leave. A
record of a version this release does not know (``consent_outdated``) never joins; the participant
re-runs ``participant.sh join`` to agree again.

A refused enrolment heals by itself (``can_self_heal``): the worker tries again with a new
pseudonym from ``.env`` at once, and with the same one once a day, as long as the record is valid
and fresh and the owner did not leave. The consent rules above are unchanged.

Format: ``v2:sources,payloads,c2,files,rechecks[,verify_reveals]:2026-11-03``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

CONSENT_VERSION = "v2"
REQUIRED_ITEMS = frozenset({"sources", "payloads", "c2", "files", "rechecks"})
OPTIONAL_ITEMS = frozenset({"verify_reveals"})

MISSING = "missing"
VALID = "valid"
OUTDATED = "consent_outdated"
INVALID = "consent_invalid"
STALE = "consent_stale"

# The record is consumed at the first start: it only starts a join while it is this fresh, so a
# leave cannot be undone later by a restored database that finds an old record in ``.env``.
MAX_AGE_DAYS = 7

_VERSION = re.compile(r"^v\d{1,3}$")

# Codes of a refused enrolment (membership state ``error``, desired ``off``) that the worker tries
# again by itself: the hub may free a name later (a ghost of an earlier install), or the owner sets
# another name. Anything else (a leave, a missing settings key) is never retried this way.
HEALABLE = frozenset(
    {
        "pseudonym_taken", "pseudonym_invalid", "enrolment_closed", "pow_timeout",
        "waiting_enrolment", "rate_limited", "hub_error", "hub_unreachable", "egress_closed",
        "challenge_expired", "pow_invalid",
    }
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Consent:
    version: str
    items: frozenset[str]
    day: date

    def has(self, item: str) -> bool:
        return item in self.items


def is_fresh(consent: Consent, today: date) -> bool:
    """True when the record is at most ``MAX_AGE_DAYS`` old (one day of clock skew allowed)."""
    age = (today - consent.day).days
    return -1 <= age <= MAX_AGE_DAYS


def parse(raw: str) -> tuple[str, Consent | None]:
    """``(state, consent)``. The consent is only returned for state ``valid``."""
    text = raw.strip()
    if not text:
        return MISSING, None
    parts = text.split(":")
    if len(parts) != 3 or not _VERSION.fullmatch(parts[0]):
        return INVALID, None
    version, items_raw, day_raw = parts
    if version != CONSENT_VERSION:
        return OUTDATED, None
    items = frozenset(i.strip() for i in items_raw.split(",") if i.strip())
    if not REQUIRED_ITEMS <= items or not items <= REQUIRED_ITEMS | OPTIONAL_ITEMS:
        return INVALID, None
    try:
        day = date.fromisoformat(day_raw)
    except ValueError:
        return INVALID, None
    return VALID, Consent(version, items, day)


def can_self_heal(
    *,
    state: str,
    desired: str,
    left_day: date | None,
    requested_by: str | None,
    error_code: str | None,
    consent: Consent | None,
    today: date,
) -> bool:
    """True when a refused enrolment may be tried again without the owner.

    Only a join that came from the consent record (``requested_by = installer``) and ended in a
    healable refusal. Never after a leave (``left_day``) and never without a valid, fresh record.
    """
    return (
        state == "error"
        and desired == "off"
        and left_day is None
        and requested_by == "installer"
        and error_code in HEALABLE
        and consent is not None
        and is_fresh(consent, today)
    )
