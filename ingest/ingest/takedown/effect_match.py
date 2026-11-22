"""Strata and matching of the report effect measure (design M38 section 3.2). Pure, no database.

A reported attacking address gets at most one control: an address that was a candidate in the same
days but was not reported. Both must match exactly on three strata, counted over the 7 UTC days
that end with the index day (the day of the first report):

* activity class: exploit (a severe tag), download, login then commands, login only, other;
* volume bucket of events: 1 to 9, 10 to 99, 100 to 999, 1,000 or more;
* recency: last seen on the index day, 1 to 2 days before, 3 to 6 days before.

Then the closest provider wins, in tiers: H (a source of the random holdout, any provider), A (same
ASN), B (same provider size class and country), C (same size class). The size class is the pair
(RDAP block size, distinct addresses of the ASN seen in 30 days). Controls are used once.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

Activity = Literal["exploit", "download", "login_commands", "login", "other"]
Tier = Literal["H", "A", "B", "C"]

UNKNOWN: Final = -1
VOLUME_BOUNDS: Final = (10, 100, 1000)
ASN_COUNT_BOUNDS: Final = (2, 10, 100)


def activity_class(*, logins: int, login_commands: bool, downloads: int, severe: bool) -> Activity:
    """The strongest activity of the window: exploit, then download, then a login with commands."""
    if severe:
        return "exploit"
    if downloads > 0:
        return "download"
    if login_commands:
        return "login_commands"
    if logins > 0:
        return "login"
    return "other"


def _bucket(n: int, bounds: tuple[int, ...]) -> int:
    for i, bound in enumerate(bounds):
        if n < bound:
            return i
    return len(bounds)


def volume_bucket(events: int) -> int:
    """0: 1 to 9 events, 1: 10 to 99, 2: 100 to 999, 3: 1,000 or more."""
    return _bucket(max(0, events), VOLUME_BOUNDS)


def recency_bucket(days_before: int) -> int | None:
    """0: seen on the index day, 1: 1 to 2 days before, 2: 3 to 6 days before; None: older."""
    if days_before < 0 or days_before > 6:
        return None
    return 0 if days_before == 0 else 1 if days_before <= 2 else 2


def block_class(prefix_len: int | None, *, ipv6: bool) -> int:
    """RDAP block size: 0 small (IPv4 /24 or smaller, IPv6 /48 or smaller), 1 medium (/23 to /16,
    /47 to /32), 2 large; UNKNOWN when no block is known."""
    if prefix_len is None:
        return UNKNOWN
    small, large = (48, 32) if ipv6 else (24, 16)
    if prefix_len >= small:
        return 0
    return 1 if prefix_len >= large else 2


def asn_count_class(addresses: int | None) -> int:
    """Distinct addresses of the ASN seen in 30 days: 0 one, 1 two to 9, 2 ten to 99, 3 100 or
    more; UNKNOWN when the ASN is unknown."""
    if addresses is None or addresses <= 0:
        return UNKNOWN
    return _bucket(addresses, ASN_COUNT_BOUNDS)


@dataclass(frozen=True, slots=True)
class Source:
    """One address with its strata and provider facts."""

    value: str
    activity: Activity
    volume: int
    recency: int
    asn: int | None = None
    country: str | None = None
    size: tuple[int, int] = (UNKNOWN, UNKNOWN)
    held: bool = False

    @property
    def strata(self) -> tuple[str, int, int]:
        return (self.activity, self.volume, self.recency)


@dataclass(frozen=True, slots=True)
class Pair:
    reported: Source
    control: Source
    tier: Tier


def _tier(r: Source, c: Source) -> Tier | None:
    if c.held:
        return "H"
    if r.asn is not None and r.asn == c.asn:
        return "A"
    if r.size == c.size and r.country is not None and r.country == c.country:
        return "B"
    if r.size == c.size:
        return "C"
    return None


TIER_ORDER: Final[dict[Tier, int]] = {"H": 0, "A": 1, "B": 2, "C": 3}


def _draw(reported: str, control: str) -> str:
    """A stable tie-break that depends on both addresses, so no ordering of the pool is favoured."""
    return hashlib.sha256(f"{reported}|{control}".encode()).hexdigest()


def match(reported: Iterable[Source], pool: Iterable[Source]) -> tuple[list[Pair], list[Source]]:
    """Pairs and the reported sources left unmatched. Exact strata, best tier, no reuse.

    The pool must already exclude reported addresses, the never list and self terms. Reported
    sources are served in the given order (oldest index time first).
    """
    by_strata: dict[tuple[str, int, int], list[Source]] = defaultdict(list)
    for c in pool:
        by_strata[c.strata].append(c)
    used: set[str] = set()
    pairs: list[Pair] = []
    unmatched: list[Source] = []
    for r in reported:
        best: tuple[int, str, Source, Tier] | None = None
        for c in by_strata.get(r.strata, ()):
            if c.value in used or c.value == r.value:
                continue
            tier = _tier(r, c)
            if tier is None:
                continue
            key = (TIER_ORDER[tier], _draw(r.value, c.value))
            if best is None or key < best[:2]:
                best = (key[0], key[1], c, tier)
        if best is None:
            unmatched.append(r)
            continue
        used.add(best[2].value)
        pairs.append(Pair(r, best[2], best[3]))
    return pairs, unmatched
