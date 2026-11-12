"""Merging campaigns that are one actor: their source addresses overlap strongly.

Clustering by key (script, payload host, credential list, ...) splits one actor into several
campaigns whenever it uses several kinds of tooling in separate sessions: credential stuffing,
then a dropper, then a ransom note are three keys and no single session carries two of them, so
the key-bridge rule in ``plan.py`` never joins them. This rule looks at *who sent* the traffic
instead.

For two live campaigns, ``shared`` is the number of distinct source addresses both have linked
sessions from, and ``size`` is the number of distinct addresses of each. They merge when

* ``shared >= min_shared`` (default 5): a couple of recycled addresses prove nothing, and
* ``shared / min(size_a, size_b) >= min_overlap`` (default 0.6): at least 60 % of the *smaller*
  campaign's addresses are also in the other one.

The measure is containment, not Jaccard, on purpose. A campaign keeps links to its newest
sessions only (``CAMPAIGN_LINK_CAP``), so each source set is a sample of the actor's real
addresses and two samples of the same actor of different size rarely reach a high Jaccard
index, while one nested in the other still shows a high containment. The floor on ``shared``
stops a tiny campaign from merging on a lucky overlap. The campaigns must also share a sensor and
the same ``demo`` flag; that is checked in the query.

Pairs that qualify are merged by single linkage (A with B and B with C puts all three in one
campaign), strongest first, and the oldest campaign of each group survives, so the id in a
shared URL stays valid. Pure: no I/O.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

MIN_SHARED = 5
MIN_OVERLAP = 0.6


@dataclass(frozen=True, slots=True)
class Overlap:
    """Two live campaigns, the addresses both have and how many addresses each has."""

    a: int
    b: int
    shared: int
    size_a: int
    size_b: int

    @property
    def containment(self) -> float:
        """The share of the smaller campaign's addresses that the other one has too."""
        smaller = min(self.size_a, self.size_b)
        return self.shared / smaller if smaller > 0 else 0.0


def qualifies(o: Overlap, min_shared: int = MIN_SHARED, min_overlap: float = MIN_OVERLAP) -> bool:
    return o.a != o.b and o.shared >= min_shared and o.containment >= min_overlap


def overlap_merges(
    pairs: Iterable[Overlap],
    order: Mapping[int, tuple[datetime, int]],
    *,
    min_shared: int = MIN_SHARED,
    min_overlap: float = MIN_OVERLAP,
    budget: int = 50,
) -> list[tuple[int, int]]:
    """(loser, winner) merges to run in this order, at most ``budget`` of them.

    ``order`` ranks campaigns by age (first seen, then id); the oldest of two groups wins. A
    pair whose campaigns are not in ``order`` is ignored. A winner may itself lose later in
    the list; running the merges in order moves everything to the final survivor.
    """
    unique: dict[tuple[int, int], Overlap] = {}
    for o in pairs:
        if qualifies(o, min_shared, min_overlap) and o.a in order and o.b in order:
            key = (min(o.a, o.b), max(o.a, o.b))
            if key not in unique or o.shared > unique[key].shared:
                unique[key] = o
    strongest_first = sorted(
        unique.values(), key=lambda o: (-o.containment, -o.shared, min(o.a, o.b), max(o.a, o.b))
    )
    parent: dict[int, int] = {}

    def root(cid: int) -> int:
        while cid in parent:
            cid = parent[cid]
        return cid

    merges: list[tuple[int, int]] = []
    for o in strongest_first:
        if len(merges) >= budget:
            break
        ra, rb = root(o.a), root(o.b)
        if ra == rb:
            continue
        winner, loser = (ra, rb) if order[ra] <= order[rb] else (rb, ra)
        parent[loser] = winner
        merges.append((loser, winner))
    return merges
