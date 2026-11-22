"""Do reports make a difference? The statistics of the node's effect measure (design M38 G1).

Pure functions, no database. The API (Results card), ``just status`` and the ingest worker use
them, so every surface counts and words the result the same way.

One matched pair is a reported source and a similar source that was not reported. At a horizon
(7 or 30 days) each observed pair falls in one cell:

* ``a``: both were still seen attacking;
* ``b``: only the reported one was still seen;
* ``c``: only the control was still seen;
* ``d``: neither was seen.

The difference of the shares still seen is ``(b - c) / n``. Its 95 % interval is Newcombe's method
10 (1998): Wilson score limits for each share, combined with the correlation of the pairs. A
number is shown only from ``MIN_PAIRS`` observed pairs and ``MIN_DISCORDANT`` discordant pairs
(``b + c``). Three verdicts follow from the interval alone, and the sentences never claim a cause.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final, Literal

Verdict = Literal["not_enough_data", "lower", "no_clear_difference", "higher"]

HORIZONS: Final = (7, 30)
MIN_PAIRS: Final = 30
MIN_DISCORDANT: Final = 10
Z95: Final = 1.959963984540054
TIERS: Final = ("H", "A", "B", "C")
EXCLUSIONS: Final = ("not_observed", "control_reported", "network_reported")


def wilson(x: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval of the proportion ``x / n`` (``(0, 1)`` when ``n`` is 0)."""
    if n <= 0:
        return 0.0, 1.0
    if not 0 <= x <= n:
        raise ValueError("x must be between 0 and n")
    z2 = z * z
    centre = x + z2 / 2
    half = z * math.sqrt(z2 / 4 + x * (n - x) / n)
    return max(0.0, (centre - half) / (n + z2)), min(1.0, (centre + half) / (n + z2))


def newcombe_paired(a: int, b: int, c: int, d: int, z: float = Z95) -> tuple[float, float]:
    """95 % interval of ``p1 - p2 = (b - c) / n`` for paired proportions (Newcombe method 10).

    ``p1 = (a + b) / n`` is the reported share, ``p2 = (a + c) / n`` the control share. The
    correlation ``phi`` uses the corrected numerator ``max(ad - bc - n/2, 0)`` when ``ad > bc``,
    and is 0 when a margin is empty, as in the paper. Never leaves ``[-1, 1]``.
    """
    if min(a, b, c, d) < 0:
        raise ValueError("cell counts must not be negative")
    n = a + b + c + d
    if n == 0:
        return -1.0, 1.0
    p1, p2 = (a + b) / n, (a + c) / n
    l1, u1 = wilson(a + b, n, z)
    l2, u2 = wilson(a + c, n, z)
    margins = (a + b) * (c + d) * (a + c) * (b + d)
    num = float(a * d - b * c)
    if num > 0:
        num = max(num - n / 2, 0.0)
    phi = 0.0 if margins == 0 else num / math.sqrt(margins)
    dl1, du1, dl2, du2 = p1 - l1, u1 - p1, p2 - l2, u2 - p2
    theta = p1 - p2
    lower = theta - math.sqrt(max(0.0, dl1 * dl1 - 2 * phi * dl1 * du2 + du2 * du2))
    upper = theta + math.sqrt(max(0.0, du1 * du1 - 2 * phi * du1 * dl2 + dl2 * dl2))
    return max(-1.0, lower), min(1.0, upper)


def verdict_of(lo: float, hi: float) -> Verdict:
    """From the interval only. An interval that touches 0 is no clear difference."""
    if hi < 0:
        return "lower"
    if lo > 0:
        return "higher"
    return "no_clear_difference"


@dataclass(frozen=True, slots=True)
class Cells:
    """The four cells of the observed pairs at one horizon."""

    a: int = 0
    b: int = 0
    c: int = 0
    d: int = 0

    @property
    def n(self) -> int:
        return self.a + self.b + self.c + self.d

    @property
    def discordant(self) -> int:
        return self.b + self.c

    def add(self, seen_reported: bool, seen_control: bool) -> Cells:
        return Cells(
            self.a + (seen_reported and seen_control),
            self.b + (seen_reported and not seen_control),
            self.c + (seen_control and not seen_reported),
            self.d + (not seen_reported and not seen_control),
        )


@dataclass(frozen=True, slots=True)
class Effect:
    """The result at one horizon. Every share is None below the minimum."""

    horizon: int
    verdict: Verdict
    pairs: int
    discordant: int
    seen_reported: float | None = None
    seen_control: float | None = None
    difference: float | None = None
    lo: float | None = None
    hi: float | None = None

    @property
    def enough(self) -> bool:
        return self.verdict != "not_enough_data"


def enough_data(cells: Cells) -> bool:
    return cells.n >= MIN_PAIRS and cells.discordant >= MIN_DISCORDANT


def summarize(cells: Cells, horizon: int = 7) -> Effect:
    if not enough_data(cells):
        return Effect(horizon, "not_enough_data", cells.n, cells.discordant)
    n = cells.n
    lo, hi = newcombe_paired(cells.a, cells.b, cells.c, cells.d)
    return Effect(
        horizon=horizon,
        verdict=verdict_of(lo, hi),
        pairs=n,
        discordant=cells.discordant,
        seen_reported=(cells.a + cells.b) / n,
        seen_control=(cells.a + cells.c) / n,
        difference=(cells.b - cells.c) / n,
        lo=lo,
        hi=hi,
    )


# ---- wording ----------------------------------------------------------------------------------


def whole(share: float) -> int:
    """A share as a whole percentage (half up, never banker's rounding)."""
    return math.floor(share * 100 + 0.5)


def _later(horizon: int) -> str:
    return {7: "a week later", 30: "a month later"}.get(horizon, f"{horizon} days later")


def _pairs(n: int) -> str:
    return f"{n:,} pair" if n == 1 else f"{n:,} pairs"


def missing_text(effect: Effect) -> str:
    """What is still missing below the minimum: pairs first, then discordant pairs."""
    if effect.pairs < MIN_PAIRS:
        return f"{effect.pairs:,} of {MIN_PAIRS} comparable pairs"
    return (
        f"{effect.pairs:,} comparable pairs, but only {effect.discordant:,} of the "
        f"{MIN_DISCORDANT} pairs where one source was seen and the other was not"
    )


def interval_text(effect: Effect) -> str | None:
    """Text like "between 9 and 37 points lower", or None below the minimum."""
    if effect.lo is None or effect.hi is None:
        return None
    lo, hi = whole(effect.lo), whole(effect.hi)
    if hi < 0:
        return f"between {-hi} and {-lo} points lower for reported sources"
    if lo > 0:
        return f"between {lo} and {hi} points higher for reported sources"
    return f"between {-lo} points lower and {hi} points higher for reported sources"


def sentence(effect: Effect) -> str:
    """The verdict sentence of the Results card. Fixed wording; no percentage below the minimum."""
    if not effect.enough or effect.seen_reported is None or effect.seen_control is None:
        return f"Not enough data yet to tell whether reports help: {missing_text(effect)}."
    r, c = whole(effect.seen_reported), whole(effect.seen_control)
    later = _later(effect.horizon)
    pairs = _pairs(effect.pairs)
    if effect.verdict == "lower" and effect.lo is not None and effect.hi is not None:
        return (
            f"Reported sources were less often seen attacking {later}: {r} % against {c} % for "
            f"similar sources that were not reported ({pairs}; the difference is between "
            f"{-whole(effect.hi)} and {-whole(effect.lo)} points). This compares two groups; it "
            "does not prove that the reports made the difference."
        )
    if effect.verdict == "higher":
        return (
            f"Reported sources were more often seen attacking {later}: {r} % against {c} % "
            f"({pairs}). This compares two groups; it does not say why."
        )
    return (
        f"No clear difference yet: {r} % of reported sources and {c} % of similar unreported "
        f"sources were still seen {later} ({pairs}). The gap could be chance."
    )


def status_line(effect: Effect) -> str:
    """The ``just status`` line (Reports section). Information only, never a warning."""
    if not effect.enough or effect.seen_reported is None or effect.seen_control is None:
        return f"Report effect: not enough data yet ({effect.pairs:,} of {MIN_PAIRS} pairs)"
    clear = "no clear" if effect.verdict == "no_clear_difference" else "clear"
    return (
        f"Report effect: {whole(effect.seen_reported)}% of reported vs "
        f"{whole(effect.seen_control)}% of similar sources still active after "
        f"{effect.horizon} days ({_pairs(effect.pairs)}, {clear} difference)"
    )


def status_json(effect: Effect) -> dict[str, object]:
    """``report_effect`` in ``just status --json``: shares and bounds in whole points or null."""

    def pts(x: float | None) -> int | None:
        return None if x is None else whole(x)

    return {
        "verdict": effect.verdict,
        "horizon": effect.horizon,
        "pairs": effect.pairs,
        "needed": MIN_PAIRS,
        "discordant": effect.discordant,
        "needed_discordant": MIN_DISCORDANT,
        "seen_reported": pts(effect.seen_reported),
        "seen_control": pts(effect.seen_control),
        "lo": pts(effect.lo),
        "hi": pts(effect.hi),
    }


# ---- reading the pairs ------------------------------------------------------------------------

SUMMARY_VIEW: Final = "report_effect_summary"
"""The view the API and ``just status`` read: the pairs without their addresses (migration 0039)."""


def cells_sql(horizon: int) -> str:
    """SQL that sums the four cells at ``horizon`` over the summary view, ``index_at`` in
    ``[:since, :until)``. Constant fragments only."""
    if horizon not in HORIZONS:
        raise ValueError("horizon must be 7 or 30")
    h = str(horizon)
    ok = f"frozen_{h}_at IS NOT NULL AND observed_{h} AND excluded_{h} IS NULL"
    cells = (
        f"count(*) FILTER (WHERE {ok} AND seen_r_{h} AND seen_c_{h}) AS a, "
        f"count(*) FILTER (WHERE {ok} AND seen_r_{h} AND NOT seen_c_{h}) AS b, "
        f"count(*) FILTER (WHERE {ok} AND NOT seen_r_{h} AND seen_c_{h}) AS c, "
        f"count(*) FILTER (WHERE {ok} AND NOT seen_r_{h} AND NOT seen_c_{h}) AS d"
    )
    where = "WHERE index_at >= :since AND index_at < :until"
    return f"SELECT {cells} FROM {SUMMARY_VIEW} {where}"  # noqa: S608 - constant fragments only
