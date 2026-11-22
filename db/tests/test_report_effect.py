"""The statistics and the wording of the report effect measure (M38 G1). Pure, no database."""

import itertools
import re

import pytest

from suckerpot_db.report_effect import (
    MIN_DISCORDANT,
    MIN_PAIRS,
    Cells,
    Effect,
    cells_sql,
    interval_text,
    newcombe_paired,
    sentence,
    status_json,
    status_line,
    summarize,
    verdict_of,
    whole,
    wilson,
)

FORBIDDEN = re.compile(r"\b(effective|works|worked|caused?|causes|because of)\b", re.I)


# ---- Wilson and Newcombe against known values ----------------------------------------------


def test_wilson_reference_values() -> None:
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.27753, abs=1e-5)
    lo, hi = wilson(5, 10)
    assert lo == pytest.approx(0.23659, abs=1e-5) and hi == pytest.approx(0.76341, abs=1e-5)
    lo, hi = wilson(10, 10)
    assert lo == pytest.approx(0.72247, abs=1e-5) and hi == 1.0
    assert wilson(0, 0) == (0.0, 1.0)
    with pytest.raises(ValueError):
        wilson(11, 10)


def test_newcombe_matches_the_published_example() -> None:
    """Armitage and Berry (1994, p. 138), as worked by StatsDirect for Newcombe's method 10:
    both 20, first only 12, second only 2, neither 16 (n = 50); difference 0.2,
    interval 0.056156 to 0.329207."""
    lo, hi = newcombe_paired(20, 12, 2, 16)
    assert lo == pytest.approx(0.056156, abs=5e-6)
    assert hi == pytest.approx(0.329207, abs=5e-6)


def test_newcombe_is_antisymmetric_in_the_discordant_cells() -> None:
    lo, hi = newcombe_paired(20, 2, 12, 16)
    assert lo == pytest.approx(-0.329207, abs=5e-6)
    assert hi == pytest.approx(-0.056156, abs=5e-6)


@pytest.mark.parametrize("cells", list(itertools.product((0, 1, 3, 17), repeat=4)))
def test_newcombe_contains_the_estimate_and_stays_in_range(cells: tuple[int, ...]) -> None:
    a, b, c, d = cells
    lo, hi = newcombe_paired(a, b, c, d)
    assert -1.0 <= lo <= hi <= 1.0
    n = a + b + c + d
    if n:
        theta = (b - c) / n
        assert lo <= theta + 1e-12 and theta - 1e-12 <= hi


def test_newcombe_refuses_negative_counts() -> None:
    with pytest.raises(ValueError):
        newcombe_paired(1, -1, 0, 0)


# ---- verdicts and minimums ------------------------------------------------------------------


def test_verdict_comes_from_the_interval_only() -> None:
    assert verdict_of(-0.3, -0.01) == "lower"
    assert verdict_of(0.01, 0.3) == "higher"
    assert verdict_of(-0.2, 0.2) == "no_clear_difference"
    # An interval that touches 0 is no clear difference, on either side.
    assert verdict_of(-0.3, 0.0) == "no_clear_difference"
    assert verdict_of(0.0, 0.3) == "no_clear_difference"


def test_below_thirty_pairs_nothing_is_computed() -> None:
    e = summarize(Cells(a=5, b=20, c=0, d=4))  # 29 pairs, very lopsided
    assert e.pairs == MIN_PAIRS - 1 and e.verdict == "not_enough_data"
    assert e.seen_reported is None and e.seen_control is None
    assert e.lo is None and e.hi is None and e.difference is None


def test_below_ten_discordant_pairs_nothing_is_computed() -> None:
    e = summarize(Cells(a=50, b=5, c=4, d=41))  # 100 pairs, 9 discordant
    assert e.discordant == MIN_DISCORDANT - 1 and e.verdict == "not_enough_data"
    assert e.seen_reported is None
    e = summarize(Cells(a=50, b=6, c=4, d=40))
    assert e.verdict != "not_enough_data" and e.seen_reported is not None


def test_a_clear_lower_share_for_reported_sources() -> None:
    # 84 pairs: reported seen 32 (38 %), controls seen 51 (61 %).
    e = summarize(Cells(a=26, b=6, c=25, d=27))
    assert e.pairs == 84 and e.verdict == "lower"
    assert whole(e.seen_reported or 0) == 38 and whole(e.seen_control or 0) == 61
    assert e.lo is not None and e.hi is not None and e.difference is not None
    assert -1 <= e.lo < e.difference < e.hi < 0


def test_whole_rounds_half_up() -> None:
    assert whole(0.125) == 13 and whole(0.375) == 38 and whole(0.005) == 1 and whole(0.0) == 0


# ---- wording --------------------------------------------------------------------------------

EXAMPLES = [
    Cells(a=3, b=6, c=2, d=1),  # not enough
    Cells(a=50, b=5, c=4, d=41),  # not enough: discordant
    Cells(a=26, b=6, c=25, d=27),  # lower
    Cells(a=30, b=14, c=16, d=24),  # no clear difference
    Cells(a=25, b=29, c=9, d=21),  # higher
]


@pytest.mark.parametrize("cells", EXAMPLES)
@pytest.mark.parametrize("horizon", [7, 30])
def test_the_wording_never_claims_a_cause(cells: Cells, horizon: int) -> None:
    e = summarize(cells, horizon)
    for text in (sentence(e), status_line(e), interval_text(e) or ""):
        assert not FORBIDDEN.search(text), text


@pytest.mark.parametrize("cells", EXAMPLES[:2])
def test_no_percentage_below_the_minimum(cells: Cells) -> None:
    e = summarize(cells)
    assert "%" not in sentence(e) and "%" not in status_line(e)
    assert interval_text(e) is None
    j = status_json(e)
    assert j["seen_reported"] is None and j["lo"] is None and j["hi"] is None


def test_the_three_verdict_sentences() -> None:
    lower = summarize(Cells(a=26, b=6, c=25, d=27))
    s = sentence(lower)
    assert s.startswith("Reported sources were less often seen attacking a week later: 38 % ")
    assert "against 61 % for similar sources that were not reported (84 pairs;" in s
    assert "This compares two groups; it does not prove" in s
    unclear = summarize(Cells(a=30, b=14, c=16, d=24))
    assert unclear.verdict == "no_clear_difference"
    assert sentence(unclear).startswith("No clear difference yet: 52 % of reported sources")
    assert "The gap could be chance." in sentence(unclear)
    higher = summarize(Cells(a=25, b=29, c=9, d=21), 30)
    assert higher.verdict == "higher"
    assert sentence(higher).startswith("Reported sources were more often seen attacking a month")
    assert "it does not say why" in sentence(higher)


def test_progress_sentences() -> None:
    e = summarize(Cells(a=3, b=6, c=2, d=1))
    assert sentence(e) == (
        "Not enough data yet to tell whether reports help: 12 of 30 comparable pairs."
    )
    assert status_line(e) == "Report effect: not enough data yet (12 of 30 pairs)"
    e = summarize(Cells(a=50, b=5, c=4, d=41))
    assert "only 9 of the 10 pairs" in sentence(e)


def test_status_line_and_json_above_the_minimum() -> None:
    e = summarize(Cells(a=26, b=6, c=25, d=27))
    assert status_line(e) == (
        "Report effect: 38% of reported vs 61% of similar sources still active after 7 days "
        "(84 pairs, clear difference)"
    )
    j = status_json(e)
    assert j["verdict"] == "lower" and j["pairs"] == 84 and j["needed"] == 30
    assert j["seen_reported"] == 38 and j["seen_control"] == 61
    assert isinstance(j["lo"], int) and isinstance(j["hi"], int) and j["hi"] < 0
    unclear = summarize(Cells(a=30, b=14, c=16, d=24))
    assert status_line(unclear).endswith("(84 pairs, no clear difference)")


def test_interval_text() -> None:
    e = Effect(7, "lower", 84, 31, 0.38, 0.61, -0.23, -0.37, -0.09)
    assert interval_text(e) == "between 9 and 37 points lower for reported sources"
    e = Effect(7, "higher", 84, 31, 0.6, 0.4, 0.2, 0.05, 0.31)
    assert interval_text(e) == "between 5 and 31 points higher for reported sources"
    e = Effect(7, "no_clear_difference", 84, 31, 0.5, 0.5, 0.0, -0.12, 0.1)
    assert interval_text(e) == "between 12 points lower and 10 points higher for reported sources"


def test_cells_sql_reads_the_summary_view_only() -> None:
    sql = cells_sql(7)
    assert "FROM report_effect_summary" in sql and "observed_7" in sql
    assert "excluded_7 IS NULL" in sql
    assert "value" not in sql
    assert "seen_r_30" in cells_sql(30)
    with pytest.raises(ValueError):
        cells_sql(14)
