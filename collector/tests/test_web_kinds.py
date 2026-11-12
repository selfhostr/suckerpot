"""The collector, the analysis library and the database helper agree on what web content is."""

from __future__ import annotations

from suckerpot_analysis import WEB_KINDS
from suckerpot_db.sample_kinds import WEB_SAMPLE_KINDS


def test_the_web_kinds_are_the_same_everywhere() -> None:
    assert set(WEB_SAMPLE_KINDS) == set(WEB_KINDS)
    assert len(WEB_SAMPLE_KINDS) == len(set(WEB_SAMPLE_KINDS))
