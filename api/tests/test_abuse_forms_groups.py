"""One kit per provider (M38 section 6): how the form queue groups open form reports."""

from types import SimpleNamespace
from typing import Any

from suckerpot_reporting.evidence import MAX_SUBJECTS

from api.abuse_forms import GROUP_MAX, Member, group_members


def member(report: int, recipient: int, entry: str | None = None, subjects: int = 2) -> Member:
    row: Any = SimpleNamespace(id=report)
    rec: Any = SimpleNamespace(id=recipient)
    found: Any = SimpleNamespace(id=entry) if entry else None
    return Member(row=row, rec=rec, subjects=subjects, stale=0, entry=found)


def ids(groups: list[list[Member]]) -> list[list[int]]:
    return [[m.row.id for m in g] for g in groups]


def test_reports_of_one_desk_share_a_card() -> None:
    groups = group_members([member(1, 10), member(2, 11), member(3, 10)])
    assert ids(groups) == [[1, 3], [2]]


def test_mailboxes_of_one_directory_entry_share_a_card() -> None:
    groups = group_members(
        [member(1, 10, "example-net"), member(2, 11, "example-net"), member(3, 12, "other")]
    )
    assert ids(groups) == [[1, 2], [3]]
    # A desk the directory does not know is never merged with an entry's desks.
    assert ids(group_members([member(1, 10, "example-net"), member(2, 10)])) == [[1], [2]]


def test_a_card_holds_at_most_one_kit() -> None:
    half = MAX_SUBJECTS // 2 + 1
    groups = group_members([member(1, 10, subjects=half), member(2, 10, subjects=half)])
    assert ids(groups) == [[1], [2]]
    many = group_members([member(i, 10, subjects=1) for i in range(GROUP_MAX + 1)])
    assert [len(g) for g in many] == [GROUP_MAX, 1]
