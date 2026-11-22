"""The xarf_id match and the names a reply gives for per-source outcomes (M38), no database."""

from __future__ import annotations

from ingest.replies.match import METHODS, find_xarf_ids
from ingest.replies.parse import strip_quoted
from ingest.replies.store import MAX_NAMES, named_values

XID = "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f601"


def test_xarf_id_comes_after_token_and_before_dsn() -> None:
    assert METHODS.index("token") < METHODS.index("xarf_id") < METHODS.index("dsn")


def test_find_xarf_ids_reads_uuid_v4_only_at_most_five() -> None:
    text = f"Re: report {XID.upper()} and 6f1c2a3b-4d5e-1f60-8a71-b2c3d4e5f601 (not v4)"
    assert find_xarf_ids(text) == [XID]
    many = " ".join(f"6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f6{i:02d}" for i in range(10))
    assert len(find_xarf_ids(many)) == 5
    assert find_xarf_ids(f"x{XID}0") == []  # part of a longer hex run


def test_named_values_reads_own_text_only() -> None:
    body = (
        "We suspended 198.51.100.23 and files.example.org.\n\n"
        "On Mon, 20 Nov 2026, reports@example.org wrote:\n"
        "> 198.51.100.99 attacked\n"
    )
    names = named_values(strip_quoted(body))
    assert {"198.51.100.23", "files.example.org"} <= names
    assert "198.51.100.99" not in names
    assert "2001:db8::7" in named_values("blocked 2001:db8::7 today")


def test_named_values_stops_at_the_limit() -> None:
    text = " ".join(f"198.51.100.{i % 250}x{i}.example.org" for i in range(300))
    assert len(named_values(text)) == MAX_NAMES
