"""Plain web samples: the shared SQL conditions are constant text over plain identifiers."""

from collections.abc import Callable

import pytest

from suckerpot_db.sample_kinds import (
    WEB_SAMPLE_KINDS,
    attacker_source,
    crawled_from_web,
    is_plain_web_hash,
    plain_web_sample,
    reopened_web_sample,
    web_content,
)


def test_the_web_kinds() -> None:
    assert WEB_SAMPLE_KINDS == ("html", "svg", "xml", "css", "json", "javascript")


def test_web_content_is_a_web_kind_without_a_family_or_a_severity() -> None:
    sql = web_content("sm")
    assert sql.startswith("COALESCE(") and sql.endswith(", false)")  # never NULL
    assert "sm.kind IN ('html', 'svg', 'xml', 'css', 'json', 'javascript')" in sql
    assert "sm.severity = 'info'" in sql
    assert "sm.family IS NULL" in sql


def test_a_plain_web_sample_is_web_content_reached_only_through_web_links() -> None:
    sql = plain_web_sample("sm")
    assert web_content("sm") in sql
    assert crawled_from_web("sm") in sql


def test_what_an_attacker_asked_for_is_never_crawled() -> None:
    sql = attacker_source("s")
    # A typed URL, a depth-0 fetch or a link in anything but web content makes it attacker content;
    # a network verification fetch counts neither way.
    assert "s_ft.indicator_id IS NULL AND s_ft.depth >= 1" in sql
    assert web_content("s_pa") in sql
    assert "s_ft.origin = 'network_verify'" in sql
    assert "LEFT JOIN samples s_pa ON s_pa.sha256 = s_ft.parent_sha256" in sql
    assert "WHERE s_ss.sha256 = s.sha256" in sql
    crawled = crawled_from_web("s")
    assert crawled.startswith("(EXISTS (") and f"AND NOT {sql})" in crawled


def test_a_spared_sample_is_reopened_once_an_attacker_asks_for_it() -> None:
    sql = reopened_web_sample("s")
    assert "s.analysis_status = 'done'" in sql
    assert web_content("s") in sql and attacker_source("s") in sql
    assert "s_hi.type = 'hash' AND s_hi.value = s.sha256" in sql


def test_the_hash_condition_looks_the_sample_up_by_its_sha256() -> None:
    sql = is_plain_web_hash("i.value")
    assert sql.startswith("EXISTS (SELECT 1 FROM samples pw WHERE pw.sha256 = lower(i.value)")
    assert plain_web_sample("pw") in sql


@pytest.mark.parametrize("alias", ["", "S", "a b", "x; DROP TABLE samples", "a.b", "1a", "a" * 40])
@pytest.mark.parametrize(
    "build",
    [web_content, plain_web_sample, crawled_from_web, attacker_source, reopened_web_sample],
)
def test_an_alias_must_be_a_plain_identifier(alias: str, build: Callable[[str], str]) -> None:
    with pytest.raises(ValueError, match="identifier"):
        build(alias)


@pytest.mark.parametrize("column", ["", "i.value; --", "lower(x)", "a.b.c", "'x'", "i. value"])
def test_the_hash_column_must_be_a_column_reference(column: str) -> None:
    with pytest.raises(ValueError, match="column"):
        is_plain_web_hash(column)
