"""Benign web samples: the shared SQL conditions are constant text over plain identifiers."""

import pytest

from suckerpot_db.sample_kinds import WEB_SAMPLE_KINDS, benign_web_sample, is_benign_web_hash


def test_the_web_kinds() -> None:
    assert WEB_SAMPLE_KINDS == ("html", "svg", "xml", "css", "json", "javascript")


def test_a_benign_web_sample_is_web_content_without_a_family_or_a_severity() -> None:
    sql = benign_web_sample("sm")
    assert sql.startswith("COALESCE(") and sql.endswith(", false)")  # never NULL
    assert "sm.kind IN ('html', 'svg', 'xml', 'css', 'json', 'javascript')" in sql
    assert "sm.severity = 'info'" in sql
    assert "sm.family IS NULL" in sql


def test_the_hash_condition_looks_the_sample_up_by_its_sha256() -> None:
    sql = is_benign_web_hash("i.value")
    assert sql.startswith("EXISTS (SELECT 1 FROM samples bw WHERE bw.sha256 = lower(i.value)")
    assert benign_web_sample("bw") in sql


@pytest.mark.parametrize("alias", ["", "S", "a b", "x; DROP TABLE samples", "a.b", "1a", "a" * 40])
def test_an_alias_must_be_a_plain_identifier(alias: str) -> None:
    with pytest.raises(ValueError, match="identifier"):
        benign_web_sample(alias)


@pytest.mark.parametrize("column", ["", "i.value; --", "lower(x)", "a.b.c", "'x'", "i. value"])
def test_the_hash_column_must_be_a_column_reference(column: str) -> None:
    with pytest.raises(ValueError, match="column"):
        is_benign_web_hash(column)
