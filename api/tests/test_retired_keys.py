"""Stored keys of a provider this version no longer knows are removed when the API starts."""

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import OperationalError
from suckerpot_db.secretbox import PROVIDERS

from api.provider_keys import ProviderName, remove_retired_keys


def db_error() -> Exception:
    return OperationalError("DELETE", {}, Exception("db is down"))


class FakeSession:
    def __init__(self, removed: list[str], fail: bool = False) -> None:
        self.removed = removed
        self.fail = fail
        self.statements: list[str] = []
        self.added: list[Any] = []
        self.commits = 0

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def scalars(self, stmt: Any) -> list[str]:
        if self.fail:
            raise db_error()
        dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
        self.statements.append(str(stmt.compile(dialect=dialect)))
        return self.removed

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1


def factory_of(session: FakeSession) -> Any:
    return MagicMock(return_value=session)


async def test_an_unknown_provider_is_removed_and_the_known_ones_stay(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    recorded: list[dict[str, Any]] = []

    async def fake_record(_db: Any, **kw: Any) -> None:
        recorded.append(kw)

    monkeypatch.setattr("api.audit.record", fake_record)
    session = FakeSession(["anthropic"])
    with caplog.at_level(logging.INFO, logger="api.provider_keys"):
        assert await remove_retired_keys(factory_of(session)) == ["anthropic"]
    sql = session.statements[0]
    assert sql.startswith("DELETE FROM provider_secrets WHERE (provider_secrets.provider NOT IN")
    assert "RETURNING" in sql and session.commits == 1
    assert recorded[0]["actor"] == "system" and recorded[0]["target"] == "anthropic"
    assert "anthropic" in caplog.text


async def test_nothing_to_remove_writes_no_audit_row(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("no audit row expected")

    monkeypatch.setattr("api.audit.record", boom)
    assert await remove_retired_keys(factory_of(FakeSession([]))) == []


async def test_a_database_error_never_stops_the_start(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="api.provider_keys"):
        assert await remove_retired_keys(factory_of(FakeSession([], fail=True))) == []
    assert "OperationalError" in caplog.text and "db is down" not in caplog.text


def test_the_provider_path_and_the_cleanup_share_one_list() -> None:
    pattern = ProviderName.__metadata__[0].metadata[0].pattern  # type: ignore[attr-defined]
    assert pattern == "^(" + "|".join(PROVIDERS) + ")$"
    assert "anthropic" not in PROVIDERS
