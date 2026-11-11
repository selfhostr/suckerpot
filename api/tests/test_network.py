"""The network API against a scripted session: roles, CSRF, re-authentication, consents, audit.

No database: ``FakeDb`` answers the few statements the routes issue and applies the membership
updates the way the database trigger allows them. ``test_network_integration.py`` runs the same
routes against a real TimescaleDB as the least-privileged API role.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from starlette.testclient import TestClient
from suckerpot_netproto import defaults
from suckerpot_reporting import SelfTermRow, load_self_terms

from api import network as network_mod
from api.auth import AuthSettings, Principal, SessionInfo
from api.deps import get_session
from api.main import create_app

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
NONCE = "nonce-for-tests"
CONSENT = ["sources", "payloads", "c2", "files", "rechecks"]
OWNER_NAME = "owner-home.example.net"


class Rows(list[Any]):
    def one_or_none(self) -> Any:
        return self[0] if self else None

    def one(self) -> Any:
        return self[0]

    def scalar_one_or_none(self) -> Any:
        return self[0][0] if self else None


class FakeDb:
    """Just enough of an AsyncSession for the membership routes."""

    def __init__(self) -> None:
        self.m: dict[str, Any] = {
            "desired": "off", "state": "off", "pseudonym": None, "country": None,
            "show_country": False, "fingerprint": None, "enrolled_day": None,
            "eligible_from_day": None, "standing": None, "last_submit_day": None,
            "next_submit_at": None, "last_error_code": None,
        }  # fmt: skip
        self.audit: list[Any] = []
        self.commits = 0
        self.statements: list[str] = []

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = " ".join(str(stmt).split())
        p = params or {}
        self.statements.append(sql)
        if sql.startswith("SELECT") and "FROM network_membership" in sql:
            assert "privkey" not in sql, "the API never selects the key column"
            return Rows([SimpleNamespace(**self.m)])
        if sql.startswith("UPDATE network_membership SET desired = 'member'"):
            assert self.m["desired"] == "off"
            self.m.update(desired="member", pseudonym=p["p"], country=p["c"], show_country=p["s"])
        elif sql.startswith("UPDATE network_membership SET desired = 'leave'"):
            assert self.m["desired"] == "member"
            self.m["desired"] = "leave"
        elif sql.startswith("UPDATE network_membership SET pseudonym"):
            self.m.update(pseudonym=p["p"], country=p["c"], show_country=p["s"])
        else:
            return Rows()
        return Rows()

    def add(self, obj: Any) -> None:
        self.audit.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        return None


PLACEHOLDERS = defaults.from_text(
    "NETWORK_DEFAULTS_VERSION=1\nNETWORK_HUB_URL=<HUB_URL>\nNETWORK_HUB_KEY=<HUB_KEY>\n"
    "NETWORK_FEED_URL=<FEED_URL>\nNETWORK_FEED_KEY=<FEED_KEY>\n"
)


@asynccontextmanager
async def no_database() -> AsyncIterator[None]:
    yield


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETWORK_ENABLED", "true")
    monkeypatch.setenv("NETWORK_HUB_URL", "https://hub.example.org")
    monkeypatch.setenv("NETWORK_HUB_KEY", "h" * 43)


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch, env: None) -> Iterator[Any]:
    db = FakeDb()
    app: FastAPI = create_app(
        no_database,  # type: ignore[arg-type]
        enable_live=False,
        auth_settings=AuthSettings(password_hash=HASH, secret=b"k" * 40),
    )

    async def fake_session() -> AsyncIterator[FakeDb]:
        yield db

    app.dependency_overrides[get_session] = fake_session
    terms = load_self_terms(
        [
            SelfTermRow(kind="address", value="203.0.113.77", source="manual"),
            SelfTermRow(kind="name", value=OWNER_NAME, source="manual"),
        ],
        {},
    )

    async def fake_terms(*_: Any, **__: Any) -> Any:
        return terms

    monkeypatch.setattr(network_mod, "load_terms", fake_terms)

    def client(role: str = "admin", csrf: bool = True) -> TestClient:
        async def resolve(*_: object) -> Principal:
            info = SessionInfo("u7", 0, 0, 2**40, NONCE)
            owner = role == "admin"
            return Principal(
                app.state.auth.settings.username, "Owner", role, owner, None, False, info
            )

        monkeypatch.setattr(app.state.auth, "resolve", resolve)
        c = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
        if csrf:
            token = app.state.auth.new_csrf(NONCE)
            c.cookies.set("__Host-sp_csrf", token)
            c.headers.update({"X-CSRF-Token": token})
        c.headers.update({"Origin": "https://testserver"})
        return c

    yield SimpleNamespace(db=db, client=client, app=app)


def join_body(**kw: Any) -> dict[str, Any]:
    return {"join": True, "accept": CONSENT, "password": PASSWORD, "show_country": False, **kw}


URL = "/api/v1/network/membership"


# -- status ------------------------------------------------------------------------------------


def test_status_is_open_to_a_viewer_and_never_404(rig: Any) -> None:
    r = rig.client("viewer").get("/api/v1/network/status")
    assert r.status_code == 200
    assert r.json() == {
        "enabled_env": True, "hub_configured": True, "desired": "off", "state": "off",
        "pseudonym": None, "country": None, "show_country": False, "fingerprint": None,
        "enrolled_day": None, "eligible_from_day": None, "standing": None,
        "last_submit_day": None, "next_submit_at": None, "last_error_code": None, "waiting": None,
    }  # fmt: skip


def test_status_reports_env_off_and_waiting_reasons(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETWORK_ENABLED", "false")
    monkeypatch.setenv("NETWORK_HUB_URL", "")
    monkeypatch.setattr(defaults, "load", lambda: PLACEHOLDERS)
    rig.db.m.update(last_error_code="waiting_self_address")
    body = rig.client().get("/api/v1/network/status").json()
    assert body["enabled_env"] is False and body["hub_configured"] is False
    assert body["waiting"] == "self_address" and body["last_error_code"] is None
    rig.db.m.update(last_error_code="egress_closed")
    body = rig.client().get("/api/v1/network/status").json()
    assert body["waiting"] == "egress" and body["last_error_code"] == "egress_closed"
    rig.db.m.update(last_error_code="no_settings_key")
    assert rig.client().get("/api/v1/network/status").json()["waiting"] == "settings_key"
    rig.db.m.update(last_error_code="waiting_enrolment")
    body = rig.client().get("/api/v1/network/status").json()
    assert body["waiting"] == "enrolment" and body["last_error_code"] is None


# -- joining -----------------------------------------------------------------------------------


def test_a_viewer_cannot_join_leave_or_read_submissions(rig: Any) -> None:
    c = rig.client("viewer")
    assert c.put(URL, json=join_body()).status_code == 403
    assert c.patch(URL, json={}).status_code == 403
    assert c.request("DELETE", URL, json={"password": PASSWORD}).status_code == 403
    assert c.get("/api/v1/network/submissions").status_code == 403
    assert c.get("/api/v1/network/preview").status_code == 403
    assert rig.db.m["desired"] == "off"


def test_joining_needs_the_csrf_token(rig: Any) -> None:
    r = rig.client(csrf=False).put(URL, json=join_body())
    assert r.status_code == 403 and rig.db.m["desired"] == "off"


def test_nothing_happens_while_the_network_is_off_in_env(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETWORK_ENABLED", "false")
    r = rig.client().put(URL, json=join_body())
    assert r.status_code == 503 and r.json()["code"] == "network_disabled"
    assert rig.db.m["desired"] == "off"


def test_no_hub_means_it_cannot_be_joined(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETWORK_HUB_KEY", "")
    monkeypatch.setattr(defaults, "load", lambda: PLACEHOLDERS)
    assert rig.client().put(URL, json=join_body()).json()["code"] == "network_disabled"


def test_committed_defaults_stand_in_for_an_unset_hub(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full install sets no hub in .env: the committed defaults make the network joinable."""
    monkeypatch.delenv("NETWORK_HUB_URL")
    monkeypatch.delenv("NETWORK_HUB_KEY")
    assert defaults.load().hub_configured  # the shipped file holds real values
    body = rig.client().get("/api/v1/network/status").json()
    assert body["hub_configured"] is True
    r = rig.client().put(URL, json=join_body())
    assert r.status_code != 503 and r.json().get("code") != "network_disabled"


@pytest.mark.parametrize(
    "accept",
    [CONSENT[:4], [], [*CONSENT, "sources"], [*CONSENT[:4], "other"], ["sources"] * 5],
)
def test_all_five_consents_are_required(rig: Any, accept: list[str]) -> None:
    r = rig.client().put(URL, json=join_body(accept=accept))
    assert r.status_code == 422 and r.json()["code"] == "consent_required"
    assert rig.db.m["desired"] == "off"


@pytest.mark.parametrize(
    "name",
    ["ab", "x" * 25, "Bob 2026", "me@example.org", "http://x.example.org", "admin", "Selfhostr",
     "-lead", "trail-", "two  spaces"],
)  # fmt: skip
def test_bad_pseudonyms_are_refused(rig: Any, name: str) -> None:
    r = rig.client().put(URL, json=join_body(pseudonym=name))
    assert r.status_code == 422 and r.json()["code"] == "pseudonym_invalid", name
    assert rig.db.m["desired"] == "off"


def test_a_pseudonym_that_names_the_owner_is_blocked_by_the_identity_guard(rig: Any) -> None:
    r = rig.client().put(URL, json=join_body(pseudonym=OWNER_NAME))
    assert r.status_code == 422 and r.json()["code"] == "identity_guard"
    assert rig.db.m["desired"] == "off" and OWNER_NAME not in r.text


def test_a_country_must_be_two_letters_and_is_needed_to_be_shown(rig: Any) -> None:
    assert rig.client().put(URL, json=join_body(country="Swiss")).status_code == 422
    assert rig.client().put(URL, json=join_body(show_country=True)).status_code == 422


def test_the_wrong_password_does_not_join(rig: Any) -> None:
    r = rig.client().put(URL, json=join_body(password="not the password"))
    assert r.status_code == 403 and r.json()["code"] == "reauth_failed"
    assert rig.db.m["desired"] == "off" and rig.db.commits == 0


def test_joining_records_the_wish_and_audits_flags_only(rig: Any) -> None:
    r = rig.client().put(
        URL, json=join_body(pseudonym="Night Owl", country="ch", show_country=True)
    )
    assert r.status_code == 200, r.text
    assert rig.db.m["desired"] == "member" and rig.db.m["pseudonym"] == "Night Owl"
    assert rig.db.m["country"] == "CH" and rig.db.m["show_country"] is True
    [entry] = rig.db.audit
    assert entry.action == "network.join"
    assert entry.details["pseudonym_set"] is True
    blob = json.dumps(entry.details) + str(entry.target) + str(entry.actor)
    assert "Night Owl" not in blob and PASSWORD not in blob
    assert PASSWORD not in r.text


def test_joining_without_a_pseudonym_stays_anonymous(rig: Any) -> None:
    assert rig.client().put(URL, json=join_body()).status_code == 200
    assert rig.db.m["pseudonym"] is None and rig.db.audit[0].details["pseudonym_set"] is False


def test_joining_twice_is_refused(rig: Any) -> None:
    c = rig.client()
    assert c.put(URL, json=join_body()).status_code == 200
    r = c.put(URL, json=join_body())
    assert r.status_code == 409 and r.json()["code"] == "already_member"


def test_unknown_fields_are_refused(rig: Any) -> None:
    assert rig.client().put(URL, json=join_body(extra=1)).status_code == 422


# -- updating and leaving -------------------------------------------------------------------


def test_only_a_member_can_change_the_pseudonym(rig: Any) -> None:
    r = rig.client().patch(URL, json={"pseudonym": "Night Owl", "show_country": False})
    assert r.status_code == 409 and r.json()["code"] == "not_member"


def test_a_member_updates_without_a_password_and_the_audit_names_fields(rig: Any) -> None:
    rig.db.m.update(desired="member", state="member")
    r = rig.client().patch(
        URL, json={"pseudonym": "Red Fox", "country": "DE", "show_country": True}
    )
    assert r.status_code == 200 and rig.db.m["pseudonym"] == "Red Fox"
    [entry] = rig.db.audit
    assert entry.action == "network.update"
    assert set(entry.details["changed"]) == {"pseudonym", "country", "show_country"}
    assert "Red Fox" not in json.dumps(entry.details)


def test_leaving_needs_the_password_and_marks_the_wish(rig: Any) -> None:
    rig.db.m.update(desired="member", state="member")
    c = rig.client()
    bad = c.request("DELETE", URL, json={"password": "nope"})
    assert bad.status_code == 403 and rig.db.m["desired"] == "member"
    ok = c.request("DELETE", URL, json={"password": PASSWORD})
    assert ok.status_code == 200 and rig.db.m["desired"] == "leave"
    assert rig.db.audit[-1].action == "network.leave"
    again = c.request("DELETE", URL, json={"password": PASSWORD})
    assert again.status_code == 200  # already leaving: idempotent


def test_the_network_is_off_by_default(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """No NETWORK_ENABLED in the environment means off; nothing joins by itself."""
    monkeypatch.delenv("NETWORK_ENABLED")
    body = rig.client().get("/api/v1/network/status").json()
    assert body["enabled_env"] is False and body["desired"] == "off"


def test_a_node_that_left_can_join_again(rig: Any) -> None:
    """After a completed leave the row is desired=off, state=off (ingest wipes it): join works."""
    rig.db.m.update(desired="member", state="member")
    c = rig.client()
    assert c.request("DELETE", URL, json={"password": PASSWORD}).status_code == 200
    rig.db.m.update(desired="off", state="off", pseudonym=None)  # what ingest's wipe leaves
    r = c.put(URL, json=join_body())
    assert r.status_code == 200 and rig.db.m["desired"] == "member"
    assert [a.action for a in rig.db.audit][-2:] == ["network.leave", "network.join"]


def test_leaving_when_not_a_member_is_a_conflict(rig: Any) -> None:
    r = rig.client().request("DELETE", URL, json={"password": PASSWORD})
    assert r.status_code == 409 and r.json()["code"] == "not_member"


# -- lists ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query", ["state=bogus", "kind=bogus", "limit=0", "limit=101", "target=nope"]
)
def test_target_filters_are_validated(rig: Any, query: str) -> None:
    assert rig.client().get(f"/api/v1/network/targets?{query}").status_code == 422


def test_a_bad_target_cursor_is_400(rig: Any) -> None:
    assert rig.client().get("/api/v1/network/targets?cursor=garbage").status_code == 400


def test_submission_day_must_be_a_date(rig: Any) -> None:
    assert rig.client().get("/api/v1/network/submissions/notaday").status_code == 422


def test_recent_submission_window() -> None:
    today = datetime(2026, 11, 3, tzinfo=UTC).date()
    assert network_mod.recent_submission(today - timedelta(days=1), today)
    assert network_mod.recent_submission(today - timedelta(days=2), today)
    assert not network_mod.recent_submission(today - timedelta(days=3), today)
    assert not network_mod.recent_submission(None, today)
    assert isinstance(date.today(), date)
