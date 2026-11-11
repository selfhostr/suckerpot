"""Roles are enforced by default: no route can forget the check.

The route table is read through the OpenAPI schema (FastAPI nests included routers, so the
public schema is the stable way to enumerate), and every route is called as a viewer. A new
write route that is not admin-only fails here without anybody touching this file. The account
lookup is replaced by a fake; ``test_users_integration.py`` covers the real thing.
"""

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from starlette.testclient import TestClient

from api.auth import AuthSettings, Principal, SessionInfo
from api.main import create_app

HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(
    "correct horse battery staple"
)
NONCE = "nonce-for-tests"

# State-changing routes that every signed-in role may call: sign in and out, own password.
ANY_ROLE_UNSAFE = {
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/password"),
}
# Reads that are for administrators only.
ADMIN_ONLY_GETS = {
    "/api/v1/users",
    "/api/v1/audit",
    "/api/v1/defend/feed-tokens",
    "/api/v1/abuse/settings",
    "/api/v1/abuse/self-terms",
    "/api/v1/abuse/smtp",
    "/api/v1/abuse/imap",
    "/api/v1/abuse/imap/requests/{request_id}",
    "/api/v1/abuse/send-queue",
    "/api/v1/settings/vpn",
    "/api/v1/setup/status",
    "/api/v1/network/submissions",
    "/api/v1/network/submissions/{day}",
    "/api/v1/network/preview",
    "/api/v1/setup/progress",
    "/api/v1/setup/ports",
}
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def no_database() -> AsyncIterator[None]:
    raise RuntimeError("no database in this test")
    yield


def build() -> FastAPI:
    return create_app(
        no_database,  # type: ignore[arg-type]
        enable_live=False,
        auth_settings=AuthSettings(password_hash=HASH, secret=b"k" * 40),
    )


def operations(app: FastAPI) -> list[tuple[str, str]]:
    """(METHOD, path) of every operation under /api/v1, from the OpenAPI schema."""
    found = [
        (method.upper(), path)
        for path, methods in app.openapi()["paths"].items()
        if path.startswith("/api/v1")
        for method in methods
    ]
    assert len(found) > 40
    return found


def fill(path: str) -> str:
    filled = path.replace("{user_id}", "1").replace("{provider}", "abuseipdb")
    return filled.replace("{exit_id}", "1")


def concrete(path: str) -> str:
    while "{" in path:
        start = path.index("{")
        path = path[:start] + "x" + path[path.index("}") + 1 :]
    return path


@pytest.fixture
def client_as(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    app = build()

    def make(role: str) -> TestClient:
        async def resolve(*_: object) -> Principal:
            info = SessionInfo("u7", 0, 0, 2**40, NONCE)
            return Principal("colleague", "Colleague", role, False, 7, False, info)

        monkeypatch.setattr(app.state.auth, "resolve", resolve)
        c = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
        token = app.state.auth.new_csrf(NONCE)
        c.cookies.set("__Host-sp_csrf", token)
        c.headers.update({"X-CSRF-Token": token, "Origin": "https://testserver"})
        return c

    yield make


def is_refused(response: Any) -> bool:
    return bool(response.status_code == 403 and response.json().get("code") == "admin_required")


def test_the_route_table_has_the_new_routes() -> None:
    ops = set(operations(build()))
    assert ("GET", "/api/v1/users") in ops and ("GET", "/api/v1/audit") in ops
    assert ("DELETE", "/api/v1/users/{user_id}") in ops
    assert ANY_ROLE_UNSAFE <= ops


def test_a_viewer_cannot_call_any_write_route(client_as: Any) -> None:
    c = client_as("viewer")
    checked = 0
    for method, path in operations(build()):
        if method not in UNSAFE or (method, path) in ANY_ROLE_UNSAFE:
            continue
        r = c.request(method, fill(path), json={})
        assert is_refused(r), (method, path, r.status_code)
        checked += 1
    assert checked >= 8


def test_the_any_role_list_has_no_stale_entries() -> None:
    unsafe = {(m, p) for m, p in operations(build()) if m in UNSAFE}
    assert ANY_ROLE_UNSAFE <= unsafe


def test_exactly_the_admin_screens_are_closed_to_a_viewer(client_as: Any) -> None:
    c = client_as("viewer")
    refused = {
        path
        for method, path in operations(build())
        if method == "GET" and is_refused(c.get(concrete(path)))
    }
    assert refused == ADMIN_ONLY_GETS


def test_an_admin_is_never_refused_by_the_role_check(client_as: Any) -> None:
    c = client_as("admin")
    for method, path in operations(build()):
        if (method, path) in ANY_ROLE_UNSAFE:
            continue
        r = c.request(method, fill(path) if method in UNSAFE else concrete(path), json=None)
        assert not is_refused(r), (method, path)


def walk(routes: Any, prefix: str = "", deps: tuple[Any, ...] = ()) -> Iterator[Any]:
    """Every leaf route with its full path and the dependencies inherited from its includes.

    This FastAPI keeps included routers nested (``_IncludedRouter``), so the walk descends
    into them and into Starlette mounts, collecting the include-time dependencies on the way.
    """
    for r in routes:
        context = getattr(r, "include_context", None)
        inner = getattr(r, "original_router", None)
        if inner is not None and context is not None:
            yield from walk(
                inner.routes,
                prefix + context.prefix,
                deps + tuple(d.dependency for d in context.dependencies),
            )
        elif hasattr(r, "routes") and not hasattr(r, "dependant"):  # a Mount or a router
            yield ("mount", prefix + getattr(r, "path", ""), r)
            yield from walk(r.routes, prefix + getattr(r, "path", ""), deps)
        else:
            own = tuple(d.dependency for d in getattr(r, "dependencies", []))
            yield ("route", prefix + getattr(r, "path", ""), (r, deps + own))


def test_every_api_route_is_behind_the_role_check_structurally() -> None:
    from fastapi.routing import APIRoute, APIWebSocketRoute

    from api.authz import authorize

    app = build()
    leaves = list(walk(app.routes))
    api_http = [(p, x) for kind, p, x in leaves if kind == "route" and p.startswith("/api/v1")]
    assert len(api_http) > 40
    websockets = []
    for path, (route, deps) in api_http:
        if isinstance(route, APIWebSocketRoute):
            websockets.append(path)
        elif isinstance(route, APIRoute):
            assert authorize in deps, path
    assert websockets == ["/api/v1/live"]
    # Nothing is mounted under /api: a mounted app would bypass the route-level checks.
    assert [p for kind, p, _ in leaves if kind == "mount" and p.startswith("/api")] == []


def public_paths(app: FastAPI) -> set[str]:
    """Every HTTP route path outside /api/v1 (the ones the dashboard login does not guard)."""
    from fastapi.routing import APIRoute

    return {
        p
        for kind, p, x in walk(app.routes)
        if kind == "route" and isinstance(x[0], APIRoute) and not p.startswith("/api/v1")
    }


def test_the_feeds_are_the_only_route_group_outside_the_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off by default; when on, only the token-authenticated feed routes (and /healthz)."""
    monkeypatch.delenv("FEEDS_ENABLED", raising=False)
    assert public_paths(build()) == {"/healthz"}
    monkeypatch.setenv("FEEDS_ENABLED", "true")
    assert public_paths(build()) == {
        "/healthz",
        "/feeds/{token}/{name}",
        "/feeds/{name}",
        "/feeds/network/{name}",  # the verified mirror of the community lists (M30)
        "/feeds/{token}/network/{name}",
    }


def test_no_feed_route_is_in_the_api_prefix_and_none_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FEEDS_ENABLED", "true")
    from fastapi.routing import APIRoute

    feeds = [
        x[0]
        for kind, p, x in walk(build().routes)
        if kind == "route" and p.startswith("/feeds") and isinstance(x[0], APIRoute)
    ]
    assert len(feeds) == 4
    assert all(r.methods == {"GET"} for r in feeds)
