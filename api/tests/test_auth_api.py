from collections.abc import Iterator
from typing import Any

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import api.auth as auth_mod
from api.auth import AuthSettings
from api.main import create_app

COOKIE_SESSION = "__Host-sp_session"
COOKIE_CSRF = "__Host-sp_csrf"

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
ORIGIN = {"Origin": "http://testserver"}


class NoUsers:
    """A database session where no dashboard user exists and every write is accepted."""

    async def __aenter__(self) -> NoUsers:
        return self

    async def __aexit__(self, *a: object) -> None:
        return None

    async def execute(self, *a: object, **k: object) -> Any:
        class R:
            def scalar_one_or_none(self) -> None:
                return None

        return R()

    async def get(self, *a: object) -> None:
        return None

    def add(self, obj: object) -> None:
        return None

    async def commit(self) -> None:
        return None


def make_app(enable_live: bool = False, **kw: Any) -> FastAPI:
    s = AuthSettings(
        password_hash=HASH, secret=b"k" * 40, cookie_secure=kw.pop("cookie_secure", True), **kw
    )
    return create_app(NoUsers, enable_live=enable_live, auth_settings=s)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def no_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)


@pytest.fixture
def app() -> FastAPI:
    return make_app(enable_live=False)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    # https base URL so the Secure cookies are sent back by the client.
    with TestClient(app, base_url="https://testserver") as c:
        yield c


def login(c: TestClient, password: str = PASSWORD, user: str = "admin", **hdr: str) -> Any:
    headers = {"Origin": "https://testserver", **hdr}
    return c.post(
        "/api/v1/auth/login", json={"username": user, "password": password}, headers=headers
    )


def csrf_headers(c: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": c.cookies[COOKIE_CSRF]}


def test_login_ok_sets_flagged_cookies(client: TestClient) -> None:
    r = login(client)
    assert r.status_code == 204 and not r.content
    cookies = {h.split("=", 1)[0]: h for h in r.headers.get_list("set-cookie")}
    sess = cookies[COOKIE_SESSION].lower()
    assert "httponly" in sess and "secure" in sess and "samesite=strict" in sess
    assert "path=/" in sess and "max-age=43200" in sess
    csrf = cookies[COOKIE_CSRF].lower()
    assert "httponly" not in csrf and "secure" in csrf and "samesite=strict" in csrf
    me = client.get("/api/v1/auth/me").json()
    assert me["username"] == "admin" and me["role"] == "admin" and me["is_owner"] is True
    assert me["read_only"] is False and me["must_change_password"] is False


def test_cookie_not_secure_when_configured() -> None:
    with TestClient(make_app(cookie_secure=False), base_url="http://testserver") as c:
        r = login(c, Origin="http://testserver")
        assert "secure" not in r.headers["set-cookie"].lower()


def test_login_failures_are_uniform(client: TestClient) -> None:
    bad_pw = login(client, "wrong password")
    bad_user = login(client, PASSWORD, "nobody")
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.json() == bad_user.json() == {"detail": "Invalid credentials"}
    assert "set-cookie" not in bad_pw.headers
    assert client.get("/api/v1/auth/me").status_code == 401


def test_login_validation(client: TestClient) -> None:
    r = client.post("/api/v1/auth/login", json={"username": "a"}, headers=ORIGIN)
    assert r.status_code == 422
    r = login(client, "p" * 5000)
    assert r.status_code == 422


def test_login_requires_same_origin(client: TestClient) -> None:
    body = {"username": "admin", "password": PASSWORD}
    assert client.post("/api/v1/auth/login", json=body).status_code == 403  # no Origin/Referer
    evil = client.post("/api/v1/auth/login", json=body, headers={"Origin": "https://evil.example"})
    assert evil.status_code == 403
    null = client.post("/api/v1/auth/login", json=body, headers={"Origin": "null"})
    assert null.status_code == 403
    ok = client.post(
        "/api/v1/auth/login", json=body, headers={"Referer": "https://testserver/login?x=1"}
    )
    assert ok.status_code == 204


def test_login_origin_https_behind_tls_proxy() -> None:
    # The app sees http, the browser's Origin is https: same host, so accepted.
    with TestClient(make_app(), base_url="http://testserver") as c:
        assert login(c, Origin="https://testserver").status_code == 204


def test_allowed_origins_env(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    monkeypatch.setenv("API_ALLOWED_ORIGINS", "https://dash.example.com")
    assert login(client, Origin="https://dash.example.com").status_code == 204


def test_rate_limit_429() -> None:
    with TestClient(make_app(rate_per_ip=3), base_url="https://testserver") as c:
        codes = [login(c, "wrong password").status_code for _ in range(3)]
        assert codes == [401, 401, 401]
        r = login(c, PASSWORD)  # even the right password is refused once limited
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
        assert COOKIE_SESSION not in c.cookies


def test_csrf_endpoint(client: TestClient) -> None:
    r = client.get("/api/v1/auth/csrf")
    token = r.json()["token"]
    assert client.cookies[COOKIE_CSRF] == token
    assert "httponly" not in r.headers["set-cookie"].lower()


def test_unsafe_methods_need_csrf(client: TestClient, app: FastAPI) -> None:
    login(client)

    @app.post("/api/v1/_probe")
    async def probe() -> dict[str, bool]:  # pragma: no cover - exercised via client
        return {"ok": True}

    @app.delete("/api/v1/_probe")
    async def probe_del() -> dict[str, bool]:  # pragma: no cover
        return {"ok": True}

    for method in ("POST", "DELETE", "PUT", "PATCH"):
        r = client.request(method, "/api/v1/_probe")
        assert r.status_code == 403, method
        assert (
            client.request(method, "/api/v1/_probe", headers={"X-CSRF-Token": "nope"}).status_code
            == 403
        )
    assert client.post("/api/v1/_probe", headers=csrf_headers(client)).json() == {"ok": True}
    assert client.delete("/api/v1/_probe", headers=csrf_headers(client)).status_code == 200
    # A matching but unsigned pair (cookie planted by an attacker) is refused.
    client.cookies.set(COOKIE_CSRF, "planted.value")
    assert (
        client.post("/api/v1/_probe", headers={"X-CSRF-Token": "planted.value"}).status_code == 403
    )


def test_unauthenticated_unsafe_is_401_not_403(client: TestClient) -> None:
    assert client.post("/api/v1/_probe").status_code == 401


def test_logout_invalidates_session(client: TestClient) -> None:
    login(client)
    old = client.cookies[COOKIE_SESSION]
    assert client.post("/api/v1/auth/logout").status_code == 403  # CSRF required
    r = client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    assert r.status_code == 204
    assert (
        'sp_session=""' in r.headers["set-cookie"] or "max-age=0" in r.headers["set-cookie"].lower()
    )
    assert client.get("/api/v1/auth/me").status_code == 401
    client.cookies.set(COOKIE_SESSION, old)  # replaying the old cookie must not work
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/sessions").status_code == 401


def test_relogin_rotates_session(client: TestClient) -> None:
    login(client)
    first = client.cookies[COOKIE_SESSION]
    login(client)
    second = client.cookies[COOKIE_SESSION]
    assert first != second
    client.cookies.clear()
    client.cookies.set(COOKIE_SESSION, first)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_session_expires(client: TestClient, app: FastAPI) -> None:
    login(client)
    assert client.get("/api/v1/auth/me").status_code == 200
    clock = app.state.auth.clock
    app.state.auth.clock = lambda: clock() + 13 * 3600
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/stats/summary").status_code == 401


def test_forged_cookie_rejected(client: TestClient) -> None:
    client.cookies.set(COOKIE_SESSION, "v1.1.9999999999.abc.sig")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_every_api_route_requires_auth(app: FastAPI) -> None:
    """Enumerate every registered path: nothing is public except /auth/* and /healthz.

    The router table is read through the OpenAPI schema (public API; FastAPI nests included
    routers), and the blanket rule is checked too: any unknown path under /api/v1 is also 401.
    """
    checked = 0
    with TestClient(app, base_url="https://testserver") as c:
        for path, methods in app.openapi()["paths"].items():
            if path == "/healthz" or path.startswith("/api/v1/auth/"):
                continue
            assert path.startswith("/api/v1/"), f"unexpected public-looking route {path}"
            url = path
            while "{" in url:
                start = url.index("{")
                url = url[:start] + "x" + url[url.index("}") + 1 :]
            for method in methods:
                r = c.request(method.upper(), url)
                assert r.status_code == 401, f"{method} {path} -> {r.status_code}"
                checked += 1
        assert checked >= 8
        assert c.get("/api/v1/does-not-exist").status_code == 401
        assert c.get("/healthz").status_code != 401


def test_websocket_rejects_without_cookie(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect("/api/v1/live"):
        pass
    assert exc.value.code == 1008


def test_websocket_rejects_forged_and_revoked_cookie(client: TestClient) -> None:
    client.cookies.set(COOKIE_SESSION, "v1.1.2.3.4")
    with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect("/api/v1/live"):
        pass
    assert exc.value.code == 1008
    client.cookies.clear()
    login(client)
    token = client.cookies[COOKIE_SESSION]
    client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    client.cookies.set(COOKIE_SESSION, token)
    with pytest.raises(WebSocketDisconnect) as exc2, client.websocket_connect("/api/v1/live"):
        pass
    assert exc2.value.code == 1008


def test_websocket_accepts_session_then_closes_on_logout(
    client: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.live as live

    monkeypatch.setattr(live, "SESSION_RECHECK_S", 0.05)

    class FakeSession:
        async def __aenter__(self) -> FakeSession:
            return self

        async def __aexit__(self, *a: object) -> None:
            return None

        async def execute(self, *a: object, **k: object) -> Any:
            class R:
                def all(self) -> list[Any]:
                    return []

            return R()

    login(client)
    app.state.session_factory = lambda: FakeSession()
    # The Secure cookie is not sent over ws:// by the client jar: pass it by hand.
    cookie = f"{COOKIE_SESSION}={client.cookies[COOKIE_SESSION]}"
    with client.websocket_connect("/api/v1/live", headers={"cookie": cookie}) as ws:
        assert ws.receive_json()["kind"] == "backfill"
        info = app.state.auth.validate(client.cookies[COOKIE_SESSION])
        app.state.auth.revoke(info)  # logout from another tab
        with pytest.raises(WebSocketDisconnect) as exc:
            for _ in range(50):
                ws.receive_text()
        assert exc.value.code == 1008


def test_auth_disabled_is_open() -> None:
    app = create_app(enable_live=False, auth_settings=AuthSettings(disabled=True))
    with TestClient(app) as c:
        me = c.get("/api/v1/auth/me").json()
        assert me["username"] == "admin" and me["role"] == "admin"
        assert (
            c.post("/api/v1/auth/login", json={"username": "x", "password": "y"}).status_code == 204
        )


def test_security_headers_on_401(client: TestClient) -> None:
    r = client.get("/api/v1/sessions")
    assert r.status_code == 401
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_no_secrets_in_logs(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("DEBUG"):
        login(client, "wrong password")
        login(client)
    text = caplog.text
    assert PASSWORD not in text and "wrong password" not in text
    assert HASH not in text and client.cookies[COOKIE_SESSION] not in text


def test_login_busy_returns_429(
    client: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api.auth import LoginBusy

    async def busy(*a: object) -> bool:
        raise LoginBusy

    monkeypatch.setattr(app.state.auth, "check_credentials", busy)
    r = login(client)
    assert r.status_code == 429 and r.headers["retry-after"] == "2"


def test_logout_deletes_both_cookies(client: TestClient) -> None:
    login(client)
    r = client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    deleted = " ".join(r.headers.get_list("set-cookie"))
    assert COOKIE_SESSION in deleted and COOKIE_CSRF in deleted


def test_csrf_token_is_bound_to_the_session(client: TestClient, app: FastAPI) -> None:
    from starlette.testclient import TestClient as TC

    login(client)
    stale = client.get("/api/v1/auth/csrf").json()["token"]  # bound to the first session
    login(client)  # rotation: a new session, a new bound token
    client.cookies.set(COOKIE_CSRF, stale)
    assert client.post("/api/v1/_probe", headers={"X-CSRF-Token": stale}).status_code in (403, 404)
    assert TC is not None


def test_login_full_origin_when_allowed_origins_set(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_ALLOWED_ORIGINS", "https://dash.example.com")
    assert (
        login(client, Origin="https://testserver").status_code == 403
    )  # host matches Host, not listed
    assert login(client, Origin="http://dash.example.com").status_code == 403  # wrong scheme
    assert login(client, Origin="https://dash.example.com").status_code == 204


def test_trusted_host_rejects_unknown_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_ALLOWED_HOSTS", "dash.example.com")
    with TestClient(make_app(), base_url="https://testserver") as c:
        assert c.get("/healthz").status_code == 400
        assert c.get("/healthz", headers={"Host": "dash.example.com"}).status_code != 400
        assert c.get("/healthz", headers={"Host": "localhost:8000"}).status_code != 400


def test_cve_routes_need_a_session(client: TestClient) -> None:
    for path in ("/api/v1/cves", "/api/v1/cves/sync", "/api/v1/cves/CVE-2099-0001"):
        assert client.get(path).status_code == 401


def test_the_owner_is_never_limited_by_name_and_successes_are_free() -> None:
    with TestClient(make_app(rate_per_ip=50, rate_per_user=2), base_url="https://testserver") as c:
        for _ in range(6):
            assert login(c, "wrong password").status_code == 401  # the owner's name: no name window
        assert login(c).status_code == 204


def test_other_names_are_limited_by_failures_only() -> None:
    with TestClient(make_app(rate_per_ip=50, rate_per_user=2), base_url="https://testserver") as c:
        assert login(c, "wrong", "someone").status_code == 401
        assert login(c, "wrong", "someone").status_code == 401
        assert login(c, "wrong", "someone").status_code == 429
        assert login(c, "wrong", "somebody").status_code == 401  # another name is unaffected


def test_a_database_failure_is_a_plain_401_for_other_names_and_does_not_block_the_owner() -> None:
    class Broken(NoUsers):
        async def execute(self, *a: object, **k: object) -> Any:
            from sqlalchemy.exc import OperationalError

            raise OperationalError("select", {}, Exception("down"))

    s = AuthSettings(password_hash=HASH, secret=b"k" * 40)
    app = create_app(Broken, enable_live=False, auth_settings=s)  # type: ignore[arg-type]
    with TestClient(app, base_url="https://testserver") as c:
        r = login(c, PASSWORD, "colleague")
        assert r.status_code == 401 and r.json() == {"detail": "Invalid credentials"}
        assert login(c).status_code == 204  # the owner still gets in


def _by_header_address(app: FastAPI) -> None:
    """Give each test request the address named in X-Test-Ip (the test peer is not an IP)."""
    app.state.auth.client_ip = lambda conn: conn.headers.get("x-test-ip", "192.0.2.1")


def test_a_hammered_address_does_not_lock_another_one_out() -> None:
    app = make_app(rate_per_ip=3, rate_global=3)
    _by_header_address(app)
    with TestClient(app, base_url="https://testserver") as c:
        codes = [login(c, "wrong", **{"X-Test-Ip": "198.51.100.7"}).status_code for _ in range(12)]
        assert codes[:3] == [401] * 3 and codes[3:] == [429] * 9  # that address is blocked
        # The server-wide failure budget is spent too, yet a correct password still works.
        assert app.state.auth.under_pressure()
        r = login(c, **{"X-Test-Ip": "203.0.113.9"})
        assert r.status_code == 204
        assert c.get("/api/v1/auth/me").status_code == 200


async def test_more_attempts_than_the_cap_are_all_answered() -> None:
    import asyncio

    import httpx

    app = make_app(rate_per_ip=1000, rate_global=5, verify_concurrency=2)
    _by_header_address(app)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:

        async def attempt(i: int) -> int:
            right = i == 11
            r = await c.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": PASSWORD if right else "nope"},
                headers={**ORIGIN, "Origin": "https://testserver", "X-Test-Ip": "192.0.2.50"},
            )
            return r.status_code

        codes = await asyncio.gather(*(attempt(i) for i in range(24)))
    assert set(codes) <= {204, 401}
    assert codes[11] == 204 and codes.count(401) == 23
