import asyncio
import ipaddress
import time
from typing import Any, cast

import pytest
from argon2 import PasswordHasher

from api.auth import (
    MIN_SECRET_BYTES,
    AuthConfigError,
    AuthService,
    AuthSettings,
)

FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
PASSWORD = "correct horse battery staple"
PW_HASH = FAST.hash(PASSWORD)
SECRET = "s" * 40


def settings(**kw: object) -> AuthSettings:
    base = {"username": "admin", "password_hash": PW_HASH, "secret": SECRET.encode()}
    return AuthSettings(**{**base, **kw})  # type: ignore[arg-type]


def env(**kw: str) -> dict[str, str]:
    return {"ADMIN_PASSWORD_HASH": PW_HASH, "SESSION_SECRET": SECRET, **kw}


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def test_from_env_defaults() -> None:
    s = AuthSettings.from_env(env())
    assert s.username == "admin"
    assert s.cookie_secure is True
    assert s.ttl_hours == 12
    assert (s.rate_per_ip, s.rate_global) == (5, 30)
    assert s.disabled is False


def test_from_env_overrides() -> None:
    s = AuthSettings.from_env(
        env(
            ADMIN_USERNAME="root",
            COOKIE_SECURE="false",
            SESSION_TTL_HOURS="1",
            LOGIN_RATE="2",
            LOGIN_RATE_GLOBAL="3",
        )
    )
    assert (s.username, s.cookie_secure, s.ttl_hours, s.rate_per_ip, s.rate_global) == (
        "root",
        False,
        1,
        2,
        3,
    )


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"ADMIN_PASSWORD_HASH": "", "SESSION_SECRET": SECRET},
        {"ADMIN_PASSWORD_HASH": "plaintext", "SESSION_SECRET": SECRET},
        {"ADMIN_PASSWORD_HASH": "$argon2id$garbage", "SESSION_SECRET": SECRET},
        {"ADMIN_PASSWORD_HASH": PW_HASH, "SESSION_SECRET": "x" * (MIN_SECRET_BYTES - 1)},
        {"ADMIN_PASSWORD_HASH": PW_HASH, "SESSION_SECRET": "change-me"},
    ],
)
def test_refuses_to_start_on_bad_config(bad: dict[str, str]) -> None:
    with pytest.raises(AuthConfigError):
        AuthSettings.from_env(bad)


def test_disabled_skips_validation_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        s = AuthSettings.from_env({"API_AUTH_DISABLED": "true", "SUCKERPOT_DEMO": "1"})
    assert s.disabled
    assert "OPEN" in caplog.text


def test_allow_default_secrets_keeps_ci_working(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        s = AuthSettings.from_env({"SUCKERPOT_ALLOW_DEFAULT_SECRETS": "1"})
    assert not s.disabled and s.password_hash is None and len(s.secret) >= MIN_SECRET_BYTES
    assert "Never use this in production" in caplog.text


async def test_login_impossible_without_hash_in_ci_mode() -> None:
    svc = AuthService(AuthSettings.from_env({"SUCKERPOT_ALLOW_DEFAULT_SECRETS": "1"}))
    assert not await svc.check_credentials("admin", "anything at all")


def test_token_roundtrip_and_tamper() -> None:
    svc = AuthService(settings())
    token, info = svc.issue()
    assert svc.validate(token) == info
    assert svc.validate(token[:-2] + "xx") is None
    assert svc.validate(None) is None
    assert svc.validate("") is None
    assert svc.validate("v1.1.2.3") is None
    assert svc.validate("v1.a.b.c.d") is None
    assert svc.validate("x" * 600) is None
    forged = token.replace(f".{info.expires_at}.", f".{info.expires_at + 99999}.")
    assert svc.validate(forged) is None


def test_token_from_other_secret_or_password_rejected() -> None:
    token, _ = AuthService(settings()).issue()
    assert AuthService(settings(secret=b"z" * 40)).validate(token) is None
    assert (
        AuthService(settings(password_hash=FAST.hash("another password!"))).validate(token) is None
    )
    assert AuthService(settings(username="other")).validate(token) is None


def test_expiry() -> None:
    clock = Clock()
    svc = AuthService(settings(ttl_hours=1), clock)
    token, info = svc.issue()
    assert info.expires_at - info.issued_at == 3600
    clock.now += 3599
    assert svc.validate(token) is not None
    clock.now += 2
    assert svc.validate(token) is None


def test_revocation() -> None:
    svc = AuthService(settings())
    token, info = svc.issue()
    svc.revoke(info)
    assert svc.validate(token) is None
    other, _ = svc.issue()
    assert svc.validate(other) is not None


def test_revocation_set_is_bounded() -> None:
    svc = AuthService(settings())
    for _ in range(1500):
        _, info = svc.issue()
        svc.revoke(info)
    assert len(svc._revoked) <= 1000


def test_disabled_validates_everything() -> None:
    svc = AuthService(settings(disabled=True))
    assert svc.validate(None) is not None


def test_csrf_token() -> None:
    svc = AuthService(settings())
    t = svc.new_csrf()
    assert svc.csrf_ok(t, t)
    assert not svc.csrf_ok(t, None)
    assert not svc.csrf_ok(None, t)
    assert not svc.csrf_ok(t, svc.new_csrf())
    planted = "attacker.value"
    assert not svc.csrf_ok(planted, planted)  # equal but not signed by us
    assert not svc.csrf_ok("a" * 500, "a" * 500)


async def test_credentials() -> None:
    svc = AuthService(settings())
    assert await svc.check_credentials("admin", PASSWORD)
    assert not await svc.check_credentials("admin", "wrong password")
    assert not await svc.check_credentials("nobody", PASSWORD)
    assert not await svc.check_credentials("", "")


async def test_unknown_user_and_bad_password_take_similar_time() -> None:
    """Both paths run the same argon2 verification; compare medians loosely."""
    hasher = PasswordHasher(time_cost=2, memory_cost=16 * 1024, parallelism=1)
    svc = AuthService(settings(password_hash=hasher.hash(PASSWORD)))

    async def fastest(user: str) -> float:
        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            await svc.check_credentials(user, "wrong password")
            samples.append(time.perf_counter() - t0)
        return min(samples)  # the minimum is the least noisy on a busy machine

    known, unknown = await fastest("admin"), await fastest("nobody")
    assert 0.5 < known / unknown < 2.0


def test_rate_limit_per_ip_and_sign_in_has_no_global_refusal() -> None:
    clock = Clock()
    svc = AuthService(settings(rate_per_ip=3, rate_global=5), clock)
    assert [svc.rate_limited("192.0.2.1") for _ in range(3)] == [None] * 3
    retry = svc.rate_limited("192.0.2.1")
    assert retry is not None and 1 <= retry <= 61
    assert svc.rate_limited("192.0.2.2") is None  # other IP unaffected
    assert not svc.under_pressure()
    for _ in range(5):
        svc.record_failure("192.0.2.2")
    # The global budget is spent: it only slows wrong answers down, nobody is refused for it.
    assert svc.under_pressure()
    assert svc.rate_limited("192.0.2.3") is None
    clock.now += 61
    assert not svc.under_pressure()
    assert svc.rate_limited("192.0.2.1") is None  # window slid


def test_rate_limit_tracking_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.auth as mod

    monkeypatch.setattr(mod, "MAX_TRACKED_IPS", 3)
    svc = AuthService(settings(rate_per_ip=10, rate_global=1000))
    for i in range(3):
        assert svc.rate_limited(f"192.0.2.{i}") is None
    assert svc.rate_limited("198.51.100.9") is not None  # full of live entries: refuse
    assert len(svc._per_ip) == 3


async def test_verify_is_off_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = AuthService(settings())
    real_verify = svc._verify

    def slow_verify(password: str) -> bool:
        # The FAST test hash is checked in microseconds, so whether the loop got a turn depended
        # on thread scheduling. A real argon2 check takes tens of milliseconds: model that, so a
        # check run on the loop thread can never let the ticker run, and one off it always does.
        time.sleep(0.05)
        return real_verify(password)

    monkeypatch.setattr(svc, "_verify", slow_verify)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0)
            ticks += 1

    t = asyncio.create_task(ticker())
    await asyncio.sleep(0)  # let the ticker reach its first await
    before = ticks
    await svc.check_credentials("admin", PASSWORD)
    t.cancel()
    # The loop must have run the ticker at least once while the hash was being checked.
    assert ticks > before


def test_csrf_is_bound_to_the_session() -> None:
    svc = AuthService(settings())
    t = svc.new_csrf("session-a")
    assert svc.csrf_ok(t, t, "session-a")
    assert not svc.csrf_ok(t, t, "session-b")
    assert not svc.csrf_ok(t, t)  # a pre-login token is worthless once logged in


def test_cookie_names_follow_cookie_secure() -> None:
    assert AuthService(settings()).cookie_name == "__Host-sp_session"
    assert AuthService(settings()).csrf_cookie_name == "__Host-sp_csrf"
    plain = AuthService(settings(cookie_secure=False))
    assert (plain.cookie_name, plain.csrf_cookie_name) == ("sp_session", "sp_csrf")


def test_restart_signs_everybody_out() -> None:
    token, _ = AuthService(settings()).issue()
    assert AuthService(settings()).validate(token) is None


def test_disabled_requires_demo_flag() -> None:
    with pytest.raises(AuthConfigError):
        AuthSettings.from_env({"API_AUTH_DISABLED": "true"})


def test_trusted_proxies_must_be_cidrs() -> None:
    with pytest.raises(AuthConfigError):
        AuthSettings.from_env(env(AUTH_TRUSTED_PROXIES="nonsense"))
    s = AuthSettings.from_env(env(AUTH_TRUSTED_PROXIES="192.0.2.0/24, 2001:db8::/32"))
    assert len(s.trusted_proxies) == 2


def test_rate_key_groups_ipv6_by_64() -> None:
    from api.auth import rate_key

    assert rate_key("203.0.113.9") == "203.0.113.9"
    assert rate_key("2001:db8:1:2::1") == rate_key("2001:db8:1:2:ffff::9")
    assert rate_key("2001:db8:1:2::1") != rate_key("2001:db8:1:3::1")


def test_ipv6_clients_share_one_budget() -> None:
    svc = AuthService(settings(rate_per_ip=2, rate_global=100))
    assert svc.rate_limited("2001:db8:1:2::1") is None
    assert svc.rate_limited("2001:db8:1:2::2") is None
    assert svc.rate_limited("2001:db8:1:2::3") is not None


class FakeConn:
    def __init__(self, peer: str, headers: dict[str, str]) -> None:
        from types import SimpleNamespace

        self.client = SimpleNamespace(host=peer)
        self.headers = headers


def ip_of(svc: AuthService, peer: str, headers: dict[str, str]) -> str:
    return svc.client_ip(cast("Any", FakeConn(peer, headers)))


def test_client_ip_ignores_forwarding_headers_from_untrusted_peers() -> None:
    cf = {"cf-connecting-ip": "203.0.113.5"}
    assert ip_of(AuthService(settings()), "198.51.100.7", cf) == "198.51.100.7"
    svc = AuthService(settings(trusted_proxies=(ipaddress.ip_network("192.0.2.0/24"),)))
    assert ip_of(svc, "198.51.100.7", cf) == "198.51.100.7"
    assert ip_of(svc, "192.0.2.3", cf) == "203.0.113.5"
    xff = {"x-forwarded-for": "1.2.3.4, 203.0.113.8, 192.0.2.9"}
    assert ip_of(svc, "192.0.2.3", xff) == "203.0.113.8"
    assert ip_of(svc, "192.0.2.3", {"cf-connecting-ip": "garbage"}) == "192.0.2.3"


def test_allowed_hosts() -> None:
    from api.auth import allowed_hosts_from_env

    assert allowed_hosts_from_env({}) == ["*"]
    hosts = allowed_hosts_from_env({"API_ALLOWED_ORIGINS": "https://dash.example.com:8443"})
    assert "dash.example.com" in hosts and "localhost" in hosts and "127.0.0.1" in hosts
    explicit = allowed_hosts_from_env(
        {"API_ALLOWED_HOSTS": "A.example.com", "API_ALLOWED_ORIGINS": "https://x.example"}
    )
    assert explicit[0] == "a.example.com" and "x.example" not in explicit


async def test_password_checks_are_capped_and_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    svc = AuthService(settings(verify_concurrency=2))
    gate = threading.Event()
    running = 0
    peak = 0
    lock = threading.Lock()

    def slow(_: str) -> bool:
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        gate.wait(2)
        with lock:
            running -= 1
        return False

    monkeypatch.setattr(svc, "_verify", slow)
    tasks = [asyncio.create_task(svc.check_credentials("admin", "x")) for _ in range(6)]
    await asyncio.sleep(0.05)
    assert running == 2  # the rest are queued, not refused
    gate.set()
    assert await asyncio.gather(*tasks) == [False] * 6
    assert peak == 2


async def test_a_check_that_waits_too_long_gets_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    from api.auth import LoginBusy

    svc = AuthService(settings(verify_concurrency=1, verify_wait_s=0.5))
    gate = threading.Event()
    monkeypatch.setattr(svc, "_verify", lambda _: gate.wait(2) and False)
    first = asyncio.create_task(svc.check_credentials("admin", "x"))
    await asyncio.sleep(0.05)
    with pytest.raises(LoginBusy):
        await svc.check_credentials("admin", "x")
    gate.set()
    await first
    assert await svc.check_hash(PW_HASH, PASSWORD)  # the slot is free again


def test_verify_limits_from_env() -> None:
    d = AuthSettings.from_env(env())
    assert (d.verify_concurrency, d.verify_wait_s) == (2, 5.0)
    s = AuthSettings.from_env(env(LOGIN_VERIFY_CONCURRENCY="3", LOGIN_VERIFY_WAIT="1.5"))
    assert (s.verify_concurrency, s.verify_wait_s) == (3, 1.5)


def test_tokens_carry_the_subject_and_the_session_version() -> None:
    svc = AuthService(settings())
    owner_token, owner = svc.issue()
    assert owner.subject == "o" and owner.user_id is None and owner.version == 0
    token, info = svc.issue("u42", 3)
    assert info.user_id == 42 and info.version == 3
    assert svc.validate(token) == info
    assert token.split(".")[:3] == ["v2", "u42", "3"]
    assert svc.validate(owner_token) == owner
    # The subject and the version are signed: swapping them breaks the signature.
    assert svc.validate(token.replace(".u42.", ".u43.")) is None
    assert svc.validate(token.replace(".u42.3.", ".u42.4.")) is None
    # Subjects must be "o" or "u<digits>".
    parts = token.split(".")
    parts[1] = "x1"
    assert svc.validate(".".join(parts)) is None


def test_old_v1_tokens_are_rejected() -> None:
    svc = AuthService(settings())
    assert svc.validate("v1.1.99999999999.nonce.sig") is None


def test_rate_limit_per_username_counts_failures_across_addresses() -> None:
    clock = Clock()
    svc = AuthService(settings(rate_per_ip=50, rate_global=500, rate_per_user=3), clock)
    for i in range(3):
        assert svc.rate_limited(f"192.0.2.{i + 1}", username="Alice") is None
        svc.record_failure(f"192.0.2.{i + 1}", username="Alice")
    assert svc.rate_limited("192.0.2.9", username="alice") is not None  # case-insensitive
    assert svc.rate_limited("192.0.2.9", username="bob") is None  # another account is unaffected
    assert svc.rate_limited("192.0.2.9") is None  # no name (the owner): never limited by name
    clock.now += 61
    assert svc.rate_limited("192.0.2.9", username="alice") is None


def test_successes_do_not_use_up_the_account_or_global_windows() -> None:
    svc = AuthService(settings(rate_per_ip=100, rate_global=3, rate_per_user=3), Clock())
    for i in range(30):
        assert svc.rate_limited(f"192.0.2.{i}", username="alice") is None  # no failures recorded


def test_reauth_has_its_own_windows() -> None:
    svc = AuthService(settings(rate_per_ip=100, rate_global=2), Clock())
    svc.record_failure("192.0.2.1", "reauth")
    svc.record_failure("192.0.2.1", "reauth")
    assert svc.rate_limited("192.0.2.1", "reauth") is not None
    assert svc.rate_limited("192.0.2.1") is None  # login is untouched


def test_source_lock_grows_and_is_per_source() -> None:
    clock = Clock()
    svc = AuthService(settings(), clock)
    for _ in range(5):
        svc.source_failed(7, "203.0.113.9")
    assert svc.source_locked(7, "203.0.113.9")
    assert not svc.source_locked(7, "192.0.2.1")  # another source
    assert not svc.source_locked(8, "203.0.113.9")  # another account
    clock.now += 61
    assert not svc.source_locked(7, "203.0.113.9")  # first lock: one minute
    for _ in range(5):
        svc.source_failed(7, "203.0.113.9")
    clock.now += 61
    assert svc.source_locked(7, "203.0.113.9")  # second lock: two minutes
    clock.now += 60
    assert not svc.source_locked(7, "203.0.113.9")
    svc.source_ok(7, "203.0.113.9")
    for _ in range(5):
        svc.source_failed(7, "203.0.113.9")
    clock.now += 61
    assert not svc.source_locked(7, "203.0.113.9")  # a success reset the strikes
    svc.clear_sources(7)
    assert not svc._sources


def test_source_lock_is_capped_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.auth as mod

    clock = Clock()
    svc = AuthService(settings(), clock)
    for _ in range(40):
        for _ in range(5):
            svc.source_failed(1, "203.0.113.9")
        clock.now += mod.SOURCE_LOCK_MAX_S + 1
    assert svc._sources[(1, "203.0.113.9")].locked_until - clock.now < mod.SOURCE_LOCK_MAX_S
    monkeypatch.setattr(mod, "MAX_TRACKED_SOURCES", 3)
    for i in range(10):
        svc.source_failed(100 + i, "x")
    assert len(svc._sources) <= 3


async def test_check_hash_with_no_hash_costs_a_verification_and_fails() -> None:
    svc = AuthService(settings())
    calls: list[str] = []
    real = svc.verify_hash

    def spy(hashed: str, password: str) -> bool:
        calls.append(hashed)
        return real(hashed, password)

    svc.verify_hash = spy  # type: ignore[method-assign]
    assert not await svc.check_hash(None, PASSWORD)
    assert len(calls) == 1  # the dummy hash was verified: same work as for a real user
    assert await svc.check_hash(PW_HASH, PASSWORD)
    assert not await svc.check_hash(PW_HASH, "wrong password")
    assert svc.is_owner_name("admin") and not svc.is_owner_name("Admin")


def _spend_global_budget(svc: AuthService) -> None:
    for _ in range(svc.settings.rate_global):
        svc.record_failure("192.0.2.9")
    assert svc.under_pressure()


async def test_under_pressure_a_wrong_attempt_holds_its_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import api.auth as auth_mod

    monkeypatch.setattr(auth_mod, "PRESSURE_DELAY_S", 0.4)
    svc = AuthService(settings(verify_concurrency=1, rate_global=2))
    _spend_global_budget(svc)
    task = asyncio.create_task(svc.check_hash(None, "wrong"))
    await asyncio.sleep(0.2)  # the check is done, the slot is still held
    assert svc._verify_sem.locked() and not task.done()
    await task
    assert not svc._verify_sem.locked() and svc._pending == 0


async def test_the_hold_survives_a_cancelled_request(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.auth as auth_mod

    monkeypatch.setattr(auth_mod, "PRESSURE_DELAY_S", 0.4)
    svc = AuthService(settings(verify_concurrency=1, rate_global=2))
    _spend_global_budget(svc)
    task = asyncio.create_task(svc.check_hash(None, "wrong"))
    await asyncio.sleep(0.2)
    task.cancel()  # the client went away
    with pytest.raises(asyncio.CancelledError):
        await task
    assert svc._verify_sem.locked()  # the slot is not freed early
    await asyncio.sleep(0.5)
    assert not svc._verify_sem.locked() and svc._pending == 0


async def test_a_right_password_is_never_held_under_pressure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import api.auth as auth_mod

    monkeypatch.setattr(auth_mod, "PRESSURE_DELAY_S", 5.0)
    svc = AuthService(settings(verify_concurrency=1, rate_global=2))
    _spend_global_budget(svc)
    start = time.monotonic()
    assert await svc.check_credentials("admin", PASSWORD)
    assert time.monotonic() - start < 2.0
    assert not svc._verify_sem.locked()
    assert svc.rate_limited("192.0.2.77") is None  # nothing refuses the owner outright


async def test_the_pending_cap_answers_busy_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    import api.auth as auth_mod
    from api.auth import LoginBusy

    monkeypatch.setattr(auth_mod, "MAX_VERIFY_PENDING", 4)
    svc = AuthService(settings(verify_concurrency=1, verify_wait_s=30))
    gate = threading.Event()
    monkeypatch.setattr(svc, "_verify", lambda _: gate.wait(5) and False)
    tasks = [asyncio.create_task(svc.check_credentials("admin", "x")) for _ in range(4)]
    await asyncio.sleep(0.05)
    start = time.monotonic()
    with pytest.raises(LoginBusy):
        await svc.check_credentials("admin", "x")
    assert time.monotonic() - start < 1.0  # no waiting on the semaphore
    gate.set()
    await asyncio.gather(*tasks)
    assert svc._pending == 0


def test_verify_concurrency_is_clamped_with_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        assert AuthSettings.from_env(env(LOGIN_VERIFY_CONCURRENCY="50")).verify_concurrency == 4
        assert AuthSettings.from_env(env(LOGIN_VERIFY_CONCURRENCY="0")).verify_concurrency == 1
    assert caplog.text.count("LOGIN_VERIFY_CONCURRENCY") == 2
    caplog.clear()
    with caplog.at_level("WARNING"):
        assert AuthSettings.from_env(env(LOGIN_VERIFY_CONCURRENCY="3")).verify_concurrency == 3
    assert "LOGIN_VERIFY_CONCURRENCY" not in caplog.text
