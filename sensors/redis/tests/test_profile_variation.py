"""The fake Redis differs per install and stays stable for one install."""

from __future__ import annotations

from redis_sensor.commands import ClientState, execute
from redis_sensor.identity import KERNELS, derive_profile
from redis_sensor.info import ServerContext


def _secret(i: int) -> str:
    return f"{i:02x}" * 32


def test_profile_is_stable_for_one_secret() -> None:
    assert derive_profile(_secret(7)) == derive_profile(_secret(7))


def test_keyspace_differs_between_installs() -> None:
    fleet = [derive_profile(_secret(i)) for i in range(1, 30)]
    keysets = {tuple(k for k, _ in p.keys) for p in fleet}
    assert len(keysets) == len(fleet)
    # No single key name or value is shared by the whole fleet.
    common = set.intersection(*({k for k, _ in p.keys} for p in fleet))
    assert common == set()
    assert len({len(p.keys) for p in fleet}) > 3
    assert any(p.ttls for p in fleet)
    for p in fleet:
        assert {k for k, _, _ in p.ttls} <= {k for k, _ in p.keys}
        assert all(0 < len(v) <= 2048 for _, v in p.keys)


def test_server_section_facts_look_like_a_host_install() -> None:
    fleet = [derive_profile(_secret(i)) for i in range(1, 30)]
    assert len({p.process_id for p in fleet}) > 10
    for p in fleet:
        assert p.process_id > 1
        assert p.executable.endswith("/redis-server") and not p.executable.startswith("/data")
        assert p.config_file.endswith(".conf") and p.workdir.startswith("/")
        assert p.kernel in KERNELS
        assert p.gcc_version in ("13.2.0", "13.3.0")
        assert len(p.git_sha1) == 8
        if p.executable.startswith("/usr/bin/"):
            assert p.git_sha1 == "00000000"
    assert len({p.executable for p in fleet}) > 1
    assert len({p.kernel for p in fleet}) > 3


def _ttl(state: ClientState, key: bytes) -> int:
    reply = execute(state, [b"TTL", key])[1].reply
    return int(reply[1:].split(b"\r\n")[0])


def _ctx_with_ttls() -> tuple[ServerContext, list[tuple[bytes, int, int]], list[float]]:
    for i in range(1, 60):
        prof = derive_profile(_secret(i))
        if len(prof.ttls) >= 2:
            now = [1000.0]

            def clock(box: list[float] = now) -> float:
                return box[0]

            ctx = ServerContext(prof, started=1000.0, clock=clock)
            return ctx, list(prof.ttls), now
    raise AssertionError("no profile with two expiring keys")


def test_ttl_is_consistent_across_connections_and_decreases() -> None:
    ctx, ttls, now = _ctx_with_ttls()
    key, life, _ = ttls[0]
    a = ClientState(ctx, 1, "198.51.100.1:1")
    first = _ttl(a, key)
    now[0] += 7
    b = ClientState(ctx, 2, "198.51.100.2:1")  # a new connection does not restart the clock
    second = _ttl(b, key)
    assert second == _ttl(a, key)
    assert first - second == 7 or second > first  # decreased by 7 s, unless it was renewed
    assert 1 <= second <= life


def test_ttl_is_renewed_never_negative_and_keys_differ() -> None:
    ctx, ttls, now = _ctx_with_ttls()
    st = ClientState(ctx, 1, "198.51.100.1:1")
    for step in range(0, 3 * 86400 * 8, 4000):
        now[0] = 1000.0 + step
        for key, life, _ in ttls:
            assert 1 <= _ttl(st, key) <= life
    offsets = {_ttl(st, k) for k, _, _ in ttls}
    assert len(offsets) > 1  # keys of one install do not share a phase


def test_expire_and_persist_change_what_ttl_answers() -> None:
    ctx, ttls, now = _ctx_with_ttls()
    key = ttls[0][0]
    st = ClientState(ctx, 1, "198.51.100.1:1")
    other = ClientState(ctx, 2, "198.51.100.2:1")  # a second connection
    assert execute(st, [b"EXPIRE", key, b"90"])[1].reply == b":1\r\n"
    assert 88 <= _ttl(st, key) <= 90
    assert key not in other.ttl_over  # the override is this connection's own view
    now[0] += 30
    assert 58 <= _ttl(st, key) <= 60
    assert execute(st, [b"PERSIST", key])[1].reply == b":1\r\n"
    assert _ttl(st, key) == -1
    assert execute(st, [b"EXPIRE", key, b"5"])[1].reply == b":1\r\n"
    now[0] += 6
    assert _ttl(st, key) == -2  # lapsed on this connection's view


def test_a_lapsed_key_is_gone_for_every_command() -> None:
    ctx, ttls, now = _ctx_with_ttls()
    key = ttls[0][0]
    st = ClientState(ctx, 1, "198.51.100.1:1")
    assert execute(st, [b"EXPIRE", key, b"5"])[1].reply == b":1\r\n"
    assert execute(st, [b"EXISTS", key])[1].reply == b":1\r\n"
    now[0] += 6
    assert execute(st, [b"EXISTS", key])[1].reply == b":0\r\n"
    assert execute(st, [b"GET", key])[1].reply == b"$-1\r\n"
    assert execute(st, [b"TYPE", key])[1].reply == b"+none\r\n"
    assert key not in execute(st, [b"KEYS", b"*"])[1].reply
    assert _ttl(st, key) == -2


def test_expire_beyond_the_cap_evicts_the_oldest_override() -> None:
    ctx, _, _ = _ctx_with_ttls()
    st = ClientState(ctx, 1, "198.51.100.1:1")
    execute(st, [b"FLUSHALL"])
    for i in range(40):
        key = b"k%d" % i
        execute(st, [b"SET", key, b"v"])
        assert execute(st, [b"EXPIRE", key, b"100"])[1].reply == b":1\r\n"
        assert 98 <= _ttl(st, key) <= 100  # answered 1, so TTL reports it as well
    assert len(st.ttl_over) <= 32
