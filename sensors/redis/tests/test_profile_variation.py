"""The fake Redis differs per install and stays stable for one install."""

from __future__ import annotations

from redis_sensor.identity import KERNELS, derive_profile


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
        assert {k for k, _ in p.ttls} <= {k for k, _ in p.keys}
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
    assert len({p.executable for p in fleet}) > 1
    assert len({p.kernel for p in fleet}) > 3
