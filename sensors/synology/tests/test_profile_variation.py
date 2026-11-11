"""Model, host name and serial differ per install, agree with each other, and are stable."""

from __future__ import annotations

from synology_sensor.config import DSM_VERSION
from synology_sensor.profile import _NAMES, MODELS, Profile, build_profile

CREATED = 1_790_000_000.0  # 2026


def _fleet(n: int = 120) -> list[Profile]:
    return [build_profile(bytes([i % 250 + 1, i // 250 + 1]) * 16, CREATED) for i in range(n)]


def test_profile_is_stable_for_one_secret() -> None:
    assert build_profile(b"q" * 32, CREATED) == build_profile(b"q" * 32, CREATED)


def test_pools_are_wide_and_real_looking() -> None:
    assert len(MODELS) >= 25 and len(_NAMES) >= 25
    assert all(n.replace("+", "").isalnum() for n in MODELS)
    # DSM 7.2.1 is what the sensor claims: every model must run it.
    assert DSM_VERSION.startswith("7.2")


def test_model_arch_and_serial_year_agree() -> None:
    fleet = _fleet()
    assert len({p.model for p in fleet}) > 15
    assert len({p.arch for p in fleet}) > 3
    for p in fleet:
        arch, launched = MODELS[p.model]
        assert p.arch == arch
        year = 2000 + int(p.serial[:2])
        assert max(launched, 2018) <= year <= 2026
        assert p.hostname.isalnum()
