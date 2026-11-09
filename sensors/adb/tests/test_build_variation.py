"""Build facts of the fake box differ per install, agree with each other, and are stable."""

from __future__ import annotations

from datetime import UTC, date, datetime

from adb_sensor.device import _BUILDS, derive_device


def _fleet(n: int = 60) -> list:  # type: ignore[type-arg]
    return [derive_device(f"seed-{i}", "", "auto", True) for i in range(n)]


def test_build_is_stable_for_one_seed() -> None:
    a = derive_device("seed-x", "", "auto", True)
    b = derive_device("seed-x", "", "auto", True)
    assert a.build == b.build and a.fingerprint == b.fingerprint


def test_incremental_and_dates_vary_and_agree() -> None:
    fleet = _fleet()
    assert len({d.build.incremental for d in fleet}) > 40
    assert not any(d.build.incremental == "eng.root.20190320.164402" for d in fleet)
    for d in fleet:
        b = d.build
        props = d.getprop()
        assert props["ro.build.version.incremental"] == b.incremental
        assert props["ro.build.fingerprint"] == d.fingerprint
        assert b.incremental in d.fingerprint and b.build_id in d.fingerprint
        assert b.incremental in props["ro.build.display.id"]
        # The incremental is the build time (CST): utc timestamp, text date and id agree.
        stamp = datetime.fromtimestamp(b.date_utc + 8 * 3600, UTC)
        assert b.incremental == f"eng.root.{stamp:%Y%m%d.%H%M%S}"
        assert b.date_text.endswith(f"CST {stamp.year}") and f"{stamp:%H:%M:%S}" in b.date_text
        assert b.kernel_build.endswith(f"CST {stamp.year}") or "CST" in b.kernel_build
        assert int(props["ro.runtime.firstboot"]) > b.date_utc * 1000


def test_patch_level_matches_build_id_and_precedes_the_build() -> None:
    for d in _fleet():
        table = dict(_BUILDS[d.model.sdk])
        assert d.build.build_id in table
        patch = date.fromisoformat(d.build.security_patch)
        assert patch == table[d.build.build_id]
        built = datetime.fromtimestamp(d.build.date_utc, UTC).date()
        assert patch <= built
        assert built >= d.model.kernel_released  # newer than the kernel it ships
