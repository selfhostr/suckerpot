"""Report effect measure (M38 G1): strata, matching, the observation check and the holdout draw."""

from __future__ import annotations

from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from ingest.abuse.candidates import holdout_roll
from ingest.abuse.config import AbuseSettings
from ingest.takedown.effect import observed, source_of
from ingest.takedown.effect_match import (
    UNKNOWN,
    Source,
    activity_class,
    asn_count_class,
    block_class,
    match,
    recency_bucket,
    volume_bucket,
)

D = date(2026, 11, 10)


def src(value: str, **kw: object) -> Source:
    base: dict[str, object] = {
        "activity": "login", "volume": 1, "recency": 0, "asn": 64500, "country": "NL",
        "size": (0, 1), "held": False,
    }  # fmt: skip
    base.update(kw)
    return Source(value, **base)  # type: ignore[arg-type]


# ---- strata ---------------------------------------------------------------------------------


def test_activity_class_takes_the_strongest_activity() -> None:
    def cls(**kw: object) -> str:
        args = {"logins": 0, "login_commands": False, "downloads": 0, "severe": False, **kw}
        return activity_class(**args)  # type: ignore[arg-type]

    assert cls(logins=60) == "login"
    assert cls(logins=3, login_commands=True) == "login_commands"
    assert cls(logins=3, login_commands=True, downloads=1) == "download"
    assert cls(logins=3, downloads=1, severe=True) == "exploit"
    assert cls() == "other"


@pytest.mark.parametrize(
    ("events", "bucket"),
    [(0, 0), (1, 0), (9, 0), (10, 1), (99, 1), (100, 2), (999, 2), (1000, 3), (10**6, 3)],
)
def test_volume_buckets(events: int, bucket: int) -> None:
    assert volume_bucket(events) == bucket


@pytest.mark.parametrize(
    ("days", "bucket"), [(0, 0), (1, 1), (2, 1), (3, 2), (6, 2), (7, None), (-1, None)]
)
def test_recency_buckets(days: int, bucket: int | None) -> None:
    assert recency_bucket(days) == bucket


def test_provider_size_parts() -> None:
    assert block_class(24, ipv6=False) == 0 and block_class(28, ipv6=False) == 0
    assert block_class(23, ipv6=False) == 1 and block_class(16, ipv6=False) == 1
    assert block_class(15, ipv6=False) == 2
    assert block_class(48, ipv6=True) == 0 and block_class(32, ipv6=True) == 1
    assert block_class(29, ipv6=True) == 2
    assert block_class(None, ipv6=False) == UNKNOWN
    assert [asn_count_class(n) for n in (1, 2, 9, 10, 99, 100)] == [0, 1, 1, 2, 2, 3]
    assert asn_count_class(None) == UNKNOWN and asn_count_class(0) == UNKNOWN


def test_source_of_counts_on_whole_days_up_to_the_index_day() -> None:
    row = SimpleNamespace(
        ip="198.51.100.10", logins=60, logcmd=False, downloads=0, severe=False, events=60,
        last_day=D - timedelta(days=1), asn=64500, country="NL",
    )  # fmt: skip
    s = source_of(row, D, {"198.51.100.10": (0, 2)}, held=False)
    assert s is not None
    assert (s.activity, s.volume, s.recency, s.size) == ("login", 1, 1, (0, 2))
    assert source_of(SimpleNamespace(**{**row.__dict__, "events": None}), D, {}, False) is None
    stale = SimpleNamespace(**{**row.__dict__, "last_day": D - timedelta(days=7)})
    assert source_of(stale, D, {}, False) is None


# ---- matching -------------------------------------------------------------------------------


def test_exact_strata_are_required() -> None:
    r = src("192.0.2.1")
    pool = [
        src("192.0.2.10", activity="download"),
        src("192.0.2.11", volume=2),
        src("192.0.2.12", recency=1),
    ]
    pairs, left = match([r], pool)
    assert pairs == [] and left == [r]


def test_tier_order_holdout_then_asn_then_size_and_country_then_size() -> None:
    r = src("192.0.2.1", asn=64500, country="NL", size=(0, 1))
    c_size = src("192.0.2.13", asn=64503, country="DE", size=(0, 1))
    c_country = src("192.0.2.12", asn=64502, country="NL", size=(0, 1))
    c_asn = src("192.0.2.11", asn=64500, country="DE", size=(2, 3))
    c_held = src("192.0.2.10", asn=64999, country="US", size=(2, 3), held=True)
    pool = [c_size, c_country, c_asn, c_held]
    for expected, tier in ((c_held, "H"), (c_asn, "A"), (c_country, "B"), (c_size, "C")):
        pairs, _ = match([r], pool)
        assert pairs[0].control == expected and pairs[0].tier == tier
        pool.remove(expected)
    pairs, left = match([r], [src("192.0.2.14", asn=64504, country="NL", size=(1, 1))])
    assert pairs == [] and left == [r]  # another size class is no match


def test_a_control_is_used_once() -> None:
    r1, r2 = src("192.0.2.1"), src("192.0.2.2")
    only = src("192.0.2.10")
    pairs, left = match([r1, r2], [only])
    assert [p.reported for p in pairs] == [r1] and left == [r2]


def test_matching_is_deterministic_whatever_the_pool_order() -> None:
    r = src("192.0.2.1")
    pool = [src(f"192.0.2.{i}") for i in range(10, 30)]
    first, _ = match([r], pool)
    again, _ = match([r], list(reversed(pool)))
    assert first[0].control == again[0].control


def test_unknown_asn_never_matches_as_same_asn() -> None:
    r = src("192.0.2.1", asn=None, country=None, size=(0, 1))
    c = src("192.0.2.10", asn=None, country=None, size=(1, 1))
    assert match([r], [c])[0] == []


# ---- observation check ----------------------------------------------------------------------


def test_a_window_with_the_node_down_is_not_observed() -> None:
    first = D + timedelta(days=7)
    up = {first + timedelta(days=i): 25 for i in range(7)}
    assert observed(up, D, 7)
    one_down = {**up, first + timedelta(days=3): 2}
    assert observed(one_down, D, 7)  # 6 of 7 days is enough
    two_down = {**one_down, first + timedelta(days=5): 0}
    assert not observed(two_down, D, 7)
    assert not observed({}, D, 7)  # nothing recorded: not observed, never "not seen"
    assert not observed(up, D, 30)


# ---- holdout --------------------------------------------------------------------------------


def test_holdout_roll() -> None:
    assert holdout_roll(0, lambda _n: 0) is False
    assert holdout_roll(10, lambda _n: 999) is True
    assert holdout_roll(10, lambda _n: 1000) is False


def test_holdout_setting_is_off_by_default_and_at_most_ten() -> None:
    assert AbuseSettings.from_env({}).holdout_pct == 0
    assert AbuseSettings.from_env({"ABUSE_EFFECT_HOLDOUT_PCT": "10"}).holdout_pct == 10
    with pytest.raises(ValueError, match="ABUSE_EFFECT_HOLDOUT_PCT"):
        AbuseSettings.from_env({"ABUSE_EFFECT_HOLDOUT_PCT": "11"})


# ---- the worker -----------------------------------------------------------------------------


async def test_the_worker_follows_abuse_reporting_not_takedown_tracking() -> None:
    from ingest.features import FeatureSettings
    from ingest.takedown.effect import ReportEffectWorker

    on = ReportEffectWorker(
        FeatureSettings(abuse_enabled=True, takedown_enabled=False),
        env={"ABUSE_EFFECT_HOLDOUT_PCT": "5", "ABUSE_MIN_LOGIN_ATTEMPTS": "20"},
    )
    assert on.enabled and on.holdout_pct == 5 and on.cfg.min_login_attempts == 20
    status = (await on.status())["report_effect"]
    assert status["enabled"] is True and status["holdout_pct"] == 5
    off = ReportEffectWorker(FeatureSettings(abuse_enabled=False, takedown_enabled=True))
    assert not off.enabled and off.holdout_pct == 0
    await off.run_once()  # no database: nothing happens
