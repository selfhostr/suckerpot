"""Listing schedule on fixed clocks, and the pure helpers of target sync."""

from datetime import UTC, datetime, timedelta

from ingest.takedown.config import TakedownSettings
from ingest.takedown.schedule import LISTING_OFFSETS, first_listing_at, next_listing_at
from ingest.takedown.sync import (
    host_kind,
    provider_of,
    target_key,
)

REP = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
UNTIL = REP + timedelta(days=30)


def test_listing_slots_are_0_24h_7d_30d() -> None:
    assert LISTING_OFFSETS == (
        timedelta(0), timedelta(hours=24), timedelta(days=7), timedelta(days=30)
    )  # fmt: skip
    assert first_listing_at(REP) == REP
    assert next_listing_at(0, REP, REP, UNTIL + timedelta(days=1)) == (1, REP + timedelta(hours=24))
    assert next_listing_at(1, REP, REP + timedelta(hours=24), UNTIL)[1] == REP + timedelta(days=7)


def test_the_30_day_slot_is_kept_only_inside_the_tracking_period() -> None:
    now = REP + timedelta(days=7)
    assert next_listing_at(2, REP, now, REP + timedelta(days=30)) == (3, REP + timedelta(days=30))
    assert next_listing_at(2, REP, now, REP + timedelta(days=20)) == (4, None)
    assert next_listing_at(3, REP, REP + timedelta(days=30), UNTIL) == (4, None)


def test_a_late_target_skips_past_slots() -> None:
    now = REP + timedelta(days=3)
    assert next_listing_at(0, REP, now, UNTIL) == (2, REP + timedelta(days=7))
    assert next_listing_at(0, REP, REP + timedelta(days=40), UNTIL) == (4, None)


def test_target_key_is_stable_and_hides_the_value() -> None:
    k = target_key("ip", "198.51.100.7")
    assert k == target_key("ip", "198.51.100.7")
    assert len(k) == 64 and "198" not in k
    assert k != target_key("domain", "198.51.100.7")


def test_provider_key_rules() -> None:
    assert provider_of(64500, 9) == "as64500"
    assert provider_of(None, 9) == "recipient:9"
    assert provider_of(None, None) == "unknown"
    assert host_kind("203.0.113.5") == "ip"
    assert host_kind("2001:db8::1") == "ip"
    assert host_kind("files.example.net") == "domain"


def test_settings_defaults_and_bounds() -> None:
    s = TakedownSettings.from_env({})
    assert (s.track_days, s.intel_daily_quota, s.abuseipdb_daily_quota, s.quiet_days) == (
        30, 100, 50, 7
    )  # fmt: skip
    assert not s.include_demo
    assert TakedownSettings.from_env({"ABUSE_REPORTS_INCLUDE_DEMO": "true"}).include_demo
    for bad in ({"TAKEDOWN_TRACK_DAYS": "3"}, {"TAKEDOWN_TRACK_DAYS": "x"}):
        try:
            TakedownSettings.from_env(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
