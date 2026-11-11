"""Takedown routes (M27): the parts that need no database."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from api import takedown
from api.takedown import like, make_fact, section, ttd_seconds_of

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def row(**kw: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "role": "payload_url", "provider_key": "as64500", "reported_at": NOW - timedelta(days=5),
        "first_down_at": None, "down_before_report": False, "demo": False,
        "track_until": NOW + timedelta(days=25), "stopped_at": None,
    }  # fmt: skip
    base.update(kw)
    return SimpleNamespace(**base)


def test_a_target_not_observed_for_the_window_is_left_out() -> None:
    old = row(reported_at=NOW - timedelta(days=10), first_down_at=NOW - timedelta(days=9))
    young = row(reported_at=NOW - timedelta(hours=10))
    young_gone = row(reported_at=NOW - timedelta(hours=10), first_down_at=NOW - timedelta(hours=8))
    still_up = row(reported_at=NOW - timedelta(days=10))
    out = section([make_fact(r, NOW) for r in (old, young, young_gone, still_up)])
    assert (out.eligible_48h, out.down_48h) == (3, 2)  # `young` says nothing about 48 hours
    assert out.tracked == 4


def test_a_stopped_target_is_observed_only_until_the_stop() -> None:
    stopped = row(reported_at=NOW - timedelta(days=10), stopped_at=NOW - timedelta(days=9))
    out = section([make_fact(stopped, NOW)])
    assert out.eligible_48h == 0 and out.eligible_7d == 0
    fact = make_fact(stopped, NOW)
    assert fact.tracked_to_end is False


def test_still_up_after_tracking() -> None:
    done = row(reported_at=NOW - timedelta(days=40), track_until=NOW - timedelta(days=10))
    out = section([make_fact(done, NOW)])
    assert out.still_up_30d == 1 and out.eligible_30d == 1 and out.down_30d == 0


def test_ttd_of_a_row_hides_targets_that_were_down_before_the_report() -> None:
    gone = row(first_down_at=NOW - timedelta(days=5) + timedelta(hours=19))
    assert ttd_seconds_of(gone) == 19 * 3600
    assert ttd_seconds_of(row()) is None
    assert ttd_seconds_of(row(role="c2", first_down_at=NOW)) is None  # c2 is never a takedown
    before = row(first_down_at=NOW - timedelta(days=5), down_before_report=True)
    assert ttd_seconds_of(before) is None
    out = takedown.to_out(
        SimpleNamespace(
            id=1, kind="url", role="payload_url", value="http://files.example.net/a",
            parent_id=None,
            provider_key="as64500", provider_name=None, asn=64500, country="NL",
            reported_at=NOW - timedelta(days=5), channels=["mail"], state="down",
            state_source="http", state_since=NOW, tracking=True, track_until=NOW,
            http_eligible=True,
            demo=False, down_before_report=True, last_up_at=None,
            first_down_at=NOW - timedelta(days=5), resurrections=0, last_check_at=None,
        )
    )  # fmt: skip
    assert out.ttd_s is None


def test_like_escapes_wildcards() -> None:
    assert like("a_b%c") == "%a\\_b\\%c%"


def test_the_api_has_no_route_out() -> None:
    """The module may not build an HTTP client: the API never contacts a target or abuse.ch."""
    import ast
    from pathlib import Path

    for module in (takedown,):
        tree = ast.parse(Path(module.__file__ or "").read_text())
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not names & {"httpx", "requests", "aiohttp", "socket", "urllib"}, module.__name__
