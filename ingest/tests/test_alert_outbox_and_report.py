"""Rate-limit planning, the weekly report summary and its HTML (no database)."""

from datetime import UTC, date, datetime
from typing import Any

import pytest
from suckerpot_db.form_queue import FormQueueCount

from ingest.alerts.outbox import (
    CYCLE_LIMIT,
    DAY_LIMIT,
    GLOBAL_DAY_LIMIT,
    MINUTE_LIMIT,
    Plan,
    Usage,
    plan_channel,
)
from ingest.reports.build import alert_facts, due, previous_week, summarize, window, zone
from ingest.reports.render import render_report


@pytest.mark.parametrize(
    ("count", "usage", "left", "plan"),
    [
        (0, Usage(), CYCLE_LIMIT, Plan.WAIT),
        (3, Usage(), CYCLE_LIMIT, Plan.EACH),
        (MINUTE_LIMIT, Usage(), CYCLE_LIMIT, Plan.EACH),
        (MINUTE_LIMIT + 1, Usage(), CYCLE_LIMIT, Plan.DIGEST),
        (3, Usage(minute=MINUTE_LIMIT), CYCLE_LIMIT, Plan.WAIT),
        (3, Usage(minute=MINUTE_LIMIT - 1), CYCLE_LIMIT, Plan.DIGEST),
        (3, Usage(day=DAY_LIMIT), CYCLE_LIMIT, Plan.DROP),
        (3, Usage(global_day=GLOBAL_DAY_LIMIT), CYCLE_LIMIT, Plan.DROP),
        (3, Usage(), 0, Plan.WAIT),
        (3, Usage(), 2, Plan.DIGEST),
    ],
)
def test_plan(count: int, usage: Usage, left: int, plan: Plan) -> None:
    assert plan_channel(count, usage, left) is plan


def make_summary(**over: object) -> dict[str, Any]:
    args: dict[str, object] = {
        "week_start": date(2026, 10, 12),
        "tz_name": "Europe/Zurich",
        "sessions": 1200,
        "sources": 340,
        "with_commands": 80,
        "malware": 5,
        "previous": 600,
        "by_sensor": [{"sensor": "ssh", "sessions": 900}, {"sensor": "web", "sessions": 300}],
        "countries": [{"country": "NL", "sessions": 400}],
        "tags": [{"tag": "crypto-miner", "sessions": 12}],
        "campaigns": [
            {"id": 4, "name": "Mirai loader #4", "severity": "severe", "sessions": 50, "sources": 9}
        ],
        "hosts": [{"host": "evil[.]example", "sightings": 7}],
        "cves": [{"cve_id": "CVE-2026-0001", "sessions": 3}],
    }
    args.update(over)
    return summarize(**args)  # type: ignore[arg-type]


def test_summary_has_a_plain_headline_and_next_actions() -> None:
    s = make_summary()
    assert s["headline"].startswith("1,200 attack sessions from 340 addresses, up 100%")
    assert "mostly against SSH" in s["headline"]
    text = " ".join(s["actions"])
    assert "Block the 1 new malware download host" in text
    assert "CVE-2026-0001" in text and "SSH" in text
    assert alert_facts(s)[0] == ["Sessions", "1,200 (+100%)"]


def test_quiet_week() -> None:
    s = make_summary(sessions=0, sources=0, with_commands=0, malware=0, previous=0, by_sensor=[],
                     countries=[], tags=[], campaigns=[], hosts=[], cves=[])  # fmt: skip
    assert s["headline"] == "A quiet week: no attack sessions were recorded."
    assert s["actions"] == ["Nothing unusual this week. Keep systems patched and exposure minimal."]


def test_report_html_escapes_everything_and_has_no_script_or_link() -> None:
    evil = '<img src=x onerror=alert(1)>"><script>alert(1)</script>'
    s = make_summary(
        campaigns=[{"id": 1, "name": evil, "severity": evil, "sessions": 1, "sources": 1}],
        tags=[{"tag": evil, "sessions": 1}],
        hosts=[{"host": evil, "sightings": 1}],
        countries=[{"country": evil, "sessions": 1}],
        cves=[{"cve_id": evil, "sessions": 1}],
    )
    s["headline"] = evil
    page = render_report(s, evil)
    assert "<script" not in page and "<img" not in page
    assert "&lt;script&gt;" in page
    for banned in ("http://", "https://", "<a ", "<link", "<iframe"):
        assert banned not in page
    assert page.count("<style>") == 1 and "<!doctype html>" in page
    assert "IP addresses are not included" in page


def test_report_html_names_sensors_and_folds_long_tables() -> None:
    hosts = [{"host": f"h{i}[.]example", "sightings": 10} for i in range(10)]
    page = render_report(make_summary(hosts=hosts))
    assert "<td>SSH</td>" in page and "<td>ssh</td>" not in page
    assert "h6[.]example" in page and "h7[.]example" not in page
    assert '<td class="more">3 more</td><td class="n">30</td>' in page
    assert "Week of Oct 12 to Oct 18, 2026" in page


def test_week_arithmetic_uses_the_site_time_zone() -> None:
    tz = zone("Europe/Zurich")
    monday_morning = datetime(2026, 10, 19, 5, 0, tzinfo=UTC)  # 07:00 local (CEST would be +2)
    assert due(monday_morning, tz)
    assert not due(datetime(2026, 10, 19, 3, 0, tzinfo=UTC), tz)  # 05:00 local
    assert due(datetime(2026, 10, 21, 0, 30, tzinfo=UTC), tz)
    assert previous_week(monday_morning, tz) == date(2026, 10, 12)
    start, end = window(date(2026, 10, 12), tz)
    assert start == datetime(2026, 10, 11, 22, 0, tzinfo=UTC)  # CEST: UTC+2
    assert (end - start).days == 7


def test_window_across_the_autumn_clock_change() -> None:
    tz = zone("Europe/Zurich")
    start, end = window(date(2026, 10, 19), tz)  # DST ends Sunday 2026-10-25
    assert start == datetime(2026, 10, 18, 22, 0, tzinfo=UTC)
    assert end == datetime(2026, 10, 25, 23, 0, tzinfo=UTC)  # a 7 day week of 169 hours


def test_unknown_time_zone_falls_back_to_utc() -> None:
    assert zone("Mars/Base").key == "UTC"


def test_waiting_form_reports_are_one_action_and_one_fact() -> None:
    s = make_summary(form_queue=FormQueueCount(reports=3, providers=2))
    assert s["form_queue"] == {"reports": 3, "providers": 2}
    line = "Waiting for a web form: 3 reports (2 providers)."
    assert sum(a.startswith(line) for a in s["actions"]) == 1
    assert alert_facts(s)[-1] == ["Waiting for a web form", "3 reports (2 providers)"]
    one = make_summary(form_queue=FormQueueCount(reports=1, providers=1))
    assert alert_facts(one)[-1] == ["Waiting for a web form", "1 report (1 provider)"]


def test_an_empty_form_queue_says_nothing() -> None:
    for s in (make_summary(), make_summary(form_queue=FormQueueCount(reports=0, providers=0))):
        assert s["form_queue"] == {"reports": 0, "providers": 0}
        assert not any("web form" in a for a in s["actions"])
        assert all(k != "Waiting for a web form" for k, _ in alert_facts(s))
    # A report stored before this field existed still gives its facts.
    old = make_summary()
    del old["form_queue"]
    assert len(alert_facts(old)) == 5
