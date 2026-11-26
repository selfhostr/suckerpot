"""Report selection, rendering, grouping, caps and sending."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text

from hub import consensus
from hub.config import Settings
from hub.never import Never
from hub.reports import render, send
from hub.reports import select as sel

from .conftest import Env
from .seed import TODAY, add_nodes, observe, target

D1, D2 = TODAY - timedelta(days=2), TODAY - timedelta(days=1)


def rt(kind: str = "ip", value: str = "192.0.2.109", **kw: Any) -> render.ReportTarget:
    base: dict[str, Any] = {
        "id": "t_000000000001",
        "kind": kind,
        "value": value,
        "first_day": date(2026, 10, 26),
        "last_day": date(2026, 10, 30),
        "services": ("ssh",),
        "activity": ("login", "command"),
        "tags": ("mirai",),
        "families": (),
        "node_count": 7,
        "country_count": 4,
    }
    return render.ReportTarget(**{**base, **kw})


def test_render_facts_only_without_template() -> None:
    r = render.render("attack_source", [rt()], reply_to="abuse-desk@example.org")
    assert "5 to 9 independent sensors in 4 or more countries" in r.body
    assert (
        "192.0.2.109" in r.body
        and "2026-10-26" in r.body
        and "Reply to: abuse-desk@example.org" in r.body
    )
    assert r.subject.startswith("Abuse report: 1 address")
    assert (
        r.xarf
        and "Source: 192.0.2.109" in r.xarf
        and "Reported-From: abuse-desk@example.org" in r.xarf
    )


def test_render_hides_countries_below_three_and_defangs() -> None:
    r = render.render("malware_host", [rt("url", "http://198.51.100.9/x.sh", country_count=2)])
    assert "countries" not in r.body
    assert "hxxp://198[.]51[.]100[.]9/x[.]sh" in r.body and "http://" not in r.body
    # the member-country rule (2) does not lower the report wording: it stays at 3 countries
    r = render.render("malware_host", [rt("url", "http://198.51.100.9/x.sh", country_count=3)])
    assert "in 3 or more countries" in r.body


def test_render_template_and_no_node_identity() -> None:
    tpl = "Hello,\n\n$facts\n\n$count item(s) from $first_day to $last_day.\nWrite to $reply_to"
    r = render.render(
        "attack_source",
        [rt(), rt(value="192.0.2.110", id="t_000000000002")],
        template=tpl,
        reply_to="a@example.org",
    )
    assert r.body.startswith("Hello,") and "2 item(s) from 2026-10-26 to 2026-10-30" in r.body
    assert r.xarf is None  # X-ARF carries one source: grouped reports are text only
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}", r.body)
    assert "pseudonym" not in r.body.lower() and "fingerprint" not in r.body.lower()


def test_render_refuses_text_naming_the_project() -> None:
    with pytest.raises(ValueError):
        render.render("attack_source", [rt()], template="from the SuckerPot network $facts")


def test_sensors_bucket_uses_the_smallest_count() -> None:
    assert render.sensors_label([30, 7]) == "5 to 9"
    assert render.sensors_label([30, 12]) == "10 to 24"


async def _confirmed_ip(env: Env, ip: str = "192.0.2.109", **obs: Any) -> list[Any]:
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await observe(env.worker, nodes, "ip", ip, [D1, D2], **obs)
    async with env.worker() as s:
        await consensus.run_consensus(s, env.settings, TODAY, never=Never(), corroborate=None)
    return nodes


async def _eligible(env: Env) -> list[Any]:
    async with env.worker() as s:
        return list(await consensus.eligible_nodes(s, env.settings, TODAY))


async def _resolver(kind: str, host: str) -> str | None:
    return "abuse@example.net" if host.startswith("192.0.2.") else None


@pytest.mark.integration
async def test_severity_rules(env: Env) -> None:
    # scans and connects alone are never reportable, even confirmed by many nodes
    await _confirmed_ip(env, "192.0.2.101", activity=["scan", "connect"], attempts=0)
    # severe activity is
    await _confirmed_ip(env, "192.0.2.102", activity=["command"], attempts=0)
    # many login attempts (bucket 3) is
    await _confirmed_ip(env, "192.0.2.103", activity=["login"], attempts=3)
    for ip in ("192.0.2.101", "192.0.2.102", "192.0.2.103"):
        assert (await target(env.worker, "ip", ip))["state"] == "confirmed"
    async with env.worker() as s:
        ids = await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env))
    got = {(await target(env.worker, "ip", ip))["id"] for ip in ("192.0.2.102", "192.0.2.103")}
    assert ids == got


@pytest.mark.integration
async def test_payload_hosts_are_reported_only_with_fetched_evidence(env: Env) -> None:
    """Payload hosts left the ``ip`` kind (security review H3). M29 reports them as malware
    download locations, under the url/domain rule: a file fetched from the host by at least
    two eligible nodes (security re-review H1)."""
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    host = "192.0.2.120"
    common: dict[str, Any] = {
        "services": [],
        "activity": ["download"],
        "tags": [],
        "attempts": None,
    }
    await observe(
        env.worker,
        nodes[:2],
        "payload_ip",
        host,
        [D1, D2],
        fetched=True,
        file_type="elf-arm",
        **common,
    )
    await observe(env.worker, nodes[2:], "payload_ip", host, [D1, D2], **common)
    async with env.worker() as s:
        await consensus.run_consensus(s, env.settings, TODAY, never=Never(), corroborate=None)
        ids = await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env))
        assert ids == {(await target(env.worker, "payload_ip", host))["id"]}
        res = await sel.queue_reports(s, env.settings, TODAY, resolver=_resolver, never=Never())
    assert res.queued == 1
    async with env.worker() as s:
        row = (await s.execute(text("SELECT kind, body_text FROM reports"))).one()
    assert row.kind == "malware_host" and "192[.]0[.]2[.]120" in row.body_text


@pytest.mark.integration
async def test_a_host_typed_into_honeypots_is_never_reported(env: Env) -> None:
    """Security re-review H1: `wget http://<victim>/x.sh` typed into ten member honeypots gives
    ten unfetched payload_ip sightings. That must not mail the victim's abuse contact."""
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    host = "192.0.2.121"
    await observe(
        env.worker, nodes, "payload_ip", host, [D1, D2],
        services=[], activity=["download"], tags=[], attempts=None, fetched=False,
    )  # fmt: skip
    async with env.worker() as s:
        await consensus.run_consensus(s, env.settings, TODAY, never=Never(), corroborate=None)
        assert (await target(env.worker, "payload_ip", host))["state"] == "confirmed"
        assert await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env)) == set()
        res = await sel.queue_reports(s, env.settings, TODAY, resolver=_resolver, never=Never())
    assert res.queued == 0
    # One fetching node is not enough either.
    await observe(
        env.worker, nodes[:1], "payload_ip", host, [TODAY - timedelta(days=3)],
        services=[], activity=["download"], tags=[], attempts=None, fetched=True, file_type="elf-arm",
    )  # fmt: skip
    async with env.worker() as s:
        assert await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env)) == set()


@pytest.mark.integration
async def test_url_needs_two_fetching_nodes_and_a_revealed_value(env: Env) -> None:
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await observe(
        env.worker,
        nodes,
        "url",
        "ab" * 32,
        [D1, D2],
        fetched=True,
        file_type="script-sh",
        activity=["download"],
    )
    await observe(
        env.worker, nodes, "url", "cd" * 32, [D1, D2], fetched=False, activity=["download"]
    )
    async with env.worker() as s:
        await consensus.run_consensus(s, env.settings, TODAY, never=Never(), corroborate=None)
        assert await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env)) == set()
        await s.execute(
            text("UPDATE targets SET value = 'http://198.51.100.9/' || substr(value_b, 1, 4)")
        )
        await s.commit()
        ids = await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env))
    assert ids == {(await target(env.worker, "url", "ab" * 32))["id"]}


@pytest.mark.integration
async def test_review_mode_queues_but_never_sends_unapproved(env: Env) -> None:
    await _confirmed_ip(env)
    sent: list[tuple[str, str]] = []

    async def mailer(to: str, subject: str, body: str, xarf: str | None) -> None:
        sent.append((to, subject))

    async with env.worker() as s:
        res = await sel.queue_reports(s, env.settings, TODAY, resolver=_resolver, never=Never())
        assert (res.queued, res.updated) == (1, 0)
        assert (
            await sel.auto_approve(s, env.settings, TODAY + timedelta(days=5)) == 0
        )  # review mode
        out = await send.send_due(s, env.settings, env.clock(), TODAY, mailer)
    assert sent == [] and out.sent == 0
    async with env.worker() as s:
        row = (
            await s.execute(text("SELECT state, recipient, kind, target_ids FROM reports"))
        ).one()
    assert (row.state, row.recipient, row.kind) == ("queued", "abuse@example.net", "attack_source")
    # nothing about nodes in the stored text
    async with env.worker() as s:
        body = (await s.execute(text("SELECT body_text FROM reports"))).scalar_one()
    assert "192.0.2.109" in body


@pytest.mark.integration
async def test_approve_send_marks_targets_and_respects_caps(env: Env) -> None:
    await _confirmed_ip(env, "192.0.2.109")
    await _confirmed_ip(env, "192.0.2.110")
    sent: list[str] = []

    async def mailer(to: str, subject: str, body: str, xarf: str | None) -> None:
        sent.append(subject)

    async with env.worker() as s:
        res = await sel.queue_reports(s, env.settings, TODAY, resolver=_resolver, never=Never())
        assert res.queued == 1  # one recipient, one kind: one grouped report
        await s.execute(text("UPDATE reports SET state = 'approved'"))
        await s.commit()
        out = await send.send_due(s, env.settings, env.clock(), TODAY, mailer)
        again = await send.send_due(s, env.settings, env.clock(), TODAY, mailer)
    assert out.sent == 1 and again.sent == 0 and len(sent) == 1 and "2 addresses" in sent[0]
    for ip in ("192.0.2.109", "192.0.2.110"):
        t = await target(env.worker, "ip", ip)
        assert t["state"] == "reported" and t["reported_day"] == TODAY
    # a reported target is not queued again, and the recipient is covered for a week
    async with env.worker() as s:
        res = await sel.queue_reports(
            s, env.settings, TODAY + timedelta(days=1), resolver=_resolver, never=Never()
        )
    assert res.queued == 0


@pytest.mark.integration
async def test_recipient_and_global_daily_caps(env: Env) -> None:
    await _confirmed_ip(env, "192.0.2.109")
    await _confirmed_ip(env, "192.0.2.110")
    async with env.worker() as s:
        for i, (rcpt, kind) in enumerate(
            [
                ("a@example.net", "attack_source"),
                ("a@example.net", "c2"),
                ("b@example.net", "attack_source"),
            ]
        ):
            await s.execute(
                text(
                    "INSERT INTO reports (recipient, kind, target_ids, state, body_text, created_day) "
                    "VALUES (:r, :k, :t, 'approved', 'Subject: s\n\nbody', :d)"
                ),
                {"r": rcpt, "k": kind, "t": [f"t_{i:012x}"], "d": TODAY},
            )
        await s.commit()
    got: list[str] = []

    async def mailer(to: str, subject: str, body: str, xarf: str | None) -> None:
        got.append(to)

    async with env.worker() as s:
        out = await send.send_due(s, env.settings, env.clock(), TODAY, mailer)
    assert got == ["a@example.net", "b@example.net"]  # one per recipient per day
    assert out.deferred == {"recipient_cap": 1}
    async with env.worker() as s:
        capped = env.settings.__class__(**{**env.settings.__dict__, "report_daily_cap": 1})
        await s.execute(
            text(
                "INSERT INTO reports (recipient, kind, target_ids, state, body_text, created_day) "
                "VALUES ('c@example.net', 'c2', ARRAY['t_x'], 'approved', 'Subject: s\n\nbody', :d)"
            ),
            {"d": TODAY},
        )
        await s.commit()
        out = await send.send_due(s, capped, env.clock(), TODAY + timedelta(days=1), mailer)
    assert out.sent == 1 and out.deferred.get("daily_cap") == 1


@pytest.mark.integration
async def test_deferred_send_keeps_reports_queued(env: Env) -> None:
    async def deferred(to: str, subject: str, body: str, xarf: str | None) -> None:
        raise send.SendDeferred("proxy_unreachable")

    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO reports (recipient, kind, target_ids, state, body_text, created_day) "
                "VALUES ('c@example.net', 'c2', ARRAY['t_x'], 'approved', 'Subject: s\n\nb', :d)"
            ),
            {"d": TODAY},
        )
        await s.commit()
        out = await send.send_due(s, env.settings, env.clock(), TODAY, deferred)
        row = (await s.execute(text("SELECT state, error_code FROM reports"))).one()
    assert out.failed == 0 and out.deferred == {"proxy_unreachable": 1}
    assert (row.state, row.error_code) == ("approved", None)


@pytest.mark.integration
async def test_failed_send_releases_the_targets(env: Env) -> None:
    await _confirmed_ip(env)

    async def broken(to: str, subject: str, body: str, xarf: str | None) -> None:
        raise send.SendError("SMTPException")

    async with env.worker() as s:
        await sel.queue_reports(s, env.settings, TODAY, resolver=_resolver, never=Never())
        await s.execute(text("UPDATE reports SET state = 'approved'"))
        await s.commit()
        out = await send.send_due(s, env.settings, env.clock(), TODAY, broken)
        row = (await s.execute(text("SELECT state, error_code FROM reports"))).one()
    assert out.failed == 1 and (row.state, row.error_code) == ("failed", "SMTPException")
    assert (await target(env.worker, "ip", "192.0.2.109"))["state"] == "confirmed"


@pytest.mark.integration
async def test_regrouping_while_queued_and_auto_hold(env: Env) -> None:
    await _confirmed_ip(env, "192.0.2.109")
    s_auto = env.settings.__class__(
        **{**env.settings.__dict__, "report_mode": "auto", "report_hold_hours": 24}
    )
    async with env.worker() as s:
        await sel.queue_reports(s, s_auto, TODAY, resolver=_resolver, never=Never())
    await _confirmed_ip(env, "192.0.2.110")
    async with env.worker() as s:
        res = await sel.queue_reports(s, s_auto, TODAY, resolver=_resolver, never=Never())
        assert (res.queued, res.updated) == (0, 1)
        assert await sel.auto_approve(s, s_auto, TODAY) == 0  # held for a day
        assert await sel.auto_approve(s, s_auto, TODAY + timedelta(days=1)) == 1
        n = (await s.execute(text("SELECT array_length(target_ids, 1) FROM reports"))).scalar_one()
    assert n == 2


@pytest.mark.integration
async def test_no_contact_and_off_mode(env: Env) -> None:
    await _confirmed_ip(env, "203.0.113.207")
    async with env.worker() as s:
        res = await sel.queue_reports(s, env.settings, TODAY, resolver=_resolver, never=Never())
        assert res.queued == 0 and res.skipped == {"no_contact": 1}
        off = env.settings.__class__(**{**env.settings.__dict__, "report_mode": "off"})
        assert (
            await sel.queue_reports(s, off, TODAY, resolver=_resolver, never=Never())
        ).candidates == 0


@pytest.mark.integration
async def test_cancelled_report_blocks_requeue(env: Env) -> None:
    await _confirmed_ip(env)
    async with env.worker() as s:
        await sel.queue_reports(s, env.settings, TODAY, resolver=_resolver, never=Never())
        await s.execute(text("UPDATE reports SET state = 'cancelled'"))
        await s.commit()
        res = await sel.queue_reports(
            s, env.settings, TODAY + timedelta(days=1), resolver=_resolver, never=Never()
        )
    assert res.candidates == 0 and res.queued == 0


def test_build_message_is_neutral() -> None:
    s = Settings(smtp_from="reports@example.org", report_reply_to="desk@example.org")
    msg = send.build_message(
        s,
        "abuse@example.net",
        "Abuse report",
        "body",
        "Source: x\n",
        datetime(2026, 11, 1, tzinfo=UTC),
    )
    names = {k.lower() for k in msg.keys()}
    assert "x-mailer" not in names and "user-agent" not in names
    assert msg["Reply-To"] == "desk@example.org" and msg["X-ARF"] == "YES"
    assert msg["Message-ID"].endswith("@example.org>")


@pytest.mark.integration
async def test_fresh_keys_cannot_make_a_quiet_address_reportable(env: Env) -> None:
    # ten eligible nodes only scanned it; five fresh keys (never eligible) claim an exploit
    await _confirmed_ip(env, "192.0.2.120", activity=["scan"], attempts=0)
    fresh = await add_nodes(env.worker, 5, enrolled=[TODAY - timedelta(days=1)] * 5)
    await observe(
        env.worker, fresh, "ip", "192.0.2.120", [D1, D2], activity=["exploit"], attempts=4
    )
    async with env.worker() as s:
        await consensus.run_consensus(s, env.settings, TODAY, never=Never(), corroborate=None)
    t = await target(env.worker, "ip", "192.0.2.120")
    assert t["state"] == "confirmed" and "exploit" not in t["activity"]  # k-supported fields
    async with env.worker() as s:
        assert await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env)) == set()


@pytest.mark.integration
async def test_fresh_keys_cannot_fake_a_fetched_payload(env: Env) -> None:
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await observe(
        env.worker, nodes, "url", "ab" * 32, [D1, D2], fetched=False, activity=["download"]
    )
    fresh = await add_nodes(env.worker, 2, enrolled=[TODAY - timedelta(days=1)] * 2)
    await observe(env.worker, fresh, "url", "ab" * 32, [D1, D2], fetched=True)
    async with env.worker() as s:
        await consensus.run_consensus(s, env.settings, TODAY, never=Never(), corroborate=None)
        await s.execute(text("UPDATE targets SET value = 'http://198.51.100.9/x'"))
        await s.commit()
        assert await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env)) == set()


@pytest.mark.integration
async def test_auto_mode_needs_cohorts_and_never_sends_c2(env: Env) -> None:
    await _confirmed_ip(env)  # ten cohorts
    s_auto = replace(env.settings, report_mode="auto", report_hold_hours=0)
    async with env.worker() as s:
        await sel.queue_reports(s, s_auto, TODAY, resolver=_resolver, never=Never())
        await s.execute(
            text(
                "INSERT INTO reports (recipient, kind, target_ids, state, body_text, created_day) "
                "VALUES ('c@example.net', 'c2', ARRAY['t_x'], 'queued', 'Subject: s\n\nb', :d)"
            ),
            {"d": TODAY},
        )
        await s.commit()
        few = replace(s_auto, auto_min_cohorts=11)
        assert await sel.auto_approve(s, few, TODAY) == 0  # not enough independent cohorts
        assert await sel.auto_approve(s, s_auto, TODAY) == 1  # the attack report only
        states: dict[Any, Any] = dict(
            (await s.execute(text("SELECT kind, state FROM reports"))).all()
        )
    assert states == {"attack_source": "approved", "c2": "queued"}


@pytest.mark.integration
async def test_fetching_an_ordinary_web_page_never_makes_a_host_reportable(env: Env) -> None:
    """A compromised victim site serves HTML: ten nodes fetching it prove no malware. An ELF
    fetched from another host does, and so does a known family without a file type."""
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    common: dict[str, Any] = {
        "services": [],
        "activity": ["download"],
        "tags": [],
        "attempts": None,
    }
    html_host, elf_host, fam_host = "192.0.2.130", "192.0.2.131", "192.0.2.132"
    await observe(
        env.worker, nodes, "payload_ip", html_host, [D1, D2], fetched=True, file_type="other",
        **common,
    )  # fmt: skip
    await observe(
        env.worker, nodes, "payload_ip", elf_host, [D1, D2], fetched=True, file_type="elf-x86_64",
        **common,
    )  # fmt: skip
    await observe(
        env.worker, nodes, "payload_ip", fam_host, [D1, D2], fetched=True, families=["mirai"],
        **common,
    )  # fmt: skip
    await observe(
        env.worker, nodes, "url", "ef" * 32, [D1, D2], fetched=True, file_type="other",
        activity=["download"],
    )  # fmt: skip
    async with env.worker() as s:
        await consensus.run_consensus(s, env.settings, TODAY, never=Never(), corroborate=None)
        await s.execute(
            text(
                "UPDATE targets SET value = 'http://198.51.100.9/' || substr(value_b, 1, 4) "
                "WHERE kind = 'url'"
            )
        )
        await s.commit()
        ids = await sel.reportable_ids(s, env.settings, TODAY, await _eligible(env))
    assert ids == {
        (await target(env.worker, "payload_ip", elf_host))["id"],
        (await target(env.worker, "payload_ip", fam_host))["id"],
    }
