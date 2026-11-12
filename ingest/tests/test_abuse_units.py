"""Settings, term learning (pure parts) and the worker's off switch."""

from datetime import UTC, datetime
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_reporting import (
    Activity,
    Evidence,
    GuardContext,
    ReportSettings,
    SelfTermRow,
    SelfTerms,
    Subject,
    load_self_terms,
)

from ingest.abuse import AbuseSettings, AbuseWorker
from ingest.abuse.build import check_evidence, default_options, fit_evidence, options_of, sha256_of
from ingest.abuse.candidates import origin_of_domain, origin_of_ip
from ingest.abuse.ports import PortMap, protocol_of
from ingest.abuse.reguard import DraftReguard, ReguardStats
from ingest.abuse.selfterms import TermsCache, count_sources, hosts_of
from ingest.features import FeatureSettings


def test_defaults_match_the_design() -> None:
    s = AbuseSettings.from_env({})
    assert (s.build_interval_s, s.min_login_attempts, s.lookback_days) == (3600, 50, 7)
    assert (s.settle_min, s.resend_days, s.max_subjects, s.max_open_drafts) == (30, 14, 100, 200)
    assert (s.rdap_daily_quota, s.rdap_hourly_quota) == (1000, 200)
    assert s.include_demo is False and s.round_times is True
    assert "malware-drop" in s.severe_tags and "php2shell" in s.severe_tags


def test_settings_from_env_and_bounds() -> None:
    s = AbuseSettings.from_env(
        {
            "ABUSE_MIN_LOGIN_ATTEMPTS": "10",
            "ABUSE_SEVERE_TAGS": "Mirai, x",
            "ABUSE_ROUND_TIMES": "no",
        }
    )
    assert s.min_login_attempts == 10 and s.severe_tags == ("mirai", "x") and not s.round_times
    with pytest.raises(ValueError):
        AbuseSettings.from_env({"ABUSE_RDAP_DAILY_QUOTA": "-1"})


def test_off_until_the_flag_is_true() -> None:
    assert FeatureSettings.from_env({}).abuse_enabled is False
    assert FeatureSettings.from_env({"ABUSE_REPORTS_ENABLED": "true"}).abuse_enabled is True
    worker = AbuseWorker(FeatureSettings.from_env({}), None)
    assert worker.enabled is False and worker.builder is None and worker.rdap is None


async def test_disabled_worker_reports_status_and_runs_nothing() -> None:
    worker = AbuseWorker(FeatureSettings.from_env({}), None)
    await worker.run_once()
    status = await worker.status()
    assert status["abuse"]["enabled"] is False and status["rdap"]["enabled"] is False


def test_destination_fields_teach_names_and_addresses() -> None:
    # documentation and private addresses are never learned (they are demo or already forbidden)
    assert hosts_of({"host": "198.51.100.7"}) == set()
    assert hosts_of({"host": "172.16.1.5"}) == set()  # gitleaks:allow
    assert hosts_of({"host": "Dash.Mydomain.Net:443"}) == {("name", "dash.mydomain.net")}
    assert hosts_of({"host": "localhost"}) == set()
    assert hosts_of({"host": "intranet"}) == set()
    sip = hosts_of(
        {"request_uri": "sip:100@vpn.mydomain.org:5060", "to": "<sip:100@vpn.mydomain.org>"}
    )
    assert sip == {("name", "vpn.mydomain.org")}
    assert hosts_of({"host": 5, "to": None}) == set()


def test_public_address_in_host_is_learned() -> None:
    assert hosts_of({"host": "8.8.4.4:80"}) == {("address", "8.8.4.4")}


def test_sources_are_counted_per_network_not_per_address() -> None:
    rows = [
        ("8.8.8.1", {"host": "8.8.4.4"}),
        ("8.8.8.2", {"host": "8.8.4.4"}),  # same /24
        ("9.9.9.2", {"host": "8.8.4.4"}),
        ("2001:db8:1::1", {"host": "other.mydomain.net"}),
        ("2001:db8:1:5::1", {"host": "other.mydomain.net"}),  # same /48
    ]
    counts = count_sources(rows)
    assert counts[("address", "8.8.4.4")] == 2 and counts[("name", "other.mydomain.net")] == 1


def test_ports_name_the_public_port_and_never_the_sensor() -> None:
    m = PortMap()
    assert m.public_port("ssh", 2222) == 22 and m.public_port("smb", 4450) == 445
    assert m.public_port("adb", 5555) == 5555 and m.public_port("web", 9999) == 9999
    assert m.service_of("ssh", 2222) == "ssh" and m.service_of("synology", 5001) == "https"
    assert m.service_of("web", 8080) == "http" and m.service_of("web", 8443) == "https"
    assert protocol_of("sip") == "udp" and protocol_of("ssh") == "tcp"


def test_host_port_variables_change_the_public_port() -> None:
    m = PortMap.from_env({"SSH_HOST_PORT": "2200", "HTTP_HOST_PORT": "junk", "SMB_HOST_PORT": "0"})
    assert m.public_port("ssh", 2222) == 2200
    assert m.public_port("web", 8080) == 80 and m.public_port("smb", 4450) == 445
    assert (
        AbuseSettings.from_env({"TELNET_HOST_PORT": "2323"}).ports.public_port("telnet", 2323)
        == 2323
    )


def test_candidates_never_include_private_demo_or_self() -> None:
    assert origin_of_ip("10.0.0.1", None, include_demo=True) is None  # gitleaks:allow
    assert origin_of_ip("203.0.113.9", None, include_demo=False) is None
    assert origin_of_ip("203.0.113.9", None, include_demo=True) == "demo"
    assert origin_of_ip("8.8.8.9", None, include_demo=False) == "real"
    assert origin_of_ip("not-an-ip", None, include_demo=True) is None
    assert origin_of_domain("evil.example.net", None) == "real"
    assert origin_of_domain("localhost", None) is None


def test_options_default_to_minute_precision() -> None:
    assert default_options(AbuseSettings(), None).time_precision == "minute"
    assert default_options(AbuseSettings(round_times=False), None).time_precision == "second"
    merged = default_options(AbuseSettings(), {"defang": False, "junk": 1})
    assert merged.defang is False
    kept = options_of({"time_precision": "second", "junk": 1}, merged)
    assert kept.time_precision == "second"
    assert options_of({"time_precision": "weekly"}, merged) == merged
    assert options_of(None, merged) == merged


def test_fit_evidence_trims_to_the_size_cap() -> None:
    now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
    act = Activity(
        ts=now, src_ip="198.51.100.4", src_port=40000, dst_port=22, protocol="tcp",
        service="ssh", action="command", text="x" * 200,
    )  # fmt: skip
    subjects = tuple(
        Subject(type="ip", value=f"198.51.100.{i}", first_ts=now, last_ts=now, sessions=1,
                events=1, activities=(act,) * 200)
        for i in range(1, 100)
    )  # fmt: skip
    ev = Evidence(kind="attack_source", recipient="abuse@example.net", subjects=subjects,
                  window_start=now, window_end=now)  # fmt: skip
    assert len(ev.model_dump_json()) > 250_000
    trimmed = fit_evidence(ev)
    assert len(trimmed.model_dump_json()) <= 250_000 and trimmed.subjects
    assert sha256_of(trimmed) == sha256_of(trimmed)


# -- re-checking the open drafts ----------------------------------------------------------

SELF_ADDR = "198.51.100.200"  # the monitored system, a placeholder
T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def _terms(*extra: SelfTermRow) -> SelfTerms:
    own = SelfTermRow(kind="address", value=SELF_ADDR, source="manual")
    return load_self_terms([own, *extra], {})


def _evidence() -> Evidence:
    act = Activity(
        ts=T0, src_ip="198.51.100.4", src_port=40000, dst_port=22, protocol="tcp",
        service="ssh", action="command", text="uname -a",
    )  # fmt: skip
    sub = Subject(type="ip", value="198.51.100.4", first_ts=T0, last_ts=T0, sessions=1,
                  events=1, activities=(act,))  # fmt: skip
    return Evidence(kind="attack_source", recipient="abuse@example.net", subjects=(sub,),
                    window_start=T0, window_end=T0, demo=True)  # fmt: skip


def test_a_draft_is_blocked_by_the_reply_contact_and_clear_once_it_is_fixed() -> None:
    ctx = GuardContext(allow_documentation=True)
    ev, terms = _evidence(), _terms()
    # The reply contact on a domain that names the project would reveal it in every draft.
    named = check_evidence(
        ev, ReportSettings(reply_contact="reports@honeypot.example.net"), terms, ctx
    )
    assert not named.ok and "project_term" in named.codes
    assert check_evidence(ev, ReportSettings(reply_contact="reports@example.org"), terms, ctx).ok
    unset = check_evidence(ev, ReportSettings(), terms, ctx)
    assert not unset.ok and "settings_incomplete" in unset.codes


class _Scalar:
    def __init__(self, value: int | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> int | None:
        return self.value


class _FakeSession:
    def __init__(self, revision: int | None) -> None:
        self.revision = revision

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def execute(self, *_args: Any, **_kwargs: Any) -> _Scalar:
        return _Scalar(self.revision)


class _FakeTerms:
    def __init__(self, terms: SelfTerms | None) -> None:
        self.terms = terms

    async def get(self) -> SelfTerms | None:
        return self.terms


def _reguard(state: dict[str, int], terms: _FakeTerms) -> DraftReguard:
    factory = cast("async_sessionmaker[AsyncSession]", lambda: _FakeSession(state["revision"]))
    return DraftReguard(factory, AbuseSettings(), cast(TermsCache, terms))


async def test_drafts_are_rechecked_only_when_the_wording_or_the_deny_set_changed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"revision": 1}
    terms = _FakeTerms(_terms())
    reg = _reguard(state, terms)
    passes: list[SelfTerms] = []

    async def fake_run(deny: SelfTerms) -> ReguardStats:
        passes.append(deny)
        return ReguardStats(checked=1)

    monkeypatch.setattr(reg, "run", fake_run)
    assert await reg.run_if_changed() is not None  # the first pass after a start
    assert await reg.run_if_changed() is None  # nothing changed since
    state["revision"] = 2
    assert await reg.run_if_changed() is not None  # the owner saved the settings
    assert await reg.run_if_changed() is None
    terms.terms = _terms(SelfTermRow(kind="name", value="srv-own01", source="manual"))
    assert await reg.run_if_changed() is not None  # the deny set grew
    terms.terms = None
    assert await reg.run_if_changed() is None  # no deny set: fail closed, results stay as they are
    assert len(passes) == 3


async def test_a_failed_pass_is_tried_again_on_the_next_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reg = _reguard({"revision": 1}, _FakeTerms(_terms()))
    attempts: list[int] = []

    async def flaky(_deny: SelfTerms) -> ReguardStats:
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("database went away")
        return ReguardStats()

    monkeypatch.setattr(reg, "run", flaky)
    with pytest.raises(RuntimeError):
        await reg.run_if_changed()
    assert await reg.run_if_changed() is not None
    assert len(attempts) == 2


async def test_the_worker_survives_a_failing_recheck() -> None:
    class Broken:
        called = False

        async def run_if_changed(self) -> None:
            Broken.called = True
            raise RuntimeError("boom")

    worker = AbuseWorker(FeatureSettings.from_env({}), None)
    worker.reguard = cast(DraftReguard, Broken())
    await worker._reguard_cycle()
    assert Broken.called
