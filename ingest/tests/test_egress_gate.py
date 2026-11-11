"""A closed egress gate is a retryable "not now": nothing is sent, no quota is spent, and no
negative result is cached. Every network worker is checked (fakes only, no real connection)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from suckerpot_egress import EgressClosed

from ingest.cve.watch import CveWatch
from ingest.egress import gate_open, get_gate, make_client, set_gate
from ingest.enrichment import EnrichmentSettings, GeoResolver
from ingest.enrichment.credentials import CredentialSync
from ingest.enrichment.downloader import GeoManager
from ingest.enrichment.intel import IntelWorker
from ingest.enrichment.reputation import ReputationWorker

from .helpers import fake_gate

ENV = EnrichmentSettings.from_env(
    {
        "ABUSEIPDB_API_KEY": "k" * 20,
        "GREYNOISE_API_KEY": "k" * 20,
        "ABUSECH_AUTH_KEY": "k" * 20,
        "VIRUSTOTAL_API_KEY": "k" * 20,
        "NVD_API_KEY": "k" * 20,
        "GITHUB_ADVISORY_TOKEN": "t" * 20,
        "MAXMIND_ACCOUNT_ID": "1",
        "MAXMIND_LICENSE_KEY": "k" * 20,
    }
)


def closed() -> Any:
    return fake_gate(open_=False, reason="tunnel_down")


class Tripwire:
    """Counts calls: the quota reservation and the HTTP client must never be reached."""

    def __init__(self) -> None:
        self.calls = 0

    async def reserve(self, *_a: Any, **_k: Any) -> bool:
        self.calls += 1
        return True

    def handler(self, _req: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json={})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def trip(monkeypatch: pytest.MonkeyPatch) -> Tripwire:
    t = Tripwire()
    for mod in ("reputation", "credentials", "intel"):
        monkeypatch.setattr(f"ingest.enrichment.{mod}.reserve_quota", t.reserve)
    monkeypatch.setattr("ingest.cve.watch.reserve_quota", t.reserve)
    return t


def test_the_default_gate_is_closed_and_a_default_client_cannot_connect() -> None:
    set_gate(None)  # the autouse fixture opened one: drop it
    assert get_gate().status.reason == "not_checked"
    assert not gate_open()

    async def go() -> None:
        async with make_client(httpx.Timeout(1.0)) as c:
            await c.get("https://api.test/x")

    import asyncio

    with pytest.raises(EgressClosed):
        asyncio.run(go())


async def test_reputation_closed_gate(trip: Tripwire) -> None:
    w = ReputationWorker(MagicMock(), ENV, trip.client(), gate=closed())
    assert await w.run_once() == 0
    for provider in ("abuseipdb", "greynoise"):
        assert (await w.run_key_test(provider))["error"] == "egress_closed"
    assert trip.calls == 0
    assert w.last_error == {} and w._retry_after == {}


async def test_reputation_gate_closing_mid_request_leaves_no_trace(trip: Tripwire) -> None:
    gate = fake_gate()

    def handler(_req: httpx.Request) -> httpx.Response:
        raise EgressClosed("tunnel_down")

    w = ReputationWorker(
        MagicMock(), ENV, httpx.AsyncClient(transport=httpx.MockTransport(handler)), gate=gate
    )
    assert (await w.run_key_test("abuseipdb"))["error"] == "egress_closed"
    assert "abuseipdb" not in w.last_error and w.enabled("abuseipdb")


async def test_intel_closed_gate(trip: Tripwire) -> None:
    w = IntelWorker(MagicMock(), ENV, trip.client(), gate=closed())
    assert await w.run_once() == 0
    for provider in ("abusech", "virustotal"):
        assert (await w.run_key_test(provider))["error"] == "egress_closed"
    with pytest.raises(EgressClosed):
        await w._reserve_contacts("virustotal")
    assert trip.calls == 0
    assert w.state.last_error == {} and w.state.retry_after == {}


async def test_cve_watch_closed_gate(trip: Tripwire) -> None:
    w = CveWatch(MagicMock(), ENV, trip.client(), gate=closed())
    assert await w.run_once() == 0
    for provider in ("nvd", "github"):
        assert (await w.run_key_test(provider))["error"] == "egress_closed"
    with pytest.raises(EgressClosed):
        await w._reserve("kev")()
    assert trip.calls == 0
    assert w.last_error == {} and w._retry_at == {}


async def test_cve_source_sync_is_not_a_failure_when_the_gate_closes(
    trip: Tripwire, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = CveWatch(MagicMock(), ENV, trip.client(), gate=closed())

    async def never(_source: str) -> None:
        return None

    monkeypatch.setattr(w, "_last_success", never)
    assert await w.sync_source("kev") == 0  # no record, no backoff
    assert w.last_error == {} and w._retry_at == {}


async def test_maxmind_key_test_closed_gate(trip: Tripwire) -> None:
    s = CredentialSync(
        MagicMock(), ENV, None, on_change=lambda _s, _c: None, client=trip.client(), gate=closed()
    )
    assert (await s.test_maxmind())["error"] == "egress_closed"
    assert trip.calls == 0


async def test_geoip_refresh_waits_and_keeps_the_force_flag(tmp_path: Path) -> None:
    s = EnrichmentSettings.from_env({"GEOIP_DIR": str(tmp_path / "geo")})
    made: list[int] = []

    def factory() -> httpx.AsyncClient:
        made.append(1)
        return httpx.AsyncClient()

    mgr = GeoManager(s, GeoResolver(s.geoip_dir), client_factory=factory, gate=closed())
    mgr._force = True
    assert await mgr.refresh_if_needed() is False
    assert made == [] and mgr._force is True and mgr.last_error is None
