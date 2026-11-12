"""Reputation worker scheduling without a database: settings, rate limits, backoff.

The order in which addresses are picked is SQL and is covered against a real database in
``test_enrichment_integration.py``.
"""

import time
from datetime import date, timedelta
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from ingest.enrichment import EnrichmentSettings
from ingest.enrichment import reputation as rep
from ingest.enrichment.reputation import ReputationWorker

IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]


class Calls:
    """Stands in for the database helpers and the two providers."""

    def __init__(self) -> None:
        self.candidate_args: list[dict[str, Any]] = []
        self.candidates = list(IPS)
        self.spent: list[tuple[str, int]] = []
        self.stored: list[str] = []
        self.requests: list[httpx.Request] = []
        self.abuse_status = 200
        self.gn_status = 200
        self.reserved = 0

    async def candidate_ips(self, _factory: Any, provider: str, *_a: Any, **kw: Any) -> list[str]:
        self.candidate_args.append({"provider": provider, **kw})
        return list(self.candidates)

    async def reserve(self, *_a: Any) -> bool:
        self.reserved += 1
        return True

    async def mark_spent(self, _factory: Any, provider: str, limit: int) -> None:
        self.spent.append((provider, limit))

    async def store(self, ip: str, _result: Any) -> None:
        self.stored.append(ip)

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host == "api.abuseipdb.com":
            if self.abuse_status != 200:
                return httpx.Response(self.abuse_status)
            return httpx.Response(
                200, json={"data": {"abuseConfidenceScore": 12, "totalReports": 1}}
            )
        if self.gn_status != 200:
            return httpx.Response(self.gn_status)
        return httpx.Response(200, json={"noise": True, "riot": False})

    def count(self, host: str) -> int:
        return sum(1 for r in self.requests if r.url.host == host)


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> Calls:
    c = Calls()
    monkeypatch.setattr(rep, "candidate_ips", c.candidate_ips)
    monkeypatch.setattr(rep, "reserve_quota", c.reserve)
    monkeypatch.setattr(rep, "mark_quota_spent", c.mark_spent)
    monkeypatch.setattr(rep, "is_routable", lambda _a: True)  # documentation addresses
    monkeypatch.setattr(ReputationWorker, "_store_abuse", lambda _s, ip, r: c.store(ip, r))
    monkeypatch.setattr(ReputationWorker, "_store_greynoise", lambda _s, ip, r: c.store(ip, r))
    return c


def worker(calls: Calls, **env: str) -> ReputationWorker:
    settings = EnrichmentSettings.from_env(env)
    client = httpx.AsyncClient(transport=httpx.MockTransport(calls.handler))
    return ReputationWorker(MagicMock(), settings, client)


# ---- settings ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 7), ("14", 14), ("0", 1), ("-3", 1), ("1", 1), ("30", 30), ("365", 30)],
)
def test_recheck_days_default_and_bounds(value: str | None, expected: int) -> None:
    env = {} if value is None else {"REPUTATION_RECHECK_DAYS": value}
    assert EnrichmentSettings.from_env(env).reputation_recheck_days == expected


# ---- what the worker asks the database for ----------------------------------------------------


async def test_the_recheck_age_reaches_the_candidate_query(calls: Calls) -> None:
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20, REPUTATION_RECHECK_DAYS="12")
    await w.run_once()
    assert calls.candidate_args[0]["provider"] == "abuseipdb"
    assert calls.candidate_args[0]["recheck_days"] == 12
    assert calls.stored == IPS  # the list is looked up in the order the query returned it


async def test_unroutable_addresses_are_excluded_from_the_next_query(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    # They never get an answer, so without the exclusion they would fill the first places of
    # the queue (new addresses come first) and starve every other address.
    monkeypatch.setattr(rep, "is_routable", lambda a: str(a) != IPS[0])
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20)
    await w.run_once()
    await w.run_once()
    assert calls.candidate_args[0]["exclude"] == []
    assert calls.candidate_args[1]["exclude"] == [IPS[0]]
    assert IPS[0] not in calls.stored


async def test_a_failed_lookup_is_left_out_for_a_while(calls: Calls) -> None:
    calls.abuse_status = 500
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20)
    await w.run_once()
    await w.run_once()
    assert calls.candidate_args[1]["exclude"] == IPS  # every one of them failed
    assert calls.stored == []  # nothing is stored for a failed lookup


# ---- GreyNoise: a 429 means the day's real allowance is gone ----------------------------------


async def test_greynoise_429_stops_until_the_next_utc_day(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls.gn_status = 429
    w = worker(calls, GREYNOISE_API_KEY="k" * 20, GREYNOISE_DAILY_QUOTA="50")
    assert await w.run_once() == 1
    assert calls.count("api.greynoise.io") == 1  # the other candidates are not tried
    assert calls.spent == [("greynoise", 50)]  # the counter reads as full
    assert w.last_error == {"greynoise": "rate_limited"}
    assert (await w.status())["greynoise"]["paused"] is True

    # The one hour timer (what the old code waited) is gone and many cycles later: still
    # nothing is sent, the stop lasts the whole UTC day.
    w._paused_until.clear()
    w._retry_after.clear()
    for _ in range(3):
        assert await w.run_once() == 0
    assert calls.count("api.greynoise.io") == 1

    # The next UTC day it asks again (and stops again if the answer is still 429).
    tomorrow = rep._quota_day() + timedelta(days=1)
    monkeypatch.setattr(rep, "_quota_day", lambda: tomorrow)
    assert await w.run_once() == 1
    assert calls.count("api.greynoise.io") == 2
    assert calls.spent[-1] == ("greynoise", 50)


async def test_greynoise_works_again_on_the_next_day_when_the_answer_is_fine(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls.gn_status = 429
    w = worker(calls, GREYNOISE_API_KEY="k" * 20)
    await w.run_once()
    calls.gn_status = 200
    day: date = rep._quota_day() + timedelta(days=1)
    monkeypatch.setattr(rep, "_quota_day", lambda: day)
    assert await w.run_once() == len(IPS)
    assert calls.stored == IPS


async def test_a_new_greynoise_key_clears_the_stop(calls: Calls) -> None:
    calls.gn_status = 429
    w = worker(calls, GREYNOISE_API_KEY="k" * 20)
    await w.run_once()
    assert (await w.status())["greynoise"]["paused"] is True
    w.apply_settings(w.s, {"greynoise"})
    assert (await w.status())["greynoise"]["paused"] is False


async def test_greynoise_uses_the_same_new_first_query(calls: Calls) -> None:
    w = worker(calls, GREYNOISE_API_KEY="k" * 20, REPUTATION_RECHECK_DAYS="3")
    await w.run_once()
    assert calls.candidate_args[0]["provider"] == "greynoise"
    assert calls.candidate_args[0]["recheck_days"] == 3


async def test_abuseipdb_429_keeps_the_one_hour_pause(calls: Calls) -> None:
    calls.abuse_status = 429
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20)
    assert await w.run_once() == 1
    assert calls.spent == []  # its quota is the real one: nothing to mark
    assert (await w.status())["abuseipdb"]["paused"] is True
    left = w._paused_until["abuseipdb"] - time.monotonic()
    assert rep.RATE_LIMIT_PAUSE_S - 60 < left <= rep.RATE_LIMIT_PAUSE_S
    assert w._spent_day == {}  # a timer, not a stop for the day
