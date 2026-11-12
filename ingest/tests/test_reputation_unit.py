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
from ingest.enrichment.reputation import Candidate, ReputationWorker, recheck_reserve

IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]


class Calls:
    """Stands in for the database helpers and the two providers."""

    def __init__(self) -> None:
        self.candidate_args: list[dict[str, Any]] = []
        self.candidates = [Candidate(ip, False) for ip in IPS]
        self.stale_candidates: list[Candidate] = []
        self.usage = (0, 0)  # lookups today, and those that refreshed a stale answer
        self.spent: list[tuple[str, int]] = []
        self.stored: list[str] = []
        self.requests: list[httpx.Request] = []
        self.abuse_status = 200
        self.gn_status = 200
        self.reserved: list[str] = []

    async def candidate_ips(
        self, _factory: Any, provider: str, *_a: Any, **kw: Any
    ) -> list[Candidate]:
        self.candidate_args.append({"provider": provider, **kw})
        return list(self.stale_candidates if kw.get("stale_only") else self.candidates)

    async def quota_usage(self, _factory: Any, _provider: str) -> tuple[int, int]:
        return self.usage

    async def reserve(self, _factory: Any, key: str, *_a: Any) -> bool:
        self.reserved.append(key)
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
    monkeypatch.setattr(rep, "quota_usage", c.quota_usage)
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


# ---- the share of each day kept for stale answers -----------------------------------------------


@pytest.mark.parametrize(
    ("quota", "reserve"),
    [
        (0, 0),
        (1, 0),
        (2, 1),
        (3, 1),
        (5, 1),
        (6, 2),
        (7, 2),
        (10, 2),
        (11, 3),
        (50, 10),
        (1000, 200),
    ],
)
def test_the_reserve_is_a_fifth_of_the_quota_at_least_one_and_at_most_half(
    quota: int, reserve: int
) -> None:
    assert recheck_reserve(quota) == reserve


async def test_new_addresses_may_take_only_what_is_not_reserved(calls: Calls) -> None:
    # Quota 10 keeps 2 for stale answers: 6 are used, so 2 are left for new addresses.
    calls.usage = (6, 0)
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20, ABUSEIPDB_DAILY_QUOTA="10")
    await w.run_once()
    assert calls.candidate_args[0]["stale_only"] is False
    assert calls.candidate_args[0]["limit"] == 2


async def test_with_a_full_share_new_addresses_get_the_whole_cycle(calls: Calls) -> None:
    calls.usage = (0, 0)
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20, ABUSEIPDB_DAILY_QUOTA="1000")
    await w.run_once()
    assert calls.candidate_args[0]["limit"] == rep.PER_CYCLE


async def test_when_only_the_reserved_lookups_are_left_stale_answers_get_them(
    calls: Calls,
) -> None:
    calls.usage = (8, 0)  # 2 left of 10, both reserved
    calls.stale_candidates = [Candidate("203.0.113.50", True), Candidate("203.0.113.51", True)]
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20, ABUSEIPDB_DAILY_QUOTA="10")
    assert await w.run_once() == 2
    assert [a["stale_only"] for a in calls.candidate_args] == [True]
    assert calls.stored == ["203.0.113.50", "203.0.113.51"]
    # Each refresh is counted apart, next to the day's total.
    assert calls.reserved == ["abuseipdb", "abuseipdb:recheck", "abuseipdb", "abuseipdb:recheck"]


async def test_the_reserve_is_not_wasted_when_nothing_is_stale(calls: Calls) -> None:
    calls.usage = (8, 0)
    calls.stale_candidates = []
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20, ABUSEIPDB_DAILY_QUOTA="10")
    assert await w.run_once() == len(IPS)
    assert [a["stale_only"] for a in calls.candidate_args] == [True, False]
    assert calls.candidate_args[1]["limit"] == 2  # the 2 left, now open to new addresses
    assert "abuseipdb:recheck" not in calls.reserved


async def test_refreshes_already_made_count_against_the_reserve(calls: Calls) -> None:
    calls.usage = (8, 2)  # the reserve is spent: the 2 left are for anyone
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20, ABUSEIPDB_DAILY_QUOTA="10")
    await w.run_once()
    assert calls.candidate_args[0]["stale_only"] is False
    assert calls.candidate_args[0]["limit"] == 2


async def test_a_stale_address_that_follows_new_ones_is_counted_as_a_refresh(
    calls: Calls,
) -> None:
    calls.candidates = [Candidate(IPS[0], False), Candidate(IPS[1], True)]
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20)
    assert await w.run_once() == 2
    assert calls.reserved == ["abuseipdb", "abuseipdb", "abuseipdb:recheck"]


async def test_greynoise_keeps_a_share_for_stale_answers_too(calls: Calls) -> None:
    calls.usage = (5, 0)  # quota 7 keeps 2: nothing left for new addresses
    calls.stale_candidates = [Candidate(IPS[0], True)]
    w = worker(calls, GREYNOISE_API_KEY="k" * 20, GREYNOISE_DAILY_QUOTA="7")
    await w.run_once()
    assert calls.candidate_args[0]["provider"] == "greynoise"
    assert calls.candidate_args[0]["stale_only"] is True


# ---- addresses left out of the query ------------------------------------------------------------


async def test_the_skip_list_keeps_only_the_most_recent_addresses(calls: Calls) -> None:
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20)
    far = time.monotonic() + 1000
    total = rep.MAX_SKIPPED + 50
    for i in range(total):
        w._retry_after[("abuseipdb", f"2001:db8::{i:x}")] = far
    w._retry_after[("greynoise", "203.0.113.1")] = far  # another provider's list
    skipped = w._backed_off("abuseipdb")
    assert len(skipped) == rep.MAX_SKIPPED
    assert skipped[0] == f"2001:db8::{50:x}" and skipped[-1] == f"2001:db8::{total - 1:x}"
    assert "203.0.113.1" not in skipped


async def test_a_backed_off_address_that_comes_back_is_still_skipped(calls: Calls) -> None:
    # The query only knows the most recent ones: the loop must not look up an older one.
    w = worker(calls, ABUSEIPDB_API_KEY="k" * 20)
    w._retry_after[("abuseipdb", IPS[0])] = time.monotonic() + 1000
    assert await w.run_once() == len(IPS) - 1
    assert IPS[0] not in calls.stored
