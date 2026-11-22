"""``GET /results/effect`` (M38 G1) against a real TimescaleDB, with synthetic frozen pairs.

The API role reads the address-free views only; the test seeds as the owner.
"""

# ruff: noqa: F811  (the imported `client` fixture is requested by name)
import base64
import os
import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from suckerpot_db.report_effect import Cells, newcombe_paired
from test_abuse_integration import client  # noqa: F401  (the seeded, signed-in admin client)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]
NOW = datetime.now(UTC).replace(microsecond=0)


@pytest.fixture(autouse=True)
def _key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", base64.b64encode(bytes(range(32, 72))).decode())


@pytest.fixture
async def world(client: httpx.AsyncClient) -> httpx.AsyncClient:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("TRUNCATE report_effect_pairs, report_effect_unmatched, abuse_holdouts")
        )
    return client


async def seed(cells: Cells, *, days_ago: int = 30, tier: str = "A") -> None:
    """Pairs with a frozen 7-day outcome, on documentation addresses (at most 250 pairs)."""
    rows: list[tuple[bool, bool]] = (
        [(True, True)] * cells.a
        + [(True, False)] * cells.b
        + [(False, True)] * cells.c
        + [(False, False)] * cells.d
    )
    async with owner_engine() as owner, owner.begin() as conn:
        base = int(await conn.scalar(text("SELECT count(*) FROM report_effect_pairs")) or 0)
        for i, (sr, sc) in enumerate(rows):
            n = base + i
            await conn.execute(
                text(
                    "INSERT INTO report_effect_pairs (index_at, reported_value, control_value, "
                    "tier, activity_class, volume_bucket, recency_bucket, seen_r_7, seen_c_7, "
                    "observed_7, frozen_7_at) VALUES (:t, CAST(:r AS inet), CAST(:c AS inet), "
                    ":tier, 'login', 1, 0, :sr, :sc, true, :t)"
                ),
                {
                    "t": NOW - timedelta(days=days_ago), "r": f"198.51.100.{n + 1}",
                    "c": f"203.0.113.{n + 1}", "tier": tier, "sr": sr, "sc": sc,
                },
            )  # fmt: skip


async def test_no_pair_says_not_enough_data(world: httpx.AsyncClient) -> None:
    res = await world.get("/api/v1/results/effect")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["available"] is True
    e = body["effect"]
    assert e["verdict"] == "not_enough_data" and e["pairs"] == 0 and e["needed"] == 30
    assert e["seen_reported"] is None and e["lo"] is None and e["interval"] is None
    assert e["sentence"].startswith("Not enough data yet")
    assert "%" not in res.text


async def test_below_the_minimum_no_number_leaves_the_api(world: httpx.AsyncClient) -> None:
    await seed(Cells(a=4, b=20, c=0, d=5))  # 29 pairs, lopsided
    res = await world.get("/api/v1/results/effect")
    e = res.json()["effect"]
    assert e["pairs"] == 29 and e["verdict"] == "not_enough_data"
    assert e["seen_reported"] is None and e["seen_control"] is None and e["difference"] is None
    assert "%" not in res.text


async def test_120_synthetic_pairs(world: httpx.AsyncClient) -> None:
    cells = Cells(a=40, b=10, c=30, d=40)
    await seed(cells)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_effect_unmatched (index_at, value, reason) VALUES "
                "(:t, '192.0.2.1', 'no_control'), (:t, '192.0.2.2', 'no_activity')"
            ),
            {"t": NOW - timedelta(days=30)},
        )
        await conn.execute(
            text(
                "INSERT INTO report_effect_pairs (index_at, reported_value, control_value, tier, "
                "activity_class, volume_bucket, recency_bucket, observed_7, excluded_7, "
                "frozen_7_at) VALUES (:t, '192.0.2.11', '192.0.2.12', 'C', 'login', 1, 0, false, "
                "'not_observed', :t), (:t, '192.0.2.13', '192.0.2.14', 'B', 'login', 1, 0, null, "
                "null, null)"
            ),
            {"t": NOW - timedelta(days=30)},
        )
    res = await world.get("/api/v1/results/effect", params={"horizon": 7})
    assert res.status_code == 200, res.text
    body = res.json()
    e = body["effect"]
    lo, hi = newcombe_paired(40, 10, 30, 40)
    assert e["pairs"] == 120 and e["discordant"] == 40
    assert e["seen_reported"] == pytest.approx(50 / 120)
    assert e["seen_control"] == pytest.approx(70 / 120)
    assert e["lo"] == pytest.approx(lo) and e["hi"] == pytest.approx(hi)
    assert e["verdict"] == "lower" and hi < 0
    assert "42 % against 58 %" in e["sentence"] and "(120 pairs;" in e["sentence"]
    m = body["method"]
    assert m["tiers"] == {"A": 120, "B": 1, "C": 1} and m["pairs_made"] == 122
    assert m["not_observed"] == 1 and m["waiting"] == 1
    assert m["unmatched"] == 2 and m["unmatched_reasons"] == {"no_control": 1, "no_activity": 1}
    assert not re.search(r"(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+", res.text)  # no address
    # The 30-day horizon has no frozen outcome yet: progress only.
    res30 = await world.get("/api/v1/results/effect", params={"horizon": 30})
    assert res30.json()["effect"]["verdict"] == "not_enough_data"
    assert res30.json()["method"]["waiting"] == 122
    # The period filter applies to the index time.
    old = await world.get(
        "/api/v1/results/effect", params={"until": (NOW - timedelta(days=60)).isoformat()}
    )
    assert old.json()["effect"]["pairs"] == 0


async def test_only_seven_or_thirty_days(world: httpx.AsyncClient) -> None:
    res = await world.get("/api/v1/results/effect", params={"horizon": 14})
    assert res.status_code == 422
