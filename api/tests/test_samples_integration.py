"""Samples, chain, egress and the guarded archive download against a real TimescaleDB."""

import hashlib
import io
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import pyzipper  # type: ignore[import-untyped]
from analytics_seed import Seed, api_engine, owner_engine
from argon2 import PasswordHasher
from sqlalchemy import text
from suckerpot_db import create_session_factory

import api.auth as auth_mod
import api.samples as samples_mod
from api.auth import AuthSettings
from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
ORIGIN = "https://testserver"
NOW = datetime.now(UTC).replace(microsecond=0)
BODY = b"#!/bin/sh\necho test payload\n"
SHA = hashlib.sha256(BODY).hexdigest()
CHILD = hashlib.sha256(b"child binary").hexdigest()
GONE = hashlib.sha256(b"purged").hexdigest()
URL = "http://192.0.2.50/a.sh"
URL2 = "http://198.51.100.8/bin.arm"


async def seed_all() -> None:
    seed = Seed()
    dl = "download_attempt"
    seed.session("s1", "ssh", "203.0.113.1", NOW - timedelta(hours=2), [(0.0, dl, {"url": URL})])
    seed.session("s2", "telnet", "203.0.113.2", NOW - timedelta(hours=1), [(0.0, dl, {"url": URL})])
    async with owner_engine() as owner:
        await seed.write(owner)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE indicators, fetch_targets, samples, enrichment_status, "
                "enrichment_quota, audit_log RESTART IDENTITY CASCADE"
            )
        )
        ind = (
            await conn.execute(
                text(
                    "INSERT INTO indicators (type, value, role, host, first_seen, last_seen) "
                    "VALUES ('url', :u, 'download_host', '192.0.2.50', :t, :t) RETURNING id"
                ),
                {"u": URL, "t": NOW},
            )
        ).scalar_one()
        for sid, sensor, ip, off in (
            ("s1", "ssh", "203.0.113.1", 2),
            ("s2", "telnet", "203.0.113.2", 1),
        ):
            await conn.execute(
                text("INSERT INTO indicator_sessions VALUES (:i, :s, CAST(:ip AS inet), :sn, :t)"),
                {"i": ind, "s": sid, "ip": ip, "sn": sensor, "t": NOW - timedelta(hours=off)},
            )
        t1 = (
            await conn.execute(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, indicator_id, status, "
                    "first_seen, last_sha256) VALUES (:u, 'http', '192.0.2.50', :i, 'fetched', "
                    ":t, :h) RETURNING id"
                ),
                {"u": URL, "i": ind, "t": NOW, "h": SHA},
            )
        ).scalar_one()
        t2 = (
            await conn.execute(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, parent_sha256, depth, status, "
                    "first_seen, last_sha256, origin) VALUES (:u, 'http', '198.51.100.8', :p, 1, "
                    "'fetched', :t, :h, 'network_verify') RETURNING id"
                ),
                {"u": URL2, "p": SHA, "t": NOW, "h": CHILD},
            )
        ).scalar_one()
        for sha, size, kind, arch, fam, seen, stored in (
            (SHA, len(BODY), "shell", None, None, NOW - timedelta(hours=1), True),
            (CHILD, 12, "ELF", "ARM", "Mirai", NOW - timedelta(minutes=30), True),
            (GONE, 6, "ELF", "MIPS", "Gafgyt", NOW - timedelta(days=2), False),
        ):
            await conn.execute(
                text(
                    "INSERT INTO samples (sha256, sha1, md5, size, kind, arch, family, first_seen, "
                    "last_seen, stored, analysis_status) VALUES (:s, 'a', 'b', :z, :k, :a, :f, "
                    ":t, :t, :st, 'done')"
                ),
                {"s": sha, "z": size, "k": kind, "a": arch, "f": fam, "t": seen, "st": stored},
            )
        await conn.execute(
            text("INSERT INTO sample_sources VALUES (:s, :t, :n, :n), (:c, :t2, :n, :n)"),
            {"s": SHA, "t": t1, "c": CHILD, "t2": t2, "n": NOW},
        )
        await conn.execute(
            text(
                "INSERT INTO sample_analysis (sha256, analyzed_at, yara, strings, deobfuscated) "
                "VALUES (:s, :t, CAST(:y AS jsonb), ARRAY['hello'], 'echo deobfuscated')"
            ),
            {
                "s": CHILD,
                "t": NOW,
                "y": '[{"rule":"mirai_generic","namespace":"botnets","tags":["mirai"],"meta":{}}]',
            },
        )
        await conn.execute(
            text(
                "INSERT INTO sample_links (sha256, kind, value, port, source, confidence) VALUES "
                "(:s, 'next_url', :u, NULL, 'regex', 'high'), "
                "(:c, 'c2_ip', '203.0.113.99', 23, 'config', 'medium')"
            ),
            {"s": SHA, "u": URL2, "c": CHILD},
        )
        await conn.execute(
            text("UPDATE sample_links SET target_id = :t WHERE kind = 'next_url'"), {"t": t2}
        )
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail) VALUES "
                "('egress', CAST(:d AS jsonb)), ('egress_collector', CAST(:c AS jsonb))"
            ),
            {
                "d": '{"open": true, "reason": "ok", "egress_ip": "198.51.100.77", '
                f'"checked_at": "{NOW.isoformat()}"}}',
                "c": '{"open": false, "reason": "tunnel_down", "egress_ip": null}',
            },
        )
        await conn.execute(
            text("INSERT INTO enrichment_quota (provider, day, used) VALUES ('collector', :d, 7)"),
            {"d": NOW.date()},
        )


@pytest.fixture
async def client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)
    monkeypatch.setenv(samples_mod.QUARANTINE_ENV, str(tmp_path))
    samples_mod._downloads.clear()
    for sha, data in ((SHA, BODY), (CHILD, b"child binary")):
        d = tmp_path / sha[:2] / sha[2:4]
        d.mkdir(parents=True, exist_ok=True)
        (d / sha).write_bytes(data)
    await seed_all()
    engine = api_engine()
    # Each archive request re-authenticates: lift the per-address limit so only
    # the archive limit is tested.
    settings = AuthSettings(password_hash=HASH, secret=b"k" * 40, rate_per_ip=100)
    app = create_app(create_session_factory(engine), enable_live=False, auth_settings=settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as c,
    ):
        r = await c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert r.status_code == 204
        c.headers.update({"Origin": ORIGIN, "X-CSRF-Token": c.cookies["__Host-sp_csrf"]})
        yield c
    await engine.dispose()


async def test_list_filters_and_pagination(client: httpx.AsyncClient) -> None:
    body: dict[str, Any] = (await client.get("/api/v1/samples")).json()
    assert [i["sha256"] for i in body["items"]] == [CHILD, SHA, GONE]
    child = body["items"][0]
    assert (child["family"], child["arch"], child["yara"], child["sources"]) == (
        "Mirai", "ARM", ["mirai_generic"], 1,
    )  # fmt: skip
    assert body["items"][1]["sessions"] == 2

    def shas(r: httpx.Response) -> list[str]:
        return [i["sha256"] for i in r.json()["items"]]

    assert shas(await client.get("/api/v1/samples", params={"family": "mirai"})) == [CHILD]
    assert shas(await client.get("/api/v1/samples", params={"yara": "mirai_generic"})) == [CHILD]
    assert shas(await client.get("/api/v1/samples", params={"q": SHA[:8].upper()})) == [SHA]
    assert shas(await client.get("/api/v1/samples", params={"q": "bin.arm"})) == [CHILD]
    assert shas(await client.get("/api/v1/samples", params={"kind": "elf", "status": "done"})) == [
        CHILD, GONE,
    ]  # fmt: skip
    since = (NOW - timedelta(hours=3)).isoformat()
    assert shas(await client.get("/api/v1/samples", params={"since": since})) == [CHILD, SHA]
    assert (await client.get("/api/v1/samples", params={"limit": 201})).status_code == 422
    assert (await client.get("/api/v1/samples", params={"cursor": "zz"})).status_code == 400

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(5):
        params: dict[str, Any] = {"limit": 1}
        if cursor:
            params["cursor"] = cursor
        page = (await client.get("/api/v1/samples", params=params)).json()
        seen += [i["sha256"] for i in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == [CHILD, SHA, GONE]


async def test_a_sample_says_whether_it_was_only_crawled(client: httpx.AsyncClient) -> None:
    page = hashlib.sha256(b"typed page").hexdigest()
    sheet = hashlib.sha256(b"style sheet of the page").hexdigest()
    async with owner_engine() as owner, owner.begin() as conn:
        for sha, kind, url, depth, parent in (
            (page, "html", "http://192.0.2.60/index.html", 0, None),  # an attacker typed it
            (sheet, "css", "http://192.0.2.60/site.css", 1, page),  # a link of that page
        ):
            await conn.execute(
                text(
                    "INSERT INTO samples (sha256, sha1, md5, size, kind, severity, first_seen, "
                    "last_seen, stored, analysis_status) VALUES (:s, 'a', 'b', 10, :k, 'info', "
                    ":t, :t, true, 'done')"
                ),
                {"s": sha, "k": kind, "t": NOW},
            )
            await conn.execute(
                text(
                    "WITH t AS (INSERT INTO fetch_targets (url, scheme, host, parent_sha256, "
                    "depth, status, first_seen, last_sha256) VALUES (:u, 'http', '192.0.2.60', "
                    ":p, :d, 'fetched', :t, :s) RETURNING id) "
                    "INSERT INTO sample_sources SELECT :s, id, :t, :t FROM t"
                ),
                {"u": url, "p": parent, "d": depth, "t": NOW, "s": sha},
            )
    items = {i["sha256"]: i for i in (await client.get("/api/v1/samples")).json()["items"]}
    assert items[sheet]["crawled"] is True
    assert items[page]["crawled"] is False
    assert items[SHA]["crawled"] is False and items[CHILD]["crawled"] is False
    detail = (await client.get(f"/api/v1/samples/{sheet}")).json()
    assert detail["item"]["crawled"] is True


async def test_detail_chain_and_malware_join(client: httpx.AsyncClient) -> None:
    d = (await client.get(f"/api/v1/samples/{CHILD}")).json()
    assert d["virustotal_url"].endswith(CHILD)
    assert d["analysis"]["deobfuscated"] == "echo deobfuscated"
    assert d["analysis"]["yara"][0]["rule"] == "mirai_generic"
    assert d["links"][0]["kind"] == "c2_ip" and d["links"][0]["port"] == 23
    assert d["sources"][0]["url"] == URL2
    # M32: a sample fetched only for the network says so; one with a local source does not.
    assert d["item"]["origin"] == "network_verify"
    top = (await client.get(f"/api/v1/samples/{SHA}")).json()
    assert top["analysis"] is None
    assert top["item"]["origin"] == "local"
    assert {s["session_id"] for s in top["recent_sessions"]} == {"s1", "s2"}
    assert top["sources"][0]["sessions"] == 2 and top["sources"][0]["sensors"] == ["ssh", "telnet"]
    assert (await client.get(f"/api/v1/samples/{'0' * 64}")).status_code == 404
    assert (await client.get("/api/v1/samples/not-a-hash")).status_code == 422

    chain = (await client.get(f"/api/v1/samples/{SHA}/chain")).json()
    kinds = sorted(n["kind"] for n in chain["nodes"])
    assert kinds == ["c2", "sample", "sample", "session", "session", "url", "url"]
    edges = {(e["from"], e["to"]) for e in chain["edges"]}
    assert ("session:s1", f"url:{URL}") in edges and (f"url:{URL}", f"sample:{SHA}") in edges
    assert (f"sample:{SHA}", f"url:{URL2}") in edges and (f"url:{URL2}", f"sample:{CHILD}") in edges
    assert (f"sample:{CHILD}", "c2:203.0.113.99:23") in edges

    m = (await client.get("/api/v1/malware")).json()["items"]
    a = next(i for i in m if i["url"] == URL)
    assert (a["sha256"], a["size"], a["fetch_status"]) == (SHA, len(BODY), "fetched")
    assert a["virustotal_url"].endswith(SHA)


async def test_egress_shows_gates_quota_and_quarantine_use_to_an_admin(
    client: httpx.AsyncClient,
) -> None:
    e = (await client.get("/api/v1/egress")).json()
    assert e["ingest"]["state"] == "open" and e["ingest"]["reason"] is None
    assert e["collector"] == {"state": "closed", "reason": "tunnel_down", "checked_at": None}
    assert e["exit_ip_allowed"] is True and e["exit_ip"] == "198.51.100.77"
    assert e["collector_quota"]["used"] == 7 and e["collector_quota"]["limit"] > 0
    assert e["quarantine"]["used_bytes"] == len(BODY) + 12  # the purged sample does not count


async def archive(client: httpx.AsyncClient, sha: str, **body: Any) -> httpx.Response:
    return await client.post(f"/api/v1/samples/{sha}/archive", json=body)


async def test_archive_requires_the_password_and_is_an_aes_zip(client: httpx.AsyncClient) -> None:
    assert (await archive(client, SHA)).status_code == 401
    wrong = await archive(client, SHA, password="nope")
    assert wrong.status_code == 403 and wrong.json()["code"] == "reauth_failed"
    assert (await archive(client, "g" * 64, password=PASSWORD)).status_code == 422
    assert (await archive(client, "A" * 64, password=PASSWORD)).status_code == 422
    assert (await archive(client, GONE, password=PASSWORD)).status_code == 404
    assert (await archive(client, "1" * 64, password=PASSWORD)).status_code == 404

    ok = await archive(client, SHA, password=PASSWORD)
    assert ok.status_code == 200
    assert ok.headers["content-type"] == "application/zip"
    assert ok.headers["cache-control"] == "no-store"
    assert ok.headers["x-content-type-options"] == "nosniff"
    assert BODY not in ok.content
    with pyzipper.AESZipFile(io.BytesIO(ok.content)) as zf:
        assert zf.namelist() == [f"{SHA}.bin"]
        data = zf.read(f"{SHA}.bin", pwd=b"infected")
        with pytest.raises(RuntimeError):
            zf.read(f"{SHA}.bin", pwd=b"wrong")
    assert hashlib.sha256(data).hexdigest() == SHA

    async with owner_engine() as owner, owner.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT actor, action, target, details FROM audit_log"
                    " WHERE action = 'sample.download'"
                )
            )
        ).all()
    assert [(r.actor, r.action, r.target) for r in rows] == [("admin", "sample.download", SHA)]
    assert "infected" not in str(rows[0].details)


async def test_archive_refuses_a_tampered_file_and_rate_limits(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    (tmp_path / CHILD[:2] / CHILD[2:4] / CHILD).write_bytes(b"swapped")
    bad = await archive(client, CHILD, password=PASSWORD)
    assert bad.status_code == 500 and b"swapped" not in bad.content
    samples_mod._downloads.clear()  # the refused download above already used one slot
    for _ in range(samples_mod.ARCHIVE_PER_HOUR):
        assert (await archive(client, SHA, password=PASSWORD)).status_code == 200
    limited = await archive(client, SHA, password=PASSWORD)
    assert limited.status_code == 429 and "retry-after" in limited.headers
