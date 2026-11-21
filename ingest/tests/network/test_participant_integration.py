"""Participant and verifier storage against a real TimescaleDB: self-term auto-confirm,
SELF_ADDRESS, the verification queue under the ingest role's grants, the leave marker, the status
document (M32)."""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.abuse.selfterms import TermsCache, learn, parse_self_address
from ingest.network import cli
from ingest.network.store import SqlStore
from ingest.network.verifier import SqlVerifyStore, StaleFetch, TaskRow

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

Factory = async_sessionmaker[AsyncSession]
NOW = datetime.now(UTC)
ENV = {
    "SUCKERPOT_STACK_MODE": "participant",
    "NETWORK_ENABLED": "true",
    "NETWORK_CONSENT": "v2:sources,payloads,c2,files,rechecks:2026-11-03",
    "NETWORK_VERIFIER": "true",
}


async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM network_verify_tasks"))
        await conn.execute(text("DELETE FROM network_submissions"))
        await conn.execute(text("DELETE FROM enrichment_status WHERE name = 'network'"))
        await conn.execute(
            text(
                "UPDATE network_membership SET desired='off', state='off', pseudonym=NULL, "
                "pubkey=NULL, privkey_enc=NULL, privkey_nonce=NULL, left_day=NULL, "
                "requested_by=NULL, requested_at=NULL, last_error_code=NULL, enrolled_day=NULL, "
                "eligible_from_day=NULL, fingerprint=NULL, standing=NULL, last_pull_at=NULL, "
                "last_summary_at=NULL WHERE id = 1"
            )
        )


async def add_http(engine: AsyncEngine, n: int, host: str, days_ago: int = 0) -> None:
    async with engine.begin() as conn:
        for i in range(n):
            await conn.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, "
                    "dst_port, data) VALUES (:ts, 'web', :sid, 'http_request', "
                    "CAST(:ip AS inet), 40000, 8080, CAST(:d AS jsonb))"
                ),
                {
                    "ts": datetime.now(UTC) - timedelta(minutes=20, days=days_ago),
                    "sid": f"pi-{host}-{days_ago}-{i}",
                    "ip": f"10.{40 + i}.0.9",
                    "d": json.dumps({"host": host, "path": "/"}),
                },
            )


async def confirmed(engine: AsyncEngine, kind: str) -> list[bool]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT confirmed FROM report_self_terms WHERE kind = :k"), {"k": kind}
        )
        return [r.confirmed for r in rows]


# -- self terms ------------------------------------------------------------------------------------


async def test_auto_confirm_applies_to_learned_addresses_only(
    engine: AsyncEngine, factory: Factory
) -> None:
    await add_http(engine, 3, "8.8.4.4")
    assert await learn(factory) == 1  # stored unconfirmed: the ingest role cannot confirm
    assert await confirmed(engine, "address") == [False]
    plain = await TermsCache(factory, {}).get()
    assert plain is not None and not plain.has_self_address
    auto = await TermsCache(
        factory, {"SELF_TERMS_AUTO_CONFIRM": "true", "SUCKERPOT_STACK_MODE": "participant"}
    ).get()
    assert auto is not None and not auto.has_self_address  # one day of planting is not enough
    for d in (1, 2):
        await add_http(engine, 3, "8.8.4.4", days_ago=d)
    seen = await TermsCache(
        factory, {"SELF_TERMS_AUTO_CONFIRM": "true", "SUCKERPOT_STACK_MODE": "participant"}
    ).get()
    assert seen is not None and seen.has_self_address  # named on three days: it acts


async def test_self_address_acts_without_a_row(engine: AsyncEngine, factory: Factory) -> None:
    terms = await TermsCache(factory, {"SELF_ADDRESS": " 8.8.4.4 "}).get()
    assert (
        terms is not None
        and terms.has_self_address
        and terms.is_self(ipaddress.ip_address("8.8.4.4")) is not None
    )
    bad = await TermsCache(factory, {"SELF_ADDRESS": "nonsense"}).get()
    assert bad is not None and not bad.has_self_address


def test_parse_self_address() -> None:
    assert parse_self_address("[2001:db8::1]") == "2001:db8::1"
    assert parse_self_address("198.51.100.4") == "198.51.100.4"
    assert parse_self_address("0.0.0.0") is None  # noqa: S104
    assert parse_self_address("224.0.0.1") is None and parse_self_address("") is None


# -- verification queue under the ingest role --------------------------------------------------------


async def test_the_verify_queue_uses_only_the_granted_columns(
    engine: AsyncEngine, factory: Factory
) -> None:
    await clean(engine)
    vs = SqlVerifyStore(factory)
    url = "http://198.51.100.9/x.sh"
    first = await vs.queue_fetch(url, "198.51.100.9", "http", NOW)
    again = await vs.queue_fetch(url, "198.51.100.9", "http", NOW)
    assert first is not None and first == again  # an existing target is reused
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT origin, depth, status FROM fetch_targets WHERE id = :i"), {"i": first}
            )
        ).one()
    assert (row.origin, row.depth, row.status) == ("network_verify", 0, "pending")

    task = TaskRow("v_00000000aaaa", url, "198.51.100.9", "queued", NOW, NOW + timedelta(hours=6))
    await vs.add_task(task)
    await vs.add_task(task)  # idempotent
    await vs.update_task(task.hub_id, fetch_target_id=first)
    assert await vs.has_task(task.hub_id) and not await vs.has_task("v_00000000bbbb")
    assert [t.hub_id for t in await vs.open_tasks()] == [task.hub_id]
    assert await vs.count_since(NOW - timedelta(minutes=1)) == 1
    assert await vs.count_since(NOW - timedelta(minutes=1), "203.0.113.1") == 0
    assert await vs.counts() == {"queued": 1}
    with pytest.raises(ValueError):
        await vs.update_task(task.hub_id, url="http://elsewhere.example.org/")

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, kind, arch, family, "
                "first_seen, last_seen, analysis_status) VALUES (:s, 'a', 'b', 4096, 'elf', "
                "'arm', 'mirai', now(), now(), 'done')"
            ),
            {"s": "c" * 64},
        )
        await conn.execute(
            text("UPDATE fetch_targets SET status='fetched', last_sha256=:s WHERE id=:i"),
            {"s": "c" * 64, "i": first},
        )
    with pytest.raises(StaleFetch):  # a fetched row with no recent attempt is never reused
        await vs.queue_fetch(url, "198.51.100.9", "http", NOW)
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE fetch_targets SET last_attempt_at = :t WHERE id = :i"),
            {"t": NOW - timedelta(hours=1), "i": first},
        )
    assert await vs.queue_fetch(url, "198.51.100.9", "http", NOW) == first  # recent: reusable
    view = await vs.fetch_view(first)
    assert view is not None and (view.status, view.size, view.kind, view.family) == (
        "fetched", 4096, "elf", "mirai",
    )  # fmt: skip
    await vs.update_task(task.hub_id, state="reported", reported_at=NOW)
    assert await vs.open_tasks() == []
    await clean(engine)


# -- leave marker and the status document ----------------------------------------------------------------


async def test_a_wipe_marks_the_leave_and_removes_the_verify_tasks(
    engine: AsyncEngine, factory: Factory
) -> None:
    await clean(engine)
    store, vs = SqlStore(factory), SqlVerifyStore(factory)
    await vs.add_task(TaskRow("v_00000000cccc", "http://x", "x", "done", NOW, NOW))
    await store.update(desired="member", state="member", requested_by="installer")
    await store.wipe()
    m = await store.membership()
    assert m.left_day == NOW.date() and m.requested_by is None and m.desired == "off"
    assert await vs.counts() == {}
    await clean(engine)


async def test_status_document_shape_and_no_secret(engine: AsyncEngine, factory: Factory) -> None:
    await clean(engine)
    store = SqlStore(factory)
    await store.update(
        desired="member", state="member", pseudonym="amber-falcon-42", fingerprint="3f9a1c07",
        privkey_enc=b"opaque-test-bytes", privkey_nonce=b"n" * 12, pubkey=b"p" * 32,
        enrolled_day=NOW.date(), eligible_from_day=NOW.date() + timedelta(days=14),
        last_pull_at=NOW - timedelta(hours=1),
    )  # fmt: skip
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO network_submissions (day, batch_id, sent_at, status, counts, "
                "dropped, payload) VALUES (:d, 'b1', now(), 'sent', "
                'CAST(\'{"sources": 412, "payloads": 9, "c2": 0, "files": 0}\' AS jsonb), '
                "CAST('{}' AS jsonb), CAST('{\"sources\": []}' AS jsonb))"
            ),
            {"d": NOW.date() - timedelta(days=1)},
        )
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail, updated_at) VALUES ('network', "
                "CAST(:d AS jsonb), now()) ON CONFLICT (name) DO UPDATE SET detail = "
                "EXCLUDED.detail"
            ),
            {
                "d": json.dumps(
                    {
                        "verifier": "ok",
                        "verify_reveals": True,
                        "revealed": {NOW.date().isoformat(): 3},
                    }
                )
            },
        )
    doc = await cli.build_status(factory, ENV, now=NOW)
    blob = json.dumps(doc)
    assert "opaque-test" not in blob and "privkey" not in blob and "last_batch" not in doc
    net = doc["network"]
    assert doc["schema"] == 1 and doc["mode"] == "participant" and doc["level"] in ("ok", "warning")
    assert net["membership"]["pseudonym"] == "amber-falcon-42"
    assert net["membership"]["counts_toward_consensus"] is False
    assert net["consent"]["state"] == "valid" and net["path"] == "vpn"
    assert net["sent"][0]["sources"] == 412 and net["sent"][0]["links"] == 9
    assert net["verify_reveals"] == {"enabled": True, "last_7_days": 3}
    assert net["verifier"]["state"] == "ok" and net["own_address"]["state"] == "waiting"
    other = await cli.build_status(factory, {**ENV, "SELF_ADDRESS": "198.51.100.4"}, now=NOW)
    assert other["network"]["own_address"]["state"] == "manual"
    assert "hub_contact_old" not in doc["warnings"]
    assert doc["state"] == "member" and doc["node"] == "3f9a1c07" and doc["path"] == "vpn"
    assert doc["hub"]["signature_ok"] is True and doc["reveals_7d"] == 3
    assert doc["sent"][0] == {"day": doc["sent"][0]["day"], "sources": 412, "links": 9, "files": 0}
    assert isinstance(doc["sessions_24h"], dict)
    withbatch = await cli.build_status(factory, ENV, now=NOW, last_batch=True)
    assert withbatch["last_batch"]["batch"] == {"sources": []}
    await clean(engine)


async def test_leave_and_join_commands(engine: AsyncEngine, factory: Factory) -> None:
    await clean(engine)
    assert (await cli.build_status(factory, ENV))["state"] == "not_joined"
    assert (await cli.leave(factory))["requested"] is False  # never joined: the marker only
    assert (await cli.build_status(factory, ENV))["state"] == "left"
    assert (await SqlStore(factory).membership()).left_day is not None
    doc, code = await cli.join(factory, ENV)
    assert code == 0 and doc["joined"] is True
    assert (await SqlStore(factory).membership()).left_day is None
    assert (await cli.join(factory, {**ENV, "SUCKERPOT_STACK_MODE": "full"}))[1] == 2
    assert (await cli.join(factory, {**ENV, "NETWORK_CONSENT": "v9:x:2026-11-03"}))[0] == {
        "joined": False,
        "reason": "consent_outdated",
    }
    await SqlStore(factory).update(desired="member", state="member")
    assert (await cli.leave(factory))["requested"] is True
    assert (await SqlStore(factory).membership()).desired == "leave"
    await clean(engine)


async def test_join_restarts_a_refused_enrolment_and_renames_a_member(
    engine: AsyncEngine, factory: Factory
) -> None:
    await clean(engine)
    store = SqlStore(factory)
    await store.update(state="error", desired="off", last_error_code="pseudonym_taken")
    doc = await cli.build_status(factory, ENV, now=NOW)
    assert doc["state"] == "error" and doc["error_code"] == "pseudonym_taken"
    assert doc["last_error"] == {"code": "pseudonym_taken", "since": None}
    assert (await cli.join(factory, ENV, "bad@name"))[0]["reason"] == "pseudonym_invalid"
    doc, code = await cli.join(factory, ENV)
    m = await store.membership()
    assert code == 0 and doc["state"] == "error"
    assert (m.state, m.desired, m.last_error_code) == ("off", "off", None)
    await store.update(
        desired="member", state="member", pseudonym=None, last_error_code="pseudonym_taken"
    )
    await cli.join(factory, ENV, "grey heron")
    m = await store.membership()
    assert m.pseudonym == "grey heron" and m.last_error_code is None and m.state == "member"
    await clean(engine)
