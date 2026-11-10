"""End to end through the real API and worker code, against a throwaway PostgreSQL.

Ten synthetic nodes enrol with a low proof-of-work difficulty, are aged by moving their
enrolment day back, submit batches with documentation addresses, the worker runs, a target is
confirmed, revealed, rechecked and reported in review mode through a local SMTP sink, and one
node leaves and is deleted.
"""

from __future__ import annotations

import asyncio
import email
import socket
from datetime import timedelta
from email.message import Message
from typing import Any

import pytest
from aiosmtpd.controller import Controller
from sqlalchemy import text
from suckerpot_netproto import blind

from hub import admin
from hub.config import Settings
from hub.reports import send
from hub.worker import WorkerContext, run_cycle

from ..conftest import Env
from ..helpers import batch, source

pytestmark = pytest.mark.integration
IP = "198.51.100.23"
URL = "http://dl.example.org/bins/x.sh"
URL_B = blind.blind_url(URL)
SHA = "ab" * 32


class Sink:
    def __init__(self) -> None:
        self.messages: list[Message] = []

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        self.messages.append(email.message_from_bytes(envelope.content))
        return "250 OK"


async def test_full_flow(env_factory: Any) -> None:
    env: Env = await env_factory(
        smtp_host="127.0.0.1", smtp_from="reports@example.org", smtp_starttls=False
    )
    nodes = await env.enrolled(10)
    # age the nodes (different enrolment weeks) and give them a week of activity
    async with env.worker() as s:
        for i, n in enumerate(nodes):
            await s.execute(
                text(
                    "UPDATE nodes SET enrolled_day = :d, reputation = 0.9 WHERE id = CAST(:i AS uuid)"
                ),
                {"d": env.clock().date() - timedelta(days=20 + 7 * i), "i": n.node_id},
            )
            for d in range(3, 9):
                await s.execute(
                    text(
                        "INSERT INTO batches (node_id, day, batch_id, items) VALUES (CAST(:i AS uuid), :d, :b, 1)"
                    ),
                    {
                        "i": n.node_id,
                        "d": env.clock().date() - timedelta(days=d),
                        "b": bytes([i, d]) * 8,
                    },
                )
        await s.commit()
    # two days of batches through the API
    for day in ("2026-10-30", "2026-10-31"):
        for n in nodes:
            r = await n.call(
                "POST",
                "/v1/observations",
                batch(
                    day,
                    sources=[
                        source(
                            IP,
                            services=["ssh", "telnet"],
                            activity=["scan"],
                            tags=[],
                            attempts=0,
                        )
                    ],
                    payloads=[
                        {
                            "url_b": URL_B,
                            "host_b": blind.blind_domain("dl.example.org"),
                            "sha256": SHA,
                            "family": "mirai",
                            "fetched": True,
                        }
                    ],
                ),
            )
            assert r.status == 200, r.json

    sink = Sink()
    with socket.socket() as probe_sock:
        probe_sock.bind(("127.0.0.1", 0))
        port = probe_sock.getsockname()[1]
    controller = Controller(sink, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        settings = Settings(**{**env.settings.__dict__, "smtp_port": port})

        async def resolver(kind: str, host: str) -> str | None:
            return "abuse@example.net"

        ctx = WorkerContext(
            settings=settings,
            sessionmaker=env.worker,
            clock=env.clock,
            corroborate=None,
            resolver=resolver,
            mailer=send.smtp_mailer(settings, env.clock),
        )
        first = await run_cycle(ctx)
        assert first.failed == [], first.steps

        # consensus: 10 nodes on 2 days confirm the sha256, the URL and the quiet address
        probe = nodes[0]
        pull = (await probe.call("GET", "/v1/targets")).json
        kinds = {(t["kind"], t["state"]) for t in pull["targets"]}
        assert ("sha256", "confirmed") in kinds and ("url", "confirmed") in kinds
        assert any(t["value"] == IP for t in pull["targets"])  # confirmed, but only a scan
        assert {"kind": "url", "value_b": URL_B} in pull["reveal"]

        # reveal flow
        r = await probe.call(
            "POST",
            "/v1/reveals",
            {"protocol": "spn/1", "items": [{"kind": "url", "value_b": URL_B, "value": URL}]},
        )
        assert r.json == {"accepted": 1, "rejected": 0}
        assert {"kind": "url", "value_b": URL_B} not in (
            await probe.call("GET", "/v1/targets")
        ).json["reveal"]

        # review mode: the report is queued and nothing is mailed
        await run_cycle(ctx)
        assert sink.messages == []
        async with env.worker() as s:
            row = (await s.execute(text("SELECT id, state, recipient FROM reports"))).one()
        assert (row.state, row.recipient) == ("queued", "abuse@example.net")

        # operator approval, next cycle sends
        assert (
            await admin.run(
                ["reports", "approve", str(row.id)], sessionmaker=env.worker, out=lambda _l: None
            )
            == 0
        )
        await run_cycle(ctx)
        assert len(sink.messages) == 1
        mail = sink.messages[0]
        part = mail.get_payload(0) if mail.is_multipart() else mail
        text_body = part.get_payload(decode=True).decode()  # type: ignore[union-attr]
        assert "hxxp://dl[.]example[.]org/bins/x[.]sh" in text_body
        assert "10 to 24 independent sensors" in text_body
        everything = mail.as_string()
        for n in nodes:
            assert str(n.node_id) not in everything and n.fingerprint not in everything
        for word in ("suckerpot", "selfhostr", "honeypot"):
            assert word not in everything.lower()
        for name in ("X-Mailer", "User-Agent"):
            assert mail[name] is None
        async with env.worker() as s:
            states: dict[str, str] = dict(
                (await s.execute(text("SELECT kind, state FROM targets"))).all()
            )
        assert states["url"] == "reported"

        # takedown: rechecks from two nodes on three days after the report
        pull = (await probe.call("GET", "/v1/targets")).json
        rid = next(t["id"] for t in pull["targets"] if t["kind"] == "url")
        assert rid in {x["id"] for x in pull["recheck"]}
        for _ in range(3):
            env.clock.advance(days=1)
            day = env.clock().date().isoformat()
            for n in nodes[:2]:
                asked = (await n.call("GET", "/v1/targets")).json["recheck"]
                assert rid in {x["id"] for x in asked}
                r = await n.call(
                    "POST",
                    "/v1/rechecks",
                    {"protocol": "spn/1", "day": day, "items": [{"id": rid, "state": "down"}]},
                )
                assert r.json == {"accepted": 1}
        await run_cycle(ctx)
        async with env.worker() as s:
            assert (
                await s.execute(text("SELECT state FROM targets WHERE id = :i"), {"i": rid})
            ).scalar_one() == "taken_down"

        # one node leaves: nothing about it remains
        leaver = nodes[-1]
        assert (await leaver.call("DELETE", "/v1/node")).json == {"deleted": True}
        async with env.worker() as s:
            for table in (
                "nodes",
                "batches",
                "observations",
                "nonces",
                "target_contributors",
                "takedown_votes",
                "recheck_assignments",
                "node_stats_weekly",
            ):
                col = "id" if table == "nodes" else "node_id"
                n = (
                    await s.execute(
                        text(f"SELECT count(*) FROM {table} WHERE {col} = CAST(:i AS uuid)"),
                        {"i": leaver.node_id},
                    )
                ).scalar_one()
                assert n == 0, table
        assert (await nodes[0].call("GET", "/v1/network")).status == 200
    finally:
        controller.stop()
        await asyncio.sleep(0)
