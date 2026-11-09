"""Real UDP and TCP clients against the running listener."""

from __future__ import annotations

import asyncio
import contextlib

from suckerpot_common import EventType

from tests.conftest import (
    HarnessFactory,
    digest_header,
    header_value,
    param,
    sip_request,
    udp_exchange,
)

OPEN = {"reply_per_ip_rate": 1000.0, "reply_per_ip_burst": 1000.0, "pps_per_ip": 1e6,
        "pps_per_ip_burst": 1e6}  # fmt: skip


async def test_options_gets_200_with_allow(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        pad = ("Accept: application/sdp", "X-Padding: " + "p" * 200)
        (reply,) = await udp_exchange(h.port, sip_request("OPTIONS", extra=pad))
        text = reply.decode()
        assert text.startswith("SIP/2.0 200 OK\r\n")
        assert "Call-ID: abc123@198.51.100.7" in text and "CSeq: 1 OPTIONS" in text
        assert "tag=as" in header_value(reply, "To")
        assert "INVITE" in header_value(reply, "Allow")
        assert header_value(reply, "Server").startswith(("Asterisk PBX ", "FPBX-"))
        for word in ("honeypot", "suckerpot", "python", "asyncio"):
            assert word not in text.lower()


async def test_register_challenge_and_wrong_password(make_harness: HarnessFactory) -> None:
    async with make_harness(**OPEN) as h:
        (r1,) = await udp_exchange(h.port, sip_request("REGISTER", "sip:pbx.example.net"))
        assert r1.startswith(b"SIP/2.0 401 Unauthorized")
        challenge = header_value(r1, "WWW-Authenticate")
        nonce = param(challenge, "nonce")
        assert len(nonce) == 8 and param(challenge, "realm") == "asterisk"
        auth = digest_header("100", "wrong", "asterisk", nonce, "REGISTER", "sip:pbx.example.net")
        req = sip_request(
            "REGISTER", "sip:pbx.example.net", cseq=2, extra=(f"Authorization: {auth}",)
        )
        (r2,) = await udp_exchange(h.port, req)
        assert r2.startswith(b"SIP/2.0 401")
        logins = await h.events("login_attempt")
        assert len(logins) == 1
        d = logins[0].data
        assert d["username"] == "100" and d["success"] is False and d["password"] is None
        assert d["realm"] == "asterisk" and len(d["response_preview"]) == 8
        assert "register" in d["flags"] and "scanner_ua" in d["flags"]


async def test_register_weak_credentials_get_stateless_200(make_harness: HarnessFactory) -> None:
    async with make_harness(**OPEN) as h:
        (r1,) = await udp_exchange(h.port, sip_request("REGISTER", "sip:pbx.example.net"))
        nonce = param(header_value(r1, "WWW-Authenticate"), "nonce")
        for qop in (False, True):
            auth = digest_header("1000", "1000", "asterisk", nonce, "REGISTER",
                                 "sip:pbx.example.net", qop=qop)  # fmt: skip
            req = sip_request("REGISTER", "sip:pbx.example.net", cseq=2,
                              extra=(f"Authorization: {auth}",))  # fmt: skip
            (r2,) = await udp_exchange(h.port, req)
            assert r2.startswith(b"SIP/2.0 200 OK")
            assert "expires=120" in header_value(r2, "Contact")
        logins = await h.events("login_attempt")
        assert [e.data["success"] for e in logins] == [True, True]
        assert logins[0].data["password"] == "1000"
        # a forged nonce is not accepted even with the right password
        forged = digest_header(
            "1000", "1000", "asterisk", "0" * 8, "REGISTER", "sip:pbx.example.net"
        )
        (r3,) = await udp_exchange(h.port, sip_request("REGISTER", "sip:pbx.example.net",
                                                       extra=(f"Authorization: {forged}",)))  # fmt: skip
        assert r3.startswith(b"SIP/2.0 401")


async def test_invite_toll_fraud_flow(make_harness: HarnessFactory) -> None:
    async with make_harness(**OPEN) as h:
        uri = "sip:0041791234567@pbx.example.net"
        to = "<sip:0041791234567@pbx.example.net>"
        (r1,) = await udp_exchange(h.port, sip_request("INVITE", uri, to=to, body="v=0\r\n"))
        assert r1.startswith(b"SIP/2.0 407")
        nonce = param(header_value(r1, "Proxy-Authenticate"), "nonce")
        bad = digest_header("100", "nope", "asterisk", nonce, "INVITE", uri)
        (r2,) = await udp_exchange(h.port, sip_request("INVITE", uri, to=to,
                                                       extra=(f"Proxy-Authorization: {bad}",)))  # fmt: skip
        assert r2.startswith(b"SIP/2.0 407")  # chan_sip alwaysauthreject: re-challenge
        good = digest_header("100", "100", "asterisk", nonce, "INVITE", uri)
        (r3,) = await udp_exchange(h.port, sip_request("INVITE", uri, to=to,
                                                       extra=(f"Proxy-Authorization: {good}",)))  # fmt: skip
        assert r3.startswith(b"SIP/2.0 486 Busy Here")
        for r in (r1, r2, r3):  # never a 200 or any SDP
            assert b"application/sdp" not in r and b"m=audio" not in r
        cmds = await h.events("command")
        assert len(cmds) == 3
        d = cmds[0].data
        assert d["dialled"] == "0041791234567" and d["input"] == f"INVITE {uri} SIP/2.0"
        assert "toll_fraud" in d["flags"] and "invite" in d["flags"]
        assert d["to"] == "sip:0041791234567@pbx.example.net" and d["from"] == "sip:100@192.0.2.10"
        assert d["body_preview"].startswith("v=0")
        assert cmds[2].data["response_code"] == 486


async def test_other_methods(make_harness: HarnessFactory) -> None:
    async with make_harness(**OPEN) as h:
        (r,) = await udp_exchange(h.port, sip_request("SUBSCRIBE"))
        assert r.startswith(b"SIP/2.0 405")
        (r,) = await udp_exchange(h.port, sip_request("FOOBAR"))
        assert r.startswith(b"SIP/2.0 501")
        (r,) = await udp_exchange(h.port, sip_request("BYE"))
        assert r.startswith(b"SIP/2.0 481")
        assert await udp_exchange(h.port, sip_request("ACK")) == []
        assert await udp_exchange(h.port, b"garbage\r\n\r\n") == []


async def test_udp_event_aggregation(make_harness: HarnessFactory) -> None:
    async with make_harness(**OPEN) as h:
        await udp_exchange(h.port, sip_request("OPTIONS"), count=100, wait=0.2)
        events = await h.events()
        assert [e.type for e in events] == [EventType.connect, EventType.scan]
        first = events[1].data
        assert first["kind"] == "options_scan" and first["user_agent"] == "friendly-scanner"
        assert "options_scan" in first["flags"] and "scanner_ua" in first["flags"]
        h.tracker.close_all("test")
        events = await h.events()
        kinds = [(e.type, e.data.get("kind")) for e in events]
        assert (EventType.scan, "sip_summary") in kinds
        summary = next(e for e in events if e.data.get("kind") == "sip_summary")
        assert summary.data["methods"] == {"OPTIONS": 100}
        assert summary.data["aggregated"] == 99
        disc = next(e for e in events if e.type == EventType.disconnect)
        assert disc.data["messages"] == 100 and disc.data["reason"] == "test"
        assert len({e.session_id for e in events}) == 1
        assert all(e.sensor == "sip" and e.dst_port == 5060 for e in events)


async def test_loopback_is_quiet_by_default(make_harness: HarnessFactory) -> None:
    async with make_harness(quiet_loopback=True) as h:
        (reply,) = await udp_exchange(h.port, sip_request("OPTIONS"))
        assert reply.startswith(b"SIP/2.0 200")
        assert await h.events() == []


async def test_tcp_requests_in_one_connection(make_harness: HarnessFactory) -> None:
    async with make_harness(**OPEN) as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.tcp_port)
        req = sip_request("OPTIONS").replace(b"UDP", b"TCP")
        writer.write(req + req[:20])  # one full message and the start of another
        await writer.drain()
        async with asyncio.timeout(2):
            data = await reader.readuntil(b"\r\n\r\n")
        assert data.startswith(b"SIP/2.0 200 OK")
        writer.write(req[20:])
        await writer.drain()
        async with asyncio.timeout(2):
            data2 = await reader.readuntil(b"\r\n\r\n")
        assert data2.startswith(b"SIP/2.0 200 OK")
        writer.close()


async def test_tcp_oversized_and_slow_clients_are_dropped(make_harness: HarnessFactory) -> None:
    async with make_harness(**OPEN, first_data_timeout=0.4, idle_timeout=0.4) as h:
        # Content-Length beyond the cap: closed without a reply
        reader, writer = await asyncio.open_connection("127.0.0.1", h.tcp_port)
        writer.write(
            sip_request("INVITE", body="").replace(b"Content-Length: 0", b"Content-Length: 99999")
        )
        async with asyncio.timeout(2):
            assert await reader.read(100) == b""
        writer.close()
        # slowloris: a never-finished head is cut by the deadline
        reader, writer = await asyncio.open_connection("127.0.0.1", h.tcp_port)
        writer.write(b"OPTIONS sip:x SIP/2.0\r\nVia: a")
        async with asyncio.timeout(3):
            assert await reader.read(100) == b""
        writer.close()
        # silence from the start
        reader, writer = await asyncio.open_connection("127.0.0.1", h.tcp_port)
        async with asyncio.timeout(3):
            assert await reader.read(100) == b""
        writer.close()
        await asyncio.sleep(0.1)
        assert h.sensor.tcp_total == 0 and not h.sensor.tcp_per_ip


async def test_tcp_per_ip_cap(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=2, **OPEN) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.tcp_port) for _ in range(4)]
        await asyncio.sleep(0.2)
        assert h.sensor.tcp_total == 2 and h.sensor.tcp_refused == 2
        for _r, w in conns:
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
