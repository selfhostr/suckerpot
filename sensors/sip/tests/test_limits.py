"""Limits: memory guard, watchdog, event quotas, TCP framing, identity, healthcheck."""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest
from suckerpot_common import EventType

from sip_sensor import healthcheck
from sip_sensor.config import Config, parse_weak
from sip_sensor.identity import derive_profile, load_or_create_secret
from sip_sensor.memguard import MemoryGuard
from sip_sensor.server import take_message
from sip_sensor.sip import MAX_MESSAGE, ParseError
from sip_sensor.watchdog import LoopWatchdog
from tests.conftest import HarnessFactory, make_sensor, sip_request, udp_exchange


def fake_cgroup(tmp_path: Path, current: int, limit: int) -> Path:
    (tmp_path / "memory.current").write_text(str(current))
    (tmp_path / "memory.max").write_text(str(limit))
    (tmp_path / "memory.stat").write_text("inactive_file 0\n")
    return tmp_path


def test_memory_guard_refuses_and_sheds(tmp_path: Path, profile) -> None:  # type: ignore[no-untyped-def]
    cg = fake_cgroup(tmp_path, 200 << 20, 256 << 20)  # 78 %: refuse, do not shed
    guard = MemoryGuard(0, cgroup=cg)
    assert guard.limit == 256 << 20
    assert guard.sample() is False and guard.refusing
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(profile, guard, allow_private=True)
    assert sensor.on_datagram(sip_request("OPTIONS"), ("198.51.100.9", 5060)) is None
    assert sensor.udp_dropped == 1
    (cg / "memory.current").write_text(str(230 << 20))  # 90 %
    assert guard.sample() is True
    (cg / "memory.current").write_text(str(50 << 20))
    assert guard.sample() is False and not guard.refusing


def test_take_message_framing() -> None:
    msg = sip_request("INVITE", body="v=0\r\n")
    assert take_message(msg[:30]) is None
    assert take_message(msg[:-2]) is None  # body incomplete
    assert take_message(b"\r\n\r\n" + msg + b"XYZ") == (msg, b"XYZ")  # keep-alives tolerated
    for bad in (
        b"INVITE sip:x SIP/2.0\r\nContent-Length: 9999\r\n\r\n",
        b"INVITE sip:x SIP/2.0\r\nContent-Length: -1\r\n\r\n",
        b"INVITE sip:x SIP/2.0\r\n" + b"X: " + b"a" * MAX_MESSAGE + b"\r\n\r\n",
        b"A" * (MAX_MESSAGE + 1),
    ):
        with pytest.raises(ParseError):
            take_message(bad)


def test_take_message_is_fast_on_pathological_input() -> None:
    started = time.perf_counter()
    for _ in range(200):
        for raw in (b"\r\n" * 2000, b"A" * 4000, b"X:" * 2000 + b"\r\n\r\n", b"l: 1\r\n" * 600):
            try:
                take_message(raw)
            except ParseError:
                pass
    assert time.perf_counter() - started < 1.0


def test_full_datagram_path_is_fast_on_pathological_input(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(profile, pps_per_ip=1e9, pps_per_ip_burst=1e9)
    nasty = [
        b"REGISTER sip:x SIP/2.0\r\nAuthorization: Digest " + b"a=" * 500 + b"\r\n\r\n",
        b"INVITE sip:" + b"+" * 400 + b" SIP/2.0\r\n\r\n",
        sip_request("INVITE", extra=("Proxy-Authorization: Digest " + 'u="' * 300,)),
        b"OPTIONS sip:x SIP/2.0\r\n" + (b"Via: " + b"v," * 500 + b"\r\n") * 3 + b"\r\n",
    ]
    started = time.perf_counter()
    for i in range(300):
        for raw in nasty:
            sensor.on_datagram(raw, (f"203.0.113.{i % 200}", 5060))
    assert time.perf_counter() - started < 2.0


async def test_session_quota_and_admission(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, pub, sink, tracker, sensor = make_sensor(
        profile, allow_private=True, quota_priority=5, pps_per_ip=1e9, pps_per_ip_burst=1e9,
        reply_per_ip_burst=1e9, reply_per_ip_rate=1e9,
    )  # fmt: skip
    sink.start()
    for i in range(50):
        sensor.on_datagram(sip_request("INVITE", cseq=i), ("198.51.100.9", 5060))
    tracker.close_all("test")
    await sink.flush()
    cmds = [e for e in pub.events if e.type == EventType.command]
    assert len(cmds) == 5
    disc = next(e for e in pub.events if e.type == EventType.disconnect)
    assert disc.data["suppressed_events"] == 45 and disc.data["messages"] == 50
    await sink.close()


async def test_unrecorded_sources_are_summarised(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, pub, sink, tracker, sensor = make_sensor(
        profile, allow_private=True, sessions_burst_per_ip=1.0, sessions_per_sec_per_ip=0.0001,
        max_sessions=3,
    )  # fmt: skip
    sink.start()
    for i in range(10):
        sensor.on_datagram(sip_request("OPTIONS"), (f"198.51.100.{i + 1}", 5060))
    assert len(tracker) == 2  # unverified sources may fill 80 % of max_sessions
    assert tracker.flush_unrecorded(60.0) == 8
    await sink.flush()
    assert sum(1 for e in pub.events if e.data.get("kind") == "rate_limited") == 8
    await sink.close()


async def test_sweep_closes_idle_sessions(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, pub, sink, tracker, sensor = make_sensor(profile, allow_private=True)
    sink.start()
    sensor.on_datagram(sip_request("OPTIONS"), ("198.51.100.9", 5060))
    assert tracker.sweep(time.monotonic()) == 0
    assert tracker.sweep(time.monotonic() + 3600) == 1 and len(tracker) == 0
    await sink.flush()
    assert any(e.type == EventType.disconnect and e.data["reason"] == "idle" for e in pub.events)
    await sink.close()


async def test_watchdog_fires_on_blocked_loop() -> None:
    fired: list[float] = []
    dog = LoopWatchdog(limit=0.3, interval=0.1, on_stall=fired.append)
    dog.start()
    await asyncio.sleep(0.3)
    assert not fired
    time.sleep(0.8)  # noqa: ASYNC251 - blocks the loop on purpose
    await asyncio.sleep(0.05)
    dog.stop()
    assert fired


def test_secret_file_mode_and_profile(tmp_path: Path) -> None:
    secret = load_or_create_secret(tmp_path / "data")
    assert len(secret) == 64 and load_or_create_secret(tmp_path / "data") == secret
    assert (tmp_path / "data" / "profile_secret").stat().st_mode & 0o777 == 0o600
    prof = derive_profile(secret)
    assert prof.user_agent.startswith(("Asterisk PBX ", "FPBX-"))
    assert derive_profile(secret, "FPBX-16.0.40(18.20.0)").user_agent == "FPBX-16.0.40(18.20.0)"


def test_nonce_is_bound_to_ip_and_expires(profile) -> None:  # type: ignore[no-untyped-def]
    now = time.time()
    nonce = profile.nonce("198.51.100.9", now)
    assert profile.nonce_valid(nonce, "198.51.100.9", now + 10)
    assert not profile.nonce_valid(nonce, "198.51.100.10", now + 10)
    assert profile.nonce_valid(nonce, "198.51.100.9", now + 60)  # still valid in the next bucket
    assert not profile.nonce_valid(nonce, "198.51.100.9", now + 1000)
    assert len(nonce) == 8 and int(nonce, 16) >= 0
    assert nonce != f"{int(now):08x}"  # not a plain Unix time
    assert not profile.nonce_valid("zz" * 4, "198.51.100.9", now)
    assert not profile.nonce_valid("", "198.51.100.9", now)


def test_config_from_env() -> None:
    cfg = Config.from_env({"SENSOR_PORT": "5062", "SIP_PUBLIC_PORT": "5060",
                           "SENSOR_SIP_WEAK_CREDENTIALS": "200:abc,300:xyz:1", "SENSOR_SIP_TCP": "no"})  # fmt: skip
    assert cfg.port == 5062 and not cfg.tcp
    assert dict(cfg.weak_credentials) == {"200": "abc", "300": "xyz:1"}
    assert Config.from_env({}).tcp and Config.from_env({}).weak_credentials
    assert parse_weak("a:b,,:x,c") == {"a": "b"}
    assert len(parse_weak(",".join(f"u{i}:p" for i in range(500)))) == 50


async def test_healthcheck_probe_gets_a_200(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        os.environ["SENSOR_PORT"] = str(h.port)
        try:
            assert await asyncio.to_thread(healthcheck.main) == 0
        finally:
            del os.environ["SENSOR_PORT"]


async def test_server_survives_garbage_flood(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        import random

        rng = random.Random(3)
        blobs = [
            bytes(rng.randrange(256) for _ in range(rng.randrange(1, 600))) for _ in range(300)
        ]
        loop = asyncio.get_running_loop()
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        for blob in blobs:
            await loop.sock_sendto(sock, blob, ("127.0.0.1", h.port))
        sock.close()
        await asyncio.sleep(0.2)
        (reply,) = await udp_exchange(h.port, sip_request("OPTIONS"))
        assert reply.startswith(b"SIP/2.0 200")


def test_versions_are_chan_sip_era(profile) -> None:  # type: ignore[no-untyped-def]
    from sip_sensor.identity import VERSIONS

    assert all(v.split(".")[0] in ("13", "16", "18") for v in VERSIONS)


def test_via_gets_received_and_rport_when_it_fits(profile) -> None:  # type: ignore[no-untyped-def]
    from sip_sensor import sip

    assert sip.with_source("SIP/2.0/UDP 198.51.100.1:5060;branch=z9;rport", "1.2.3.4", 4000) == (
        "SIP/2.0/UDP 198.51.100.1:5060;branch=z9;received=1.2.3.4;rport=4000"
    )
    _c, _p, _s, _t, sensor = make_sensor(profile, allow_private=True)
    raw = sip_request("OPTIONS", extra=("X-Pad: " + "p" * 200,))
    out = sensor.on_datagram(raw, ("198.51.100.9", 4000))
    assert out is not None and b"received=198.51.100.9;rport=4000" in out and len(out) <= len(raw)
    assert b"Contact: <sip:100@192.0.2.10>" in out and b"Accept: application/sdp" in out
    tiny = sip_request("OPTIONS", ua=None)
    out = sensor.on_datagram(tiny, ("198.51.100.10", 4000))
    assert out is None or len(out) <= len(tiny)


async def test_verified_sources_have_their_own_admission_lane(profile) -> None:  # type: ignore[no-untyped-def]
    from tests.conftest import digest_header

    _c, pub, sink, tracker, sensor = make_sensor(
        profile, allow_private=True, global_sessions_per_sec=0.5, max_sessions=100,
        reply_per_ip_burst=1e9, reply_per_ip_rate=1e9, pps_per_ip=1e9, pps_per_ip_burst=1e9,
        pps_global=1e9, pps_global_burst=1e9,
    )  # fmt: skip
    sink.start()
    for i in range(400):  # spoofed flood exhausts the unverified lane
        sensor.on_datagram(sip_request("OPTIONS"), (f"203.0.{i // 250}.{i % 250 + 1}", 5060))
    assert tracker.unrecorded_total > 200
    real = "198.51.100.77"
    nonce = profile.nonce(real)
    auth = digest_header("100", "x", "asterisk", nonce, "REGISTER", "sip:pbx.example.net")
    sensor.on_datagram(
        sip_request("REGISTER", "sip:pbx.example.net", extra=(f"Authorization: {auth}",)),
        (real, 5060),
    )
    tracker.close_all("test")
    await sink.flush()
    mine = [e for e in pub.events if str(e.src_ip) == real]
    assert any(e.type == EventType.login_attempt for e in mine)
    assert all(e.data["source_verified"] is True for e in mine if e.data.get("kind") != "x")
    others = [e for e in pub.events if str(e.src_ip) != real and e.type == EventType.connect]
    assert others and all(e.data["source_verified"] is False for e in others)
    await sink.close()


def test_loopback_skips_global_reply_buckets() -> None:
    from dataclasses import replace

    from sip_sensor.guard import ReplyGate

    gate = ReplyGate(replace(Config(), reply_global_burst=0.0, reply_global_rate=0.0))
    assert not gate.permit("198.51.100.1", 5060, 300, 200)
    assert gate.permit("127.0.0.1", 5060, 300, 200)


def test_take_message_ignores_folded_lines() -> None:
    raw = (
        b"INVITE sip:x SIP/2.0\r\nSubject: a\r\n  Content-Length: 9999\r\nContent-Length: 0\r\n\r\n"
    )
    taken = take_message(raw)
    assert taken is not None and taken[0] == raw


async def test_forced_events_are_capped(profile) -> None:  # type: ignore[no-untyped-def]
    _c, _pub, sink, _t, _s = make_sensor(profile)
    sent = sum(
        sink.emit(
            session_id="x",
            src_ip="198.51.100.1",
            src_port=1,
            type_=EventType.scan,
            data={},
            force=True,
        )
        for _ in range(2000)
    )
    assert sent <= 340
