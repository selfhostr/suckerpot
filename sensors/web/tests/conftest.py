from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from suckerpot_common import Event

from web_sensor.config import Config
from web_sensor.events import EventSink
from web_sensor.memguard import MemoryGuard
from web_sensor.profile import build_profile
from web_sensor.server import WebSensor, WebServer
from web_sensor.site import Site
from web_sensor.tls import ensure_certificate, make_context


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


@dataclass
class Harness:
    http: int
    https: int
    publisher: FakePublisher
    sensor: WebSensor
    sink: EventSink
    cfg: Config

    async def events(self, type_: str | None = None, wait: float = 0.15) -> list[Event]:
        await asyncio.sleep(wait)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def raw(self, data: bytes, *, port: int | None = None, wait: float = 1.0) -> bytes:
        """Send bytes, read until the server closes or ``wait`` passes without data."""
        reader, writer = await asyncio.open_connection("127.0.0.1", port or self.http)
        writer.write(data)
        await writer.drain()
        out = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), wait)
                if not chunk:
                    break
                out += chunk
        except TimeoutError:
            pass
        writer.close()
        return out

    def tls_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    d = tmp_path_factory.mktemp("tls")
    profile = build_profile(b"x" * 32, 1_790_000_000.0)
    return ensure_certificate(str(d), "srv-web01", profile)


@pytest.fixture
async def harness(tls_files: tuple[Path, Path]) -> AsyncIterator[Harness]:
    async with _start(tls_files, {}) as h:
        yield h


@contextlib.asynccontextmanager
async def _start(
    tls_files: tuple[Path, Path], overrides: dict[str, object]
) -> AsyncIterator[Harness]:
    base: dict[str, object] = {
        "host": "127.0.0.1",
        "http_port": 0,
        "https_port": 0,
        "quiet_loopback": False,
        "conn_rate": 1000.0,
        "conn_burst": 1000.0,
    }
    opts = dict(overrides)
    # The real guard would read the test runner's own cgroup: use a fixed one unless a test
    # brings its own.
    guard = opts.pop("guard", None) or MemoryGuard(1 << 40, cgroup=Path("/nonexistent"))
    cfg = replace(Config(), **{**base, **opts})  # type: ignore[arg-type]
    profile = build_profile(b"x" * 32, 1_790_000_000.0)
    site = Site(cfg, profile, "2026-10-01T10:00:00+0000")
    pub = FakePublisher()
    sink = EventSink(pub, rate=1000, burst=2000, global_rate=5000, global_burst=10000)
    sink.start()
    holder: list[WebSensor] = []
    ctx = make_context(*tls_files, lambda o, n: holder[0].on_sni(o, n))
    sensor = WebSensor(cfg, sink, site, ctx, guard=guard)  # type: ignore[arg-type]
    holder.append(sensor)
    server = WebServer(cfg, sensor)
    ports = await server.start()
    h = Harness(ports["http"], ports["https"], pub, sensor, sink, cfg)
    try:
        yield h
    finally:
        await server.stop()
        await sink.close()


@pytest.fixture
def start_with(
    tls_files: tuple[Path, Path],
) -> Callable[..., contextlib.AbstractAsyncContextManager[Harness]]:
    def factory(**overrides: object) -> contextlib.AbstractAsyncContextManager[Harness]:
        return _start(tls_files, overrides)

    return factory


@pytest.fixture(scope="session", autouse=True)
def _record_trap_differential() -> Iterator[None]:
    """Every request the suite sends is replayed against the pre-pack reference at the end
    (test_zz_trap_differential.py): flags, CVEs and the SEVERE decision must be identical."""
    from legacy_detect import recording

    with recording():
        yield
