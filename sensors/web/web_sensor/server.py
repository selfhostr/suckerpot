"""Listeners, connection handling and event emission for the web sensor."""

from __future__ import annotations

import asyncio
import asyncio.sslproto
import contextlib
import ipaddress
import json
import logging
import random
import secrets
import socket
import ssl
import time
import weakref
from dataclasses import dataclass, field
from typing import Any

from suckerpot_common import EventType

from web_sensor import apache
from web_sensor.config import Config
from web_sensor.detect import Analysis, Detector
from web_sensor.events import EventSink, _Buckets
from web_sensor.httpio import (
    ClientGone,
    ConnReader,
    HeaderTimeout,
    HttpError,
    Request,
    to_text,
)
from web_sensor.memguard import MemoryGuard
from web_sensor.response import RenderContext, Response, render
from web_sensor.site import Ctx, Outcome, Site

log = logging.getLogger("web_sensor.server")

# Budgeted bytes per connection, measured on the hardened container with
# tests/load/measure.sh (see README, "Limits"): a client that sends three pipelined 118 KB
# requests and never reads holds 327 KiB (plain) / 544 KiB (TLS) per connection, of which the
# 146 KB pending response is charged separately when it is written. That leaves parser state,
# the StreamReader buffer, transport buffers and the kernel socket buffers (charged to the
# container's cgroup): 181 KiB; TLS adds OpenSSL's state and buffers, the MemoryBIOs and
# SSLProtocol's buffers: 217 KiB more. Rounded up.
_CONN_COST = 192 * 1024
_TLS_COST = 224 * 1024
_READER_LIMIT = 16 * 1024  # StreamReader pauses the transport at twice this
_TLS_READ_CHUNK = 16 * 1024  # asyncio's SSLProtocol default is 256 KiB per connection
_TLS_READ_HIGH = 32 * 1024
_TLS_WRITE_HIGH = 32 * 1024
_TLS_WRITE_CHUNK = 16 * 1024  # decrypted-side read buffer high-water mark (default 256 KiB)
_SOCK_BUF = 32 * 1024  # Linux doubles it: ~64 KB effective SO_RCVBUF / SO_SNDBUF
_XMLRPC_BODY = 256 * 1024
_MAX_RESPONSE = 8 * 1024 * 1024
_MAX_HEADERS_LOGGED = 64
_LOOPBACK = frozenset({"127.0.0.1", "::1"})


# Per-field-group budgets (JSON size), applied before ``truncate_data`` so that padding in one
# group can never shrink the others (the whole event is capped at 16 KB).
_G_HEADERS = 4500
_G_PATH = 2000
_G_BODY = 2500
_G_SMALL = 1000
_G_PHP2SHELL = 2000


def _fit(text: str, limit: int) -> str:
    """Cut ``text`` so that its JSON encoding is at most ``limit`` bytes."""
    text = text[:limit]
    while len(json.dumps(text)) > limit and text:
        text = text[: max(0, len(text) * 3 // 4 - 1)]
    return text


def _cap_strings(obj: Any, n: int, depth: int = 0) -> Any:
    if isinstance(obj, str):
        return obj[:n]
    if depth > 4:
        return None
    if isinstance(obj, dict):
        return {str(k)[:64]: _cap_strings(v, n, depth + 1) for k, v in list(obj.items())[:16]}
    if isinstance(obj, list):
        return [_cap_strings(v, n, depth + 1) for v in obj[:16]]
    return obj


def normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return "0.0.0.0"  # noqa: S104 - placeholder for an unparsable peer address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


class Budget:
    """Global byte budget for per-connection buffers."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def acquire(self, n: int) -> bool:
        if self.used + n > self.limit:
            return False
        self.used += n
        return True

    def release(self, n: int) -> None:
        self.used = max(0, self.used - n)

    def available(self) -> int:
        return max(0, self.limit - self.used)


@dataclass
class Listener:
    name: str
    port: int
    public_port: int
    tls: bool


@dataclass
class Conn:
    """State of one TCP connection = one session."""

    sid: str
    ip: str
    port: int
    listener: Listener
    start: float = field(default_factory=time.monotonic)
    quiet: bool = False
    sni: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    requests: int = 0
    logins: int = 0
    downloads: int = 0
    bytes_out: int = 0
    flags: set[str] = field(default_factory=set)
    statuses: dict[str, int] = field(default_factory=dict)
    reason: str = "closed"
    # What the memory guard needs to rank and abort live connections.
    transport: asyncio.BaseTransport | None = None
    reader: asyncio.StreamReader | None = None
    cr: ConnReader | None = None
    inflight: int = 0  # response bytes being written
    cost: int = 0  # bytes charged to the budget at admission

    def buffered(self) -> int:
        """Estimate of the bytes this connection holds right now."""
        total = self.cost + self.inflight
        if self.reader is not None:
            total += len(getattr(self.reader, "_buffer", b""))
        if self.cr is not None:
            total += len(self.cr.buf) + len(self.cr.raw_head)
        t = self.transport
        if isinstance(t, asyncio.WriteTransport):
            with contextlib.suppress(Exception):
                total += t.get_write_buffer_size()
        if t is not None and hasattr(t, "get_read_buffer_size"):
            with contextlib.suppress(Exception):
                total += int(t.get_read_buffer_size())
        return total

    def abort(self) -> bool:
        t = self.transport
        if not isinstance(t, asyncio.WriteTransport):
            return False
        with contextlib.suppress(Exception):
            t.abort()
        return True


class WebSensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self,
        cfg: Config,
        sink: EventSink,
        site: Site,
        tls_ctx: ssl.SSLContext | None,
        guard: MemoryGuard | None = None,
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.site = site
        self.detector = Detector(cfg)
        self.tls_ctx = tls_ctx
        self.budget = Budget(cfg.memory_budget)
        self.dates = apache.DateCache()
        self.guard = guard or MemoryGuard(
            cfg.memory_limit, refuse=cfg.memory_refuse, shed=cfg.memory_shed
        )
        self.total = 0
        self.tls_total = 0
        self.per_ip: dict[str, int] = {}
        self.live: dict[str, Conn] = {}
        self.rejected = 0
        self.responses_shed = 0
        self.connections_seen = 0
        self.requests_seen = 0
        self._sni: weakref.WeakKeyDictionary[ssl.SSLObject, str | None] = (
            weakref.WeakKeyDictionary()
        )
        self._limited: dict[tuple[str, int], int] = {}
        self._slow_close = 0
        self._rate = _Buckets(cfg.conn_rate, cfg.conn_burst)

    # -- admission -------------------------------------------------------------------------

    def _note_limited(self, ip: str, dst_port: int) -> None:
        key = (ip, dst_port)
        if key in self._limited or len(self._limited) < 2000:
            self._limited[key] = self._limited.get(key, 0) + 1

    def flush_limited(self) -> None:
        """One aggregated ``scan`` event per (IP, port) for the connections refused since last call."""
        pending, self._limited = self._limited, {}
        for (ip, dst_port), count in pending.items():
            if self.cfg.quiet_loopback and ip in _LOOPBACK:
                continue
            self.sink.emit(
                session_id=secrets.token_hex(8),
                src_ip=ip,
                src_port=0,
                dst_port=dst_port,
                type_=EventType.scan,
                data={"kind": "rate_limited", "refused": count, "window_s": 60},
                important=False,
            )

    async def _slow_reject(
        self,
        loop: asyncio.AbstractEventLoop,
        sock: socket.socket,
        busy: tuple[str, int, Listener] | None = None,
    ) -> None:
        """Refuse a connection less abruptly: read a little, wait a short random time, close.

        ``busy`` = (ip, port, listener): the sensor is short of memory, so a plain HTTP request
        gets Apache's 503 page first (a busy server, not a dead one). Nothing is buffered: the
        page is a few hundred bytes sent straight to the socket.
        """
        if self._slow_close >= 64:
            with contextlib.suppress(OSError):
                sock.close()
            return
        self._slow_close += 1
        try:
            data = b""
            with contextlib.suppress(Exception):
                data = await asyncio.wait_for(loop.sock_recv(sock, 512), 0.5)
            await asyncio.sleep(random.uniform(0.1, 0.6))  # noqa: S311 - timing jitter only
            if busy is not None and not busy[2].tls and data[:1].isalpha():
                ip, port, listener = busy
                ctx = Ctx(ip, port, False, listener.public_port, time.time())
                wire, _ = self._render(self.site.error(503, None, ctx, close=True), None, False)
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(loop.sock_sendall(sock, wire), 1.0)
        finally:
            self._slow_close -= 1
            with contextlib.suppress(OSError):
                sock.close()

    def admit(self, ip: str, tls: bool) -> str | None:
        """Take the slots and budget for a new connection: None if admitted, else why not.

        Everything here is checked before any TLS work."""
        cfg = self.cfg
        if cfg.quiet_loopback and ip in _LOOPBACK:
            # The container healthcheck: never refused (a local peer cannot be spoofed from
            # outside), or the container would flap unhealthy exactly when it is under load.
            self.budget.used += conn_cost(tls)
            self.total += 1
            self.tls_total += tls
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return None
        if not self._rate.allow(ip):
            reason = "rate"
        elif self.guard.refusing:
            self.guard.refused += 1
            reason = "memory"
        elif self.total >= cfg.max_connections or self.per_ip.get(ip, 0) >= cfg.max_per_ip:
            reason = "cap"
        elif tls and self.tls_total >= cfg.max_tls_connections:
            reason = "tls-cap"
        elif not self.budget.acquire(conn_cost(tls)):
            reason = "budget"
        else:
            self.total += 1
            self.tls_total += tls
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return None
        self.rejected += 1
        return reason

    def release(self, ip: str, tls: bool) -> None:
        self.total = max(0, self.total - 1)
        if tls:
            self.tls_total = max(0, self.tls_total - 1)
        left = self.per_ip.get(ip, 1) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left
        self.budget.release(conn_cost(tls))

    def check_memory(self) -> int:
        """One memory-guard tick: refuse above 70 %, abort the fattest connections above 85 %.

        Returns how many connections were aborted."""
        if not self.guard.sample():
            return 0
        self.guard.shed_events += 1
        need = max(self.guard.excess(), 1)
        ranked = sorted(self.live.values(), key=lambda c: (-c.buffered(), c.start))
        # Estimates undercount (allocator overhead): never abort more than half at once.
        freed = aborted = 0
        for conn in ranked[: max(1, len(ranked) // 2)]:
            if freed >= need:
                break
            size = conn.buffered()
            if conn.abort():
                conn.reason = "memory-pressure"
                freed += size
                aborted += 1
        self.guard.aborted += aborted
        if aborted:
            log.warning(
                "memory %d MiB of %d MiB: aborted %d connections",
                self.guard.usage >> 20,
                self.guard.limit >> 20,
                aborted,
            )
        return aborted

    def on_sni(self, sslobj: ssl.SSLObject, name: str | None) -> None:
        with contextlib.suppress(TypeError):
            self._sni[sslobj] = name[:255] if name else None

    def stats(self) -> dict[str, int]:
        return {
            "connections": self.total,
            "seen": self.connections_seen,
            "requests": self.requests_seen,
            "rejected": self.rejected,
            "budget_used": self.budget.used,
            "tls_connections": self.tls_total,
            "memory_used": self.guard.usage,
            "memory_peak": self.guard.peak,
            "memory_refused": self.guard.refused,
            "memory_aborted": self.guard.aborted,
            **self.sink.stats(),
        }

    # -- events ----------------------------------------------------------------------------

    def emit(
        self, conn: Conn, type_: EventType, data: dict[str, Any], *, important: bool = False
    ) -> None:
        if conn.quiet:
            return
        self.sink.emit(
            session_id=conn.sid,
            src_ip=conn.ip,
            src_port=conn.port,
            dst_port=conn.listener.public_port,
            type_=type_,
            data=data,
            important=important,
        )

    def _request_event(
        self,
        conn: Conn,
        req: Request | None,
        status: int,
        analysis: Analysis | None,
        outcome: Outcome | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        data: dict[str, Any] = {"status": status, "tls": conn.listener.tls, "sni": conn.sni}
        flags: set[str] = set(analysis.flags) if analysis else set()
        cve: list[str] = list(analysis.cve) if analysis else []
        if req is not None:
            headers: dict[str, str] = {}
            hsize = 0
            for k, v in req.headers:
                if hsize >= _G_HEADERS:
                    break
                if k in headers:
                    if len(headers[k]) < 500:
                        headers[k] += ", " + to_text(v[:512])[: 500 - len(headers[k])]
                elif len(headers) < _MAX_HEADERS_LOGGED:
                    headers[to_text(k)[:128]] = to_text(v)[:512]
                    hsize += len(json.dumps(headers[to_text(k)[:128]])) + len(json.dumps(k[:128]))
            while headers and len(json.dumps(headers)) > _G_HEADERS:
                headers.popitem()
            body_preview = _fit(req.body[:2048].decode("utf-8", "replace"), _G_BODY)
            data.update(
                {
                    "method": to_text(req.method)[:64],
                    "path": _fit(to_text(req.path), _G_PATH),
                    "query": _fit(to_text(req.query), _G_PATH),
                    "http_version": req.version,
                    "host": _fit(to_text(req.header("host") or ""), 255),
                    "headers": headers,
                    "user_agent": _fit(to_text(req.header("user-agent") or ""), _G_SMALL // 2),
                    "body_preview": body_preview,
                    "body_sha256": req.body_sha256,
                    "body_length": req.body_len,
                    "body_truncated": req.body_truncated,
                }
            )
            if req.content_length is not None:
                data["content_length"] = req.content_length
            if req.chunked:
                data["chunked"] = True
        if outcome is not None:
            data["app"] = outcome.app
            data["route"] = outcome.route
            flags.update(outcome.flags)
            data.update(outcome.extra)
        if analysis is not None and analysis.php2shell:
            p2s: Any = analysis.php2shell
            if len(json.dumps(p2s, default=str)) > _G_PHP2SHELL:
                p2s = _cap_strings(p2s, 200)
            data["php2shell"] = p2s
        data["flags"] = sorted(flags)
        data["cve"] = cve
        if analysis is not None and analysis.traps:
            data["traps"] = analysis.traps
        if extra:
            data.update(extra)
        conn.flags |= flags
        important = bool(flags & self.detector.severe)
        self.emit(conn, EventType.http_request, data, important=important)

    # -- connection lifecycle --------------------------------------------------------------

    async def handle(self, sock: socket.socket, addr: Any, listener: Listener) -> None:
        loop = asyncio.get_running_loop()
        ip = normalize_ip(str(addr[0]))
        port = int(addr[1])
        refused = self.admit(ip, listener.tls)
        if refused is not None:
            self._note_limited(ip, listener.public_port)
            busy = (ip, port, listener) if refused in ("memory", "budget") else None
            await self._slow_reject(loop, sock, busy)
            return
        self.connections_seen += 1
        conn = Conn(
            sid=secrets.token_hex(8),
            ip=ip,
            port=port,
            listener=listener,
            quiet=self.cfg.quiet_loopback and ip in _LOOPBACK,
            cost=conn_cost(listener.tls),
        )
        self.live[conn.sid] = conn
        writer: asyncio.StreamWriter | None = None
        reader: asyncio.StreamReader | None = None
        try:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            first: bytes | None = None
            if listener.tls:
                first = await _peek(loop, sock, self.cfg.first_byte_timeout)
                if not first:
                    conn.reason = "no-data"
                    sock.close()
                    return
            if listener.tls and first and first[0] == 0x16 and self.tls_ctx is not None:
                reader, writer = await self._start_tls(loop, sock, conn)
                if reader is None or writer is None:
                    return
                self.emit(
                    conn,
                    EventType.connect,
                    {
                        "tls": True,
                        "sni": conn.sni,
                        "tls_version": conn.tls_version,
                        "cipher": conn.cipher,
                        "handshake": True,
                    },
                )
            else:
                reader, writer = await _plain_stream(loop, sock)
                conn.transport, conn.reader = writer.transport, reader
                if listener.tls and first and not (65 <= first[0] <= 90):
                    # Not TLS and not an HTTP method: nothing sensible to answer.
                    self.emit(conn, EventType.connect, {"tls": True, "handshake": False})
                    self.emit(
                        conn,
                        EventType.scan,
                        {"kind": "non_tls_on_tls_port", "payload_preview": first[:8].hex()},
                    )
                    conn.reason = "not-tls"
                    return
                self.emit(
                    conn, EventType.connect, {"tls": listener.tls, "sni": None, "handshake": False}
                )
                if listener.tls:
                    await self._plain_on_tls(conn, reader, writer)
                    return
            await self._serve(conn, reader, writer)
        except asyncio.CancelledError:
            conn.reason = "shutdown"
            raise
        except Exception:
            conn.reason = "error"
            log.exception("connection handler failed")
            if writer is not None:
                with contextlib.suppress(Exception):
                    await self._send_500(conn, writer)
        finally:
            suppressed = self.sink.end_session(conn.sid)
            self.emit(
                conn,
                EventType.disconnect,
                {
                    "duration_s": round(time.monotonic() - conn.start, 3),
                    "reason": conn.reason,
                    "requests": conn.requests,
                    "login_attempts": conn.logins,
                    "downloads": conn.downloads,
                    "bytes_out": conn.bytes_out,
                    "tls": listener.tls,
                    "sni": conn.sni,
                    "flags": sorted(conn.flags)[:32],
                    "statuses": conn.statuses,
                    "suppressed": suppressed,
                },
            )
            # Slots and budget are given back only once the transport is really gone.
            try:
                if writer is not None:
                    await _close(
                        reader,
                        writer,
                        force=conn.reason in ("write-failed", "memory-pressure"),
                        flush_timeout=self.cfg.write_chunk_timeout,
                    )
                else:
                    with contextlib.suppress(OSError):
                        sock.close()
            finally:
                self.live.pop(conn.sid, None)
                self.release(ip, listener.tls)

    async def _send_500(self, conn: Conn, writer: asyncio.StreamWriter) -> None:
        """Apache's own 500 page, so an unexpected failure looks like a server error."""
        ctx = Ctx(conn.ip, conn.port, conn.listener.tls, conn.listener.public_port, time.time())
        resp = self.site.error(500, None, ctx, close=True)
        wire, _ = self._render(resp, None, persist=False)
        if self.budget.acquire(len(wire)):
            try:
                await asyncio.wait_for(self._write(conn, writer, wire), 5)
            finally:
                self.budget.release(len(wire))

    async def _start_tls(
        self, loop: asyncio.AbstractEventLoop, sock: socket.socket, conn: Conn
    ) -> tuple[asyncio.StreamReader | None, asyncio.StreamWriter | None]:
        if self.tls_ctx is None:
            raise RuntimeError("TLS context missing")
        reader = asyncio.StreamReader(limit=_READER_LIMIT)
        proto = asyncio.StreamReaderProtocol(reader)
        try:
            transport, _ = await loop.connect_accepted_socket(
                lambda: proto,
                sock,
                ssl=self.tls_ctx,
                ssl_handshake_timeout=self.cfg.handshake_timeout,
            )
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            conn.reason = "tls-handshake-failed"
            self.emit(conn, EventType.connect, {"tls": True, "sni": None, "handshake": False})
            self.emit(
                conn,
                EventType.scan,
                {
                    "kind": "tls_handshake_failed",
                    "error": type(exc).__name__,
                    "detail": str(exc)[:200],
                },
            )
            with contextlib.suppress(OSError):
                sock.close()
            return None, None
        sslobj = transport.get_extra_info("ssl_object")
        if sslobj is not None:
            conn.sni = self._sni.pop(sslobj, None)
            conn.tls_version = sslobj.version()
            cipher = sslobj.cipher()
            conn.cipher = cipher[0] if cipher else None
        transport.set_write_buffer_limits(high=_TLS_WRITE_HIGH, low=_TLS_WRITE_HIGH // 4)
        # The encrypted side has its own socket transport (default high-water 64 KiB) that
        # SSLProtocol fills before its own buffer counts: keep it small too.
        inner = getattr(getattr(transport, "_ssl_protocol", None), "_transport", None)
        if isinstance(inner, asyncio.WriteTransport):
            inner.set_write_buffer_limits(high=_TLS_WRITE_HIGH, low=_TLS_WRITE_HIGH // 4)
        # Decrypted-side incoming buffer: pause the socket at 32 KiB instead of 256 KiB.
        set_read_limits = getattr(transport, "set_read_buffer_limits", None)
        if set_read_limits is not None:
            set_read_limits(high=_TLS_READ_HIGH, low=_TLS_READ_HIGH // 4)
        conn.transport, conn.reader = transport, reader
        writer = asyncio.StreamWriter(transport, proto, reader, loop)
        return reader, writer

    # -- request loop ----------------------------------------------------------------------

    async def _write(self, conn: Conn, writer: asyncio.StreamWriter, data: bytes) -> bool:
        """Write in chunks; every chunk must drain in ``write_chunk_timeout`` (minimum rate)."""
        cfg = self.cfg
        # SSLProtocol encrypts a whole write at once and hands it to the socket transport
        # whatever its buffer holds: smaller chunks keep that buffer small. The minimum rate
        # (``write_chunk`` bytes per ``write_chunk_timeout``) stays the same.
        chunk = _TLS_WRITE_CHUNK if conn.listener.tls else cfg.write_chunk
        chunk_timeout = cfg.write_chunk_timeout * chunk / cfg.write_chunk
        conn.inflight += len(data)
        try:
            if len(data) <= chunk:
                writer.write(data)
                await asyncio.wait_for(writer.drain(), cfg.write_timeout)
            else:
                view = memoryview(data)  # slices share ``data``: no per-chunk copies
                for off in range(0, len(data), chunk):
                    writer.write(view[off : off + chunk])
                    await asyncio.wait_for(writer.drain(), chunk_timeout)
        except TimeoutError, ConnectionError, OSError:
            if conn.reason != "memory-pressure":
                conn.reason = "write-failed"
            return False
        finally:
            conn.inflight -= len(data)
        conn.bytes_out += len(data)
        return True

    async def _serve(
        self, conn: Conn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        cfg = self.cfg
        cr = ConnReader(reader, cfg)
        conn.cr = cr
        started = time.monotonic()
        while True:
            if time.monotonic() - started > cfg.max_connection_age:
                conn.reason = "max-age"
                return
            ctx = Ctx(conn.ip, conn.port, conn.listener.tls, conn.listener.public_port, time.time())
            req: Request | None = None
            try:
                req = await cr.read_request(first=conn.requests == 0)
            except HttpError as err:
                req = err.req
                await self._reply_error(conn, writer, cr, err, req, ctx)
                return
            except HeaderTimeout:
                self._partial(conn, cr)
                await self._reply_error(conn, writer, cr, HttpError(408), None, ctx)
                conn.reason = "timeout"
                return
            except ClientGone:
                if conn.reason != "memory-pressure":
                    conn.reason = "client-closed"
                self._partial(conn, cr)
                return
            if req is None:
                conn.reason = "idle" if conn.requests else "closed"
                return
            conn.requests += 1
            self.requests_seen += 1
            keep = await self._request(conn, cr, reader, writer, req, ctx)
            if not keep:
                return

    def _partial(self, conn: Conn, cr: ConnReader) -> None:
        """Record what arrived of a request that never completed (slowloris, scanners)."""
        if cr.raw_head or cr.buf:
            preview = (bytes(cr.raw_head) + bytes(cr.buf))[:1024].decode("utf-8", "replace")
            self._request_event(
                conn,
                None,
                0,
                Analysis(flags=["incomplete_request"]),
                None,
                {"request_head_preview": preview},
            )

    async def _plain_on_tls(
        self, conn: Conn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Plain HTTP on the TLS port: answer like mod_ssl does."""
        cr = ConnReader(reader, self.cfg)
        ctx = Ctx(conn.ip, conn.port, True, conn.listener.public_port, time.time())
        req: Request | None = None
        try:
            req = await cr.read_request(first=True)
        except HttpError as err:
            req = err.req
        except HeaderTimeout, ClientGone:
            pass
        conn.requests += 1
        conn.reason = "plain-http-on-tls"
        resp = self.site.error(400, None, ctx, extra=apache.EXTRA_PLAIN_HTTP, close=True)
        self._request_event(
            conn, req, 400, Analysis(flags=["plain_http_on_tls"]), None,
            {"request_head_preview": bytes(cr.raw_head[:1024]).decode("utf-8", "replace")},
        )  # fmt: skip
        self._count(conn, 400)
        wire, _ = self._render(resp, None, persist=False)
        await self._write(conn, writer, wire)

    async def _reply_error(
        self,
        conn: Conn,
        writer: asyncio.StreamWriter,
        cr: ConnReader,
        err: HttpError,
        req: Request | None,
        ctx: Ctx,
    ) -> None:
        resp = self.site.error_for(err, req, ctx)
        extra: dict[str, Any] = {"malformed": True}
        if cr.raw_head:
            extra["request_head_preview"] = bytes(cr.raw_head[:1024]).decode("utf-8", "replace")
        conn.requests += 1
        conn.reason = f"http-{err.status}"
        flags = {"malformed"} if err.status in (400, 414, 501) else set()
        analysis = Analysis(flags=sorted(flags))
        self._request_event(conn, req, resp.status, analysis, None, extra)
        self._count(conn, resp.status)
        wire, _ = self._render(resp, req, persist=False)
        await self._write(conn, writer, wire)

    def _count(self, conn: Conn, status: int) -> None:
        key = str(status)
        if key in conn.statuses or len(conn.statuses) < 16:
            conn.statuses[key] = conn.statuses.get(key, 0) + 1

    def _render(
        self, resp: Response, req: Request | None, persist: bool, left: int = 0
    ) -> tuple[bytes, bool]:
        cfg = self.cfg
        ctx = RenderContext(
            method=req.method if req else "GET",
            minor=req.minor if req else 1,
            accept_encoding=req.header("accept-encoding") if req else None,
            server_token=cfg.server_token,
            php_version=cfg.php_version,
            expose_php=cfg.expose_php,
            date=self.dates.now(),
            persist=persist,
            keepalive_header=bool(req and "keep-alive" in req.connection_tokens()),
            keepalive_left=left,
            keepalive_timeout=int(cfg.keepalive_timeout),
        )
        wire, stays = render(resp, ctx)
        if req is not None and req.http09:
            return resp.body, False
        return wire, stays

    async def _request(
        self,
        conn: Conn,
        cr: ConnReader,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        req: Request,
        ctx: Ctx,
    ) -> bool:
        cfg = self.cfg
        outcome: Outcome | None = None
        analysis: Analysis | None = None
        body_error: HttpError | None = None
        extra_cost = 0
        # Body (bounded; xmlrpc gets a larger prefix for big multicalls).
        retain = None
        is_xmlrpc = req.method == "POST" and req.path.lower().endswith("/xmlrpc.php")
        if is_xmlrpc:
            extra_cost = _XMLRPC_BODY - cfg.analysis_cap
            if self.budget.acquire(extra_cost):
                retain = _XMLRPC_BODY
            else:
                extra_cost = 0

        async def send_continue() -> None:
            await self._write(conn, writer, b"HTTP/1.1 100 Continue\r\n\r\n")

        try:
            try:
                await cr.read_body(req, send_continue, retain)
            except HttpError as err:
                body_error = err
            except HeaderTimeout:
                body_error = HttpError(408)
                conn.reason = "timeout"
            except ClientGone:
                conn.reason = "client-closed"
                self._request_event(conn, req, 0, Analysis(flags=["incomplete_body"]), None)
                return False
            try:
                analysis = self.detector.analyze(req, conn.ip)
            except Exception:
                log.exception("analysis failed")
                analysis = Analysis()
            persist_allowed = True
            if body_error is not None:
                resp = self.site.error_for(body_error, req, ctx)
                persist_allowed = False
                conn.reason = f"http-{body_error.status}"
                if body_error.status == 413:
                    analysis.flags = sorted({*analysis.flags, "oversized_body"})
            else:
                try:
                    # What a handler may build is bounded by what the budget can still hold.
                    ctx.max_response = max(0, min(_MAX_RESPONSE, self.budget.available()))
                    outcome = self.site.trap_outcome(
                        req, ctx, analysis.trap_hits, self.detector.traps.groups
                    ) or self.site.handle(req, ctx, analysis)
                    resp = outcome.resp
                except HttpError as err:
                    resp = self.site.error_for(err, req, ctx)
                    persist_allowed = not err.close
                except Exception:
                    log.exception("handler failed")
                    resp = self.site.error(500, req, ctx, close=True)
                    persist_allowed = False
            # Everything captured is emitted before the response is written.
            self._request_event(conn, req, resp.status, analysis, outcome)
            self._count(conn, resp.status)
            self._emit_side_events(conn, req, analysis, outcome)
            # Keep-alive decision, like Apache.
            tokens = req.connection_tokens()
            wants = ("close" not in tokens) if req.minor >= 1 else ("keep-alive" in tokens)
            if req.http09 or (req.chunked and req.header("content-length") is not None):
                wants = False
            left = cfg.keepalive_max - conn.requests + 1
            persist = wants and persist_allowed and left > 1 and not resp.close
            wire, persist = self._render(resp, req, persist=persist, left=left)
            # Response bytes are part of the memory budget until they are drained.
            if not self.budget.acquire(len(wire)):
                self.responses_shed += 1
                conn.reason = "overloaded"
                wire, _ = self._render(
                    self.site.error(503, req, ctx, close=True), req, persist=False
                )
                persist = False
                if not self.budget.acquire(len(wire)):
                    return False
            # Only ``wire`` is needed from here on; a stuck peer must not pin the rest.
            resp.body = b""
            req.release()
            outcome = None
            try:
                ok = await self._write(conn, writer, wire)
            finally:
                self.budget.release(len(wire))
            if not ok:
                return False
            if not persist:
                if conn.reason == "closed":
                    conn.reason = "server-close"
                return False
            return True
        finally:
            if extra_cost:
                self.budget.release(extra_cost)

    def _emit_side_events(
        self, conn: Conn, req: Request, analysis: Analysis, outcome: Outcome | None
    ) -> None:
        path = to_text(req.path)[:512]
        ua = to_text(req.header("user-agent") or "")[:256]
        cap = self.cfg.xmlrpc_max_calls
        logins = list(outcome.logins) if outcome else []
        if analysis.basic_auth:
            user, pwd = analysis.basic_auth
            logins.append(
                {"username": user, "password": pwd, "success": False, "method": "http-basic"}
            )
        for entry in logins[:cap]:
            conn.logins += 1
            self.emit(
                conn,
                EventType.login_attempt,
                {**entry, "path": path, "user_agent": ua},
                important=True,
            )
        downloads = list(analysis.downloads) + (list(outcome.downloads) if outcome else [])
        seen: set[str] = set()
        for dl in downloads[:16]:
            if dl["url"] in seen:
                continue
            seen.add(dl["url"])
            conn.downloads += 1
            self.emit(
                conn,
                EventType.download_attempt,
                {**dl, "path": path, "user_agent": ua},
                important=True,
            )


def conn_cost(tls: bool) -> int:
    return _CONN_COST + (_TLS_COST if tls else 0)


def tune_tls_buffers() -> None:
    """Shrink asyncio's per-connection TLS receive buffer before any TLS listener starts.

    ``SSLProtocol.__init__`` allocates ``max_size`` bytes (256 KiB by default) for every
    connection and reads up to that much per call: 64 TLS connections would hold 16 MiB in
    these buffers alone. TLS records are at most 16 KiB, so a 16 KiB buffer costs nothing in
    throughput. The value is a class attribute read in ``__init__`` and ``get_buffer``.
    """
    asyncio.sslproto.SSLProtocol.max_size = _TLS_READ_CHUNK


def _tune_socket(sock: socket.socket) -> None:
    """Small kernel buffers (charged to the container) and a bounded unacknowledged-send time."""
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _SOCK_BUF)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _SOCK_BUF)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000)


async def _peek(loop: asyncio.AbstractEventLoop, sock: socket.socket, wait: float) -> bytes:
    """Wait for the first bytes and look at them without consuming them."""
    fut: asyncio.Future[None] = loop.create_future()
    fd = sock.fileno()

    def ready() -> None:
        if not fut.done():
            fut.set_result(None)

    loop.add_reader(fd, ready)
    try:
        await asyncio.wait_for(fut, wait)
        return sock.recv(16, socket.MSG_PEEK)
    except TimeoutError, OSError:
        return b""
    finally:
        loop.remove_reader(fd)


async def _plain_stream(
    loop: asyncio.AbstractEventLoop, sock: socket.socket
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader = asyncio.StreamReader(limit=_READER_LIMIT)
    proto = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_accepted_socket(lambda: proto, sock)
    transport.set_write_buffer_limits(high=64 * 1024, low=16 * 1024)
    return reader, asyncio.StreamWriter(transport, proto, reader, loop)


async def _close(
    reader: asyncio.StreamReader | None,
    writer: asyncio.StreamWriter,
    force: bool = False,
    flush_timeout: float = 10.0,
) -> None:
    """Close like Apache: flush, half-close, drain a little unread input, then close.

    ``drain()`` returns as soon as the transport buffer is below its low-water mark, so the
    tail of a response may still be buffered here: it gets ``flush_timeout`` (the per-chunk
    minimum rate) to go out. A peer that does not take it is aborted, so its buffers go away.
    """
    transport = writer.transport
    try:
        if not force and transport.get_write_buffer_size() > 0:
            with contextlib.suppress(Exception):
                transport.set_write_buffer_limits(high=0)  # drain() now waits for empty
                await asyncio.wait_for(writer.drain(), flush_timeout)
        if force or transport.get_write_buffer_size() > 0:
            transport.abort()  # peer is not reading: do not keep buffers around
            return
        if writer.can_write_eof():
            writer.write_eof()
            if reader is not None:
                deadline = time.monotonic() + 2.0
                budget = 64 * 1024
                while budget > 0:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        break
                    data = await asyncio.wait_for(reader.read(8192), left)
                    if not data:
                        break
                    budget -= len(data)
    except TimeoutError, OSError, RuntimeError, asyncio.CancelledError:
        pass
    finally:
        with contextlib.suppress(Exception):
            if transport.get_write_buffer_size() > 0:
                transport.abort()
            else:
                writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2.0)
        except BaseException:  # timeout, reset, cancellation: make sure nothing lingers
            with contextlib.suppress(Exception):
                transport.abort()


class WebServer:
    """Owns the listening sockets and the accept loops."""

    def __init__(self, cfg: Config, sensor: WebSensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._socks: list[socket.socket] = []
        self._accept_tasks: list[asyncio.Task[None]] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self.ports: dict[str, int] = {}

    def _listen(self, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set before listen(): accepted sockets inherit the sizes, and the TCP window scale
        # offered in the SYN-ACK matches the small receive buffer.
        _tune_socket(s)
        s.bind((self.cfg.host, port))
        s.listen(512)
        s.setblocking(False)
        return s

    async def start(self) -> dict[str, int]:
        cfg = self.cfg
        tune_tls_buffers()
        self.sensor.guard.sample()
        log.info(
            "memory guard: %s, limit %d MiB",
            self.sensor.guard.source,
            self.sensor.guard.limit >> 20,
        )
        specs = [Listener("http", cfg.http_port, cfg.http_public_port, False)]
        if self.sensor.tls_ctx is not None:
            specs.append(Listener("https", cfg.https_port, cfg.https_public_port, True))
        for spec in specs:
            sock = self._listen(spec.port)
            self._socks.append(sock)
            self.ports[spec.name] = sock.getsockname()[1]
            self._accept_tasks.append(asyncio.create_task(self._accept(sock, spec)))
        self._accept_tasks.append(asyncio.create_task(self._flush_loop()))
        self._accept_tasks.append(asyncio.create_task(self._memory_loop()))
        return self.ports

    async def _memory_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                self.sensor.check_memory()
            except Exception:
                log.exception("memory guard failed")

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            self.sensor.flush_limited()

    async def _accept(self, lsock: socket.socket, listener: Listener) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                conn, addr = await loop.sock_accept(lsock)
            except asyncio.CancelledError:
                raise
            except OSError:
                if lsock.fileno() == -1:
                    return
                await asyncio.sleep(0.1)  # EMFILE and friends: back off
                continue
            conn.setblocking(False)
            _tune_socket(conn)
            task = asyncio.create_task(self.sensor.handle(conn, addr, listener))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def stop(self) -> None:
        for t in self._accept_tasks:
            t.cancel()
        for t in self._accept_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        for s in self._socks:
            s.close()
        for t in list(self._tasks):
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
