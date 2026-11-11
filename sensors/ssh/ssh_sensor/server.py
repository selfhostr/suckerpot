"""The SSH server: connection limits, authentication, event emission and the shell session."""

from __future__ import annotations

import asyncio
import codecs
import collections
import contextlib
import hashlib
import ipaddress
import logging
import random
import socket
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncssh
from suckerpot_common import EventType

from ssh_sensor.config import Config
from ssh_sensor.cpu import CpuBudget, FairBudget
from ssh_sensor.events import EventSink, TokenBuckets
from ssh_sensor.memguard import MemoryProbe
from ssh_sensor.replay import ReplayRecorder
from ssh_sensor.shell.baseimage import Profile, build_base_image
from ssh_sensor.shell.fs import BaseImage, FakeFS
from ssh_sensor.shell.interp import Result, Shell

log = logging.getLogger("ssh_sensor.server")

_CPU_MAX_WAIT = 10.0  # a command waits at most this long for shell CPU, then fork fails
_REPEAT_FLUSH = 1000  # a run of identical command lines is reported at least this often
_GUARD_INTERVAL = 1.0
_GUARD_TRACKED_FLOOR = 0.10  # the guard acts only if sessions + events hold this share
_READ_CHUNK = 1024
_FEED_SLICE = 4 * 1024  # bytes handed to asyncssh per loop callback

# Algorithm lists copied, order included, from the KEXINIT of a stock OpenSSH 9.6p1 server on
# Ubuntu 24.04 (RSA, ECDSA and Ed25519 host keys). Checked against asyncssh 2.24.1 by
# tests/test_fingerprint.py: every list matches except one. A real 9.6p1 starts its KEX list with
# sntrup761x25519-sha512@openssh.com, which asyncssh does not implement; advertising it without
# being able to complete it would break handshakes, so it is left out. The trailing "ext-info-s"
# and "kex-strict-s-v00@openssh.com" markers are added by asyncssh itself, in OpenSSH's order.
# What still differs from the real thing is therefore only the missing first KEX entry, which
# changes the HASSHServer value. A banner asyncssh can match exactly would be Ubuntu 20.04's
# OpenSSH 8.2p1 (no sntrup, no strict-kex), but it would clash with the 24.04 image.
KEX_ALGS = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
]
ENC_ALGS = [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
]
MAC_ALGS = [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
]
# OpenSSH advertises "none,zlib@openssh.com"; only "none" is offered here: a compressed stream is a
# decompression bomb risk and carries nothing worth capturing. This is the one deliberate
# difference in the KEXINIT besides the missing sntrup entry.
COMP_ALGS = ["none"]
SIG_ALGS = ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"]

_MOTD = (
    "Welcome to {os_pretty} (GNU/Linux {kernel} x86_64)\n\n"
    " * Documentation:  https://help.ubuntu.com\n"
    " * Management:     https://landscape.canonical.com\n"
    " * Support:        https://ubuntu.com/pro\n\n"
    " System information as of {when}\n\n"
    "  System load:  0.08              Processes:             112\n"
    "  Usage of /:   30.2% of 38.59GB  Users logged in:       0\n"
    "  Memory usage: 24%               IPv4 address for ens5: {ip}\n"
    "  Swap usage:   0%\n\n\n"
    "Expanded Security Maintenance for Applications is not enabled.\n\n"
    "0 updates can be applied immediately.\n\n"
    "Last login: {last} from {last_ip}\n"
)


def normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return "0.0.0.0"  # noqa: S104 - placeholder for an unparsable peer address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(self, cfg: Config, sink: EventSink, profile: Profile) -> None:
        self.cfg = cfg
        self.sink = sink
        self.profile = profile
        self.base: BaseImage = build_base_image(profile)
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.rejected = 0
        self.rate_rejected = 0
        self.connections_seen = 0
        self.connections: set[Connection] = set()
        self._rng = random.SystemRandom()
        # new connections per source IP (concurrency is capped separately by max_per_ip)
        self._new_conn = TokenBuckets(cfg.conn_rate_per_ip, cfg.conn_burst_per_ip)
        self.cpu = CpuBudget(cfg.shell_cpu_share, cfg.shell_cpu_burst)
        self.memory = MemoryProbe(cfg.memory_limit)
        self.mem_level = 0  # 0 ok, 1 pressure, 2 critical
        self.mem_ratio = 0.0
        self.mem_refused = 0
        self.mem_dropped = 0
        self._guard: asyncio.Task[None] | None = None
        self._in_conn = TokenBuckets(cfg.inbound_conn_bytes_per_sec, cfg.inbound_conn_bytes_burst)
        # sensor-wide inbound bytes, shared fairly between source IPs
        self.inbound_fair = FairBudget(
            cfg.inbound_bytes_per_sec, cfg.inbound_bytes_burst, name="inbound", scale=1.0
        )
        self.inbound_pauses = 0
        self.inbound_bytes = 0

    def admit(self, ip: str) -> bool:
        """Admit a new connection, or refuse it (concurrency caps, per-IP connection rate).

        Refused connections are not given events of their own; the caller counts them in the
        per-IP connection summary."""
        if self.total >= self.cfg.max_connections or self.per_ip.get(ip, 0) >= self.cfg.max_per_ip:
            self.rejected += 1
            return False
        if self.mem_level > 0:
            self.rejected += 1
            self.mem_refused += 1
            return False
        if not self._new_conn.allow(ip):
            self.rejected += 1
            self.rate_rejected += 1
            return False
        self.total += 1
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        return True

    def release(self, ip: str) -> None:
        self.total = max(0, self.total - 1)
        left = self.per_ip.get(ip, 1) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left

    def credentials_ok(self, username: str, password: str) -> bool:
        if (username, password) in self.cfg.accept_credentials:
            return True
        return bool(password) and self._rng.random() < self.cfg.accept_random_prob

    def fail_delay(self) -> float:
        lo, hi = self.cfg.auth_fail_delay
        return self._rng.uniform(lo, hi) if hi > 0 else 0.0

    def memory_in_use(self, ip: str | None = None) -> int:
        """Approximate bytes held by all sessions (or those of one source IP): fake
        filesystems, shells, replay buffers and input not read yet."""
        return sum(
            conn.memory_bytes() for conn in self.connections if ip is None or conn.src_ip == ip
        )

    def over_budget(self, ip: str | None = None) -> bool:
        """Over the sessions memory budget, or (with ``ip``) over that IP's share of it."""
        if self.memory_in_use() > self.cfg.memory_budget:
            return True
        share = self.cfg.memory_budget * self.cfg.memory_share_per_ip
        return ip is not None and self.memory_in_use(ip) > share

    def inbound(self, key: str, ip: str, nbytes: int) -> None:
        """Charge bytes read from a connection to its and the sensor-wide inbound budget."""
        self.inbound_bytes += nbytes
        self._in_conn.charge(key, nbytes)
        self.inbound_fair.spend(ip, nbytes)

    def inbound_wait(self, key: str) -> float:
        """How long this connection must wait for its own inbound budget."""
        return max(0.0, -self._in_conn.balance(key) / self._in_conn.rate)

    def forget_inbound(self, key: str) -> None:
        self._in_conn.drop(key)

    # ---- process memory guard ------------------------------------------------------------
    def guard_tick(self) -> None:
        """Compare process memory with the limit. Under pressure: refuse new connections and
        sessions, stop reading input from the biggest connections. Critical: close the
        biggest connections."""
        used, limit = self.memory.usage(), self.memory.limit()
        ratio = used / limit
        tracked = self.memory_in_use() + self.sink.queued_bytes
        if tracked < limit * _GUARD_TRACKED_FLOOR:
            # What sessions and events hold is small: the rest is heap that the allocator
            # keeps after a burst and reuses, so refusing or dropping sessions would not help.
            level = 0
        elif ratio >= self.cfg.memory_critical:
            level = 2
        elif ratio >= self.cfg.memory_pressure:
            level = 1
        else:
            level = 0
        if level != self.mem_level:
            log.warning("memory level %d: %d MiB of %d MiB in use", level, used >> 20, limit >> 20)
        self.mem_level, self.mem_ratio = level, ratio
        conns = sorted(self.connections, key=lambda c: c.memory_bytes(), reverse=True)
        throttled = set(conns[: max(1, len(conns) // 4)]) if level else set()
        for conn in conns:
            conn.throttled = conn in throttled
        if level == 2:
            for conn in conns[: max(1, len(conns) // 10)]:
                self.mem_dropped += 1
                conn.drop("memory limit")

    async def _guard_loop(self) -> None:
        while True:
            await asyncio.sleep(_GUARD_INTERVAL)
            try:
                self.guard_tick()
            except Exception:
                log.exception("memory guard failed")

    def start(self) -> None:
        if self._guard is None:
            self._guard = asyncio.create_task(self._guard_loop())

    async def stop(self) -> None:
        if self._guard is not None:
            self._guard.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._guard
            self._guard = None

    def stats(self) -> dict[str, int]:
        return {
            "memory_bytes": self.memory_in_use(),
            "memory_level": self.mem_level,
            "memory_pct": int(self.mem_ratio * 100),
            "memory_refused": self.mem_refused,
            "memory_dropped": self.mem_dropped,
            "connections": self.total,
            "seen": self.connections_seen,
            "rejected": self.rejected,
            "rate_rejected": self.rate_rejected,
            "inbound_pauses": self.inbound_pauses,
            **self.inbound_fair.stats(),
            **self.cpu.stats(),
            **self.sink.stats(),
        }


class Connection(asyncssh.SSHServer):
    """One SSH connection (asyncssh creates one instance per client)."""

    def __init__(self, sensor: Sensor) -> None:
        self.sensor = sensor
        self.cfg = sensor.cfg
        self.session_id = uuid.uuid4().hex[:24]
        self.src_ip = "0.0.0.0"  # noqa: S104 - replaced in connection_made
        self.src_port = 0
        self.started_ts = datetime.now(UTC)
        self.started = time.monotonic()
        self.conn: asyncssh.SSHServerConnection | None = None
        self.admitted = False
        self.connect_emitted = False
        self.username = ""
        self.attempts = 0
        self.logins_ok = 0
        self.commands = 0
        self.downloads = 0
        self.client_version = ""
        self.replay = ReplayRecorder()
        self.reason = "closed by client"
        self._limit_timer: asyncio.TimerHandle | None = None
        self.bytes_out = 0
        self.fs: FakeFS | None = None
        self.shells: list[Shell] = []
        self.channels = 0
        self.refused = 0
        self.commands_run = 0
        self.auth_requests = 0
        self.throttled = False  # set by the memory guard: stop reading input for now
        self._in_paused = False
        self._pump: asyncio.Task[None] | None = None
        self._backlog: collections.deque[bytes] = collections.deque()
        self.processes: set[asyncssh.SSHServerProcess[bytes]] = set()
        self._repeat: dict[str, Any] | None = None

    # ---- lifecycle -----------------------------------------------------------------------
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)  # noqa: S104
        self.src_ip, self.src_port = normalize_ip(str(peer[0])), int(peer[1])
        self.sensor.connections_seen += 1
        if not self.sensor.admit(self.src_ip):
            self.reason = "connection limit"
            if not self._quiet():
                self.sensor.sink.note_connection(self.src_ip, rejected=True)
            conn.abort()
            return
        self.admitted = True
        # meter inbound bytes (same object layout, one extra method)
        if type(conn) is asyncssh.SSHServerConnection:
            conn.__class__ = _MeteredConnection
            setattr(conn, "_sp_owner", self)  # noqa: B010 - dynamic attribute on a foreign class
        self.sensor.connections.add(self)
        loop = asyncio.get_running_loop()
        self._limit_timer = loop.call_later(self.cfg.max_session, self._hit_session_limit)

    def _hit_session_limit(self) -> None:
        self.drop("session time limit")

    # ---- inbound metering ----------------------------------------------------------------
    # Every chunk read from the socket is queued and the socket is paused at once. The queue
    # is fed to asyncssh in small slices, one per loop callback, at the pace of the inbound
    # byte budgets: the packet decryption a client causes is spread over many callbacks
    # (other connections and the heartbeat run in between) and capped in rate, and while
    # the queue is not empty the kernel buffer fills and TCP pushes back on the client.
    def feed(self, data: bytes) -> None:
        self._backlog.append(data)
        transport = self._transport()
        if transport is not None and not self._in_paused:
            self._in_paused = True
            transport.pause_reading()
        if self._pump is None or self._pump.done():
            self._pump = asyncio.create_task(self._pump_input())

    def _transport(self) -> asyncio.Transport | None:
        transport = getattr(self.conn, "_transport", None)
        if transport is None or transport.is_closing():
            return None
        return transport  # type: ignore[no-any-return]

    async def _pump_input(self) -> None:
        sensor = self.sensor
        while self._backlog:
            wait = sensor.inbound_wait(self.session_id)
            if wait > 0:  # this connection's own budget
                sensor.inbound_pauses += 1
                await asyncio.sleep(min(wait, 10.0))
                continue
            # the sensor-wide budget, least recent user first
            if not await sensor.inbound_fair.acquire(self.src_ip, 30.0):
                continue
            conn = self.conn
            if conn is None or self._transport() is None or not self._backlog:
                sensor.inbound_fair.spend(self.src_ip, 0)  # pass the turn on
                self._backlog.clear()
                return
            head = self._backlog.popleft()
            if len(head) > _FEED_SLICE:
                self._backlog.appendleft(head[_FEED_SLICE:])
                head = head[:_FEED_SLICE]
            sensor.inbound(self.session_id, self.src_ip, len(head))
            try:
                asyncssh.SSHServerConnection.data_received(conn, head)
            except Exception:
                log.debug("ssh input processing failed", exc_info=True)
                self._backlog.clear()
                conn.abort()
                return
            await asyncio.sleep(0)  # one slice per loop step
        self._resume_inbound()

    def _resume_inbound(self) -> None:
        transport = self._transport()
        if self._backlog or not self._in_paused or transport is None:
            return
        self._in_paused = False
        transport.resume_reading()

    def drop(self, reason: str) -> None:
        self.reason = reason
        if self.conn is not None:
            self.conn.close()

    def connection_lost(self, exc: Exception | None) -> None:
        if self._limit_timer is not None:
            self._limit_timer.cancel()
        if not self.admitted:
            return
        self.sensor.release(self.src_ip)
        self.sensor.connections.discard(self)
        self.sensor.forget_inbound(self.session_id)
        if exc is not None and self.reason == "closed by client":
            self.reason = f"connection lost: {type(exc).__name__}"
        engaged = self.logins_ok > 0 or self.commands > 0
        if not engaged and self.auth_requests == 0:
            # Never asked to authenticate (port scan, banner grab, key exchange only): no
            # events of its own, counted in the per-IP periodic summary instead.
            self.sensor.sink.end_session(self.session_id)
            if not self._quiet():
                self.sensor.sink.note_connection(self.src_ip)
            return
        self._ensure_connect()
        self.flush_repeat()
        suppressed = self.sensor.sink.end_session(self.session_id)
        data: dict[str, Any] = {
            "duration_s": round(time.monotonic() - self.started, 2),
            "reason": self.reason,
            "login_attempts": self.attempts,
            "commands": self.commands,
            "downloads": self.downloads,
        }
        if suppressed:
            data["events_suppressed"] = suppressed
        if self.replay:
            frames, truncated = self.replay.export()
            data["replay"] = frames
            if truncated:
                data["replay_truncated"] = True
        # Sessions that logged in or ran a command get the reserve of the global bucket; the
        # disconnect goes first, it already carries the suppressed count.
        self.emit(EventType.disconnect, data, cap=False, priority=engaged)
        if suppressed and engaged:
            self.emit(
                EventType.scan,
                {"kind": "events_suppressed", "count": suppressed},
                force=True,
            )

    # ---- events --------------------------------------------------------------------------
    def emit(
        self,
        type_: EventType,
        data: dict[str, Any],
        *,
        ts: datetime | None = None,
        cap: bool = True,
        max_string: int = 4096,
        force: bool = False,
        priority: bool = False,
    ) -> None:
        if self._quiet():
            return
        if not cap:
            # Only the replay frames bypass truncate_data (it limits lists to 64 items).
            replay = data.pop("replay", None)
            from suckerpot_common import truncate_data

            data = truncate_data(data)
            if replay is not None:
                data["replay"] = replay
        self.sensor.sink.emit(
            session_id=self.session_id,
            src_ip=self.src_ip,
            src_port=self.src_port,
            type_=type_,
            data=data,
            ts=ts,
            max_string=max_string,
            cap_data=cap,
            force=force,
            priority=priority,
        )

    def _quiet(self) -> bool:
        return self.cfg.quiet_loopback and ipaddress.ip_address(self.src_ip).is_loopback

    # ---- repeated command lines ----------------------------------------------------------
    def note_repeat(self, data: dict[str, Any], ts: datetime) -> bool:
        """Track runs of identical command lines. Returns True if this command repeats the
        previous line and is only counted (reported later by ``flush_repeat``)."""
        line = data["input"]
        rep = self._repeat
        if rep is not None and rep["input"] == line:
            rep["repeat_count"] += 1
            rep["last_ts"] = ts
            for key in ("output_preview", "status", "cwd", "user", "prompt"):
                rep[key] = data[key]
            if rep["repeat_count"] >= _REPEAT_FLUSH:
                self.flush_repeat()
            return True
        self.flush_repeat()
        self._repeat = {
            "input": line,
            "repeat_count": 0,
            "first_ts": ts,
            "last_ts": ts,
            **{k: data[k] for k in ("output_preview", "status", "cwd", "user", "prompt")},
        }
        return False

    def flush_repeat(self) -> None:
        """Emit one counted ``command`` event for the repeats seen since the last report."""
        rep = self._repeat
        if rep is None or rep["repeat_count"] == 0:
            return
        first, last = rep["first_ts"], rep["last_ts"]
        self.emit(
            EventType.command,
            {**rep, "first_ts": first.isoformat(), "last_ts": last.isoformat()},
            ts=last,
        )
        rep["repeat_count"] = 0
        rep["first_ts"] = last

    def _ensure_connect(self) -> None:
        if self.connect_emitted:
            return
        self.connect_emitted = True
        self.emit(
            EventType.connect,
            {"client_version": self.client_version, "banner": self.cfg.banner},
            ts=self.started_ts,
        )

    # ---- authentication ------------------------------------------------------------------
    def begin_auth(self, username: str) -> bool:
        self.username = username
        self.auth_requests += 1
        if self.auth_requests > self.cfg.max_auth_attempts * 4:
            self.reason = "too many authentication requests"
            self._schedule_disconnect()
            return True
        if not self.client_version and self.conn is not None:
            version = self.conn.get_extra_info("client_version")
            self.client_version = str(version or "")[:128]
        self._ensure_connect()
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        # the fake sshd_config says KbdInteractiveAuthentication no, like a stock Ubuntu image
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def _schedule_disconnect(self) -> None:
        asyncio.get_running_loop().call_soon(self._disconnect_auth)

    async def _attempt(
        self, username: str, password: str | None, method: str, extra: dict[str, Any] | None = None
    ) -> bool:
        # Everything that enforces the cap happens before the first await: asyncssh cancels
        # an in-flight auth task when the client pipelines the next request, so code after
        # an await is not guaranteed to run.
        self.attempts += 1
        if self.attempts > self.cfg.max_auth_attempts:
            self.reason = "too many authentication failures"
            self._schedule_disconnect()
            return False
        ok = password is not None and self.sensor.credentials_ok(username, password)
        data: dict[str, Any] = {
            "username": username,
            "password": password,
            "success": ok,
            "method": method,
        }
        if extra:
            data.update(extra)
        self.emit(EventType.login_attempt, data)
        if ok:
            self.logins_ok += 1
            return True
        if self.attempts >= self.cfg.max_auth_attempts:
            self.reason = "too many authentication failures"
            self._schedule_disconnect()
        delay = self.sensor.fail_delay()
        if delay:
            await asyncio.sleep(delay)
        return False

    def _disconnect_auth(self) -> None:
        if self.conn is not None:
            self.conn.disconnect(asyncssh.DISC_PROTOCOL_ERROR, "Too many authentication failures")

    async def validate_password(self, username: str, password: str) -> bool:
        return await self._attempt(username, password, "password")

    async def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        await self._attempt(
            username,
            None,
            "publickey",
            {
                "key_type": key.algorithm.decode("ascii", "replace"),
                "key_fingerprint": key.get_fingerprint("sha256"),
            },
        )
        return False

    # ---- everything else is refused -------------------------------------------------------
    def _refuse(self) -> None:
        self.refused += 1
        if self.refused > self.cfg.max_refused_requests and self.conn is not None:
            self.reason = "too many refused requests"
            self.conn.disconnect(asyncssh.DISC_PROTOCOL_ERROR, "Too many authentication failures")

    def connection_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> Any:
        self._refuse()
        self.emit(
            EventType.scan,
            {"kind": "tcp_forward_attempt", "host": dest_host[:255], "port": dest_port},
        )
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> Any:
        self._refuse()
        return False

    # ---- sessions ------------------------------------------------------------------------
    def session_requested(self) -> Any:
        sensor = self.sensor
        if (
            self.channels >= self.cfg.max_channels
            or sensor.mem_level > 0
            or sensor.over_budget(self.src_ip)
        ):
            self._refuse()
            return False
        self.channels += 1
        process = _Process(self)
        if self.conn is None:
            return process
        chan = self.conn.create_server_channel()
        chan.__class__ = _FlowControlledChannel  # same layout, fixed window accounting
        return chan, process

    def channel_closed(self) -> None:
        self.channels = max(0, self.channels - 1)
        if self.channels == 0 and self.conn is not None:
            # Like sshd with a single session: the connection ends with its last channel.
            asyncio.get_running_loop().call_soon(self.conn.close)

    def memory_bytes(self) -> int:
        fs_bytes = self.fs.used_bytes if self.fs is not None else 0
        pending = sum(_pending_input(p) for p in self.processes)
        shells = sum(sh.private_bytes() for sh in self.shells)
        return fs_bytes + shells + self.replay.size + pending + 4096

    def shared_fs(self) -> FakeFS:
        if self.fs is None:
            self.fs = FakeFS(
                self.sensor.base,
                max_bytes=self.cfg.max_fs_bytes,
                max_nodes=self.cfg.max_fs_nodes,
                now=int(time.time()),
            )
        return self.fs

    # ---- shell ---------------------------------------------------------------------------
    async def handle_process(self, process: asyncssh.SSHServerProcess[bytes]) -> None:
        session = ShellSession(self, process)
        self.shells.append(session.shell)
        self.processes.add(process)
        try:
            status = await session.run()
        except (asyncssh.Error, ConnectionError, OSError, TimeoutError) as exc:
            log.debug("session ended: %r", exc)
            status = 1
        except asyncio.CancelledError:
            raise
        finally:
            self.processes.discard(process)
            with contextlib.suppress(ValueError):
                self.shells.remove(session.shell)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(process.stdout.drain(), 5)
            process.exit(status)
            await asyncio.wait_for(process.wait_closed(), 5)


class _MeteredConnection(asyncssh.SSHServerConnection):
    """An SSH connection whose socket data goes through its owner's metered queue."""

    def data_received(self, data: bytes, datatype: Any = None) -> None:
        owner = getattr(self, "_sp_owner", None)
        if owner is None:
            super().data_received(data, datatype)
        else:
            owner.feed(data)


class _FlowControlledChannel(asyncssh.SSHServerChannel[bytes]):
    """A session channel whose receive window counts data that is still buffered.

    While the shell is not reading (its stream is paused), asyncssh keeps incoming packets in
    the channel's receive buffer. When reading resumes, delivering ONE of them re-opens the
    whole window, although the rest is still buffered: a client that keeps sending makes the
    buffer grow without bound. Here the buffered bytes are treated as still in flight, so the
    data held for one channel never exceeds about twice the window.
    """

    _sp_buffered = 0  # bytes waiting in the receive buffer (kept up to date in O(1))
    _sp_direct = False

    def _accept_data(self, data: bytes, datatype: Any = None) -> None:
        if self._recv_paused:
            before = len(self._recv_buf)
            super()._accept_data(data, datatype)
            if len(self._recv_buf) > before:
                self._sp_buffered += len(data)
            return
        self._sp_direct = True
        try:
            super()._accept_data(data, datatype)
        finally:
            self._sp_direct = False

    def _deliver_data(self, data: bytes, datatype: Any) -> None:
        if not self._sp_direct:  # popped from the receive buffer
            self._sp_buffered = max(0, self._sp_buffered - len(data))
        buffered = self._sp_buffered
        self._recv_window += buffered
        try:
            super()._deliver_data(data, datatype)
        finally:
            self._recv_window -= buffered


class _Process(asyncssh.SSHServerProcess[bytes]):
    """A session channel that tells its connection when it goes away (channel accounting)."""

    def __init__(self, owner: Connection) -> None:
        super().__init__(owner.handle_process, None, 0, False)
        self._owner = owner
        self._counted = True

    def subsystem_requested(self, subsystem: str) -> bool:
        return subsystem == "sftp"

    def session_started(self) -> None:
        chan = self._chan
        if chan is not None and chan.get_subsystem() == "sftp":
            # Behave like a server whose sftp-server binary is broken: accept, then close.
            self._owner.emit(
                EventType.command,
                {"input": "subsystem sftp", "output": "", "status": 127},
            )
            chan.exit(127)
            return
        super().session_started()

    def connection_lost(self, exc: Exception | None) -> None:
        super().connection_lost(exc)
        if self._counted:
            self._counted = False
            self._owner.channel_closed()


class ShellSession:
    """Drives a fake shell over one SSH channel (interactive, piped or exec)."""

    def __init__(self, owner: Connection, process: asyncssh.SSHServerProcess[bytes]) -> None:
        self.o = owner
        self.cfg = owner.cfg
        self.p = process
        term = process.get_terminal_type()
        self.tty = term is not None
        command = process.command
        self.command = command
        self.shell = Shell(
            cfg=self.cfg,
            base=owner.sensor.base,
            profile=owner.sensor.profile,
            username=owner.username or "root",
            client_ip=owner.src_ip,
            client_port=owner.src_port,
            term=term or "dumb",
            tty=self.tty,
            interactive=self.tty and command is None,
            shared_fs=owner.shared_fs(),
        )
        self.out_bytes = 0

    # ---- output --------------------------------------------------------------------------
    async def write(self, text: str, err: bool = False) -> None:
        """Send text to the client. Without a PTY, errors go to the stderr channel."""
        if not text:
            return
        if self.tty:
            text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        self.o.replay.add("o", text)
        data = text.encode("utf-8", "replace")
        self.out_bytes += len(data)
        self.o.bytes_out = self.out_bytes
        stream = self.p.stderr if (err and not self.tty) else self.p.stdout
        stream.write(data)
        await asyncio.wait_for(stream.drain(), 30)
        if self.out_bytes > self.cfg.max_session_output:
            self.o.reason = "output limit"
            raise ConnectionError("output limit reached")

    async def read(self, size: int = _READ_CHUNK) -> bytes:
        if _pending_input(self.p) > self.cfg.max_pending_input:
            # backstop if the window accounting above stops working (asyncssh internals)
            self.o.reason = "input flood"
            raise ConnectionError("input flood")
        waited = 0.0
        while self.o.throttled and waited < self.cfg.idle_timeout:
            # memory pressure: leave the input in the (window-bounded) channel buffers
            await asyncio.sleep(0.25)
            waited += 0.25
        while True:
            try:
                return await asyncio.wait_for(self.p.stdin.read(size), self.cfg.idle_timeout)
            except asyncssh.TerminalSizeChanged:
                continue
            except asyncssh.BreakReceived, asyncssh.SignalReceived:
                return b"\x03"
            except TimeoutError:
                self.o.reason = "idle timeout"
                raise

    # ---- commands ------------------------------------------------------------------------
    async def execute(self, line: str) -> bool:
        """Run one command line, emit events, write output. Returns True if the shell exited."""
        await asyncio.sleep(0)  # a client that floods lines must not starve the event loop
        self.o.commands_run += 1
        if self.o.commands_run > self.cfg.max_commands:
            self.o.reason = "command limit"
            raise ConnectionError("command limit reached")
        sensor, ip = self.o.sensor, self.o.src_ip
        may_run = await sensor.cpu.acquire(ip, _CPU_MAX_WAIT)
        started = datetime.now(UTC)
        cpu_start = time.perf_counter()
        plain_prompt = self._plain_prompt()
        cwd, user = self.shell.cwd, self.shell.user.name
        result = Result([], 2)
        prefix = self.shell.error_prefix()
        try:
            if not may_run:
                result = Result(
                    [(True, f"{prefix}fork: retry: Resource temporarily unavailable\n")], 254
                )
                self.shell.last_status = result.status
            elif sensor.over_budget(ip):
                result = Result([(True, f"{prefix}fork: Cannot allocate memory\n")], 12)
                self.shell.last_status = result.status
            else:
                result = self.shell.run_line(line)
        finally:
            # The event is recorded even if the run was cancelled or failed unexpectedly.
            self.o.commands += 1
            text = result.output
            data: dict[str, Any] = {
                "input": line,
                "output": text,
                "output_preview": text[:1024],
                "cwd": cwd,
                "user": user,
                "prompt": plain_prompt,
                "status": result.status,
            }
            repeated = self.o.note_repeat(data, started)
            if not repeated:
                self.o.emit(EventType.command, data, ts=started, max_string=8192)
            for pending in self.shell.pending:
                if pending.type == EventType.download_attempt:
                    self.o.downloads += 1
                if not repeated:
                    self.o.emit(pending.type, {**pending.data, "cwd": cwd, "user": user})
            self.shell.pending.clear()
            sensor.cpu.spend(ip, time.perf_counter() - cpu_start)
        if result.delay and self.cfg.command_delay:
            await asyncio.sleep(result.delay)
        if self.tty:
            await self.write(text)
        else:
            for err, chunk in result.chunks:
                await self.write(chunk, err)
        return result.exit

    def _plain_prompt(self) -> str:
        sign = "#" if self.shell.is_root else "$"
        sh = self.shell
        return f"{sh.user.name}@{sh.profile.hostname}:{sh.display_cwd()}{sign} "

    # ---- main loops ----------------------------------------------------------------------
    async def run(self) -> int:
        try:
            async with asyncio.timeout(self.cfg.max_session):
                if self.command is not None:
                    return await self._run_exec(self.command)
                if self.tty:
                    return await self._run_tty()
                return await self._run_pipe()
        except TimeoutError:
            if self.o.reason == "closed by client":
                self.o.reason = "session time limit"
            return 1

    async def _run_exec(self, command: str) -> int:
        if len(command) > self.cfg.max_line:
            self.o.reason = "line too long"
            return 1
        if command.startswith("scp ") and " -t" in command:
            return await self._scp_sink(command)
        self.o.replay.add("i", command[:1024] + "\n")
        await self.execute(command)
        return self.shell.last_status

    async def _run_pipe(self) -> int:
        buf = ""
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        while True:
            chunk = await self.read()
            await asyncio.sleep(0)
            if not chunk:
                if buf.strip():
                    await self.execute(buf)
                return self.shell.last_status
            self.o.replay.add("i", chunk.decode("utf-8", "replace"))
            buf += decoder.decode(chunk)
            if len(buf) > self.cfg.max_line * 4 and "\n" not in buf:
                self.o.reason = "line too long"
                return 1
            while "\n" in buf:
                line, _, buf = buf.partition("\n")
                if len(line) > self.cfg.max_line:
                    self.o.reason = "line too long"
                    return 1
                if await self.execute(line.rstrip("\r")):
                    return self.shell.last_status

    async def _run_tty(self) -> int:
        profile = self.shell.profile
        last = time.strftime(
            "%a %b %e %H:%M:%S %Y", time.gmtime(time.time() - profile.last_login_age)
        )
        await self.write(
            _MOTD.format(
                os_pretty=self.shell.profile.os_pretty,
                kernel=self.shell.profile.kernel,
                when=time.strftime("%a %b %e %H:%M:%S UTC %Y", time.gmtime()),
                ip=self.shell.profile.ip,
                last=last,
                last_ip=profile.last_login_ip,
            )
            + "\n"
        )
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        line: list[str] = []
        esc = ""
        hist_pos = 0
        skip_lf = False
        await self.write(self.shell.prompt())
        while True:
            chunk = await self.read()
            await asyncio.sleep(0)
            if not chunk:
                return self.shell.last_status
            self.o.replay.add("i", chunk.decode("utf-8", "replace")[:256])
            for ch in decoder.decode(chunk):
                if esc:
                    esc += ch
                    if esc == "\x1b[" or esc == "\x1bO" or esc == "\x1b":
                        continue
                    if len(esc) > 2 and not ("@" <= ch <= "~"):
                        if len(esc) < 16:
                            continue
                    final = ch
                    esc = ""
                    if final in "AB":
                        hist = self.shell.history
                        hist_pos = min(max(hist_pos + (1 if final == "A" else -1), 0), len(hist))
                        new = hist[-hist_pos] if hist_pos else ""
                        await self.write("\r\x1b[K" + self.shell.prompt() + new)
                        line = list(new)
                    continue
                if ch == "\x1b":
                    esc = ch
                    continue
                if ch == "\n" and skip_lf:
                    skip_lf = False
                    continue
                skip_lf = ch == "\r"
                if ch in "\r\n":
                    text = "".join(line)
                    line.clear()
                    hist_pos = 0
                    await self.write("\n")
                    if text.strip():
                        if await self.execute(text):
                            await self.write("logout\n")
                            return self.shell.last_status
                    await self.write(self.shell.prompt())
                elif ch in "\x7f\x08":
                    if line:
                        line.pop()
                        await self.write("\b \b")
                elif ch == "\x03":
                    line.clear()
                    await self.write("^C\n" + self.shell.prompt())
                elif ch == "\x04":
                    if not line:
                        await self.write("logout\n")
                        return self.shell.last_status
                elif ch == "\x15":
                    await self.write("\b \b" * len(line))
                    line.clear()
                elif ch == "\x0c":
                    await self.write("\x1b[H\x1b[2J" + self.shell.prompt() + "".join(line))
                elif ch >= " " and ch != "\x7f":
                    if len(line) >= self.cfg.max_line:
                        self.o.reason = "line too long"
                        return 1
                    line.append(ch)
                    await self.write(ch)

    async def _scp_sink(self, command: str) -> int:
        """Accept (and discard) an scp upload, recording name, size and sha256 only."""
        started = datetime.now(UTC)
        self.p.stdout.write(b"\0")
        uploads: list[dict[str, Any]] = []
        budget = 8 * 1024 * 1024
        try:
            while len(uploads) < 8:
                header = await asyncio.wait_for(self.p.stdin.readline(), self.cfg.idle_timeout)
                if not header:
                    break
                if len(header) > 1024:
                    break
                if header[:1] == b"C":
                    parts = header.decode("utf-8", "replace").split(" ", 2)
                    size = _scp_size(parts[1] if len(parts) > 1 else "")
                    if size is None or size > budget:
                        break
                    budget -= size
                    self.p.stdout.write(b"\0")
                    digest = hashlib.sha256()
                    remaining = size
                    while remaining > 0:
                        part = await asyncio.wait_for(
                            self.p.stdin.read(min(65536, remaining)), self.cfg.idle_timeout
                        )
                        if not part:
                            break
                        digest.update(part)
                        remaining -= len(part)
                    await asyncio.wait_for(self.p.stdin.read(1), self.cfg.idle_timeout)
                    uploads.append(
                        {
                            "name": parts[2].strip()[:128] if len(parts) > 2 else "",
                            "mode": parts[0][1:],
                            "size": size,
                            "sha256": digest.hexdigest(),
                        }
                    )
                self.p.stdout.write(b"\0")
        except TimeoutError, asyncssh.Error, ConnectionError:
            pass
        self.o.commands += 1
        self.o.emit(
            EventType.command,
            {"input": command, "output": "", "scp_upload": uploads, "user": self.shell.user.name},
            ts=started,
        )
        return 0


class SSHSensorServer:
    """Owns the asyncssh listener."""

    def __init__(self, cfg: Config, sensor: Sensor, host_keys: list[asyncssh.SSHKey]) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self.host_keys = host_keys
        self._server: asyncssh.SSHAcceptor | None = None

    async def start(self) -> int:
        cfg = self.cfg
        server = await asyncssh.create_server(
            lambda: Connection(self.sensor),
            cfg.host,
            cfg.port,
            server_host_keys=_ordered_keypairs(self.host_keys),
            server_version=cfg.software_version,
            kex_algs=KEX_ALGS,
            encryption_algs=ENC_ALGS,
            mac_algs=MAC_ALGS,
            compression_algs=COMP_ALGS,
            signature_algs=SIG_ALGS,
            login_timeout=cfg.login_timeout,
            encoding=None,
            line_editor=False,
            allow_pty=True,
            agent_forwarding=False,
            x11_forwarding=False,
            sftp_factory=None,
            allow_scp=False,
            # small flow-control window: input a client sends faster than the shell reads it
            # stays on the client side instead of piling up in our buffers
            window=cfg.channel_window,
            max_pktsize=cfg.max_pktsize,
            backlog=128,
            reuse_address=True,
        )
        self._server = server
        for sock in server.sockets:
            # small receive buffers: each read (and asyncssh's per-read work) stays small,
            # and a paused connection pushes back on the client sooner
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, cfg.recv_buffer)
        self.sensor.start()
        sockets = server.sockets
        return int(sockets[0].getsockname()[1]) if sockets else cfg.port

    async def stop(self) -> None:
        await self.sensor.stop()
        if self._server is not None:
            self._server.close()
            for conn in list(self.sensor.connections):
                if conn.conn is not None:
                    conn.reason = "server shutdown"
                    conn.conn.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 5)


def _pending_input(process: asyncssh.SSHServerProcess[bytes]) -> int:
    """Bytes received on a channel that the shell has not read yet (O(1)). Reads asyncssh
    internals defensively: anything missing counts as 0."""
    total = 0
    with contextlib.suppress(Exception):
        total += int(getattr(process, "_recv_buf_len", 0) or 0)
        total += int(getattr(getattr(process, "_chan", None), "_sp_buffered", 0) or 0)
    return total


def _scp_size(text: str) -> int | None:
    """Size field of an scp ``C`` header: ASCII digits only (no sign, no ``_``, no Unicode
    digits, which ``int()`` would all accept), bounded length."""
    if 0 < len(text) <= 12 and text.isascii() and text.isdigit():
        return int(text)
    return None


def _ordered_keypairs(keys: list[asyncssh.SSHKey]) -> list[asyncssh.SSHKeyPair]:
    """Advertise host key algorithms in OpenSSH 9.6 order, without the ssh.com/SHA-1 variants:
    rsa-sha2-512, rsa-sha2-256, ecdsa-sha2-nistp256, ssh-ed25519."""
    rank = {b"ssh-rsa": 0, b"ecdsa-sha2-nistp256": 1, b"ssh-ed25519": 2}
    pairs: list[asyncssh.SSHKeyPair] = []
    for key in sorted(keys, key=lambda k: rank.get(k.algorithm, 9)):
        pair = asyncssh.load_keypairs(key)[0]
        if key.algorithm == b"ssh-rsa":
            pair.host_key_algorithms = [b"rsa-sha2-512", b"rsa-sha2-256"]
        pairs.append(pair)
    return pairs
