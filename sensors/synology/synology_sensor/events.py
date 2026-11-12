"""Event emission: bounded queue, rate limits, background publishing.

Handlers never wait for Redis. ``emit`` builds the event, applies the limits and puts it on a
bounded queue; background workers call the publisher. Anything that cannot be queued, or that
the publisher refuses, is only counted.

Limits (per event class):

* ``connect``: per source IP (connection floods).
* ordinary ``http_request``: per session (one TCP connection).
* important events (``login_attempt``, ``download_attempt``, exploit ``http_request``): a
  separate, larger per-session bucket that ordinary traffic can never drain.
* ``disconnect``: has its own per-IP bucket (sized above the connection rate limit, so a normal
  source never hits it) and its own reserved queue slots, so a flooding IP cannot keep its
  sessions from closing in the UI. It carries the counters and the number of suppressed events.
* every event that is still dropped is written to a per-IP ledger; ``flush_overflow`` turns the
  ledger into ONE ``scan`` summary per IP (counts by type, lost disconnects), through the same
  reserved slots, so nothing disappears without a trace.
* important events are also limited per source IP, in front of the global cap.
* ONE sensor-wide bucket caps the total rate. Ordinary events may only use it while a reserved
  share of tokens is left for important events; ``disconnect`` may dip slightly below zero, so
  the ceiling stays close to the configured rate even for floods of short connections.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import logging
import time
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError
from suckerpot_common import Event, EventType, SensorName, truncate_data

log = logging.getLogger("synology_sensor.events")

_MAX_TRACKED = 10_000
_PRIORITY_TYPES = frozenset(
    {EventType.connect, EventType.disconnect, EventType.login_attempt, EventType.download_attempt}
)
_WORKERS = 2


class Publisher(Protocol):
    async def publish(self, event: Event) -> bool: ...

    async def close(self) -> None: ...


class _Buckets:
    """Token buckets keyed by string, bounded in size (oldest keys are evicted)."""

    def __init__(self, rate: float, burst: float, max_keys: int = _MAX_TRACKED) -> None:
        self.rate = rate
        self.burst = burst
        self._max = max_keys
        self._items: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= min(cost, self.burst)
        if allowed:
            tokens -= min(cost, self.burst)
        self._items[key] = (tokens, now)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return allowed

    def tokens(self, key: str) -> float:
        """Tokens a key would have now (a full burst for an unknown key); nothing is consumed."""
        item = self._items.get(key)
        if item is None:
            return self.burst
        return min(self.burst, item[0] + (time.monotonic() - item[1]) * self.rate)

    def drop(self, key: str) -> None:
        self._items.pop(key, None)


class _GlobalBucket:
    """One token bucket with a reserved share for important events and a debt for disconnects."""

    def __init__(self, rate: float, burst: float, reserve_fraction: float = 0.25) -> None:
        self.rate = rate
        self.burst = burst
        self.reserve = burst * reserve_fraction
        self.debt = min(20.0, burst * 0.1)
        self.tokens = burst
        self.last = time.monotonic()

    def allow(self, important: bool, final: bool = False) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if final:
            floor = 1.0 - self.debt
        elif important:
            floor = 1.0
        else:
            floor = 1.0 + self.reserve
        if self.tokens < floor:
            return False
        self.tokens -= 1.0
        return True


class _Guarantee:
    """A small per-IP quota that works even when the sensor-wide bucket is empty.

    It is only used after the sensor-wide bucket refused, so light sources never notice it and
    flooding sources get at most ``rate`` extra events per second each. A shared bucket caps the
    total of all guaranteed events, so many IPs together stay bounded too.
    """

    def __init__(self, ip_rate: float, ip_burst: float, rate: float, burst: float) -> None:
        self._ips = _Buckets(ip_rate, ip_burst)
        self._shared = _Buckets(rate, burst, max_keys=1)

    def allow(self, ip: str) -> bool:
        return self._ips.allow(ip) and self._shared.allow("*")


class EventSink:
    def __init__(
        self,
        publisher: Publisher,
        *,
        rate: float = 20.0,
        burst: float = 100.0,
        queue_size: int = 5000,
        queue_bytes: int = 4 * 1024 * 1024,
        important_rate: float = 50.0,
        important_burst: float = 400.0,
        global_rate: float = 200.0,
        global_burst: float = 400.0,
        important_ip_rate: float = 20.0,
        important_ip_burst: float = 200.0,
        ip_rate: float = 40.0,
        ip_burst: float = 200.0,
        ip_byte_rate: float = 64 * 1024.0,
        ip_byte_burst: float = 512 * 1024.0,
        ip_queue_limit: int = 100,
        disc_ip_rate: float = 10.0,
        disc_ip_burst: float = 60.0,
    ) -> None:
        self._publisher = publisher
        # Two classes share one priority queue: priority 0 (connect, disconnect, login,
        # download, flagged events) is always taken first. Each class is bounded in count AND
        # in bytes (JSON size of ``data``), and every source IP may hold only a few entries of
        # each class, so a flooding IP can neither fill the queue nor push out a victim.
        self._queue: asyncio.PriorityQueue[tuple[int, int, Event, int, str, bool]] = (
            asyncio.PriorityQueue()
        )
        self._seq = itertools.count()
        self._cap = (queue_size // 2, queue_size - queue_size // 2)
        self._cap_bytes = (queue_bytes // 2, queue_bytes - queue_bytes // 2)
        self._count = [0, 0]
        self._bytes = [0, 0]
        self._ip_queued: dict[tuple[int, str], int] = {}
        self._ip_limit = ip_queue_limit
        self.queued_bytes = 0
        self._ip_events = _Buckets(ip_rate, ip_burst)
        self._ip_bytes = _Buckets(ip_byte_rate, ip_byte_burst)
        self._ip_important = _Buckets(important_ip_rate, important_ip_burst)
        self._ip = _Buckets(rate, burst)
        self._session = _Buckets(rate, burst)
        self._important = _Buckets(important_rate, important_burst)
        self._global = _GlobalBucket(global_rate, global_burst)
        self._ok_important = _Guarantee(4.0, 40.0, 150.0, 1200.0)
        self._ok_ordinary = _Guarantee(2.0, 40.0, 100.0, 800.0)
        self._ip_disc = _Buckets(disc_ip_rate, disc_ip_burst)
        self._disc_cap = max(16, queue_size // 10)  # slots for disconnects and summaries
        self._disc_count = 0
        self._ledger: dict[str, dict[str, Any]] = {}
        self._suppressed: dict[str, int] = {}
        self._tasks: list[asyncio.Task[None]] = []
        self._dst_port = 0
        self.emitted = 0
        self.published = 0
        self.rate_limited = 0
        self.global_limited = 0
        self.queue_full = 0
        self.publish_failed = 0
        self.invalid = 0
        self.summaries = 0

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(_WORKERS)]

    def _suppress(self, session_id: str) -> None:
        self.rate_limited += 1
        if session_id in self._suppressed or len(self._suppressed) < _MAX_TRACKED:
            self._suppressed[session_id] = self._suppressed.get(session_id, 0) + 1

    def _lost(self, ip: str, type_: EventType, session_id: str) -> None:
        """Remember that an event of ``ip`` was dropped (summarised later, one per IP)."""
        self._suppress(session_id)
        entry = self._ledger.get(ip)
        if entry is None:
            if len(self._ledger) >= _MAX_TRACKED:
                return
            entry = self._ledger[ip] = {"events": 0, "disconnects": 0, "types": {}}
        entry["events"] += 1
        if type_ == EventType.disconnect:
            entry["disconnects"] += 1
        types = entry["types"]
        types[type_.value] = types.get(type_.value, 0) + 1

    def flush_overflow(self, window_s: int = 15, max_summaries: int = 50) -> int:
        """Queue one ``scan`` summary per IP that lost events since the last call."""
        ledger, self._ledger = self._ledger, {}
        ranked = sorted(ledger.items(), key=lambda kv: -kv[1]["events"])
        sent = 0
        for ip, entry in ranked[:max_summaries]:
            data = {
                "kind": "events_suppressed",
                "suppressed": entry["events"],
                "disconnects_lost": entry["disconnects"],
                "by_type": entry["types"],
                "window_s": window_s,
            }
            if self._enqueue_reserved(ip, data):
                sent += 1
        self.summaries += sent
        return sent

    def _enqueue_reserved(self, ip: str, data: dict[str, Any]) -> bool:
        try:
            event = Event(
                ts=datetime.now(UTC),
                sensor=SensorName("synology"),
                session_id=uuid.uuid4().hex[:24],
                src_ip=ip,  # type: ignore[arg-type]
                src_port=0,
                dst_port=self._dst_port,
                type=EventType.scan,
                data=truncate_data(data),
            )
        except ValidationError, ValueError, TypeError:
            return False
        return self._put(event, 0, 600, ip, reserved=True)

    def _put(self, event: Event, prio: int, size: int, ip: str, *, reserved: bool = False) -> bool:
        if reserved:
            if self._disc_count >= self._disc_cap:
                return False
            self._disc_count += 1
        else:
            if (
                self._count[prio] >= self._cap[prio]
                or self._bytes[prio] + size > self._cap_bytes[prio]
            ):
                return False
            self._count[prio] += 1
        self._bytes[prio] += size
        self.queued_bytes += size
        key = (prio, ip)
        self._ip_queued[key] = self._ip_queued.get(key, 0) + 1
        self._queue.put_nowait((prio, next(self._seq), event, size, ip, reserved))
        return True

    def end_session(self, session_id: str) -> int:
        """Forget a session's buckets; returns how many of its events were suppressed."""
        self._session.drop(session_id)
        self._important.drop(session_id)
        return self._suppressed.pop(session_id, 0)

    def emit(
        self,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        dst_port: int,
        type_: EventType,
        data: dict[str, Any],
        important: bool = False,
        ts: datetime | None = None,
        max_string: int = 4096,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises."""
        self._dst_port = dst_port
        final = type_ == EventType.disconnect
        if final:
            # Own per-IP bucket, then the sensor-wide one (which lets a disconnect dip below zero).
            ok = self._ip_disc.allow(src_ip) and self._global.allow(True, final=True)
        elif important:
            ok = (
                self._important.allow(session_id)
                and self._ip_important.allow(src_ip)
                and (self._global.allow(True) or self._ok_important.allow(src_ip))
            )
        elif type_ == EventType.connect:
            ok = self._ip.allow(src_ip) and (
                self._global.allow(False) or self._ok_important.allow(src_ip)
            )
        else:
            ok = (
                self._ip_events.allow(src_ip)
                and self._session.allow(session_id)
                and (self._global.allow(False) or self._ok_ordinary.allow(src_ip))
            )
        if not ok:
            if final:
                self.global_limited += 1
            self._lost(src_ip, type_, session_id)
            return False
        try:
            event = Event(
                ts=ts or datetime.now(UTC),
                sensor=SensorName("synology"),
                session_id=session_id,
                src_ip=src_ip,  # type: ignore[arg-type]
                src_port=src_port,
                dst_port=dst_port,
                type=type_,
                data=truncate_data(data, max_string=max_string),
            )
        except ValidationError, ValueError, TypeError:
            self.invalid += 1
            log.warning("event rejected by schema validation (type=%s)", type_)
            return False
        size = len(json.dumps(event.data, default=str, separators=(",", ":"))) + 256
        prio = 0 if (important or type_ in _PRIORITY_TYPES) else 1
        key = (prio, src_ip)
        if not final and not self._ip_bytes.allow(src_ip, size):
            self._lost(src_ip, type_, session_id)
            return False
        if not final and self._ip_queued.get(key, 0) >= self._ip_limit:
            self.queue_full += 1
            self._lost(src_ip, type_, session_id)
            return False
        # Disconnects use the reserved slots first; if those are full they compete normally.
        if not self._put(event, prio, size, src_ip, reserved=final and self._disc_room()):
            self.queue_full += 1
            self._lost(src_ip, type_, session_id)
            return False
        self.emitted += 1
        return True

    def _disc_room(self) -> bool:
        return self._disc_count < self._disc_cap

    async def _worker(self) -> None:
        while True:
            prio, _, event, size, ip, reserved = await self._queue.get()
            if reserved:
                self._disc_count -= 1
            else:
                self._count[prio] -= 1
            self._bytes[prio] -= size
            self.queued_bytes -= size
            key = (prio, ip)
            left = self._ip_queued.get(key, 1) - 1
            if left <= 0:
                self._ip_queued.pop(key, None)
            else:
                self._ip_queued[key] = left
            try:
                if await self._publisher.publish(event):
                    self.published += 1
                else:
                    self.publish_failed += 1
            except Exception:
                self.publish_failed += 1
                log.exception("publisher raised unexpectedly")
            finally:
                self._queue.task_done()

    async def flush(self, wait: float = 5.0) -> None:
        """Wait until the queue is drained (bounded)."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._queue.join(), wait)

    async def close(self) -> None:
        self.flush_overflow()
        await self.flush()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self._publisher.close()

    def stats(self) -> dict[str, int]:
        return {
            "emitted": self.emitted,
            "published": self.published,
            "rate_limited": self.rate_limited,
            "global_limited": self.global_limited,
            "queue_full": self.queue_full,
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
            "summaries": self.summaries,
        }
