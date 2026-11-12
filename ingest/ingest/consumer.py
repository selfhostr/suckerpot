"""Redis Streams consumer loop (one consumer group, one stream per sensor).

Redis commands used (ACL user ``ingest``): XGROUP CREATE, XREADGROUP, XACK, XAUTOCLAIM,
XTRIM (plus AUTH/HELLO performed implicitly by the client on connect), and XADD on the one key
``events:parked`` (events that cannot be stored, see "Failure handling": at most 500
entries, each reduced to its identifying fields and 2 KB of ``data``).

Failure handling. A failed write is classified (``classify_failure``): a data error (the event
itself is bad) is retried per message and then dropped; an outage (connection, restart, Redis)
is retried forever with a global backoff; anything else (a statement timeout, a deadlock, a
permission error) counts against the stream. A stream is isolated: it backs off on its own and the
others keep flowing. After ``INGEST_MAX_BATCH_FAILURES`` such failures in a row the batch is
bisected, so one poisonous event is found, copied to ``events:parked`` (capped) and acknowledged.
Bisection never parks a whole batch that failed as a unit (that is a systemic fault, not a bad
event) and parks at most ``MAX_CONSECUTIVE_PARKS`` events in a row without a successful write.

Every stream (``events:ssh``, ``events:telnet``, ...) has its own group state: ACK, reclaim and
trim are per stream. Single-consumer assumption: after each committed and acknowledged batch
the stream is trimmed with ``XTRIM MINID ~ <last acked id>``, but only once that stream's
pending list has been drained, so entries that were never read cannot be trimmed away. Run
exactly one ingest instance.

Defences against a misbehaving producer: an event whose ``sensor`` differs from the stream
suffix, or whose ``session_id`` starts with ``burst-`` (reserved for flood groups, see
``db/migrations/versions/0034_session_floods.py``), is dropped (counted); entry ids far in the
future are reported and never used as a trim target (an explicit future id would otherwise make
MINID trimming wipe the stream).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Iterable, Sequence
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import Event

from ingest.config import Settings
from ingest.diskguard import DiskGuard
from ingest.enrichment.enricher import Enricher
from ingest.writer import write_batch

log = logging.getLogger(__name__)

PREVIEW_CHARS = 200
# Session ids of flood groups (sessions.kind = 'burst'). No sensor produces one, and an event that
# did would land on, or forge, a group row.
RESERVED_SESSION_PREFIX = "burst-"
MAX_ATTEMPTS = 5
FUTURE_ID_SLACK_MS = 24 * 3600 * 1000
WARN_INTERVAL_S = 60.0
PARKED_STREAM = "events:parked"
# Nothing reads the parked stream and the broker never evicts (noeviction): keep it small, so a
# bad day cannot fill the broker's memory and make every sensor XADD fail.
PARKED_MAXLEN = 500
PARKED_DATA_BYTES = 2048
RETRY_PAUSE_S = 1.0
MAX_CONSECUTIVE_PARKS = 3
ERROR_CHARS = 200
STATE_INTERVAL_S = 30.0
STATE_TIMEOUT_S = 5.0
MAX_STREAM_BACKOFF_S = 30.0
# SQLSTATEs that mean the server (not the statement) is unavailable: retried forever.
OUTAGE_SQLSTATES = frozenset({"57P01", "57P02", "57P03", "53300"})

Message = tuple[bytes | str, dict[Any, Any]]
Parsed = tuple[list[tuple[bytes | str, Event]], list[Any], int]


def preview(fields: dict[Any, Any] | None) -> str:
    text = repr(fields)
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "...<truncated>"


def stream_sensor(stream: str) -> str | None:
    """Sensor name implied by a stream name (``events:ssh`` gives ``ssh``), if any."""
    return stream.rsplit(":", 1)[1] if ":" in stream else None


def parse_messages(messages: Sequence[Message], expected_sensor: str | None = None) -> Parsed:
    """Validate messages.

    Returns (valid (id, event) pairs, ids to drop, number dropped as forged). An event is forged
    when its sensor differs from the stream's or its session id uses the reserved ``burst-`` prefix.
    """
    good: list[tuple[bytes | str, Event]] = []
    bad: list[Any] = []
    mismatched = 0
    for msg_id, fields in messages:
        try:
            ev = Event.from_stream_fields(fields)
        except Exception:
            log.warning("invalid message %r skipped: %s", msg_id, preview(fields))
            bad.append(msg_id)
            continue
        forged_sensor = expected_sensor is not None and str(ev.sensor) != expected_sensor
        if forged_sensor or ev.session_id.startswith(RESERVED_SESSION_PREFIX):
            mismatched += 1
            bad.append(msg_id)
            continue
        good.append((msg_id, ev))
    return good, bad, mismatched


class Consumer:
    def __init__(
        self,
        settings: Settings,
        redis: Redis,
        factory: async_sessionmaker[AsyncSession],
        enricher: Enricher | None = None,
        guard: DiskGuard | None = None,
    ) -> None:
        self.enricher = enricher
        self.guard = guard
        self.s = settings
        self.redis = redis
        self.factory = factory
        self.stop = asyncio.Event()
        self.attempts: dict[tuple[str, Any], int] = {}
        # Streams whose pending list is not yet fully drained: trimming them is unsafe.
        self.draining: set[str] = set()
        self.sensor_mismatches = 0
        self._last_warn: dict[str, float] = {}
        # Consecutive failed batches of kind "other" per stream (drives bisection).
        self.failures: dict[str, int] = {}
        self.consecutive_parks: dict[str, int] = {}
        self.parked = 0
        # Streams that failed and are waiting out their own backoff (monotonic deadline).
        self.cooldown: dict[str, float] = {}
        self.stream_backoff: dict[str, float] = {}
        self.unhealthy: set[str] = set()
        self._last_state = -STATE_INTERVAL_S

    def heartbeat(self) -> None:
        try:
            self.s.heartbeat_path.touch()
        except OSError:
            log.exception("cannot touch heartbeat file")

    def _warn(self, key: str, msg: str, *args: Any) -> None:
        """Rate-limited warning (one per key and minute)."""
        now = time.monotonic()
        if now - self._last_warn.get(key, -WARN_INTERVAL_S) >= WARN_INTERVAL_S:
            self._last_warn[key] = now
            log.warning(msg, *args)

    async def ensure_groups(self) -> None:
        for stream in self.s.streams:
            try:
                await self.redis.xgroup_create(stream, self.s.group, id="0", mkstream=True)
                log.info("created consumer group %s on %s", self.s.group, stream)
            except ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    async def reclaim_stale(self, stream: str, min_idle_ms: int | None = None) -> int:
        """Take over entries pending for any consumer on ``stream`` (XAUTOCLAIM)."""
        idle = self.s.claim_idle_ms if min_idle_ms is None else min_idle_ms
        start: bytes | str = "0-0"
        claimed = 0
        while not self.stop.is_set():
            res = await self.redis.xautoclaim(
                stream,
                self.s.group,
                self.s.consumer,
                min_idle_time=idle,
                start_id=start,
                count=self.s.batch_size,
            )
            start, messages = res[0], res[1]
            claimed += len(messages)
            if start in (b"0-0", "0-0"):
                break
        if claimed:
            log.info("reclaimed %d pending entries on %s", claimed, stream)
        return claimed

    def _check_future_ids(self, stream: str, ids: Sequence[Any]) -> None:
        limit = int(time.time() * 1000) + FUTURE_ID_SLACK_MS
        if any(_id_key(i)[0] > limit for i in ids):
            self._warn("future-id:" + stream, "entry id far in the future on %s", stream)

    async def process(self, stream: str, messages: Sequence[Message]) -> None:
        """Validate, write, ack and trim one batch of ``stream``. Raises on write failure."""
        self._check_future_ids(stream, [m[0] for m in messages])
        live: list[Message] = []
        dead: list[Any] = []
        for msg in messages:
            n = self.attempts.get((stream, msg[0]), 0)
            if n >= MAX_ATTEMPTS:
                log.error("dead-lettering %r on %s after %d failed attempts", msg[0], stream, n)
                dead.append(msg[0])
            else:
                live.append(msg)
        await self._ack(stream, dead)
        for mid in dead:
            self.attempts.pop((stream, mid), None)
        acked: list[Any] = list(dead)
        try:
            if live:
                if self.failures.get(stream, 0) >= self.s.max_batch_failures:
                    acked += await self._isolate(stream, live)
                else:
                    acked += await self._process_live(stream, live)
        except Exception as exc:
            kind = classify_failure(exc)
            if kind == "data":
                for mid, _ in live:
                    key = (stream, mid)
                    self.attempts[key] = self.attempts.get(key, 0) + 1
            elif kind == "other":
                self.failures[stream] = self.failures.get(stream, 0) + 1
                await self._note_failure(stream, exc)
            raise
        for mid, _ in live:
            self.attempts.pop((stream, mid), None)
        self.failures.pop(stream, None)
        await self._trim(stream, acked)

    async def _isolate(self, stream: str, messages: Sequence[Message]) -> list[Any]:
        """Find the event(s) that keep a batch from being stored. Returns the ids acknowledged.

        Writes the batch in halves, then singles. Events that still fail are parked. When no
        event of a batch of several can be stored, the fault is not in the events: nothing is
        parked, the failure counter restarts and the original error is raised.
        """
        good, bad, mismatched = parse_messages(messages, stream_sensor(stream))
        self.sensor_mismatches += mismatched
        await self._ack(stream, bad)
        done: list[Any] = []
        poisoned: list[tuple[bytes | str, Event, Exception]] = []
        await self._bisect(stream, good, done, poisoned, top=True)
        if done:
            self.consecutive_parks[stream] = 0
        leftover: Exception | None = None
        if poisoned:
            systemic = not done and (
                len(good) > 1 or self.consecutive_parks.get(stream, 0) >= MAX_CONSECUTIVE_PARKS
            )
            if systemic:
                self.failures[stream] = 0
                raise poisoned[0][2]
            # Never park more than a few per call: intermittent timeouts under load must not
            # turn a busy batch into parked events. The rest stays pending and is retried.
            for msg_id, ev, exc in poisoned[:MAX_CONSECUTIVE_PARKS]:
                await self._park(stream, msg_id, ev, exc)
                done.append(msg_id)
            self.consecutive_parks[stream] = self.consecutive_parks.get(stream, 0) + min(
                len(poisoned), MAX_CONSECUTIVE_PARKS
            )
            if len(poisoned) > MAX_CONSECUTIVE_PARKS:
                leftover = poisoned[MAX_CONSECUTIVE_PARKS][2]
        self.failures[stream] = 0
        if leftover is not None:
            raise leftover
        return done + bad

    async def _bisect(
        self,
        stream: str,
        items: list[tuple[bytes | str, Event]],
        done: list[Any],
        poisoned: list[tuple[bytes | str, Event, Exception]],
        *,
        top: bool = False,
    ) -> None:
        if not items:
            return
        if not (top and len(items) > 1):  # the whole batch has just failed: do not retry it
            try:
                await self._write([ev for _, ev in items])
            except (StatementError, DBAPIError) as exc:
                if classify_failure(exc) == "outage":
                    raise
                if len(items) == 1:
                    # One more try after a pause: a timeout under load is not a bad event.
                    await self._sleep(RETRY_PAUSE_S)
                    if self.stop.is_set():
                        return  # stays pending
                    try:
                        await self._write([items[0][1]])
                    except (StatementError, DBAPIError) as again:
                        if classify_failure(again) == "outage":
                            raise
                        poisoned.append((items[0][0], items[0][1], again))
                    else:
                        await self._ack(stream, [items[0][0]])
                        done.append(items[0][0])
                    return
            else:
                ids = [i for i, _ in items]
                await self._ack(stream, ids)
                done.extend(ids)
                return
        mid = len(items) // 2
        await self._bisect(stream, items[:mid], done, poisoned)
        await self._bisect(stream, items[mid:], done, poisoned)

    async def _park(self, stream: str, msg_id: bytes | str, ev: Event, exc: Exception) -> None:
        """Copy an event that cannot be stored to the capped dead-letter stream, then ACK it."""
        mid = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)
        log.error(
            "parking event %s of %s (sensor %s): SQLSTATE %s",
            mid,
            stream,
            ev.sensor,
            _sqlstate(exc) or "none",
        )
        data = json.dumps(ev.data, default=str).encode("utf-8", "replace")
        fields: dict[Any, Any] = {
            "sensor": str(ev.sensor),
            "session_id": ev.session_id[:128],
            "src_ip": str(ev.src_ip),
            "type": str(ev.type),
            "ts": ev.ts.isoformat(),
            "origin_stream": stream,
            "origin_id": mid,
            "error": _sqlstate(exc) or "none",
            "data": data[:PARKED_DATA_BYTES].decode("utf-8", "ignore"),
            "truncated": "1" if len(data) > PARKED_DATA_BYTES else "0",
        }
        await self.redis.xadd(PARKED_STREAM, fields, maxlen=PARKED_MAXLEN, approximate=True)
        await self._ack(stream, [msg_id])
        self.parked += 1
        await self._state("parked_events = parked_events + 1")

    async def _state(self, assignments: str, **params: Any) -> None:
        """Best effort update of the ``pipeline_state`` row: never raises, never blocks long."""
        try:
            async with asyncio.timeout(STATE_TIMEOUT_S), self.factory() as session:
                # ``assignments`` is a constant fragment written in this module.
                await session.execute(
                    text(
                        f"UPDATE pipeline_state SET {assignments}, updated_at = now() WHERE id = 1"  # noqa: S608
                    ),
                    params,
                )
                await session.commit()
        except Exception as exc:
            log.debug("pipeline_state not updated (%s)", type(exc).__name__)

    async def _note_failure(self, stream: str, exc: Exception) -> None:
        err = f"{_sqlstate(exc) or 'none'} {_err_name(exc)} on {stream}"[:ERROR_CHARS]
        await self._state("last_error = :e, failing_since = coalesce(failing_since, now())", e=err)

    async def _state_ok(self) -> None:
        """Stamp the heartbeat in ``pipeline_state`` (at most every 30 s, only when healthy)."""
        if self.unhealthy or time.monotonic() - self._last_state < STATE_INTERVAL_S:
            return
        self._last_state = time.monotonic()
        await self._state("last_ok_at = now(), failing_since = NULL, last_error = NULL")

    async def _process_live(self, stream: str, messages: Sequence[Message]) -> list[Any]:
        """Returns the ids acknowledged."""
        good, bad, mismatched = parse_messages(messages, stream_sensor(stream))
        if mismatched:
            self.sensor_mismatches += mismatched
            self._warn(
                "mismatch:" + stream,
                "dropped %d event(s) on %s with a forged sensor or session id (total %d)",
                mismatched,
                stream,
                self.sensor_mismatches,
            )
        done: list[Any] = []
        if good:
            try:
                await self._write([ev for _, ev in good])
            except StatementError as exc:
                if not _is_data_error(exc):
                    raise
                if len(good) == 1:
                    log.error("dropping event rejected by database: %s", _err_name(exc))
                    bad.append(good[0][0])
                else:
                    bad += await self._write_individually(stream, good, done)
            else:
                done = [i for i, _ in good]
                await self._ack(stream, done)
        await self._ack(stream, bad)
        return done + bad

    async def _write_individually(
        self, stream: str, good: list[tuple[bytes | str, Event]], done: list[Any]
    ) -> list[Any]:
        """Write events one by one. Returns ids dropped as bad data (caller ACKs them)."""
        dropped: list[Any] = []
        for msg_id, ev in good:
            try:
                await self._write([ev])
            except StatementError as exc:
                if not _is_data_error(exc):
                    raise
                log.error("dropping event rejected by database: %s", _err_name(exc))
                dropped.append(msg_id)
            else:
                await self._ack(stream, [msg_id])
                done.append(msg_id)
        return dropped

    async def _write(self, events: list[Event]) -> None:
        if self.enricher is None and self.guard is None:
            await write_batch(self.factory, events)
        else:
            await write_batch(self.factory, events, self.enricher, self.guard)

    async def _trim(self, stream: str, ids: Sequence[Any]) -> None:
        if stream in self.draining:
            return
        limit = int(time.time() * 1000) + FUTURE_ID_SLACK_MS
        usable = [i for i in ids if _id_key(i)[0] <= limit]  # never trim to a forged future id
        if not usable:
            return
        last = max(usable, key=_id_key)
        last_s = last.decode() if isinstance(last, bytes) else str(last)
        try:
            await self.redis.xtrim(stream, minid=last_s, approximate=True)
        except RedisError as exc:
            log.warning("XTRIM failed on %s (%s)", stream, type(exc).__name__)

    async def _ack(self, stream: str, ids: Sequence[Any]) -> None:
        if ids:
            await self.redis.xack(stream, self.s.group, *ids)

    async def _read(self) -> list[tuple[str, list[Message]]]:
        """One XREADGROUP over the streams not waiting out a backoff.

        Draining streams are read from "0" (their pending entries), not blocking.
        """
        now = time.monotonic()
        active = [st for st in self.s.streams if self.cooldown.get(st, 0.0) <= now]
        if not active:
            await self._sleep(min(1.0, min(self.cooldown.values()) - now))
            return []
        draining = [st for st in active if st in self.draining]
        ids: dict[Any, Any]
        if draining:
            ids = dict.fromkeys(draining, "0")
        else:
            ids = dict.fromkeys(active, ">")
        res = await self.redis.xreadgroup(
            self.s.group,
            self.s.consumer,
            ids,
            count=self.s.batch_size,
            block=None if draining else self.s.block_ms,
        )
        out: list[tuple[str, list[Message]]] = []
        # redis-py 8 types the reply as the RESP2 list shape or the RESP3 map shape. The client
        # keeps the default (legacy) response shapes, a list of [stream, messages]; accept both.
        pairs: Iterable[Any] = res.items() if isinstance(res, dict) else (res or [])
        for name, msgs in pairs:
            if msgs:
                key = name.decode() if isinstance(name, bytes) else str(name)
                out.append((key, list(msgs)))
        if draining:
            returned = {k for k, _ in out}
            self.draining -= {st for st in draining if st not in returned}
        return out

    async def run(self) -> None:
        await self.ensure_groups()
        # Single consumer: everything pending, whoever it was delivered to, is ours now.
        for stream in self.s.streams:
            await self.reclaim_stale(stream, min_idle_ms=0)
        self.heartbeat()
        self.draining = set(self.s.streams)
        last_reclaim = time.monotonic()
        backoff = 1.0
        while not self.stop.is_set():
            try:
                if (
                    not self.draining
                    and time.monotonic() - last_reclaim >= self.s.reclaim_interval_s
                ):
                    last_reclaim = time.monotonic()
                    for stream in self.s.streams:
                        if await self.reclaim_stale(stream) > 0:
                            self.draining.add(stream)
                failed = False
                for stream, messages in await self._read():
                    try:
                        await self.process(stream, messages)
                    except Exception as exc:
                        if classify_failure(exc) == "outage":
                            raise
                        self._stream_failed(stream, exc)
                        failed = True
                    else:
                        self._stream_ok(stream)
                # Heartbeat only after a read without a failing batch (and commit, with data).
                if not failed:
                    self.heartbeat()
                await self._state_ok()
                backoff = 1.0
            except (RedisError, SQLAlchemyError, OSError) as exc:
                if isinstance(exc, ResponseError) and str(exc).startswith("NOGROUP"):
                    # The broker lost its data while we ran: recreate the groups and go on.
                    try:
                        await self.ensure_groups()
                    except RedisError:
                        pass  # fall through to the backoff below
                    else:
                        log.warning("consumer group missing on the broker, recreated")
                        self.draining = set(self.s.streams)
                        continue
                log.error("batch failed (%s), retrying in %.0fs", _describe(exc), backoff)
                self.draining = set(self.s.streams)  # unacked entries stay pending: re-read
                await self._sleep(backoff)
                backoff = min(backoff * 2, MAX_STREAM_BACKOFF_S)
        log.info("consumer stopped")

    def _stream_failed(self, stream: str, exc: Exception) -> None:
        """Back this stream off alone; its unacknowledged entries are re-read from "0"."""
        delay = self.stream_backoff.get(stream, 1.0)
        log.error(
            "batch failed on %s: SQLSTATE %s: %s (this stream retries in %.0fs)",
            stream,
            _sqlstate(exc) or "none",
            _db_message(exc),
            delay,
        )
        self.cooldown[stream] = time.monotonic() + delay
        self.stream_backoff[stream] = min(delay * 2, MAX_STREAM_BACKOFF_S)
        self.draining.add(stream)
        self.unhealthy.add(stream)

    def _stream_ok(self, stream: str) -> None:
        self.cooldown.pop(stream, None)
        self.stream_backoff.pop(stream, None)
        self.unhealthy.discard(stream)

    async def _sleep(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.stop.wait(), timeout=seconds)


def _id_key(msg_id: Any) -> tuple[int, int]:
    text = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)
    ms, _, seq = text.partition("-")
    return int(ms), int(seq or 0)


def _sqlstate(exc: BaseException) -> str:
    return str(getattr(getattr(exc, "orig", None), "sqlstate", None) or "")


def _err_name(exc: BaseException) -> str:
    orig = getattr(exc, "orig", None)
    return type(orig.__cause__ or orig if orig is not None else exc).__name__


def _is_data_error(exc: StatementError) -> bool:
    """True for errors caused by the event content (not by the connection/server state)."""
    if exc.connection_invalidated if isinstance(exc, DBAPIError) else False:
        return False
    if not isinstance(exc, DBAPIError):
        return True  # StatementError: the statement could not be built/bound from this data
    return _sqlstate(exc).startswith(("22", "23"))


def _db_message(exc: BaseException) -> str:
    """The database's own error text, first 200 characters, one line.

    A statement error that is not a driver error carries bound parameters (event data) in its
    text, so only the exception class is reported for it.
    """
    if not isinstance(exc, DBAPIError) or exc.orig is None:
        return type(exc).__name__
    return " ".join(str(exc.orig).split())[:ERROR_CHARS]


def _describe(exc: BaseException) -> str:
    sqlstate = _sqlstate(exc)
    return f"{type(exc).__name__}, SQLSTATE {sqlstate}" if sqlstate else type(exc).__name__


def classify_failure(exc: BaseException) -> str:
    """Sort a failed write into ``data``, ``outage`` or ``other``.

    * ``data``: SQLSTATE class 22 (data exception) or 23 (integrity violation), or a statement
      that could not be built from the event. The event is at fault.
    * ``outage``: the connection or server is gone or restarting (invalidated connection, class
      08, 57P01 to 57P03, 53300, no SQLSTATE at all), any other SQLAlchemy error that is not a
      statement error (pool exhausted), a socket error or a Redis error. Retried forever.
    * ``other``: everything the database refused for a reason that is neither the event nor an
      outage: a statement timeout (57014), a deadlock (40P01), a serialization failure (40001), a
      missing privilege (42501), a missing table or column (42xxx), disk or memory limits
      (53xxx other than 53300), internal errors (XX...).
    """
    if isinstance(exc, RedisError | OSError):
        return "outage"
    if isinstance(exc, DBAPIError):
        state = _sqlstate(exc)
        if exc.connection_invalidated or not state:
            return "outage"
        if state.startswith(("22", "23")):
            return "data"
        if state.startswith("08") or state in OUTAGE_SQLSTATES:
            return "outage"
        return "other"
    if isinstance(exc, StatementError):
        return "data"
    return "outage" if isinstance(exc, SQLAlchemyError) else "other"


def _counts_as_attempt(exc: Exception) -> bool:
    """Only failures caused by the message itself count toward dropping that message.

    That is ``classify_failure`` returning ``data``. Outages retry forever (the heartbeat goes
    stale and the container turns unhealthy). Other refusals (a timeout, a deadlock, a missing
    privilege) are counted per stream instead, not per message, and lead to bisection.
    """
    return classify_failure(exc) == "data"
