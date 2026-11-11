"""Command emulation: canned and generated replies from a bounded per-connection fake keyspace.

Nothing here executes, evaluates or loads anything. ``EVAL`` scripts and ``MODULE LOAD`` paths
are only recorded. ``CONFIG SET`` and ``SLAVEOF`` change fields of the *connection's own*
state object (so a later ``CONFIG GET`` or ``INFO`` agrees with what the attacker did) and
nothing else: no file is written, no outbound connection is made.

:func:`execute` turns one parsed command into an :class:`Outcome`: the encoded reply, the
indicator flags for the event (``cron_write``, ``slaveof``, ...) and side information.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from redis_sensor import resp
from redis_sensor.cpu import CpuAccount
from redis_sensor.glob import MAX_PATTERN, Budget, glob_match
from redis_sensor.info import InfoView, ServerContext, parse_sections, render_info
from redis_sensor.resp import Reply

MAX_KEYS = 64
MAX_TTL_KEYS = 32  # EXPIRE / PERSIST overrides tracked per connection
MAX_KEY_BYTES = 256
MAX_VALUE_STORED = 16 * 1024
MAX_STORE_BYTES = 64 * 1024
MAX_CONFIG_VALUE = 512
MAX_REPLY = 256 * 1024
NUM_DBS = 16

CRON_PREFIXES = (
    "/var/spool/cron",
    "/etc/cron",
    "/var/spool/anacron",
    "/etc/crontab",
    "/etc/anacrontab",
)
WEB_DIR_HINTS = ("/www", "/html", "/htdocs", "/wwwroot", "/webapps")
WEB_FILE_SUFFIXES = (".php", ".jsp", ".aspx", ".asp", ".phtml")

# CONFIG parameters a client can read (name, default). Order is the order of ``CONFIG GET *``.
_CONFIG_DEFAULTS: tuple[tuple[str, str], ...] = (
    ("dir", "/data"),
    ("dbfilename", "dump.rdb"),
    ("appendonly", "no"),
    ("appendfilename", "appendonly.aof"),
    ("appenddirname", "appendonlydir"),
    ("appendfsync", "everysec"),
    ("save", "3600 1 300 100 60 10000"),
    ("requirepass", ""),
    ("masterauth", ""),
    ("masteruser", ""),
    ("bind", "* -::*"),
    ("port", "6379"),
    ("protected-mode", "no"),
    ("daemonize", "no"),
    ("databases", "16"),
    ("timeout", "0"),
    ("tcp-keepalive", "300"),
    ("maxclients", "10000"),
    ("maxmemory", "0"),
    ("maxmemory-policy", "noeviction"),
    ("loglevel", "notice"),
    ("logfile", ""),
    ("pidfile", ""),
    ("rdbcompression", "yes"),
    ("rdbchecksum", "yes"),
    ("stop-writes-on-bgsave-error", "yes"),
    ("replica-read-only", "yes"),
    ("slave-read-only", "yes"),
    ("replicaof", ""),
    ("slaveof", ""),
    ("lua-time-limit", "5000"),
    ("busy-reply-threshold", "5000"),
    ("slowlog-log-slower-than", "10000"),
    ("slowlog-max-len", "128"),
    ("hz", "10"),
    ("cluster-enabled", "no"),
    ("notify-keyspace-events", ""),
)
_CONFIG_NAMES = {name for name, _ in _CONFIG_DEFAULTS}
_IMMUTABLE = frozenset({"daemonize", "databases", "cluster-enabled", "pidfile", "appenddirname"})
_NOISY = frozenset(
    {
        "PING",
        "ECHO",
        "INFO",
        "COMMAND",
        "CLIENT",
        "SELECT",
        "GET",
        "DBSIZE",
        "TYPE",
        "TTL",
        "PTTL",
        "EXISTS",
        "HELLO",
        "TIME",
        "ROLE",
        "KEYS",
        "SCAN",
        "LASTSAVE",
        "STRLEN",
        "MGET",
        "RANDOMKEY",
    }
)


@dataclass
class Outcome:
    reply: bytes
    flags: set[str] = field(default_factory=set)
    # A large reply produced piece by piece (so it is never built whole): the session writes
    # the pieces with back-pressure. ``reply`` then only holds a short preview.
    parts: Iterator[bytes] | None = None
    close: bool = False
    # What the attacker supplied, for the event: set by the commands that carry such data.
    login: tuple[str, str | None, bool] | None = None  # username, password, success
    master: tuple[str, int] | None = None  # SLAVEOF target
    module_path: str | None = None
    script: str | None = None


def _text(raw: bytes, limit: int = 4096) -> str:
    return raw[:limit].decode("utf-8", "replace")


class ClientState:
    """Everything one connection can change. Dies with the connection."""

    def __init__(
        self, ctx: ServerContext, client_id: int, addr: str, cpu: CpuAccount | None = None
    ) -> None:
        self.ctx = ctx
        self.cpu = cpu or CpuAccount()
        self.kinds: dict[tuple[int, bytes], tuple[str, int]] = {}
        self.config_log: list[tuple[str, str]] = []
        self.lib_name = b""
        self.lib_ver = b""
        self.client_id = client_id
        self.addr = addr
        self.proto = 2
        self.name = b""
        self.db = 0
        self.dbs: list[dict[bytes, bytes]] = [{} for _ in range(NUM_DBS)]
        self.dbs[0] = dict(ctx.profile.keys)
        self.stored = sum(len(k) + len(v) for k, v in self.dbs[0].items())
        self.config: dict[str, str] = dict(_CONFIG_DEFAULTS)
        self.config["dir"] = ctx.profile.workdir
        self.config["pidfile"] = ctx.profile.pidfile
        # Expiring keys of db 0: key -> (lifetime, phase offset) in seconds, read against the
        # process-wide clock so every connection sees the same, steadily decreasing value.
        self.ttls: dict[bytes, tuple[int, int]] = {k: (t, o) for k, t, o in ctx.profile.ttls}
        # This connection's EXPIRE / PERSIST: key -> deadline on that clock, None = persistent.
        self.ttl_over: dict[bytes, float | None] = {}
        self.master: tuple[str, int] | None = None
        self.dirty = 0
        self.last_save: int | None = None
        self.multi = False
        self.queued = 0
        self.commands = 0
        self.created = time.monotonic()
        self.last_cmd = ""

    @property
    def reply(self) -> Reply:
        return Reply(self.proto)

    def keyspace(self) -> dict[bytes, bytes]:
        self._reap_due()
        return self.dbs[self.db]

    def total_keys(self) -> int:
        self._reap_due()
        return sum(len(d) for d in self.dbs)

    def _reap_due(self) -> None:
        """Remove keys whose EXPIRE deadline passed. Every read path goes through here, so GET,
        EXISTS, TYPE, KEYS, SCAN, DBSIZE and TTL all agree that a lapsed key is gone."""
        if not self.ttl_over:
            return
        now = self.ctx.elapsed()
        for key in [k for k, d in self.ttl_over.items() if d is not None and d <= now]:
            del self.ttl_over[key]
            old = self.dbs[0].pop(key, None)
            self.kinds.pop((0, key), None)
            if old is not None:
                self.stored -= len(key) + len(old)

    def store(self, key: bytes, value: bytes) -> None:
        """Bounded write: keys and bytes are capped, anything beyond is silently not kept."""
        space = self.keyspace()
        old = space.get(key)
        if len(key) > MAX_KEY_BYTES:
            return
        if old is None and self.total_keys() >= MAX_KEYS:
            return
        value = value[:MAX_VALUE_STORED]
        grow = len(value) - (len(old) if old is not None else -len(key))
        if grow > 0 and self.stored + grow > MAX_STORE_BYTES:
            return
        space[key] = value
        self.kinds.pop((self.db, key), None)
        if self.db == 0:
            self.ttls.pop(key, None)  # a plain SET clears the expiry, as in Redis
            self.ttl_over.pop(key, None)
        self.stored += grow
        self.dirty += 1

    def drop(self, key: bytes) -> bool:
        old = self.keyspace().pop(key, None)
        self.kinds.pop((self.db, key), None)
        if self.db == 0:
            self.ttls.pop(key, None)
            self.ttl_over.pop(key, None)
        if old is None:
            return False
        self.stored -= len(key) + len(old)
        self.dirty += 1
        return True

    def flush(self, everything: bool) -> None:
        targets = range(NUM_DBS) if everything else (self.db,)
        for i in targets:
            self.stored -= sum(len(k) + len(v) for k, v in self.dbs[i].items())
            self.dbs[i] = {}
        self.kinds = {k: v for k, v in self.kinds.items() if k[0] not in targets}
        if 0 in targets:
            self.ttls.clear()
            self.ttl_over.clear()
        self.dirty += 1

    def remaining_ttl(self, key: bytes) -> float | None:
        """Seconds left on a key of db 0, None when it has no expiry.

        Profile keys follow ``life - (elapsed + offset) % life`` on the shared clock: they run
        down together and are renewed when they run out, as an application re-setting them
        would, so the value is never zero or negative."""
        self._reap_due()
        if self.db != 0 or key not in self.dbs[0]:
            return None
        if key in self.ttl_over:
            deadline = self.ttl_over[key]
            return None if deadline is None else max(0.001, deadline - self.ctx.elapsed())
        entry = self.ttls.get(key)
        if entry is None:
            return None
        life, offset = entry
        return life - (self.ctx.elapsed() + offset) % life

    def reap(self, key: bytes) -> None:
        """Kept for callers that name the key; every keyspace read reaps already."""
        self._reap_due()

    def set_expiry(self, key: bytes, seconds: float | None) -> bool:
        """EXPIRE / PERSIST bookkeeping (bounded). False when the key has nothing to change."""
        self._reap_due()
        if self.db != 0 or key not in self.dbs[0]:
            return False
        if seconds is None:
            if self.remaining_ttl(key) is None:
                return False
            self.ttl_over[key] = None
        else:
            self.ttl_over.pop(key, None)  # re-inserted last: the dict order is the age order
            while len(self.ttl_over) >= MAX_TTL_KEYS:
                del self.ttl_over[next(iter(self.ttl_over))]  # forget the oldest override
            self.ttl_over[key] = self.ctx.elapsed() + seconds
        return True

    def kind(self, key: bytes) -> str | None:
        """Type of an existing key: ``string`` or a collection kind; None when missing."""
        if key not in self.keyspace():
            return None
        entry = self.kinds.get((self.db, key))
        return entry[0] if entry else "string"

    def grow_collection(self, key: bytes, kind: str, by: int) -> int | None:
        """Create or extend a list/set/hash/zset (only its size is modelled).

        Returns the new size, or None if the key holds another type (or the keyspace is full)."""
        current = self.kind(key)
        if current not in (None, kind):
            return None
        if current is None:
            if len(key) > MAX_KEY_BYTES or self.total_keys() >= MAX_KEYS:
                return by
            self.keyspace()[key] = b""
            self.stored += len(key)
        size = self.kinds.get((self.db, key), (kind, 0))[1] + by
        self.kinds[(self.db, key)] = (kind, size)
        self.dirty += 1
        return size

    def info_view(self) -> InfoView:
        self._reap_due()
        try:
            maxmem = int(self.config["maxmemory"])
        except ValueError:
            maxmem = 0
        left = (self.remaining_ttl(k) for k in {*self.ttls, *self.ttl_over})
        live = [v for v in left if v is not None]
        return InfoView(
            client_id=self.client_id,
            keys=len(self.dbs[0]),
            dirty=self.dirty,
            last_save=self.last_save,
            role_master=self.master,
            appendonly=self.config["appendonly"] == "yes",
            maxmemory=maxmem,
            requirepass=bool(self.config["requirepass"]),
            expires=len(live),
            avg_ttl_ms=int(sum(live) * 1000 / len(live)) if live else 0,
        )


def persistence_flags(state: ClientState) -> set[str]:
    """Flags for the (dir, dbfilename) pair as currently configured on this connection."""
    directory = state.config["dir"].lower()
    filename = state.config["dbfilename"]
    flags: set[str] = set()
    if directory.startswith(CRON_PREFIXES) or filename == "root":
        flags.add("cron_write")
    if directory.rstrip("/").endswith(".ssh") and filename == "authorized_keys":
        flags.add("ssh_key_write")
    if filename.lower().endswith(WEB_FILE_SUFFIXES) and any(h in directory for h in WEB_DIR_HINTS):
        flags.add("webshell_write")
    return flags


# --- helpers ---------------------------------------------------------------------------------


def _wrong_args(name: str) -> bytes:
    return resp.error(f"ERR wrong number of arguments for '{name.lower()}' command")


def _syntax() -> bytes:
    return resp.error("ERR syntax error")


def _not_int() -> bytes:
    return resp.error("ERR value is not an integer or out of range")


def _unknown(raw_name: bytes, args: list[bytes]) -> bytes:
    shown = _text(raw_name, 128)
    parts: list[str] = []
    size = 0
    for a in args[1:]:
        piece = "'%s' " % _text(a, 128)
        size += len(piece)
        if size > 128:
            break
        parts.append(piece)
    return resp.error(f"ERR unknown command '{shown}', with args beginning with: {''.join(parts)}")


def _unknown_sub(cmd: str, sub: bytes, args: list[bytes]) -> bytes:
    return resp.error(f"ERR unknown subcommand '{_text(sub, 128)}'. Try {cmd.upper()} HELP.")


def _parse_int(raw: bytes) -> int | None:
    body = raw[1:] if raw[:1] in (b"-", b"+") else raw
    if not body or len(body) > 18 or not body.isdigit():
        return None
    return int(raw)


def _scan_match(state: ClientState, pattern: bytes) -> list[bytes]:
    budget = Budget(state.cpu.headroom())
    out: list[bytes] = []
    for key in list(state.keyspace()):
        if pattern == b"*":
            out.append(key)
        elif glob_match(pattern, key, budget):
            out.append(key)
        if budget.exhausted:
            break
    state.cpu.charge(budget.used)
    return out


# --- handlers --------------------------------------------------------------------------------

Handler = Callable[[ClientState, list[bytes]], Outcome]


CHUNK = 16 * 1024


def _bulk_reply(value: bytes) -> Outcome:
    """A bulk reply; one that is large is streamed from ``value`` instead of being copied."""
    if len(value) <= CHUNK:
        return Outcome(resp.bulk(value))
    return Outcome(resp.bulk(value[:64]), parts=_bulk_parts(value))


def _bulk_parts(value: bytes) -> Iterator[bytes]:
    yield b"$%d\r\n" % len(value)
    view = memoryview(value)
    for i in range(0, len(value), CHUNK):
        yield bytes(view[i : i + CHUNK])
    yield b"\r\n"


def _ping(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) > 2:
        return Outcome(_wrong_args("ping"))
    return _bulk_reply(a[1]) if len(a) == 2 else Outcome(resp.simple("PONG"))


def _echo(state: ClientState, a: list[bytes]) -> Outcome:
    return _bulk_reply(a[1]) if len(a) == 2 else Outcome(_wrong_args("echo"))


def _info(state: ClientState, a: list[bytes]) -> Outcome:
    sections = parse_sections([_text(x, 32) for x in a[1:]])
    return Outcome(resp.bulk(render_info(state.ctx, state.info_view(), sections).encode()))


def _config(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 2:
        return Outcome(_wrong_args("config"))
    sub = a[1].upper()
    if sub == b"GET":
        return _config_get(state, a)
    if sub == b"SET":
        return _config_set(state, a)
    if sub in (b"RESETSTAT", b"REWRITE"):
        if len(a) != 2:
            return Outcome(_wrong_args("config|" + sub.decode().lower()))
        if sub == b"REWRITE":
            return Outcome(resp.error("ERR The server is running without a config file"))
        return Outcome(resp.simple("OK"))
    return Outcome(_unknown_sub("config", a[1], a[2:]))


def _config_get(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 3:
        return Outcome(_wrong_args("config|get"))
    budget = Budget(state.cpu.headroom())
    seen: set[str] = set()
    pairs: list[tuple[bytes, bytes]] = []
    for pattern in a[2:34]:
        low = pattern.lower()
        for name, _ in _CONFIG_DEFAULTS:
            if budget.exhausted:
                break
            if name in seen or len(low) > MAX_PATTERN:
                continue
            if low == b"*" or glob_match(low, name.encode(), budget):
                seen.add(name)
                pairs.append((resp.bulk(name.encode()), resp.bulk(state.config[name].encode())))
    state.cpu.charge(budget.used)
    return Outcome(state.reply.mapping(pairs))


def _config_set(state: ClientState, a: list[bytes]) -> Outcome:
    pairs = a[2:]
    if len(pairs) < 2 or len(pairs) % 2:
        return Outcome(_wrong_args("config|set"))
    flags: set[str] = {"config_set"}
    pending: dict[str, str] = {}
    for i in range(0, len(pairs), 2):
        name = _text(pairs[i], 128).lower()
        value = _text(pairs[i + 1], MAX_CONFIG_VALUE)
        if name not in _CONFIG_NAMES:
            return Outcome(
                resp.error(
                    f"ERR Unknown option or number of arguments for CONFIG SET - '{_text(pairs[i], 128)}'"
                ),
                flags,
            )
        if name in _IMMUTABLE:
            return Outcome(
                resp.error(
                    f"ERR CONFIG SET failed (possibly related to argument '{name}') - can't set immutable config"
                ),
                flags,
            )
        if name == "dbfilename" and ("/" in value or "\\" in value or not value):
            return Outcome(
                resp.error(
                    "ERR CONFIG SET failed (possibly related to argument 'dbfilename') - "
                    "dbfilename can't be a path, just a filename"
                ),
                flags,
            )
        if name == "appendonly" and value.lower() not in ("yes", "no"):
            return Outcome(
                resp.error(
                    "ERR CONFIG SET failed (possibly related to argument 'appendonly') - argument must be 'yes' or 'no'"
                ),
                flags,
            )
        if name == "dir" and not value.startswith("/"):
            value = state.ctx.profile.workdir + "/" + value  # relative chdir from the workdir
        pending[name] = value
    for name, value in pending.items():
        state.config[name] = value.lower() if name == "appendonly" else value
        if len(state.config_log) < 10:
            state.config_log.append((name, value[:128]))
        if name == "dir":
            flags.add("config_set_dir")
        elif name == "dbfilename":
            flags.add("config_set_dbfilename")
        elif name == "requirepass":
            flags.add("requirepass_set")
        elif name in ("replicaof", "slaveof"):
            flags.add("slaveof")
        elif name == "appendonly" and value.lower() == "yes":
            flags.add("aof_enabled")
    if "dir" in pending or "dbfilename" in pending:
        flags |= persistence_flags(state)
    return Outcome(resp.simple("OK"), flags)


def _set(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 3:
        return Outcome(_wrong_args("set"))
    nx = xx = get = False
    i = 3
    while i < len(a):
        opt = a[i].upper()
        if opt == b"NX":
            nx = True
        elif opt == b"XX":
            xx = True
        elif opt == b"GET":
            get = True
        elif opt in (b"EX", b"PX", b"EXAT", b"PXAT"):
            if i + 1 >= len(a):
                return Outcome(_syntax())
            if _parse_int(a[i + 1]) is None:
                return Outcome(_not_int())
            i += 1
        elif opt != b"KEEPTTL":
            return Outcome(_syntax())
        i += 1
    if nx and xx:
        return Outcome(_syntax())
    exists = a[1] in state.keyspace()
    previous = state.keyspace().get(a[1])
    if (nx and exists) or (xx and not exists):
        return Outcome(state.reply.null() if not get else _bulk_or_null(state, previous))
    state.store(a[1], a[2])
    return Outcome(_bulk_or_null(state, previous) if get else resp.simple("OK"))


def _bulk_or_null(state: ClientState, value: bytes | None) -> bytes:
    return state.reply.null() if value is None else resp.bulk(value)


WRONGTYPE = "WRONGTYPE Operation against a key holding the wrong kind of value"


def _typed(state: ClientState, key: bytes) -> Outcome | None:
    return Outcome(resp.error(WRONGTYPE)) if state.kind(key) not in (None, "string") else None


def _get(state: ClientState, a: list[bytes]) -> Outcome:
    if (bad := _typed(state, a[1])) is not None:
        return bad
    return Outcome(_bulk_or_null(state, state.keyspace().get(a[1])))


def _setnx(state: ClientState, a: list[bytes]) -> Outcome:
    if a[1] in state.keyspace():
        return Outcome(resp.integer(0))
    state.store(a[1], a[2])
    return Outcome(resp.integer(1))


def _setex(state: ClientState, a: list[bytes]) -> Outcome:
    if _parse_int(a[2]) is None:
        return Outcome(_not_int())
    state.store(a[1], a[3])
    return Outcome(resp.simple("OK"))


def _append(state: ClientState, a: list[bytes]) -> Outcome:
    if (bad := _typed(state, a[1])) is not None:
        return bad
    new = state.keyspace().get(a[1], b"") + a[2]
    state.store(a[1], new)
    return Outcome(resp.integer(len(new)))


def _strlen(state: ClientState, a: list[bytes]) -> Outcome:
    if (bad := _typed(state, a[1])) is not None:
        return bad
    return Outcome(resp.integer(len(state.keyspace().get(a[1], b""))))


def _incr_by(delta: int) -> Handler:
    def handler(state: ClientState, a: list[bytes]) -> Outcome:
        if (bad := _typed(state, a[1])) is not None:
            return bad
        step = delta
        if len(a) == 3:
            parsed = _parse_int(a[2])
            if parsed is None:
                return Outcome(_not_int())
            step = parsed if delta > 0 else -parsed
        current = state.keyspace().get(a[1], b"0")
        value = _parse_int(current)
        if value is None:
            return Outcome(_not_int())
        value += step
        state.store(a[1], str(value).encode())
        return Outcome(resp.integer(value))

    return handler


def _del(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.integer(sum(state.drop(k) for k in a[1:65])))


def _exists(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.integer(sum(k in state.keyspace() for k in a[1:65])))


def _mget(state: ClientState, a: list[bytes]) -> Outcome:
    keys = a[1:65]
    first = _bulk_or_null(state, state.keyspace().get(keys[0])) if keys else b""
    return Outcome(first[:64], parts=_mget_parts(state, keys))


def _mget_parts(state: ClientState, keys: list[bytes]) -> Iterator[bytes]:
    yield b"*%d\r\n" % len(keys)
    space = state.keyspace()
    for k in keys:
        value = space.get(k) if state.kind(k) == "string" else None
        yield _bulk_or_null(state, value)


def _mset(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 3 or len(a) % 2 == 0:
        return Outcome(_wrong_args("mset"))
    for i in range(1, min(len(a), 129), 2):
        state.store(a[i], a[i + 1])
    return Outcome(resp.simple("OK"))


def _type(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.simple(state.kind(a[1]) or "none"))


def _ttl(state: ClientState, a: list[bytes]) -> Outcome:
    state.reap(a[1])
    if a[1] not in state.keyspace():
        return Outcome(resp.integer(-2))
    left = state.remaining_ttl(a[1])
    if left is None:
        return Outcome(resp.integer(-1))
    millis = a[0].upper() == b"PTTL"
    return Outcome(resp.integer(int(left * 1000) if millis else max(1, round(left))))


def _expire(state: ClientState, a: list[bytes]) -> Outcome:
    n = _parse_int(a[2])
    if n is None:
        return Outcome(_not_int())
    state.reap(a[1])
    if n <= 0:  # a non-positive lifetime deletes the key at once
        return Outcome(resp.integer(1 if state.drop(a[1]) else 0))
    seconds = n / 1000 if a[0].upper() == b"PEXPIRE" else float(n)
    return Outcome(resp.integer(1 if state.set_expiry(a[1], seconds) else 0))


def _persist(state: ClientState, a: list[bytes]) -> Outcome:
    state.reap(a[1])
    return Outcome(resp.integer(1 if state.set_expiry(a[1], None) else 0))


def _keys(state: ClientState, a: list[bytes]) -> Outcome:
    keys = _scan_match(state, a[1])
    return Outcome(resp.array([resp.bulk(k) for k in keys]))


def _scan(state: ClientState, a: list[bytes]) -> Outcome:
    cursor = _parse_int(a[1])
    if cursor is None or cursor < 0:
        return Outcome(resp.error("ERR invalid cursor"))
    pattern = b"*"
    i = 2
    while i < len(a):
        opt = a[i].upper()
        if opt in (b"MATCH", b"COUNT", b"TYPE") and i + 1 < len(a):
            if opt == b"MATCH":
                pattern = a[i + 1]
            elif opt == b"COUNT" and (_parse_int(a[i + 1]) or 0) < 1:
                return Outcome(_syntax() if _parse_int(a[i + 1]) is not None else _not_int())
            i += 2
        else:
            return Outcome(_syntax())
    keys = _scan_match(state, pattern) if cursor == 0 else []
    return Outcome(resp.array([resp.bulk(b"0"), resp.array([resp.bulk(k) for k in keys])]))


def _flushall(state: ClientState, a: list[bytes]) -> Outcome:
    for extra in a[1:]:
        if extra.upper() not in (b"ASYNC", b"SYNC"):
            return Outcome(_syntax())
    state.flush(True)
    return Outcome(resp.simple("OK"), {"flushall"})


def _flushdb(state: ClientState, a: list[bytes]) -> Outcome:
    for extra in a[1:]:
        if extra.upper() not in (b"ASYNC", b"SYNC"):
            return Outcome(_syntax())
    state.flush(False)
    return Outcome(resp.simple("OK"), {"flushdb"})


def _dbsize(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.integer(len(state.keyspace())))


def _save(state: ClientState, a: list[bytes]) -> Outcome:
    flags = {"save"} | persistence_flags(state)
    state.last_save = int(time.time())
    state.dirty = 0
    return Outcome(resp.simple("OK"), flags)


def _bgsave(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) > 2 or (len(a) == 2 and a[1].upper() != b"SCHEDULE"):
        return Outcome(_syntax())
    flags = {"save"} | persistence_flags(state)
    state.last_save = int(time.time())
    state.dirty = 0
    return Outcome(resp.simple("Background saving started"), flags)


def _bgrewriteaof(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.simple("Background append only file rewriting started"), {"aof_rewrite"})


def _lastsave(state: ClientState, a: list[bytes]) -> Outcome:
    when = state.last_save
    if when is None:
        when = int(time.time()) - state.ctx.profile.saved_ago - state.ctx.uptime() % 3600
    return Outcome(resp.integer(when))


def _slaveof(state: ClientState, a: list[bytes]) -> Outcome:
    name = a[0].lower().decode("ascii", "replace")
    if len(a) != 3:
        return Outcome(_wrong_args(name))
    host = _text(a[1], 255)
    if host.lower() == "no" and a[2].lower() == b"one":
        state.master = None
        return Outcome(resp.simple("OK"), {"slaveof"})
    port = _parse_int(a[2])
    if port is None or not 0 <= port <= 65535:
        return Outcome(resp.error("ERR Invalid master port"), {"slaveof"})
    state.master = (host, port)
    # The target is recorded, never contacted. The reply is the one a real server gives.
    return Outcome(resp.simple("OK"), {"slaveof"}, master=(host, port))


def _module(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 2:
        return Outcome(_wrong_args("module"))
    sub = a[1].upper()
    if sub in (b"LOAD", b"LOADEX"):
        if len(a) < 3:
            return Outcome(_wrong_args("module|" + sub.decode().lower()))
        path = _text(a[2], 1024)
        return Outcome(
            resp.error("ERR Error loading the extension. Please check the server logs."),
            {"module_load"},
            module_path=path,
        )
    if sub == b"UNLOAD":
        if len(a) != 3:
            return Outcome(_wrong_args("module|unload"))
        return Outcome(resp.error("ERR Error unloading module: no such module with that name"))
    if sub == b"LIST":
        return Outcome(resp.array([]))
    return Outcome(_unknown_sub("module", a[1], a[2:]))


def _client(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 2:
        return Outcome(_wrong_args("client"))
    sub = a[1].upper()
    if sub == b"SETNAME":
        if len(a) != 3:
            return Outcome(_wrong_args("client|setname"))
        state.name = a[2][:64]
        return Outcome(resp.simple("OK"))
    if sub == b"GETNAME":
        return Outcome(_bulk_or_null(state, state.name or None))
    if sub == b"ID":
        return Outcome(resp.integer(state.client_id))
    if sub in (b"LIST", b"INFO"):
        age = int(time.monotonic() - state.created)
        line = (
            f"id={state.client_id} addr={state.addr} laddr={state.ctx.profile.local_ip}:{state.ctx.port} "
            f"fd=8 name={_text(state.name, 64)} age={age} idle=0 flags=N db={state.db} sub=0 psub=0 "
            f"ssub=0 multi=-1 qbuf=26 qbuf-free=20448 argv-mem=10 multi-mem=0 rbs=16384 rbp=0 obl=0 "
            f"oll=0 omem=0 tot-mem=22298 events=r cmd=client|{sub.decode().lower()} user=default "
            f"redir=-1 resp={state.proto} lib-name={_text(state.lib_name, 64)} "
            f"lib-ver={_text(state.lib_ver, 64)}\n"
        )
        return Outcome(resp.bulk(line.encode()))
    if sub == b"SETINFO" and len(a) == 4:
        if a[2].upper() == b"LIB-NAME":
            state.lib_name = a[3][:64]
        elif a[2].upper() == b"LIB-VER":
            state.lib_ver = a[3][:64]
        else:
            return Outcome(resp.error(f"ERR Unrecognized option '{_text(a[2], 64)}'"))
        return Outcome(resp.simple("OK"))
    if sub in (b"SETINFO", b"NO-EVICT", b"NO-TOUCH", b"REPLY", b"TRACKING", b"CACHING"):
        return Outcome(resp.simple("OK"))
    if sub == b"KILL":
        return Outcome(resp.error("ERR No such client") if len(a) > 2 else _syntax())
    if sub == b"UNBLOCK":
        return Outcome(resp.integer(0))
    return Outcome(_unknown_sub("client", a[1], a[2:]))


def _command(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) == 1:
        return Outcome(resp.array([]))
    sub = a[1].upper()
    if sub == b"COUNT":
        return Outcome(resp.integer(241))
    if sub in (b"DOCS", b"INFO", b"LIST", b"GETKEYS", b"GETKEYSANDFLAGS"):
        return Outcome(resp.array([]))
    return Outcome(_unknown_sub("command", a[1], a[2:]))


def _select(state: ClientState, a: list[bytes]) -> Outcome:
    index = _parse_int(a[1])
    if index is None:
        return Outcome(resp.error("ERR invalid DB index"))
    if not 0 <= index < NUM_DBS:
        return Outcome(resp.error("ERR DB index is out of range"))
    state.db = index
    return Outcome(resp.simple("OK"))


def _auth(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) > 3:
        return Outcome(_syntax())
    password = _text(a[-1], 256)
    username = _text(a[1], 128) if len(a) == 3 else "default"
    required = state.config["requirepass"]
    if required:
        ok = username == "default" and password == required
        reply = (
            resp.simple("OK")
            if ok
            else resp.error("WRONGPASS invalid username-password pair or user is disabled.")
        )
        return Outcome(reply, {"auth"}, login=(username, password, ok))
    if len(a) == 2:
        reply = resp.error(
            "ERR AUTH <password> called without any password configured for the default user. "
            "Are you sure your configuration is correct?"
        )
        return Outcome(reply, {"auth"}, login=(username, password, False))
    if username == "default":  # a user without a password accepts any password
        return Outcome(resp.simple("OK"), {"auth"}, login=(username, password, True))
    return Outcome(
        resp.error("WRONGPASS invalid username-password pair or user is disabled."),
        {"auth"},
        login=(username, password, False),
    )


def _hello(state: ClientState, a: list[bytes]) -> Outcome:
    login: tuple[str, str | None, bool] | None = None
    version = state.proto
    i = 1
    if len(a) > 1:
        parsed = _parse_int(a[1])
        if parsed is None:
            return Outcome(resp.error("ERR Protocol version is not an integer or out of range"))
        if parsed not in (2, 3):
            return Outcome(resp.error("NOPROTO unsupported protocol version"))
        version = parsed
        i = 2
    while i < len(a):
        opt = a[i].upper()
        if opt == b"AUTH" and i + 2 < len(a):
            user, pw = _text(a[i + 1], 128), _text(a[i + 2], 256)
            ok = user == "default" and (
                not state.config["requirepass"] or pw == state.config["requirepass"]
            )
            if not ok:
                return Outcome(
                    resp.error("WRONGPASS invalid username-password pair or user is disabled."),
                    {"auth"},
                    login=(user, pw, False),
                )
            login = (user, pw, True)
            i += 3
        elif opt == b"SETNAME" and i + 1 < len(a):
            state.name = a[i + 1][:64]
            i += 2
        else:
            return Outcome(resp.error(f"ERR Syntax error in HELLO option '{_text(a[i], 64)}'"))
    state.proto = version
    p = state.ctx.profile
    pairs = [
        (resp.bulk(b"server"), resp.bulk(b"redis")),
        (resp.bulk(b"version"), resp.bulk(p.version.encode())),
        (resp.bulk(b"proto"), resp.integer(version)),
        (resp.bulk(b"id"), resp.integer(state.client_id)),
        (resp.bulk(b"mode"), resp.bulk(b"standalone")),
        (resp.bulk(b"role"), resp.bulk(b"master" if state.master is None else b"replica")),
        (resp.bulk(b"modules"), resp.array([])),
    ]
    return Outcome(state.reply.mapping(pairs), {"auth"} if login else set(), login=login)


def _quit(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.simple("OK"), close=True)


def _reset(state: ClientState, a: list[bytes]) -> Outcome:
    state.proto, state.db, state.name, state.multi = 2, 0, b"", False
    return Outcome(resp.simple("RESET"))


_SANDBOX_NAMES = ("package", "loadlib", "require", "dofile", "loadfile", "io.", "os.", "debug.")


def _eval(state: ClientState, a: list[bytes]) -> Outcome:
    """Record the script; never run it. Plausible replies only."""
    name = a[0].lower().decode("ascii", "replace")
    if len(a) < 3:
        return Outcome(_wrong_args(name))
    numkeys = _parse_int(a[2])
    if numkeys is None:
        return Outcome(_not_int())
    if numkeys < 0:
        return Outcome(resp.error("ERR Number of keys can't be negative"))
    if numkeys > len(a) - 3:
        return Outcome(resp.error("ERR Number of keys can't be greater than number of args"))
    script = _text(a[1], 8192)
    flags = {"eval"}
    low = script.lower()
    if name == "evalsha" or name == "evalsha_ro":
        flags = {"eval", "evalsha"}
        return Outcome(
            resp.error("NOSCRIPT No matching script. Please use EVAL."), flags, script=script
        )
    for needle in _SANDBOX_NAMES:
        at = low.find(needle)
        if at >= 0:
            flags.add("lua_sandbox_escape")  # CVE-2022-0543 style probes
            var = needle.rstrip(".")
            return Outcome(
                resp.error(
                    f"ERR user_script:1: Script attempted to access nonexistent global variable '{var}' "
                    f"script: {hashlib.sha1(a[1][:8192], usedforsecurity=False).hexdigest()}, on @user_script:1."
                ),
                flags,
                script=script,
            )
    stripped = low.strip().removeprefix("return").strip().rstrip(";")
    if low.strip().startswith("return") and stripped.isdigit() and len(stripped) < 18:
        return Outcome(resp.integer(int(stripped)), flags, script=script)
    return Outcome(state.reply.null(), flags, script=script)


def _script(state: ClientState, a: list[bytes]) -> Outcome:
    if len(a) < 2:
        return Outcome(_wrong_args("script"))
    sub = a[1].upper()
    if sub == b"FLUSH":
        return Outcome(resp.simple("OK"))
    if sub == b"LOAD" and len(a) == 3:
        return Outcome(
            resp.bulk(hashlib.sha1(a[2][:8192], usedforsecurity=False).hexdigest().encode()),
            {"eval"},
            script=_text(a[2], 8192),
        )
    if sub == b"EXISTS":
        return Outcome(resp.array([resp.integer(0) for _ in a[2:65]]))
    return Outcome(_unknown_sub("script", a[1], a[2:]))


def _time(state: ClientState, a: list[bytes]) -> Outcome:
    now = time.time()
    return Outcome(
        resp.array([resp.bulk(b"%d" % int(now)), resp.bulk(b"%d" % int((now % 1) * 1_000_000))])
    )


def _role(state: ClientState, a: list[bytes]) -> Outcome:
    if state.master is None:
        return Outcome(resp.array([resp.bulk(b"master"), resp.integer(0), resp.array([])]))
    host, port = state.master
    return Outcome(
        resp.array(
            [
                resp.bulk(b"slave"),
                resp.bulk(host.encode()),
                resp.integer(port),
                resp.bulk(b"connect"),
                resp.integer(-1),
            ]
        )
    )


def _debug(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(
        resp.error(
            'ERR DEBUG command not allowed. If the enable-debug-command option is set to "local", you can run it from a local connection, otherwise you need to set this option in the configuration file, and then restart the server.'
        ),
        {"debug"},
    )


def _shutdown(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(b"", {"shutdown"}, close=True)


def _sync(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.error("ERR Unable to perform background save"), {"psync"})


def _monitor(state: ClientState, a: list[bytes]) -> Outcome:
    return Outcome(resp.simple("OK"))


def _multi(state: ClientState, a: list[bytes]) -> Outcome:
    if state.multi:
        return Outcome(resp.error("ERR MULTI calls can not be nested"))
    state.multi, state.queued = True, 0
    return Outcome(resp.simple("OK"))


def _exec(state: ClientState, a: list[bytes]) -> Outcome:
    if not state.multi:
        return Outcome(resp.error("ERR EXEC without MULTI"))
    state.multi = False
    return Outcome(resp.array([resp.simple("OK") for _ in range(min(state.queued, 64))]))


def _discard(state: ClientState, a: list[bytes]) -> Outcome:
    if not state.multi:
        return Outcome(resp.error("ERR DISCARD without MULTI"))
    state.multi = False
    return Outcome(resp.simple("OK"))


def _randomkey(state: ClientState, a: list[bytes]) -> Outcome:
    keys = list(state.keyspace())
    return Outcome(_bulk_or_null(state, secrets.choice(keys) if keys else None))


# name -> (arity, handler); negative arity means "at least |arity|", as in Redis.
TABLE: dict[str, tuple[int, Handler]] = {
    "PING": (-1, _ping),
    "ECHO": (2, _echo),
    "INFO": (-1, _info),
    "CONFIG": (-2, _config),
    "SET": (-3, _set),
    "GET": (2, _get),
    "SETNX": (3, _setnx),
    "SETEX": (4, _setex),
    "PSETEX": (4, _setex),
    "APPEND": (3, _append),
    "STRLEN": (2, _strlen),
    "INCR": (2, _incr_by(1)),
    "DECR": (2, _incr_by(-1)),
    "INCRBY": (3, _incr_by(1)),
    "DECRBY": (3, _incr_by(-1)),
    "DEL": (-2, _del),
    "UNLINK": (-2, _del),
    "EXISTS": (-2, _exists),
    "MGET": (-2, _mget),
    "MSET": (-3, _mset),
    "TYPE": (2, _type),
    "TTL": (2, _ttl),
    "PTTL": (2, _ttl),
    "EXPIRE": (-3, _expire),
    "PEXPIRE": (-3, _expire),
    "PERSIST": (2, _persist),
    "KEYS": (2, _keys),
    "SCAN": (-2, _scan),
    "RANDOMKEY": (1, _randomkey),
    "FLUSHALL": (-1, _flushall),
    "FLUSHDB": (-1, _flushdb),
    "DBSIZE": (1, _dbsize),
    "SAVE": (1, _save),
    "BGSAVE": (-1, _bgsave),
    "BGREWRITEAOF": (1, _bgrewriteaof),
    "LASTSAVE": (1, _lastsave),
    "SLAVEOF": (3, _slaveof),
    "REPLICAOF": (3, _slaveof),
    "MODULE": (-2, _module),
    "CLIENT": (-2, _client),
    "COMMAND": (-1, _command),
    "SELECT": (2, _select),
    "AUTH": (-2, _auth),
    "HELLO": (-1, _hello),
    "QUIT": (-1, _quit),
    "RESET": (1, _reset),
    "EVAL": (-3, _eval),
    "EVAL_RO": (-3, _eval),
    "EVALSHA": (-3, _eval),
    "EVALSHA_RO": (-3, _eval),
    "SCRIPT": (-2, _script),
    "TIME": (1, _time),
    "ROLE": (1, _role),
    "DEBUG": (-2, _debug),
    "SHUTDOWN": (-1, _shutdown),
    "SYNC": (1, _sync),
    "PSYNC": (-3, _sync),
    "MONITOR": (1, _monitor),
    "MULTI": (1, _multi),
    "EXEC": (1, _exec),
    "DISCARD": (1, _discard),
}


def is_noisy(name: str) -> bool:
    return name in _NOISY


def execute(state: ClientState, args: list[bytes]) -> tuple[str, Outcome]:
    """Run one command against the fake state. Returns (upper-case name, outcome)."""
    raw = args[0]
    name = raw[:64].decode("ascii", "replace").upper()
    state.commands += 1
    state.ctx.total_commands += 1
    entry = TABLE.get(name)
    if entry is None:
        return name, Outcome(_unknown(raw, args), {"unknown_command"})
    arity, handler = entry
    if (arity >= 0 and len(args) != arity) or (arity < 0 and len(args) < -arity):
        return name, Outcome(_wrong_args(name), set())
    if state.multi and name not in ("EXEC", "DISCARD", "MULTI", "QUIT", "RESET"):
        state.queued += 1
        return name, Outcome(resp.simple("QUEUED"))
    outcome = handler(state, args)
    if len(outcome.reply) > MAX_REPLY:  # pragma: no cover - replies are bounded by construction
        outcome.reply = resp.error("ERR reply too large")
    return name, outcome


from redis_sensor import others  # noqa: E402 - registers the remaining commands in TABLE

others.register(TABLE)
