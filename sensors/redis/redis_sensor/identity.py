"""Per-deployment fake identity, derived from a random secret kept under the data directory.

The secret is generated once (mode 0600) and everything a client can learn about the "server"
(patch version, run id, replication id, kernel build, uptime at start, memory baseline, the
handful of cached keys) is derived from it with HMAC, so two deployments never look alike and
nothing can be predicted from public data.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("redis_sensor.identity")

SECRET_FILE = "profile_secret"  # noqa: S105 - a file name, not a secret
DEFAULT_SERIES = "7.2"
PATCHES = (4, 5, 6, 7, 8, 9)
# Ubuntu 24.04 (noble) kernel builds; the gcc that a source build on that host reports follows
# the toolchain of the same point release (13.2.0 early, 13.3.0 from the 24.04.1 era on).
KERNELS = (
    "6.8.0-31-generic", "6.8.0-35-generic", "6.8.0-36-generic", "6.8.0-38-generic",
    "6.8.0-40-generic", "6.8.0-45-generic", "6.8.0-48-generic", "6.8.0-49-generic",
    "6.8.0-50-generic", "6.8.0-51-generic", "6.8.0-52-generic", "6.8.0-54-generic",
    "6.8.0-57-generic", "6.8.0-58-generic", "6.8.0-60-generic", "6.8.0-63-generic",
)  # fmt: skip
_GCC_BY_KERNEL = {k: ("13.2.0" if int(k.split("-")[1]) < 40 else "13.3.0") for k in KERNELS}
# (executable, config file, working dir, pidfile, supervised): how a package or a source
# install lays Redis out on an Ubuntu host. None of them is a container path.
_LAYOUTS = (
    ("/usr/bin/redis-server", "/etc/redis/redis.conf", "/var/lib/redis",
     "/run/redis/redis-server.pid", "systemd"),
    ("/usr/local/bin/redis-server", "/etc/redis/redis.conf", "/var/lib/redis",
     "/var/run/redis_6379.pid", "no"),
    ("/usr/local/bin/redis-server", "/etc/redis/6379.conf", "/var/lib/redis/6379",
     "/var/run/redis_6379.pid", "no"),
    ("/opt/redis/bin/redis-server", "/opt/redis/redis.conf", "/opt/redis/data",
     "/var/run/redis.pid", "no"),
)  # fmt: skip
_WORDS = (
    "home", "index", "about", "pricing", "products", "contact", "blog", "login", "faq",
    "terms", "search", "cart", "news", "support", "team", "careers", "docs", "events",
)  # fmt: skip
_SITE = (
    "Harbor", "Pine", "Northwind", "Atlas", "Summit", "Brightside", "Cobalt", "Juniper",
    "Meridian", "Lakeside", "Ironwood", "Bluebird", "Oakfield", "Redwood", "Silverline",
)  # fmt: skip
_PARTS = (
    "Welcome", "Latest updates", "Our services", "Contact us", "Opening hours", "Read more",
    "Customer stories", "Get a quote", "Help centre", "Newsletter", "Terms of use", "Careers",
)  # fmt: skip


def write_private(path: Path, data: bytes) -> None:
    """Atomically write ``data`` with mode 0600."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    tmp.replace(path)


def load_or_create_secret(directory: str | Path) -> str:
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / SECRET_FILE
    try:
        value = path.read_text().strip()
    except OSError:
        value = ""
    if len(value) < 32:
        value = secrets.token_hex(32)
        write_private(path, (value + "\n").encode())
        log.warning("generated new profile secret in %s (persist the data volume)", root)
    return value


def valid_version(text: str) -> bool:
    parts = text.split(".")
    return len(parts) in (2, 3) and all(p.isdigit() and len(p) <= 3 for p in parts)


@dataclass(frozen=True)
class Profile:
    version: str
    run_id: str
    replid: str
    build_id: str
    kernel: str
    uptime_offset: int  # seconds the "server" was up before this process started
    base_memory: int  # bytes
    rss_extra: int
    local_ip: str
    saved_ago: int  # seconds since the last "RDB save" at process start
    keys: tuple[tuple[bytes, bytes], ...]
    ttls: tuple[tuple[bytes, int], ...]  # lifetime in seconds of the keys that expire
    process_id: int
    executable: str
    config_file: str
    workdir: str
    pidfile: str
    supervised: str
    git_sha1: str
    gcc_version: str


def _digest(secret: str, label: str) -> bytes:
    return hmac.new(secret.encode(), label.encode(), hashlib.sha256).digest()


def _hex(secret: str, label: str, n: int) -> str:
    out = ""
    counter = 0
    while len(out) < n:
        out += _digest(secret, f"{label}/{counter}").hex()
        counter += 1
    return out[:n]


def _num(secret: str, label: str, low: int, high: int) -> int:
    return low + int.from_bytes(_digest(secret, label)[:8], "big") % (high - low + 1)


def _pick[T](secret: str, label: str, items: Sequence[T]) -> T:
    return items[_num(secret, label, 0, len(items) - 1)]


def _b36(secret: str, label: str, n: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw = _hex(secret, label, n * 2)
    return "".join(alphabet[int(raw[2 * i : 2 * i + 2], 16) % 36] for i in range(n))


def _page(secret: str, label: str) -> str:
    """A small cached HTML fragment, composed from word lists so no two installs match."""
    site = _pick(secret, "site", _SITE)
    bits = [_pick(secret, f"{label}/p{i}", _PARTS) for i in range(_num(secret, f"{label}/n", 2, 5))]
    items = "".join(f"<li>{b}</li>" for b in bits)
    return (
        f"<html><head><title>{site} - {bits[0]}</title></head>"
        f"<body><h1>{bits[0]}</h1><ul>{items}</ul></body></html>"
    )


def _keyspace(secret: str) -> tuple[tuple[tuple[bytes, bytes], ...], tuple[tuple[bytes, int], ...]]:
    """An application-shaped keyspace: one primary style plus a couple of side styles.

    Styles are a session store, a page cache, a job queue and a rate limiter; key names, id
    widths, value shapes, counts and TTLs all come from the secret.
    """
    styles = ["session", "cache", "queue", "rate"]
    first = _pick(secret, "style1", styles)
    plan = [(first, _num(secret, "n-first", 3, 9))]
    for i, extra in enumerate(s for s in styles if s != first):
        if _num(secret, f"side{i}", 0, 2):
            plan.append((extra, _num(secret, f"n-side{i}", 1, 4)))
    keys: list[tuple[bytes, bytes]] = []
    ttls: list[tuple[bytes, int]] = []

    def add(key: str, value: str, ttl: int = 0) -> None:
        raw = key.encode()
        if all(raw != k for k, _ in keys):
            keys.append((raw, value[:2048].encode()))
            if ttl:
                ttls.append((raw, ttl))

    for style, count in plan:
        tag = f"{style}"
        for i in range(count):
            lab = f"{tag}/{i}"
            if style == "session":
                prefix = _pick(secret, "sess-prefix", ("sess:", "session:", "sessions:", "sess_"))
                sid = _b36(secret, lab, _pick(secret, "sess-len", (24, 26, 32, 40)))
                uid = _num(secret, lab + "/uid", 1, 4999)
                shape = _num(secret, "sess-shape", 0, 2)
                if shape == 0:
                    value = '{"uid":%d,"role":"%s"}' % (uid, _pick(secret, lab, ("user", "member")))
                elif shape == 1:
                    value = "user_id|i:%d;login_time|i:%d;" % (uid, 1_760_000_000 + uid * 977)
                else:
                    value = '{"user":{"id":%d},"csrf":"%s"}' % (uid, _hex(secret, lab + "/c", 16))
                ttl = _pick(secret, "sess-ttl", (1440, 1800, 3600, 86400, 604800))
                add(prefix + sid, value, ttl)
            elif style == "cache":
                prefix = _pick(secret, "cache-prefix", ("cache:", "page:", "views:", "app_cache:"))
                page = _WORDS[_num(secret, lab, 0, len(_WORDS) - 1)]
                ttl = _pick(secret, "cache-ttl", (0, 300, 600, 3600, 21600))
                add(prefix + page, _page(secret, lab), ttl)
            elif style == "queue":
                kind = _pick(secret, "queue-kind", ("sidekiq", "resque", "bull", "jobs"))
                name = _pick(secret, lab, ("stat:processed", "stat:failed", "email:last", "id"))
                value = (
                    str(_num(secret, lab + "/v", 100, 900_000))
                    if name.startswith(("stat", "id"))
                    else "job-" + _hex(secret, lab + "/j", _num(secret, "job-len", 8, 24))
                )
                add(f"{kind}:{name}", value)
            else:
                prefix = _pick(secret, "rate-prefix", ("rate:", "throttle:", "rl:", "limit:"))
                who = _pick(secret, "rate-who", ("api", "login", "ip", "user"))
                ident = _num(secret, lab + "/id", 10, 9999)
                add(f"{prefix}{who}:{ident}", str(_num(secret, lab + "/v", 1, 120)),
                    _pick(secret, "rate-ttl", (60, 120, 900, 3600)))  # fmt: skip
    if _num(secret, "visits", 0, 1):
        add("user:%d:visits" % _num(secret, "u2", 1000, 9999), str(_num(secret, "v2", 3, 4000)))
    return tuple(keys), tuple(ttls)


def derive_profile(secret: str, version: str = "") -> Profile:
    """Build the profile. ``version`` is a series (``7.2``) or a full version (``7.2.5``)."""
    version = version.strip()
    if not valid_version(version):
        version = DEFAULT_SERIES
    if version.count(".") == 1:
        version = f"{version}.{PATCHES[_num(secret, 'patch', 0, len(PATCHES) - 1)]}"
    keys, ttls = _keyspace(secret)
    kernel = KERNELS[_num(secret, "kernel", 0, len(KERNELS) - 1)]
    executable, config_file, workdir, pidfile, supervised = _pick(secret, "layout", _LAYOUTS)
    return Profile(
        version=version,
        run_id=_hex(secret, "run", 40),
        replid=_hex(secret, "replid", 40),
        build_id=_hex(secret, "build", 16),
        kernel=kernel,
        uptime_offset=_num(secret, "uptime", 2 * 86400, 70 * 86400),
        base_memory=_num(secret, "mem", 880_000, 1_450_000),
        rss_extra=_num(secret, "rss", 7_500_000, 11_500_000),
        local_ip="10.%d.%d.%d"
        % (_num(secret, "ip1", 0, 30), _num(secret, "ip2", 0, 250), _num(secret, "ip3", 2, 250)),
        saved_ago=_num(secret, "saved", 40, 3000),
        keys=keys,
        ttls=ttls,
        process_id=_num(secret, "pid", 640, 48_000),
        executable=executable,
        config_file=config_file,
        workdir=workdir,
        pidfile=pidfile,
        supervised=supervised,
        # Release tarballs and distro packages report 00000000; a git checkout shows a sha.
        git_sha1=_hex(secret, "sha", 8) if _num(secret, "sha-kind", 0, 9) < 3 else "00000000",
        gcc_version=_GCC_BY_KERNEL[kernel],
    )


def load_profile(directory: str | Path, version: str = "") -> Profile:
    return derive_profile(load_or_create_secret(directory), version)
