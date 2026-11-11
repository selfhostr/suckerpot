"""Per-deployment fake identity.

Everything attacker-visible that should differ between two deployments (private server IP,
site title, user names, post dates, certificate dates, file modification times) is derived from
a random secret that is generated once and stored in ``<data_dir>/profile.json`` (mode 0600).
Nothing here comes from public data, and the secret itself is never shown to clients.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from web_sensor import corpus

log = logging.getLogger("web_sensor.profile")


@dataclass(frozen=True)
class WPUser:
    id: int
    login: str
    display: str
    email_hash: str


@dataclass(frozen=True)
class Post:
    id: int
    slug: str
    title: str
    ts: float  # publication time (epoch)
    body: str


@dataclass(frozen=True)
class Profile:
    secret: bytes
    created: float
    server_ip: str
    site_title: str
    tagline: str
    install_ts: float  # when WordPress "was installed": base of every static mtime
    users: tuple[WPUser, ...]
    posts: tuple[Post, ...]

    def derive(self, label: str, length: int = 16) -> str:
        """Stable per-deployment hex string for ``label``."""
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).hexdigest()
        return digest[:length]

    def rng(self, label: str) -> random.Random:
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).digest()
        return random.Random(int.from_bytes(digest[:16], "big"))  # noqa: S311 - content only


def _slug(title: str) -> str:
    out: list[str] = []
    for ch in title.lower():
        if ch.isascii() and ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-")


def build_profile(secret: bytes, created: float) -> Profile:
    base = Profile(secret, created, "", "", "", 0.0, (), ())
    rng = base.rng("layout")
    ip = f"10.{rng.randrange(0, 4)}.{rng.randrange(0, 256)}.{rng.randrange(5, 250)}"
    trade = corpus.pick_trade(rng)
    title, tagline = corpus.site_identity(rng, trade)
    install_ts = created - rng.randrange(150, 520) * 86400 - rng.randrange(0, 86400)
    first = rng.choice(corpus.first_names())
    last = rng.choice(corpus.SURNAMES)
    users = (
        WPUser(1, "admin", "admin", base.derive("email-1", 32)),
        WPUser(2, (first[0] + last).lower(), f"{first} {last}", base.derive("email-2", 32)),
    )
    prng = base.rng("posts")
    posts: list[Post] = []
    if prng.random() < 0.35:  # many owners never delete the stock first post
        posts.append(
            Post(
                1,
                "hello-world",
                "Hello world!",
                install_ts,
                "Welcome to WordPress. This is your first post. Edit or delete it, "
                "then start writing!",
            )
        )
    post_id = 1
    slugs = {p.slug for p in posts}
    wanted = prng.randrange(3, 7)
    span = max(int(created - install_ts) - 2 * 86400, 86400)
    while len(posts) < wanted:
        ts = min(install_ts + prng.randrange(3 * 86400, span), created - 86400)
        year = datetime.fromtimestamp(ts, UTC).year
        t, body = corpus.compose_post(prng, trade, year)
        slug = _slug(t)
        if slug in slugs:
            continue
        slugs.add(slug)
        post_id += prng.randrange(2, 9)
        posts.append(Post(post_id, slug, t, ts, body))
    posts.sort(key=lambda p: p.ts, reverse=True)
    return Profile(secret, created, ip, title, tagline, install_ts, users, tuple(posts))


def load_or_create_profile(data_dir: str) -> Profile:
    """Read the profile from ``data_dir`` or create it. Falls back to an ephemeral secret."""
    path = Path(data_dir) / "profile.json"
    try:
        doc = json.loads(path.read_text())
        secret = bytes.fromhex(doc["secret"])
        created = float(doc["created"])
        if len(secret) >= 16:
            return build_profile(secret, created)
    except OSError, ValueError, KeyError, TypeError:
        pass
    secret = secrets.token_bytes(32)
    created = float(int(time.time()))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"secret": secret.hex(), "created": created}))
        os.replace(tmp, path)
    except OSError:
        log.warning("cannot persist the profile in %s; identity will change on restart", data_dir)
    return build_profile(secret, created)
