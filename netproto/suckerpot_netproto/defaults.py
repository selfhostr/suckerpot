"""Committed public defaults of the SuckerPot network (design M32 section 6.5).

The values live in ``data/network_defaults.env`` (package data, so inside every signed image) and
are mirrored at ``config/network-defaults.env`` for host scripts. An explicit environment value
always wins over a default; an empty one counts as unset.

A value written ``<LIKE_THIS>`` is a placeholder: it means "not configured". The network cannot
be joined with a placeholder, and the release workflow refuses to publish one. Pure functions,
no network access.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from urllib.parse import urlsplit

from . import sign
from .feeds import minisign

DEFAULTS_FILE = "network_defaults.env"
WORDS_FILE = "pseudonym_words.txt"
KNOWN_KEYS = (
    "NETWORK_DEFAULTS_VERSION",
    "NETWORK_HUB_URL",
    "NETWORK_HUB_KEY",
    "NETWORK_FEED_URL",
    "NETWORK_FEED_KEY",
)
KEY_NAMES = ("NETWORK_HUB_KEY", "NETWORK_FEED_KEY")
SUPPORTED_VERSION = 1
RESERVED_SUFFIXES = (".local", ".lan", ".internal", ".home.arpa", ".localhost", ".test")

_PLACEHOLDER = re.compile(r"^<[A-Z][A-Z0-9_]*>$")
_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")


class DefaultsError(ValueError):
    """The defaults file is malformed. Never raised for a placeholder (that is a valid state)."""


def is_placeholder(value: str) -> bool:
    """True for ``<NAME>``-style values and for an empty value."""
    v = value.strip()
    return not v or _PLACEHOLDER.fullmatch(v) is not None or ("<" in v and ">" in v)


def _check_host(host: str) -> None:
    h = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        pass
    else:
        raise DefaultsError("a URL must name a public DNS host, not an IP address")
    if "." not in h or h.endswith(RESERVED_SUFFIXES):
        raise DefaultsError("a URL must name a public DNS host")


def check_https_url(value: str, *, allow_path: bool) -> str:
    """Normalised https URL (no trailing slash) or DefaultsError. Same rules as the hub URL."""
    url = value.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise DefaultsError("a URL must be https with a host")
    if parts.username or parts.password or parts.fragment or parts.query:
        raise DefaultsError("a URL must not hold credentials, a query or a fragment")
    if parts.path and not allow_path:
        raise DefaultsError("this URL must not have a path")
    _check_host(parts.hostname)
    return url


def check_key_list(value: str) -> tuple[str, ...]:
    """A pinned key set (1 to 3 comma-separated public keys) or DefaultsError."""
    try:
        return sign.parse_key_set(value)
    except ValueError as exc:
        raise DefaultsError(f"not a key set: {exc}") from None


def check_feed_key(value: str) -> str:
    """One minisign public key (the feed key is not a hub key set) or DefaultsError."""
    try:
        minisign.parse_public_key(value.strip())
    except ValueError as exc:
        raise DefaultsError(f"not a minisign public key: {exc}") from None
    return value.strip()


def parse(text: str) -> dict[str, str]:
    """Strict parse of a defaults file: ``KEY=value`` lines, known keys only, no duplicates."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE.fullmatch(line)
        if m is None:
            raise DefaultsError("malformed line")
        name, value = m.group(1), m.group(2).strip()
        if name not in KNOWN_KEYS:
            raise DefaultsError(f"unknown key {name}")
        if name in out:
            raise DefaultsError(f"duplicate key {name}")
        out[name] = value
    missing = [k for k in KNOWN_KEYS if k not in out]
    if missing:
        raise DefaultsError(f"missing key {missing[0]}")
    return out


@dataclass(frozen=True, slots=True)
class Defaults:
    version: int
    hub_url: str
    hub_key: str
    feed_url: str
    feed_key: str

    def placeholders(self) -> tuple[str, ...]:
        """Names of the settings that still hold a placeholder (empty tuple when releasable)."""
        values = {
            "NETWORK_HUB_URL": self.hub_url,
            "NETWORK_HUB_KEY": self.hub_key,
            "NETWORK_FEED_URL": self.feed_url,
            "NETWORK_FEED_KEY": self.feed_key,
        }
        return tuple(k for k, v in values.items() if is_placeholder(v))

    @property
    def hub_configured(self) -> bool:
        return "NETWORK_HUB_URL" not in self.placeholders() and (
            "NETWORK_HUB_KEY" not in self.placeholders()
        )

    @property
    def feed_configured(self) -> bool:
        ph = self.placeholders()
        return "NETWORK_FEED_URL" not in ph and "NETWORK_FEED_KEY" not in ph

    @property
    def hub_keys(self) -> tuple[str, ...]:
        """The pinned hub key set. Empty while the key is a placeholder."""
        return () if is_placeholder(self.hub_key) else check_key_list(self.hub_key)

    @property
    def feed_keys(self) -> tuple[str, ...]:
        return () if is_placeholder(self.feed_key) else (check_feed_key(self.feed_key),)


def from_text(text: str) -> Defaults:
    """Validate a defaults file. Placeholders are accepted; anything else must be well formed."""
    data = parse(text)
    try:
        version = int(data["NETWORK_DEFAULTS_VERSION"])
    except ValueError:
        raise DefaultsError("NETWORK_DEFAULTS_VERSION must be an integer") from None
    if version != SUPPORTED_VERSION:
        raise DefaultsError(f"unsupported defaults version {version}")
    d = Defaults(
        version=version,
        hub_url=data["NETWORK_HUB_URL"],
        hub_key=data["NETWORK_HUB_KEY"],
        feed_url=data["NETWORK_FEED_URL"],
        feed_key=data["NETWORK_FEED_KEY"],
    )
    if not is_placeholder(d.hub_url):
        check_https_url(d.hub_url, allow_path=False)
    if not is_placeholder(d.feed_url):
        check_https_url(d.feed_url, allow_path=True)
    if not is_placeholder(d.hub_key):
        check_key_list(d.hub_key)
    if not is_placeholder(d.feed_key):
        check_feed_key(d.feed_key)
    return d


def load() -> Defaults:
    """The committed defaults of this package, strictly parsed."""
    text = resources.files("suckerpot_netproto").joinpath("data", DEFAULTS_FILE).read_text("utf-8")
    return from_text(text)


def effective(env: Mapping[str, str], name: str) -> str:
    """``env[name]`` when non-empty, else the committed default, else ``""`` (placeholder)."""
    explicit = env.get(name, "").strip()
    if explicit:
        return explicit
    d = load()
    value = {
        "NETWORK_HUB_URL": d.hub_url,
        "NETWORK_HUB_KEY": d.hub_key,
        "NETWORK_FEED_URL": d.feed_url,
        "NETWORK_FEED_KEY": d.feed_key,
    }.get(name, "")
    return "" if is_placeholder(value) else value


def effective_pair(env: Mapping[str, str], url_name: str, key_name: str) -> tuple[str, str]:
    """The (URL, key) a node uses. Committed defaults apply only when the operator set neither
    value: a half-set pair is returned as is (the caller rejects it), never mixed with a default
    of the other half. A placeholder half means "not configured": both come back empty."""
    url = env.get(url_name, "").strip().rstrip("/")
    key = env.get(key_name, "").strip()
    if not url and not key:
        url = effective(env, url_name).rstrip("/")
        key = effective(env, key_name)
        if not (url and key):
            return "", ""
    return url, key


def _scope_url(env: Mapping[str, str], url_name: str, key_name: str, *, allow_path: bool) -> str:
    try:
        url, key = effective_pair(env, url_name, key_name)
        if not (url and key):
            return ""
        return check_https_url(url, allow_path=allow_path)
    except DefaultsError:
        return ""  # a malformed default or value closes the scope, never opens it
    except OSError:
        return ""


def scope_env(env: Mapping[str, str]) -> dict[str, str]:
    """The hub and feed URLs the egress gate scopes direct mode to (M32 D2): exactly what the
    network code resolves, defaults included. ``NETWORK_HUB_URL`` / ``NETWORK_FEED_URL`` come back
    empty when unset, half-set, a placeholder or invalid, so the scope can only shrink."""
    return {
        "NETWORK_HUB_URL": _scope_url(env, "NETWORK_HUB_URL", "NETWORK_HUB_KEY", allow_path=False),
        "NETWORK_FEED_URL": _scope_url(
            env, "NETWORK_FEED_URL", "NETWORK_FEED_KEY", allow_path=True
        ),
    }


def pseudonym_words() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(adjectives, nouns) from the shared word list."""
    text = resources.files("suckerpot_netproto").joinpath("data", WORDS_FILE).read_text("utf-8")
    sections: dict[str, list[str]] = {"adjectives": [], "nouns": []}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            name = line.strip("[]")
            if name not in sections:
                raise DefaultsError(f"unknown word section {name}")
            current = name
        elif current is None or not re.fullmatch(r"[a-z]{2,9}", line):
            raise DefaultsError("malformed word list")
        else:
            sections[current].append(line)
    return tuple(sections["adjectives"]), tuple(sections["nouns"])
