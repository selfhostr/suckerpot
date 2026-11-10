"""Settings of the network worker (design M29 section 9.1).

``NETWORK_ENABLED`` is the master switch and defaults to off: it only unlocks joining, and
nothing is sent until the membership says ``member``. Unset or ``false`` switches everything
off. The hub address and key ship empty: without both the network cannot be joined. Nothing
here is a secret (the hub key is public).
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from suckerpot_netproto import defaults, sign

TRUE_VALUES = {"1", "true", "yes", "on"}
MIN_SUBMIT_DELAY_H = 2
RESERVED_SUFFIXES = (".local", ".lan", ".internal", ".home.arpa", ".localhost", ".test")


def check_hub_host(host: str) -> None:
    """Refuse a hub host that is not a public DNS name (IP literal, single label, local suffix)."""
    h = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("NETWORK_HUB_URL must name a public DNS host, not an IP address")
    if "." not in h or h.endswith(RESERVED_SUFFIXES):
        raise ValueError("NETWORK_HUB_URL must name a public DNS host")


@dataclass(frozen=True, slots=True)
class NetworkSettings:
    enabled: bool = True
    hub_url: str = ""
    hub_key: str = ""
    interval_s: int = 900
    delay_min_h: float = 2.0
    delay_max_h: float = 20.0
    max_sources: int = 5000
    # M32 (participant and verifier). ``hub_key`` may hold a pinned set of up to three keys.
    stack_mode: str = "full"
    egress_mode: str = "vpn"
    consent: str = ""
    pseudonym: str = ""
    country: str = ""
    show_country: bool = False
    verify_reveals: bool = False
    verifier: bool = False
    verify_daily_cap: int = 100
    verify_host_daily_cap: int = 3
    collector_enabled: bool = False

    @property
    def hub_configured(self) -> bool:
        return bool(self.hub_url and self.hub_key)

    @property
    def hub_keys(self) -> tuple[str, ...]:
        """The pinned hub key set (N19). Empty while no hub is configured."""
        return sign.parse_key_set(self.hub_key) if self.hub_key else ()

    @property
    def participant(self) -> bool:
        return self.stack_mode == "participant"

    @property
    def hub_host(self) -> str:
        return urlsplit(self.hub_url).hostname or ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> NetworkSettings:
        e = os.environ if env is None else env
        url = e.get("NETWORK_HUB_URL", "").strip().rstrip("/")
        key = e.get("NETWORK_HUB_KEY", "").strip()
        if not url and not key:
            # Committed defaults (M32 D5) apply only when the operator set neither value: a
            # half-set pair is an error, never mixed with a default of the other half.
            url = defaults.effective(e, "NETWORK_HUB_URL").rstrip("/")
            key = defaults.effective(e, "NETWORK_HUB_KEY")
            if not (url and key):  # a placeholder half means "not configured", never half a pair
                url = key = ""
        stack_mode = e.get("SUCKERPOT_STACK_MODE", "").strip().lower() or "full"
        if stack_mode not in ("full", "participant"):
            raise ValueError("SUCKERPOT_STACK_MODE must be full or participant")
        egress_mode = e.get("EGRESS_MODE", "").strip().lower() or "vpn"
        if egress_mode not in ("vpn", "direct"):
            raise ValueError("EGRESS_MODE must be vpn or direct")
        settings = cls(
            enabled=e.get("NETWORK_ENABLED", "false").strip().lower() in TRUE_VALUES,
            hub_url=url,
            hub_key=key,
            interval_s=_int(e, "NETWORK_INTERVAL_S", 900, 30, 86_400),
            delay_min_h=float(_int(e, "NETWORK_SUBMIT_DELAY_MIN_H", 2, MIN_SUBMIT_DELAY_H, 23)),
            delay_max_h=float(_int(e, "NETWORK_SUBMIT_DELAY_MAX_H", 20, 1, 23)),
            max_sources=_int(e, "NETWORK_MAX_SOURCES", 5000, 1, 5000),
            stack_mode=stack_mode,
            egress_mode=egress_mode,
            consent=e.get("NETWORK_CONSENT", "").strip(),
            pseudonym=e.get("NETWORK_PSEUDONYM", "").strip(),
            country=e.get("NETWORK_COUNTRY", "").strip().upper(),
            show_country=_flag(e, "NETWORK_SHOW_COUNTRY"),
            verify_reveals=_flag(e, "NETWORK_VERIFY_REVEALS"),
            verifier=_flag(e, "NETWORK_VERIFIER"),
            verify_daily_cap=_int(e, "NETWORK_VERIFY_DAILY_CAP", 100, 0, 5000),
            verify_host_daily_cap=_int(e, "NETWORK_VERIFY_HOST_DAILY_CAP", 3, 0, 100),
            collector_enabled=_flag(e, "COLLECTOR_ENABLED"),
        )
        if settings.delay_min_h >= settings.delay_max_h:
            raise ValueError("NETWORK_SUBMIT_DELAY_MIN_H must be below NETWORK_SUBMIT_DELAY_MAX_H")
        if bool(url) != bool(key):
            raise ValueError("NETWORK_HUB_URL and NETWORK_HUB_KEY must be set together")
        if url:
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname or parts.path or parts.query:
                raise ValueError("NETWORK_HUB_URL must be an https URL without a path")
            if parts.username or parts.password or parts.fragment:
                raise ValueError("NETWORK_HUB_URL must not hold credentials")
            check_hub_host(parts.hostname)
            try:
                _ = settings.hub_keys  # parsing is the check: 1 to 3 base64url keys
            except ValueError:
                raise ValueError("NETWORK_HUB_KEY must be a base64url public key") from None
        return settings


def _flag(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "false").strip().lower() in TRUE_VALUES


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value
