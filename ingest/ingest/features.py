"""Settings and the common worker shape of the M15 to M19 features.

The local analysis features (ATT&CK, campaigns, blocklists, scripts) are on by default: they read
only the database and make no outbound request. An explicit ``false`` turns one off. Every other
feature is off by default (``*_ENABLED=false``). Phase 0 wires one no-op worker per feature
so the plumbing (settings, status, shutdown) exists before the logic does; later phases replace
``run_once`` with the real job. A worker follows the ``IntelWorker`` shape: ``run(publish)``,
``status()``, ``apply_settings()`` and ``aclose()``; an error in one cycle is logged and the next
cycle runs; nothing here holds a secret.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

Publish = Callable[[dict[str, Any]], Awaitable[None]]

TRUE_VALUES = {"1", "true", "yes", "on"}


def _flag(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    """A true/false setting. A missing or empty value gives ``default``; anything else is read."""
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in TRUE_VALUES


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


@dataclass(frozen=True, slots=True)
class FeatureSettings:
    attack_enabled: bool = True
    campaigns_enabled: bool = True
    campaign_min_sources: int = 2
    campaign_link_cap: int = 500
    blocklist_enabled: bool = True
    blocklist_window_days: int = 30
    blocklist_max_rows: int = 20_000
    scripts_enabled: bool = True
    alerts_enabled: bool = False
    reports_enabled: bool = False
    abuse_enabled: bool = False
    network_enabled: bool = True
    network_feed_enabled: bool = False  # M30: fetch the public blocklist feed
    replies_enabled: bool = False
    takedown_enabled: bool = False  # M27: target tracking and re-check scheduling
    site_timezone: str = "UTC"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> FeatureSettings:
        e = os.environ if env is None else env
        return cls(
            attack_enabled=_flag(e, "ATTACK_ENABLED", True),
            campaigns_enabled=_flag(e, "CAMPAIGNS_ENABLED", True),
            campaign_min_sources=_int(e, "CAMPAIGN_MIN_SOURCES", 2, 2, 100),
            campaign_link_cap=_int(e, "CAMPAIGN_LINK_CAP", 500, 10, 10_000),
            blocklist_enabled=_flag(e, "BLOCKLIST_ENABLED", True),
            blocklist_window_days=_int(e, "BLOCKLIST_WINDOW_DAYS", 30, 1, 365),
            blocklist_max_rows=_int(e, "BLOCKLIST_MAX_ROWS", 20_000, 100, 1_000_000),
            scripts_enabled=_flag(e, "SCRIPTS_ENABLED", True),
            alerts_enabled=_flag(e, "ALERTS_ENABLED"),
            reports_enabled=_flag(e, "REPORTS_ENABLED"),
            abuse_enabled=_flag(e, "ABUSE_REPORTS_ENABLED"),
            network_enabled=e.get("NETWORK_ENABLED", "false").strip().lower() in TRUE_VALUES,
            network_feed_enabled=_flag(e, "NETWORK_FEED_ENABLED"),
            replies_enabled=_flag(e, "ABUSE_REPLIES_ENABLED"),
            takedown_enabled=_flag(e, "TAKEDOWN_ENABLED"),
            site_timezone=(e.get("SITE_TIMEZONE", "").strip() or "UTC"),
        )


class FeatureWorker:
    """Base of the feature workers. ``name`` is the key of its ``enrichment_status`` row."""

    name = "feature"
    interval_s = 300.0
    # Seconds to wait before the first cycle, so a heavy cycle does not compete with the start of
    # the stack (cold caches, catch-up of the event stream). The status is published first.
    start_delay_s = 0.0

    def __init__(self, settings: FeatureSettings, *, enabled: bool) -> None:
        self.settings = settings
        self.enabled = enabled
        self.cycles = 0
        self.last_error: str | None = None

    def apply_settings(self, settings: Any, changed: set[str]) -> None:
        """Provider keys changed in Settings. The base worker has nothing to refresh."""

    async def run_once(self) -> None:
        """One cycle of work. Phase 0: nothing to do."""

    async def status(self) -> dict[str, Any]:
        return {
            self.name: {
                "enabled": self.enabled,
                "cycles": self.cycles,
                "last_error": self.last_error,
            }
        }

    async def run(self, publish: Publish | None = None) -> None:
        if not self.enabled:
            if publish is not None:
                await publish(await self.status())
            return
        if self.start_delay_s > 0:
            await self._publish(publish)
            await asyncio.sleep(self.start_delay_s)
        while True:
            try:
                await self.run_once()
                self.cycles += 1
                self.last_error = None
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # isolate errors per cycle; the message may hold a statement
                # A worker may attach a ``summary`` that is safe to log (no statement, no values).
                summary = str(getattr(exc, "summary", "") or type(exc).__name__)[:200]
                self.last_error = summary
                log.warning("%s cycle failed (%s)", self.name, summary)
            await self._publish(publish)
            await self.pause()

    async def pause(self) -> None:
        """The wait between two cycles. A worker may end it early (NetworkWorker does)."""
        await asyncio.sleep(self.interval_s)

    async def _publish(self, publish: Publish | None) -> None:
        if publish is None:
            return
        try:
            await publish(await self.status())
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("%s status publish failed", self.name)

    async def aclose(self) -> None:
        """Release resources (none in the base worker)."""
