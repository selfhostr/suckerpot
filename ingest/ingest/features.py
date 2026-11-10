"""Settings and the common worker shape of the M15 to M19 features.

Every feature is off by default (``*_ENABLED=false``). Phase 0 wires one no-op worker per feature
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


def _model(env: Mapping[str, str]) -> str:
    raw = env.get("LLM_MODEL", "").strip() or "claude-haiku-5-5"
    if len(raw) > 64 or not set(raw) <= set("abcdefghijklmnopqrstuvwxyz0123456789-._"):
        raise ValueError("LLM_MODEL must be a model name such as claude-haiku-5-5")
    return raw


@dataclass(frozen=True, slots=True)
class FeatureSettings:
    attack_enabled: bool = False
    campaigns_enabled: bool = False
    campaign_min_sources: int = 2
    campaign_link_cap: int = 500
    blocklist_enabled: bool = False
    blocklist_window_days: int = 30
    blocklist_max_rows: int = 20_000
    scripts_enabled: bool = False
    llm_enabled: bool = False
    llm_daily_quota: int = 50
    llm_monthly_token_cap: int = 2_000_000
    llm_model: str = "claude-haiku-5-5"
    alerts_enabled: bool = False
    reports_enabled: bool = False
    abuse_enabled: bool = False
    network_enabled: bool = True
    network_feed_enabled: bool = False  # M30: fetch the public blocklist feed
    replies_enabled: bool = False
    takedown_enabled: bool = False  # M27: target tracking and re-check scheduling
    abusech_submit_enabled: bool = False  # M27: server-side switch for abuse.ch submissions
    site_timezone: str = "UTC"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> FeatureSettings:
        e = os.environ if env is None else env
        return cls(
            attack_enabled=_flag(e, "ATTACK_ENABLED"),
            campaigns_enabled=_flag(e, "CAMPAIGNS_ENABLED"),
            campaign_min_sources=_int(e, "CAMPAIGN_MIN_SOURCES", 2, 2, 100),
            campaign_link_cap=_int(e, "CAMPAIGN_LINK_CAP", 500, 10, 10_000),
            blocklist_enabled=_flag(e, "BLOCKLIST_ENABLED"),
            blocklist_window_days=_int(e, "BLOCKLIST_WINDOW_DAYS", 30, 1, 365),
            blocklist_max_rows=_int(e, "BLOCKLIST_MAX_ROWS", 20_000, 100, 1_000_000),
            scripts_enabled=_flag(e, "SCRIPTS_ENABLED"),
            llm_enabled=_flag(e, "LLM_ENABLED"),
            llm_daily_quota=_int(e, "LLM_DAILY_QUOTA", 50, 0, 10_000),
            llm_monthly_token_cap=_int(e, "LLM_MONTHLY_TOKEN_CAP", 2_000_000, 0, 1_000_000_000),
            llm_model=_model(e),
            alerts_enabled=_flag(e, "ALERTS_ENABLED"),
            reports_enabled=_flag(e, "REPORTS_ENABLED"),
            abuse_enabled=_flag(e, "ABUSE_REPORTS_ENABLED"),
            network_enabled=e.get("NETWORK_ENABLED", "false").strip().lower() in TRUE_VALUES,
            network_feed_enabled=_flag(e, "NETWORK_FEED_ENABLED"),
            replies_enabled=_flag(e, "ABUSE_REPLIES_ENABLED"),
            takedown_enabled=_flag(e, "TAKEDOWN_ENABLED"),
            abusech_submit_enabled=_flag(e, "ABUSECH_SUBMIT_ENABLED"),
            site_timezone=(e.get("SITE_TIMEZONE", "").strip() or "UTC"),
        )


class FeatureWorker:
    """Base of the feature workers. ``name`` is the key of its ``enrichment_status`` row."""

    name = "feature"
    interval_s = 300.0

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
        while True:
            try:
                await self.run_once()
                self.cycles += 1
                self.last_error = None
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # isolate errors per cycle; the message may hold a statement
                self.last_error = type(exc).__name__
                log.warning("%s cycle failed (%s)", self.name, type(exc).__name__)
            if publish is not None:
                try:
                    await publish(await self.status())
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.warning("%s status publish failed", self.name)
            await asyncio.sleep(self.interval_s)

    async def aclose(self) -> None:
        """Release resources (none in the base worker)."""
