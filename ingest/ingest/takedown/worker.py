"""The takedown worker (design M27). Off until ``TAKEDOWN_ENABLED=true``.

One cycle (every ``TAKEDOWN_INTERVAL_S``, 600 s): sync targets from sent reports,
run the due listing checks, evaluate the passive signals, decide the state of every target whose
checks changed and, once a day, rebuild the monthly roll-up. The HTTP re-checks are not here: the
collector (the only service allowed to contact a payload host) does them.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.egress import EgressGate
from ingest.features import FeatureSettings, FeatureWorker
from ingest.takedown import passive, rollup
from ingest.takedown.config import TakedownSettings
from ingest.takedown.listing import IntelLike, ListingChecker, ReputationLike
from ingest.takedown.sync import AsnLookup, TargetSync

log = logging.getLogger(__name__)

ROLLUP_EVERY_S = 86_400.0


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TakedownWorker(FeatureWorker):
    name = "takedown"

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        *,
        intel: IntelLike | None = None,
        reputation: ReputationLike | None = None,
        takedown: TakedownSettings | None = None,
        asn_lookup: AsnLookup | None = None,
        gate: EgressGate | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        super().__init__(settings, enabled=settings.takedown_enabled)
        self.factory = factory
        self.td = takedown or TakedownSettings.from_env()
        self.interval_s = float(self.td.interval_s)
        self._clock = clock
        self._last_rollup = -ROLLUP_EVERY_S
        self.sync: TargetSync | None = None
        self.listing: ListingChecker | None = None
        self.counters: dict[str, int] = {}
        if self.enabled and factory is not None:
            self.sync = TargetSync(factory, self.td, asn_lookup)
            if intel is not None and reputation is not None:
                self.listing = ListingChecker(factory, self.td, intel, reputation, gate)

    def _count(self, key: str, n: int) -> None:
        self.counters[key] = self.counters.get(key, 0) + n

    async def run_once(self) -> None:
        if self.factory is None or self.sync is None:
            return
        now = self._clock()
        for key, n in (await self.sync.sync(now)).items():
            self._count(f"synced_{key}", n)
        if self.listing is not None:
            self._count("listing_checks", await self.listing.run(now))
        self._count("sightings", await passive.sightings(self.factory, now))
        self._count("sample_signals", await passive.sample_signals(self.factory, now))
        self._count(
            "state_changes", await passive.update_states(self.factory, now, self.td.quiet_days)
        )
        if time.monotonic() - self._last_rollup >= ROLLUP_EVERY_S:
            self._last_rollup = time.monotonic()
            self._count("rollup_rows", await rollup.recompute(self.factory, now))

    async def status(self) -> dict[str, Any]:
        base = await super().status()
        base[self.name].update(self.counters)
        return base
