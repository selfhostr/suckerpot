"""Campaign clustering worker: groups finished sessions that share a script, payload host, hash,
malware family, exploit or credential list into campaigns, then merges campaigns that are one
actor (their source addresses overlap). One bounded cycle every 300 s.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.attack.mapping import AttackMap
from ingest.campaigns.cluster import (
    ClusterConfig,
    ContentCache,
    CycleStats,
    MergeCursor,
    run_cycle,
)
from ingest.features import FeatureSettings, FeatureWorker


class CampaignWorker(FeatureWorker):
    name = "campaigns"
    interval_s = 300.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        attack: AttackMap | None = None,
    ) -> None:
        super().__init__(settings, enabled=settings.campaigns_enabled)
        self._factory = factory
        self._attack = attack
        self._cache = ContentCache()
        self._cursor = MergeCursor()
        self._cfg = ClusterConfig(
            min_sources=settings.campaign_min_sources, link_cap=settings.campaign_link_cap
        )
        self.last: CycleStats | None = None
        self.created = 0
        self.merged = 0

    async def run_once(self) -> None:
        if self._factory is None:
            return
        self.last = await run_cycle(
            self._factory, self._attack, self._cfg, self._cache, cursor=self._cursor
        )
        self.created += self.last.created
        self.merged += self.last.merged

    async def status(self) -> dict[str, Any]:
        out = await super().status()
        if not self.enabled:
            return out
        out[self.name].update(
            created=self.created,
            merged=self.merged,
            examined_last_cycle=self.last.examined if self.last else 0,
            deferred_last_cycle=self.last.deferred if self.last else 0,
            overlap_checked_last_cycle=self.last.overlap_checked if self.last else 0,
        )
        return out
