"""The synchronous, hot-path part of enrichment: local geo lookups plus tagging rules."""

from __future__ import annotations

from dataclasses import dataclass, field

from ingest.attack.mapping import AttackMap
from ingest.bruteforce import BruteForceTracker
from ingest.enrichment.geo import GeoResolver
from ingest.floods.fold import FloodFold
from ingest.indicators import IndicatorExtractor
from ingest.scanners import ScannerSet
from ingest.tagging import RuleSet


@dataclass(slots=True)
class Enricher:
    geo: GeoResolver
    rules: RuleSet
    brute: BruteForceTracker = field(default_factory=BruteForceTracker)
    indicators: IndicatorExtractor | None = None
    link_cap: int = 500
    attack: AttackMap | None = None
    scanners: ScannerSet = field(default_factory=ScannerSet)
    # Flood groups; None (tests, SESSION_FOLD_ENABLED=false) leaves every connection its own row.
    fold: FloodFold | None = None
