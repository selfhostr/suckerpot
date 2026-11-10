"""Entry point: ``python -m ingest``."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import Any

from redis.asyncio import Redis
from suckerpot_db import create_engine, create_session_factory
from suckerpot_db.diskguard import max_db_bytes
from suckerpot_db.secretbox import SecretBox, SecretError, box_from_env
from suckerpot_db.trusted_exits import self_networks_provider, trusted_exit_provider

from ingest.abuse import AbuseWorker, selfterms
from ingest.abuse.selfterms import TermsCache
from ingest.abusech import AbusechSubmitWorker
from ingest.abusech.body import load_malpedia
from ingest.alerts import AlertWorker
from ingest.alerts.config import AlertSettings
from ingest.attack import AttackCatalogWorker, load_attack
from ingest.blocklist import BlocklistWorker
from ingest.campaigns import CampaignWorker
from ingest.check_requests import run as run_check_requests
from ingest.config import Settings, missing_default_streams
from ingest.consumer import Consumer
from ingest.cve import CveWatch
from ingest.cve.relevance import load_relevance
from ingest.diskguard import DiskGuard, publish_system_status
from ingest.egress import get_gate, install_gate
from ingest.enrichment import EnrichmentSettings, GeoResolver
from ingest.enrichment.credentials import CredentialSync
from ingest.enrichment.downloader import GeoManager
from ingest.enrichment.enricher import Enricher
from ingest.enrichment.intel import IntelWorker
from ingest.enrichment.reputation import ReputationWorker
from ingest.enrichment.status import publish_status
from ingest.features import FeatureSettings, FeatureWorker
from ingest.indicators import IndicatorExtractor, IndicatorSettings
from ingest.network import BatchBuilder, NetworkSettings, NetworkWorker
from ingest.network.feed import FeedWorker, SqlFeedStore
from ingest.network.feed_client import FeedSettings
from ingest.network.source import SqlSource
from ingest.network.store import SqlStore
from ingest.network.verifier import SqlVerifyStore
from ingest.replies import ReplyWorker
from ingest.reports import ReportWorker
from ingest.scanners import load_scanners
from ingest.scripts import ScriptWorker, load_annotations
from ingest.tagging import load_rules
from ingest.takedown import TakedownWorker
from ingest.updatecheck import UpdateChecker

log = logging.getLogger(__name__)


def load_secret_box() -> SecretBox | None:
    """The Settings-key encryption box; a bad value disables the feature instead of crashing."""
    try:
        return box_from_env()
    except SecretError as exc:
        log.error("SETTINGS_ENCRYPTION_KEY is unusable (%s): keys set in Settings are ignored", exc)
        return None


def build_network_worker(features: FeatureSettings, factory: Any) -> NetworkWorker:
    """The opt-in network worker. A bad NETWORK_* value leaves the network off."""
    try:
        network = NetworkSettings.from_env()
    except ValueError as exc:
        log.error("network settings are invalid (%s): the network stays off", exc)
        network = NetworkSettings()
    terms = TermsCache(factory)
    builder = BatchBuilder(SqlSource(factory), terms, max_sources=network.max_sources)

    async def learn() -> int:
        # Participant mode has no abuse worker to learn the own address (M32 8.4).
        return await selfterms.learn(factory)

    return NetworkWorker(
        features, network, SqlStore(factory), terms, builder, box=load_secret_box(),
        verify_store=SqlVerifyStore(factory), learn=learn,
    )  # fmt: skip


def build_feed_worker(features: FeatureSettings, factory: Any) -> FeedWorker:
    """The public blocklist feed worker (M30). A bad NETWORK_FEED_* value leaves it unconfigured
    (nothing is fetched); it never turns the flag off, so stored data is not wiped by a typo."""
    try:
        feed = FeedSettings.from_env()
    except ValueError as exc:
        log.error("network feed settings are invalid (%s): the feed is not fetched", exc)
        feed = FeedSettings()
    return FeedWorker(features, feed, SqlFeedStore(factory))


async def run() -> None:
    settings = Settings.from_env()
    if missing := missing_default_streams(settings.streams):
        log.warning("INGEST_STREAMS leaves out %s: those sensors' events are not ingested", missing)
    enrich = EnrichmentSettings.from_env()
    redis = Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        username=settings.redis_user,
        password=settings.redis_password,
        lib_name=None,
        lib_version=None,
        socket_timeout=settings.block_ms / 1000 + 10,
        socket_connect_timeout=5,
    )
    engine = create_engine()
    factory = create_session_factory(engine)

    rules = load_rules(enrich.rules_dir)  # fail fast on a broken rule file
    log.info("loaded %d tagging rules", len(rules.rules))
    scanners = load_scanners(enrich.rules_dir)  # fail fast here too
    log.info("loaded %d research scanner definitions", len(scanners.scanners))
    resolver = GeoResolver(enrich.geoip_dir, fake_for_private=enrich.geoip_fake_for_private)

    def exit_asn(ip: str) -> tuple[int | None, str | None]:
        info = resolver.lookup(ip)
        return info.asn, info.org

    install_gate(trusted_exit_provider(factory), self_networks_provider(factory), exit_asn)

    async def disk_status(detail: dict[str, Any]) -> None:
        await publish_system_status(factory, "ingest_disk", detail)

    guard = DiskGuard(factory, max_db_bytes(), on_status=disk_status)
    indicator_settings = IndicatorSettings.from_env()
    features = FeatureSettings.from_env()
    # ATT&CK mapping: fail fast on a broken file, like the tagging rules.
    attack = load_attack(enrich.rules_dir) if features.attack_enabled else None
    if attack is not None:
        log.info(
            "loaded %d ATT&CK techniques and %d mapping rules",
            len(attack.techniques),
            len(attack.rules),
        )
    enricher = Enricher(
        resolver,
        rules,
        indicators=IndicatorExtractor(indicator_settings) if indicator_settings.enabled else None,
        link_cap=indicator_settings.link_cap,
        attack=attack,
        scanners=scanners,
    )
    consumer = Consumer(settings, redis, factory, enricher, guard)

    async def geo_status(detail: dict[str, Any]) -> None:
        await publish_status(factory, "geoip", detail)

    # Keys set in Settings override .env. Read them once before the workers start.
    appliers: list[Any] = []

    def apply_credentials(settings: EnrichmentSettings, changed: set[str]) -> None:
        for apply in appliers:
            apply(settings, changed)

    sync = CredentialSync(factory, enrich, load_secret_box(), on_change=apply_credentials)
    try:
        await sync.sync_once()
    except Exception as exc:
        log.warning("initial provider credential sync failed (%s)", type(exc).__name__)
    enrich = sync.current

    geo = GeoManager(enrich, resolver, on_status=geo_status)
    reputation = ReputationWorker(factory, enrich)
    appliers.append(
        lambda settings, changed: geo.apply_settings(
            settings, credentials_changed="maxmind" in changed
        )
    )
    appliers.append(reputation.apply_settings)
    cve_watch = CveWatch(factory, enrich, relevance=load_relevance(enrich.rules_dir))
    appliers.append(cve_watch.apply_settings)
    intel = IntelWorker(factory, enrich, indicator_settings=indicator_settings, resolver=resolver)
    appliers.append(intel.apply_settings)

    async def rep_status(detail: dict[str, Any]) -> None:
        for name, value in detail.items():
            await publish_status(factory, name, {**value, **sync.status(name)})

    async def cve_status(detail: dict[str, Any]) -> None:
        for name, value in detail.items():
            extra = sync.status(name) if name in ("nvd", "github") else {}
            await publish_status(factory, name, {**value, **extra})

    async def publish_all() -> None:
        await rep_status(await reputation.status())
        await cve_status(await cve_watch.status())
        await rep_status(await intel.status())
        await publish_status(factory, "maxmind", sync.status("maxmind"))

    # M15 to M19 feature workers: off by default, no-op until their phase lands.
    annotations = load_annotations(enrich.rules_dir)  # fail fast on a broken annotation file
    log.info("loaded %d script annotations", len(annotations.entries))
    try:
        alert_settings = AlertSettings.from_env()
    except ValueError as exc:
        log.error("alert e-mail settings are invalid (%s): e-mail alerts are off", exc)
        alert_settings = AlertSettings()
    malpedia = load_malpedia(enrich.rules_dir)  # fail fast on a broken mapping
    feature_workers: list[FeatureWorker] = [
        AttackCatalogWorker(features, factory, attack),
        CampaignWorker(features, factory, attack),
        BlocklistWorker(features, factory),
        ScriptWorker(features, factory, annotations),
        AlertWorker(
            features,
            factory,
            load_secret_box(),
            alert_settings,
            enrich.smtp_password,
        ),
        ReportWorker(features, factory),
        AbuseWorker(features, factory, box=load_secret_box()),
        ReplyWorker(
            features, factory, box=load_secret_box(), rules_dir=enrich.rules_dir / "replies"
        ),
        # M27: both off until their *_ENABLED flags; the abuse.ch worker also needs the owner's
        # mode in Settings. Lookups reuse the intel and reputation clients (same gate, same quotas).
        TakedownWorker(features, factory, intel=intel, reputation=reputation, asn_lookup=exit_asn),
        AbusechSubmitWorker(
            features,
            factory,
            TermsCache(factory),
            get_gate(),
            load_secret_box(),
            intel=intel,
            malpedia=malpedia,
        ),
        build_network_worker(features, factory),
        build_feed_worker(features, factory),
    ]
    for worker in feature_workers:
        appliers.append(worker.apply_settings)

    async def feature_status(detail: dict[str, Any]) -> None:
        for name, value in detail.items():
            await publish_status(factory, name, value)

    async def run_test(provider: str) -> None:
        if provider in ("smtp", "anthropic"):
            return  # alert channels have their own test button; "anthropic" is a retired key slot
        elif provider in ("abusech", "virustotal"):
            await intel.run_key_test(provider)
        elif provider == "maxmind":
            await sync.test_maxmind()
        elif provider in ("nvd", "github"):
            await cve_watch.run_key_test(provider)
        else:
            await reputation.run_key_test(provider)

    sync.run_test = run_test
    sync.on_synced = publish_all
    gate = get_gate()

    async def egress_status(status: Any) -> None:
        await publish_status(
            factory,
            "egress",
            {
                "open": status.open,
                "reason": status.reason,
                "egress_ip": status.egress_ip,
                "egress_asn": status.asn,
                "egress_org": status.org,
                "checked_at": status.checked_at.isoformat(),
            },
        )

    update_checker = UpdateChecker(factory, gate=gate)
    background = [
        asyncio.create_task(gate.run(egress_status), name="egress-gate"),
        asyncio.create_task(run_check_requests(factory, gate.request_check), name="egress-checks"),
        asyncio.create_task(geo.run(), name="geoip"),
        asyncio.create_task(reputation.run(rep_status), name="reputation"),
        asyncio.create_task(cve_watch.run(cve_status), name="cve-watch"),
        asyncio.create_task(intel.run(rep_status), name="intel"),
        asyncio.create_task(sync.run(), name="credentials"),
        asyncio.create_task(update_checker.run(), name="update-check"),
        *(
            asyncio.create_task(w.run(feature_status), name=f"feature-{w.name}")
            for w in feature_workers
        ),
    ]
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, consumer.stop.set)
    try:
        await consumer.run()
    finally:
        for task in background:
            task.cancel()
        for task in background:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await gate.aclose()
        await reputation.aclose()
        await cve_watch.aclose()
        await intel.aclose()
        for worker in feature_workers:
            await worker.aclose()
        await sync.aclose()
        resolver.close()
        await redis.aclose()
        await engine.dispose()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    asyncio.run(run())
