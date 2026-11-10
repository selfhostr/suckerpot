"""Phase 0 feature workers: off by default, error isolation, provider keys for the new features."""

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from ingest.alerts import AlertWorker
from ingest.attack import AttackCatalogWorker
from ingest.blocklist import BlocklistWorker
from ingest.campaigns import CampaignWorker
from ingest.enrichment import EnrichmentSettings
from ingest.enrichment.credentials import KEY_FIELDS, changed_providers
from ingest.features import FeatureSettings, FeatureWorker
from ingest.reports import ReportWorker
from ingest.scripts import ScriptWorker

WORKERS: list[Callable[[FeatureSettings], FeatureWorker]] = [
    AttackCatalogWorker,
    CampaignWorker,
    BlocklistWorker,
    ScriptWorker,
    AlertWorker,
    ReportWorker,
]


def test_every_feature_is_off_by_default() -> None:
    s = FeatureSettings.from_env({})
    assert not any(
        (
            s.attack_enabled,
            s.campaigns_enabled,
            s.blocklist_enabled,
            s.scripts_enabled,
            s.alerts_enabled,
            s.reports_enabled,
        )
    )
    assert (s.campaign_min_sources, s.campaign_link_cap) == (2, 500)
    assert (s.blocklist_window_days, s.blocklist_max_rows) == (30, 20_000)
    assert s.site_timezone == "UTC"


def test_settings_from_env() -> None:
    s = FeatureSettings.from_env(
        {"CAMPAIGNS_ENABLED": "true", "CAMPAIGN_MIN_SOURCES": "3", "SITE_TIMEZONE": "Europe/Zurich"}
    )
    assert s.campaigns_enabled and s.campaign_min_sources == 3
    assert s.site_timezone == "Europe/Zurich"


@pytest.mark.parametrize(
    "env",
    [{"CAMPAIGN_MIN_SOURCES": "1"}, {"CAMPAIGN_LINK_CAP": "x"}, {"BLOCKLIST_WINDOW_DAYS": "0"}],
)
def test_bad_numbers_are_refused(env: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="must be"):
        FeatureSettings.from_env(env)


@pytest.mark.parametrize("cls", WORKERS)
async def test_a_disabled_worker_publishes_once_and_returns(
    cls: Callable[[FeatureSettings], FeatureWorker],
) -> None:
    worker = cls(FeatureSettings())
    seen: list[dict[str, Any]] = []

    async def publish(detail: dict[str, Any]) -> None:
        seen.append(detail)

    await asyncio.wait_for(worker.run(publish), timeout=2)
    base = {"enabled": False, "cycles": 0, "last_error": None}
    assert len(seen) == 1
    assert {k: v for k, v in seen[0][worker.name].items() if k in base} == base
    await worker.aclose()


async def test_an_enabled_worker_isolates_cycle_errors() -> None:
    worker = CampaignWorker(FeatureSettings(campaigns_enabled=True))
    worker.interval_s = 0.01
    calls = 0

    async def flaky() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("boom")

    worker.run_once = flaky  # type: ignore[method-assign]
    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls > 1 and worker.cycles >= 1 and worker.last_error is None


def test_the_new_providers_have_key_fields() -> None:
    assert "anthropic" not in KEY_FIELDS
    assert KEY_FIELDS["smtp"] == "smtp_password"
    base = EnrichmentSettings.from_env({})
    assert base.smtp_password == ""
    new = EnrichmentSettings.from_env({"SMTP_PASSWORD": "not-a-real-key-" + "x" * 8})
    assert changed_providers(base, new) == {"smtp"}
    assert "not-a-real-key" not in repr(new)
