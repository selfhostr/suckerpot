"""Enrichment settings from environment variables (no secret is ever logged)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

PROVIDERS = ("auto", "maxmind", "dbip", "off")
RECHECK_DAYS_MIN = 1
RECHECK_DAYS_MAX = 30


def _flag(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class EnrichmentSettings:
    geoip_dir: Path
    geoip_provider: str
    geoip_refresh_days: int
    geoip_fake_for_private: bool
    maxmind_account_id: str = field(default="", repr=False)
    maxmind_license_key: str = field(default="", repr=False)
    abuseipdb_api_key: str = field(default="", repr=False)
    greynoise_api_key: str = field(default="", repr=False)
    nvd_api_key: str = field(default="", repr=False)
    github_token: str = field(default="", repr=False)
    cve_watch_enabled: bool = True
    cve_nvd_daily_quota: int = 200
    cve_github_daily_quota: int = 100
    abusech_auth_key: str = field(default="", repr=False)
    virustotal_api_key: str = field(default="", repr=False)
    smtp_password: str = field(default="", repr=False)
    abuseipdb_daily_quota: int = 1000
    greynoise_daily_quota: int = 7
    abusech_daily_quota: int = 1000
    virustotal_daily_quota: int = 400
    intel_interval_s: float = 30.0
    reputation_min_events: int = 10
    reputation_interval_s: float = 30.0
    reputation_recheck_days: int = 7
    rules_dir: Path = Path("/app/rules")

    @property
    def maxmind_enabled(self) -> bool:
        return bool(self.maxmind_account_id and self.maxmind_license_key)

    @property
    def effective_geoip_provider(self) -> str:
        """Which provider will be downloaded/used: maxmind, dbip or off."""
        if self.geoip_provider == "off":
            return "off"
        if self.geoip_provider == "maxmind" or (
            self.geoip_provider == "auto" and self.maxmind_enabled
        ):
            return "maxmind" if self.maxmind_enabled else "off"
        return "dbip"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> EnrichmentSettings:
        e = os.environ if env is None else env
        provider = e.get("GEOIP_PROVIDER", "auto").strip().lower()
        if provider not in PROVIDERS:
            raise ValueError(f"GEOIP_PROVIDER must be one of {', '.join(PROVIDERS)}")
        default_rules = Path(__file__).resolve().parents[2] / "rules"
        return cls(
            geoip_dir=Path(e.get("GEOIP_DIR", "/data/geoip")),
            geoip_provider=provider,
            geoip_refresh_days=max(1, int(e.get("GEOIP_REFRESH_DAYS", "30"))),
            geoip_fake_for_private=_flag(e.get("GEOIP_FAKE_FOR_PRIVATE", "false")),
            maxmind_account_id=e.get("MAXMIND_ACCOUNT_ID", "").strip(),
            maxmind_license_key=e.get("MAXMIND_LICENSE_KEY", "").strip(),
            abuseipdb_api_key=e.get("ABUSEIPDB_API_KEY", "").strip(),
            greynoise_api_key=e.get("GREYNOISE_API_KEY", "").strip(),
            nvd_api_key=e.get("NVD_API_KEY", "").strip(),
            github_token=e.get("GITHUB_ADVISORY_TOKEN", "").strip(),
            cve_watch_enabled=_flag(e.get("CVE_WATCH_ENABLED", "true")),
            cve_nvd_daily_quota=max(0, int(e.get("CVE_NVD_DAILY_QUOTA", "200"))),
            cve_github_daily_quota=max(0, int(e.get("CVE_GITHUB_DAILY_QUOTA", "100"))),
            abusech_auth_key=e.get("ABUSECH_AUTH_KEY", "").strip(),
            virustotal_api_key=e.get("VIRUSTOTAL_API_KEY", "").strip(),
            smtp_password=e.get("SMTP_PASSWORD", "").strip(),
            abuseipdb_daily_quota=max(0, int(e.get("ABUSEIPDB_DAILY_QUOTA", "1000"))),
            greynoise_daily_quota=max(0, int(e.get("GREYNOISE_DAILY_QUOTA", "7"))),
            abusech_daily_quota=max(0, int(e.get("ABUSECH_DAILY_QUOTA", "1000"))),
            virustotal_daily_quota=max(0, int(e.get("VIRUSTOTAL_DAILY_QUOTA", "400"))),
            intel_interval_s=max(5.0, float(e.get("INTEL_INTERVAL_S", "30"))),
            reputation_min_events=max(1, int(e.get("REPUTATION_MIN_EVENTS", "10"))),
            reputation_interval_s=max(5.0, float(e.get("REPUTATION_INTERVAL_S", "30"))),
            reputation_recheck_days=min(
                RECHECK_DAYS_MAX,
                max(RECHECK_DAYS_MIN, int(e.get("REPUTATION_RECHECK_DAYS", "7"))),
            ),
            rules_dir=Path(e.get("RULES_DIR", str(default_rules))),
        )
