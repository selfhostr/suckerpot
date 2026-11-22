"""Settings of the abuse-report worker (``ABUSE_*``). The worker itself is off until
``ABUSE_REPORTS_ENABLED=true`` (see ``ingest.features``)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from ingest.abuse.ports import PortMap
from ingest.features import TRUE_VALUES, _int

DEFAULT_SEVERE_TAGS = ("malware-drop", "mirai", "crypto-miner", "php2shell", "exploit")


def _tags(raw: str) -> tuple[str, ...]:
    out = [t.strip().lower() for t in raw.split(",") if t.strip()]
    return tuple(dict.fromkeys(t for t in out if len(t) <= 64)) or DEFAULT_SEVERE_TAGS


HOLDOUT_MAX_PCT = 10


def holdout_pct(env: Mapping[str, str]) -> int:
    """``ABUSE_EFFECT_HOLDOUT_PCT``: 0 (the default, off) to 10; anything else stops the start."""
    return _int(env, "ABUSE_EFFECT_HOLDOUT_PCT", 0, 0, HOLDOUT_MAX_PCT)


@dataclass(frozen=True, slots=True)
class AbuseSettings:
    build_interval_s: int = 3600
    min_login_attempts: int = 50
    severe_tags: tuple[str, ...] = DEFAULT_SEVERE_TAGS
    lookback_days: int = 7
    settle_min: int = 30
    resend_days: int = 14
    max_subjects: int = 100
    max_open_drafts: int = 200
    rdap_daily_quota: int = 1000
    rdap_hourly_quota: int = 200
    include_demo: bool = False
    ports: PortMap = field(default_factory=PortMap)
    round_times: bool = True  # owner decision: minute precision unless exact times are chosen
    holdout_pct: int = 0  # M38 D9: share of new attack candidates held back 21 days (0 to 10)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AbuseSettings:
        e = os.environ if env is None else env
        return cls(
            build_interval_s=_int(e, "ABUSE_BUILD_INTERVAL_S", 3600, 60, 86_400),
            min_login_attempts=_int(e, "ABUSE_MIN_LOGIN_ATTEMPTS", 50, 1, 100_000),
            severe_tags=_tags(e.get("ABUSE_SEVERE_TAGS", "")),
            lookback_days=_int(e, "ABUSE_LOOKBACK_DAYS", 7, 1, 90),
            settle_min=_int(e, "ABUSE_SETTLE_MIN", 30, 0, 1440),
            resend_days=_int(e, "ABUSE_RESEND_DAYS", 14, 0, 365),
            max_subjects=_int(e, "ABUSE_MAX_SUBJECTS", 100, 1, 100),
            max_open_drafts=_int(e, "ABUSE_MAX_OPEN_DRAFTS", 200, 1, 10_000),
            rdap_daily_quota=_int(e, "ABUSE_RDAP_DAILY_QUOTA", 1000, 0, 100_000),
            rdap_hourly_quota=_int(e, "ABUSE_RDAP_HOURLY_QUOTA", 200, 0, 10_000),
            include_demo=e.get("ABUSE_REPORTS_INCLUDE_DEMO", "false").strip().lower()
            in TRUE_VALUES,
            ports=PortMap.from_env(e),
            round_times=e.get("ABUSE_ROUND_TIMES", "true").strip().lower() in TRUE_VALUES,
            holdout_pct=holdout_pct(e),
        )
