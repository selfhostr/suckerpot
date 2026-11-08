"""Hub settings, read from HUB_* environment variables.

Nothing here is a secret except the database passwords inside the URLs; the signing key is read
from the file named by ``HUB_SIGNING_KEY_FILE`` and never from the environment.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from suckerpot_netproto import sign


class ConfigError(RuntimeError):
    """A setting is missing or invalid. The message never contains a value."""


def _int(env: Mapping[str, str], name: str, default: int, lo: int = 0, hi: int = 10**9) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc


def _bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = ""
    worker_database_url: str = ""
    signing_key_file: str = ""
    # Test overlay only: accept documentation address ranges.
    allow_documentation: bool = False
    # Read the client address from the proxy header of the reverse proxy in front of the hub.
    trust_proxy: bool = False

    # Proof of work and enrolment caps.
    pow_difficulty: int = 27
    enrol_soft_cap: int = 3  # challenges one address prefix may draw per window before +1 bit
    enrol_hard_cap: int = 5000  # a flood stopper far above any honest day
    enrol_step: int = 3  # one more proof-of-work bit per this many further challenges of one prefix
    challenges_per_prefix: int = 20
    challenge_ttl_s: int = 600
    max_pending_challenges: int = 20000

    # Rate limits.
    unsigned_per_min: int = 10
    unsigned_per_day: int = 100
    auth_failures_per_min: int = 30
    signed_per_hour: int = 60
    reveals_per_day: int = 2000
    new_values_per_day: int = 20000

    # Consensus (used by the worker; the API publishes them in /v1/info).
    min_nodes: int = 5
    min_weight: float = 3.0
    node_min_age_days: int = 14
    node_min_active_days: int = 7
    min_reputation: float = 0.3
    window_days: int = 7
    cohort_max_share: float = 0.5
    # Auto mode (reports sent without review) needs this many independent enrolment cohorts.
    auto_min_cohorts: int = 5

    # Retention.
    obs_retention_days: int = 14
    inactive_node_days: int = 30
    contributor_retention_days: int = 30
    vote_retention_days: int = 30

    # Worker.
    worker_interval_s: int = 3600

    # Reports (worker).
    report_mode: str = "review"
    report_hold_hours: int = 24
    report_daily_cap: int = 100
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = field(default="", repr=False)
    smtp_from: str = ""
    smtp_starttls: bool = True
    report_reply_to: str = ""
    report_template_file: str = ""
    # Public blocklist feeds (design M30, section 7.6). Off until the owner turns them on.
    feed_mode: str = "off"
    feed_dir: str = "/srv/feeds"
    feed_signing_key_file: str = ""
    feed_interval_min: int = 60
    feed_hold_hours: int = 6
    feed_valid_days: int = 3
    feed_ttl_inbound_days: int = 7
    feed_ttl_payload_days: int = 14
    feed_ttl_c2_days: int = 30
    feed_max_inbound: int = 50_000
    feed_max_outbound: int = 20_000
    feed_max_domains: int = 20_000
    feed_breaker_add_pct: int = 50
    feed_breaker_remove_pct: int = 50
    feed_breaker_min: int = 200
    feed_never: tuple[str, ...] = ()
    external_ranges_enabled: bool = True
    # Public network observatory (design M34): network.json in HUB_FEED_DIR, once a day. Off until
    # the operator turns it on; independent of HUB_FEED_MODE.
    observatory_enabled: bool = False
    # Public delisting (design M30 section 9): proof-of-work bits, requests per day, and how many
    # inbound values may be hidden at once, per day, before an operator has looked at them.
    delist_pow_difficulty: int = 20
    delist_daily_cap: int = 200
    delist_auto_suppress_daily: int = 50
    # Filled into the public README.txt: the feed host name and the delisting mailbox (optional).
    feeds_domain: str = "feeds.example.org"
    delist_mailbox: str = ""
    # abuse.ch submissions (URLhaus, ThreatFox). Off until a mode and an Auth-Key are both set.
    abusech_mode: str = "off"
    abusech_auth_key: str = field(default="", repr=False)
    abusech_daily_cap: int = 50
    # Link verification (design M32 section 7). Off: no task, no early reveal.
    verify_mode: str = "off"
    verify_min_reporters: int = 2
    verify_daily_cap: int = 200
    verify_host_daily_cap: int = 5
    verify_lease_hours: int = 6
    verify_max_attempts: int = 2
    verify_url_max_age_days: int = 3
    verify_delay_min_h: int = 6
    verify_delay_max_h: int = 30
    # Second hub key for a signing-key rollover (answers carry both signatures); empty = none.
    signing_key_alt_file: str = ""
    # External corroboration (optional keys; empty disables the source).
    abuseipdb_key: str = field(default="", repr=False)
    greynoise_key: str = field(default="", repr=False)

    @property
    def abusech_active(self) -> bool:
        """Submissions are queued and sent only with a mode other than off AND an Auth-Key."""
        return self.abusech_mode != "off" and bool(self.abusech_auth_key)

    @property
    def verify_enabled(self) -> bool:
        return self.verify_mode in ("review", "auto")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e: Mapping[str, str] = os.environ if env is None else env
        mode = e.get("HUB_REPORT_MODE", "review") or "review"
        if mode not in {"review", "auto", "off"}:
            raise ConfigError("HUB_REPORT_MODE must be review, auto or off")
        feed_mode = e.get("HUB_FEED_MODE", "off") or "off"
        if feed_mode not in {"off", "review", "auto"}:
            raise ConfigError("HUB_FEED_MODE must be off, review or auto")
        abusech_mode = e.get("HUB_ABUSECH_MODE", "off") or "off"
        if abusech_mode not in {"off", "review", "auto"}:
            raise ConfigError("HUB_ABUSECH_MODE must be off, review or auto")
        verify_mode = e.get("HUB_VERIFY_MODE", "off") or "off"
        if verify_mode not in {"off", "review", "auto"}:
            raise ConfigError("HUB_VERIFY_MODE must be off, review or auto")
        delay_min = _int(e, "HUB_VERIFY_DELAY_MIN_H", 6, 0, 720)
        delay_max = _int(e, "HUB_VERIFY_DELAY_MAX_H", 30, 0, 720)
        if delay_max < delay_min:
            raise ConfigError("HUB_VERIFY_DELAY_MAX_H must not be below HUB_VERIFY_DELAY_MIN_H")
        return cls(
            verify_mode=verify_mode,
            # Never below 2: one reporter must not be able to steer the verifier.
            verify_min_reporters=_int(e, "HUB_VERIFY_MIN_REPORTERS", 2, 2, 1000),
            verify_daily_cap=_int(e, "HUB_VERIFY_DAILY_CAP", 200, 0),
            verify_host_daily_cap=_int(e, "HUB_VERIFY_HOST_DAILY_CAP", 5, 0),
            verify_lease_hours=_int(e, "HUB_VERIFY_LEASE_HOURS", 6, 1, 168),
            verify_max_attempts=_int(e, "HUB_VERIFY_MAX_ATTEMPTS", 2, 1, 10),
            verify_url_max_age_days=_int(e, "HUB_VERIFY_URL_MAX_AGE_DAYS", 3, 1, 14),
            verify_delay_min_h=delay_min,
            verify_delay_max_h=delay_max,
            signing_key_alt_file=e.get("HUB_SIGNING_KEY_ALT_FILE", ""),
            abusech_mode=abusech_mode,
            abusech_auth_key=e.get("HUB_ABUSECH_AUTH_KEY", ""),
            abusech_daily_cap=_int(e, "HUB_ABUSECH_DAILY_CAP", 50, 0),
            feed_mode=feed_mode,
            feed_dir=e.get("HUB_FEED_DIR", "/srv/feeds") or "/srv/feeds",
            feed_signing_key_file=e.get("HUB_FEED_SIGNING_KEY_FILE", ""),
            feed_interval_min=_int(e, "HUB_FEED_INTERVAL_MIN", 60, 1),
            feed_hold_hours=_int(e, "HUB_FEED_HOLD_HOURS", 6, 0),
            feed_valid_days=_int(e, "HUB_FEED_VALID_DAYS", 3, 1, 30),
            feed_ttl_inbound_days=_int(e, "HUB_FEED_TTL_INBOUND_DAYS", 7, 1, 365),
            feed_ttl_payload_days=_int(e, "HUB_FEED_TTL_PAYLOAD_DAYS", 14, 1, 365),
            feed_ttl_c2_days=_int(e, "HUB_FEED_TTL_C2_DAYS", 30, 1, 365),
            feed_max_inbound=_int(e, "HUB_FEED_MAX_INBOUND", 50_000, 1, 50_000),
            feed_max_outbound=_int(e, "HUB_FEED_MAX_OUTBOUND", 20_000, 1, 20_000),
            feed_max_domains=_int(e, "HUB_FEED_MAX_DOMAINS", 20_000, 1, 20_000),
            feed_breaker_add_pct=_int(e, "HUB_FEED_BREAKER_ADD_PCT", 50, 0),
            feed_breaker_remove_pct=_int(e, "HUB_FEED_BREAKER_REMOVE_PCT", 50, 0),
            feed_breaker_min=_int(e, "HUB_FEED_BREAKER_MIN", 200, 0),
            feed_never=tuple(
                v.strip() for v in e.get("HUB_FEED_NEVER", "").split(",") if v.strip()
            ),
            external_ranges_enabled=_bool(e, "HUB_EXTERNAL_RANGES_ENABLED", True),
            observatory_enabled=_bool(e, "HUB_OBSERVATORY_ENABLED"),
            delist_pow_difficulty=_int(e, "HUB_DELIST_POW_DIFFICULTY", 20, 0, 32),
            delist_daily_cap=_int(e, "HUB_DELIST_DAILY_CAP", 200, 0),
            delist_auto_suppress_daily=_int(e, "HUB_DELIST_AUTO_SUPPRESS_DAILY", 50, 0),
            feeds_domain=e.get("HUB_FEEDS_DOMAIN", "feeds.example.org") or "feeds.example.org",
            delist_mailbox=e.get("HUB_DELIST_MAILBOX", ""),
            database_url=e.get("HUB_DATABASE_URL", ""),
            worker_database_url=e.get("HUB_WORKER_DATABASE_URL", ""),
            signing_key_file=e.get("HUB_SIGNING_KEY_FILE", ""),
            allow_documentation=_bool(e, "HUB_ALLOW_DOCUMENTATION"),
            trust_proxy=_bool(e, "HUB_TRUST_PROXY"),
            pow_difficulty=_int(e, "HUB_POW_DIFFICULTY", 27, 0, 40),
            enrol_soft_cap=_int(e, "HUB_ENROL_SOFT_CAP", 3, 0),
            enrol_hard_cap=_int(e, "HUB_ENROL_HARD_CAP", 5000, 0),
            enrol_step=_int(e, "HUB_ENROL_STEP", 3, 1),
            challenges_per_prefix=_int(e, "HUB_CHALLENGES_PER_PREFIX", 20, 1),
            unsigned_per_min=_int(e, "HUB_RATE_UNSIGNED_PER_MIN", 10, 1),
            unsigned_per_day=_int(e, "HUB_RATE_UNSIGNED_PER_DAY", 100, 1),
            signed_per_hour=_int(e, "HUB_RATE_SIGNED_PER_HOUR", 60, 1),
            reveals_per_day=_int(e, "HUB_REVEALS_PER_DAY", 2000, 1),
            new_values_per_day=_int(e, "HUB_NEW_VALUES_PER_DAY", 20000, 1),
            min_nodes=_int(e, "HUB_MIN_NODES", 5, 1),
            min_weight=_float(e, "HUB_MIN_WEIGHT", 3.0),
            node_min_age_days=_int(e, "HUB_NODE_MIN_AGE_DAYS", 14, 0),
            node_min_active_days=_int(e, "HUB_NODE_MIN_ACTIVE_DAYS", 7, 0, 14),
            min_reputation=_float(e, "HUB_MIN_REPUTATION", 0.3),
            window_days=_int(e, "HUB_WINDOW_DAYS", 7, 1, 14),
            cohort_max_share=_float(e, "HUB_COHORT_MAX_SHARE", 0.5),
            auto_min_cohorts=_int(e, "HUB_AUTO_MIN_COHORTS", 5, 1),
            obs_retention_days=_int(e, "HUB_OBS_RETENTION_DAYS", 14, 1, 60),
            worker_interval_s=_int(e, "HUB_WORKER_INTERVAL_S", 3600, 5),
            report_mode=mode,
            report_hold_hours=_int(e, "HUB_REPORT_HOLD_HOURS", 24, 0),
            report_daily_cap=_int(e, "HUB_REPORT_DAILY_CAP", 100, 0),
            smtp_host=e.get("HUB_SMTP_HOST", ""),
            smtp_port=_int(e, "HUB_SMTP_PORT", 587, 1, 65535),
            smtp_user=e.get("HUB_SMTP_USER", ""),
            smtp_password=e.get("HUB_SMTP_PASSWORD", ""),
            smtp_from=e.get("HUB_SMTP_FROM", ""),
            smtp_starttls=_bool(e, "HUB_SMTP_STARTTLS", True),
            report_reply_to=e.get("HUB_REPORT_REPLY_TO", ""),
            report_template_file=e.get("HUB_REPORT_TEMPLATE_FILE", ""),
            abuseipdb_key=e.get("HUB_ABUSEIPDB_KEY", ""),
            greynoise_key=e.get("HUB_GREYNOISE_KEY", ""),
        )


def load_signing_key(path: str) -> bytes:
    """The hub's Ed25519 private seed (base64url, 32 bytes) from a secret file."""
    if not path:
        raise ConfigError("HUB_SIGNING_KEY_FILE is not set")
    try:
        text = Path(path).read_text(encoding="ascii").strip()
        seed = sign.b64u_decode(text)
        if len(seed) != 32:
            raise ValueError
        sign.public_key_of(seed)
    except (OSError, ValueError) as exc:
        raise ConfigError("HUB_SIGNING_KEY_FILE does not hold a valid key") from exc
    return seed
