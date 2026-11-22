"""The report effect worker (design M38 section 3.5). Database only: it never contacts anything.

``ReportEffectWorker`` runs whenever abuse reporting is on (``ABUSE_REPORTS_ENABLED``), whatever
the takedown tracker does, at most once an hour. Each run does a bounded amount of work, so the
first runs backfill the reports sent in the last 45 days and later runs only follow new ones.

1. ``fill_days``: count the distinct addresses of each finished UTC day (the observation check).
2. ``make_pairs``: for reported attacking addresses whose index day is at least 4 days old, find
   the candidates of the same days that were not reported and match one control each
   (``effect_match``). At most ``MAX_DAYS`` index days and ``MAX_NEW_PAIRS`` sources per run.
3. ``freeze``: when the 7-day window after day 7 (or day 30) is over, record whether each address
   was seen in it, once. At most ``MAX_CHECKS`` pair outcomes per run.
4. ``clear``: drop the addresses 30 days after the 30-day outcome is frozen; prune the holdout.

Reads are indexed: the pool is one aggregate over 13 days of ``sessions`` (``last_event_at``);
an outcome is an index probe on ``(src_ip, sensor, started_at)``. On a copy of a live node (214,000
sessions over 21 days) the pool ran in 0.3 s, the 30-day ASN count in 36 ms, an outcome in 0.1 ms.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.network_names import host_of_target
from suckerpot_db.retention import RetentionError, retention_days
from suckerpot_reporting import SelfTerms

from ingest.abuse.candidates import origin_of_ip
from ingest.abuse.config import DEFAULT_SEVERE_TAGS, AbuseSettings
from ingest.abuse.selfterms import TermsCache
from ingest.features import FeatureSettings, FeatureWorker
from ingest.takedown.effect_match import (
    Source,
    activity_class,
    asn_count_class,
    block_class,
    match,
    recency_bucket,
    volume_bucket,
)

log = logging.getLogger(__name__)
Factory = async_sessionmaker[AsyncSession]

HORIZONS: Final = (7, 30)
WINDOW_DAYS: Final = 7  # an outcome window is the 7 days from T0 + N
MATCH_DAYS: Final = 3  # a control was a candidate within 3 days of the index day
STRATA_DAYS: Final = 7
ASN_DAYS: Final = 30
BACKFILL_DAYS: Final = 45  # never more: addresses are cleared after 67 days at the earliest
MAX_DAYS: Final = 2
MAX_NEW_PAIRS: Final = 500
MAX_CHECKS: Final = 2000
MIN_ADDRESSES: Final = 10  # a day counts as observed with sessions from 10 distinct addresses
MIN_OBSERVED_DAYS: Final = 6  # of the 7 days of a window
CLEAR_AFTER: Final = timedelta(days=30)
UNMATCHED_CLEAR_AFTER: Final = timedelta(days=67)
HOLDOUT_KEEP: Final = timedelta(days=60)
DAYS_LOOKBACK: Final = 60


def day_start(d: date) -> datetime:
    return datetime.combine(d, time.min, UTC)


def utc_day(t: datetime) -> date:
    return t.astimezone(UTC).date()


@dataclass(frozen=True, slots=True)
class EffectConfig:
    severe_tags: tuple[str, ...] = DEFAULT_SEVERE_TAGS
    min_login_attempts: int = 50
    retention_days: int = 90
    include_demo: bool = False  # ABUSE_REPORTS_INCLUDE_DEMO: CI and screenshots only


# ---- 1. observation days --------------------------------------------------------------------

DAY_COUNTS = """
SELECT (started_at AT TIME ZONE 'UTC')::date AS day, count(DISTINCT src_ip) AS n
FROM sessions WHERE started_at >= :lo AND started_at < :hi GROUP BY 1
"""


async def fill_days(factory: Factory, now: datetime, retention_days: int) -> int:
    """Store the distinct addresses of each finished day not stored yet. A stored day never
    changes. Days before the raw retention are not computed (their sessions are gone)."""
    today = utc_day(now)
    first = today - timedelta(days=min(DAYS_LOOKBACK, max(1, retention_days - 1)))
    async with factory() as session:
        have = {
            r.day
            for r in await session.execute(
                text("SELECT day FROM report_effect_days WHERE day >= :d"), {"d": first}
            )
        }
    missing = [
        first + timedelta(days=i)
        for i in range((today - first).days)
        if first + timedelta(days=i) not in have
    ]
    if not missing:
        return 0
    lo, hi = day_start(missing[0]), day_start(missing[-1] + timedelta(days=1))
    async with factory() as session, session.begin():
        counts = {
            r.day: int(r.n) for r in await session.execute(text(DAY_COUNTS), {"lo": lo, "hi": hi})
        }
        for d in missing:
            await session.execute(
                text(
                    "INSERT INTO report_effect_days (day, addresses) VALUES (:d, :n) "
                    "ON CONFLICT (day) DO NOTHING"
                ),
                {"d": d, "n": counts.get(d, 0)},
            )
    return len(missing)


def observed(days: Mapping[date, int], index_day: date, horizon: int) -> bool:
    """At least 6 of the 7 days of the window had sessions from 10 distinct addresses."""
    first = index_day + timedelta(days=horizon)
    up = sum(
        1 for i in range(WINDOW_DAYS) if days.get(first + timedelta(days=i), 0) >= MIN_ADDRESSES
    )
    return up >= MIN_OBSERVED_DAYS


# ---- 2. pairs -------------------------------------------------------------------------------

# The units: every attacking address named in a sent report, with the time of its first send.
# A report counts as sent when it is marked sent (by SMTP, by hand, or later as a submitted form),
# or when one of its SMTP send requests succeeded. Takedown targets, when the tracker runs, add
# nothing new but are read too (their ``reported_at`` is the same first send). Demo reports never
# count. ``{kind}`` is the attack-source test: per subject once subjects carry a kind (daily
# digests hold several kinds), else per report.
PENDING = """
WITH units AS (
    SELECT s.value, r.sent_at AS t0
    FROM abuse_reports r
    JOIN abuse_report_subjects s ON s.report_id = r.id AND s.subject_type = 'ip'
    WHERE r.status IN ('sent', 'closed') AND r.sent_at IS NOT NULL AND NOT r.demo AND {kind}
    UNION ALL
    SELECT s.value, q.done_at AS t0
    FROM abuse_send_requests q
    JOIN abuse_reports r ON r.id = q.report_id
    JOIN abuse_report_subjects s ON s.report_id = r.id AND s.subject_type = 'ip'
    WHERE q.kind = 'send' AND q.status = 'sent' AND q.done_at IS NOT NULL AND NOT r.demo
      AND {kind}
    UNION ALL
    SELECT t.value, t.reported_at AS t0 FROM takedown_targets t
    WHERE t.role = 'attack_source' AND t.kind = 'ip' AND NOT t.demo
),
firsts AS (SELECT value, min(t0) AS t0 FROM units GROUP BY value)
SELECT f.value, f.t0 FROM firsts f
WHERE f.t0 >= :oldest AND f.t0 < :newest
  AND NOT EXISTS (SELECT 1 FROM report_effect_pairs p
                  WHERE p.reported_value = CAST(f.value AS inet))
  AND NOT EXISTS (SELECT 1 FROM report_effect_unmatched u
                  WHERE u.value = CAST(f.value AS inet))
ORDER BY f.t0, f.value
LIMIT :n
"""
KIND_PER_SUBJECT = "COALESCE(s.kind, r.kind) = 'attack_source'"
KIND_PER_REPORT = "r.kind = 'attack_source'"
SUBJECT_KIND = """
SELECT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'abuse_report_subjects'
                 AND column_name = 'kind')
"""


async def pending_sql(session: AsyncSession) -> str:
    per_subject = bool(await session.scalar(text(SUBJECT_KIND)))
    return PENDING.format(kind=KIND_PER_SUBJECT if per_subject else KIND_PER_REPORT)


# Per address and UTC day, then per 7-day window ending on each day from D-3 to D+3: the same
# rules as candidates.attack_sources. Returns the addresses that passed on one of those days (or
# that are among the reported ones) with their strata over the window ending on D.
POOL = """
WITH d AS (
    SELECT src_ip, (last_event_at AT TIME ZONE 'UTC')::date AS day,
           sum(login_attempts) AS logins,
           bool_or(login_success AND commands > 0) AS logcmd,
           sum(downloads) AS downloads,
           bool_or(tags && CAST(:severe AS text[])
                   OR EXISTS (SELECT 1 FROM unnest(tags) AS t WHERE t LIKE 'cve-%')) AS severe,
           sum(event_count) AS events, max(asn) AS asn, max(country) AS country
    FROM sessions
    WHERE NOT benign AND scanner_name IS NULL
      AND last_event_at >= :lo AND last_event_at < :hi
    GROUP BY 1, 2
),
w AS (
    SELECT d.src_ip, e.day::date AS end_day,
           sum(d.logins) AS logins, bool_or(d.logcmd) AS logcmd,
           sum(d.downloads) AS downloads, bool_or(d.severe) AS severe,
           sum(d.events) AS events, max(d.day) AS last_day,
           max(d.asn) AS asn, max(d.country) AS country
    FROM d
    JOIN generate_series(CAST(:e_from AS date), CAST(:e_to AS date), INTERVAL '1 day') AS e(day)
      ON d.day BETWEEN e.day::date - 6 AND e.day::date
    GROUP BY d.src_ip, e.day
)
SELECT host(src_ip) AS ip,
       max(logins) FILTER (WHERE end_day = :d0) AS logins,
       bool_or(logcmd) FILTER (WHERE end_day = :d0) AS logcmd,
       max(downloads) FILTER (WHERE end_day = :d0) AS downloads,
       bool_or(severe) FILTER (WHERE end_day = :d0) AS severe,
       max(events) FILTER (WHERE end_day = :d0) AS events,
       max(last_day) FILTER (WHERE end_day = :d0) AS last_day,
       max(asn) FILTER (WHERE end_day = :d0) AS asn,
       max(country) FILTER (WHERE end_day = :d0) AS country
FROM w
GROUP BY src_ip
HAVING bool_or(end_day = :d0)
   AND (bool_or(logins >= :min_logins OR logcmd OR downloads > 0 OR severe)
        OR host(src_ip) = ANY(CAST(:reported AS text[])))
"""

BLOCKS = """
SELECT l.subject, masklen(n.cidr) AS bits, family(n.cidr) AS fam
FROM abuse_lookups l JOIN abuse_networks n ON n.id = l.network_id
WHERE l.subject = ANY(CAST(:vals AS text[])) AND n.cidr IS NOT NULL
"""

ASN_COUNTS = """
SELECT asn, count(DISTINCT src_ip) AS n FROM sessions
WHERE asn = ANY(CAST(:asns AS integer[])) AND started_at >= :lo AND started_at < :hi
GROUP BY asn
"""

# Every address this node ever reported (a sent report of any kind names it).
REPORTED = """
SELECT DISTINCT s.value FROM abuse_report_subjects s
JOIN abuse_reports r ON r.id = s.report_id
WHERE s.subject_type = 'ip' AND s.value = ANY(CAST(:vals AS text[]))
  AND r.status IN ('sent', 'closed') AND r.sent_at IS NOT NULL
"""

USED_CONTROLS = """
SELECT host(control_value) AS v FROM report_effect_pairs
WHERE control_value = ANY(CAST(CAST(:vals AS text[]) AS inet[]))
"""

HELD = """
SELECT host(value) AS v FROM abuse_holdouts
WHERE held AND value = ANY(CAST(CAST(:vals AS text[]) AS inet[]))
  AND chosen_at >= :lo AND chosen_at < :hi
"""

NETWORK = """
SELECT value, min(reported_day) AS first_day FROM network_targets
WHERE state IN ('reported', 'taken_down') AND value IS NOT NULL
  AND kind IN ('ip', 'c2_ip') AND reported_day IS NOT NULL AND reported_day >= :since
GROUP BY value
"""

INSERT_PAIR = """
INSERT INTO report_effect_pairs
    (index_at, reported_value, control_value, tier, activity_class, volume_bucket, recency_bucket)
VALUES (:t0, CAST(CAST(:r AS text) AS inet), CAST(CAST(:c AS text) AS inet),
        :tier, :act, :vol, :rec)
ON CONFLICT DO NOTHING
"""

INSERT_UNMATCHED = """
INSERT INTO report_effect_unmatched (index_at, value, reason)
VALUES (:t0, CAST(CAST(:v AS text) AS inet), :why)
ON CONFLICT DO NOTHING
"""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def network_days(session: AsyncSession, since: date) -> dict[str, date]:
    """Hosts the network reported (or took down) since ``since``, with the first report day."""
    out: dict[str, date] = {}
    for r in await session.execute(text(NETWORK), {"since": since}):
        host = host_of_target(str(r.value))
        if host not in out or r.first_day < out[host]:
            out[host] = r.first_day
    return out


def network_hit(days: Mapping[str, date], value: str, lo: date, hi: date) -> bool:
    d = days.get(value.lower())
    return d is not None and lo <= d <= hi


def source_of(
    row: Any, index_day: date, sizes: Mapping[str, tuple[int, int]], held: bool
) -> Source | None:
    """The strata of one pool row, or None without activity in the strata window."""
    if row.events is None or row.last_day is None:
        return None
    recency = recency_bucket((index_day - row.last_day).days)
    if recency is None:
        return None
    return Source(
        value=row.ip,
        activity=activity_class(
            logins=int(row.logins or 0),
            login_commands=bool(row.logcmd),
            downloads=int(row.downloads or 0),
            severe=bool(row.severe),
        ),
        volume=volume_bucket(int(row.events)),
        recency=recency,
        asn=row.asn,
        country=row.country,
        size=sizes.get(row.ip, (block_class(None, ipv6=False), asn_count_class(None))),
        held=held,
    )


async def _pool(
    session: AsyncSession, index_day: date, reported: Sequence[str], cfg: EffectConfig
) -> list[Any]:
    lo = day_start(index_day - timedelta(days=MATCH_DAYS + STRATA_DAYS - 1))
    hi = day_start(index_day + timedelta(days=MATCH_DAYS + 1))
    return list(
        (
            await session.execute(
                text(POOL),
                {
                    "lo": lo, "hi": hi, "d0": index_day,
                    "e_from": index_day - timedelta(days=MATCH_DAYS),
                    "e_to": index_day + timedelta(days=MATCH_DAYS),
                    "severe": list(cfg.severe_tags), "min_logins": cfg.min_login_attempts,
                    "reported": list(reported),
                },
            )
        ).all()
    )  # fmt: skip


async def _sizes(
    session: AsyncSession, index_day: date, rows: Sequence[Any]
) -> dict[str, tuple[int, int]]:
    vals = [r.ip for r in rows]
    blocks: dict[str, int] = {}
    for b in await session.execute(text(BLOCKS), {"vals": vals}):
        blocks[b.subject] = block_class(int(b.bits), ipv6=int(b.fam) == 6)
    asns = sorted({int(r.asn) for r in rows if r.asn is not None})
    counts: dict[int, int] = {}
    if asns:
        for a in await session.execute(
            text(ASN_COUNTS),
            {
                "asns": asns,
                "lo": day_start(index_day - timedelta(days=ASN_DAYS - 1)),
                "hi": day_start(index_day + timedelta(days=1)),
            },
        ):
            counts[int(a.asn)] = int(a.n)
    return {
        r.ip: (
            blocks.get(r.ip, block_class(None, ipv6=False)),
            asn_count_class(counts.get(int(r.asn)) if r.asn is not None else None),
        )
        for r in rows
    }


async def pair_day(
    factory: Factory,
    index_day: date,
    units: Sequence[tuple[str, datetime]],
    terms: SelfTerms,
    cfg: EffectConfig,
) -> dict[str, int]:
    """Pair the reported addresses whose index day is ``index_day``. Every unit ends as a pair or
    as an unmatched row, so a day is never processed twice."""
    reported = [v for v, _ in units]
    t0_of = dict(units)
    async with factory() as session:
        rows = await _pool(session, index_day, reported, cfg)
        sizes = await _sizes(session, index_day, rows)
        others = [r.ip for r in rows if r.ip not in t0_of]
        ever = {r.value for r in await session.execute(text(REPORTED), {"vals": others})}
        used = {r.v for r in await session.execute(text(USED_CONTROLS), {"vals": others})}
        held = {
            r.v
            for r in await session.execute(
                text(HELD),
                {
                    "vals": others,
                    "lo": day_start(index_day - timedelta(days=MATCH_DAYS)),
                    "hi": day_start(index_day + timedelta(days=MATCH_DAYS + 1)),
                },
            )
        }
        net = await network_days(session, index_day - timedelta(days=30))
    net_lo, net_hi = index_day - timedelta(days=30), index_day + timedelta(days=MATCH_DAYS + 1)
    by_ip = {r.ip: r for r in rows}
    pool: list[Source] = []
    for r in rows:
        v = r.ip
        if v in t0_of or v in ever or v in used:
            continue
        if origin_of_ip(v, terms, include_demo=cfg.include_demo) is None:
            continue  # the never list, self terms, private (and documentation) ranges
        if network_hit(net, v, net_lo, net_hi):
            continue
        src = source_of(r, index_day, sizes, v in held)
        if src is not None:
            pool.append(src)
    candidates: list[Source] = []
    unmatched: list[tuple[str, str]] = []
    for v, t0 in sorted(units, key=lambda u: (u[1], u[0])):
        if network_hit(net, v, net_lo, utc_day(t0)):
            unmatched.append((v, "network_reported"))
            continue
        row = by_ip.get(v)
        src = source_of(row, index_day, sizes, False) if row is not None else None
        if src is None:
            unmatched.append((v, "no_activity"))
            continue
        candidates.append(src)
    pairs, left = match(candidates, pool)
    unmatched += [(s.value, "no_control") for s in left]
    async with factory() as session, session.begin():
        for p in pairs:
            await session.execute(
                text(INSERT_PAIR),
                {
                    "t0": t0_of[p.reported.value], "r": p.reported.value, "c": p.control.value,
                    "tier": p.tier, "act": p.reported.activity, "vol": p.reported.volume,
                    "rec": p.reported.recency,
                },
            )  # fmt: skip
        for v, why in unmatched:
            await session.execute(text(INSERT_UNMATCHED), {"t0": t0_of[v], "v": v, "why": why})
    tiers: dict[str, int] = defaultdict(int)
    for p in pairs:
        tiers[f"pairs_{p.tier}"] += 1
    return {"pairs": len(pairs), "unmatched": len(unmatched), **tiers}


async def make_pairs(
    factory: Factory, now: datetime, terms: SelfTerms, cfg: EffectConfig
) -> dict[str, int]:
    today = utc_day(now)
    back = min(BACKFILL_DAYS, cfg.retention_days - (MATCH_DAYS + STRATA_DAYS))
    if back <= MATCH_DAYS:
        return {}
    async with factory() as session:
        units = (
            await session.execute(
                text(await pending_sql(session)),
                {
                    "oldest": day_start(today - timedelta(days=back)),
                    "newest": day_start(today - timedelta(days=MATCH_DAYS)),
                    "n": MAX_NEW_PAIRS,
                },
            )
        ).all()
    by_day: dict[date, list[tuple[str, datetime]]] = defaultdict(list)
    for u in units:
        if _is_ip(u.value):
            by_day[utc_day(u.t0)].append((u.value, u.t0))
    out: dict[str, int] = defaultdict(int)
    for d in sorted(by_day)[:MAX_DAYS]:
        for k, n in (await pair_day(factory, d, by_day[d], terms, cfg)).items():
            out[k] += n
    return dict(out)


# ---- 3. outcomes ----------------------------------------------------------------------------

DUE = """
SELECT id, index_at, host(reported_value) AS r, host(control_value) AS c
FROM report_effect_pairs
WHERE frozen_{h}_at IS NULL AND index_at <= :due
  AND reported_value IS NOT NULL AND control_value IS NOT NULL
ORDER BY index_at, id
LIMIT :n
"""

SEEN = """
SELECT EXISTS (SELECT 1 FROM sessions
               WHERE src_ip = CAST(CAST(:v AS text) AS inet)
                 AND started_at >= :lo AND started_at < :hi)
"""

CONTROL_REPORTED = """
SELECT EXISTS (SELECT 1 FROM abuse_report_subjects s JOIN abuse_reports r ON r.id = s.report_id
               WHERE s.subject_type = 'ip' AND s.value = :v
                 AND r.status IN ('sent', 'closed') AND r.sent_at IS NOT NULL
                 AND r.sent_at < :until)
"""

FREEZE = """
UPDATE report_effect_pairs
SET seen_r_{h} = :sr, seen_c_{h} = :sc, observed_{h} = :obs, excluded_{h} = :ex,
    frozen_{h}_at = :now
WHERE id = :id AND frozen_{h}_at IS NULL
"""


async def freeze(factory: Factory, now: datetime) -> dict[str, int]:
    """Freeze the outcomes whose window is over. "Seen" is any session of the address on any
    sensor in the 7 days from T0 + N; scans count too."""
    budget = MAX_CHECKS
    out: dict[str, int] = defaultdict(int)
    async with factory() as session:
        days = {r.day: int(r.addresses) for r in await session.execute(
            text("SELECT day, addresses FROM report_effect_days WHERE day >= :d"),
            {"d": utc_day(now) - timedelta(days=BACKFILL_DAYS + 60)},
        )}  # fmt: skip
        net = await network_days(session, utc_day(now) - timedelta(days=BACKFILL_DAYS + 90))
    for h in HORIZONS:
        if budget <= 0:
            break
        due_before = now - timedelta(days=h + WINDOW_DAYS)
        async with factory() as session:
            rows = (
                await session.execute(text(DUE.format(h=h)), {"due": due_before, "n": budget})
            ).all()
        budget -= len(rows)
        for p in rows:
            t0: datetime = p.index_at
            d0 = utc_day(t0)
            lo = t0 + timedelta(days=h)
            hi = lo + timedelta(days=WINDOW_DAYS)
            async with factory() as session, session.begin():
                excluded: str | None = None
                seen_r: bool | None = None
                seen_c: bool | None = None
                if await session.scalar(text(CONTROL_REPORTED), {"v": p.c, "until": hi}):
                    excluded = "control_reported"
                elif any(
                    network_hit(net, v, d0 - timedelta(days=30), utc_day(hi)) for v in (p.r, p.c)
                ):
                    excluded = "network_reported"
                ok = observed(days, d0, h)
                if excluded is None and not ok:
                    excluded = "not_observed"
                if excluded is None:
                    seen_r = bool(await session.scalar(text(SEEN), {"v": p.r, "lo": lo, "hi": hi}))
                    seen_c = bool(await session.scalar(text(SEEN), {"v": p.c, "lo": lo, "hi": hi}))
                await session.execute(
                    text(FREEZE.format(h=h)),
                    {"sr": seen_r, "sc": seen_c, "obs": ok, "ex": excluded, "now": now, "id": p.id},
                )
            out[f"frozen_{h}"] += 1
            if excluded is not None:
                out[f"excluded_{h}_{excluded}"] += 1
    return dict(out)


# ---- 4. clean-up ----------------------------------------------------------------------------


async def clear(factory: Factory, now: datetime) -> int:
    """Clear the addresses once nothing needs them; the counts stay. Prune old holdout rows."""
    async with factory() as session, session.begin():
        pairs = await session.execute(
            text(
                "UPDATE report_effect_pairs SET reported_value = NULL, control_value = NULL, "
                "cleared_at = :now WHERE cleared_at IS NULL AND frozen_30_at < :before"
            ),
            {"now": now, "before": now - CLEAR_AFTER},
        )
        await session.execute(
            text(
                "UPDATE report_effect_unmatched SET value = NULL "
                "WHERE value IS NOT NULL AND index_at < :before"
            ),
            {"before": now - UNMATCHED_CLEAR_AFTER},
        )
        await session.execute(
            text("DELETE FROM abuse_holdouts WHERE release_at < :before"),
            {"before": now - HOLDOUT_KEEP},
        )
    return int(getattr(pairs, "rowcount", 0) or 0)


async def run(
    factory: Factory, now: datetime, terms: SelfTerms | None, cfg: EffectConfig
) -> dict[str, int]:
    """One bounded run. Without the self terms no pair is made (they decide who may be a
    control); outcomes and the clean-up still run."""
    out: dict[str, int] = {"days": await fill_days(factory, now, cfg.retention_days)}
    if terms is not None:
        out.update(await make_pairs(factory, now, terms, cfg))
    out.update(await freeze(factory, now))
    out["cleared"] = await clear(factory, now)
    return out


# ---- the worker -----------------------------------------------------------------------------


class ReportEffectWorker(FeatureWorker):
    """Runs the measure once an hour while abuse reporting is on. Reads only this node's own
    reports and sessions: no lookup, no egress, and no address leaves the node."""

    name = "report_effect"
    interval_s = 3_600.0
    start_delay_s = 300.0  # not while the stack starts: caches are cold

    def __init__(
        self,
        settings: FeatureSettings,
        factory: Factory | None = None,
        *,
        terms: TermsCache | None = None,
        env: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__(settings, enabled=settings.abuse_enabled)
        self.factory = factory
        self.terms = terms
        self._clock = clock
        self.cfg = EffectConfig()
        self.holdout_pct = 0
        self.counters: dict[str, int] = {}
        if self.enabled:
            # The same candidate rules as the abuse worker, so controls are chosen like reports.
            e = os.environ if env is None else env
            abuse = AbuseSettings.from_env(e)
            self.cfg = EffectConfig(
                severe_tags=abuse.severe_tags,
                min_login_attempts=abuse.min_login_attempts,
                retention_days=_retention(e),
                include_demo=abuse.include_demo,
            )
            self.holdout_pct = abuse.holdout_pct

    async def run_once(self) -> None:
        if self.factory is None:
            return
        terms = await self.terms.get() if self.terms is not None else None
        for key, n in (await run(self.factory, self._clock(), terms, self.cfg)).items():
            self.counters[key] = self.counters.get(key, 0) + n

    async def status(self) -> dict[str, Any]:
        base = await super().status()
        base[self.name].update(self.counters)
        base[self.name]["holdout_pct"] = self.holdout_pct
        return base


def _retention(env: Mapping[str, str]) -> int:
    try:
        return retention_days(env)
    except RetentionError:
        return 90
