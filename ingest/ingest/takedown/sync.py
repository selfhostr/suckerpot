"""Targets come from sent reports and submitted indicators (design M27 section 3). Database only.

Nothing here talks to the network: it reads reports, their subjects and fetched URLs and writes
``takedown_targets`` rows. A payload URL becomes HTTP-eligible only when the collector already
fetched it and kept a sample (``fetch_targets.status = 'fetched'`` with a hash) and its host is
not an attacking or C2 address; that is the one condition under which the collector may later
re-check it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.takedown.config import TakedownSettings
from ingest.takedown.schedule import first_listing_at

log = logging.getLogger(__name__)

MAX_REPORTS = 200
MAX_CHILDREN_PER_HOST = 20
HOSTILE_DAYS = 30  # a host that attacked us this recently is an attacker, whatever else it serves
DEMOTE_BATCH = 2000
AsnLookup = Callable[[str], tuple[int | None, str | None]]

ROLE_OF_REPORT = {"attack_source": "attack_source", "payload_host": "payload_host", "c2": "c2"}

UPSERT = """
INSERT INTO takedown_targets
    (kind, role, value, target_key, parent_id, fetch_target_id, network_id, asn, country,
     provider_key, provider_name, reported_at, channels, demo, track_until, listing_next_at,
     http_eligible, baseline_sha256, http_next_at)
VALUES
    (:kind, :role, :value, :key, :parent, :fetch, :net, :asn, :country, :pkey, :pname, :rep,
     CAST(:channels AS text[]), :demo, :until, :listing, :elig, :baseline,
     CASE WHEN :elig THEN CAST(:rep AS timestamptz) END)
ON CONFLICT (kind, role, value) DO UPDATE SET
    reported_at = LEAST(takedown_targets.reported_at, EXCLUDED.reported_at),
    track_until = LEAST(takedown_targets.track_until, EXCLUDED.track_until),
    channels = ARRAY(SELECT DISTINCT unnest(takedown_targets.channels || EXCLUDED.channels)
                     ORDER BY 1),
    network_id = COALESCE(takedown_targets.network_id, EXCLUDED.network_id),
    asn = COALESCE(takedown_targets.asn, EXCLUDED.asn),
    country = COALESCE(takedown_targets.country, EXCLUDED.country),
    provider_name = COALESCE(takedown_targets.provider_name, EXCLUDED.provider_name),
    provider_key = CASE WHEN takedown_targets.provider_key LIKE 'recipient:%'
                         OR takedown_targets.provider_key = 'unknown'
                        THEN EXCLUDED.provider_key ELSE takedown_targets.provider_key END,
    fetch_target_id = COALESCE(takedown_targets.fetch_target_id, EXCLUDED.fetch_target_id),
    parent_id = COALESCE(takedown_targets.parent_id, EXCLUDED.parent_id)
RETURNING id
"""

PENDING_REPORTS = """
SELECT r.id AS report_id, r.kind AS report_kind, r.demo, r.sent_at, r.recipient_id,
       s.subject_type, s.value, s.network_id,
       n.asn, n.name AS net_name, n.country, rec.name AS rec_name
FROM (
    SELECT id, kind, demo, sent_at, recipient_id FROM abuse_reports
    WHERE status IN ('sent', 'closed') AND sent_at IS NOT NULL
      AND sent_at > :since AND (NOT demo OR :demo)
      AND NOT EXISTS (SELECT 1 FROM takedown_target_links l WHERE l.report_id = abuse_reports.id)
      AND EXISTS (SELECT 1 FROM abuse_report_subjects x
                  WHERE x.report_id = abuse_reports.id AND x.subject_type IN ('ip', 'domain'))
    ORDER BY sent_at LIMIT :n
) r
JOIN abuse_report_subjects s ON s.report_id = r.id AND s.subject_type IN ('ip', 'domain')
JOIN abuse_recipients rec ON rec.id = r.recipient_id
LEFT JOIN abuse_networks n ON n.id = s.network_id
ORDER BY r.sent_at, r.id
"""

HOST_CHILDREN = """
SELECT t.id AS parent_id, t.reported_at, t.network_id, t.asn, t.country, t.provider_key,
       t.provider_name, t.channels, t.demo, f.id AS fetch_id, f.url, f.last_sha256,
       (SELECT count(*) FROM takedown_targets c WHERE c.parent_id = t.id) AS have
FROM takedown_targets t
JOIN fetch_targets f ON f.host = t.value
WHERE t.role = 'payload_host' AND t.tracking AND NOT t.demo AND t.track_until > :now
  AND f.status = 'fetched' AND f.last_sha256 IS NOT NULL AND char_length(f.url) <= 1024
  AND NOT EXISTS (SELECT 1 FROM takedown_targets c
                  WHERE c.kind = 'url' AND c.role = 'payload_url' AND c.value = f.url)
ORDER BY t.id, f.last_attempt_at DESC NULLS LAST
"""


def target_key(kind: str, value: str) -> str:
    """sha256(kind || ':' || value): a stable key that does not reveal the value (for M29)."""
    return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()


def host_kind(host: str) -> str:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "domain"
    return "ip"


def provider_of(asn: int | None, recipient_id: int | None) -> str:
    if asn is not None:
        return f"as{asn}"
    return f"recipient:{recipient_id}" if recipient_id is not None else "unknown"


@dataclass(frozen=True, slots=True)
class Provider:
    key: str
    name: str | None = None
    asn: int | None = None
    country: str | None = None
    network_id: int | None = None


def _country(value: str | None) -> str | None:
    return value.upper() if value and len(value) == 2 and value.isalpha() else None


def url_host(url: str) -> str:
    """The lower-case host of a URL ('' when it has none)."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


HOSTILE_SQL = """
SELECT h AS host FROM unnest(CAST(:hosts AS text[])) AS h
WHERE EXISTS (SELECT 1 FROM sample_links l
              WHERE l.kind IN ('c2_ip', 'c2_domain') AND l.value = h)
   OR EXISTS (SELECT 1 FROM takedown_targets t
              WHERE t.role IN ('c2', 'attack_source') AND t.value = h)
   OR CASE WHEN h = ANY(CAST(:ips AS text[])) THEN EXISTS (
        SELECT 1 FROM sessions s WHERE s.src_ip = CAST(h AS inet)
          AND s.started_at > CAST(:now AS timestamptz) - make_interval(days => :days))
      ELSE false END
"""


async def hostile_hosts(session: AsyncSession, hosts: list[str], now: datetime) -> set[str]:
    """Which of ``hosts`` are an attacking address seen in the last 30 days, a C2 address of a
    captured sample, or a target we reported as one. Such a host is never contacted (T1): a
    payload URL on it, like a Mirai loader on its own address, is followed by passive signals."""
    unique = sorted({h for h in hosts if h})
    if not unique:
        return set()
    ips = [h for h in unique if host_kind(h) == "ip"]
    rows = await session.execute(
        text(HOSTILE_SQL), {"hosts": unique, "ips": ips, "now": now, "days": HOSTILE_DAYS}
    )
    return {r.host for r in rows}


class TargetSync:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: TakedownSettings,
        asn_lookup: AsnLookup | None = None,
    ) -> None:
        self.factory = factory
        self.s = settings
        self._asn_lookup = asn_lookup
        self._now: datetime | None = None  # the clock of the sync in progress

    async def sync(self, now: datetime) -> dict[str, int]:
        self._now = now
        since = now - timedelta(days=self.s.track_days)
        made = {
            "reports": await self._from_reports(now, since),
            "children": await self._children(now),
            "demoted": await self.demote_hostile(now),
        }
        return made

    # ---- helpers ---------------------------------------------------------------------------
    async def _upsert(
        self,
        session: AsyncSession,
        *,
        kind: str,
        role: str,
        value: str,
        provider: Provider,
        reported_at: datetime,
        channels: list[str],
        demo: bool = False,
        parent: int | None = None,
        fetch_id: int | None = None,
        eligible: bool = False,
        baseline: str | None = None,
    ) -> int:
        if eligible and kind == "url":
            host = url_host(value)
            if not host or host in await hostile_hosts(session, [host], self._now or reported_at):
                eligible, baseline = False, None  # attacker or C2 address: passive signals only
        params: dict[str, Any] = {
            "kind": kind, "role": role, "value": value[:1024], "key": target_key(kind, value),
            "parent": parent, "fetch": fetch_id, "net": provider.network_id,
            "asn": provider.asn, "country": provider.country, "pkey": provider.key[:64],
            "pname": provider.name[:200] if provider.name else None, "rep": reported_at,
            "channels": channels, "demo": demo,
            "until": reported_at + timedelta(days=self.s.track_days),
            "listing": first_listing_at(reported_at), "elig": eligible, "baseline": baseline,
        }  # fmt: skip
        return int((await session.execute(text(UPSERT), params)).scalar_one())

    @staticmethod
    async def _link(
        session: AsyncSession, target: int, *, report: int | None = None, sub: int | None = None
    ) -> None:
        await session.execute(
            text(
                "INSERT INTO takedown_target_links (target_id, report_id, submission_id) "
                "VALUES (:t, :r, :s) ON CONFLICT DO NOTHING"
            ),
            {"t": target, "r": report, "s": sub},
        )

    async def demote_hostile(self, now: datetime) -> int:
        """Stop HTTP re-checks of payload URLs whose host became an attacker or C2 address after
        the target was made. Runs every cycle, so a host that starts attacking later is dropped
        before the next request."""
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT id, value FROM takedown_targets WHERE kind = 'url' "
                        "AND http_eligible AND tracking ORDER BY id LIMIT :n"
                    ),
                    {"n": DEMOTE_BATCH},
                )
            ).all()
            hostile = await hostile_hosts(session, [url_host(r.value) for r in rows], now)
        ids = [r.id for r in rows if not url_host(r.value) or url_host(r.value) in hostile]
        if not ids:
            return 0
        async with self.factory() as session, session.begin():
            await session.execute(
                text("UPDATE takedown_targets SET http_eligible = false WHERE id = ANY(:ids)"),
                {"ids": ids},
            )
        return len(ids)

    # ---- sent reports ----------------------------------------------------------------------
    async def _from_reports(self, now: datetime, since: datetime) -> int:
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(PENDING_REPORTS),
                    {"since": since, "demo": self.s.include_demo, "n": MAX_REPORTS},
                )
            ).all()
        if not rows:
            return 0
        count = 0
        async with self.factory() as session, session.begin():
            for r in rows:
                role = ROLE_OF_REPORT.get(r.report_kind)
                if role is None:
                    continue
                provider = Provider(
                    provider_of(r.asn, r.recipient_id),
                    r.net_name or r.rec_name,
                    r.asn,
                    _country(r.country),
                    r.network_id,
                )
                kind = "ip" if r.subject_type == "ip" else "domain"
                tid = await self._upsert(
                    session,
                    kind=kind,
                    role=role,
                    value=r.value,
                    provider=provider,
                    reported_at=r.sent_at,
                    channels=["mail"],
                    demo=r.demo,
                )
                await self._link(session, tid, report=r.report_id)
                count += 1
        return count

    # ---- URLs a tracked host served ----------------------------------------------------------
    async def _children(self, now: datetime) -> int:
        async with self.factory() as session:
            rows = (await session.execute(text(HOST_CHILDREN), {"now": now})).all()
        count = 0
        taken: dict[int, int] = {}
        async with self.factory() as session, session.begin():
            for r in rows:
                have = r.have + taken.get(r.parent_id, 0)
                if have >= MAX_CHILDREN_PER_HOST:
                    continue
                provider = Provider(r.provider_key, r.provider_name, r.asn, r.country, r.network_id)
                tid = await self._upsert(
                    session,
                    kind="url",
                    role="payload_url",
                    value=r.url,
                    provider=provider,
                    reported_at=r.reported_at,
                    channels=list(r.channels or ["mail"]),
                    parent=r.parent_id,
                    fetch_id=r.fetch_id,
                    eligible=True,
                    baseline=r.last_sha256,
                )
                # The child belongs to the same reports as its host.
                await session.execute(
                    text(
                        "INSERT INTO takedown_target_links (target_id, report_id, submission_id) "
                        "SELECT :c, report_id, submission_id FROM takedown_target_links "
                        "WHERE target_id = :p ON CONFLICT DO NOTHING"
                    ),
                    {"c": tid, "p": r.parent_id},
                )
                taken[r.parent_id] = taken.get(r.parent_id, 0) + 1
                count += 1
        return count

    def _provider_for_host(self, host: str) -> Provider:
        if host_kind(host) == "ip" and self._asn_lookup is not None:
            asn, org = self._asn_lookup(host)
            if asn is not None:
                return Provider(f"as{asn}", org, asn)
        return Provider("unknown")
