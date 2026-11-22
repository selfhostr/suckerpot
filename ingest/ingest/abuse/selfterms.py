"""The deny set: learning the monitored system's address, loading ``SelfTerms`` (design 7.1).

No event stores a destination address and the stack must not ask an outside service for it.
Scanners that address a server by its IP put that IP in the HTTP ``Host`` header or the SIP
request URI, so the worker reads those fields from recent events and counts distinct sources.
A value seen from three sources within a week counts as confirmed (``load_self_terms`` applies
the threshold to ``distinct_sources``). A false positive only over-redacts, which is the safe
direction. Values are never logged.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import time
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_reporting import SelfTermRow, SelfTerms, load_self_terms

log = logging.getLogger(__name__)

SCAN_LIMIT = 20_000
CANDIDATE_CAP = 50
CACHE_S = 60.0
_HOSTLIKE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
)
_SIP_HOST = re.compile(r"(?i)\bsips?:(?:[^@/;\s>]*@)?([^:;/\s>?]+)")
_IGNORED = frozenset({"localhost"})


# Words a report or its renderers use. A name made of them can never be "ours": learning it
# would hide ordinary evidence (and lets an attacker steer what is redacted).
VOCABULARY = frozenset(
    "abuse report reports failed login logins ssh telnet http https exploit download command "
    "username usernames password agent user-agent address network source ports port tcp udp "
    "example localhost root admin test unknown none null".split()
)
LEARNED_CAP = 200
MIN_NETWORKS = 2  # distinct /24 (IPv4) or /48 (IPv6) source networks before a candidate is stored
PER_SOURCE_ROWS = 20
FRESH_HOURS = 72
# An auto-confirmed address only opens the fail-closed guards after it was named on this many
# distinct UTC days. Planting a decoy needs sources from two networks, which is cheap for one
# burst; three separate days makes steering the guard a sustained campaign, while the real
# address (every scanner that hits the node by IP names it) reaches three days within a week.
MIN_LEARNED_DAYS = 3
DAYS_WINDOW = 14

# SQL that extracts the host the same way ``hosts_of`` does (exact match, no substring search).
_SIP_RE = r"sips?:(?:[^@/;[:space:]>]*@)?([^:;/[:space:]>?]+)"
_HOST_EXPR = (
    "lower(split_part(data->>'host', ':', 1)) = :v "
    f"OR lower((regexp_match(data->>'request_uri', '{_SIP_RE}', 'i'))[1]) = :v "
    f"OR lower((regexp_match(data->>'to', '{_SIP_RE}', 'i'))[1]) = :v"
)


def _classify(raw: str) -> tuple[str, str] | None:
    """``(kind, value)`` for a public address or a dotted name, else None."""
    value = raw.strip().strip("[]").lower().rstrip(".")
    if not value or len(value) > 253:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        if value in _IGNORED or not _HOSTLIKE.match(value) or value.rsplit(".", 1)[-1].isdigit():
            return None
        labels = set(value.split("."))
        if labels & VOCABULARY or value in VOCABULARY:
            return None
        return "name", value
    if not addr.is_global or addr.is_multicast:
        return None  # private and documentation addresses are already forbidden / are demo values
    return "address", str(addr)


def hosts_of(data: Mapping[str, Any]) -> set[tuple[str, str]]:
    """Terms named by the destination fields of one event's data."""
    found: set[tuple[str, str]] = set()
    host = data.get("host")
    if isinstance(host, str):
        h = host.strip()
        if h.count(":") == 1:
            h = h.split(":", 1)[0]
        if (c := _classify(h)) is not None:
            found.add(c)
    for key in ("request_uri", "to"):
        val = data.get(key)
        if isinstance(val, str) and (m := _SIP_HOST.search(val[:300])):
            if (c := _classify(m.group(1))) is not None:
                found.add(c)
    return found


def source_network(ip: str) -> str:
    """The /24 (IPv4) or /48 (IPv6) a source belongs to: one scanner farm counts once."""
    addr = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network((addr, 24 if addr.version == 4 else 48), strict=False))


def count_sources(rows: Iterable[tuple[str, Mapping[str, Any]]]) -> dict[tuple[str, str], int]:
    """Distinct source networks per term."""
    seen: dict[tuple[str, str], set[str]] = defaultdict(set)
    for src, data in rows:
        try:
            net = source_network(src)
        except ValueError:
            continue
        for term in hosts_of(data):
            seen[term].add(net)
    return {term: len(nets) for term, nets in seen.items()}


_INDICATOR_HOST = "UNION ALL SELECT 1 FROM indicators WHERE host = :v "


async def _known_infrastructure(
    session: AsyncSession, kind: str, value: str, *, refresh: bool = False
) -> bool:
    """True for something that attacked us or that a report names: never ours.

    ``refresh`` is the check for an address that is already a learned row. Attackers name the
    address of the machine they attack in their commands (``wget http://<it>/x``), so an
    indicator with that host says nothing against a learned own address: only a new candidate is
    checked against the indicators. Without this, one such command stopped the refresh for good
    and the address expired after ``FRESH_HOURS``.
    """
    attacked = (
        "SELECT 1 FROM sessions WHERE src_ip = CAST(:ip AS inet) "
        "UNION ALL SELECT 1 FROM events WHERE src_ip = CAST(:ip AS inet) "
        "AND ts >= now() - interval '7 days' "
        "UNION ALL SELECT 1 FROM abuse_report_subjects WHERE value = :v "
    )
    sql = (
        (attacked + "LIMIT 1" if refresh else attacked + _INDICATOR_HOST + "LIMIT 1")
        if kind == "address"
        else "SELECT 1 FROM abuse_report_subjects WHERE value = :v OR value LIKE '%.' || :v "
        "UNION ALL SELECT 1 FROM indicators WHERE host = :v OR host LIKE '%.' || :v LIMIT 1"
    )
    params = {"v": value, "ip": value} if kind == "address" else {"v": value}
    return (await session.execute(text(sql), params)).first() is not None


async def learn(factory: async_sessionmaker[AsyncSession], now: datetime | None = None) -> int:
    """Scan the last hour, recount candidates over seven days, upsert. Returns terms touched.

    Rows are stored unconfirmed: only the owner confirms a learned term (in the UI), and only a
    confirmed, recent address counts as "the monitored system's address".
    """
    moment = now or datetime.now(UTC)
    async with factory() as session:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT src, h, u, t FROM (
                        SELECT d.*, row_number() OVER (PARTITION BY src ORDER BY h, u, t) AS rn
                        FROM (
                            SELECT DISTINCT ON (src_ip, data->>'host', data->>'request_uri',
                                                data->>'to')
                                   host(src_ip) AS src, data->>'host' AS h,
                                   data->>'request_uri' AS u, data->>'to' AS t
                            FROM events
                            WHERE ts >= :since AND ts < :until
                              AND sensor IN ('web', 'synology', 'sip')
                              AND (data ? 'host' OR data ? 'request_uri' OR data ? 'to')
                            ORDER BY src_ip, data->>'host', data->>'request_uri', data->>'to'
                        ) d
                    ) x WHERE rn <= :per LIMIT :lim
                    """
                ),
                {"since": moment - timedelta(hours=1), "until": moment,
                 "per": PER_SOURCE_ROWS, "lim": SCAN_LIMIT},
            )
        ).all()  # fmt: skip
    hourly = count_sources((r.src, {"host": r.h, "request_uri": r.u, "to": r.t}) for r in rows)
    best = sorted(hourly.items(), key=lambda kv: -kv[1])[:CANDIDATE_CAP]
    touched = 0
    for (kind, value), _n in best:
        async with factory() as session, session.begin():
            existing = (
                await session.execute(
                    text("SELECT source FROM report_self_terms WHERE kind = :k AND value = :v"),
                    {"k": kind, "v": value},
                )
            ).first()
            if existing is not None and existing.source != "learned":
                continue  # the owner's (or a sensor's) entry is authoritative
            refresh = existing is not None and kind == "address"
            if await _known_infrastructure(session, kind, value, refresh=refresh):
                continue
            week = (
                await session.execute(
                    text(
                        f"""
                        SELECT count(DISTINCT network(set_masklen(src_ip,
                                   CASE family(src_ip) WHEN 4 THEN 24 ELSE 48 END)))
                        FROM events
                        WHERE ts >= :since AND sensor IN ('web', 'synology', 'sip')
                          AND ({_HOST_EXPR})
                        """  # noqa: S608  (constant fragments only, the value is bound)
                    ),
                    {"since": moment - timedelta(days=7), "v": value},
                )
            ).scalar_one()
            if int(week) < MIN_NETWORKS:
                continue
            if existing is None:
                total = (
                    await session.execute(
                        text("SELECT count(*) FROM report_self_terms WHERE source = 'learned'")
                    )
                ).scalar_one()
                if total >= LEARNED_CAP:
                    continue
            await session.execute(
                text(
                    """
                    INSERT INTO report_self_terms (kind, value, source, distinct_sources)
                    VALUES (:k, :v, 'learned', :n)
                    ON CONFLICT (kind, value) DO UPDATE SET last_seen = now(),
                        distinct_sources = GREATEST(report_self_terms.distinct_sources, :n)
                    """
                ),
                {"k": kind, "v": value, "n": int(week)},
            )
            touched += 1
    return touched


async def self_address_state(factory: async_sessionmaker[AsyncSession]) -> dict[str, Any]:
    """What the UI shows when no fresh self address exists: reports stay blocked until then."""
    async with factory() as session:
        row = (
            await session.execute(
                text(
                    """
                    SELECT
                      count(*) FILTER (WHERE kind IN ('address', 'cidr') AND (
                          source = 'manual' OR (source = 'learned' AND confirmed
                          AND last_seen > now() - make_interval(hours => :h)))) AS active,
                      count(*) FILTER (WHERE source = 'learned' AND NOT confirmed) AS pending
                    FROM report_self_terms
                    """
                ),
                {"h": FRESH_HOURS},
            )
        ).one()
    return {"self_address_fresh": row.active > 0, "self_terms_pending": row.pending}


def auto_confirm_enabled(env: Mapping[str, str] | None = None) -> bool:
    """``SELF_TERMS_AUTO_CONFIRM``, honoured in participant mode only (M32 section 8.4)."""
    e = os.environ if env is None else env
    if e.get("SUCKERPOT_STACK_MODE", "").strip().lower() != "participant":
        return False
    return e.get("SELF_TERMS_AUTO_CONFIRM", "false").strip().lower() in ("1", "true", "yes", "on")


def parse_self_address(raw: str) -> str | None:
    """The canonical address of ``SELF_ADDRESS``, or ``None`` when it is empty or not an address."""
    value = raw.strip().strip("[]")
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
        return None
    return str(addr)


def effective_rows(
    rows: Iterable[SelfTermRow],
    env: Mapping[str, str],
    learned_days: Mapping[str, int] | None = None,
) -> list[SelfTermRow]:
    """The table rows plus what the environment adds in participant mode (M32 section 8.4).

    The ingest role cannot confirm a row or write a ``manual`` one (the owner's decision lives in
    the database), so both happen in memory only:

    * ``SELF_TERMS_AUTO_CONFIRM``: a learned *address* row (it already passed the learning
      thresholds) acts as confirmed once it was named on ``MIN_LEARNED_DAYS`` distinct days
      (``learned_days``, address to day count). Before that it is only redacted (as a literal
      text term) and does not count as a known self address, so a decoy planted in a burst of
      ``Host:`` headers cannot open the fail-closed guards. Names never auto-confirm (M13).
    * ``SELF_ADDRESS``: a ``manual`` address that never expires and always counts.
    """
    days = learned_days or {}
    out: list[SelfTermRow] = []
    for r in rows:
        if (
            auto_confirm_enabled(env)
            and r.source == "learned"
            and r.kind == "address"
            and not r.confirmed
        ):
            if days.get(r.value, 0) >= MIN_LEARNED_DAYS:
                out.append(r.model_copy(update={"confirmed": True}))
            else:
                out.append(r)
                out.append(SelfTermRow(kind="text", value=r.value, source="manual", confirmed=True))
            continue
        out.append(r)
    address = parse_self_address(env.get("SELF_ADDRESS", ""))
    if address is not None:
        out.append(SelfTermRow(kind="address", value=address, source="manual", confirmed=True))
    return out


async def learned_address_days(
    factory: async_sessionmaker[AsyncSession], addresses: Iterable[str], now: datetime | None = None
) -> dict[str, int]:
    """Distinct UTC days (last ``DAYS_WINDOW``) on which each address was named as a destination."""
    moment = now or datetime.now(UTC)
    out: dict[str, int] = {}
    async with factory() as session:
        for value in addresses:
            out[value] = int(
                (
                    await session.execute(
                        text(
                            f"""
                            SELECT count(DISTINCT (ts AT TIME ZONE 'UTC')::date) FROM events
                            WHERE ts >= :since AND sensor IN ('web', 'synology', 'sip')
                              AND ({_HOST_EXPR})
                            """  # noqa: S608  (constant fragments only, the value is bound)
                        ),
                        {"since": moment - timedelta(days=DAYS_WINDOW), "v": value},
                    )
                ).scalar_one()
            )
    return out


class TermsCache:
    """``SelfTerms`` rebuilt at most once a minute. ``None`` when the table cannot be read."""

    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        env: Mapping[str, str] | None = None,
        *,
        with_pseudonym: bool = False,
    ) -> None:
        self.factory = factory
        self.env = dict(os.environ if env is None else env)
        # The network pseudonym is a deny term for abuse reports only (M38). The network worker,
        # which checks and sends the pseudonym itself, keeps the default.
        self.with_pseudonym = with_pseudonym
        self._terms: SelfTerms | None = None
        self._at = 0.0

    async def get(self) -> SelfTerms | None:
        if self._terms is not None and time.monotonic() - self._at < CACHE_S:
            return self._terms
        try:
            async with self.factory() as session:
                rows = (
                    await session.execute(
                        text(
                            "SELECT kind, value, source, distinct_sources, confirmed, last_seen "
                            "FROM report_self_terms"
                        )
                    )
                ).all()
                egress = (
                    await session.execute(
                        text(
                            "SELECT detail->>'egress_ip' AS ip FROM enrichment_status "
                            "WHERE name = 'egress'"
                        )
                    )
                ).first()
                # The node's public network pseudonym (M29) never goes into a report (M38).
                names = (
                    (
                        await session.execute(
                            text("SELECT pseudonym, synced_pseudonym FROM network_membership")
                        )
                    ).all()
                    if self.with_pseudonym
                    else []
                )
        except Exception as exc:
            log.warning("self terms unavailable (%s)", type(exc).__name__)
            self._terms = None
            return None
        table = [
            SelfTermRow(
                kind=r.kind,
                value=r.value,
                source=r.source,
                distinct_sources=r.distinct_sources,
                confirmed=r.confirmed,
                last_seen=r.last_seen,
            )
            for r in rows
        ]
        days: dict[str, int] = {}
        if auto_confirm_enabled(self.env):
            pending = [
                r.value
                for r in table
                if r.source == "learned" and r.kind == "address" and not r.confirmed
            ]
            try:
                days = await learned_address_days(self.factory, pending)
            except Exception as exc:
                log.warning("self address days unavailable (%s)", type(exc).__name__)
        terms = load_self_terms(
            effective_rows(table, self.env, days),
            self.env,
            vpn_exit=egress.ip if egress is not None and egress.ip else None,
            extra_texts=[v for r in names for v in (r.pseudonym, r.synced_pseudonym) if v],
        )
        self._terms, self._at = terms, time.monotonic()
        return terms
