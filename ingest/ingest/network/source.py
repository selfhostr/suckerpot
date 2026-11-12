"""What the batch builder may read, and nothing else (design M29 section 9.4, N3).

Every query here lists its columns. It reads ``sessions`` counters, ``indicators`` (type, value,
role, host, trusted), ``fetch_targets`` / ``samples`` metadata and the high-confidence C2 links of
analysed samples. It never touches the event table, its JSON payloads, a credential, a command or
an HTTP field: ``tests/network/test_static.py`` fails when this file or ``builder.py`` mentions
them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.sample_kinds import is_plain_web_hash, plain_web_sample

from . import demo

SESSION_ROWS = 20_000
PAYLOAD_ROWS = 3_000
C2_ROWS = 3_000
FILE_ROWS = 3_000


@dataclass(frozen=True, slots=True)
class SessionFact:
    """All of one address's real sessions on one sensor in a day, counters only."""

    ip: str
    sensor: str
    sessions: int
    login_attempts: int
    login_success: bool
    commands: int
    downloads: int
    http_requests: int
    tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PayloadFact:
    url: str
    sha256: str | None
    family: str | None
    kind: str | None
    arch: str | None


@dataclass(frozen=True, slots=True)
class C2Fact:
    kind: str  # c2_ip | c2_domain
    value: str
    port: int
    sha256: str
    family: str | None


@dataclass(frozen=True, slots=True)
class FileFact:
    sha256: str
    family: str | None
    kind: str | None
    arch: str | None


class BatchSource(Protocol):
    async def sessions(self, day: date) -> list[SessionFact]: ...
    async def payloads(self, day: date) -> list[PayloadFact]: ...
    async def c2(self, day: date) -> list[C2Fact]: ...
    async def files(self, day: date) -> list[FileFact]: ...


def _bounds(day: date) -> dict[str, datetime]:
    from .scheduler import day_start

    return {"d0": day_start(day), "d1": day_start(day + timedelta(days=1))}


class SqlSource:
    """The database reader. Demo indicators are skipped; sessions of research scanners and
    harmless visitors are never selected."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self.factory = factory

    async def sessions(self, day: date) -> list[SessionFact]:
        from .scheduler import day_start

        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        f"""
                        WITH s AS (
                            SELECT src_ip, sensor, login_attempts, login_success, commands,
                                   downloads, http_requests, tags
                            FROM sessions se
                            WHERE NOT benign AND scanner_name IS NULL
                              AND started_at >= :d0 AND started_at < :d1
                              AND {demo.not_demo("se", ":d0", ":d2")}
                        ), t AS (
                            SELECT src_ip, sensor, array_agg(DISTINCT tag) AS tags
                            FROM s, unnest(s.tags) AS tag GROUP BY src_ip, sensor
                        )
                        SELECT host(s.src_ip) AS ip, s.sensor, count(*) AS sessions,
                               sum(s.login_attempts) AS attempts, bool_or(s.login_success) AS ok,
                               sum(s.commands) AS commands, sum(s.downloads) AS downloads,
                               sum(s.http_requests) AS http,
                               COALESCE(t.tags, CAST('{{}}' AS text[])) AS tags
                        FROM s LEFT JOIN t ON t.src_ip = s.src_ip AND t.sensor = s.sensor
                        GROUP BY s.src_ip, s.sensor, t.tags
                        ORDER BY count(*) DESC LIMIT :lim
                        """  # noqa: S608  (constant fragments only)
                    ),
                    {
                        **_bounds(day),
                        "d2": day_start(day + timedelta(days=3)),
                        "lim": SESSION_ROWS,
                    },
                )
            ).all()
        return [
            SessionFact(
                ip=r.ip,
                sensor=r.sensor,
                sessions=int(r.sessions),
                login_attempts=int(r.attempts or 0),
                login_success=bool(r.ok),
                commands=int(r.commands or 0),
                downloads=int(r.downloads or 0),
                http_requests=int(r.http or 0),
                tags=tuple(r.tags or ()),
            )
            for r in rows
        ]

    async def payloads(self, day: date) -> list[PayloadFact]:
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT i.value AS url, ft.last_sha256 AS sha256, sm.family AS family,
                               sm.kind AS kind, sm.arch AS arch
                        FROM indicators i
                        LEFT JOIN fetch_targets ft ON ft.url = i.value AND ft.status = 'fetched'
                        LEFT JOIN samples sm ON sm.sha256 = ft.last_sha256
                        WHERE i.type = 'url' AND i.role = 'download_host' AND NOT i.demo
                          AND EXISTS (
                            SELECT 1 FROM indicator_sessions x
                            JOIN sessions s ON s.session_id = x.session_id
                            WHERE x.indicator_id = i.id AND NOT s.benign
                              AND s.scanner_name IS NULL
                              AND x.seen_at >= :d0 AND x.seen_at < :d1)
                        ORDER BY i.id LIMIT :lim
                        """
                    ),
                    {**_bounds(day), "lim": PAYLOAD_ROWS},
                )
            ).all()
        return [PayloadFact(r.url, r.sha256, r.family, r.kind, r.arch) for r in rows]

    async def c2(self, day: date) -> list[C2Fact]:
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        """
                        SELECT l.kind AS kind, l.value AS value, l.port AS port,
                               l.sha256 AS sha256, sm.family AS family
                        FROM sample_links l JOIN samples sm ON sm.sha256 = l.sha256
                        WHERE l.kind IN ('c2_ip', 'c2_domain') AND l.confidence = 'high'
                          AND l.port IS NOT NULL AND sm.last_seen >= :d0 AND sm.last_seen < :d1
                        ORDER BY l.sha256, l.value LIMIT :lim
                        """
                    ),
                    {**_bounds(day), "lim": C2_ROWS},
                )
            ).all()
        return [C2Fact(r.kind, r.value, int(r.port), r.sha256, r.family) for r in rows]

    async def files(self, day: date) -> list[FileFact]:
        """Hashes of stored samples and trusted hash indicators, except plain web content (see
        ``suckerpot_db.sample_kinds``)."""
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(
                        f"""
                        SELECT sm.sha256 AS sha256, sm.family AS family, sm.kind AS kind,
                               sm.arch AS arch
                        FROM samples sm
                        WHERE sm.stored AND sm.last_seen >= :d0 AND sm.last_seen < :d1
                          AND NOT {plain_web_sample("sm")}
                        UNION
                        SELECT lower(i.value), NULL, NULL, NULL
                        FROM indicators i
                        WHERE i.type = 'hash' AND i.trusted AND NOT i.demo
                          AND length(i.value) = 64
                          AND NOT {is_plain_web_hash("i.value")}
                          AND i.last_seen >= :d0 AND i.last_seen < :d1
                        LIMIT :lim
                        """  # noqa: S608  (constant fragments only)
                    ),
                    {**_bounds(day), "lim": FILE_ROWS},
                )
            ).all()
        return [FileFact(r.sha256, r.family, r.kind, r.arch) for r in rows]
