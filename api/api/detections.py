"""Detection rules (M16): Sigma and Suricata rules built from what the honeypot saw.

Every rule is generated on request from rows already in the database, so nothing is stored and
nothing is contacted. Captured strings are untrusted: ``api.rulegen`` only lets printable ASCII
through, quotes or hex-escapes it, and keeps it out of titles and messages. Every rule and every
export says "review before deploying": the rules come from decoy traffic, not from your network.

Also here: the "check this at your company" guidance, limited to the behaviour the honeypot has
actually recorded.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from suckerpot_db.session_counts import sql_sessions_count

from api import guidance, rulegen
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.session_floods import SQL_LAST_SEEN

router = APIRouter(tags=["detections"])

DEFAULT_LIMIT = 25
MAX_LIMIT = 100
WEB_TAGS = (
    "php2shell",
    "env-file-probe",
    "wordpress-bruteforce",
    "phpmyadmin-bruteforce",
    "sql-rce",
)
COMMAND_TAGS = ("malware-drop", "mirai", "crypto-miner", "persistence", "exec-attempt")
STATIC_BODY_MARKERS = {"php2shell": "PHP_SESSION_UPLOAD_PROGRESS"}
PATHS_PER_TAG = 10
COMMANDS_PER_TAG = 15
INDICATORS_PER_KIND = 40
SEVERITY_ORDER = {"severe": 0, "warning": 1, "notice": 2}

Days = Annotated[int, Query(ge=1, le=90)]
MinSources = Annotated[int, Query(ge=1, le=50)]


class RuleOut(BaseModel):
    id: str
    kind: Literal["sigma", "suricata"]
    title: str
    severity: Literal["notice", "warning", "severe"]
    source: str
    rationale: str
    sessions: int
    sources: int
    text: str


class RulePage(BaseModel):
    generated_at: datetime
    days: int
    total: int
    items: list[RuleOut]
    next_cursor: str | None


class Seen(BaseModel):
    sessions: int
    sources: int
    last_seen: datetime | None


class GuidanceItem(BaseModel):
    tag: str
    title: str
    what: str
    look: list[str]
    fix: list[str]
    severity: Literal["notice", "warning", "severe"]
    seen: Seen


class GuidancePage(BaseModel):
    days: int
    items: list[GuidanceItem]


def _demo_clause(include_demo: bool) -> str:
    """Research scanners are never a source of rules; demo events only when asked for."""
    base = "AND coalesce(benign, false) = false"
    return base if include_demo else base + " AND coalesce(data ->> 'demo', 'false') <> 'true'"


async def _tag_totals(db: Any, tag: str, etype: str, since: datetime, demo: str) -> tuple[int, int]:
    row = (
        await db.execute(
            text(
                "SELECT count(*), count(DISTINCT src_ip) FROM events "  # noqa: S608
                f"WHERE type = :t AND ts >= :since AND :tag = ANY(tags) {demo}"
            ),
            {"t": etype, "since": since, "tag": tag},
        )
    ).one()
    return int(row[0]), int(row[1])


async def generate(
    db: DbSession, days: int, min_sources: int, include_demo: bool
) -> list[rulegen.Generated]:
    """All rules for the period, most serious first."""
    today = datetime.now(UTC).date()
    since = datetime.now(UTC) - timedelta(days=days)
    demo = _demo_clause(include_demo)
    taken: set[int] = set()
    rules: list[rulegen.Generated] = []
    for tag in WEB_TAGS:
        sessions, sources = await _tag_totals(db, tag, "http_request", since, demo)
        if sources < min_sources:
            continue
        rows = (
            await db.execute(
                text(
                    "SELECT left(data ->> 'path', 200) AS path, count(*) AS n, "  # noqa: S608
                    "count(DISTINCT src_ip) AS sources FROM events "
                    "WHERE type = 'http_request' AND ts >= :since AND :tag = ANY(tags) "
                    f"AND data ->> 'path' IS NOT NULL {demo} "
                    "GROUP BY 1 HAVING count(DISTINCT src_ip) >= :min "
                    "ORDER BY n DESC, 1 LIMIT 60"
                ),
                {"since": since, "tag": tag, "min": min_sources},
            )
        ).all()
        sev = rulegen.severity_of(tag)
        usable = [r for r in rows if rulegen.printable(r.path) and str(r.path) not in
                  rulegen.GENERIC_PATHS and len(str(r.path)) >= rulegen.MIN_PATH]  # fmt: skip
        paths = [str(r.path) for r in usable]
        sigma = rulegen.sigma_web_paths(tag, paths, sev, sessions, sources, today)
        if sigma:
            rules.append(sigma)
        for r in usable[:PATHS_PER_TAG]:
            one = rulegen.suricata_web_path(
                tag, str(r.path), sev, int(r.n), int(r.sources), today, taken
            )
            if one:
                rules.append(one)
        marker = STATIC_BODY_MARKERS.get(tag)
        if marker:
            body = rulegen.suricata_static_body(tag, marker, sessions, sources, today, taken)
            if body:
                rules.append(body)
    for tag in COMMAND_TAGS:
        sessions, sources = await _tag_totals(db, tag, "command", since, demo)
        if sources < min_sources:
            continue
        rows = (
            await db.execute(
                text(
                    "SELECT left(data ->> 'input', 160) AS cmd, count(*) AS n "  # noqa: S608
                    "FROM events WHERE type = 'command' AND ts >= :since AND :tag = ANY(tags) "
                    f"AND data ->> 'input' IS NOT NULL {demo} "
                    "GROUP BY 1 HAVING count(DISTINCT src_ip) >= :min "
                    "ORDER BY n DESC, 1 LIMIT :n"
                ),
                {"since": since, "tag": tag, "min": min_sources, "n": COMMANDS_PER_TAG},
            )
        ).all()
        sigma_cmd = rulegen.sigma_commands(
            tag, [str(r.cmd) for r in rows], rulegen.severity_of(tag), sessions, sources, today
        )
        if sigma_cmd:
            rules.append(sigma_cmd)
    rules += await _indicator_rules(db, today, include_demo, taken)
    rules.sort(key=lambda r: (SEVERITY_ORDER[r.severity], -r.sessions, r.kind, r.key))
    return rules


async def _indicator_rules(
    db: Any, today: Any, include_demo: bool, taken: set[int]
) -> list[rulegen.Generated]:
    """Rules from the blocklist: hosts, download URLs and file hashes with a high score."""
    out: list[rulegen.Generated] = []
    demo = "" if include_demo else "AND NOT demo"
    try:
        async with db.begin_nested():
            rows = (
                await db.execute(
                    text(
                        "SELECT kind, value, score, sessions, sources FROM blocklist_entries "  # noqa: S608
                        "WHERE kind IN ('domain', 'url', 'hash') AND NOT benign "
                        f"AND score >= 60 {demo} "
                        "ORDER BY score DESC, last_seen DESC, value LIMIT 150"
                    )
                )
            ).all()
    except DBAPIError:
        return out
    by_kind: dict[str, list[Any]] = {"domain": [], "url": [], "hash": []}
    for r in rows:
        if len(by_kind[r.kind]) < INDICATORS_PER_KIND:
            by_kind[r.kind].append(r)

    def totals(items: list[Any]) -> tuple[int, int]:
        return sum(int(i.sessions) for i in items), sum(int(i.sources) for i in items)

    for kind, builder in (
        ("domain", rulegen.sigma_domains),
        ("url", rulegen.sigma_urls),
        ("hash", rulegen.sigma_hashes),
    ):
        items = by_kind[kind]
        sessions, sources = totals(items)
        rule = builder([str(i.value) for i in items], sessions, sources, today)
        if rule:
            out.append(rule)
    for item in by_kind["domain"][:25]:
        out += rulegen.suricata_domain(
            str(item.value), int(item.score), int(item.sessions), int(item.sources), today, taken
        )
    return out


def _out(rule: rulegen.Generated) -> RuleOut:
    return RuleOut(
        id=rulegen.sigma_id(rule.key),
        kind=rule.kind,
        title=rule.title,
        severity=rule.severity,
        source=rule.source,
        rationale=rule.rationale,
        sessions=rule.sessions,
        sources=rule.sources,
        text=rule.text,
    )


@router.get("/defend/detections", response_model=RulePage)
async def list_rules(
    db: DbSession,
    kind: Annotated[Literal["sigma", "suricata"] | None, Query()] = None,
    days: Days = 30,
    min_sources: MinSources = 2,
    include_demo: Annotated[bool, Query()] = True,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> RulePage:
    """Generated rules, most serious first. ``text`` is the rule itself; review it before use."""
    offset = 0
    if cursor:
        try:
            (offset,) = decode_cursor(cursor)  # type: ignore[assignment]
            if not isinstance(offset, int) or offset < 0:
                raise ValueError
        except (InvalidCursorError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
    rules = [
        r for r in await generate(db, days, min_sources, include_demo) if not kind or r.kind == kind
    ]
    page = rules[offset : offset + limit]
    more = offset + limit < len(rules)
    return RulePage(
        generated_at=datetime.now(UTC),
        days=days,
        total=len(rules),
        items=[_out(r) for r in page],
        next_cursor=encode_cursor([offset + limit]) if more else None,
    )


@router.get("/defend/detections/export")
async def export_rules(
    db: DbSession,
    kind: Annotated[Literal["sigma", "suricata"], Query()],
    days: Days = 30,
    min_sources: MinSources = 2,
    include_demo: Annotated[bool, Query()] = False,
) -> Response:
    """All rules of one kind as a single file (Sigma: YAML documents; Suricata: .rules)."""
    rules = [r for r in await generate(db, days, min_sources, include_demo) if r.kind == kind]
    body = rulegen.sigma_file(rules) if kind == "sigma" else rulegen.suricata_file(rules)
    name = "sigma-rules.yml" if kind == "sigma" else "suricata.rules"
    return PlainTextResponse(
        body,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Rule-Count": str(len(rules)),
        },
    )


@router.get("/defend/guidance", response_model=GuidancePage)
async def check_at_work(db: DbSession, days: Days = 30) -> GuidancePage:
    """What to check at your own company, for the behaviour seen in the last ``days`` days."""
    since = datetime.now(UTC) - timedelta(days=days)
    rows = (
        await db.execute(
            text(
                f"SELECT t AS tag, {sql_sessions_count()} AS sessions, "  # noqa: S608 (constants only)
                "count(DISTINCT src_ip) AS sources, "
                f"{SQL_LAST_SEEN} AS last_seen "
                "FROM sessions CROSS JOIN LATERAL unnest(tags) AS t "
                "WHERE started_at >= :since AND NOT benign GROUP BY t"
            ),
            {"since": since},
        )
    ).all()
    items: list[GuidanceItem] = []
    for r in rows:
        advice = guidance.TAG_ADVICE.get(r.tag)
        if advice is None:
            continue
        items.append(
            GuidanceItem(
                tag=r.tag,
                title=advice["title"],
                what=advice["what"],
                look=advice["look"],
                fix=advice["fix"],
                severity=rulegen.severity_of(r.tag),
                seen=Seen(sessions=int(r.sessions), sources=int(r.sources), last_seen=r.last_seen),
            )
        )
    items.sort(key=lambda i: (SEVERITY_ORDER[i.severity], -i.seen.sessions, i.tag))
    return GuidancePage(days=days, items=items)


__all__ = ["router"]
