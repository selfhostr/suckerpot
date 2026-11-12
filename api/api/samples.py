"""Collected samples (M21): list, detail, chain and the guarded archive download.

Read-only for every role except ``POST /samples/{sha256}/archive``, which is administrator only
and asks for the account password again. Nothing here contacts the internet or runs a sample: the
API only reads tables and, for the archive, one file of the read-only quarantine volume.

The archive route builds the file path from a validated 64-hex sha256 (never from anything else),
refuses anything but a regular file below a size cap, checks that the bytes hash to the name, and
only ever sends them inside an AES-256 zip with the conventional password ``infected``. The raw
bytes are never served.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import stat
import time
from collections import deque
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import SessionRow
from suckerpot_db.sample_kinds import crawled_from_web
from suckerpot_reporting import build_encrypted_zip

from api import audit as audit_db
from api import auth as auth_mod
from api import reauth
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.schemas import SessionOut

router = APIRouter(tags=["samples"])
audit = logging.getLogger("api.audit")

MAX_LIMIT = 200
RECENT_SESSIONS = 20
MAX_STRINGS = 500
MAX_STRING_LEN = 120
MAX_CHAIN_NODES = 100
MAX_CHAIN_DEPTH = 3
SESSIONS_PER_URL = 5
MAX_ARCHIVE_INPUT = 16 * 1024 * 1024
ARCHIVE_PER_HOUR = 10
QUARANTINE_ENV = "QUARANTINE_DIR"
DEFAULT_QUARANTINE = "/quarantine"
VIRUSTOTAL_FILE = "https://www.virustotal.com/gui/file/"

SHA256_PATTERN = r"^[0-9a-f]{64}$"
SHA256_RE = re.compile(SHA256_PATTERN)
Sha256 = Annotated[str, Path(pattern=SHA256_PATTERN)]
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
Word = Annotated[str, Query(pattern=r"^[A-Za-z0-9_.+ -]{1,64}$")]


class SampleItem(BaseModel):
    sha256: str
    kind: str | None
    arch: str | None
    bits: int | None
    family: str | None
    severity: str
    size: int
    sources: int
    sessions: int
    first_seen: datetime
    last_seen: datetime
    yara: list[str]
    stored: bool
    analysis_status: str
    # "network_verify" when every source was fetched for the network (M32), else "local".
    origin: str = "local"
    # True when the collector reached the file only by following links found in other web
    # content and no attacker asked for it (suckerpot_db.sample_kinds.crawled_from_web).
    crawled: bool = False


class SamplePage(BaseModel):
    items: list[SampleItem]
    next_cursor: str | None


class YaraHit(BaseModel):
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, str]


class DeobStep(BaseModel):
    step: str
    detail: str | None


class SampleAnalysis(BaseModel):
    analyzed_at: datetime
    elapsed_ms: int | None
    yara: list[YaraHit]
    strings: list[str]
    deobfuscated: str | None
    deob_steps: list[DeobStep]
    errors: list[str]


class SampleSource(BaseModel):
    url: str
    host: str
    first_fetched: datetime
    last_fetched: datetime
    sessions: int
    ips: int
    sensors: list[str]


class SampleLink(BaseModel):
    kind: str
    value: str
    port: int | None
    source: str
    confidence: str


class SampleDetail(BaseModel):
    item: SampleItem
    sha1: str
    md5: str
    tlsh: str | None
    endian: str | None
    linking: str | None
    packer: str | None
    virustotal_url: str
    analysis: SampleAnalysis | None
    sources: list[SampleSource]
    links: list[SampleLink]
    recent_sessions: list[SessionOut]


class ChainNode(BaseModel):
    id: str
    kind: str  # session | url | sample | c2
    label: str
    sha256: str | None = None
    family: str | None = None
    session_id: str | None = None


class ArchiveBody(BaseModel):
    password: str | None = None


# ---- list ------------------------------------------------------------------------------------

_ITEM_SELECT = f"""
SELECT s.sha256, s.kind, s.arch, s.bits, s.family, s.severity, s.size, s.first_seen, s.last_seen,
       s.stored, s.analysis_status,
       (SELECT count(*) FROM sample_sources x WHERE x.sha256 = s.sha256) AS sources,
       (SELECT count(DISTINCT l.session_id)
          FROM sample_sources x
          JOIN fetch_targets t ON t.id = x.target_id
          JOIN indicator_sessions l ON l.indicator_id = t.indicator_id
         WHERE x.sha256 = s.sha256) AS sessions,
       CASE WHEN EXISTS (SELECT 1 FROM sample_sources x WHERE x.sha256 = s.sha256)
             AND NOT EXISTS (SELECT 1 FROM sample_sources x
                             JOIN fetch_targets t ON t.id = x.target_id
                             WHERE x.sha256 = s.sha256 AND t.origin <> 'network_verify')
            THEN 'network_verify' ELSE 'local' END AS origin,
       {crawled_from_web("s")} AS crawled,
       COALESCE(jsonb_path_query_array(a.yara, '$[*].rule'), '[]'::jsonb) AS yara
FROM samples s
LEFT JOIN sample_analysis a ON a.sha256 = s.sha256
"""  # noqa: S608  (constant fragment only)


def _item(r: Any) -> SampleItem:
    return SampleItem(
        sha256=r.sha256,
        kind=r.kind,
        arch=r.arch,
        bits=r.bits,
        family=r.family,
        severity=r.severity,
        size=r.size,
        sources=r.sources,
        sessions=r.sessions,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
        yara=[str(y) for y in (r.yara or [])][:50],
        stored=r.stored,
        analysis_status=r.analysis_status,
        origin=r.origin,
        crawled=bool(r.crawled),
    )


def _parse_cursor(cursor: str) -> tuple[datetime, str]:
    values = decode_cursor(cursor)
    try:
        ts, sha = values
        if not isinstance(ts, str) or not isinstance(sha, str) or not SHA256_RE.match(sha):
            raise TypeError
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed, sha
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc


@router.get("/samples", response_model=SamplePage)
async def list_samples(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Limit = 50,
    kind: Word | None = None,
    arch: Word | None = None,
    family: Word | None = None,
    yara: Word | None = None,
    status: Annotated[str | None, Query(pattern="^(pending|done|failed|timeout)$")] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    since: datetime | None = None,
) -> SamplePage:
    where: list[str] = []
    params: dict[str, Any] = {"lim": limit + 1}
    for column, value in (("kind", kind), ("arch", arch), ("family", family)):
        if value is not None:
            where.append(f"lower(s.{column}) = lower(:{column})")
            params[column] = value
    if yara is not None:
        where.append(
            "jsonb_path_exists(a.yara, '$[*] ? (@.rule == $r)', "
            "jsonb_build_object('r', CAST(:yara AS text)))"
        )
        params["yara"] = yara
    if status is not None:
        where.append("s.analysis_status = :status")
        params["status"] = status
    if q is not None:
        where.append(
            "(starts_with(s.sha256, lower(:q)) OR EXISTS (SELECT 1 FROM sample_sources x "
            "JOIN fetch_targets t ON t.id = x.target_id "
            "WHERE x.sha256 = s.sha256 AND strpos(lower(t.url), lower(:q)) > 0))"
        )
        params["q"] = q
    if since is not None:
        if since.tzinfo is None:
            raise HTTPException(status_code=422, detail="since must include a time zone")
        where.append("s.last_seen >= :since")
        params["since"] = since
    if cursor is not None:
        try:
            c_ts, c_sha = _parse_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        where.append("(s.last_seen, s.sha256) < (:c_ts, :c_sha)")
        params["c_ts"], params["c_sha"] = c_ts, c_sha
    sql = _ITEM_SELECT + (f"WHERE {' AND '.join(where)}\n" if where else "")
    sql += "ORDER BY s.last_seen DESC, s.sha256 DESC LIMIT :lim"
    rows = (await db.execute(text(sql), params)).all()
    page, more = rows[:limit], len(rows) > limit
    next_cursor = encode_cursor([page[-1].last_seen.isoformat(), page[-1].sha256]) if more else None
    return SamplePage(items=[_item(r) for r in page], next_cursor=next_cursor)


# ---- detail ----------------------------------------------------------------------------------


def _str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k)[:64]: str(v)[:256] for k, v in list(value.items())[:20]}


def _hits(raw: Any) -> list[YaraHit]:
    out: list[YaraHit] = []
    for h in (raw or [])[:50]:
        if not isinstance(h, dict) or not h.get("rule"):
            continue
        out.append(
            YaraHit(
                rule=str(h["rule"])[:128],
                namespace=str(h.get("namespace") or "")[:64],
                tags=[str(t)[:64] for t in (h.get("tags") or [])][:20],
                meta=_str_map(h.get("meta")),
            )
        )
    return out


def _steps(raw: Any) -> list[DeobStep]:
    out: list[DeobStep] = []
    for s in (raw or [])[:50]:
        if isinstance(s, dict) and s.get("step"):
            detail = s.get("detail")
            out.append(
                DeobStep(
                    step=str(s["step"])[:128], detail=None if detail is None else str(detail)[:512]
                )
            )
    return out


@router.get("/samples/{sha256}", response_model=SampleDetail)
async def get_sample(sha256: Sha256, db: DbSession) -> SampleDetail:
    row = (await db.execute(text(_ITEM_SELECT + "WHERE s.sha256 = :sha"), {"sha": sha256})).first()
    if row is None:
        raise HTTPException(status_code=404, detail="sample not found")
    meta = (
        await db.execute(
            text(
                "SELECT sha1, md5, tlsh, endian, linking, packer FROM samples WHERE sha256 = :sha"
            ),
            {"sha": sha256},
        )
    ).one()
    a = (
        await db.execute(
            text(
                "SELECT analyzed_at, elapsed_ms, yara, strings, deobfuscated, deob_steps, errors "
                "FROM sample_analysis WHERE sha256 = :sha"
            ),
            {"sha": sha256},
        )
    ).first()
    analysis = None
    if a is not None:
        analysis = SampleAnalysis(
            analyzed_at=a.analyzed_at,
            elapsed_ms=a.elapsed_ms,
            yara=_hits(a.yara),
            strings=[s[:MAX_STRING_LEN] for s in (a.strings or [])[:MAX_STRINGS]],
            deobfuscated=a.deobfuscated,
            deob_steps=_steps(a.deob_steps),
            errors=[e[:256] for e in (a.errors or [])][:20],
        )
    src_rows = (
        await db.execute(
            text(
                """
SELECT t.url, t.host, x.first_fetched, x.last_fetched,
       count(DISTINCT l.session_id) AS sessions, count(DISTINCT l.src_ip) AS ips,
       COALESCE(array_agg(DISTINCT l.sensor) FILTER (WHERE l.sensor IS NOT NULL), '{}') AS sensors
FROM sample_sources x
JOIN fetch_targets t ON t.id = x.target_id
LEFT JOIN indicator_sessions l ON l.indicator_id = t.indicator_id
WHERE x.sha256 = :sha
GROUP BY t.url, t.host, x.first_fetched, x.last_fetched
ORDER BY x.last_fetched DESC, t.url
LIMIT 50
"""
            ),
            {"sha": sha256},
        )
    ).all()
    link_rows = (
        await db.execute(
            text(
                "SELECT kind, value, port, source, confidence FROM sample_links "
                "WHERE sha256 = :sha ORDER BY kind, value LIMIT 100"
            ),
            {"sha": sha256},
        )
    ).all()
    ids = (
        await db.execute(
            text(
                """
SELECT l.session_id, max(l.seen_at) AS last
FROM sample_sources x
JOIN fetch_targets t ON t.id = x.target_id
JOIN indicator_sessions l ON l.indicator_id = t.indicator_id
WHERE x.sha256 = :sha
GROUP BY l.session_id ORDER BY last DESC, l.session_id DESC LIMIT :n
"""
            ),
            {"sha": sha256, "n": RECENT_SESSIONS},
        )
    ).all()
    sessions: list[SessionRow] = []
    if ids:
        found = {s.session_id: s for s in await _load_sessions(db, [i.session_id for i in ids])}
        sessions = [found[i.session_id] for i in ids if i.session_id in found]
    return SampleDetail(
        item=_item(row),
        sha1=meta.sha1,
        md5=meta.md5,
        tlsh=meta.tlsh,
        endian=meta.endian,
        linking=meta.linking,
        packer=meta.packer,
        virustotal_url=VIRUSTOTAL_FILE + sha256,
        analysis=analysis,
        sources=[
            SampleSource(
                url=r.url,
                host=r.host,
                first_fetched=r.first_fetched,
                last_fetched=r.last_fetched,
                sessions=r.sessions,
                ips=r.ips,
                sensors=sorted(r.sensors or []),
            )
            for r in src_rows
        ],
        links=[
            SampleLink(
                kind=r.kind, value=r.value, port=r.port, source=r.source, confidence=r.confidence
            )
            for r in link_rows
        ],
        recent_sessions=[SessionOut.model_validate(s, from_attributes=True) for s in sessions],
    )


async def _load_sessions(db: AsyncSession, session_ids: list[str]) -> list[SessionRow]:
    return list(
        (await db.scalars(select(SessionRow).where(SessionRow.session_id.in_(session_ids)))).all()
    )


# ---- chain -----------------------------------------------------------------------------------


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, ChainNode] = {}
        self.edges: set[tuple[str, str]] = set()

    def add(self, node: ChainNode) -> bool:
        if node.id in self.nodes:
            return True
        if len(self.nodes) >= MAX_CHAIN_NODES:
            return False
        self.nodes[node.id] = node
        return True

    def edge(self, a: str, b: str) -> None:
        if a in self.nodes and b in self.nodes:
            self.edges.add((a, b))


def _sample_node(sha: str, family: str | None, kind: str | None) -> ChainNode:
    return ChainNode(
        id=f"sample:{sha}", kind="sample", label=sha[:12], sha256=sha, family=family or kind
    )


@router.get("/samples/{sha256}/chain")
async def get_chain(sha256: Sha256, db: DbSession) -> dict[str, Any]:
    """Session, URL, sample and C2 nodes around one sample: depth 3, 100 nodes at most."""
    root = (
        await db.execute(
            text("SELECT sha256, family, kind FROM samples WHERE sha256 = :s"), {"s": sha256}
        )
    ).first()
    if root is None:
        raise HTTPException(status_code=404, detail="sample not found")
    g = _Graph()
    g.add(_sample_node(root.sha256, root.family, root.kind))
    queue: deque[tuple[str, int]] = deque([(sha256, 0)])
    seen = {sha256}
    while queue and len(g.nodes) < MAX_CHAIN_NODES:
        sha, depth = queue.popleft()
        me = f"sample:{sha}"
        # Upstream: URLs that served it, sessions that pointed at them, the script it came from.
        for t in (
            await db.execute(
                text(
                    "SELECT t.url, t.indicator_id, t.parent_sha256 FROM sample_sources x "
                    "JOIN fetch_targets t ON t.id = x.target_id WHERE x.sha256 = :s "
                    "ORDER BY x.last_fetched DESC LIMIT 20"
                ),
                {"s": sha},
            )
        ).all():
            uid = f"url:{t.url}"
            if not g.add(ChainNode(id=uid, kind="url", label=t.url[:200])):
                continue
            g.edge(uid, me)
            if t.indicator_id is not None:
                for ses in (
                    await db.execute(
                        text(
                            "SELECT DISTINCT ON (session_id) session_id, seen_at "
                            "FROM indicator_sessions "
                            "WHERE indicator_id = :i ORDER BY session_id, seen_at DESC LIMIT :n"
                        ),
                        {"i": t.indicator_id, "n": SESSIONS_PER_URL},
                    )
                ).all():
                    sid = f"session:{ses.session_id}"
                    if g.add(
                        ChainNode(
                            id=sid,
                            kind="session",
                            label=ses.session_id[:64],
                            session_id=ses.session_id,
                        )
                    ):
                        g.edge(sid, uid)
            if t.parent_sha256 and depth < MAX_CHAIN_DEPTH and SHA256_RE.match(t.parent_sha256):
                await _add_sample(db, g, t.parent_sha256, uid, depth, seen, queue, parent=True)
        # Downstream: next-stage URLs (and what they served) and command servers.
        for lk in (
            await db.execute(
                text(
                    "SELECT l.kind, l.value, l.port, t.last_sha256 FROM sample_links l "
                    "LEFT JOIN fetch_targets t ON t.id = l.target_id "
                    "WHERE l.sha256 = :s ORDER BY l.kind, l.value LIMIT 30"
                ),
                {"s": sha},
            )
        ).all():
            if lk.kind in ("next_url", "c2_url"):
                nid = f"url:{lk.value}"
                if g.add(ChainNode(id=nid, kind="url", label=lk.value[:200])):
                    g.edge(me, nid)
                    if (
                        lk.last_sha256
                        and depth < MAX_CHAIN_DEPTH
                        and SHA256_RE.match(lk.last_sha256)
                    ):
                        await _add_sample(
                            db, g, lk.last_sha256, nid, depth, seen, queue, parent=False
                        )
            else:
                label = f"{lk.value}:{lk.port}" if lk.port else lk.value
                cid = f"c2:{label}"
                if g.add(ChainNode(id=cid, kind="c2", label=label[:200])):
                    g.edge(me, cid)
    return {
        "nodes": [n.model_dump(exclude_none=True) for n in g.nodes.values()],
        "edges": [{"from": a, "to": b} for a, b in sorted(g.edges)],
    }


async def _add_sample(
    db: AsyncSession,
    g: _Graph,
    sha: str,
    url_node: str,
    depth: int,
    seen: set[str],
    queue: deque[tuple[str, int]],
    *,
    parent: bool,
) -> None:
    row = (
        await db.execute(
            text("SELECT sha256, family, kind FROM samples WHERE sha256 = :s"), {"s": sha}
        )
    ).first()
    node = _sample_node(sha, row.family if row else None, row.kind if row else None)
    if not g.add(node):
        return
    # A parent script points at the URL it mentions; a child sample was served by that URL.
    if parent:
        g.edge(node.id, url_node)
    else:
        g.edge(url_node, node.id)
    if sha not in seen:
        seen.add(sha)
        queue.append((sha, depth + 1))


# ---- archive ---------------------------------------------------------------------------------

_downloads: dict[str, deque[float]] = {}


def _rate_limited(user: str) -> int | None:
    """Seconds to wait when the user has used up their hourly archive downloads."""
    now = time.monotonic()
    window = _downloads.setdefault(user, deque())
    while window and now - window[0] > 3600:
        window.popleft()
    if len(window) >= ARCHIVE_PER_HOUR:
        return int(3600 - (now - window[0])) + 1
    return None


def _note_download(user: str) -> None:
    _downloads.setdefault(user, deque()).append(time.monotonic())


def quarantine_path(sha256: str) -> str:
    """``<root>/ab/cd/<sha256>``; the only input is a validated 64-hex name."""
    if not SHA256_RE.match(sha256):
        raise ValueError("not a sha256")
    root = os.environ.get(QUARANTINE_ENV, DEFAULT_QUARANTINE)
    return os.path.join(root, sha256[:2], sha256[2:4], sha256)


class ArchiveError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


def read_quarantined(sha256: str) -> bytes:
    """Read one stored sample: regular file only, size capped, content checked against its name."""
    path = quarantine_path(sha256)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError as exc:
        raise ArchiveError(404, "sample file not found") from exc
    except OSError as exc:
        raise ArchiveError(503, "quarantine unavailable") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ArchiveError(404, "sample file not found")
        if st.st_size > MAX_ARCHIVE_INPUT:
            raise ArchiveError(413, "sample too large to download")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_ARCHIVE_INPUT + 1)
    except OSError as exc:
        raise ArchiveError(503, "quarantine unavailable") from exc
    finally:
        os.close(fd)
    if len(data) > MAX_ARCHIVE_INPUT:
        raise ArchiveError(413, "sample too large to download")
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ArchiveError(500, "stored file does not match its hash")
    return data


def build_archive(sha256: str, data: bytes) -> bytes:
    """One AES-256 zip (password ``infected``, neutral metadata) holding ``<sha256>.bin``."""
    return build_encrypted_zip([(f"{sha256}.bin", data)])


@router.post("/samples/{sha256}/archive")
async def download_archive(
    sha256: Sha256, body: ArchiveBody, request: Request, db: DbSession
) -> Response:
    """Administrator only (default-deny for POST), password required again, 10 per hour."""
    service: auth_mod.AuthService = request.app.state.auth
    if body.password is None and not service.settings.disabled:
        return reauth.error(401, "Password required", "reauth_required")
    principal, refused = await reauth.guard(request, body.password, "sample download")
    if refused is not None:
        return refused
    actor = principal.username if principal else "anonymous"
    wait = _rate_limited(actor)
    if wait is not None:
        return reauth.error(429, "Too many downloads", "rate_limited", {"Retry-After": str(wait)})
    row = (
        await db.execute(text("SELECT stored, size FROM samples WHERE sha256 = :s"), {"s": sha256})
    ).first()
    if row is None or not row.stored:
        return reauth.error(404, "Sample is not stored", "not_stored")
    try:
        data = await asyncio.to_thread(read_quarantined, sha256)
    except ArchiveError as exc:
        return reauth.error(exc.status, exc.detail, "archive_unavailable")
    payload = await asyncio.to_thread(build_archive, sha256, data)
    _note_download(actor)
    await audit_db.record(
        db,
        actor=actor,
        action="sample.download",
        target=sha256,
        ip=service.client_ip(request),
        details={"size": len(data)},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    audit.info("sample archive downloaded sha256=%s actor=%s", sha256, actor)
    return Response(
        payload,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{sha256[:16]}.zip"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
