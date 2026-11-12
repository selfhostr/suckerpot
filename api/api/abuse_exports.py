"""Exports for CERTs and malware repositories (M22): STIX 2.1, MISP, and the sample bundle.

Nothing is uploaded or sent: the owner downloads a file and submits it himself. Every export is
built from the database with the shared ``suckerpot_reporting`` package and runs the identity
guard on the structure and on the exact text before it is returned (a failure answers 409 with
reason codes only). The sample bundle also asks for the account password again.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
import uuid
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request, Response
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import AttackTechniqueRow, CampaignRow
from suckerpot_reporting import (
    BundleLimitError,
    BundleSample,
    ExportData,
    ExportItem,
    GuardContext,
    GuardFailed,
    RenderUnavailable,
    SampleRef,
    SelfTerms,
    Technique,
    build_sample_bundle,
    derive_id,
    export_from_evidence,
    export_names,
    guard,
    new_public_id,
    new_seed,
    render_misp,
    render_stix,
    stix_dumps,
)
from suckerpot_reporting.normalize import is_documentation, is_forbidden_range

from api import audit as audit_db
from api import auth as auth_mod
from api import reauth
from api.abuse import _actor, _client_ip, _load, _principal
from api.abuse_core import (
    EvidenceInvalidError,
    build_evidence,
    error,
    guard_context,
    guard_failed_response,
    held_evidence_codes,
    include_demo,
    load_settings,
    load_terms,
    missing_for,
    release,
    settings_incomplete_response,
)
from api.deps import DbSession
from api.samples import ArchiveError, read_quarantined

router = APIRouter(tags=["abuse"])
log = logging.getLogger("api.abuse")

MAX_WINDOW_DAYS = 31
MAX_SOURCES = 2000
MAX_URLS = 1500
MAX_SAMPLES = 500
MAX_ITEMS = 5000
BUNDLE_PER_HOUR = 5
Tlp = Literal["clear", "green", "amber", "red"]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

SEVERE = "(s.commands > 0 OR s.downloads > 0 OR s.login_attempts >= 50)"
BENIGN = "NOT s.benign AND s.scanner_name IS NULL"


# ---- indicators of a scope -----------------------------------------------------------------


def _scope_sql(campaign: int | None) -> str:
    if campaign is not None:
        return (
            "(s.campaign_id = :campaign OR s.campaign_id IN "
            "(SELECT id FROM campaigns WHERE merged_into = :campaign))"
        )
    return "(s.started_at >= :since AND s.started_at < :until)"


async def collect_items(
    db: AsyncSession,
    *,
    campaign: int | None,
    since: datetime | None,
    until: datetime | None,
    demo: bool,
) -> list[ExportItem]:
    """Attack sources, payload URLs, samples and C2 addresses of a campaign or a time window."""
    scope = _scope_sql(campaign)
    params: dict[str, Any] = {"campaign": campaign, "since": since, "until": until, "demo": demo}
    if campaign is None:
        params.pop("campaign")
    else:
        params.pop("since")
        params.pop("until")
    severity = f" AND {SEVERE}" if campaign is None else ""
    items: list[ExportItem] = []

    sources = (
        await db.execute(
            text(
                "SELECT host(s.src_ip) AS ip, min(s.started_at) AS first, "  # noqa: S608 (constants only)
                "max(s.last_event_at) AS last, count(*) AS n, "
                "coalesce(array_agg(DISTINCT t) FILTER (WHERE t IS NOT NULL), '{}') AS techs "
                "FROM sessions s LEFT JOIN LATERAL unnest(s.techniques) AS t ON true "
                f"WHERE {scope} AND {BENIGN}{severity} "
                "GROUP BY s.src_ip ORDER BY count(*) DESC LIMIT :lim"
            ),
            {**params, "lim": MAX_SOURCES},
        )
    ).all()
    tech_ids = {t for r in sources for t in r.techs}
    names: dict[str, str] = {}
    if tech_ids:
        names = {
            r.id: r.name
            for r in await db.execute(
                select(AttackTechniqueRow.id, AttackTechniqueRow.name).where(
                    AttackTechniqueRow.id.in_(tech_ids)
                )
            )
        }
    key = f"campaign:{campaign}" if campaign is not None else None
    for r in sources:
        items.append(
            ExportItem(
                role="attack_source",
                type="ip",
                value=r.ip,
                first_seen=r.first,
                last_seen=r.last,
                sightings=int(r.n),
                techniques=tuple(
                    Technique(id=t, name=names[t][:100]) for t in sorted(r.techs) if t in names
                ),
                cluster_key=key,
            )
        )

    urls = (
        await db.execute(
            text(
                "SELECT i.value AS value, min(x.seen_at) AS first, max(x.seen_at) AS last, "  # noqa: S608 (constants only)
                "count(*) AS n FROM indicators i "
                "JOIN indicator_sessions x ON x.indicator_id = i.id "
                "JOIN sessions s ON s.session_id = x.session_id "
                "WHERE i.role = 'download_host' AND i.type = 'url' AND (:demo OR NOT i.demo) "
                f"AND {scope} AND {BENIGN} "
                "GROUP BY i.value ORDER BY count(*) DESC LIMIT :lim"
            ),
            {**params, "lim": MAX_URLS},
        )
    ).all()
    items += [
        ExportItem(
            role="payload_host",
            type="url",
            value=r.value[:1024],
            first_seen=r.first,
            last_seen=r.last,
            sightings=int(r.n),
            cluster_key=key,
        )
        for r in urls
    ]

    samples = (
        await db.execute(
            text(
                "SELECT sm.sha256, sm.sha1, sm.md5, sm.tlsh, sm.size, sm.kind, sm.arch, "  # noqa: S608 (constants only)
                "sm.family, sm.first_seen, sm.last_seen FROM samples sm WHERE sm.sha256 IN ("
                "SELECT ss.sha256 FROM sample_sources ss "
                "JOIN fetch_targets ft ON ft.id = ss.target_id "
                "JOIN indicator_sessions x ON x.indicator_id = ft.indicator_id "
                "JOIN sessions s ON s.session_id = x.session_id "
                f"WHERE {scope} AND {BENIGN}) "
                "ORDER BY sm.first_seen LIMIT :lim"
            ),
            {**params, "lim": MAX_SAMPLES},
        )
    ).all()
    for r in samples:
        ref = SampleRef(
            sha256=r.sha256,
            sha1=r.sha1,
            md5=r.md5,
            tlsh=r.tlsh,
            size=r.size,
            kind=r.kind,
            arch=r.arch,
            family=r.family,
            first_seen=r.first_seen,
        )
        items.append(
            ExportItem(
                role="sample",
                type="file",
                value=r.sha256,
                first_seen=r.first_seen,
                last_seen=r.last_seen,
                family=r.family,
                sample=ref,
                cluster_key=key,
            )
        )
    if samples:
        links = (
            await db.execute(
                text(
                    "SELECT l.value, l.kind, min(sm.first_seen) AS first, "
                    "max(sm.last_seen) AS last, max(sm.family) AS family FROM sample_links l "
                    "JOIN samples sm ON sm.sha256 = l.sha256 "
                    "WHERE l.sha256 = ANY(:shas) AND l.kind IN ('c2_ip', 'c2_domain') "
                    "AND l.confidence = 'high' GROUP BY l.value, l.kind LIMIT :lim"
                ),
                {"shas": [r.sha256 for r in samples], "lim": MAX_SAMPLES},
            )
        ).all()
        items += [
            ExportItem(
                role="c2",
                type="ip" if r.kind == "c2_ip" else "domain",
                value=r.value[:1024],
                first_seen=r.first,
                last_seen=r.last,
                family=r.family,
                cluster_key=key,
            )
            for r in links
        ]
    return items[:MAX_ITEMS]


def _screen(
    items: list[ExportItem], terms: SelfTerms | None, ctx: GuardContext
) -> list[ExportItem]:
    """Drop what must not be shared before the final guard: other people's private ranges, the
    monitored system itself, and any single value the guard refuses. The whole export is still
    guarded afterwards."""
    kept: list[ExportItem] = []
    for item in items:
        if item.type == "ip":
            try:
                addr = ipaddress.ip_address(item.value)
            except ValueError:
                continue
            if is_documentation(addr):
                if not ctx.allow_documentation:
                    continue
            elif is_forbidden_range(addr):
                continue
            if terms is not None and terms.is_self(addr):
                continue
        if terms is not None:
            verdict = guard(item.value, terms, fmt="text", ctx=ctx)
            if set(verdict.codes) - {"no_self_address"}:
                continue
        kept.append(item)
    return kept


def _render(
    data: ExportData, kind: str, terms: SelfTerms | None, ctx: GuardContext
) -> tuple[str, str, str]:
    """(file name, media type, text). Guarded twice: the structure, then the exact text."""
    names = export_names(data.export_id)
    if kind == "stix":
        obj = render_stix(data)
        body = stix_dumps(obj)
        name, media = names["stix"], "application/stix+json"
    else:
        obj = render_misp(data)
        body = json.dumps(obj, indent=2, ensure_ascii=True) + "\n"
        name, media = names["misp"], "application/json"
    for artefact in (obj, body):
        verdict = guard(artefact, terms, fmt="json", ctx=ctx)
        release(verdict)
    return name, media, body


async def build_export(
    db: AsyncSession,
    kind: Literal["stix", "misp"],
    *,
    report: uuid.UUID | None,
    campaign: int | None,
    since: datetime | None,
    until: datetime | None,
    tlp: str | None,
    description: str | None = None,
) -> tuple[str, str, str, int] | Response:
    """Build, guard and return (name, media, text, item count) or an error response."""
    bundle = await load_settings(db)
    missing = list(missing_for(bundle.settings))
    if kind == "misp" and not (description or "").strip():
        missing.append("description")
    if missing:
        return settings_incomplete_response(missing)
    chosen: Tlp = tlp if tlp in ("clear", "green", "amber", "red") else bundle.tlp  # type: ignore[assignment]
    terms = await load_terms(db)
    now = datetime.now(UTC)
    if report is not None:
        loaded = await _load(db, report)
        if loaded is None:
            return error(404, "Report not found", "not_found")
        row, rec = loaded
        if held := held_evidence_codes(row):
            log.warning("abuse export held kind=%s reasons=%s", kind, ",".join(held))
            return guard_failed_response(held)
        try:
            evidence = build_evidence(row, rec, bundle)
        except EvidenceInvalidError:
            return error(409, "The stored evidence is not valid.", "evidence_invalid")
        ctx = await guard_context(db, row, evidence)
        data = export_from_evidence(
            evidence,
            export_id=derive_id(row.id_seed, "export", "report"),
            id_seed=row.id_seed,
            created=now,
            tlp=chosen,
        ).model_copy(update={"description": (description or "").strip()})
    else:
        demo = include_demo()
        ctx = GuardContext(allow_documentation=demo)
        if campaign is not None and await db.get(CampaignRow, campaign) is None:
            return error(404, "Campaign not found", "not_found")
        items = await collect_items(db, campaign=campaign, since=since, until=until, demo=demo)
        items = await asyncio.to_thread(_screen, items, terms, ctx)
        if not items:
            return error(404, "Nothing to export for that scope.", "no_indicators")
        data = ExportData(
            export_id=new_public_id(),
            id_seed=new_seed(),
            created=now,
            tlp=chosen,
            demo=demo,
            description=(description or "").strip(),
            items=tuple(items),
        )
    name, media, body = await asyncio.to_thread(_render, data, kind, terms, ctx)
    return name, media, body, len(data.items)


@router.get("/abuse/exports/{kind}")
async def export_indicators(
    kind: Literal["stix", "misp"],
    request: Request,
    db: DbSession,
    report: uuid.UUID | None = None,
    campaign: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    tlp: Tlp | None = None,
    description: Annotated[str | None, Query(max_length=500)] = None,
) -> Response:
    """One report, one campaign, or a window of at most 31 days. TLP chosen at export."""
    given = [report is not None, campaign is not None, since is not None]
    if sum(given) != 1 or (until is not None and since is None):
        return error(422, "Give exactly one of report, campaign or since.", "invalid_scope")
    if since is not None:
        since = since.astimezone(UTC)
        until = (until or datetime.now(UTC)).astimezone(UTC)
        if until <= since or until - since > timedelta(days=MAX_WINDOW_DAYS):
            return error(422, f"The window must be 1 second to {MAX_WINDOW_DAYS} days.", "window")
    try:
        built = await build_export(
            db,
            kind,
            report=report,
            campaign=campaign,
            since=since,
            until=until,
            tlp=tlp,
            description=description,
        )
    except RenderUnavailable as exc:
        if exc.code == "settings_incomplete":
            return settings_incomplete_response(["description"])
        return error(409, "This export is not available.", exc.code)
    except GuardFailed as exc:
        log.warning("abuse export blocked kind=%s reasons=%s", kind, ",".join(exc.codes))
        return guard_failed_response(exc.codes)
    if isinstance(built, Response):
        return built
    name, media, body, count = built
    principal = await _principal(request)
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.export",
        target=name,
        ip=_client_ip(request),
        details={
            "format": kind,
            "scope": "report" if report else "campaign" if campaign else "window",
            "items": count,
            "tlp": tlp,
        },
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Response(
        body.encode("ascii"),
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


# ---- sample bundle -------------------------------------------------------------------------

_bundles: dict[str, deque[float]] = {}


def _rate_limited(user: str) -> int | None:
    now = time.monotonic()
    window = _bundles.setdefault(user, deque())
    while window and now - window[0] > 3600:
        window.popleft()
    if len(window) >= BUNDLE_PER_HOUR:
        return int(3600 - (now - window[0])) + 1
    return None


class BundleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: Annotated[list[Sha256Hex], Field(min_length=1, max_length=10)]
    password: Annotated[str | None, Field(max_length=1024)] = None


@router.post("/abuse/exports/samples")
async def export_samples(body: BundleBody, request: Request, db: DbSession) -> Response:
    """Up to 10 stored samples in one AES-256 zip (password ``infected``). Administrator only,
    password asked again, 5 per hour. A sample that embeds the monitored system's address is left
    out and reported in ``X-Excluded`` (a count) and ``X-Excluded-Samples`` (the hashes)."""
    service: auth_mod.AuthService = request.app.state.auth
    if body.password is None and not service.settings.disabled:
        return reauth.error(401, "Password required", "reauth_required")
    principal, refused = await reauth.guard(request, body.password, "sample bundle")
    if refused is not None:
        return refused
    actor = principal.username if principal else "anonymous"
    wait = _rate_limited(actor)
    if wait is not None:
        return reauth.error(429, "Too many exports", "rate_limited", {"Retry-After": str(wait)})
    missing = missing_for((await load_settings(db)).settings)
    if missing:
        return settings_incomplete_response(missing)
    wanted = sorted(set(body.sha256))
    rows = (
        await db.execute(
            text(
                "SELECT sha256, sha1, md5, tlsh, size, kind, arch, family, first_seen "
                "FROM samples WHERE stored AND sha256 = ANY(:shas)"
            ),
            {"shas": wanted},
        )
    ).all()
    if len(rows) != len(wanted):
        return reauth.error(404, "A sample is not stored", "not_stored")
    samples: list[BundleSample] = []
    for r in rows:
        try:
            data = await asyncio.to_thread(read_quarantined, r.sha256)
        except ArchiveError as exc:
            return reauth.error(exc.status, exc.detail, "archive_unavailable")
        samples.append(
            BundleSample(
                SampleRef(
                    sha256=r.sha256,
                    sha1=r.sha1,
                    md5=r.md5,
                    tlsh=r.tlsh,
                    size=r.size,
                    kind=r.kind,
                    arch=r.arch,
                    family=r.family,
                    first_seen=r.first_seen,
                ),
                data,
            )
        )
    terms = await load_terms(db)
    try:
        result = await asyncio.to_thread(
            build_sample_bundle,
            samples,
            terms,
            ctx=GuardContext(allow_documentation=include_demo()),
        )
    except GuardFailed as exc:
        log.warning("abuse bundle blocked reasons=%s", ",".join(exc.codes))
        return guard_failed_response(exc.codes)
    except BundleLimitError as exc:
        return reauth.error(
            413 if exc.code == "bundle_limit" else 422, "Bundle too large", exc.code
        )
    _bundles.setdefault(actor, deque()).append(time.monotonic())
    excluded: list[dict[str, Any]] = [
        {"sha256": sha, "reasons": list(codes)} for sha, codes in result.excluded
    ]
    await audit_db.record(
        db,
        actor=actor,
        action="abuse.export",
        target="samples",
        ip=service.client_ip(request),
        details={
            "format": "samples",
            "samples": len(result.included),
            "excluded": len(excluded),
        },
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    if result.data is None:
        return Response(
            json.dumps(
                {
                    "detail": "Every sample was left out by the identity check.",
                    "code": "all_excluded",
                    "excluded": excluded,
                }
            ),
            status_code=409,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )
    name = export_names(new_public_id())["samples"]
    headers = {
        "Content-Disposition": f'attachment; filename="{name}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }
    if excluded:
        headers["X-Excluded"] = str(len(excluded))
        headers["X-Excluded-Samples"] = ",".join(e["sha256"] for e in excluded)
    return Response(result.data, media_type="application/zip", headers=headers)
