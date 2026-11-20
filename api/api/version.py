"""The running version and the result of the daily update check (M28, ``docs/dev/design/m28.md`` 7).

The version comes from the image (``SUCKERPOT_RUNNING_VERSION``, baked in at build time). The
latest release is whatever ingest stored in ``enrichment_status`` row ``update_check``: this
module never makes a request. ``release_url`` is built from the configured repository and a
validated tag, never from a response.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import EnrichmentStatusRow

from api.deps import DbSession

router = APIRouter(tags=["settings"])

DEFAULT_UPDATE_REPO = "selfhostr/suckerpot"
UPDATE_ROW = "update_check"
RELEASE_TAG = re.compile(r"v(\d{1,3})\.(\d{1,3})\.(\d{1,3})")
REPO_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
COMMIT = re.compile(r"[0-9a-f]{4,40}")

Check = Literal["ok", "off", "no_egress", "error", "pending"]
CHECK_STATES: tuple[str, ...] = ("ok", "no_egress", "error")


class VersionInfo(BaseModel):
    version: str
    build: Literal["image", "source"]
    commit: str | None
    latest: str | None
    update_available: bool
    checked_at: datetime | None
    check: Check
    release_url: str


def parse_release(tag: object) -> tuple[int, int, int] | None:
    """``v1.2.3`` to ``(1, 2, 3)``; anything else (``dev``, ``v0.8.0-3-gabc``) is None."""
    if not isinstance(tag, str):
        return None
    m = RELEASE_TAG.fullmatch(tag)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def update_check_enabled() -> bool:
    return os.environ.get("UPDATE_CHECK_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def update_repo() -> str:
    repo = os.environ.get("UPDATE_CHECK_REPO", "").strip()
    return repo if REPO_NAME.fullmatch(repo) else DEFAULT_UPDATE_REPO


def _checked_at(detail: dict[str, Any]) -> datetime | None:
    raw = detail.get("checked_at")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def build_info(
    detail: dict[str, Any] | None,
    *,
    running: str,
    kind: str,
    commit: str | None,
    enabled: bool,
    repo: str,
) -> VersionInfo:
    """Pure core of the route: the stored check result and the environment in, the answer out."""
    latest_raw = detail.get("latest") if detail else None
    latest = latest_raw if parse_release(latest_raw) is not None else None
    state = detail.get("state") if detail else None
    check: Check
    if not enabled:
        check = "off"
        latest = None
    elif state == "ok":
        check = "ok"
    elif state == "no_egress":
        check = "no_egress"
    elif state == "error":
        check = "error"
    else:
        check = "pending"
    current, newest = parse_release(running), parse_release(latest)
    available = current is not None and newest is not None and newest > current
    base = f"https://github.com/{repo}/releases"
    return VersionInfo(
        version=running,
        build="image" if kind == "image" else "source",
        commit=commit,
        latest=latest,
        update_available=available,
        checked_at=_checked_at(detail) if detail and enabled else None,
        check=check,
        release_url=f"{base}/tag/{latest}" if latest else base,
    )


async def load_version(db: AsyncSession) -> VersionInfo:
    detail = await db.scalar(
        select(EnrichmentStatusRow.detail).where(EnrichmentStatusRow.name == UPDATE_ROW)
    )
    commit = os.environ.get("SUCKERPOT_COMMIT", "").strip().lower()
    return build_info(
        detail,
        running=(os.environ.get("SUCKERPOT_RUNNING_VERSION", "").strip() or "dev")[:64],
        kind=os.environ.get("SUCKERPOT_BUILD_KIND", "source").strip().lower(),
        commit=commit if COMMIT.fullmatch(commit) else None,
        enabled=update_check_enabled(),
        repo=update_repo(),
    )


@router.get("/version", response_model=VersionInfo)
async def get_version(db: DbSession) -> VersionInfo:
    return await load_version(db)
