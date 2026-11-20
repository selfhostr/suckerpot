"""The daily "is there a newer release?" check (M28, ``docs/dev/design/m28.md`` 7.2).

Privacy contract (invariant P4):

* it only ever runs through the egress gate (``ingest.egress.make_client``); with the gate
  closed nothing is sent and the state is ``no_egress``;
* the request carries no version, no instance identifier, no cookie and no token: two fixed
  headers, nothing else;
* only ``tag_name`` (strict format), ``published_at``, ``prerelease`` and ``draft`` are read from
  the answer; release notes and URLs are never kept;
* it never downloads, pulls or runs anything: updating stays a human action on the host.

The result is one ``enrichment_status`` row, ``update_check``, which the API compares with the
running version.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.egress import EgressClosed, gate_open, make_client
from ingest.enrichment.status import publish_status

log = logging.getLogger(__name__)

DEFAULT_REPO = "selfhostr/suckerpot"
ROW = "update_check"
TIMEOUT = httpx.Timeout(10.0)
MAX_BODY = 64 * 1024
TAG = re.compile(r"v\d{1,3}\.\d{1,3}\.\d{1,3}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2}))?")
# Exactly these two headers; no If-None-Match, no cookie, no token, nothing naming this project.
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "Mozilla/5.0"}
FIRST_DELAY_S = (1 * 3600.0, 6 * 3600.0)
NEXT_DELAY_S = (18 * 3600.0, 30 * 3600.0)  # 24 h +/- 6 h
RETRY_CLOSED_S = 30 * 60.0  # the gate was closed: look again soon, without sending anything


def enabled_from_env(env: dict[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    return source.get("UPDATE_CHECK_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def repo_from_env(env: dict[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    repo = source.get("UPDATE_CHECK_REPO", "").strip()
    return repo if REPO.fullmatch(repo) else DEFAULT_REPO


def first_delay(rng: random.Random | None = None) -> float:
    return (rng or random).uniform(*FIRST_DELAY_S)


def next_delay(rng: random.Random | None = None) -> float:
    return (rng or random).uniform(*NEXT_DELAY_S)


def parse_release(body: object) -> tuple[str, str | None] | None:
    """``(tag, published_at)`` of a usable release, or None. Nothing else is read."""
    if not isinstance(body, dict):
        return None
    if body.get("prerelease") is True or body.get("draft") is True:
        return None
    tag = body.get("tag_name")
    if not isinstance(tag, str) or not TAG.fullmatch(tag):
        return None
    published = body.get("published_at")
    date = published if isinstance(published, str) and DATE.fullmatch(published) else None
    return tag, date


class UpdateChecker:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        *,
        enabled: bool | None = None,
        repo: str | None = None,
        gate: Any = None,
        rng: random.Random | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        publish: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        previous: Callable[[], Awaitable[dict[str, Any]]] | None = None,
    ) -> None:
        self._factory = factory
        self.enabled = enabled_from_env() if enabled is None else enabled
        self.repo = repo if repo is not None and REPO.fullmatch(repo) else repo_from_env()
        self._gate = gate
        self._rng = rng
        self._sleep = sleep
        self._publish = publish or self._publish_row
        self._previous = previous or self._previous_row

    async def _publish_row(self, detail: dict[str, Any]) -> None:
        await publish_status(self._factory, ROW, detail)

    async def _previous_row(self) -> dict[str, Any]:
        async with self._factory() as session:
            raw = await session.scalar(
                text("SELECT detail FROM enrichment_status WHERE name = :n"), {"n": ROW}
            )
        return raw if isinstance(raw, dict) else {}

    async def _fetch(self) -> object:
        url = f"https://api.github.com/repos/{self.repo}/releases/latest"
        async with (
            make_client(TIMEOUT, gate=self._gate, headers=HEADERS) as client,
            client.stream("GET", url) as response,
        ):
            if response.status_code != 200:
                raise ValueError(f"unexpected status {response.status_code}")
            body = b""
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > MAX_BODY:
                    raise ValueError("answer too large")
        return json.loads(body)

    async def check_once(self) -> str:
        """One check. Returns the state written: off, no_egress, ok or error."""
        now = datetime.now(UTC).isoformat()
        if not self.enabled:
            await self._publish({"state": "off", "checked_at": now})
            return "off"
        old = await self._previous()
        kept: dict[str, Any] = {k: old[k] for k in ("latest", "published_at") if k in old}
        if not gate_open(self._gate):
            await self._publish({**kept, "state": "no_egress", "checked_at": now})
            return "no_egress"
        try:
            release = parse_release(await self._fetch())
        except EgressClosed:
            await self._publish({**kept, "state": "no_egress", "checked_at": now})
            return "no_egress"
        except (httpx.HTTPError, ValueError, OSError) as exc:
            log.info("update check failed (%s)", type(exc).__name__)
            await self._publish({**kept, "state": "error", "checked_at": now})
            return "error"
        if release is None:
            # A draft, a prerelease or a tag in a format we do not trust: keep what we knew.
            await self._publish({**kept, "state": "ok", "checked_at": now})
            return "ok"
        latest, published = release
        await self._publish(
            {"latest": latest, "published_at": published, "state": "ok", "checked_at": now}
        )
        return "ok"

    async def run(self) -> None:
        if not self.enabled:
            await self.check_once()  # records "off" once; nothing else ever runs
            return
        delay = first_delay(self._rng)
        while True:
            await self._sleep(delay)
            try:
                state = await self.check_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("update check crashed")
                state = "error"
            delay = RETRY_CLOSED_S if state == "no_egress" else next_delay(self._rng)
