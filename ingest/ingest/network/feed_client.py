"""Anonymous, bounded downloads of the public blocklist feed (design M30 section 10, N11 and N12).

* The only HTTP client is ``ingest.egress.make_client`` (VPN proxy, gate checked per request); a
  closed gate raises ``EgressClosed`` before any byte is written.
* ``GET`` only, to the host of ``NETWORK_FEED_URL`` only, HTTPS, no redirect, no query string, no
  cookie, ``Accept-Encoding: identity``. The only identifying header is the generic
  ``User-Agent: spn-feed/1``. Nothing about this node is sent.
* Every answer is read through a byte cap and an overall deadline.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

import httpx
from suckerpot_netproto import defaults
from suckerpot_netproto.feeds import LIST_IDS, minisign

from ingest.egress import EgressClosed, EgressGate, gate_open, make_client

from .config import check_hub_host

USER_AGENT: Final = "spn-feed/1"
TIMEOUT: Final = httpx.Timeout(30.0, connect=10.0)
DEADLINE_S: Final = 120.0
LIMITS: Final = httpx.Limits(max_connections=2, max_keepalive_connections=0)
MAX_SIGNATURE: Final = 4096
DEFAULT_LISTS: Final = ("inbound", "outbound", "outbound-domains")


class FeedHttpError(Exception):
    """The server answered with an unusable status. ``code`` is ``http_<status>``."""

    def __init__(self, status: int) -> None:
        super().__init__(f"http_{status}")
        self.status = status
        self.code = f"http_{status}"


class FeedTooLarge(Exception):
    """An answer is larger than its cap."""


class FeedUnavailable(Exception):
    """The feed host could not be reached, or answered in an unusable way (encoding, timeout)."""


@dataclass(frozen=True, slots=True)
class FeedSettings:
    url: str = ""
    key: str = ""
    interval_s: int = 3600
    lists: tuple[str, ...] = DEFAULT_LISTS

    @property
    def configured(self) -> bool:
        return bool(self.url and self.key)

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> FeedSettings:
        e = os.environ if env is None else env
        # Committed defaults apply only when the operator set neither value (same rule as the hub).
        url, key = defaults.effective_pair(e, "NETWORK_FEED_URL", "NETWORK_FEED_KEY")
        raw_interval = e.get("NETWORK_FEED_INTERVAL_S", "").strip() or "3600"
        try:
            interval = int(raw_interval)
        except ValueError:
            raise ValueError("NETWORK_FEED_INTERVAL_S must be an integer") from None
        if not 900 <= interval <= 86_400:
            raise ValueError("NETWORK_FEED_INTERVAL_S must be between 900 and 86400")
        raw_lists = e.get("NETWORK_FEED_LISTS", "").strip() or ",".join(DEFAULT_LISTS)
        lists: list[str] = []
        for item in (p.strip() for p in raw_lists.split(",")):
            if not item:
                continue
            if item not in LIST_IDS:
                raise ValueError("NETWORK_FEED_LISTS names an unknown list")
            if item not in lists:
                lists.append(item)
        if not lists:
            raise ValueError("NETWORK_FEED_LISTS must name at least one list")
        settings = cls(
            url=url,
            key=key,
            interval_s=interval,
            lists=tuple(lists),
        )
        if bool(url) != bool(key):
            raise ValueError("NETWORK_FEED_URL and NETWORK_FEED_KEY must be set together")
        if url:
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
                raise ValueError("NETWORK_FEED_URL must be an https URL without a query")
            if parts.username or parts.password:
                raise ValueError("NETWORK_FEED_URL must not hold credentials")
            check_hub_host(parts.hostname)
            minisign.parse_public_key(key)  # FeedError is a ValueError
        return settings


@dataclass(frozen=True, slots=True)
class FeedResponse:
    status: int  # 200, or 304 when ``etag`` matched
    body: bytes
    etag: str | None


class FeedClient:
    def __init__(
        self,
        settings: FeedSettings,
        *,
        gate: EgressGate | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not settings.configured:
            raise ValueError("no feed configured")
        self.settings = settings
        self._gate = gate
        self._client = client

    def _url(self, name: str) -> str:
        if not name or "/" in name or "?" in name or "#" in name or name.startswith("."):
            raise ValueError("refusing a file name outside the feed")
        url = f"{self.settings.url}/{name}"
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname != self.settings.host or parts.query:
            raise ValueError("refusing a URL outside the configured feed")
        return url

    async def get(self, name: str, *, max_bytes: int, etag: str | None = None) -> FeedResponse:
        """``GET <base>/<name>``. 200 and 304 are answers; anything else raises."""
        url = self._url(name)
        if not gate_open(self._gate):
            raise EgressClosed("egress_closed")
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity", "Accept": "*/*"}
        if etag:
            headers["If-None-Match"] = etag
        owned = self._client is None
        client = self._client or make_client(
            TIMEOUT, gate=self._gate, follow_redirects=False, limits=LIMITS
        )
        try:
            async with asyncio.timeout(DEADLINE_S):
                return await self._read(client, url, headers, max_bytes)
        except (httpx.HTTPError, TimeoutError) as exc:
            raise FeedUnavailable(type(exc).__name__) from None
        finally:
            client.cookies.clear()
            if owned:
                await client.aclose()

    @staticmethod
    async def _read(
        client: httpx.AsyncClient, url: str, headers: dict[str, str], max_bytes: int
    ) -> FeedResponse:
        async with client.stream("GET", url, headers=headers) as resp:
            status = resp.status_code
            if status == 304:
                return FeedResponse(304, b"", resp.headers.get("etag"))
            if status != 200:  # includes every redirect: none is followed
                raise FeedHttpError(status)
            encoding = resp.headers.get("content-encoding", "identity").strip().lower()
            if encoding not in ("", "identity"):
                raise FeedUnavailable("content-encoding")
            declared = resp.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise FeedTooLarge(name_of(url))
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise FeedTooLarge(name_of(url))
                chunks.append(chunk)
            return FeedResponse(200, b"".join(chunks), resp.headers.get("etag"))

    async def get_text(self, name: str, *, max_bytes: int = MAX_SIGNATURE) -> str:
        resp = await self.get(name, max_bytes=max_bytes)
        try:
            return resp.body.decode("utf-8")
        except UnicodeDecodeError:
            raise FeedUnavailable("encoding") from None


def name_of(url: str) -> str:
    return urlsplit(url).path.rsplit("/", 1)[-1]
