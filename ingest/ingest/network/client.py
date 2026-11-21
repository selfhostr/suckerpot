"""Signed requests to the hub, through the egress gate and nowhere else (design M29, N2 and N9).

* The only HTTP client is ``ingest.egress.make_client`` (VPN proxy, gate checked per request);
  a closed gate raises ``EgressClosed`` before any byte is written.
* The URL is ``NETWORK_HUB_URL`` plus a ``/v1`` path built here: HTTPS, no redirects, never any
  other host.
* Bodies are padded to a multiple of 4096 bytes and signed with the node key; every answer must
  carry the hub's signature over this request's nonce, or it is thrown away unread
  (``ProtoError('hub_signature')``).
* Nothing from an answer is logged. Error bodies are reduced to their protocol code.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from typing import Any, Final
from urllib.parse import quote, urlsplit

import httpx
from suckerpot_netproto import ERROR_STATUS, parse_response, sign
from suckerpot_netproto import models as wire
from suckerpot_netproto.enums import API_PREFIX, PROTOCOL, USER_AGENT

from ingest.egress import EgressClosed, EgressGate, gate_open, make_client

from .config import NetworkSettings
from .identity import Identity

TIMEOUT: Final = httpx.Timeout(30.0, connect=10.0)
MAX_RESPONSE: Final = 2 * 1024 * 1024
LIMITS: Final = httpx.Limits(max_connections=2, max_keepalive_connections=0)


class HubError(Exception):
    """The hub answered with a protocol error (signature verified)."""

    def __init__(self, code: str, status: int, retry_after: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after = retry_after


class HubUnavailable(Exception):
    """The hub could not be reached (timeout, refused, oversized or unreadable answer)."""


class HubNoVerify(HubUnavailable):
    """A pre-M32 hub: the verification endpoints answer an unsigned 404 (retry once a day)."""


class HubClient:
    """One node's view of the hub. Build it with the node identity once it exists."""

    def __init__(
        self,
        settings: NetworkSettings,
        identity: Identity | None = None,
        *,
        gate: EgressGate | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not settings.hub_configured:
            raise ValueError("no hub configured")
        self.settings = settings
        self.identity = identity
        self._gate = gate
        self._client = client
        self._clock = clock
        # Clock reading of the last answer that passed the signature check with a 2xx status:
        # the worker counts it as hub contact even when a later call of the cycle fails.
        self.last_ok: float | None = None

    # -- plumbing ---------------------------------------------------------------------------

    def _url(self, target: str) -> str:
        url = self.settings.hub_url + target
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname != self.settings.hub_host:
            raise ValueError("refusing a URL outside the configured hub")
        if not target.startswith(API_PREFIX + "/"):
            raise ValueError("refusing a path outside the protocol")
        return url

    async def _send(
        self, method: str, target: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, bytes, Mapping[str, str]]:
        url = self._url(target)
        if not gate_open(self._gate, host=self.settings.hub_host):
            raise EgressClosed("egress_closed")
        owned = self._client is None
        client = self._client or make_client(
            TIMEOUT, gate=self._gate, follow_redirects=False, limits=LIMITS
        )
        try:
            async with client.stream(method, url, content=body or None, headers=headers) as resp:
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        raise HubUnavailable("answer too large")
                    chunks.append(chunk)
                return resp.status_code, b"".join(chunks), resp.headers
        except httpx.HTTPError as exc:
            raise HubUnavailable(type(exc).__name__) from None
        finally:
            if owned:
                await client.aclose()

    async def _call(
        self,
        method: str,
        target: str,
        payload: Mapping[str, Any] | None,
        model: type[Any] | None,
        *,
        signed: bool = True,
        identity: Identity | None = None,
    ) -> Any:
        who = identity or self.identity
        body = sign.pad_body(payload) if payload is not None else b""
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if signed:
            if who is None:
                raise ValueError("a signed request needs the node identity")
            sig = sign.sign_request(who.seed, method, target, body, timestamp=int(self._clock()))
            headers.update(sig.as_dict())
            nonce = sig.nonce
        else:
            nonce = sign.new_nonce()
            headers[sign.H_NONCE] = nonce
        status, raw, resp_headers = await self._send(method, target, body, headers)
        if (
            status == 404
            and target.startswith(f"{API_PREFIX}/verify/")
            and not any(_signatures(resp_headers))
        ):
            raise HubNoVerify("hub_no_verify")
        if status >= 400 and not any(_signatures(resp_headers)):
            # The hub does not sign an answer to a request it could not authenticate: that is
            # "not authenticated", never a statement by the hub. Try again later.
            raise HubUnavailable("unsigned error")
        self._verify(
            method=method,
            target=target,
            node_key=who.node_key if signed and who is not None else None,
            nonce=nonce,
            request_signature=headers.get(sign.H_SIGNATURE),
            request_body=body,
            status=status,
            body=raw,
            hub_signatures=_signatures(resp_headers),
        )
        if status >= 400:
            raise _hub_error(status, raw, resp_headers)
        self.last_ok = self._clock()
        if model is None:
            return None
        return parse_response(model, raw)

    def _verify(
        self,
        *,
        method: str,
        target: str,
        node_key: str | None,
        nonce: str,
        request_signature: str | None,
        request_body: bytes,
        status: int,
        body: bytes,
        hub_signatures: tuple[str | None, str | None],
    ) -> None:
        """The ONE place that checks the hub's answer signature (raises ``hub_signature``).

        Either signature header (primary, alternate) may verify under any pinned key (N19).

        The answer is bound to the whole request (method, target, node key, nonce, request
        signature or body hash). A newer netproto that binds more changes this method only.
        """
        if node_key is not None and request_signature is not None:
            binding = sign.RequestBinding.signed(method, target, node_key, nonce, request_signature)
        else:
            binding = sign.RequestBinding.unsigned(method, target, nonce, request_body)
        sign.require_response_any(self.settings.hub_keys, hub_signatures, binding, status, body)

    # -- unsigned ---------------------------------------------------------------------------

    async def info(self) -> wire.InfoResponse:
        return await self._call("GET", f"{API_PREFIX}/info", None, wire.InfoResponse, signed=False)  # type: ignore[no-any-return]

    async def challenge(self, identity: Identity) -> wire.ChallengeResponse:
        return await self._call(  # type: ignore[no-any-return]
            "POST",
            f"{API_PREFIX}/enrol/challenge",
            {"protocol": PROTOCOL, "node_key": identity.node_key},
            wire.ChallengeResponse,
            signed=False,
        )

    # -- signed -----------------------------------------------------------------------------

    async def enrol(
        self,
        identity: Identity,
        *,
        challenge: str,
        pow_nonce: str,
        pseudonym: str | None,
        country: str | None,
        show_country: bool,
    ) -> wire.EnrolResponse:
        payload: dict[str, Any] = {
            "protocol": PROTOCOL,
            "challenge": challenge,
            "pow_nonce": pow_nonce,
            "show_country": show_country,
        }
        if pseudonym:
            payload["pseudonym"] = pseudonym
        if country:
            payload["country"] = country
        return await self._call(  # type: ignore[no-any-return]
            "POST", f"{API_PREFIX}/enrol", payload, wire.EnrolResponse, identity=identity
        )

    async def node(self) -> wire.NodeInfo:
        return await self._call("GET", f"{API_PREFIX}/node", None, wire.NodeInfo)  # type: ignore[no-any-return]

    async def patch_node(
        self, *, pseudonym: str | None, country: str | None, show_country: bool
    ) -> wire.NodeInfo:
        payload: dict[str, Any] = {"protocol": PROTOCOL, "show_country": show_country}
        if pseudonym:
            payload["pseudonym"] = pseudonym
        if country:
            payload["country"] = country
        return await self._call("PATCH", f"{API_PREFIX}/node", payload, wire.NodeInfo)  # type: ignore[no-any-return]

    async def delete_node(self) -> wire.Deleted:
        return await self._call("DELETE", f"{API_PREFIX}/node", None, wire.Deleted)  # type: ignore[no-any-return]

    async def observations(self, batch: Mapping[str, Any]) -> wire.BatchAccepted:
        return await self._call(  # type: ignore[no-any-return]
            "POST", f"{API_PREFIX}/observations", batch, wire.BatchAccepted
        )

    async def targets(self, cursor: str | None, limit: int = 1000) -> wire.TargetsResponse:
        query = f"limit={int(limit)}"
        if cursor:
            query = f"since={quote(cursor, safe='')}&{query}"
        return await self._call(  # type: ignore[no-any-return]
            "GET", f"{API_PREFIX}/targets?{query}", None, wire.TargetsResponse
        )

    async def reveals(self, items: list[dict[str, str]]) -> wire.AcceptedCount:
        return await self._call(  # type: ignore[no-any-return]
            "POST",
            f"{API_PREFIX}/reveals",
            {"protocol": PROTOCOL, "items": items},
            wire.AcceptedCount,
        )

    async def rechecks(self, day: str, items: list[dict[str, str]]) -> wire.AcceptedCount:
        return await self._call(  # type: ignore[no-any-return]
            "POST",
            f"{API_PREFIX}/rechecks",
            {"protocol": PROTOCOL, "day": day, "items": items},
            wire.AcceptedCount,
        )

    async def verify_reveals(self) -> wire.VerifyRevealsResponse:
        return await self._call(  # type: ignore[no-any-return]
            "GET", f"{API_PREFIX}/verify/reveals", None, wire.VerifyRevealsResponse
        )

    async def verify_tasks(self, limit: int) -> wire.VerifyTasksResponse:
        n = max(1, min(int(limit), wire.MAX_VERIFY_TASKS))
        return await self._call(  # type: ignore[no-any-return]
            "GET", f"{API_PREFIX}/verify/tasks?limit={n}", None, wire.VerifyTasksResponse
        )

    async def verify_results(self, items: list[dict[str, Any]]) -> wire.AcceptedCount:
        return await self._call(  # type: ignore[no-any-return]
            "POST",
            f"{API_PREFIX}/verify/results",
            {"protocol": PROTOCOL, "items": items},
            wire.AcceptedCount,
        )

    async def network(self) -> wire.NetworkSummary:
        return await self._call("GET", f"{API_PREFIX}/network", None, wire.NetworkSummary)  # type: ignore[no-any-return]


def _signatures(headers: Mapping[str, str]) -> tuple[str | None, str | None]:
    return headers.get(sign.H_HUB_SIGNATURE), headers.get(sign.H_HUB_SIGNATURE_ALT)


def _hub_error(status: int, raw: bytes, headers: Mapping[str, str]) -> HubError:
    code = "hub_error"
    try:
        data = json.loads(raw)
        value = data.get("error") if isinstance(data, dict) else None
        # Only a code of the protocol's list is kept; anything else the hub sends (a long or
        # odd string) is reduced to ``hub_error`` so it never reaches the status or a log.
        if isinstance(value, str) and value in ERROR_STATUS:
            code = value
    except ValueError:
        pass
    retry: int | None = None
    raw_retry = headers.get("retry-after", "")
    if raw_retry.isdigit() and len(raw_retry) <= 6:
        retry = int(raw_retry)
    return HubError(code, status, retry)
