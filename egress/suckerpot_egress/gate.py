"""The egress gate: a periodic self-check that opens or closes every outbound client.

Check order and reason codes follow docs/dev/design/m21.md section 3.4. A reason is always a
constant code, never a server answer.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from suckerpot_egress.settings import HUBPROXY_PORT, EgressSettings

log = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ECHO_TIMEOUT_S = 10.0
CONTROL_TIMEOUT_S = 5.0
ECHO_MAX_BYTES = 64
PROXY_ERRORS_BEFORE_RECHECK = 3
STALE_FACTOR = 2  # a verdict older than this many intervals no longer counts as open
FAST_RETRY_S = 20.0  # while closed, re-check this often ...
FAST_RETRY_MAX = 10  # ... for this many consecutive failures, then back off to the interval
EXTRA_CIDRS_TTL_S = 60.0  # the extra allowed ranges are read at most this often

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network
type ExtraCidrs = Callable[[], Awaitable[Sequence[Network]]]
type SelfNetworks = Callable[[], Awaitable[Sequence[Network]]]
type AsnLookup = Callable[[str], tuple[int | None, str | None]]

REASONS = (
    "ok",
    "not_checked",
    "stale",
    "no_vpn",
    "tunnel_down",
    "no_public_ip",
    "echo_failed",
    "echo_disagree",
    "ip_mismatch",
    "ip_not_global",
    "ip_not_allowed",
    "exit_is_self",
    "exit_asn_denied",
    "check_error",
    # direct mode (M32)
    "egress_direct",
    "no_hubproxy",
    "direct_allow_mismatch",
)


class EgressClosed(Exception):
    """The gate is closed. Retry later; nothing was sent, so no quota may be spent."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GateStatus:
    open: bool
    reason: str
    egress_ip: str | None
    checked_at: datetime
    asn: int | None = None
    org: str | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_ip(text: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


class EgressGate:
    def __init__(
        self,
        settings: EgressSettings,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = _utcnow,
        extra_cidrs: ExtraCidrs | None = None,
        self_networks: SelfNetworks | None = None,
        asn_lookup: AsnLookup | None = None,
    ) -> None:
        self.settings = settings
        # Ranges the owner trusted at run time (M23). They only ever add to the ``.env`` list.
        self._extra = _Cached(extra_cidrs, clock)
        # The honeypot's own addresses (M23): the exit may never be one of them.
        self._self = _Cached(self_networks, clock)
        self._asn_lookup = asn_lookup  # local database only, never a network call
        self._clock = clock
        self._injected = client
        self._control: httpx.AsyncClient | None = client
        self._proxied: httpx.AsyncClient | None = client
        self._status = GateStatus(False, "not_checked", None, datetime.fromtimestamp(0, UTC))
        self._proxy_errors = 0
        self._failures = 0  # consecutive closed verdicts
        self._wake = asyncio.Event()

    # ---- state --------------------------------------------------------------------------------
    @property
    def status(self) -> GateStatus:
        return self._status

    def require_open(self, host: str | None = None) -> None:
        """Raise ``EgressClosed`` unless egress may start. In direct mode the gate is open only
        for a request whose ``host`` is in the scope (hub, feed); any other caller, or one that
        names no host, is refused with ``egress_direct``. VPN mode ignores ``host``."""
        if self.settings.direct and not self._in_scope(host):
            raise EgressClosed("egress_direct")
        st = self._status
        if not st.open:
            raise EgressClosed(st.reason)
        age = (self._clock() - st.checked_at).total_seconds()
        if age > self.settings.check_interval_s * STALE_FACTOR:
            raise EgressClosed("stale")

    def _in_scope(self, host: str | None) -> bool:
        return host is not None and host.lower().rstrip(".") in self.settings.scope_hosts

    def note_proxy_ok(self) -> None:
        self._proxy_errors = 0

    def note_proxy_error(self) -> None:
        """Three proxy errors in a row ask for a re-check right away."""
        self._proxy_errors += 1
        if self._proxy_errors >= PROXY_ERRORS_BEFORE_RECHECK:
            self._proxy_errors = 0
            self._wake.set()

    def _set(
        self,
        ok: bool,
        reason: str,
        ip: str | None,
        asn: int | None = None,
        org: str | None = None,
    ) -> GateStatus:
        previous = self._status
        self._status = GateStatus(ok, reason, ip, self._clock(), asn, org)
        if (previous.open, previous.reason) != (ok, reason):
            log.info("egress gate %s (%s)", "open" if ok else "closed", reason)
        return self._status

    # ---- clients ------------------------------------------------------------------------------
    def _clients(self) -> tuple[httpx.AsyncClient, httpx.AsyncClient]:
        if self._control is None or self._proxied is None:
            s = self.settings
            # The control server is on an internal network: never through the proxy.
            self._control = httpx.AsyncClient(
                timeout=CONTROL_TIMEOUT_S, trust_env=False, follow_redirects=False
            )
            self._proxied = httpx.AsyncClient(
                timeout=ECHO_TIMEOUT_S,
                trust_env=False,
                follow_redirects=False,
                proxy=httpx.Proxy(s.proxy_url, auth=(s.proxy_user, s.proxy_password)),
            )
        return self._control, self._proxied

    async def aclose(self) -> None:
        if self._injected is not None:
            return
        for c in {id(c): c for c in (self._control, self._proxied) if c is not None}.values():
            await c.aclose()
        self._control = self._proxied = None

    # ---- the check ----------------------------------------------------------------------------
    async def check(self) -> GateStatus:
        try:
            return await self._check()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("egress self-check crashed (%s)", type(exc).__name__)
            return self._set(False, "check_error", None)

    async def _check(self) -> GateStatus:
        if self.settings.direct:
            return await self._check_direct()
        control, _ = self._clients()
        base = self.settings.control_url
        # 1. tunnel state
        try:
            resp = await control.get(f"{base}/v1/vpn/status")
        except httpx.HTTPError:
            return self._set(False, "no_vpn", None)
        if resp.status_code != 200 or _json_field(resp, "status") != "running":
            return self._set(False, "tunnel_down", None)
        # 2. gluetun's own view of its exit address
        try:
            resp = await control.get(f"{base}/v1/publicip/ip")
        except httpx.HTTPError:
            return self._set(False, "no_public_ip", None)
        reported = (
            _parse_ip(_json_field(resp, "public_ip") or "") if resp.status_code == 200 else None
        )
        if reported is None:
            return self._set(False, "no_public_ip", None)
        # 3. what the outside world sees through the proxy
        answers = await asyncio.gather(*(self._echo(u) for u in self.settings.echo_urls))
        good = [a for a in answers if a is not None]
        if len(good) < 2:
            return self._set(False, "echo_failed", None)
        seen = good[0]
        if any(a != seen for a in good[1:]):
            return self._set(False, "echo_disagree", None)
        shown = str(seen)
        # 4. same address as gluetun reports
        if seen != reported:
            return self._set(False, "ip_mismatch", shown)
        # 5. a public address
        if not seen.is_global:
            return self._set(False, "ip_not_global", shown)
        asn, org = self._asn_of(shown)
        # 6. never the honeypot's own address (or its network), whatever the ranges say
        if any(seen in net for net in await self._self.get()):
            return self._set(False, "exit_is_self", shown, asn, org)
        # 7. not an operator-denied AS
        if asn is not None and asn in self.settings.deny_asns:
            return self._set(False, "exit_asn_denied", shown, asn, org)
        # 8. inside the VPN's expected range, or one the owner trusted
        if not any(seen in net for net in self.settings.allowed_cidrs) and not any(
            seen in net for net in await self._extra.get()
        ):
            return self._set(False, "ip_not_allowed", shown, asn, org)
        return self._set(True, "ok", shown, asn, org)

    async def _check_direct(self) -> GateStatus:
        """Direct mode: ``hubproxy`` must be up and allow no name outside the scope. No echo
        request (it would reach a third party from the home address) and no exit-address check
        (there is no tunnel)."""
        control, _ = self._clients()
        try:
            resp = await control.get(f"{self.settings.control_url}/status")
        except httpx.HTTPError:
            return self._set(False, "no_hubproxy", None)
        if resp.status_code != 200:
            return self._set(False, "no_hubproxy", None)
        try:
            body = resp.json()
        except ValueError:
            return self._set(False, "no_hubproxy", None)
        if not isinstance(body, dict) or body.get("mode") != "direct" or body.get("ok") is not True:
            return self._set(False, "no_hubproxy", None)
        allow = body.get("allow")
        wanted = {f"{h}:{HUBPROXY_PORT}" for h in self.settings.scope_hosts}
        if (
            not isinstance(allow, list)
            or not allow
            or not all(isinstance(a, str) for a in allow)
            or not set(allow) <= wanted
        ):
            return self._set(False, "direct_allow_mismatch", None)
        return self._set(True, "ok", None)

    def _asn_of(self, ip: str) -> tuple[int | None, str | None]:
        if self._asn_lookup is None:
            return None, None
        try:
            return self._asn_lookup(ip)
        except Exception as exc:
            log.warning("asn lookup failed (%s)", type(exc).__name__)
            return None, None

    async def _echo(self, url: str) -> IPAddress | None:
        _, proxied = self._clients()
        try:
            async with proxied.stream("GET", url, timeout=ECHO_TIMEOUT_S) as resp:
                if resp.status_code != 200:
                    return None
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > ECHO_MAX_BYTES:
                        return None
        except httpx.HTTPError:
            return None
        return _parse_ip(body.decode("ascii", "ignore"))

    def next_delay(self, status: GateStatus) -> float:
        """Seconds to wait before the next check. A closed gate is re-checked quickly (a tunnel
        that was restarted comes back within seconds), for ``FAST_RETRY_MAX`` failures in a
        row; after that, or while open, the normal interval applies. Opening resets the count."""
        if status.open:
            self._failures = 0
            return float(self.settings.check_interval_s)
        self._failures += 1
        if self._failures <= FAST_RETRY_MAX:
            return min(FAST_RETRY_S, float(self.settings.check_interval_s))
        return float(self.settings.check_interval_s)

    def request_check(self) -> None:
        """Re-check now (the dashboard's "Check now"); restarts the fast retry window."""
        self._failures = 0
        self._wake.set()

    async def run(self, on_status: Callable[[GateStatus], Awaitable[None]] | None = None) -> None:
        """Check at start, then every interval, or sooner after repeated proxy errors.

        ``on_status`` is awaited after every check (to publish it); its errors are logged only.
        """
        while True:
            # Clear first: a request that arrives during the check must not be lost.
            self._wake.clear()
            status = await self.check()
            if on_status is not None:
                try:
                    await on_status(status)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning("could not publish the egress status (%s)", type(exc).__name__)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self.next_delay(status))


class _Cached:
    """A list of networks read from ``provider`` at most once a minute. A failing read keeps the
    last good list (empty at start) and is retried after the same delay, not at every check."""

    def __init__(
        self,
        provider: Callable[[], Awaitable[Sequence[Network]]] | None,
        clock: Callable[[], datetime],
    ) -> None:
        self._provider = provider
        self._clock = clock
        self._value: tuple[Network, ...] = ()
        self._read_at: datetime | None = None

    async def get(self) -> tuple[Network, ...]:
        if self._provider is None:
            return ()
        now = self._clock()
        if self._read_at is not None and (now - self._read_at).total_seconds() < EXTRA_CIDRS_TTL_S:
            return self._value
        self._read_at = now
        try:
            self._value = tuple(await self._provider())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("could not read a network list (%s)", type(exc).__name__)
        return self._value


def _json_field(resp: httpx.Response, key: str) -> str | None:
    try:
        body = resp.json()
    except ValueError:
        return None
    value = body.get(key) if isinstance(body, dict) else None
    return value if isinstance(value, str) else None
