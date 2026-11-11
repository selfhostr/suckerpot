"""The process-wide egress gate and the only HTTP client factory ingest may use.

Every outbound call goes through ``suckerpot_egress``: the VPN proxy, with the gate checked before
each request. The gate starts closed and only ``main`` runs its self-check loop, so a client built
anywhere else (a unit test, a forgotten code path) can never reach the network: it raises
``EgressClosed``. ``tests/test_egress_static.py`` keeps raw clients out of this package.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

import httpx
from suckerpot_egress import EgressClosed, EgressGate, EgressSettings, egress_client
from suckerpot_egress.gate import AsnLookup, ExtraCidrs, SelfNetworks
from suckerpot_egress.settings import MODE_DIRECT, MODE_VPN
from suckerpot_netproto import defaults

__all__ = [
    "EgressClosed",
    "EgressGate",
    "egress_settings",
    "gate_open",
    "get_gate",
    "install_gate",
    "make_client",
    "set_gate",
]

_gate: EgressGate | None = None


def egress_settings(env: Mapping[str, str] | None = None) -> EgressSettings:
    """``EgressSettings.from_env`` with the direct-mode scope resolved the way the network code
    resolves its URLs (explicit value, else the shipped defaults), so the scope and the URL the
    worker calls cannot disagree. In any other mode the result is exactly ``EgressSettings.from_env``."""
    e = dict(os.environ if env is None else env)
    if (e.get("EGRESS_MODE", "") or MODE_VPN).strip().lower() == MODE_DIRECT:
        e.update(defaults.scope_env(e))
    return EgressSettings.from_env(e)


def get_gate() -> EgressGate:
    global _gate
    if _gate is None:
        _gate = EgressGate(egress_settings())
    return _gate


def install_gate(
    extra_cidrs: ExtraCidrs, self_networks: SelfNetworks, asn_lookup: AsnLookup
) -> EgressGate:
    """Build the process gate with the owner-trusted exit ranges, the honeypot's own networks
    and the local ASN lookup (M23). Call it before any worker is created, so that every worker
    shares this gate."""
    gate = EgressGate(
        egress_settings(),
        extra_cidrs=extra_cidrs,
        self_networks=self_networks,
        asn_lookup=asn_lookup,
    )
    set_gate(gate)
    return gate


def set_gate(gate: EgressGate | None) -> None:
    global _gate
    _gate = gate


def gate_open(gate: EgressGate | None = None, *, host: str | None = None) -> bool:
    """True when egress work may start. Use it before spending any quota.

    In direct mode (M32) only a call that names a ``host`` inside the scope (hub, feed) can be
    true; without a host it is always False there. VPN mode ignores ``host``."""
    g = gate or get_gate()
    try:
        # Without a host the call is the one every caller made before M32.
        if host is None:
            g.require_open()
        else:
            g.require_open(host)
    except EgressClosed:
        return False
    return True


def make_client(
    timeout: httpx.Timeout,
    *,
    gate: EgressGate | None = None,
    follow_redirects: bool = False,
    verify: bool = True,
    limits: httpx.Limits | None = None,
    headers: Mapping[str, str] | None = None,
) -> httpx.AsyncClient:
    return egress_client(
        gate or get_gate(),
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        limits=limits,
        headers=headers,
    )
