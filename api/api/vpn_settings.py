"""Upload the WireGuard configuration of the ``vpn`` service from the dashboard (M23).

Design: ``docs/dev/design/m23.md``. The parser here is strict and pure: it returns a summary or a
list of error codes and never echoes the input. The writer drops ``wg.env`` and ``meta.json``
into ``VPN_CONFIG_DIR`` (the ``vpn-config`` volume, mounted read-write in the API only) with a
temp file and ``os.replace``, so the ``vpn`` container never reads half a file. The private key
only ever lives in that volume: it is not logged, not audited and not returned.

Trusting a new exit never uses an address from the client: the API stores the /24 (IPv4) or /48
(IPv6) containing the exit address the egress gate itself observed and published.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi import Path as PathParam
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import EgressCheckRequestRow, EgressTrustedExitRow, EnrichmentStatusRow
from suckerpot_db.trusted_exits import load_self_networks

from api import audit as audit_db
from api import auth as auth_mod
from api import reauth
from api.authz import require_admin
from api.deps import DbSession
from api.egress import _checked_at

router = APIRouter(tags=["settings"])
log = logging.getLogger("api.audit")

CONFIG_DIR_ENV = "VPN_CONFIG_DIR"
DEFAULT_CONFIG_DIR = "/vpn-config"
ENV_FILE = "wg.env"
RESTART_FILE = "restart"  # M24: a timestamp; the vpn entrypoint restarts when it changes
CHECK_MIN_GAP = timedelta(seconds=10)
RECONNECT_MIN_GAP = timedelta(seconds=60)
META_FILE = "meta.json"
MAX_CONF_BYTES = 4096
MAX_TRUSTED_EXITS = 8
CANDIDATE_MAX_AGE = timedelta(minutes=10)
FILE_MODE = 0o644  # gluetun's root has no CAP_DAC_OVERRIDE: it must be able to read the file
# The candidate comes from the ingest gate only (never the collector's row).
GATE_ROW = "egress"
DENY_ASNS_ENV = "EGRESS_DENY_ASNS"
RECONNECT_LOCK_KEY = 0x5350_5243  # distinct from CHECK_LOCK_KEY
CHECK_LOCK_KEY = 0x5350_4348  # advisory lock: one "Check now" decision at a time
BLOCKED_REASONS = ("exit_is_self", "exit_asn_denied")

AdminOnly = Depends(require_admin)

# ---- strict parser ----------------------------------------------------------------------------

_B64_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_PORT = re.compile(r"^[0-9]{1,5}$")
_INTERFACE_KEYS = {"privatekey", "address", "dns"}
_PEER_KEYS = {"publickey", "endpoint", "allowedips", "persistentkeepalive"}
# Keys that run commands or change routing: refused with a specific code.
_DANGEROUS_KEYS = {
    "preup", "postup", "predown", "postdown", "table", "fwmark", "saveconfig", "mtu", "listenport",
}  # fmt: skip
_FULL_TUNNEL = ipaddress.ip_network("0.0.0.0/0")
MAX_ADDRESSES = 4
MAX_ALLOWED_IPS = 8

PROBLEMS = (
    "too_large",
    "empty",
    "not_ascii",
    "syntax",
    "unknown_section",
    "duplicate_section",
    "duplicate_key",
    "forbidden_key",
    "preshared_key_refused",
    "unknown_key",
    "missing_section",
    "missing_private_key",
    "bad_private_key",
    "missing_address",
    "bad_address",
    "no_ipv4_address",
    "missing_public_key",
    "bad_public_key",
    "missing_endpoint",
    "endpoint_not_ip",
    "endpoint_not_global",
    "bad_port",
    "not_full_tunnel",
)


@dataclass(frozen=True)
class WireguardSummary:
    """The validated configuration. ``private_key`` is secret: never log or return it."""

    private_key: str
    public_key: str
    addresses: tuple[str, ...]
    endpoint_ip: str
    endpoint_port: int

    def __repr__(self) -> str:
        return f"WireguardSummary(endpoint={self.endpoint_ip}:{self.endpoint_port})"

    @property
    def peer_key_fingerprint(self) -> str:
        return hashlib.sha256(self.public_key.encode("ascii")).hexdigest()[:12]


@dataclass(frozen=True)
class ParseResult:
    summary: WireguardSummary | None
    problems: tuple[str, ...]


def _valid_key(value: str) -> bool:
    if not _B64_KEY.match(value):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error, ValueError:
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode("ascii") == value  # canonical only


def _parse_addresses(value: str) -> tuple[tuple[str, ...], list[str]]:
    problems: list[str] = []
    out: list[str] = []
    parts = [p.strip() for p in value.split(",")]
    if not value or len(parts) > MAX_ADDRESSES or any(not p or "/" not in p for p in parts):
        return (), ["bad_address"]
    for part in parts:
        try:
            iface = ipaddress.ip_interface(part)
        except ValueError:
            return (), ["bad_address"]
        addr = iface.ip
        if not re.fullmatch(r"[0-9a-fA-F:./]+", str(iface)):
            return (), ["bad_address"]  # e.g. an IPv6 scope id
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
            return (), ["bad_address"]
        out.append(str(iface))
    if not any(ipaddress.ip_interface(a).version == 4 for a in out):
        problems.append("no_ipv4_address")
    return tuple(out), problems


def _parse_endpoint(value: str) -> tuple[str, int, list[str]]:
    host, sep, port = value.rpartition(":")
    if not sep:
        return "", 0, ["endpoint_not_ip"]
    problems: list[str] = []
    try:
        ip = ipaddress.IPv4Address(host)  # a literal: a host name would need a DNS lookup
    except ValueError:
        return "", 0, ["endpoint_not_ip"]
    if not ip.is_global:
        problems.append("endpoint_not_global")
    if not _PORT.match(port) or not 1 <= int(port) <= 65535:
        problems.append("bad_port")
        return str(ip), 0, problems
    return str(ip), int(port), problems


def _has_full_tunnel(value: str) -> tuple[bool, bool]:
    """(parsed fine, contains 0.0.0.0/0)."""
    parts = [p.strip() for p in value.split(",")]
    if not value or len(parts) > MAX_ALLOWED_IPS or any(not p for p in parts):
        return False, False
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in parts:
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            return False, False
    return True, _FULL_TUNNEL in nets


def parse_wireguard(conf: str) -> ParseResult:
    """Strictly parse a wg-quick file. Errors are codes (``PROBLEMS``), never a quote of it."""
    if len(conf.encode("utf-8", "surrogatepass")) > MAX_CONF_BYTES:
        return ParseResult(None, ("too_large",))
    if any(ord(c) > 126 or (ord(c) < 32 and c not in "\r\n\t") for c in conf):
        return ParseResult(None, ("not_ascii",))

    if not any(re.split(r"[#;]", ln, maxsplit=1)[0].strip() for ln in conf.splitlines()):
        return ParseResult(None, ("empty",))
    problems: set[str] = set()
    sections: dict[str, dict[str, str]] = {}
    counts = {"interface": 0, "peer": 0}
    current: dict[str, str] | None = None
    current_name = ""
    for raw in conf.splitlines():
        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            name = line.lower()
            if name not in ("[interface]", "[peer]"):
                problems.add("unknown_section")
                current = None
                continue
            current_name = name.strip("[]")
            counts[current_name] += 1
            if counts[current_name] > 1:
                problems.add("duplicate_section")
                current = None
                continue
            current = sections.setdefault(current_name, {})
            continue
        key, eq, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if not eq or not key:
            problems.add("syntax")
            continue
        if current is None:
            if not current_name:
                problems.add("syntax")  # a key before any section
            continue  # inside a refused or duplicate section: already reported
        if key in _DANGEROUS_KEYS:
            problems.add("forbidden_key")
        elif key == "presharedkey":
            problems.add("preshared_key_refused")
        elif key not in (_INTERFACE_KEYS if current_name == "interface" else _PEER_KEYS):
            problems.add("unknown_key")
        elif key in current:
            problems.add("duplicate_key")
        else:
            current[key] = value

    interface = sections.get("interface")
    peer = sections.get("peer")
    if interface is None:
        problems.add("missing_section")
    if peer is None:
        problems.add("missing_section")

    private_key = public_key = ""
    addresses: tuple[str, ...] = ()
    endpoint_ip, endpoint_port = "", 0
    if interface is not None:
        private_key = interface.get("privatekey", "")
        if "privatekey" not in interface:
            problems.add("missing_private_key")
        elif not _valid_key(private_key):
            problems.add("bad_private_key")
        if "address" not in interface:
            problems.add("missing_address")
        else:
            addresses, found = _parse_addresses(interface["address"])
            problems.update(found)
    if peer is not None:
        public_key = peer.get("publickey", "")
        if "publickey" not in peer:
            problems.add("missing_public_key")
        elif not _valid_key(public_key):
            problems.add("bad_public_key")
        if "endpoint" not in peer:
            problems.add("missing_endpoint")
        else:
            endpoint_ip, endpoint_port, found = _parse_endpoint(peer["endpoint"])
            problems.update(found)
        if "allowedips" not in peer:
            problems.add("not_full_tunnel")
        else:
            parsed, full = _has_full_tunnel(peer["allowedips"])
            if not parsed:
                problems.add("not_full_tunnel")
            elif not full:
                problems.add("not_full_tunnel")

    if problems:
        return ParseResult(None, tuple(p for p in PROBLEMS if p in problems))
    return ParseResult(
        WireguardSummary(private_key, public_key, addresses, endpoint_ip, endpoint_port), ()
    )


# ---- files ------------------------------------------------------------------------------------


def config_dir() -> Path:
    return Path(os.environ.get(CONFIG_DIR_ENV, "") or DEFAULT_CONFIG_DIR)


def config_available() -> bool:
    d = config_dir()
    return d.is_dir() and os.access(d, os.W_OK | os.X_OK)


STALE_TMP_S = 60.0


def clean_stale_tmp(directory: Path, now: float | None = None) -> int:
    """Remove temp files a crashed write left behind (older than a minute, so that a write in
    flight is never touched). Returns how many were removed."""
    cutoff = (time.time() if now is None else now) - STALE_TMP_S
    removed = 0
    for path in directory.glob(".*.tmp"):
        try:
            if path.is_file() and not path.is_symlink() and path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def _atomic_write(directory: Path, name: str, content: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, FILE_MODE)
        os.replace(tmp, directory / name)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def render_env(summary: WireguardSummary) -> str:
    return (
        f"WIREGUARD_PRIVATE_KEY={summary.private_key}\n"
        f"WIREGUARD_PUBLIC_KEY={summary.public_key}\n"
        f"WIREGUARD_ADDRESSES={','.join(summary.addresses)}\n"
        f"WIREGUARD_ENDPOINT_IP={summary.endpoint_ip}\n"
        f"WIREGUARD_ENDPOINT_PORT={summary.endpoint_port}\n"
    )


def write_config(summary: WireguardSummary, uploaded_by: str, now: datetime) -> dict[str, Any]:
    """Write ``meta.json`` then ``wg.env`` (the file the vpn container watches)."""
    directory = config_dir()
    clean_stale_tmp(directory)
    meta = {
        "uploaded_at": now.isoformat(),
        "uploaded_by": uploaded_by,
        "endpoint_ip": summary.endpoint_ip,
        "endpoint_port": summary.endpoint_port,
        "addresses": list(summary.addresses),
        "peer_key_fingerprint": summary.peer_key_fingerprint,
    }
    _atomic_write(directory, META_FILE, json.dumps(meta, ensure_ascii=True) + "\n")
    _atomic_write(directory, ENV_FILE, render_env(summary))
    return meta


def remove_config() -> None:
    directory = config_dir()
    (directory / ENV_FILE).unlink(missing_ok=True)  # first: this is the file that matters
    (directory / META_FILE).unlink(missing_ok=True)


def read_meta() -> dict[str, Any] | None:
    """The non-secret summary of the uploaded file, or None (no upload, or an unreadable file)."""
    directory = config_dir()
    try:
        if not (directory / ENV_FILE).is_file():
            return None
        raw = json.loads((directory / META_FILE).read_text(encoding="ascii"))
    except OSError, ValueError:
        return {}
    return raw if isinstance(raw, dict) else {}


# ---- responses --------------------------------------------------------------------------------

_error = reauth.error


class VpnGate(BaseModel):
    state: str
    reason: str | None
    egress_ip: str | None
    egress_asn: int | None
    egress_org: str | None
    checked_at: datetime | None


class TrustedExit(BaseModel):
    id: int
    cidr: str
    created_at: datetime
    created_by: str | None


class CheckRequest(BaseModel):
    requested_at: datetime
    done_at: datetime | None


class Accepted(BaseModel):
    requested_at: datetime


class VpnSettings(BaseModel):
    source: str  # "env" | "upload"
    uploaded_at: datetime | None
    uploaded_by: str | None
    endpoint_ip: str | None
    endpoint_port: int | None
    addresses: list[str] | None
    peer_key_fingerprint: str | None
    gate: VpnGate
    trusted_exits: list[TrustedExit]
    trust_candidate: str | None
    trust_blocked: str | None  # "exit_is_self" | "exit_asn_denied" | None
    config_writable: bool  # False: the vpn-config volume is missing or read-only (PUT: 503)
    last_check_request: CheckRequest | None  # M24: the latest "Check now"


class PasswordBody(BaseModel):
    password: str = Field(max_length=1024, repr=False)


class UploadBody(BaseModel):
    # Bounded by the model (twice the 4 KiB limit, in characters); the route answers 413 for
    # anything over 4 KiB and, for bigger bodies, the model's own 422.
    conf: str = Field(max_length=8192, repr=False)
    password: str = Field(max_length=1024, repr=False)


def _str(value: object, limit: int = 128) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _meta_fields(meta: dict[str, Any] | None) -> dict[str, Any]:
    keys = ("uploaded_at", "uploaded_by", "endpoint_ip", "endpoint_port", "addresses",
            "peer_key_fingerprint")  # fmt: skip
    if not meta:
        return dict.fromkeys(keys)
    uploaded_at: datetime | None = None
    raw = meta.get("uploaded_at")
    if isinstance(raw, str):
        try:
            uploaded_at = datetime.fromisoformat(raw)
        except ValueError:
            uploaded_at = None
    port = meta.get("endpoint_port")
    addresses = meta.get("addresses")
    return {
        "uploaded_at": uploaded_at,
        "uploaded_by": _str(meta.get("uploaded_by")),
        "endpoint_ip": _str(meta.get("endpoint_ip"), 64),
        "endpoint_port": port if isinstance(port, int) and not isinstance(port, bool) else None,
        "addresses": [a[:64] for a in addresses[:MAX_ADDRESSES] if isinstance(a, str)]
        if isinstance(addresses, list)
        else None,
        "peer_key_fingerprint": _str(meta.get("peer_key_fingerprint"), 16),
    }


def _gate_of(detail: dict[str, Any] | None) -> VpnGate:
    if not detail:
        return VpnGate(
            state="closed", reason="no_status", egress_ip=None, egress_asn=None, egress_org=None,
            checked_at=None,
        )  # fmt: skip
    is_open = detail.get("open") is True
    return VpnGate(
        state="open" if is_open else "closed",
        reason=_str(detail.get("reason"), 64),
        egress_ip=_str(detail.get("egress_ip"), 64),
        egress_asn=_asn_of(detail),
        egress_org=_str(detail.get("egress_org"), 128),
        checked_at=_checked_at(detail),
    )


def _asn_of(detail: dict[str, Any]) -> int | None:
    asn = detail.get("egress_asn")
    return asn if isinstance(asn, int) and not isinstance(asn, bool) and 0 < asn < 2**32 else None


def deny_asns() -> frozenset[int]:
    """``EGRESS_DENY_ASNS``: a comma list such as ``AS64500,64501``. Bad entries are ignored."""
    out: set[int] = set()
    for part in os.environ.get(DENY_ASNS_ENV, "").split(","):
        digits = part.strip().upper().removeprefix("AS")
        if digits.isdigit() and 0 < int(digits) < 2**32:
            out.add(int(digits))
    return frozenset(out)


def candidate_network(
    detail: dict[str, Any] | None, now: datetime
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The /24 (IPv4) or /48 (IPv6) around the exit address a gate observed, if it qualifies:
    the gate is closed on ``ip_not_allowed``, was checked in the last 10 minutes, and the
    address is global."""
    if not detail or detail.get("open") is True or detail.get("reason") != "ip_not_allowed":
        return None
    checked = _checked_at(detail)
    if checked is None or now - checked > CANDIDATE_MAX_AGE or checked - now > timedelta(minutes=1):
        return None
    raw = detail.get("egress_ip")
    if not isinstance(raw, str):
        return None
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if not ip.is_global or ip.is_multicast:
        return None
    prefix = 24 if ip.version == 4 else 48
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


async def _status_rows(db: AsyncSession) -> dict[str, dict[str, Any]]:
    rows = await db.execute(
        select(EnrichmentStatusRow.name, EnrichmentStatusRow.detail).where(
            EnrichmentStatusRow.name == GATE_ROW
        )
    )
    return {r.name: r.detail for r in rows}


async def _trusted(db: AsyncSession) -> list[TrustedExit]:
    rows = (await db.scalars(select(EgressTrustedExitRow).order_by(EgressTrustedExitRow.id))).all()
    return [
        TrustedExit(id=r.id, cidr=str(r.cidr), created_at=r.created_at, created_by=r.created_by)
        for r in rows
    ]


Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def evaluate_candidate(
    detail: dict[str, Any] | None,
    now: datetime,
    self_networks: Sequence[Net],
    denied: frozenset[int],
) -> tuple[Net | None, str | None]:
    """(range to offer, reason it is refused). Never offers a range that contains one of the
    honeypot's own addresses (the owner's home IP must not become a trusted exit), nor one of
    an operator-denied AS."""
    net = candidate_network(detail, now)
    if detail and detail.get("open") is not True and detail.get("reason") in BLOCKED_REASONS:
        checked = _checked_at(detail)
        if checked is not None and -timedelta(minutes=1) < now - checked <= CANDIDATE_MAX_AGE:
            return None, str(detail["reason"])
    if net is None or detail is None:
        return None, None
    if any(net.version == s.version and net.overlaps(s) for s in self_networks):
        return None, "exit_is_self"
    if _asn_of(detail) in denied:
        return None, "exit_asn_denied"
    return net, None


async def _candidate(db: AsyncSession, trusted: list[TrustedExit]) -> tuple[str | None, str | None]:
    """(cidr to offer, blocked reason)."""
    detail = (await _status_rows(db)).get(GATE_ROW)
    own = await load_self_networks(db)
    net, blocked = evaluate_candidate(detail, datetime.now(UTC), own, deny_asns())
    if net is None:
        return None, blocked
    cidr = str(net)
    return (None if any(t.cidr == cidr for t in trusted) else cidr), None


async def _settings(db: AsyncSession) -> VpnSettings:
    meta = await asyncio.to_thread(read_meta)
    details = await _status_rows(db)
    trusted = await _trusted(db)
    candidate, blocked = await _candidate(db, trusted)
    return VpnSettings(
        source="env" if meta is None else "upload",
        **_meta_fields(meta),
        gate=_gate_of(details.get("egress")),
        trusted_exits=trusted,
        trust_candidate=candidate,
        trust_blocked=blocked,
        config_writable=await asyncio.to_thread(config_available),
        last_check_request=await _last_check(db),
    )


async def _last_check(db: AsyncSession) -> CheckRequest | None:
    row = (
        await db.execute(
            select(EgressCheckRequestRow.requested_at, EgressCheckRequestRow.done_at)
            .order_by(EgressCheckRequestRow.id.desc())
            .limit(1)
        )
    ).first()
    return None if row is None else CheckRequest(requested_at=row.requested_at, done_at=row.done_at)


def _ip(request: Request) -> str:
    service: auth_mod.AuthService = request.app.state.auth
    return service.client_ip(request)


def _unavailable() -> Response:
    return _error(503, "The VPN configuration volume is not available.", "vpn_config_unavailable")


# ---- routes -----------------------------------------------------------------------------------


@router.get("/settings/vpn", response_model=VpnSettings, dependencies=[AdminOnly])
async def get_vpn(db: DbSession) -> VpnSettings:
    return await _settings(db)


@router.put("/settings/vpn", response_model=VpnSettings)
async def put_vpn(body: UploadBody, request: Request, db: DbSession) -> Response:
    if len(body.conf.encode("utf-8", "surrogatepass")) > MAX_CONF_BYTES:
        return _error(413, "The file is larger than 4 KiB.", "too_large")
    if not await asyncio.to_thread(config_available):
        return _unavailable()
    principal, refused = await reauth.guard(request, body.password, "vpn upload")
    if refused is not None:
        return refused
    result = parse_wireguard(body.conf)
    if result.summary is None:
        return JSONResponse(
            {
                "detail": "The WireGuard configuration was refused.",
                "code": "invalid_wireguard_config",
                "problems": list(result.problems),
            },
            status_code=422,
        )
    actor = principal.username if principal else "unknown"
    summary = result.summary
    try:
        await asyncio.to_thread(write_config, summary, actor, datetime.now(UTC))
    except OSError:
        log.error("vpn configuration could not be written")
        return _unavailable()
    await audit_db.record(
        db,
        actor=actor,
        action="vpn.upload",
        target=f"{summary.endpoint_ip}:{summary.endpoint_port}",
        ip=_ip(request),
        details={"peer_key_fingerprint": summary.peer_key_fingerprint},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    log.info("vpn configuration uploaded actor=%s endpoint=%s", actor, summary.endpoint_ip)
    return JSONResponse((await _settings(db)).model_dump(mode="json"))


def _too_soon(gap: timedelta, since: datetime, now: datetime) -> Response | None:
    wait = gap - (now - since)
    if timedelta(0) < wait <= gap:
        retry = max(1, int(wait.total_seconds()) + 1)
        return _error(429, "Please wait a moment before trying again.", "too_soon",
                      {"Retry-After": str(retry)})  # fmt: skip
    return None


@router.post("/settings/vpn/check", status_code=202, response_model=Accepted)
async def request_check(request: Request, db: DbSession) -> Response:
    """Ask ingest to re-check the egress gate now. Admin and CSRF only: it changes nothing."""
    principal, refused = await reauth.guard(request, None, "vpn check")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    # One at a time across all workers: serialise on the table's own newest row.
    await db.execute(select(func.pg_advisory_xact_lock(CHECK_LOCK_KEY)))
    now = datetime.now(UTC)
    last = await db.scalar(select(func.max(EgressCheckRequestRow.requested_at)))
    if last is not None and (early := _too_soon(CHECK_MIN_GAP, last, now)) is not None:
        return early
    row = EgressCheckRequestRow(requested_by=actor[:120])
    db.add(row)
    await db.flush()
    await db.refresh(row)
    requested_at = row.requested_at
    await db.commit()
    return JSONResponse(
        Accepted(requested_at=requested_at).model_dump(mode="json"), status_code=202
    )


def _read_restart(directory: Path) -> datetime | None:
    try:
        value = datetime.fromisoformat(
            (directory / RESTART_FILE).read_text(encoding="ascii")[:64].strip()
        )
    except OSError, ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def write_restart(now: datetime) -> None:
    """Drop the restart marker: only a timestamp, atomically, so the vpn entrypoint sees a
    complete file or none."""
    directory = config_dir()
    clean_stale_tmp(directory)
    _atomic_write(directory, RESTART_FILE, now.isoformat() + "\n")


@router.post("/settings/vpn/reconnect", status_code=202, response_model=Accepted)
async def reconnect_vpn(body: PasswordBody, request: Request, db: DbSession) -> Response:
    """Restart the tunnel (the vpn entrypoint watches the marker file). Password again, and at
    most once a minute."""
    if not await asyncio.to_thread(config_available):
        return _unavailable()
    principal, refused = await reauth.guard(request, body.password, "vpn reconnect")
    if refused is not None:
        return refused
    # One decision at a time across workers: held until the commit (or rollback) below.
    await db.execute(select(func.pg_advisory_xact_lock(RECONNECT_LOCK_KEY)))
    now = datetime.now(UTC)
    previous = await asyncio.to_thread(_read_restart, config_dir())
    if previous is not None and (early := _too_soon(RECONNECT_MIN_GAP, previous, now)) is not None:
        return early
    actor = principal.username if principal else "unknown"
    try:
        await asyncio.to_thread(write_restart, now)
    except OSError:
        log.error("vpn restart marker could not be written")
        return _unavailable()
    await audit_db.record(
        db, actor=actor, action="vpn.reconnect", target="vpn", ip=_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    log.info("vpn reconnect requested actor=%s", actor)
    return JSONResponse(Accepted(requested_at=now).model_dump(mode="json"), status_code=202)


@router.delete("/settings/vpn", status_code=204)
async def delete_vpn(body: PasswordBody, request: Request, db: DbSession) -> Response:
    if not await asyncio.to_thread(config_available):
        return _unavailable()
    principal, refused = await reauth.guard(request, body.password, "vpn revert")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    try:
        await asyncio.to_thread(remove_config)
    except OSError:
        log.error("vpn configuration could not be removed")
        return _unavailable()
    await audit_db.record(
        db, actor=actor, action="vpn.revert", target="env", ip=_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    log.info("vpn configuration reverted to .env actor=%s", actor)
    return Response(status_code=204)


@router.post("/settings/vpn/trusted-exits", status_code=201, response_model=TrustedExit)
async def trust_exit(body: PasswordBody, request: Request, db: DbSession) -> Response:
    principal, refused = await reauth.guard(request, body.password, "vpn trust exit")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    trusted = await _trusted(db)
    cidr, blocked = await _candidate(db, trusted)
    if blocked is not None:
        return _error(409, "This exit address cannot be trusted.", blocked)
    if cidr is None:
        return _error(409, "There is no exit range to trust right now.", "no_candidate")
    if len(trusted) >= MAX_TRUSTED_EXITS:
        return _error(409, "Too many trusted exit ranges. Remove one first.", "too_many")
    row = EgressTrustedExitRow(cidr=cidr, created_by=actor[:120])
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return _error(409, "There is no exit range to trust right now.", "no_candidate")
    except DBAPIError as exc:  # the table's own cap (check_violation), if a race got past ours
        await db.rollback()
        if getattr(exc.orig, "sqlstate", None) == "23514":
            return _error(409, "Too many trusted exit ranges. Remove one first.", "too_many")
        raise
    await db.refresh(row)
    await audit_db.record(
        db, actor=actor, action="vpn.trust_exit", target=cidr, ip=_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )  # fmt: skip
    created = TrustedExit(
        id=row.id, cidr=str(row.cidr), created_at=row.created_at, created_by=row.created_by
    )
    await db.commit()
    log.info("vpn exit range trusted actor=%s range=%s", actor, cidr)
    return JSONResponse(created.model_dump(mode="json"), status_code=201)


@router.delete("/settings/vpn/trusted-exits/{exit_id}", status_code=204)
async def untrust_exit(
    exit_id: int = PathParam(ge=1, le=2**62),
    *,
    body: PasswordBody,
    request: Request,
    db: DbSession,
) -> Response:
    principal, refused = await reauth.guard(request, body.password, "vpn untrust exit")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    cidr = await db.scalar(
        delete(EgressTrustedExitRow)
        .where(EgressTrustedExitRow.id == exit_id)
        .returning(EgressTrustedExitRow.cidr)
    )
    if cidr is not None:
        await audit_db.record(
            db, actor=actor, action="vpn.untrust_exit", target=str(cidr), ip=_ip(request),
            actor_id=audit_db.actor_id_of(principal),
        )  # fmt: skip
        log.info("vpn exit range removed actor=%s range=%s", actor, cidr)
    await db.commit()
    return Response(status_code=204)


__all__ = ["parse_wireguard", "router"]
