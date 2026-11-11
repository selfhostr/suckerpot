"""Test doubles of the network worker: an in-memory store, a fake hub and a fake gate.

The fake hub signs its answers with the real netproto functions and checks the node's request
signatures, so a client or worker that cuts a corner fails here. Every address is a
documentation address or ``example.org``.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import fields
from datetime import UTC, date, datetime
from typing import Any

import httpx
from suckerpot_netproto import models as wire
from suckerpot_netproto import sign
from suckerpot_reporting import SelfTermRow, SelfTerms, load_self_terms

from ingest.network.config import NetworkSettings
from ingest.network.store import Membership

HUB_SEED = bytes(range(32, 64))
HUB_PUBLIC = sign.public_key_of(HUB_SEED)
HUB_KEY = sign.node_key(HUB_PUBLIC)
HUB_URL = "https://hub.example.org"
SELF_IP = "203.0.113.77"
SELF_NAME = "owner-home.example.net"
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def settings(**kw: Any) -> NetworkSettings:
    base: dict[str, Any] = {"enabled": True, "hub_url": HUB_URL, "hub_key": HUB_KEY}
    base.update(kw)
    return NetworkSettings(**base)


def make_terms(with_address: bool = True) -> SelfTerms:
    rows = [SelfTermRow(kind="name", value=SELF_NAME, source="manual")]
    if with_address:
        rows.append(SelfTermRow(kind="address", value=SELF_IP, source="manual"))
    return load_self_terms(rows, {})


class FakeTerms:
    def __init__(self, terms: SelfTerms | None) -> None:
        self.terms = terms

    async def get(self) -> SelfTerms | None:
        return self.terms


class FakeGate:
    def __init__(self, open_: bool = True) -> None:
        self.open = open_

    def require_open(self, host: str | None = None) -> None:
        if not self.open:
            from suckerpot_egress import EgressClosed

            raise EgressClosed("closed")


class MemoryStore:
    """The ``Store`` interface in memory."""

    def __init__(self, **membership: Any) -> None:
        self.m = Membership(**membership)
        self.subs: dict[date, dict[str, Any]] = {}
        self.targets: dict[str, wire.Target] = {}
        self.summary: dict[str, Any] | None = None
        self.values: dict[str, list[str]] = {"url": [], "domain": []}
        self.mine: set[str] = set()
        self.reveal_pool: dict[str, list[str]] = {}
        self.wiped = 0

    async def membership(self) -> Membership:
        return Membership(**{f.name: getattr(self.m, f.name) for f in fields(Membership)})

    async def update(self, **values: Any) -> None:
        for k, v in values.items():
            assert hasattr(self.m, k), k
            setattr(self.m, k, v)

    async def wipe(self, *, leave_error: str | None = None) -> None:
        self.m = Membership(last_error_code=leave_error, left_day=NOW.date())
        self.subs.clear()
        self.targets.clear()
        self.summary = None
        self.wiped += 1

    async def submitted_days(self) -> set[date]:
        return {d for d, s in self.subs.items() if s["status"] in ("sent", "skipped")}

    async def submission(self, day: date) -> dict[str, Any] | None:
        return self.subs.get(day)

    async def record_submission(self, day: date, **kw: Any) -> None:
        old = self.subs.get(day, {})
        payload = kw.pop("payload", None) or old.get("payload")
        self.subs[day] = {**kw, "payload": payload}

    async def drop_payload(self, day: date) -> None:
        if day in self.subs:
            self.subs[day]["payload"] = None

    async def upsert_targets(self, targets: list[wire.Target]) -> None:
        for t in targets:
            self.targets[t.id] = t

    async def refresh_mine(self) -> None:
        return None

    async def mark_mine_blinded(self, value_bs: set[str]) -> None:
        self.mine |= value_bs

    async def save_summary(self, data: dict[str, Any]) -> None:
        self.summary = data

    async def recent_values(self, kind: str) -> list[str]:
        return list(self.values.get(kind, []))

    async def reveal_values(self, kind: str) -> list[str]:
        return list(self.reveal_pool.get(kind, self.values.get(kind, [])))

    async def revealable(self, value_bs: set[str]) -> set[str]:
        return {
            t.value_b
            for t in self.targets.values()
            if t.value_b in value_bs
            and t.value is None
            and t.state in ("confirmed", "reported", "taken_down")
        }


class FakeHub:
    """Answers like the hub, signed with ``HUB_SEED``. Records every request."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[dict[str, Any]] = []
        self.enrolled = False
        self.fail: dict[str, tuple[int, str]] = {}  # "METHOD path" -> (status, error code)
        self.bad_signature = False
        self.unsigned_errors = False
        self.targets: dict[str, Any] = {"cursor": "c_1", "targets": [], "reveal": [], "recheck": []}
        self.node_key: str | None = None
        self.deleted = False
        self.fail_once: dict[str, tuple[int, str]] = {}  # same as ``fail``, consumed on use
        self.duplicate = False  # answer observations as already held (zero accepted)
        self.accept_at_most: int | None = None  # cap each accepted counter (hub rejects the rest)
        self.alt_seed: bytes | None = None  # also sign with this key in the Alt header
        self.primary_signs = True  # False: only the Alt header carries a valid signature
        self.verify_refs: list[str] = []  # blinded hashes of /v1/verify/reveals
        self.verify_tasks: list[dict[str, Any]] = []
        self.no_verify = False  # a pre-M32 hub: unsigned 404 on /v1/verify/*

    def _reply(self, request: httpx.Request, status: int, body: dict[str, Any]) -> httpx.Response:
        raw = json.dumps(body).encode()
        nonce = request.headers.get(sign.H_NONCE, "")
        target = request.url.raw_path.decode()
        if request.headers.get(sign.H_SIGNATURE):
            binding = sign.RequestBinding.signed(
                request.method,
                target,
                request.headers[sign.H_KEY],
                nonce,
                request.headers[sign.H_SIGNATURE],
            )
        else:
            binding = sign.RequestBinding.unsigned(request.method, target, nonce, request.content)
        sig = sign.sign_response(HUB_SEED, binding, status, raw)
        if self.bad_signature:
            sig = sign.sign_response(bytes(32), binding, status, raw)
        if self.unsigned_errors and status >= 400:
            return httpx.Response(status, content=raw)
        headers = {sign.H_HUB_SIGNATURE: sig}
        if not self.primary_signs:
            headers[sign.H_HUB_SIGNATURE] = sign.sign_response(bytes(32), binding, status, raw)
        if self.alt_seed is not None:
            headers[sign.H_HUB_SIGNATURE_ALT] = sign.sign_response(
                self.alt_seed, binding, status, raw
            )
        return httpx.Response(status, content=raw, headers=headers)

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "hub.example.org", "a call left the configured hub"
        assert request.url.scheme == "https"
        path = request.url.raw_path.decode()
        bare = path.split("?")[0]
        self.calls.append((request.method, bare))
        route = f"{request.method} {bare}"
        body = request.content
        if self.no_verify and bare.startswith("/v1/verify/"):
            return httpx.Response(404, content=b"{}")
        assert request.headers.get("Accept-Encoding") == "identity"
        if request.method in ("POST", "PATCH"):
            assert len(body) % 4096 == 0, "bodies are padded"
            self.bodies.append(json.loads(body))
        if bare not in ("/v1/info", "/v1/enrol/challenge"):
            key = request.headers[sign.H_KEY]
            ok = sign.verify_request(
                sign.parse_node_key(key),
                request.headers[sign.H_SIGNATURE],
                request.method,
                path,
                request.headers[sign.H_TIMESTAMP],
                request.headers[sign.H_NONCE],
                body,
            )
            assert ok, "bad node signature"
            self.node_key = key
        if route in self.fail_once:
            status, code = self.fail_once.pop(route)
            return self._reply(request, status, {"error": code})
        if route in self.fail:
            status, code = self.fail[route]
            return self._reply(request, status, {"error": code})
        return self._reply(request, *self.route(route))

    def route(self, route: str) -> tuple[int, dict[str, Any]]:
        day = "2026-11-03"
        node = {
            "node_id": str(uuid.UUID(int=7)),
            "fingerprint": "3f9a1c07",
            "pseudonym": None,
            "country": None,
            "show_country": False,
            "enrolled_day": day,
            "eligible_from_day": "2026-11-17",
            "standing": "good",
            "active_days_14": 3,
        }
        if route == "GET /v1/info":
            return 200, {
                "protocols": ["spn/1"],
                "hub_key": HUB_KEY,
                "pow": {"algorithm": "sha256-leading-zero-bits", "difficulty": 1},
                "limits": {k: 1 for k in wire.Limits.model_fields},
                "thresholds": {"min_nodes": 5, "min_age_days": 14},
                "today": day,
            }
        if route == "POST /v1/enrol/challenge":
            return 200, {
                "challenge": sign.b64u_encode(bytes(32)),
                "difficulty": 1,
                "expires_in": 600,
            }
        if route == "POST /v1/enrol":
            self.enrolled = True
            return 200, {
                "node_id": node["node_id"],
                "fingerprint": "3f9a1c07",
                "enrolled_day": day,
                "eligible_from_day": "2026-11-17",
            }
        if route == "POST /v1/observations":
            b = self.bodies[-1]
            counts = {k: len(b[k]) for k in ("sources", "payloads", "c2", "files")}
            if self.duplicate:  # the hub already holds this batch id
                zeros = dict.fromkeys(counts, 0)
                return 200, {"accepted": zeros, "rejected": {}, "duplicate": True}
            if self.accept_at_most is not None:
                counts = {k: min(v, self.accept_at_most) for k, v in counts.items()}
            return 200, {"accepted": counts, "rejected": {}, "duplicate": False}
        if route == "DELETE /v1/node":
            self.deleted = True
            return 200, {"deleted": True}
        if route in ("PATCH /v1/node", "GET /v1/node"):
            return 200, node
        if route == "GET /v1/targets":
            return 200, self.targets
        if route in ("POST /v1/reveals", "POST /v1/rechecks"):
            return 200, {"accepted": len(self.bodies[-1]["items"]), "rejected": 0}
        if route == "GET /v1/verify/reveals":
            return 200, {"items": [{"kind": "url", "value_b": b} for b in self.verify_refs]}
        if route == "GET /v1/verify/tasks":
            return 200, {"tasks": self.verify_tasks}
        if route == "POST /v1/verify/results":
            return 200, {"accepted": len(self.bodies[-1]["items"]), "rejected": 0}
        if route == "GET /v1/network":
            return 200, {
                "generated_day": day,
                "totals": {
                    "members": 7,
                    "active_7d": 6,
                    "countries": 3,
                    "confirmed_30d": 4,
                    "reported_30d": 2,
                    "taken_down_30d": 1,
                    "median_days_to_takedown": 3,
                },
                "weekly": [],
                "countries": [],
                "members": [],
            }
        return 404, {"error": "invalid_payload"}


def hub_client(hub: FakeHub) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(hub.handle))
