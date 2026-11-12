"""Host-script entry point: ``python -m ingest.network.cli status --json | leave | join``.

Used by ``status.sh`` and ``participant.sh`` through ``docker compose exec -T ingest``. Output is
one JSON document on stdout. It holds no key, no secret and no attacker data; only
``status --last-batch`` adds the exact body of the last submission, which holds attacker
addresses (design M32 section 10).

``status --json`` shape (``schema`` 1)::

    {"schema": 1, "generated_at": "<UTC>", "mode": "participant|full", "enabled": bool,
     "level": "ok|warning|error", "warnings": [code], "errors": [code],
     "state": "off|not_joined|left|enrolling|member|leaving|error", "pseudonym", "node",
     "standing", "counts_from", "path", "self_address", "hub": {"host", "last_contact",
     "signature_ok"}, "sent": [{"day", "sources", "links", "files"}], "reveals_7d": int,
     "sessions_24h": {"<sensor>": int},    # flat keys, the host renderer reads these
     "network": {
       "hub_configured": bool, "hub_host": str|null, "hub_key_differs_from_release": bool,
       "path": "direct|vpn",
       "consent": {"state": "valid|missing|consent_outdated|consent_invalid",
                   "day": "<date>"|null, "items": [str]},
       "membership": {"desired", "state", "pseudonym", "fingerprint", "standing",
                      "enrolled_day", "eligible_from_day", "counts_toward_consensus": bool,
                      "left_day", "requested_by", "last_error"},
       "hub_contact": {"last_at": "<UTC>"|null, "age_hours": float|null},
       "own_address": {"state": "manual|learned|waiting", "waiting_days": int|null},
       "sent": [{"day", "status", "sources", "links", "c2", "files"}],   # newest first, <= 7
       "verify_reveals": {"enabled": bool, "last_7_days": int},
       "verifier": {"enabled": bool, "state": str, "tasks": {"<task state>": int}}},
     "last_batch": {"day": "<date>", "batch": {...}}|null}   # only with --last-batch

Warning codes: ``waiting_self_address`` (more than 2 days), ``hub_contact_old`` (over 26 h),
``consent_outdated``, ``hub_key_differs_from_release``. Error codes: ``hub_signature``,
``guard_failed``. The caller turns ``level`` into exit code 0, 1 or 2.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db import create_engine, create_session_factory
from suckerpot_db.session_counts import sql_sessions_count
from suckerpot_netproto import defaults

from ingest.abuse.selfterms import auto_confirm_enabled, parse_self_address

from . import participant
from .config import NetworkSettings
from .store import SqlStore
from .verifier import SqlVerifyStore

SCHEMA = 1
SENT_DAYS = 7
CONTACT_WARN_H = 26
WAITING_WARN_DAYS = 2
OWN_ADDRESS_FRESH_H = 72
ERROR_CODES = frozenset({"hub_signature", "guard_failed"})


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


def _day(value: date | None) -> str | None:
    return None if value is None else value.isoformat()


def settings_of(env: Mapping[str, str]) -> NetworkSettings | None:
    try:
        return NetworkSettings.from_env(env)
    except ValueError:
        return None


def key_differs_from_release(settings: NetworkSettings) -> bool:
    """True when the pinned hub keys do not contain every key of the release defaults."""
    try:
        release = defaults.load().hub_keys
    except defaults.DefaultsError:
        return False
    return bool(release) and not set(release) <= set(settings.hub_keys)


async def _own_address(session: AsyncSession, env: Mapping[str, str]) -> str:
    if parse_self_address(env.get("SELF_ADDRESS", "")) is not None:
        return "manual"
    auto = auto_confirm_enabled(env)
    row = (
        await session.execute(
            text(
                """
                SELECT
                  count(*) FILTER (WHERE source = 'manual') AS manual,
                  count(*) FILTER (WHERE source = 'learned'
                        AND (confirmed OR (CAST(:auto AS boolean) AND kind = 'address'))
                        AND last_seen > now() - make_interval(hours => :h)) AS learned
                FROM report_self_terms WHERE kind IN ('address', 'cidr')
                """
            ),
            {"h": OWN_ADDRESS_FRESH_H, "auto": auto},
        )
    ).one()
    return "manual" if row.manual else "learned" if row.learned else "waiting"


async def build_status(
    factory: async_sessionmaker[AsyncSession],
    env: Mapping[str, str],
    *,
    now: datetime | None = None,
    last_batch: bool = False,
) -> dict[str, Any]:
    moment = now or datetime.now(UTC)
    settings = settings_of(env) or NetworkSettings()
    consent_state, consent = participant.parse(settings.consent)
    m = await SqlStore(factory).membership()
    async with factory() as session:
        subs = (
            await session.execute(
                text(
                    "SELECT day, status, counts, sent_at FROM network_submissions "
                    "ORDER BY day DESC LIMIT :n"
                ),
                {"n": SENT_DAYS},
            )
        ).all()
        detail_row = (
            await session.execute(text("SELECT detail FROM enrichment_status WHERE name='network'"))
        ).first()
        own = await _own_address(session, env)
        sensors = (
            await session.execute(
                text(
                    f"SELECT sensor, {sql_sessions_count()} AS n FROM sessions "  # noqa: S608
                    "WHERE started_at >= now() - interval '24 hours' GROUP BY sensor"
                )
            )
        ).all()
        batch_row = (
            (
                await session.execute(
                    text(
                        "SELECT day, payload FROM network_submissions "
                        "WHERE payload IS NOT NULL ORDER BY day DESC LIMIT 1"
                    )
                )
            ).first()
            if last_batch
            else None
        )
    tasks = await SqlVerifyStore(factory).counts()
    detail: dict[str, Any] = detail_row.detail if detail_row is not None else {}

    member = m.state == "member"
    stamps = [t for t in (m.last_pull_at, m.last_summary_at) if t is not None]
    stamps += [r.sent_at for r in subs if r.sent_at is not None]
    last_contact = max(stamps) if stamps else None
    age_h = None if last_contact is None else (moment - last_contact).total_seconds() / 3600
    waiting_days: int | None = None
    if own == "waiting" and member and m.enrolled_day is not None:
        waiting_days = max(0, (moment.date() - m.enrolled_day).days)

    differs = key_differs_from_release(settings) if settings.hub_configured else False
    warnings: list[str] = []
    errors: list[str] = []
    if waiting_days is not None and waiting_days > WAITING_WARN_DAYS:
        warnings.append("waiting_self_address")
    if member and (age_h is None or age_h > CONTACT_WARN_H):
        warnings.append("hub_contact_old")
    if settings.participant and consent_state == participant.OUTDATED:
        warnings.append("consent_outdated")
    if differs:
        warnings.append("hub_key_differs_from_release")
    if m.last_error_code in ERROR_CODES:
        errors.append(m.last_error_code)

    sent = []
    for r in subs:
        counts = r.counts or {}
        sent.append(
            {
                "day": _day(r.day),
                "status": r.status,
                "sources": int(counts.get("sources", 0)),
                "links": int(counts.get("payloads", 0)),
                "c2": int(counts.get("c2", 0)),
                "files": int(counts.get("files", 0)),
            }
        )
    week_ago = (moment - timedelta(days=SENT_DAYS)).date().isoformat()
    revealed = sum(int(n) for d, n in (detail.get("revealed") or {}).items() if str(d) > week_ago)
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": _iso(moment),
        "mode": settings.stack_mode,
        "enabled": settings.enabled,
        "level": "error" if errors else "warning" if warnings else "ok",
        "warnings": warnings,
        "errors": errors,
        "network": {
            "hub_configured": settings.hub_configured,
            "hub_host": settings.hub_host or None,
            "hub_key_differs_from_release": differs,
            "path": "direct" if settings.egress_mode == "direct" else "vpn",
            "consent": {
                "state": consent_state,
                "day": _day(consent.day) if consent else None,
                "items": sorted(consent.items) if consent else [],
            },
            "membership": {
                "desired": m.desired,
                "state": m.state,
                "pseudonym": m.pseudonym,
                "fingerprint": m.fingerprint,
                "standing": m.standing,
                "enrolled_day": _day(m.enrolled_day),
                "eligible_from_day": _day(m.eligible_from_day),
                "counts_toward_consensus": bool(
                    member
                    and m.eligible_from_day is not None
                    and m.eligible_from_day <= moment.date()
                ),
                "left_day": _day(m.left_day),
                "requested_by": m.requested_by,
                "last_error": m.last_error_code,
            },
            "hub_contact": {
                "last_at": _iso(last_contact),
                "age_hours": None if age_h is None else round(age_h, 1),
            },
            "own_address": {"state": own, "waiting_days": waiting_days},
            "sent": sent,
            "verify_reveals": {
                "enabled": bool(detail.get("verify_reveals", False)),
                "last_7_days": revealed,
            },
            "verifier": {
                "enabled": settings.verifier,
                "state": str(detail.get("verifier", "off")) if settings.verifier else "off",
                "tasks": tasks,
            },
        },
    }
    # Flat keys for the host renderer (status.sh). Every one is optional there.
    flat_state = m.state
    if m.state == "off":
        flat_state = "left" if m.left_day is not None else "not_joined"
    out.update(
        state=flat_state,
        pseudonym=m.pseudonym,
        node=m.fingerprint,
        standing=m.standing,
        counts_from=_day(m.eligible_from_day),
        path="direct" if settings.egress_mode == "direct" else "vpn",
        self_address=own,
        hub={
            "host": settings.hub_host or None,
            "last_contact": _iso(last_contact),
            "signature_ok": m.last_error_code != "hub_signature",
        },
        sent=[{k: r[k] for k in ("day", "sources", "links", "files")} for r in sent],
        reveals_7d=revealed,
        sessions_24h={r.sensor: int(r.n) for r in sensors},
    )
    if last_batch:
        out["last_batch"] = (
            None if batch_row is None else {"day": _day(batch_row.day), "batch": batch_row.payload}
        )
    return out


async def leave(factory: async_sessionmaker[AsyncSession]) -> dict[str, Any]:
    """Ask the worker to leave. Without a membership the leave marker alone is stored."""
    store = SqlStore(factory)
    m = await store.membership()
    if m.state == "off" and m.desired == "off" and m.pubkey is None:
        await store.update(left_day=datetime.now(UTC).date(), last_error_code=None)
        return {"requested": False, "state": "off"}
    await store.update(desired="leave")
    return {"requested": True, "state": m.state}


async def join(
    factory: async_sessionmaker[AsyncSession], env: Mapping[str, str]
) -> tuple[dict[str, Any], int]:
    """Participant mode only: agree again after a leave (clears the marker, ingest re-joins)."""
    settings = settings_of(env)
    if settings is None or not settings.participant:
        return {"joined": False, "reason": "not_participant"}, 2
    if not settings.enabled:
        return {"joined": False, "reason": "network_disabled"}, 2
    state, _ = participant.parse(settings.consent)
    if state != participant.VALID:
        return {"joined": False, "reason": state}, 2
    store = SqlStore(factory)
    m = await store.membership()
    if m.state == "error":
        await store.update(state="off", desired="off", last_error_code=None)
    await store.update(left_day=None)
    return {"joined": True, "state": m.state}, 0


async def _run(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    engine = create_engine()
    try:
        factory = create_session_factory(engine)
        if args.command == "status":
            doc = await build_status(factory, env, last_batch=args.last_batch)
            code = 0
        elif args.command == "leave":
            doc, code = await leave(factory), 0
        else:
            doc, code = await join(factory, env)
        sys.stdout.write(json.dumps(doc, sort_keys=True) + "\n")
        return code
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ingest.network.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    status = sub.add_parser("status", help="print the network status as JSON")
    status.add_argument("--json", action="store_true", help="accepted for clarity (always JSON)")
    status.add_argument("--last-batch", action="store_true", help="include the last batch body")
    sub.add_parser("leave", help="leave the network (the worker wipes and tells the hub)")
    sub.add_parser("join", help="participant mode: agree again after a leave")
    args = parser.parse_args(argv)
    return asyncio.run(_run(args, dict(os.environ)))


if __name__ == "__main__":
    raise SystemExit(main())
