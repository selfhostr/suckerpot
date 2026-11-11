"""The opt-in SuckerPot network, node API (design M29 section 9.6).

The API has no route out and no builder: it records what the administrator asked for
(``network_membership.desired``, a trigger limits it to ``off -> member -> leave``), and shows
what ingest stored (submissions, targets, the hub's daily summary). Ingest does the rest.

* Joining and leaving ask for the account password again; joining also needs the explicit list
  of the five consents. The audit log gets flags only, never the pseudonym.
* The private key column is not selectable by this role: every read lists its columns.
* Reads are open to every signed-in user, except the submissions (they hold the exact JSON that
  was sent) which are administrator only.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.network_names import (
    clean_pseudonym,
    host_of_target,
    pseudonym_problem,
    valid_country,
)
from suckerpot_netproto import defaults
from suckerpot_reporting import guard

from api import audit as audit_db
from api import reauth
from api.abuse_core import error, load_terms
from api.authz import require_admin
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

router = APIRouter(tags=["network"])
log = logging.getLogger("api.network")

CONSENTS = frozenset({"sources", "payloads", "c2", "files", "rechecks"})
TARGET_STATES = ("confirmed", "reported", "taken_down", "disputed", "expired")
TARGET_KINDS = ("ip", "url", "domain", "sha256", "c2_ip", "c2_domain")
WAITING = {
    "waiting_self_address": "self_address",
    "waiting_enrolment": "enrolment",
    "egress_closed": "egress",
    "no_settings_key": "settings_key",
}
HIDDEN_CODES = frozenset({"waiting_self_address", "waiting_enrolment"})
TRUE_VALUES = {"1", "true", "yes", "on"}
RECENT_SUBMISSION = timedelta(days=2)
MAX_SUBMISSIONS = 90

# Everything the API role may read of the membership row (never ``privkey_enc``).
_MEMBERSHIP = (
    "desired, state, pseudonym, country, show_country, fingerprint, enrolled_day, "
    "eligible_from_day, standing, last_submit_day, next_submit_at, last_error_code"
)
_ROW_COLUMNS = "hub_id, kind, value, value_b, state, nodes, countries, first_day, last_day, " \
    "services, activity, tags, families, reported_day, taken_down_day, mine"  # fmt: skip


# ---- shapes --------------------------------------------------------------------------------


class JoinBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    join: Literal[True]
    pseudonym: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, max_length=2)
    show_country: bool = False
    accept: list[str] = Field(max_length=16)
    password: str = Field(max_length=1024, repr=False)  # re-authentication


class UpdateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pseudonym: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, max_length=2)
    show_country: bool = False


class LeaveBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(max_length=1024, repr=False)  # re-authentication


# ---- helpers -------------------------------------------------------------------------------


def _enabled() -> bool:
    """Off unless ``NETWORK_ENABLED`` is set to something true."""
    return os.environ.get("NETWORK_ENABLED", "false").strip().lower() in TRUE_VALUES


def _hub_configured() -> bool:
    """Explicit env value, else the committed default (placeholders count as unset)."""
    return bool(defaults.effective(os.environ, "NETWORK_HUB_URL")) and bool(
        defaults.effective(os.environ, "NETWORK_HUB_KEY")
    )


def _day(value: date | None) -> str | None:
    return value.isoformat() if value else None


def _stamp(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _no_store(body: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


async def _membership(db: AsyncSession) -> Any:
    return (
        await db.execute(text(f"SELECT {_MEMBERSHIP} FROM network_membership WHERE id = 1"))  # noqa: S608
    ).one_or_none()


def status_body(row: Any) -> dict[str, Any]:
    """The ``GET /network/status`` answer (the shape of ``NetworkStatus`` in the web app)."""
    code = row.last_error_code if row is not None else None
    waiting = WAITING.get(code) if code else None
    return {
        "enabled_env": _enabled(),
        "hub_configured": _hub_configured(),
        "desired": row.desired if row else "off",
        "state": row.state if row else "off",
        "pseudonym": row.pseudonym if row else None,
        "country": row.country.strip() if row and row.country else None,
        "show_country": bool(row.show_country) if row else False,
        "fingerprint": row.fingerprint if row else None,
        "enrolled_day": _day(row.enrolled_day) if row else None,
        "eligible_from_day": _day(row.eligible_from_day) if row else None,
        "standing": row.standing if row else None,
        "last_submit_day": _day(row.last_submit_day) if row else None,
        "next_submit_at": _stamp(row.next_submit_at) if row else None,
        "last_error_code": None if code in HIDDEN_CODES else code,
        "waiting": waiting,
    }


async def _status(db: AsyncSession) -> JSONResponse:
    return _no_store(status_body(await _membership(db)))


async def _check_values(
    db: AsyncSession, pseudonym: str | None, country: str | None, show_country: bool
) -> tuple[str | None, str | None, Response | None]:
    """Cleaned pseudonym and country, or the 422 to return."""
    name = clean_pseudonym(pseudonym)
    if name is not None and pseudonym_problem(name) is not None:
        return None, None, error(422, "That pseudonym is not allowed.", "pseudonym_invalid")
    code = (country or "").strip().upper() or None
    if code is not None and not valid_country(code):
        return None, None, error(422, "Use a two-letter country code.", "country_invalid")
    if show_country and code is None:
        return None, None, error(422, "Choose a country to show it.", "country_invalid")
    if name is not None:
        terms = await load_terms(db)
        result = guard(name, terms, fmt="text")
        if set(result.codes) - {"no_self_address"}:
            return (
                None,
                None,
                error(422, "The identity check blocked this pseudonym.", "identity_guard"),
            )
    return name, code, None


# ---- status and membership -----------------------------------------------------------------


@router.get("/network/status")
async def get_status(db: DbSession) -> Response:
    return await _status(db)


@router.put("/network/membership")
async def join(body: JoinBody, request: Request, db: DbSession) -> Response:
    if not _enabled():
        return error(503, "The network is switched off in .env.", "network_disabled")
    if not _hub_configured():
        return error(503, "No network hub is configured.", "network_disabled")
    if set(body.accept) != CONSENTS or len(body.accept) != len(CONSENTS):
        return error(422, "All five consents must be accepted.", "consent_required")
    name, country, bad = await _check_values(db, body.pseudonym, body.country, body.show_country)
    if bad is not None:
        return bad
    principal, refused = await reauth.guard(request, body.password, "network join")
    if refused is not None:
        return refused
    row = await _membership(db)
    if row is None or row.desired != "off" or row.state not in ("off", "error"):
        return error(409, "This system is already part of the network.", "already_member")
    actor = principal.username if principal else "anonymous"
    try:
        await db.execute(
            text(
                "UPDATE network_membership SET desired = 'member', pseudonym = :p, "
                "country = :c, show_country = :s, requested_by = :by, requested_at = now() "
                "WHERE id = 1"
            ),
            {"p": name, "c": country, "s": body.show_country and country is not None,
             "by": actor[:120]},
        )  # fmt: skip
        await audit_db.record(
            db,
            actor=actor,
            action="network.join",
            ip=request.app.state.auth.client_ip(request),
            details={"pseudonym_set": name is not None, "country_set": country is not None},
            actor_id=audit_db.actor_id_of(principal),
        )
        await db.commit()
    except DBAPIError:
        await db.rollback()
        return error(409, "The membership cannot change right now.", "already_member")
    return await _status(db)


@router.patch("/network/membership")
async def update(body: UpdateBody, request: Request, db: DbSession) -> Response:
    name, country, bad = await _check_values(db, body.pseudonym, body.country, body.show_country)
    if bad is not None:
        return bad
    principal, refused = await reauth.guard(request, None, "network update")
    if refused is not None:
        return refused
    row = await _membership(db)
    if row is None or row.desired != "member" or row.state != "member":
        return error(409, "Only a member can change these.", "not_member")
    show = body.show_country and country is not None
    changed = [
        key
        for key, old, new in (
            ("pseudonym", row.pseudonym, name),
            ("country", row.country.strip() if row.country else None, country),
            ("show_country", bool(row.show_country), show),
        )
        if old != new
    ]
    actor = principal.username if principal else "anonymous"
    if changed:
        await db.execute(
            text(
                "UPDATE network_membership SET pseudonym = :p, country = :c, show_country = :s "
                "WHERE id = 1"
            ),
            {"p": name, "c": country, "s": show},
        )
        await audit_db.record(
            db,
            actor=actor,
            action="network.update",
            ip=request.app.state.auth.client_ip(request),
            details={"changed": changed},  # field names only
            actor_id=audit_db.actor_id_of(principal),
        )
        await db.commit()
    return await _status(db)


@router.delete("/network/membership")
async def leave(body: LeaveBody, request: Request, db: DbSession) -> Response:
    principal, refused = await reauth.guard(request, body.password, "network leave")
    if refused is not None:
        return refused
    row = await _membership(db)
    if row is not None and row.desired == "leave":
        return await _status(db)  # already leaving
    if row is None or row.desired != "member":
        return error(409, "This system is not part of the network.", "not_member")
    try:
        await db.execute(
            text(
                "UPDATE network_membership SET desired = 'leave', requested_at = now() WHERE id = 1"
            )
        )
        await audit_db.record(
            db,
            actor=principal.username if principal else "anonymous",
            action="network.leave",
            ip=request.app.state.auth.client_ip(request),
            actor_id=audit_db.actor_id_of(principal),
        )
        await db.commit()
    except DBAPIError:
        await db.rollback()
        return error(409, "The membership cannot change right now.", "not_member")
    return await _status(db)


# ---- submissions (administrators) ----------------------------------------------------------


def _submission(r: Any) -> dict[str, Any]:
    return {
        "day": r.day.isoformat(),
        "batch_id": r.batch_id,
        "sent_at": _stamp(r.sent_at),
        "status": r.status,
        "counts": r.counts or {},
        "dropped": r.dropped or {},
        "error_code": r.error_code,
    }


_SUB_COLUMNS = "day, batch_id, sent_at, status, counts, dropped, error_code"


@router.get("/network/submissions", dependencies=[Depends(require_admin)])
async def list_submissions(
    db: DbSession, limit: Annotated[int, Query(ge=1, le=MAX_SUBMISSIONS)] = 30
) -> Response:
    """The newest days first, as a bare array (at most 90 rows exist, so no cursor)."""
    rows = await db.execute(
        text(f"SELECT {_SUB_COLUMNS} FROM network_submissions ORDER BY day DESC LIMIT :n"),  # noqa: S608
        {"n": limit},
    )
    return _no_store([_submission(r) for r in rows])


@router.get("/network/submissions/{day}", dependencies=[Depends(require_admin)])
async def get_submission(day: date, db: DbSession) -> Response:
    r = (
        await db.execute(
            text(f"SELECT {_SUB_COLUMNS}, payload FROM network_submissions WHERE day = :d"),  # noqa: S608
            {"d": day},
        )
    ).one_or_none()
    if r is None:
        return error(404, "No batch for that day.", "not_found")
    return _no_store({**_submission(r), "payload": r.payload})


@router.get("/network/preview", dependencies=[Depends(require_admin)])
async def preview(db: DbSession) -> Response:
    """The last batch that was sent, exactly as it left. Nothing is built here."""
    r = (
        await db.execute(
            text(
                f"SELECT {_SUB_COLUMNS}, payload FROM network_submissions "  # noqa: S608
                "WHERE payload IS NOT NULL ORDER BY day DESC LIMIT 1"
            )
        )
    ).one_or_none()
    if r is None:
        return error(404, "Nothing has been sent yet.", "not_found")
    return _no_store({**_submission(r), "payload": r.payload})


# ---- targets, summary, impact --------------------------------------------------------------


def _target(r: Any) -> dict[str, Any]:
    return {
        "hub_id": r.hub_id,
        "kind": r.kind,
        "value": r.value,
        "value_b": r.value_b,
        "state": r.state,
        "nodes": r.nodes,
        "countries": r.countries,
        "first_day": r.first_day.isoformat(),
        "last_day": r.last_day.isoformat(),
        "services": list(r.services or []),
        "activity": list(r.activity or []),
        "tags": list(r.tags or []),
        "families": list(r.families or []),
        "reported_day": _day(r.reported_day),
        "taken_down_day": _day(r.taken_down_day),
        "mine": bool(r.mine),
    }


@router.get("/network/targets")
async def list_targets(
    db: DbSession,
    state: Annotated[str | None, Query(max_length=16)] = None,
    kind: Annotated[str | None, Query(max_length=16)] = None,
    mine: Annotated[str | None, Query(max_length=8)] = None,
    target: Annotated[str | None, Query(pattern=r"^t_[0-9a-f]{12}$")] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> Response:
    """Targets the network confirmed, newest last day first. Keyset pagination."""
    if state not in (None, "all", *TARGET_STATES):
        return error(422, "Unknown state.", "invalid_filter")
    if kind not in (None, "all", *TARGET_KINDS):
        return error(422, "Unknown kind.", "invalid_filter")
    where = ["true"]
    params: dict[str, Any] = {"n": limit + 1}
    if state and state != "all":
        where.append("state = :state")
        params["state"] = state
    if kind and kind != "all":
        where.append("kind = :kind")
        params["kind"] = kind
    if mine and mine.strip().lower() in TRUE_VALUES:
        where.append("mine")
    if target:
        where.append("hub_id = :target")
        params["target"] = target
    if cursor:
        try:
            values = decode_cursor(cursor)
            params["c_day"] = date.fromisoformat(str(values[0]))
            params["c_id"] = str(values[1])
        except InvalidCursorError, ValueError, IndexError:
            return error(400, "Invalid cursor.", "invalid_cursor")
        where.append("(last_day, hub_id) < (:c_day, :c_id)")
    rows = list(
        await db.execute(
            text(
                f"SELECT {_ROW_COLUMNS} FROM network_targets WHERE {' AND '.join(where)} "  # noqa: S608
                "ORDER BY last_day DESC, hub_id DESC LIMIT :n"
            ),
            params,
        )
    )
    more = len(rows) > limit
    rows = rows[:limit]
    nxt = encode_cursor([rows[-1].last_day.isoformat(), rows[-1].hub_id]) if more and rows else None
    return _no_store({"items": [_target(r) for r in rows], "next_cursor": nxt})


@router.get("/network/summary")
async def summary(db: DbSession) -> Response:
    """The hub's daily summary and when this node fetched it; 404 until there is one."""
    r = (
        await db.execute(text("SELECT data, fetched_at FROM network_summary WHERE id = 1"))
    ).one_or_none()
    if r is None:
        return error(404, "No network summary yet.", "not_found")
    return _no_store({**r.data, "fetched_at": r.fetched_at.isoformat()})


@router.get("/network/impact")
async def impact(db: DbSession) -> Response:
    """Network figures from the hub's summary and what this sensor helped confirm (30 days)."""
    row = await _membership(db)
    if row is None or row.state != "member":
        return error(404, "This system is not part of the network.", "not_member")
    data = (
        await db.execute(text("SELECT data FROM network_summary WHERE id = 1"))
    ).scalar_one_or_none()
    totals = (data or {}).get("totals", {}) if isinstance(data, dict) else {}
    mine = (
        await db.execute(
            text(
                """
                SELECT
                  count(*) FILTER (WHERE state IN ('confirmed', 'reported', 'taken_down')
                    AND last_day >= (now() AT TIME ZONE 'UTC')::date - 30) AS helped_confirm,
                  count(*) FILTER (WHERE state = 'taken_down'
                    AND taken_down_day >= (now() AT TIME ZONE 'UTC')::date - 30) AS helped_down
                FROM network_targets WHERE mine
                """
            )
        )
    ).one()
    return _no_store(
        {
            "network": {
                "confirmed_30d": int(totals.get("confirmed_30d", 0)),
                "reported_30d": int(totals.get("reported_30d", 0)),
                "taken_down_30d": int(totals.get("taken_down_30d", 0)),
                "median_days_to_takedown": totals.get("median_days_to_takedown"),
            },
            "mine": {
                "helped_confirm_30d": int(mine.helped_confirm),
                "helped_takedown_30d": int(mine.helped_down),
            },
        }
    )


def recent_submission(last_submit_day: date | None, today: date | None = None) -> bool:
    """Used by the setup checklist: a batch within the last two days."""
    if last_submit_day is None:
        return False
    return (today or datetime.now(UTC).date()) - last_submit_day <= RECENT_SUBMISSION


async def network_states(db: AsyncSession, values: list[str]) -> dict[str, str]:
    """State of the targets the network handles among ``values`` (hosts), for the chip
    "Reported by the network" in the abuse report subjects. Empty unless this node is a member."""
    if not values:
        return {}
    rows = await db.execute(
        text(
            """
            SELECT t.value, t.state FROM network_targets t
            JOIN network_membership m ON m.id = 1 AND m.state = 'member'
            WHERE t.state IN ('confirmed', 'reported', 'taken_down') AND t.value IS NOT NULL
              AND t.kind IN ('ip', 'domain', 'c2_ip', 'c2_domain')
              AND t.last_day >= (now() AT TIME ZONE 'UTC')::date - 30
            """
        )
    )
    handled = {host_of_target(str(r.value)): str(r.state) for r in rows}
    return {v: handled[v.lower()] for v in values if v.lower() in handled}
