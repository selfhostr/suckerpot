"""The setup checklist (M24, ``docs/design/m24.md`` section 3). Admin only, read only.

Every item is computed from real state with the API role: the last event of each sensor, the
gate rows ingest and the collector publish, the reporting settings, the self addresses, the alert
channels and the provider keys. ``detail`` is a short English sentence (never a value: no key,
address or mailbox is ever repeated), ``href`` a dashboard path. The host firewall cannot be seen
from inside the stack, so it is not an item.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import AlertChannelRow, EnrichmentStatusRow
from suckerpot_db.models import ReportImapRow, ReportImapStateRow
from suckerpot_db.trusted_exits import ACTIVE_SELF_NETWORKS_SQL

from api import network_feed
from api.abuse_core import env_flag, load_settings, missing_for
from api.authz import require_admin
from api.deps import DbSession
from api.egress import _checked_at
from api.network import recent_submission
from api.provider_keys import _configured
from api.sensors import SENSOR_LABELS, SENSORS, latest_event_per_sensor
from api.setup_wizard import build_ports, last_events, sensor_enabled
from api.version import load_version

router = APIRouter(tags=["settings"])

State = Literal["ok", "todo", "warning", "off"]
SILENT_AFTER = timedelta(hours=24)
GATE_FRESH = timedelta(minutes=15)  # an "open" verdict older than this is not trusted
MAX_NAMED = 6
PORTS_GRACE = timedelta(hours=2)  # a sensor may wait this long for its first visitor
STARTED = datetime.now(UTC)  # this process; the setup is "old enough" once it has run 2 hours


class SetupItem(BaseModel):
    id: str
    state: State
    detail: str
    href: str


class SetupStatus(BaseModel):
    items: list[SetupItem]


def _item(id_: str, state: State, detail: str, href: str) -> SetupItem:
    return SetupItem(id=id_, state=state, detail=detail, href=href)


def _names(names: list[str]) -> str:
    shown = names[:MAX_NAMED]
    extra = len(names) - len(shown)
    text_ = ", ".join(shown)
    return f"{text_} and {extra} more" if extra > 0 else text_


async def _gate_details(db: AsyncSession) -> dict[str, dict[str, Any]]:
    rows = await db.execute(
        select(EnrichmentStatusRow.name, EnrichmentStatusRow.detail).where(
            EnrichmentStatusRow.name.in_(("egress", "egress_collector"))
        )
    )
    return {r.name: r.detail for r in rows}


def _gate_open(detail: dict[str, Any] | None, now: datetime) -> bool:
    if not detail or detail.get("open") is not True:
        return False
    checked = _checked_at(detail)
    return checked is not None and now - checked <= GATE_FRESH


def _reason(detail: dict[str, Any] | None) -> str:
    raw = detail.get("reason") if detail else None
    return raw[:64] if isinstance(raw, str) else "no_status"


async def _sensors(db: AsyncSession, now: datetime) -> SetupItem:
    active = set(await latest_event_per_sensor(db, now - SILENT_AFTER))
    enabled = [s for s in SENSORS if sensor_enabled(s)]  # a disabled sensor is not "silent"
    silent = [SENSOR_LABELS.get(s, s) for s in enabled if s not in active]
    href = "/settings"
    if not enabled:
        return _item("sensors", "warning", "Every sensor is switched off.", href)
    if not silent:
        return _item(
            "sensors", "ok", f"All {len(enabled)} sensors sent events in the last 24 hours.", href
        )
    if len(silent) == len(enabled):
        return _item(
            "sensors", "warning", "No sensor has sent an event in the last 24 hours.", href
        )
    return _item("sensors", "warning", f"Silent for 24 hours or more: {_names(silent)}.", href)


async def _ports(db: AsyncSession, now: datetime) -> SetupItem:
    href = "/settings?tab=ports"
    items = build_ports(await last_events(db, now), now)
    enabled = [i for i in items if i.enabled]
    waiting = sorted({i.label for i in enabled if i.state == "waiting"})
    if not enabled:
        return _item("ports", "off", "No sensor is switched on, so no port needs opening.", href)
    if not waiting:
        return _item("ports", "ok", "Every enabled port has received a connection.", href)
    if now - STARTED < PORTS_GRACE:
        return _item(
            "ports",
            "ok",
            "Waiting for the first connections. Bots usually arrive within minutes.",
            href,
        )
    return _item(
        "ports",
        "todo",
        f"Nothing has reached {_names(waiting)} yet. Check the port forwards on your router.",
        href,
    )


async def _vpn(db: AsyncSession, now: datetime) -> SetupItem:
    detail = (await _gate_details(db)).get("egress")
    href = "/settings?tab=vpn"
    if _gate_open(detail, now):
        return _item("vpn", "ok", "The VPN tunnel is up and the egress gate is open.", href)
    if detail is None:
        return _item(
            "vpn", "todo", "The egress gate has not reported yet. Start the VPN service.", href
        )
    return _item(
        "vpn",
        "warning",
        f"The egress gate is closed ({_reason(detail)}). Outbound lookups are paused.",
        href,
    )


async def _collector(db: AsyncSession, now: datetime) -> SetupItem:
    href = "/settings"
    if not env_flag("COLLECTOR_ENABLED", False):
        return _item(
            "collector",
            "off",
            "Payload fetching is off. Enable it to download and analyse the files attackers "
            "point to.",
            href,
        )
    detail = (await _gate_details(db)).get("egress_collector")
    if _gate_open(detail, now):
        return _item("collector", "ok", "Payload fetching is on and its egress gate is open.", href)
    return _item(
        "collector",
        "warning",
        f"Payload fetching is on but its egress gate is closed ({_reason(detail)}).",
        href,
    )


async def _reporting_settings(db: AsyncSession, _now: datetime) -> SetupItem:
    href = "/settings?tab=reporting"
    missing = missing_for((await load_settings(db)).settings)
    if not missing:
        return _item(
            "reporting_settings",
            "ok",
            "The reply contact is set. The report texts are optional.",
            href,
        )
    return _item(
        "reporting_settings",
        "todo",
        "Set the reply contact for abuse reports. The report texts are optional.",
        href,
    )


async def _self_address(db: AsyncSession, _now: datetime) -> SetupItem:
    href = "/settings?tab=reporting"
    found = (await db.scalars(text(ACTIVE_SELF_NETWORKS_SQL + " LIMIT 1"))).first()
    if found is not None:
        return _item("self_address", "ok", "The honeypot's own address is known.", href)
    return _item(
        "self_address",
        "todo",
        "Add the honeypot's public address, so it can never appear in a report or become a VPN "
        "exit.",
        href,
    )


async def _abuse_worker(_db: AsyncSession, _now: datetime) -> SetupItem:
    href = "/settings?tab=reporting"
    if env_flag("ABUSE_REPORTS_ENABLED", False):
        return _item("abuse_worker", "ok", "Abuse report drafts are being prepared.", href)
    return _item(
        "abuse_worker",
        "off",
        "Abuse reports are off. Enable them to get drafts you review and send yourself.",
        href,
    )


async def _replies(db: AsyncSession, _now: datetime) -> SetupItem:
    """Optional: reading replies needs a mailbox and the server switch. Never a to-do."""
    href = "/settings?tab=reporting"
    profile = (
        await db.execute(
            select(ReportImapRow.enabled, ReportImapRow.password_set).where(ReportImapRow.id == 1)
        )
    ).first()
    if profile is None or not profile.password_set:
        return _item(
            "replies",
            "off",
            "Replies mailbox: optional, not set up. You can still paste a reply on a report.",
            href,
        )
    if not env_flag("ABUSE_REPLIES_ENABLED", False) or not profile.enabled:
        return _item(
            "replies", "off", "Replies mailbox is saved but reading is switched off.", href
        )
    error = await db.scalar(select(ReportImapStateRow.last_error).where(ReportImapStateRow.id == 1))
    if error:
        return _item(
            "replies", "warning", "The last check of the replies mailbox did not work.", href
        )
    return _item("replies", "ok", "Replies are read from your mailbox through the VPN.", href)


async def _takedown(_db: AsyncSession, _now: datetime) -> SetupItem:
    href = "/settings?tab=reporting"
    if env_flag("TAKEDOWN_ENABLED", False):
        return _item("takedown", "ok", "Takedown tracking is on.", href)
    return _item(
        "takedown",
        "off",
        "Takedown tracking is off. Turn it on to see which reported targets went down.",
        href,
    )


async def _alerts(db: AsyncSession, _now: datetime) -> SetupItem:
    href = "/settings?tab=alerts"
    count = await db.scalar(
        select(func.count()).select_from(AlertChannelRow).where(AlertChannelRow.enabled)
    )
    if count:
        return _item("alerts", "ok", "At least one alert channel is set up.", href)
    return _item(
        "alerts", "off", "No alert channel yet. Add one to hear about serious attacks.", href
    )


async def _provider_keys(db: AsyncSession, _now: datetime) -> SetupItem:
    href = "/settings?tab=keys"
    have = [p for p in ("abuseipdb", "greynoise") if await _configured(db, p)]
    if len(have) == 2:
        return _item("provider_keys", "ok", "AbuseIPDB and GreyNoise keys are set.", href)
    if have:
        missing = "GreyNoise" if have == ["abuseipdb"] else "AbuseIPDB"
        return _item(
            "provider_keys",
            "warning",
            f"The {missing} key is missing. It adds "
            + (
                "scanner context to attacker profiles."
                if missing == "GreyNoise"
                else "abuse scores to attacker profiles."
            ),
            href,
        )
    return _item(
        "provider_keys",
        "off",
        "No reputation keys. AbuseIPDB adds abuse scores and GreyNoise tells scanners from "
        "attackers.",
        href,
    )


async def _updates(db: AsyncSession, _now: datetime) -> SetupItem:
    href = "/settings"
    info = await load_version(db)
    if info.check == "off":
        return _item("updates", "off", "The update check is off.", href)
    if info.update_available:
        return _item(
            "updates",
            "warning",
            f"SuckerPot {info.latest} is available (you run {info.version}).",
            href,
        )
    return _item("updates", "ok", "No newer release is known.", href)


async def _network(db: AsyncSession, now: datetime) -> SetupItem:
    """The opt-in network (M29): off unless this system joined; then fresh batches or a reason."""
    href = "/network"
    row = (
        await db.execute(
            text(
                "SELECT state, last_submit_day, last_error_code FROM network_membership "
                "WHERE id = 1"
            )
        )
    ).one_or_none()
    if row is None or row.state != "member":
        return _item("network", "off", "This system is not part of the SuckerPot network.", href)
    if recent_submission(row.last_submit_day, now.date()):
        return _item("network", "ok", "Part of the SuckerPot network; batches are going out.", href)
    waiting = {
        "waiting_self_address": "Waiting for the honeypot's own address before sending.",
        "waiting_enrolment": "The hub is not taking new members right now; trying again later.",
        "egress_closed": "The outbound gate is closed, so nothing is sent.",
        "no_settings_key": "The settings encryption key is missing.",
    }
    return _item(
        "network",
        "warning",
        waiting.get(row.last_error_code or "", "No batch sent recently."),
        href,
    )


# Words for the fetch error codes of the community lists (the web UI uses the same wording). An
# unknown code is not shown: a raw code means nothing to the reader.
FEED_ERROR_WORDS: dict[str, str] = {
    "not_configured": "The address or the key of the lists is not set.",
    "egress_closed": "Outbound access is closed, so the lists could not be fetched.",
    "bad_signature": "The signature did not verify, so the new lists were refused.",
    "feed_rollback": "The lists offered were older than the ones already stored, so they were "
    "refused.",
    "feed_expired": "No fresh copy has been published.",
    "feed_invalid": "The lists failed a check and were refused.",
    "too_large": "The lists were larger than allowed and were refused.",
    "unreachable": "The list server could not be reached.",
}


def _feed_error_words(code: str | None) -> str | None:
    if not code:
        return None
    if code in FEED_ERROR_WORDS:
        return FEED_ERROR_WORDS[code]
    if code.startswith("http_") and code[5:].isdigit():
        return f"The list server answered with an error ({code[5:]})."
    return None


async def _network_feed(db: AsyncSession, now: datetime) -> SetupItem:
    """The community lists (M30): off unless fetching is on; then fresh, or the reason it is not."""
    href = "/defend/blocklists?tab=network"
    if not network_feed.feed_enabled():
        return _item("network_feed", "off", "The community lists are not fetched here.", href)
    if network_feed.public_base_url() is None:
        return _item(
            "network_feed", "warning", "The address of the community lists is not set.", href
        )
    info = await network_feed.load_state(db, now)
    if info.state == "ok":
        return _item("network_feed", "ok", "The community lists are up to date.", href)
    if info.state == "never":
        return _item("network_feed", "ok", "Waiting for the first fetch of the lists.", href)
    if info.state == "stale":
        detail = (
            "The community lists have expired; this dashboard stopped serving its copy to "
            "firewalls."
        )
    else:
        detail = "The last fetch of the community lists failed."
    if (words := _feed_error_words(info.error_code)) is not None:
        detail = f"{detail} {words}"
    return _item("network_feed", "warning", detail, href)


CHECKS: tuple[tuple[str, Callable[[AsyncSession, datetime], Awaitable[SetupItem]], str], ...] = (
    ("sensors", _sensors, "/settings"),
    ("ports", _ports, "/settings?tab=ports"),
    ("vpn", _vpn, "/settings?tab=vpn"),
    ("collector", _collector, "/settings"),
    ("reporting_settings", _reporting_settings, "/settings?tab=reporting"),
    ("self_address", _self_address, "/settings?tab=reporting"),
    ("abuse_worker", _abuse_worker, "/settings?tab=reporting"),
    ("replies", _replies, "/settings?tab=reporting"),
    ("alerts", _alerts, "/settings?tab=alerts"),
    ("provider_keys", _provider_keys, "/settings?tab=keys"),
    ("takedown", _takedown, "/settings?tab=reporting"),
    ("updates", _updates, "/settings"),
    ("network", _network, "/network"),
    ("network_feed", _network_feed, "/defend/blocklists?tab=network"),
)


async def compute(db: AsyncSession, now: datetime | None = None) -> list[SetupItem]:
    """Every item in the documented order. One failing read becomes a warning, not an error."""
    moment = now or datetime.now(UTC)
    items: list[SetupItem] = []
    for id_, check, href in CHECKS:
        try:
            async with db.begin_nested():
                items.append(await check(db, moment))
        except SQLAlchemyError:
            items.append(_item(id_, "warning", "This could not be checked right now.", href))
    return items


@router.get("/setup/status", response_model=SetupStatus, dependencies=[Depends(require_admin)])
async def setup_status(db: DbSession) -> SetupStatus:
    return SetupStatus(items=await compute(db))
