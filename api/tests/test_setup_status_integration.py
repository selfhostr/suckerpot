"""The setup checklist against a real TimescaleDB, as the least-privileged API role (M24)."""

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from test_vpn_settings_integration import (  # noqa: F401
    admin,
    app,
    put_status,
    viewer,
    vpn_dir,
)

from api.sensors import SENSORS

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

URL = "/api/v1/setup/status"
ORDER = [
    "sensors",
    "ports",
    "vpn",
    "collector",
    "reporting_settings",
    "self_address",
    "abuse_worker",
    "replies",
    "alerts",
    "provider_keys",
    "takedown",
    "updates",
    "network",
    "network_feed",
]
SQL_RESET = (
    "DELETE FROM events",
    "DELETE FROM report_self_terms",
    "DELETE FROM alert_channels",
    "DELETE FROM provider_secrets",
    "DELETE FROM report_settings",
    "UPDATE network_membership SET desired = 'off', state = 'off', last_submit_day = NULL, "
    "last_error_code = NULL",
)


@pytest.fixture(autouse=True)
async def clean(app: Any, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.delenv("COLLECTOR_ENABLED", raising=False)
    monkeypatch.delenv("ABUSE_REPORTS_ENABLED", raising=False)
    monkeypatch.delenv("TAKEDOWN_ENABLED", raising=False)
    async with owner_engine() as owner, owner.begin() as conn:
        for sql in SQL_RESET:
            await conn.execute(text(sql))


async def items(c: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
    r = await c.get(URL)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items"}
    assert [i["id"] for i in body["items"]] == ORDER
    for i in body["items"]:
        assert set(i) == {"id", "state", "detail", "href"}
        # Every link is an in-app path: Settings, or the Network and Blocklists pages (M29, M30).
        home = {"network": "/network", "network_feed": "/defend/blocklists"}.get(
            i["id"], "/settings"
        )
        assert i["href"].startswith(home) and i["detail"].endswith(".")
    return {i["id"]: i for i in body["items"]}


async def event(sensor: str, age: timedelta = timedelta(minutes=5)) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, "
                "data)"
                " VALUES (:ts, :s, 'sess-1', 'connect', '192.0.2.10', 40000, 22, '{}'::jsonb)"
            ),
            {"ts": datetime.now(UTC) - age, "s": sensor},
        )


async def test_a_fresh_install_has_things_to_do(admin: httpx.AsyncClient) -> None:  # noqa: F811
    got = await items(admin)
    assert got["sensors"]["state"] == "warning"
    assert got["vpn"]["state"] == "todo"
    assert got["collector"]["state"] == "off"
    assert got["reporting_settings"]["state"] == "todo"
    assert got["self_address"]["state"] == "todo"
    assert got["abuse_worker"]["state"] == "off"
    assert got["network"]["state"] == "off"  # never joined by itself
    assert got["alerts"]["state"] == "off"
    assert got["provider_keys"]["state"] == "off"
    assert got["takedown"]["state"] == "off"
    assert got["vpn"]["href"] == "/settings?tab=vpn"
    assert got["alerts"]["href"] == "/settings?tab=alerts"
    assert got["provider_keys"]["href"] == "/settings?tab=keys"
    assert got["self_address"]["href"] == "/settings?tab=reporting"


async def test_sensors_warn_and_name_the_silent_ones(admin: httpx.AsyncClient) -> None:  # noqa: F811
    for s in SENSORS:
        await event(s, timedelta(hours=30) if s == "sip" else timedelta(minutes=5))
    got = (await items(admin))["sensors"]
    assert got["state"] == "warning" and "SIP" in got["detail"] and "SSH" not in got["detail"]
    await event("sip")
    got = (await items(admin))["sensors"]
    assert got["state"] == "ok"


async def test_vpn_and_collector_follow_the_gates(
    admin: httpx.AsyncClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC).isoformat()
    await put_status("egress", open=True, reason="ok", egress_ip="9.9.9.77", checked_at=now)
    got = await items(admin)
    assert got["vpn"]["state"] == "ok"
    assert "9.9.9.77" not in json.dumps(got)  # never repeats the exit address
    assert got["collector"]["state"] == "off"
    monkeypatch.setenv("COLLECTOR_ENABLED", "true")
    assert (await items(admin))["collector"]["state"] == "warning"  # enabled, no gate row yet
    await put_status("egress_collector", open=True, reason="ok", checked_at=now)
    assert (await items(admin))["collector"]["state"] == "ok"
    await put_status("egress", open=False, reason="tunnel_down", checked_at=now)
    got = await items(admin)
    assert got["vpn"]["state"] == "warning" and "tunnel_down" in got["vpn"]["detail"]
    stale = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    await put_status("egress", open=True, reason="ok", checked_at=stale)
    assert (await items(admin))["vpn"]["state"] == "warning"  # an old "open" is not trusted


async def test_reporting_wording_self_address_and_worker(
    admin: httpx.AsyncClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO report_settings (id, intro, outro) VALUES (1, 'Hello.', 'Thanks.')")
        )
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source, confirmed) VALUES "
                "('address', '203.0.113.9', 'learned', false), ('name', 'srv-example', 'manual', "
                "false)"
            )
        )
    got = await items(admin)
    assert got["reporting_settings"]["state"] == "todo"
    assert "reply contact" in got["reporting_settings"]["detail"]
    assert got["self_address"]["state"] == "todo"  # unconfirmed learned address does not count
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("UPDATE report_settings SET reply_contact = 'reports@example.org'"))
        await conn.execute(text("UPDATE report_self_terms SET confirmed = true"))
    monkeypatch.setenv("ABUSE_REPORTS_ENABLED", "true")
    got = await items(admin)
    assert got["reporting_settings"]["state"] == "ok"
    assert "optional" in got["reporting_settings"]["detail"]
    assert got["self_address"]["state"] == "ok"
    assert got["abuse_worker"]["state"] == "ok"
    assert "203.0.113.9" not in json.dumps(got)


async def test_alerts_and_provider_keys(admin: httpx.AsyncClient) -> None:  # noqa: F811
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO alert_channels (kind, name, enabled, target_ciphertext, created_by) "
                "VALUES ('discord', 'off one', false, decode(repeat('00', 40), 'hex'), 'admin')"
            )
        )
    assert (await items(admin))["alerts"]["state"] == "off"  # a disabled channel does not count
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("UPDATE alert_channels SET enabled = true"))
        await conn.execute(
            text(
                "INSERT INTO provider_secrets (provider, ciphertext, nonce, last4, updated_by) "
                "VALUES ('abuseipdb', decode(repeat('00', 40), 'hex'), "
                "decode(repeat('00', 12), 'hex'), 'abcd', 'admin')"
            )
        )
    got = await items(admin)
    assert got["alerts"]["state"] == "ok"
    assert (
        got["provider_keys"]["state"] == "warning" and "GreyNoise" in got["provider_keys"]["detail"]
    )
    await put_status("greynoise", configured=True)
    assert (await items(admin))["provider_keys"]["state"] == "ok"
    assert "abcd" not in json.dumps(await items(admin))


async def test_a_viewer_gets_403(viewer: httpx.AsyncClient) -> None:  # noqa: F811
    r = await viewer.get(URL)
    assert r.status_code == 403 and r.json()["code"] == "admin_required"
