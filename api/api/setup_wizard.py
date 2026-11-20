"""First-run setup (M28, ``docs/dev/design/m28.md`` 4): progress, and the ports table.

The progress is one row of ``setup_progress``. The routes never start or stop anything and never
learn the honeypot's public address: the ports table only says which sensor received traffic.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Self

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, model_validator
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import SetupProgressRow

from api import audit as audit_db
from api import auth as auth_mod
from api.authz import require_admin
from api.deps import DbSession
from api.sensors import latest_event_per_sensor

router = APIRouter(tags=["settings"])

STEP_IDS: tuple[str, ...] = (
    "welcome",
    "sensors",
    "ports",
    "vpn",
    "self",
    "reporting",
    "alerts",
    "network",
    "done",
)
MAX_STEPS_BYTES = 4096
RECEIVING_WINDOW = timedelta(hours=24)
DEFAULT_DASHBOARD_PORT = 8443

State = Literal["new", "in_progress", "finished", "skipped"]
PortState = Literal["receiving", "waiting", "off"]


class SetupProgress(BaseModel):
    state: State
    steps: dict[str, Literal["done", "skipped"]]
    show: bool


class ProgressUpdate(BaseModel):
    """Exactly one action per call."""

    model_config = ConfigDict(extra="forbid")

    step: str | None = None
    status: Literal["done", "skipped"] | None = None
    finish: Literal[True] | None = None
    skip: Literal[True] | None = None
    reopen: Literal[True] | None = None

    @model_validator(mode="after")
    def _one_action(self) -> Self:
        actions = [self.step is not None, self.finish, self.skip, self.reopen]
        if sum(1 for a in actions if a) != 1:
            raise ValueError("send exactly one of step, finish, skip, reopen")
        if (self.step is None) != (self.status is None):
            raise ValueError("step and status go together")
        if self.step is not None and self.step not in STEP_IDS:
            raise ValueError("unknown step")
        return self


def progress_of(row: SetupProgressRow | None) -> SetupProgress:
    if row is None:
        return SetupProgress(state="new", steps={}, show=True)
    state: State = "in_progress"
    if row.finished_at is not None:
        state = "finished"
    elif row.skipped_at is not None:
        state = "skipped"
    steps: dict[str, Literal["done", "skipped"]] = {}
    for key, value in (row.steps or {}).items():
        if key in STEP_IDS and value == "done":
            steps[key] = "done"
        elif key in STEP_IDS and value == "skipped":
            steps[key] = "skipped"
    return SetupProgress(state=state, steps=steps, show=state in ("new", "in_progress"))


def _error(status: int, detail: str, code: str) -> JSONResponse:
    return JSONResponse({"detail": detail, "code": code}, status_code=status)


@router.get("/setup/progress", response_model=SetupProgress, dependencies=[Depends(require_admin)])
async def get_progress(db: DbSession) -> SetupProgress:
    return progress_of(await db.get(SetupProgressRow, 1))


@router.put("/setup/progress", response_model=SetupProgress)
async def put_progress(body: ProgressUpdate, request: Request, db: DbSession) -> Response:
    # Writes are admin-only through ``authz.authorize``; CSRF is checked by the auth middleware.
    principal = await auth_mod.current_principal(request)
    actor = principal.username if principal else "unknown"
    service: auth_mod.AuthService = request.app.state.auth
    await db.execute(insert(SetupProgressRow).values(id=1).on_conflict_do_nothing())
    row = await db.scalar(
        select(SetupProgressRow).where(SetupProgressRow.id == 1).with_for_update()
    )
    if row is None:  # pragma: no cover - the insert above guarantees the row
        return _error(503, "Service unavailable", "unavailable")
    action: str | None = None
    now = datetime.now(UTC)
    if body.step is not None and body.status is not None:
        steps = {**(row.steps or {}), body.step: body.status}
        if len(json.dumps(steps).encode()) > MAX_STEPS_BYTES:
            return _error(413, "Too much progress data.", "too_large")
        row.steps = steps
    elif body.finish:
        row.finished_at, row.finished_by, row.skipped_at = now, actor[:120], None
        action = "setup.finish"
    elif body.skip:
        row.skipped_at, row.finished_at, row.finished_by = now, None, None
        action = "setup.skip"
    else:
        row.finished_at = row.skipped_at = row.finished_by = None
        action = "setup.reopen"
    if action is not None:
        await audit_db.record(
            db,
            actor=actor,
            action=action,
            target="setup",
            ip=service.client_ip(request),
            actor_id=audit_db.actor_id_of(principal),
        )
    await db.commit()
    return JSONResponse(progress_of(row).model_dump(mode="json"))


# ---- ports ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PortSpec:
    sensor: str
    label: str
    protocols: tuple[str, ...]
    external_port: int
    env_var: str


# What to open on the router. Web and Synology listen on two ports, so they have two rows (same
# ``sensor``, told apart by ``env_var``).
PORTS: tuple[PortSpec, ...] = (
    PortSpec("ssh", "SSH", ("tcp",), 22, "SSH_HOST_PORT"),
    PortSpec("telnet", "Telnet", ("tcp",), 23, "TELNET_HOST_PORT"),
    PortSpec("web", "Web (HTTP)", ("tcp",), 80, "HTTP_HOST_PORT"),
    PortSpec("web", "Web (HTTPS)", ("tcp",), 443, "HTTPS_HOST_PORT"),
    PortSpec("rdp", "RDP", ("tcp",), 3389, "RDP_HOST_PORT"),
    PortSpec("redis", "Redis", ("tcp",), 6379, "REDIS_HOST_PORT"),
    PortSpec("docker", "Docker", ("tcp",), 2375, "DOCKER_HOST_PORT"),
    PortSpec("mysql", "MySQL", ("tcp",), 3306, "MYSQL_HOST_PORT"),
    PortSpec("adb", "ADB", ("tcp",), 5555, "ADB_HOST_PORT"),
    PortSpec("mssql", "MSSQL", ("tcp",), 1433, "MSSQL_HOST_PORT"),
    PortSpec("smb", "SMB", ("tcp",), 445, "SMB_HOST_PORT"),
    PortSpec("sip", "SIP", ("udp", "tcp"), 5060, "SIP_HOST_PORT"),
    PortSpec("synology", "Synology NAS (HTTP)", ("tcp",), 5000, "SYNOLOGY_HTTP_HOST_PORT"),
    PortSpec("synology", "Synology NAS (HTTPS)", ("tcp",), 5001, "SYNOLOGY_HTTPS_HOST_PORT"),
)


class PortItem(BaseModel):
    sensor: str
    label: str
    enabled: bool
    protocols: list[str]
    external_port: int
    host_port: int
    env_var: str
    state: PortState
    last_event_at: datetime | None


class Ports(BaseModel):
    dashboard_port: int
    items: list[PortItem]


def sensor_enabled(sensor: str, env: Mapping[str, str] | None = None) -> bool:
    """``SENSOR_<NAME>=0`` turns a sensor off; unset or anything else keeps it on."""
    source = os.environ if env is None else env
    return source.get(f"SENSOR_{sensor.upper()}", "1").strip() != "0"


def _port_env(name: str, default: int, env: Mapping[str, str]) -> int:
    try:
        value = int(env.get(name, ""))
    except ValueError:
        return default
    return value if 1 <= value <= 65535 else default


def dashboard_port(env: Mapping[str, str] | None = None) -> int:
    return _port_env("DASHBOARD_PORT", DEFAULT_DASHBOARD_PORT, os.environ if env is None else env)


def build_ports(
    last_events: Mapping[str, datetime], now: datetime, env: Mapping[str, str] | None = None
) -> list[PortItem]:
    source = os.environ if env is None else env
    items: list[PortItem] = []
    for spec in PORTS:
        enabled = sensor_enabled(spec.sensor, source)
        last = last_events.get(spec.sensor)
        state: PortState = "off"
        if enabled:
            state = (
                "receiving" if last is not None and now - last <= RECEIVING_WINDOW else "waiting"
            )
        items.append(
            PortItem(
                sensor=spec.sensor,
                label=spec.label,
                enabled=enabled,
                protocols=list(spec.protocols),
                external_port=spec.external_port,
                host_port=_port_env(spec.env_var, spec.external_port, source),
                env_var=spec.env_var,
                state=state,
                last_event_at=last if enabled else None,
            )
        )
    return items


async def last_events(db: AsyncSession, now: datetime) -> dict[str, datetime]:
    """Newest event per sensor in the last 24 hours (index lookups, not a grouped scan)."""
    return await latest_event_per_sensor(db, now - RECEIVING_WINDOW)


@router.get("/setup/ports", response_model=Ports, dependencies=[Depends(require_admin)])
async def get_ports(db: DbSession) -> Ports:
    now = datetime.now(UTC)
    return Ports(
        dashboard_port=dashboard_port(), items=build_ports(await last_events(db, now), now)
    )
