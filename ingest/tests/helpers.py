from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import Event
from suckerpot_egress import EgressGate, EgressSettings, GateStatus

from ingest.floods.config import FoldSettings
from ingest.floods.fold import fold_buckets

T0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)


def make_event(
    etype: str,
    *,
    sid: str = "s1",
    offset_s: float = 0,
    data: dict[str, Any] | None = None,
    sensor: str = "ssh",
    ip: str = "203.0.113.7",
    base: datetime = T0,
) -> Event:
    return Event.model_validate(
        {
            "ts": base + timedelta(seconds=offset_s),
            "sensor": sensor,
            "session_id": sid,
            "src_ip": ip,
            "src_port": 40000,
            "dst_port": 2222,
            "type": etype,
            "data": data or {},
        }
    )


def fake_gate(*, open_: bool = True, reason: str = "ok") -> EgressGate:
    """A gate with a fixed verdict and no network: ``check()`` is never called."""
    gate = EgressGate(EgressSettings(proxy_password="t" * 24))
    gate._status = GateStatus(open_, reason, "9.9.9.9" if open_ else None, datetime.now(UTC))
    return gate


async def fold_hour(
    factory: async_sessionmaker[AsyncSession],
    ip: str,
    sensor: str,
    hour: datetime,
    *,
    plain_tags: Collection[str] = (),
    minimum: int = 20,
) -> int:
    """Fold one (address, sensor, UTC hour) bucket as the ingest role does; returns the number
    of connections folded."""
    async with factory() as session, session.begin():
        return await fold_buckets(
            session, [(ip, sensor, hour)], FoldSettings(min_connections=minimum), plain_tags,
            limit=1000,
        )  # fmt: skip
