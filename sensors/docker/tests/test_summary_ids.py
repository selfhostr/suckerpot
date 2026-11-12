"""Summary events get random session ids: no repeat across restarts or source addresses."""

from __future__ import annotations

import re

from suckerpot_common import Event, EventType

from docker_sensor.events import EventSink

IPS = [f"198.51.100.{n}" for n in range(1, 21)]


class Pub:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


async def _summaries() -> list[Event]:
    """One fresh sink (a freshly started sensor process): flood from every IP, then summarise."""
    pub = Pub()
    sink = EventSink(pub, ip_rate=0.001, ip_burst=1.0)
    sink.start()
    for ip in IPS:
        for _ in range(5):
            sink.emit(
                session_id="flood",
                src_ip=ip,
                src_port=1,
                dst_port=2375,
                type_=EventType.http_request,
                data={},
            )
    assert sink.flush_overflow() == len(IPS)
    await sink.flush()
    out = [e for e in pub.events if e.data.get("kind") == "events_suppressed"]
    await sink.close()
    return out


async def test_summary_session_ids_are_unique_across_restarts_and_addresses() -> None:
    first = await _summaries()
    second = await _summaries()  # a restart: a new EventSink, the old counters are gone
    assert len(first) == len(second) == len(IPS)
    assert {str(e.src_ip) for e in first} == set(IPS)
    ids = [e.session_id for e in first + second]
    assert len(set(ids)) == len(ids)  # no id reused, not across IPs, not across the two runs
    for sid in ids:
        assert re.fullmatch(r"[0-9a-f]{24}", sid)
        assert not sid.startswith(("sum-", "burst-"))
