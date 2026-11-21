"""``fetch_recent`` reads a time window first and widens it; the order stays newest id first."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from suckerpot_db import EventRow, create_engine, create_session_factory

from api.live import fetch_recent

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


async def test_the_window_widens_until_the_page_is_full() -> None:
    engine = create_engine(pool_size=1)
    factory = create_session_factory(engine)
    now = datetime.now(UTC)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE events, sessions"))
        # Inserted in this order, so the ids grow: old (30 days), fresh (now), late (3 days).
        for sid, age in (("old", 30), ("fresh", 0), ("late", 3)):
            async with factory() as s, s.begin():
                s.add(
                    EventRow(
                        ts=now - timedelta(days=age),
                        sensor="ssh",
                        session_id=sid,
                        type="connect",
                        src_ip="203.0.113.7",
                        src_port=1,
                        dst_port=2,
                        data={},
                    )
                )
        async with factory() as s:
            every = await fetch_recent(s, 10)
            two = await fetch_recent(s, 2)
            one = await fetch_recent(s, 1)
        # Fewer rows than asked: the unbounded read, newest id first, as before.
        assert [e.session_id for e in every] == ["late", "fresh", "old"]
        assert [e.id for e in every] == sorted((e.id for e in every), reverse=True)
        # The 7 day window fills a page of two.
        assert [e.session_id for e in two] == ["late", "fresh"]
        # The 24 hour window fills a page of one.
        assert [e.session_id for e in one] == ["fresh"]
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE events, sessions"))
        await engine.dispose()
