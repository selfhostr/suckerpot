"""The network pseudonym is a deny term for abuse reports only (M38): the node's own pseudonym
check (and so its enrolment) must never refuse the name because it matches itself."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.abuse.selfterms import TermsCache
from ingest.features import FeatureSettings
from ingest.network.config import NetworkSettings
from ingest.network.worker import NetworkWorker

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NAME = "quiet-heron-17"


async def test_the_pseudonym_check_accepts_the_nodes_own_name(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source) "
                "VALUES ('address', '198.51.100.200', 'manual') ON CONFLICT DO NOTHING"
            )
        )
        await conn.execute(
            text(
                "UPDATE network_membership SET pseudonym = :n, desired = 'member', "
                "state = 'enrolling' WHERE id = 1"
            ),
            {"n": NAME},
        )
    env = {"NETWORK_PSEUDONYM": NAME}
    try:
        network_terms = TermsCache(factory, env)  # what main.py gives the network worker
        worker = NetworkWorker(
            FeatureSettings(network_enabled=True),
            NetworkSettings(),
            None,
            network_terms,
            None,
        )
        assert await worker._pseudonym_ok(NAME) is True
        assert NAME not in (await network_terms.get()).texts  # type: ignore[union-attr]
        # The abuse worker's deny set does carry it: a report never names the node.
        abuse_terms = await TermsCache(factory, env, with_pseudonym=True).get()
        assert abuse_terms is not None and NAME in abuse_terms.texts
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE network_membership SET pseudonym = NULL, desired = 'off', "
                    "state = 'off' WHERE id = 1"
                )
            )
            await conn.execute(text("DELETE FROM report_self_terms"))
