"""A refused enrolment heals by itself (2026-11-21 field report): a node stuck in ``error`` after
``pseudonym_taken`` must not need the owner to type a command."""

from __future__ import annotations

import random
from datetime import date, datetime, timedelta
from typing import Any

import pytest
from suckerpot_db.secretbox import SecretBox

from ingest.features import FeatureSettings
from ingest.network import participant, pseudonym
from ingest.network.builder import BatchBuilder
from ingest.network.worker import NetworkWorker

from .helpers import (
    NOW,
    FakeGate,
    FakeHub,
    FakeTerms,
    MemoryStore,
    hub_client,
    make_terms,
    settings,
)
from .test_worker import Src

BOX = SecretBox(bytes(range(32)))
CONSENT = "v2:sources,payloads,c2,files,rechecks:2026-11-03"
GENERATED = "amber-falcon-42"
TAKEN = (409, "pseudonym_taken")


class Node:
    """One worker process over a store, with a clock the test moves."""

    def __init__(self, store: MemoryStore, hub: FakeHub | None = None, **kw: Any) -> None:
        self.store = store
        self.hub = hub or FakeHub()
        self.now: datetime = NOW
        base: dict[str, Any] = {"stack_mode": "participant", "consent": CONSENT}
        base.update(kw)
        terms = FakeTerms(make_terms())
        self.worker = NetworkWorker(
            FeatureSettings(network_enabled=True),
            settings(**base),
            store,
            terms,
            BatchBuilder(Src(), terms, allow_documentation=True),
            box=BOX,
            gate=FakeGate(True),  # type: ignore[arg-type]
            client=hub_client(self.hub),
            clock=lambda: self.now,
            rng=random.Random(11),  # noqa: S311
            allow_documentation=True,
        )

    async def cycle(self, at: timedelta = timedelta(0)) -> None:
        self.now = NOW + at
        await self.worker.run_once()

    def enrols(self) -> int:
        return len([c for c in self.hub.calls if c == ("POST", "/v1/enrol")])


def stuck(**kw: Any) -> MemoryStore:
    """The field state: a refused join, left as error / desired off."""
    base: dict[str, Any] = {
        "state": "error", "desired": "off", "last_error_code": "pseudonym_taken",
        "pseudonym": "night owl", "requested_by": "installer", "requested_at": NOW,
    }  # fmt: skip
    base.update(kw)
    return MemoryStore(**base)


# -- the field case ------------------------------------------------------------------------------


async def test_a_stuck_node_with_a_new_name_in_env_enrols_on_the_first_cycle() -> None:
    """After the update: the owner had set a new name, nothing cleared the error. No command."""
    store = stuck(requested_at=NOW - timedelta(days=2))
    node = Node(store, pseudonym="grey heron")
    await node.cycle()
    assert store.m.state == "member" and store.m.pseudonym == "grey heron"
    assert node.hub.bodies[-1]["pseudonym"] == "grey heron"
    assert store.m.last_error_code is None and store.m.requested_at == NOW


async def test_a_new_name_is_tried_at_once_even_right_after_the_refusal() -> None:
    store = stuck()
    node = Node(store, pseudonym="grey heron")
    await node.cycle(timedelta(minutes=1))
    assert store.m.state == "member" and store.m.pseudonym == "grey heron"


async def test_a_refused_new_name_is_not_hammered() -> None:
    store = stuck()
    node = Node(store, pseudonym="grey heron")
    node.hub.fail["POST /v1/enrol"] = TAKEN
    await node.cycle(timedelta(minutes=1))
    assert node.enrols() == 1 and store.m.state == "error"
    assert store.m.pseudonym == "grey heron" and store.m.last_error_code == "pseudonym_taken"
    for minutes in (2, 30, 60 * 23):
        await node.cycle(timedelta(minutes=minutes))
    assert node.enrols() == 1  # now the same name: once a day only


async def test_an_anonymous_env_after_a_refused_name_enrols_without_a_name() -> None:
    store = stuck()
    node = Node(store, pseudonym="")
    await node.cycle()
    assert store.m.state == "member" and "pseudonym" not in node.hub.bodies[-1]


# -- a chosen name: once a day ----------------------------------------------------------------------


async def test_a_chosen_name_is_tried_again_once_a_day_until_the_hub_frees_it() -> None:
    store = stuck()
    node = Node(store, pseudonym="night owl")
    node.hub.fail["POST /v1/enrol"] = TAKEN
    await node.cycle(timedelta(hours=1))
    await node.cycle(timedelta(hours=23, minutes=59))
    assert node.hub.calls == [] and store.m.state == "error"
    await node.cycle(timedelta(hours=24))
    assert node.enrols() == 1 and store.m.state == "error"
    assert store.m.pseudonym == "night owl"  # a chosen name is kept
    await node.cycle(timedelta(hours=24, minutes=1))
    await node.cycle(timedelta(hours=47))
    assert node.enrols() == 1
    del node.hub.fail["POST /v1/enrol"]  # the hub freed the ghost's name
    await node.cycle(timedelta(hours=48))
    assert node.enrols() == 2 and store.m.state == "member"
    assert node.hub.bodies[-1]["pseudonym"] == "night owl"


async def test_the_daily_wait_survives_a_restart() -> None:
    store = stuck()
    first = Node(store, pseudonym="night owl")
    first.hub.fail["POST /v1/enrol"] = TAKEN
    await first.cycle(timedelta(hours=24))
    assert first.enrols() == 1
    again = Node(store, pseudonym="night owl")  # same database, new process
    again.hub.fail["POST /v1/enrol"] = TAKEN
    await again.cycle(timedelta(hours=25))
    assert again.hub.calls == []
    await again.cycle(timedelta(hours=48))
    assert again.enrols() == 1


async def test_an_invalid_name_is_checked_again_once_a_day_without_a_hub_call() -> None:
    store = stuck(last_error_code="pseudonym_invalid", pseudonym="owner-home.example.net")
    node = Node(store, pseudonym="owner-home.example.net")
    await node.cycle(timedelta(hours=24))
    # the local guard refuses it again before any call
    assert node.hub.calls == [] and store.m.last_error_code == "pseudonym_invalid"
    assert store.m.state == "error" and store.m.requested_at == NOW + timedelta(hours=24)


# -- a generated name: a new one ------------------------------------------------------------------


async def test_a_taken_generated_name_is_replaced_after_the_backoff() -> None:
    store = stuck(pseudonym=GENERATED)
    node = Node(store, pseudonym=GENERATED)
    await node.cycle(timedelta(minutes=10))
    assert node.hub.calls == []  # inside the first 15 minutes
    await node.cycle(timedelta(minutes=16))
    new = store.m.pseudonym
    assert store.m.state == "member" and new != GENERATED and pseudonym.is_generated(new)
    assert node.hub.bodies[-1]["pseudonym"] == new


async def test_a_worker_replacement_is_not_traded_back_for_the_env_name() -> None:
    """After five refused replacements the stored name differs from .env, both generated: the
    worker picks yet another name with backoff, never the .env name it already knows is taken."""
    store = stuck(pseudonym="calm-otter-17")
    node = Node(store, pseudonym=GENERATED)
    await node.cycle(timedelta(minutes=1))
    assert node.hub.calls == []
    await node.cycle(timedelta(minutes=16))
    assert store.m.state == "member" and store.m.pseudonym not in (GENERATED, "calm-otter-17")


async def test_generated_retries_back_off() -> None:
    store = stuck(pseudonym=GENERATED)
    node = Node(store, pseudonym=GENERATED)
    node.hub.fail["POST /v1/enrol"] = TAKEN
    minutes = 0
    for _ in range(40):  # 40 cycles of 30 minutes = 20 hours
        minutes += 30
        await node.cycle(timedelta(minutes=minutes))
    assert store.m.state == "error"
    # 15 min, 30, 60, 120, 240, 360, 360 ... plus the five in-process replacements of _retry_name
    assert node.enrols() <= 16


# -- never ---------------------------------------------------------------------------------------


async def test_a_node_that_left_never_rejoins() -> None:
    store = stuck(left_day=date(2026, 11, 2))
    node = Node(store, pseudonym="grey heron")
    await node.cycle(timedelta(days=2))
    assert node.hub.calls == [] and store.m.state == "error" and store.m.desired == "off"


async def test_a_pending_leave_is_not_turned_into_a_join() -> None:
    store = stuck(desired="leave")
    node = Node(store, pseudonym="grey heron")
    await node.cycle(timedelta(days=2))
    assert store.m.desired == "off" and store.m.state == "off" and store.m.left_day is not None
    assert ("POST", "/v1/enrol") not in node.hub.calls


@pytest.mark.parametrize(
    "consent",
    ["", "x", "v3:sources:2026-11-03", "v2:sources,payloads,c2,files,rechecks:2026-10-20"],
)
async def test_no_retry_without_a_valid_fresh_record(consent: str) -> None:
    store = stuck(requested_at=NOW - timedelta(days=2))
    node = Node(store, pseudonym="grey heron", consent=consent)
    await node.cycle()
    assert node.hub.calls == [] and store.m.state == "error"


async def test_an_admin_request_is_left_to_the_dashboard() -> None:
    store = stuck(requested_by="admin")
    node = Node(store, pseudonym="grey heron")
    await node.cycle(timedelta(days=2))
    assert node.hub.calls == [] and store.m.state == "error"


@pytest.mark.parametrize("code", ["no_settings_key", "unsupported_protocol", None])
async def test_other_errors_are_not_retried_this_way(code: str | None) -> None:
    store = stuck(last_error_code=code)
    node = Node(store, pseudonym="grey heron")
    await node.cycle(timedelta(days=2))
    assert node.hub.calls == [] and store.m.state == "error"


def test_can_self_heal_rules() -> None:
    _, consent = participant.parse(CONSENT)
    ok: dict[str, Any] = {
        "state": "error", "desired": "off", "left_day": None, "requested_by": "installer",
        "error_code": "pseudonym_taken", "consent": consent, "today": NOW.date(),
    }  # fmt: skip
    assert participant.can_self_heal(**ok)
    for key, value in (
        ("state", "off"),
        ("desired", "member"),
        ("desired", "leave"),
        ("left_day", NOW.date()),
        ("requested_by", "admin"),
        ("error_code", "no_settings_key"),
        ("consent", None),
        ("today", NOW.date() + timedelta(days=8)),
    ):
        assert not participant.can_self_heal(**{**ok, key: value}), key
