"""The network worker against a fake hub: opt-in, egress, schedule, leave (N1, N2, N5, N8, N9)."""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from suckerpot_db.secretbox import SecretBox
from suckerpot_netproto import blind
from suckerpot_netproto import models as wire
from suckerpot_reporting import SelfTermRow, load_self_terms

from ingest.features import FeatureSettings
from ingest.network import identity as ident
from ingest.network.builder import BatchBuilder
from ingest.network.source import PayloadFact, SessionFact
from ingest.network.worker import NetworkWorker

from .helpers import (
    NOW,
    SELF_NAME,
    FakeGate,
    FakeHub,
    FakeTerms,
    MemoryStore,
    hub_client,
    make_terms,
    settings,
)

BOX = SecretBox(bytes(range(32)))


class Src:
    def __init__(self) -> None:
        self.sessions_for: list[date] = []

    async def sessions(self, day: date) -> list[SessionFact]:
        self.sessions_for.append(day)
        return [SessionFact("198.51.100.23", "ssh", 2, 5, False, 0, 0, 0, ("mirai",))]

    async def payloads(self, day: date) -> list[PayloadFact]:
        return []

    async def c2(self, day: date) -> list[Any]:
        return []

    async def files(self, day: date) -> list[Any]:
        return []


class Rig:
    def __init__(
        self,
        store: MemoryStore,
        *,
        enabled: bool = True,
        terms: bool = True,
        gate_open: bool = True,
        now: datetime = NOW,
    ) -> None:
        self.store, self.hub, self.src = store, FakeHub(), Src()
        self.gate = FakeGate(gate_open)
        self.now = now
        fake_terms = FakeTerms(make_terms(terms))
        self.worker = NetworkWorker(
            FeatureSettings(network_enabled=enabled),
            settings(enabled=enabled),
            store,
            fake_terms,
            BatchBuilder(self.src, fake_terms, allow_documentation=True),
            box=BOX,
            gate=self.gate,  # type: ignore[arg-type]
            client=hub_client(self.hub),
            clock=lambda: self.now,
            allow_documentation=True,
        )

    async def cycle(self) -> None:
        await self.worker.run_once()


def member_store(**kw: Any) -> MemoryStore:
    identity = ident.generate()
    cipher, nonce = ident.seal(identity, BOX)
    base: dict[str, Any] = {
        "desired": "member", "state": "member", "pubkey": identity.public,
        "privkey_enc": cipher, "privkey_nonce": nonce, "fingerprint": identity.fingerprint,
        "node_id": __import__("uuid").UUID(int=7), "enrolled_day": date(2026, 10, 20),
        "next_submit_at": NOW - timedelta(hours=1), "last_pull_at": NOW,
        "last_summary_at": NOW, "synced_show_country": False,
    }  # fmt: skip
    return MemoryStore(**{**base, **kw})


# -- N1: opt-in --------------------------------------------------------------------------


async def test_idle_without_the_admin_opt_in() -> None:
    rig = Rig(MemoryStore())  # NETWORK_ENABLED on, but desired = off
    await rig.cycle()
    assert rig.hub.calls == []
    assert rig.worker.state == "off"


async def test_disabled_in_env_never_calls_the_hub_even_when_asked() -> None:
    rig = Rig(MemoryStore(desired="member"), enabled=False)
    task = asyncio.create_task(rig.worker.run())
    await asyncio.sleep(0.05)
    task.cancel()
    assert rig.hub.calls == []
    assert rig.store.m.state == "off"


async def test_leaving_with_the_env_off_wipes_locally_and_calls_nothing() -> None:
    store = member_store(desired="leave")
    rig = Rig(store, enabled=False)
    task = asyncio.create_task(rig.worker.run())
    await asyncio.sleep(0.05)
    task.cancel()
    assert rig.hub.calls == [] and store.wiped == 1
    assert store.m.privkey_enc is None and store.m.last_error_code == "leave_unconfirmed"


async def test_no_hub_configured_does_nothing() -> None:
    rig = Rig(MemoryStore(desired="member"))
    rig.worker.network = settings(hub_url="", hub_key="")
    await rig.cycle()
    assert rig.hub.calls == []


# -- N2: egress ----------------------------------------------------------------------------


async def test_a_closed_gate_sends_nothing_and_keeps_the_state() -> None:
    store = member_store()
    rig = Rig(store, gate_open=False)
    await rig.cycle()
    assert rig.hub.calls == []
    assert store.m.state == "member" and store.m.last_error_code == "egress_closed"


async def test_a_closed_gate_blocks_enrolment_before_a_key_is_made() -> None:
    store = MemoryStore(desired="member")
    rig = Rig(store, gate_open=False)
    await rig.cycle()
    assert rig.hub.calls == [] and store.m.privkey_enc is None


# -- enrolment -----------------------------------------------------------------------------


async def test_enrolment_stores_an_encrypted_key_and_schedules_the_first_batch() -> None:
    store = MemoryStore(desired="member", pseudonym="night owl", country="CH", show_country=True)
    rig = Rig(store)
    await rig.cycle()
    assert store.m.state == "member" and store.m.fingerprint == "3f9a1c07"
    assert rig.hub.enrolled
    assert [c for c in rig.hub.calls][:3] == [
        ("GET", "/v1/info"), ("POST", "/v1/enrol/challenge"), ("POST", "/v1/enrol"),
    ]  # fmt: skip
    seed = ident.unseal(BOX, store.m.privkey_enc or b"", store.m.privkey_nonce or b"",
                        store.m.pubkey or b"").seed  # fmt: skip
    assert seed not in (store.m.privkey_enc or b"")  # ciphertext, not the key
    assert rig.hub.bodies[-1]["pseudonym"] == "night owl"
    # the first release is after midnight plus 2 to 20 hours (N5)
    nxt = store.m.next_submit_at
    assert nxt is not None
    midnight = datetime(2026, 11, 4, tzinfo=UTC)
    assert midnight + timedelta(hours=2) <= nxt <= midnight + timedelta(hours=20)


async def test_without_the_settings_key_no_key_is_made() -> None:
    store = MemoryStore(desired="member")
    rig = Rig(store)
    rig.worker.box = None
    await rig.cycle()
    assert store.m.state == "error" and store.m.last_error_code == "no_settings_key"
    assert rig.hub.calls == []


async def test_a_pseudonym_naming_the_owner_is_refused_before_any_call() -> None:
    store = MemoryStore(desired="member", pseudonym=SELF_NAME[:24])
    rig = Rig(store)
    await rig.cycle()
    assert rig.hub.calls == []
    assert store.m.state == "error" and store.m.last_error_code == "pseudonym_invalid"


async def test_a_taken_pseudonym_ends_the_attempt_for_good() -> None:
    store = MemoryStore(desired="member", pseudonym="night owl")
    rig = Rig(store)
    rig.hub.fail["POST /v1/enrol"] = (409, "pseudonym_taken")
    await rig.cycle()
    assert store.m.state == "error" and store.m.desired == "off"
    assert store.m.last_error_code == "pseudonym_taken"
    await rig.cycle()  # nothing more is attempted
    assert [c for c in rig.hub.calls if c[1] == "/v1/enrol"] == [("POST", "/v1/enrol")]


@pytest.mark.parametrize("code", ["enrolment_closed", "pow_timeout"])
async def test_a_closed_or_too_hard_enrolment_waits_with_backoff_and_never_opts_out(
    code: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = MemoryStore(desired="member", pseudonym="night owl")
    rig = Rig(store)
    if code == "pow_timeout":

        async def too_slow(*_: Any, **__: Any) -> None:
            return None

        monkeypatch.setattr("ingest.network.worker.solve_low_priority", too_slow)
    else:
        rig.hub.fail["POST /v1/enrol"] = (503, "enrolment_closed")
    await rig.cycle()
    assert store.m.desired == "member" and store.m.state == "enrolling"
    assert store.m.last_error_code == "waiting_enrolment"
    attempts = len([c for c in rig.hub.calls if c[1] == "/v1/enrol/challenge"])
    await rig.cycle()  # still inside the first 15 minutes: no call at all
    assert len([c for c in rig.hub.calls if c[1] == "/v1/enrol/challenge"]) == attempts
    rig.now = NOW + timedelta(minutes=16)
    await rig.cycle()
    assert len([c for c in rig.hub.calls if c[1] == "/v1/enrol/challenge"]) == attempts + 1
    rig.now = NOW + timedelta(minutes=16 + 20)  # the second wait is twice as long (30 min)
    await rig.cycle()
    assert len([c for c in rig.hub.calls if c[1] == "/v1/enrol/challenge"]) == attempts + 1
    assert store.m.desired == "member"


async def test_enrolment_succeeds_once_the_hub_reopens(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemoryStore(desired="member")
    rig = Rig(store)
    rig.hub.fail["POST /v1/enrol"] = (503, "enrolment_closed")
    await rig.cycle()
    del rig.hub.fail["POST /v1/enrol"]
    rig.now = NOW + timedelta(minutes=16)
    await rig.cycle()
    assert store.m.state == "member" and store.m.last_error_code is None


# -- N9: the hub's signature -------------------------------------------------------------------


async def test_an_answer_with_a_bad_signature_is_refused() -> None:
    store = MemoryStore(desired="member")
    rig = Rig(store)
    rig.hub.bad_signature = True
    await rig.cycle()
    assert store.m.state != "member" and not rig.hub.enrolled
    assert store.m.last_error_code == "hub_signature"


# -- submissions (N5) --------------------------------------------------------------------------


async def test_closed_days_are_sent_the_current_day_never() -> None:
    store = member_store()
    rig = Rig(store)
    await rig.cycle()
    sent = sorted(rig.src.sessions_for)
    assert sent == [date(2026, 11, 1), date(2026, 11, 2)]  # at most the last two closed days
    posts = [b for b in rig.hub.bodies if "batch_id" in b]
    assert {b["day"] for b in posts} == {"2026-11-01", "2026-11-02"}
    assert all(b["day"] != "2026-11-03" for b in posts)
    assert store.m.last_submit_day == date(2026, 11, 2)
    assert store.m.next_submit_at is not None and store.m.next_submit_at > NOW
    assert store.subs[date(2026, 11, 2)]["status"] == "sent"
    await rig.cycle()  # nothing due now
    assert len([b for b in rig.hub.bodies if "batch_id" in b]) == 2


async def test_nothing_is_sent_before_the_release_time() -> None:
    store = member_store(next_submit_at=NOW + timedelta(hours=3))
    rig = Rig(store)
    await rig.cycle()
    assert rig.hub.calls == []


async def test_a_day_is_not_sent_twice() -> None:
    store = member_store()
    rig = Rig(store)
    await rig.cycle()
    store.m.next_submit_at = NOW - timedelta(minutes=1)
    await rig.cycle()
    assert len([b for b in rig.hub.bodies if "batch_id" in b]) == 2


async def test_without_a_confirmed_self_address_nothing_is_sent() -> None:
    store = member_store()
    rig = Rig(store, terms=False)
    await rig.cycle()
    assert [c for c in rig.hub.calls if c[1] == "/v1/observations"] == []
    assert store.m.last_error_code == "waiting_self_address"


async def test_a_lost_answer_resends_the_same_batch_id() -> None:
    store = member_store()
    rig = Rig(store)
    rig.hub.fail["POST /v1/observations"] = (500, "server_error")
    await rig.cycle()
    first = rig.hub.bodies[0]["batch_id"]
    del rig.hub.fail["POST /v1/observations"]
    await rig.cycle()
    assert rig.hub.bodies[1]["batch_id"] == first and rig.hub.bodies[1]["day"] == "2026-11-01"


async def _pending_rig() -> tuple[Rig, MemoryStore]:
    store = member_store()
    rig = Rig(store)
    rig.hub.fail["POST /v1/observations"] = (500, "server_error")
    await rig.cycle()
    del rig.hub.fail["POST /v1/observations"]
    assert store.subs[date(2026, 11, 1)]["payload"] is not None
    return rig, store


async def test_a_duplicate_answer_to_a_resend_keeps_the_sent_counts() -> None:
    rig, store = await _pending_rig()
    stored = store.subs[date(2026, 11, 1)]["payload"]
    expected = {k: len(stored[k]) for k in ("sources", "payloads", "c2", "files")}
    assert sum(expected.values()) > 0
    rig.hub.duplicate = True
    await rig.cycle()
    row = store.subs[date(2026, 11, 1)]
    assert row["status"] == "sent" and row["counts"] == expected


async def test_a_duplicate_answer_to_a_fresh_build_keeps_the_sent_counts() -> None:
    store = member_store()
    rig = Rig(store)
    rig.hub.duplicate = True
    await rig.cycle()
    row = store.subs[date(2026, 11, 1)]
    posted = next(b for b in rig.hub.bodies if b.get("day") == "2026-11-01")
    expected = {k: len(posted[k]) for k in ("sources", "payloads", "c2", "files")}
    assert sum(expected.values()) > 0
    assert row["status"] == "sent" and row["counts"] == expected


async def test_a_normal_answer_records_the_hub_numbers_even_when_lower() -> None:
    store = member_store()
    rig = Rig(store)
    rig.hub.accept_at_most = 0
    await rig.cycle()
    row = store.subs[date(2026, 11, 1)]
    posted = next(b for b in rig.hub.bodies if b.get("day") == "2026-11-01")
    assert sum(len(posted[k]) for k in ("sources", "payloads", "c2", "files")) > 0
    assert row["status"] == "sent"
    assert row["counts"] == {"sources": 0, "payloads": 0, "c2": 0, "files": 0}


async def test_a_stored_batch_is_guarded_again_before_the_resend() -> None:
    rig, store = await _pending_rig()
    sent = len(rig.hub.bodies)
    # The owner adds the address of a stored source to the self terms after the batch was built.
    rig.worker.terms = FakeTerms(
        load_self_terms([SelfTermRow(kind="address", value="198.51.100.23", source="manual")], {})
    )
    await rig.cycle()
    assert len(rig.hub.bodies) == sent  # nothing went out
    row = store.subs[date(2026, 11, 1)]
    assert row["error_code"] == "guard_failed" and row["payload"] is None
    assert store.m.last_error_code == "guard_failed"


async def test_a_stored_batch_is_not_resent_without_a_self_address() -> None:
    rig, store = await _pending_rig()
    sent = len(rig.hub.bodies)
    rig.worker.terms = FakeTerms(make_terms(False))
    await rig.cycle()
    assert len(rig.hub.bodies) == sent
    assert store.m.last_error_code == "waiting_self_address"
    assert store.subs[date(2026, 11, 1)]["payload"] is not None  # kept for later


async def test_a_malformed_stored_batch_is_dropped_not_sent() -> None:
    rig, store = await _pending_rig()
    sent = len(rig.hub.bodies)
    store.subs[date(2026, 11, 1)]["payload"] = {**store.subs[date(2026, 11, 1)]["payload"], "x": 1}
    await rig.cycle()
    assert len(rig.hub.bodies) == sent
    assert store.subs[date(2026, 11, 1)]["payload"] is None


# -- leaving (N8) --------------------------------------------------------------------------


async def test_leaving_deletes_at_the_hub_then_everywhere_locally() -> None:
    store = member_store(desired="leave")
    store.subs[date(2026, 11, 1)] = {"status": "sent", "payload": None}
    rig = Rig(store)
    await rig.cycle()
    assert rig.hub.deleted and store.wiped == 1
    assert store.m.privkey_enc is None and store.m.pubkey is None and store.m.state == "off"
    assert store.subs == {} and store.targets == {} and store.summary is None
    assert store.m.last_error_code is None


async def test_leaving_when_the_hub_does_not_know_the_node_still_wipes() -> None:
    store = member_store(desired="leave")
    rig = Rig(store)
    rig.hub.fail["DELETE /v1/node"] = (401, "unknown_node")
    await rig.cycle()
    assert store.wiped == 1


async def test_leaving_sends_a_signed_delete_even_without_a_node_id() -> None:
    store = member_store(desired="leave", node_id=None)
    rig = Rig(store)
    await rig.cycle()
    assert rig.hub.deleted and store.wiped == 1 and store.m.last_error_code is None


async def test_any_hub_error_ends_in_the_seven_day_give_up() -> None:
    store = member_store(desired="leave")
    rig = Rig(store)
    rig.hub.fail["DELETE /v1/node"] = (500, "server_error")
    await rig.cycle()
    assert store.wiped == 0 and store.m.state == "leaving"
    rig.now = NOW + timedelta(days=8)
    await rig.cycle()
    assert store.wiped == 1 and store.m.last_error_code == "leave_unconfirmed"
    assert store.m.privkey_enc is None


async def test_leaving_is_retried_for_seven_days_then_given_up() -> None:
    store = member_store(desired="leave")
    rig = Rig(store)
    rig.hub.fail["DELETE /v1/node"] = (429, "rate_limited")
    await rig.cycle()
    assert store.wiped == 0 and store.m.state == "leaving"
    rig.now = NOW + timedelta(days=6)
    await rig.cycle()
    assert store.wiped == 0
    rig.gate.open = False
    rig.now = NOW + timedelta(days=8)
    await rig.cycle()
    assert store.wiped == 1 and store.m.last_error_code == "leave_unconfirmed"
    assert store.m.privkey_enc is None


async def test_leaving_before_enrolment_makes_no_call() -> None:
    store = MemoryStore(desired="leave", state="error")
    rig = Rig(store)
    await rig.cycle()
    assert rig.hub.calls == [] and store.wiped == 1


# -- pulling, reveals, rechecks, summary -------------------------------------------------------


def target(tid: str, kind: str, value: str | None, value_b: str | None) -> dict[str, Any]:
    return {
        "id": tid, "kind": kind, "value": value, "value_b": value_b, "state": "confirmed",
        "nodes": 0, "countries": None, "first_day": "2026-10-30", "last_day": "2026-11-02",
        "services": ["ssh"], "activity": ["login"], "tags": ["mirai"], "families": [],
        "reported_day": None, "taken_down_day": None,
    }  # fmt: skip


async def test_pull_stores_targets_and_answers_only_requested_reveals() -> None:
    url = "http://dropper.example.org/a.sh"
    own = f"http://{SELF_NAME}/b.sh"
    asked_b = blind.blind_url(url)
    other_b = blind.blind_url("http://unasked.example.org/c.sh")
    store = member_store(last_pull_at=None, last_summary_at=None)
    store.values["url"] = [url, own, "http://unasked.example.org/c.sh"]
    rig = Rig(store)
    rig.hub.targets = {
        "cursor": "c_2",
        "targets": [target("t_00000000000a", "url", None, asked_b),
                    target("t_00000000000b", "ip", "198.51.100.23", None)],
        "reveal": [{"kind": "url", "value_b": asked_b},
                   {"kind": "url", "value_b": blind.blind_url(own)}],
        "recheck": [{"id": "t_00000000000b", "kind": "ip", "value": "198.51.100.23"}],
    }  # fmt: skip
    del other_b
    await rig.cycle()
    assert set(store.targets) == {"t_00000000000a", "t_00000000000b"}
    assert store.m.pull_cursor == "c_2"
    assert asked_b in store.mine
    reveals = [b for b in rig.hub.bodies if b.get("items") and "kind" in b["items"][0]]
    assert len(reveals) == 1
    assert [i["value"] for i in reveals[0]["items"]] == [url]  # the guard kept our name out
    assert SELF_NAME not in str(reveals)
    # the M27 adapter is a documented limit: every state is unknown, so no recheck leaves
    assert [c for c in rig.hub.calls if c[1] == "/v1/rechecks"] == []
    assert store.summary is not None and store.m.standing == "good"


async def test_nothing_is_revealed_without_a_known_own_address() -> None:
    url = "http://dropper.example.org/a.sh"
    asked_b = blind.blind_url(url)
    store = member_store(last_pull_at=None, last_summary_at=None)
    store.values["url"] = [url]
    rig = Rig(store, terms=False)
    rig.hub.targets = {
        "cursor": "c_2", "targets": [target("t_00000000000a", "url", None, asked_b)],
        "reveal": [{"kind": "url", "value_b": asked_b}], "recheck": [],
    }  # fmt: skip
    await rig.cycle()
    assert [c for c in rig.hub.calls if c[1] == "/v1/reveals"] == []


async def test_a_hash_the_hub_asks_for_without_a_confirmed_target_is_not_revealed() -> None:
    held = "http://canary.example.org/x.sh"  # an indicator we hold, but never confirmed
    asked_b = blind.blind_url(held)
    store = member_store(last_pull_at=None, last_summary_at=None)
    store.values["url"] = [held]
    rig = Rig(store)
    rig.hub.targets = {
        "cursor": "c_2", "targets": [],
        "reveal": [{"kind": "url", "value_b": asked_b}], "recheck": [],
    }  # fmt: skip
    await rig.cycle()
    assert [b for b in rig.hub.bodies if b.get("items") and "kind" in b["items"][0]] == []
    assert [c for c in rig.hub.calls if c[1] == "/v1/reveals"] == []


async def test_a_confirmed_hash_outside_the_reveal_pool_is_not_revealed() -> None:
    other = "http://seen-as-other-role.example.org/x.sh"
    asked_b = blind.blind_url(other)
    store = member_store(last_pull_at=None, last_summary_at=None)
    store.values["url"] = [other]
    store.reveal_pool["url"] = []  # not a download_host of a real session
    rig = Rig(store)
    rig.hub.targets = {
        "cursor": "c_2", "targets": [target("t_00000000000a", "url", None, asked_b)],
        "reveal": [{"kind": "url", "value_b": asked_b}], "recheck": [],
    }  # fmt: skip
    await rig.cycle()
    assert [c for c in rig.hub.calls if c[1] == "/v1/reveals"] == []


async def test_an_unknown_field_in_a_pulled_target_is_refused() -> None:
    store = member_store(last_pull_at=None)
    rig = Rig(store)
    bad = target("t_00000000000a", "ip", "198.51.100.23", None) | {"extra": 1}
    rig.hub.targets = {"cursor": "c_2", "targets": [bad], "reveal": [], "recheck": []}
    await rig.cycle()
    assert store.targets == {} and store.m.last_error_code == "invalid_payload"
    wire.Target.model_validate(target("t_00000000000a", "ip", "198.51.100.23", None))


@pytest.mark.parametrize("ip", [".".join(("10", "0", "0", "4"))])
async def test_a_private_target_value_is_not_stored_as_a_list_entry(ip: str) -> None:
    # The wire model accepts any string value; the blocklist side validates again (normalize_value).
    from suckerpot_db.blocklist_values import normalize_value

    assert normalize_value("ip", ip) is None


async def test_an_unverified_deleted_answer_is_not_a_confirmed_leave() -> None:
    store = member_store(desired="leave")
    rig = Rig(store)
    rig.hub.bad_signature = True
    await rig.cycle()
    assert store.wiped == 0 and store.m.state == "leaving"
    assert store.m.last_error_code == "hub_signature"
    rig.hub.bad_signature = False
    await rig.cycle()
    assert store.wiped == 1 and rig.hub.deleted
