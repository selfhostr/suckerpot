"""The network worker (design M29 section 9.3). Off unless ``NETWORK_ENABLED=true`` (default off),
and idle until the node has joined (``network_membership.desired``: the dashboard, or a valid
``NETWORK_CONSENT`` from the installer). Nothing is sent otherwise (N1).

One cycle:

1. idle when there is nothing asked for;
2. ``desired = leave``: delete at the hub, wipe every local network row and the key (N8);
3. ``desired = member``: make the key, enrol (proof of work off the event loop);
4. member: sync a changed pseudonym/country, send due days, pull targets (6 hourly), answer
   reveals and rechecks, fetch the daily summary.

Every hub call goes through ``HubClient`` (egress gate, pinned key). A failure ends the cycle with
a protocol error code in ``last_error_code``; no value from the hub or the database is logged.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx
from suckerpot_db.network_names import pseudonym_problem, valid_country
from suckerpot_db.secretbox import SecretBox
from suckerpot_netproto import ProtoError, sign
from suckerpot_netproto import models as wire
from suckerpot_reporting import GuardContext, SelfTerms, guard

from ingest.egress import EgressClosed, EgressGate, gate_open
from ingest.features import FeatureSettings, FeatureWorker

from . import identity as ident
from . import participant, pseudonym, scheduler, sync, verify_reveal
from .builder import BatchBuilder, TermsSource, batch_counts
from .client import HubClient, HubError, HubNoVerify, HubUnavailable
from .config import NetworkSettings
from .powproc import solve_low_priority
from .store import Membership, Store
from .verifier import Verifier, VerifyStore

log = logging.getLogger(__name__)

PULL_EVERY = timedelta(hours=6)
SUMMARY_EVERY = timedelta(hours=24)
LEAVE_GIVE_UP = timedelta(days=7)
POW_CAP_S = 15 * 60
PERMANENT = frozenset({"pseudonym_taken", "pseudonym_invalid"})
# The hub may close enrolment or set a hard puzzle for a while: wait, never opt out.
TEMPORARY = frozenset({"enrolment_closed", "pow_timeout"})
BACKOFF_FIRST = timedelta(minutes=15)
BACKOFF_MAX = timedelta(hours=6)
WAITING_ENROLMENT = "waiting_enrolment"
FAST_INTERVAL_S = 60.0
VERIFY_REVEAL_EVERY = timedelta(minutes=15)
VERIFY_RETRY = timedelta(hours=24)
LEARN_EVERY = timedelta(hours=1)
NAME_RETRIES = 5


class NetworkWorker(FeatureWorker):
    name = "network"

    def __init__(
        self,
        features: FeatureSettings,
        network: NetworkSettings,
        store: Store | None,
        terms: TermsSource | None,
        builder: BatchBuilder | None,
        *,
        box: SecretBox | None = None,
        gate: EgressGate | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        rng: random.Random | None = None,
        allow_documentation: bool = False,
        verify_store: VerifyStore | None = None,
        learn: Callable[[], Awaitable[object]] | None = None,
    ) -> None:
        super().__init__(features, enabled=network.enabled)
        self.network = network
        self.store = store
        self.terms = terms
        self.builder = builder
        self.box = box
        self._gate = gate
        self._client = client
        self._clock = clock
        self._rng = rng
        self._allow_doc = allow_documentation  # test overlay, as in the builder
        self.interval_s = float(network.interval_s)
        self.state = "off"
        self.reason: str | None = None
        self._enrol_failures = 0
        self._enrol_retry_at: datetime | None = None
        # M32: participant mode, early reveals, verifier role, own-address learning.
        self.consent_state, self.consent = participant.parse(network.consent)
        self.verifier = (
            Verifier(network, verify_store, terms, gate=gate, clock=clock)
            if verify_store is not None
            else None
        )
        self._learn = learn
        self._last_learn: datetime | None = None
        self._last_vreveal: datetime | None = None
        self._vreveal_retry_at: datetime | None = None
        self._name_tries = 0
        self._consent_reason: str | None = None  # why participant mode did not join
        self.revealed: dict[str, int] = {}  # UTC day -> links revealed for verification

    # -- status -----------------------------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        return {
            self.name: {
                "enabled": self.enabled,
                "hub_configured": self.network.hub_configured,
                "state": self.state,
                "reason": self.reason,
                "cycles": self.cycles,
                "last_error": self.last_error,
                "mode": self.network.stack_mode,
                "consent": self.consent_state,
                "verify_reveals": verify_reveal.enabled(self.network, self.consent),
                "revealed": dict(sorted(self.revealed.items())[-8:]),
                "verifier": self.verifier.state if self.verifier is not None else "off",
            }
        }

    # -- loop -------------------------------------------------------------------------------

    async def run(self, publish: Any = None) -> None:
        """Disabled in .env: no hub contact ever, but a pending 'leave' still wipes locally."""
        if self.enabled or self.store is None:
            await super().run(publish)
            return
        while True:
            try:
                m = await self.store.membership()
                if m.desired == "leave" or m.state == "leaving":
                    await self.store.wipe(leave_error="leave_unconfirmed")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("network local leave failed (%s)", type(exc).__name__)
            await asyncio.sleep(self.network.interval_s)

    async def run_once(self) -> None:
        store = self.store
        if store is not None:
            await self._learn_self_address()
        if store is None or not self.network.hub_configured:
            self.state, self.reason = "off", "no_hub" if store is not None else None
            return
        m = await store.membership()
        m = await self._auto_join(m)  # participant and full mode alike (M33)
        self.state = m.state
        pending = m.desired == "leave" or (m.desired == "member" and m.state != "member")
        self.interval_s = FAST_INTERVAL_S if pending else float(self.network.interval_s)
        if m.desired == "off" and m.state in ("off", "error"):
            self.reason = self._consent_reason
            return
        try:
            if m.desired == "leave" or m.state == "leaving":
                await self._leave(m)
            elif m.state != "member":
                if self._enrol_retry_at is not None and self._now() < self._enrol_retry_at:
                    self.reason = WAITING_ENROLMENT  # still backing off: no call
                    return
                await self._enrol(m)
            else:
                await self._maintain(m)
        except EgressClosed:
            await self._note(m, "egress_closed")
        except HubError as exc:
            await self._note(m, exc.code if exc.code != "server_error" else "hub_error")
        except HubUnavailable:
            await self._note(m, "hub_unreachable")
        except ProtoError as exc:
            await self._note(m, exc.code)

    async def _learn_self_address(self) -> None:
        """Participant mode has no abuse worker: learn the own address from traffic here."""
        if self._learn is None or not self.network.participant:
            return
        now = self._now()
        if self._last_learn is not None and now - self._last_learn < LEARN_EVERY:
            return
        self._last_learn = now
        try:
            await self._learn()
        except Exception as exc:
            log.warning("self address learning failed (%s)", type(exc).__name__)

    async def _auto_join(self, m: Membership) -> Membership:
        """Request membership from the installer's consent record (N1', M33): once, never re-joins.

        Full mode does this too; its traffic still only leaves through the VPN gate."""
        store = self.store
        assert store is not None  # noqa: S101
        self._consent_reason = None
        if m.desired != "off" or m.state != "off" or m.left_day is not None:
            return m
        if self.consent is None:
            self._consent_reason = (
                self.consent_state if self.consent_state != participant.MISSING else None
            )
            return m
        if not participant.is_fresh(self.consent, self._now().date()):
            self._consent_reason = participant.STALE
            return m
        country = self.network.country if valid_country(self.network.country) else None
        await store.update(
            desired="member",
            pseudonym=self.network.pseudonym or None,
            country=country,
            show_country=self.network.show_country and country is not None,
            requested_by="installer",
            requested_at=self._now(),
            last_error_code=None,
        )
        return await store.membership()

    async def _retry_name(self, m: Membership) -> bool:
        """A generated pseudonym that is taken is replaced (up to 5 times); a chosen one stops."""
        store = self.store
        assert store is not None  # noqa: S101
        if (
            m.requested_by != "installer"
            or not pseudonym.is_generated(m.pseudonym)
            or self._name_tries >= NAME_RETRIES
        ):
            return False
        name = await pseudonym.fresh(self._pseudonym_ok, self._rng)
        if name is None:
            return False
        self._name_tries += 1
        await store.update(pseudonym=name, last_error_code=None)
        self.state, self.reason = "enrolling", "pseudonym_retry"
        return True

    async def _note(self, m: Membership, code: str) -> None:
        self.reason = code
        if m.last_error_code != code:
            assert self.store is not None  # noqa: S101
            await self.store.update(last_error_code=code)

    # -- helpers ----------------------------------------------------------------------------

    def _now(self) -> datetime:
        return self._clock()

    def _hub(self, identity: ident.Identity | None) -> HubClient:
        return HubClient(
            self.network, identity, gate=self._gate, client=self._client,
            clock=lambda: self._now().timestamp(),
        )  # fmt: skip

    def _identity(self, m: Membership) -> ident.Identity:
        if m.privkey_enc is None or m.privkey_nonce is None or m.pubkey is None:
            raise ident.NoSettingsKey
        return ident.unseal(self.box, m.privkey_enc, m.privkey_nonce, m.pubkey)

    async def _pseudonym_ok(self, name: str | None) -> bool:
        """Local shape rules, then the identity guard (an owner name or domain is refused)."""
        if name is None:
            return True
        if pseudonym_problem(name) is not None:
            return False
        terms: SelfTerms | None = await self.terms.get() if self.terms is not None else None
        if terms is None:
            return False
        result = guard(
            name, terms, fmt="text", ctx=GuardContext(allow_documentation=self._allow_doc)
        )
        return set(result.codes) <= {"no_self_address"}

    # -- leave ------------------------------------------------------------------------------

    async def _leave(self, m: Membership) -> None:
        store = self.store
        assert store is not None  # noqa: S101
        now = self._now()
        if m.state != "leaving" or m.leave_requested_at is None:
            await store.update(state="leaving", leave_requested_at=m.leave_requested_at or now)
            m.leave_requested_at = m.leave_requested_at or now
        if m.pubkey is None or m.privkey_enc is None:
            await store.wipe()  # no key was ever made: nothing at the hub
            self.state = "off"
            return
        # Whenever a key exists a signed DELETE goes out, even if the enrolment answer was lost
        # (no node id): a signed unknown_node means the hub holds nothing of ours.
        try:
            identity = self._identity(m)
            await self._hub(identity).delete_node()
        except HubError as exc:
            if exc.code != "unknown_node":
                if now - m.leave_requested_at > LEAVE_GIVE_UP:
                    await store.wipe(leave_error="leave_unconfirmed")
                    self.state = "off"
                    return
                raise
        except ident.NoSettingsKey:
            await store.wipe(leave_error="leave_unconfirmed")  # the key is gone: cannot sign
            self.state = "off"
            return
        except EgressClosed, HubUnavailable, ProtoError:
            if now - m.leave_requested_at > LEAVE_GIVE_UP:
                await store.wipe(leave_error="leave_unconfirmed")
                self.state = "off"
                return
            raise
        await store.wipe()
        self.state, self.reason = "off", None

    # -- enrol ------------------------------------------------------------------------------

    async def _enrol(self, m: Membership) -> None:
        store = self.store
        assert store is not None  # noqa: S101
        if not gate_open(self._gate, host=self.network.hub_host):
            raise EgressClosed("egress_closed")
        if m.privkey_enc is None:
            try:
                identity = ident.generate()
                ciphertext, nonce = ident.seal(identity, self.box)
            except ident.NoSettingsKey:
                await store.update(state="error", last_error_code="no_settings_key")
                self.state, self.reason = "error", "no_settings_key"
                return
            await store.update(
                state="enrolling", pubkey=identity.public, fingerprint=identity.fingerprint,
                privkey_enc=ciphertext, privkey_nonce=nonce, last_error_code=None,
            )  # fmt: skip
        else:
            try:
                identity = self._identity(m)
            except ident.NoSettingsKey:
                await store.update(state="error", last_error_code="no_settings_key")
                self.state, self.reason = "error", "no_settings_key"
                return
        if not await self._pseudonym_ok(m.pseudonym):
            await store.update(state="error", desired="off", last_error_code="pseudonym_invalid")
            self.state, self.reason = "error", "pseudonym_invalid"
            return
        hub = self._hub(identity)
        try:
            info = await hub.info()
            if "spn/1" not in info.protocols or not sign.key_in_set(
                self.network.hub_keys, info.hub_key
            ):
                await store.update(state="error", last_error_code="unsupported_protocol")
                self.state, self.reason = "error", "unsupported_protocol"
                return
            ch = await hub.challenge(identity)
            nonce_raw = await solve_low_priority(
                sign.b64u_decode(ch.challenge), identity.public, ch.difficulty, POW_CAP_S
            )
            if nonce_raw is None:
                await self._enrol_wait(store)
                return
            done = await hub.enrol(
                identity,
                challenge=ch.challenge,
                pow_nonce=sign.b64u_encode(nonce_raw),
                pseudonym=m.pseudonym,
                country=m.country,
                show_country=m.show_country,
            )
        except HubError as exc:
            if exc.code == "pseudonym_taken" and await self._retry_name(m):
                return
            if exc.code in PERMANENT:
                await store.update(state="error", desired="off", last_error_code=exc.code)
                self.state, self.reason = "error", exc.code
                return
            if exc.code in TEMPORARY:
                await self._enrol_wait(store)
                return
            raise
        self._enrol_failures, self._enrol_retry_at = 0, None
        await store.update(
            state="member",
            node_id=done.node_id,
            fingerprint=done.fingerprint,
            enrolled_day=date.fromisoformat(done.enrolled_day),
            eligible_from_day=date.fromisoformat(done.eligible_from_day),
            synced_pseudonym=m.pseudonym,
            synced_country=m.country,
            synced_show_country=m.show_country,
            next_submit_at=scheduler.next_submit_at(
                self._now(), self.network.delay_min_h, self.network.delay_max_h, self._rng
            ),
            standing="new",
            last_error_code=None,
        )
        self.state, self.reason = "member", None

    async def _enrol_wait(self, store: Store) -> None:
        """Enrolment is temporarily out of reach: stay a member-to-be, retry with backoff."""
        delay = min(BACKOFF_FIRST * 2**self._enrol_failures, BACKOFF_MAX)
        self._enrol_failures = min(self._enrol_failures + 1, 10)
        self._enrol_retry_at = self._now() + delay
        await store.update(state="enrolling", last_error_code=WAITING_ENROLMENT)
        self.state, self.reason = "enrolling", WAITING_ENROLMENT

    # -- member -----------------------------------------------------------------------------

    async def _maintain(self, m: Membership) -> None:
        store = self.store
        assert store is not None  # noqa: S101
        identity = self._identity(m)
        hub = self._hub(identity)
        now = self._now()
        errors: list[str] = []
        await self._sync_profile(m, hub)
        await self._submit(m, hub, errors)
        if m.last_pull_at is None or now - m.last_pull_at >= PULL_EVERY:
            await self._pull(m, hub)
        if m.last_summary_at is None or now - m.last_summary_at >= SUMMARY_EVERY:
            summary = await hub.network()
            await store.save_summary(sync.summary_json(summary))
            node = await hub.node()
            await store.update(standing=node.standing, last_summary_at=now)
        await self._verification(hub, errors)
        if errors:
            await self._note(m, errors[0])
        elif m.last_error_code is not None:
            await store.update(last_error_code=None)
            self.reason = None

    async def _verification(self, hub: HubClient, errors: list[str]) -> None:
        """Early reveals (N17) and the verifier role (N18). A pre-M32 hub is asked once a day."""
        now = self._now()
        if verify_reveal.enabled(self.network, self.consent) and (
            self._last_vreveal is None or now - self._last_vreveal >= VERIFY_REVEAL_EVERY
        ):
            if self._vreveal_retry_at is None or now >= self._vreveal_retry_at:
                self._last_vreveal = now
                terms = await self.terms.get() if self.terms is not None else None
                store = self.store
                assert store is not None  # noqa: S101
                try:
                    await verify_reveal.answer(
                        hub, store, terms, self.network, self.consent,
                        allow_documentation=self._allow_doc, on_sent=self._count_reveals,
                    )  # fmt: skip
                except HubNoVerify:
                    self._vreveal_retry_at = now + VERIFY_RETRY
        if self.verifier is not None:
            await self.verifier.cycle(hub)

    def _count_reveals(self, n: int) -> None:
        day = self._now().date().isoformat()
        self.revealed[day] = self.revealed.get(day, 0) + n
        for old in sorted(self.revealed)[:-14]:
            del self.revealed[old]

    async def _sync_profile(self, m: Membership, hub: HubClient) -> None:
        store = self.store
        assert store is not None  # noqa: S101
        if (m.pseudonym, m.country, m.show_country) == (
            m.synced_pseudonym, m.synced_country, m.synced_show_country,
        ):  # fmt: skip
            return
        if not await self._pseudonym_ok(m.pseudonym):
            await store.update(
                pseudonym=m.synced_pseudonym, country=m.synced_country,
                show_country=bool(m.synced_show_country), last_error_code="pseudonym_invalid",
            )  # fmt: skip
            return
        try:
            await hub.patch_node(
                pseudonym=m.pseudonym, country=m.country, show_country=m.show_country
            )
        except HubError as exc:
            if exc.code not in PERMANENT:
                raise
            await store.update(
                pseudonym=m.synced_pseudonym, country=m.synced_country,
                show_country=bool(m.synced_show_country), last_error_code=exc.code,
            )  # fmt: skip
            return
        await store.update(
            synced_pseudonym=m.pseudonym, synced_country=m.country,
            synced_show_country=m.show_country,
        )  # fmt: skip

    async def _submit(self, m: Membership, hub: HubClient, errors: list[str]) -> None:
        store = self.store
        builder = self.builder
        assert store is not None and builder is not None  # noqa: S101
        now = self._now()
        days = scheduler.due_days(
            now, m.next_submit_at, await store.submitted_days(), since=m.enrolled_day
        )
        if not days:
            if m.next_submit_at is not None and now >= m.next_submit_at:
                # Everything due is already in: draw the next random release time.
                await store.update(
                    next_submit_at=scheduler.next_submit_at(
                        now, self.network.delay_min_h, self.network.delay_max_h, self._rng
                    )
                )
            return
        blocked = False
        for day in days:
            existing = await store.submission(day)
            if (
                existing
                and existing["payload"]
                and existing["status"] == "failed"
                and (existing["error_code"] in ("pending", "hub_unreachable"))
            ):
                batch: dict[str, Any] = existing["payload"]  # resend the same batch id
                counts: dict[str, int] = {}
                dropped: dict[str, int] = {}
                # The stored body goes through today's guard and wire models first: the owner
                # terms may have changed since it was built.
                verdict = await self._recheck_stored(batch)
                if verdict != "ok":
                    if verdict == "guard_failed":
                        await store.record_submission(
                            day, batch_id="-", status="failed", counts={}, dropped={},
                            error_code="guard_failed", payload=None, sent_at=None,
                        )  # fmt: skip
                        await store.drop_payload(day)
                    errors.append(verdict)
                    blocked = True
                    break
            else:
                built = await builder.build(day)
                if built.status != "ok" or built.batch is None:
                    code = (
                        "waiting_self_address"
                        if built.status == "waiting_self_address"
                        else (
                            "guard_failed"
                            if built.status == "guard_failed"
                            else "self_terms_unavailable"
                        )
                    )
                    if built.status == "guard_failed":
                        await store.record_submission(
                            day, batch_id="-", status="failed", counts=built.counts,
                            dropped=built.dropped, error_code="guard_failed", payload=None,
                            sent_at=None,
                        )  # fmt: skip
                    errors.append(code)
                    blocked = True
                    break
                batch, counts, dropped = built.batch, built.counts, built.dropped
                await store.record_submission(
                    day, batch_id=batch["batch_id"], status="failed", counts=counts,
                    dropped=dropped, error_code="pending", payload=batch, sent_at=None,
                )  # fmt: skip
            try:
                answer = await hub.observations(batch)
            except HubError as exc:
                if exc.code in ("day_not_closed", "day_too_old"):
                    await store.record_submission(
                        day, batch_id=batch["batch_id"], status="skipped", counts={},
                        dropped=dropped, error_code=exc.code, payload=None, sent_at=None,
                    )  # fmt: skip
                    continue
                if exc.code == "invalid_payload":
                    await store.record_submission(
                        day, batch_id=batch["batch_id"], status="failed", counts=counts,
                        dropped=dropped, error_code="invalid_payload", payload=None, sent_at=None,
                    )  # fmt: skip
                    errors.append("invalid_payload")
                    blocked = True
                    break
                raise
            except HubUnavailable:
                await store.record_submission(
                    day, batch_id=batch["batch_id"], status="failed", counts=counts,
                    dropped=dropped, error_code="hub_unreachable", payload=None, sent_at=None,
                )  # fmt: skip
                raise
            # A duplicate answer carries zeros (the hub already held the batch): record what
            # was sent instead. Otherwise the hub's numbers are the truth (it may reject items).
            sent_counts = (
                batch_counts(batch)
                if answer.duplicate
                else {k: int(v) for k, v in answer.accepted.items()}
            )
            await store.record_submission(
                day, batch_id=batch["batch_id"], status="sent",
                counts=sent_counts, dropped=dropped,
                error_code=None, payload=None, sent_at=self._now(),
            )  # fmt: skip
            await store.update(last_submit_day=day)
        if not blocked:
            await store.update(
                next_submit_at=scheduler.next_submit_at(
                    now, self.network.delay_min_h, self.network.delay_max_h, self._rng
                )
            )

    async def _recheck_stored(self, batch: dict[str, Any]) -> str:
        """``ok``, or the error code that stops a stored batch from being resent."""
        terms = await self.terms.get() if self.terms is not None else None
        if terms is None:
            return "self_terms_unavailable"
        if not terms.has_self_address:
            return "waiting_self_address"
        ctx = GuardContext(allow_documentation=self._allow_doc)
        if not set(guard(batch, terms, fmt="json", ctx=ctx).codes) <= {"no_self_address"}:
            return "guard_failed"
        try:
            wire.ObservationBatch.model_validate(
                batch, context={"allow_documentation": self._allow_doc}
            )
        except Exception:  # a malformed stored batch is never sent
            return "guard_failed"
        return "ok"

    async def _pull(self, m: Membership, hub: HubClient) -> None:
        store = self.store
        assert store is not None  # noqa: S101
        got = await sync.pull(hub, store, m.pull_cursor)
        await sync.mark_mine(store, got.blinded)
        terms = await self.terms.get() if self.terms is not None else None
        await sync.answer_reveals(
            hub, store, got.reveal, terms, allow_documentation=self._allow_doc
        )
        await sync.answer_rechecks(hub, got.recheck, self._now().date())
        await store.update(pull_cursor=got.cursor, last_pull_at=self._now())
