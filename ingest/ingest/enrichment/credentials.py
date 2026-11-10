"""Provider credentials set from the Settings page, hot-swapped into the running workers.

Every ``interval_s`` (and once at start) this reads ``provider_secrets``, decrypts the rows with
``SETTINGS_ENCRYPTION_KEY`` and builds the effective ``EnrichmentSettings``: a value set in
Settings overrides the same value from ``.env``. Workers are told which providers changed, so a
new key takes effect without a restart. It also answers "Test key" requests (the API has no
internet access, so ingest makes the one real call and records the outcome).

Nothing here logs or raises a key: decrypt failures are reported by provider name only.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, cast

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db import ProviderSecretRow, ProviderTestRequestRow
from suckerpot_db.secretbox import PROVIDERS, SecretBox, SecretError

from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate, make_client
from ingest.enrichment.config import EnrichmentSettings
from ingest.enrichment.reputation import HTTP_TIMEOUT, reserve_quota

log = logging.getLogger(__name__)

SYNC_INTERVAL_S = 30.0
MAXMIND_TEST_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download"
MAXMIND_TEST_QUOTA = 30  # MaxMind allows 30 GeoLite2 downloads a day per account


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    source: str | None  # "env" | "settings" | None (no key anywhere)
    error: str | None = None  # "cannot_decrypt" | "no_encryption_key"


# Providers with a single key, and the EnrichmentSettings field that holds it.
KEY_FIELDS = {
    "abuseipdb": "abuseipdb_api_key",
    "greynoise": "greynoise_api_key",
    "nvd": "nvd_api_key",
    "github": "github_token",
    "abusech": "abusech_auth_key",
    "virustotal": "virustotal_api_key",
    "smtp": "smtp_password",
}


def _env_has(base: EnrichmentSettings, provider: str) -> bool:
    field = KEY_FIELDS.get(provider)
    if field is not None:
        return bool(getattr(base, field))
    return provider == "maxmind" and base.maxmind_enabled


def changed_providers(old: EnrichmentSettings, new: EnrichmentSettings) -> set[str]:
    out: set[str] = {
        provider
        for provider, field in KEY_FIELDS.items()
        if getattr(old, field) != getattr(new, field)
    }
    if (old.maxmind_account_id, old.maxmind_license_key) != (
        new.maxmind_account_id,
        new.maxmind_license_key,
    ):
        out.add("maxmind")
    return out


class CredentialSync:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        base: EnrichmentSettings,
        box: SecretBox | None,
        *,
        on_change: Callable[[EnrichmentSettings, set[str]], None],
        run_test: Callable[[str], Awaitable[None]] | None = None,
        on_synced: Callable[[], Awaitable[None]] | None = None,
        client: httpx.AsyncClient | None = None,
        interval_s: float = SYNC_INTERVAL_S,
        gate: EgressGate | None = None,
    ) -> None:
        self._gate = gate or get_gate()
        self.factory = factory
        self.base = base
        self.box = box
        self.current = base
        self.on_change = on_change
        self.run_test = run_test
        self.on_synced = on_synced
        self.client = client or make_client(HTTP_TIMEOUT, gate=self._gate)
        self.interval_s = interval_s
        self.info: dict[str, ProviderInfo] = {
            p: ProviderInfo("env" if _env_has(base, p) else None) for p in PROVIDERS
        }
        self.maxmind_test: dict[str, Any] | None = None

    # ---- reading the stored keys --------------------------------------------------------------
    def effective(self, rows: dict[str, ProviderSecretRow]) -> EnrichmentSettings:
        eff = self.base
        info: dict[str, ProviderInfo] = {}
        for provider in PROVIDERS:
            env_source = "env" if _env_has(self.base, provider) else None
            row = rows.get(provider)
            if row is None:
                info[provider] = ProviderInfo(env_source)
            elif self.box is None:
                info[provider] = ProviderInfo(env_source, "no_encryption_key")
            else:
                try:
                    cred = self.box.decrypt(provider, row.ciphertext, row.nonce)
                except SecretError:
                    info[provider] = ProviderInfo(env_source, "cannot_decrypt")
                    continue
                info[provider] = ProviderInfo("settings")
                if provider in KEY_FIELDS:
                    eff = replace(eff, **cast(dict[str, Any], {KEY_FIELDS[provider]: cred.key}))
                elif provider == "maxmind":
                    eff = replace(
                        eff, maxmind_account_id=cred.account_id or "", maxmind_license_key=cred.key
                    )
        self.info = info
        return eff

    async def _rows(self) -> dict[str, ProviderSecretRow]:
        async with self.factory() as session:
            return {r.provider: r for r in await session.scalars(select(ProviderSecretRow))}

    async def sync_once(self) -> set[str]:
        """Apply the stored keys and answer pending tests. Returns the providers that changed."""
        eff = self.effective(await self._rows())
        changed = changed_providers(self.current, eff)
        if changed:
            self.current = eff
            self.on_change(eff, changed)
            if "maxmind" in changed:
                self.maxmind_test = None
            log.info("provider credentials updated: %s", ", ".join(sorted(changed)))
        tested = await self._answer_tests()
        if (changed or tested) and self.on_synced is not None:
            await self.on_synced()
        return changed

    # ---- "Test key" requests ------------------------------------------------------------------
    async def _pending_tests(self) -> list[ProviderTestRequestRow]:
        async with self.factory() as session:
            rows = await session.scalars(
                select(ProviderTestRequestRow).where(
                    (ProviderTestRequestRow.handled_at.is_(None))
                    | (ProviderTestRequestRow.handled_at < ProviderTestRequestRow.requested_at)
                )
            )
            return list(rows)

    async def _mark_handled(self, req: ProviderTestRequestRow) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE provider_test_requests SET handled_at = now() "
                    "WHERE provider = :p AND requested_at = :t"
                ),
                {"p": req.provider, "t": req.requested_at},
            )

    async def _answer_tests(self) -> bool:
        done = False
        for req in await self._pending_tests():
            if req.provider not in PROVIDERS or self.run_test is None:
                continue
            await self._mark_handled(req)  # at most once: a test spends quota
            await self.run_test(req.provider)
            done = True
        return done

    async def test_maxmind(self) -> dict[str, Any]:
        """One authenticated request to the checksum file of a GeoLite2 database."""
        error: str | None = None
        if not self.current.maxmind_enabled:
            error = "no_key"
        elif not gate_open(self._gate):
            error = "egress_closed"  # nothing is sent and no quota is spent
        elif not await reserve_quota(self.factory, "maxmind", MAXMIND_TEST_QUOTA):
            error = "quota_exhausted"
        else:
            cur = self.current
            auth = httpx.BasicAuth(cur.maxmind_account_id, cur.maxmind_license_key)
            try:
                resp = await self.client.get(
                    MAXMIND_TEST_URL,
                    params={"suffix": "tar.gz.sha256"},
                    auth=auth,
                    follow_redirects=False,
                )
                if resp.status_code in (401, 403):
                    error = "auth"
                elif resp.status_code == 429:
                    error = "rate_limited"
                elif resp.status_code != 200 and not 300 <= resp.status_code < 400:
                    # A valid key is answered with a redirect to the file store: not followed
                    # (that would download the database), and proof enough that the key works.
                    error = "error"
            except EgressClosed:
                error = "egress_closed"
            except httpx.HTTPError:
                error = "error"
        self.maxmind_test = {
            "ok": error is None,
            "error": error,
            "checked_at": datetime.now(UTC).isoformat(),
        }
        return self.maxmind_test

    # ---- status for the API (no secrets) --------------------------------------------------------
    def status(self, provider: str) -> dict[str, Any]:
        info = self.info[provider]
        out: dict[str, Any] = {
            "source": info.source,
            "secret_error": info.error,
            "env_configured": _env_has(self.base, provider),
        }
        if provider == "maxmind":
            out["configured"] = self.current.maxmind_enabled
            out["test"] = self.maxmind_test
        return out

    async def run(self) -> None:
        while True:
            try:
                await self.sync_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never include the message: it could carry a statement
                log.warning("provider credential sync failed (%s)", type(exc).__name__)
            await asyncio.sleep(self.interval_s)

    async def aclose(self) -> None:
        await self.client.aclose()
