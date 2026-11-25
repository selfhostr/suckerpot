/**
 * Enrichment API keys entered on the Settings page. Keys are write-only: they go to the API in
 * one request and are never kept in the browser, and nothing here ever reads one back.
 */
import { ApiError, sendJson } from "@/lib/api"
import { t } from "@/i18n"
import type { ProviderId } from "@/lib/settings"

export const PROVIDER_NAMES: Record<ProviderId, string> = {
  abuseipdb: "AbuseIPDB",
  get greynoise() {
    return t("providerkey_name_greynoise")
  },
  maxmind: "MaxMind GeoLite2",
  get nvd() {
    return t("providerkey_name_nvd")
  },
  get github() {
    return t("providerkey_name_github")
  },
  get abusech() {
    return t("providerkey_name_abusech")
  },
  virustotal: "VirusTotal",
}

export const MIN_KEY_LENGTH = 16
export const MAX_KEY_LENGTH = 128

export interface KeyInput {
  key: string
  accountId: string
}

export type KeyField = "key" | "accountId"

/** Same rules as the API (it checks again): printable ASCII, no spaces, 16 to 128 characters. */
export function validateKeyInput(
  provider: ProviderId,
  { key, accountId }: KeyInput,
): Partial<Record<KeyField, string>> {
  const errors: Partial<Record<KeyField, string>> = {}
  if (!key) errors.key = t("providerkey_error_required")
  else if (!/^[\x21-\x7e]+$/.test(key)) errors.key = t("providerkey_error_chars")
  else if (key.length < MIN_KEY_LENGTH || key.length > MAX_KEY_LENGTH)
    errors.key = t("providerkey_error_length", { min: MIN_KEY_LENGTH, max: MAX_KEY_LENGTH })
  if (provider === "maxmind" && !/^[0-9]{1,16}$/.test(accountId))
    errors.accountId = t("providerkey_error_account_id")
  return errors
}

export type KeyFailure =
  | "wrong-password"
  | "invalid-key"
  | "rate-limited"
  | "editing-disabled"
  | "origin"
  | "session"
  | "network"

export class KeyError extends Error {
  constructor(
    readonly reason: KeyFailure,
    /** The API's own sentence, shown for `invalid-key`. */
    readonly detail?: string,
  ) {
    super(reason)
    this.name = "KeyError"
  }
}

export const KEY_MESSAGES: Record<Exclude<KeyFailure, "invalid-key">, string> = {
  get "wrong-password"() {
    return t("providerkey_msg_wrong_password")
  },
  get "rate-limited"() {
    return t("providerkey_msg_rate_limited")
  },
  get "editing-disabled"() {
    return t("providerkey_msg_editing_disabled")
  },
  get origin() {
    return t("providerkey_msg_origin")
  },
  get session() {
    return t("providerkey_msg_session")
  },
  get network() {
    return t("providerkey_msg_network")
  },
}

/** Explains a failure in plain words; never repeats what was typed. */
export function describeKeyError(e: unknown): string {
  if (e instanceof KeyError) {
    if (e.detail) return e.detail
    if (e.reason !== "invalid-key") return KEY_MESSAGES[e.reason]
    return t("providerkey_msg_invalid")
  }
  return KEY_MESSAGES.network
}

function toKeyError(e: unknown): KeyError {
  if (e instanceof KeyError) return e
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return new KeyError("wrong-password")
    if (e.code === "invalid_key") return new KeyError("invalid-key", e.message)
    if (e.code === "editing_disabled") return new KeyError("editing-disabled")
    if (e.code === "origin") return new KeyError("origin")
    if (e.status === 429) return new KeyError("rate-limited")
    if (e.status === 401) return new KeyError("session")
  }
  return new KeyError("network")
}

const path = (provider: ProviderId) => `/settings/providers/${provider}`

/** Saves or replaces a key. `password` is the admin password (re-authentication). */
export async function setProviderKey(
  provider: ProviderId,
  input: KeyInput,
  password: string,
): Promise<void> {
  const body: Record<string, string> = { key: input.key, password }
  if (provider === "maxmind") body.account_id = input.accountId
  try {
    await sendJson("PUT", path(provider), body)
  } catch (e) {
    throw toKeyError(e)
  }
}

export async function removeProviderKey(provider: ProviderId, password: string): Promise<void> {
  try {
    await sendJson("DELETE", path(provider), { password })
  } catch (e) {
    throw toKeyError(e)
  }
}

/** Asks ingest to spend one quota call on the current key. The result shows up in the status. */
export async function requestKeyTest(provider: ProviderId): Promise<void> {
  try {
    await sendJson("POST", `${path(provider)}/test`, undefined)
  } catch (e) {
    if (e instanceof ApiError && e.code === "cooldown")
      throw new KeyError("rate-limited", t("providerkey_msg_cooldown"))
    if (e instanceof ApiError && e.code === "no_key")
      throw new KeyError("invalid-key", t("settings_test_no_key"))
    throw toKeyError(e)
  }
}
