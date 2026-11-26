/**
 * The SuckerPot network (M29, docs/dev/design/m29.md sections 7 and 9.6): shapes of the node API
 * under `/api/v1/network`, the plain-English sentences of the pages, the consent list and the
 * calls. The mocks in `src/mocks/network.ts` match these types exactly (a test checks it).
 *
 * Joining is strictly opt-in: nothing here ever joins by default, and every wording says what is
 * and what is not shared.
 */
import { ApiError, getJson, sendJson, type Page } from "./api"
import { intlLocale, t, tk } from "@/i18n"
import { countryName } from "./format"
import { UserError } from "./users"

// --- Shapes ------------------------------------------------------------------------

export type NetworkDesired = "off" | "member" | "leave"
export type NetworkState = "off" | "enrolling" | "member" | "leaving" | "error"
export type NetworkWaiting = "self_address" | "egress" | "settings_key" | "enrolment"
export type NetworkStanding = "new" | "good" | "low"

/** `GET /api/v1/network/status` (any signed-in user). Never 404. */
export interface NetworkStatus {
  /** `NETWORK_ENABLED` in .env. False: the page explains how to allow it. */
  enabled_env: boolean
  /** Whether a hub address and key are set. False: the network cannot be joined yet. */
  hub_configured: boolean
  desired: NetworkDesired
  state: NetworkState
  pseudonym: string | null
  country: string | null
  show_country: boolean
  /** First 8 hex characters of the node key hash, e.g. "3f9a1c07". */
  fingerprint: string | null
  enrolled_day: string | null
  eligible_from_day: string | null
  standing: NetworkStanding | null
  last_submit_day: string | null
  next_submit_at: string | null
  last_error_code: string | null
  waiting: NetworkWaiting | null
}

export interface NetworkTotals {
  members: number
  active_7d: number
  countries: number
  confirmed_30d: number
  reported_30d: number
  taken_down_30d: number
  median_days_to_takedown: number | null
}

export interface NetworkWeek {
  /** Monday of the week, YYYY-MM-DD (UTC). */
  week: string
  confirmed: number
  reported: number
  taken_down: number
}

export interface NetworkCountry {
  cc: string
  members: number
}

/** Tier 0 to 4 of distinct items submitted in the last full week (log scale). */
export type MemberTier = 0 | 1 | 2 | 3 | 4

export interface NetworkMember {
  fingerprint: string
  pseudonym: string | null
  /** Only when the member chose to show it and at least 3 members share it. */
  country: string | null
  /** YYYY-MM */
  member_since: string
  /** Days with a batch in the last full ISO week, 0 to 7. */
  active_days: number
  tier: MemberTier
}

/** `GET /api/v1/network/summary`: the hub's daily summary plus when this node fetched it. */
export interface NetworkSummary {
  generated_day: string
  totals: NetworkTotals
  weekly: NetworkWeek[]
  countries: NetworkCountry[]
  members: NetworkMember[]
  fetched_at: string
}

/** `GET /api/v1/network/impact`. */
export interface NetworkImpact {
  network: {
    confirmed_30d: number
    reported_30d: number
    taken_down_30d: number
    median_days_to_takedown: number | null
  }
  mine: { helped_confirm_30d: number; helped_takedown_30d: number }
}

export type TargetKind = "ip" | "url" | "domain" | "sha256" | "c2_ip" | "c2_domain"
export type TargetState = "confirmed" | "reported" | "taken_down" | "disputed" | "expired"

/** One row of `GET /api/v1/network/targets` (a row of `network_targets`). */
export interface NetworkTarget {
  hub_id: string
  kind: TargetKind
  /** Null for a blinded value the network has not revealed. */
  value: string | null
  value_b: string | null
  state: TargetState
  /** Bucket of sensors that saw it: 0 is 5 to 9, 1 is 10 to 24, 2 is 25 or more. */
  nodes: 0 | 1 | 2
  /** Number of countries, or null below 3. */
  countries: number | null
  first_day: string
  last_day: string
  services: string[]
  activity: string[]
  tags: string[]
  families: string[]
  reported_day: string | null
  taken_down_day: string | null
  /** This sensor contributed to it. */
  mine: boolean
}

export type SubmissionStatus = "sent" | "failed" | "skipped"

/** One row of `GET /api/v1/network/submissions`. */
export interface NetworkSubmission {
  day: string
  batch_id: string
  sent_at: string | null
  status: SubmissionStatus
  /** What the hub accepted, by list. */
  counts: Record<string, number>
  /** What this node left out, by reason (`guard`, `cap`, `self`). */
  dropped: Record<string, number>
  error_code: string | null
}

/** `GET /api/v1/network/submissions/{day}`: the row plus the exact JSON that was sent. */
export interface NetworkSubmissionDetail extends NetworkSubmission {
  payload: unknown
}

export interface TargetFilters {
  state?: string | undefined
  kind?: string | undefined
  mine?: boolean | undefined
  /** One hub target id (the "show this target" link of the table). */
  target?: string | undefined
}

export const networkKeys = {
  status: ["network", "status"] as const,
  summary: ["network", "summary"] as const,
  impact: ["network", "impact"] as const,
  targets: (f: TargetFilters) => ["network", "targets", f] as const,
  submissions: ["network", "submissions"] as const,
  submission: (day: string) => ["network", "submission", day] as const,
}

// --- The consent list ------------------------------------------------------------------

export type Consent = "sources" | "payloads" | "c2" | "files" | "rechecks"

export interface ConsentItem {
  id: Consent
  title: string
  /** What leaves this system, in plain words. */
  shared: string
}

/**
 * The five things a member agrees to, one checkbox each. The API wants all five in `accept`,
 * so that joining is never a single blind click.
 */
export const CONSENTS: readonly ConsentItem[] = [
  {
    id: "sources",
    get title() {
      return t("network_consent_sources_title")
    },
    get shared() {
      return t("network_consent_sources_shared")
    },
  },
  {
    id: "payloads",
    get title() {
      return t("network_consent_payloads_title")
    },
    get shared() {
      return t("network_consent_payloads_shared")
    },
  },
  {
    id: "c2",
    get title() {
      return t("network_consent_c2_title")
    },
    get shared() {
      return t("network_consent_c2_shared")
    },
  },
  {
    id: "files",
    get title() {
      return t("network_consent_files_title")
    },
    get shared() {
      return t("network_consent_files_shared")
    },
  },
  {
    id: "rechecks",
    get title() {
      return t("network_consent_rechecks_title")
    },
    get shared() {
      return t("network_consent_rechecks_shared")
    },
  },
]

export const ALL_CONSENTS: readonly Consent[] = CONSENTS.map((c) => c.id)

/** Things that never leave this system, whatever you accept. */
export function neverShared(): string[] {
  return [
    t("network_never_credentials"),
    t("network_never_commands"),
    t("network_never_ports"),
    t("network_never_scanners"),
    t("network_never_own_address"),
    t("network_never_private"),
    t("network_never_blocklist"),
  ]
}

/** What the network does with it, and what it keeps. */
export function networkFacts(): string[] {
  return [
    t("network_fact_delay"),
    t("network_fact_consensus"),
    t("network_fact_hub"),
    t("network_fact_leave"),
  ]
}

export function residualRisk(): string {
  return t("network_residual_risk")
}

export function benefitText(): string {
  return t("network_benefit")
}

// --- Sentences ------------------------------------------------------------------------

const dayFmt = () =>
  new Intl.DateTimeFormat(intlLocale(), { month: "short", day: "numeric", timeZone: "UTC" })
const dayYearFmt = () =>
  new Intl.DateTimeFormat(intlLocale(), {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  })
const monthFmt = () =>
  new Intl.DateTimeFormat(intlLocale(), { month: "short", year: "numeric", timeZone: "UTC" })

/** "15 Nov": a calendar day from the hub is a date, not a moment, so no time zone shift. */
export function formatDay(day: string | null | undefined, withYear = false): string {
  if (!day) return "–"
  const d = new Date(`${day}T00:00:00Z`)
  if (Number.isNaN(d.getTime())) return "–"
  return (withYear ? dayYearFmt() : dayFmt()).format(d)
}

/** "Sep 2026" from "2026-09". */
export function formatMonth(month: string): string {
  const d = new Date(`${month}-01T00:00:00Z`)
  return Number.isNaN(d.getTime()) ? month : monthFmt().format(d)
}

export const SENSORS_BUCKET: Record<0 | 1 | 2, string> = {
  get 0() {
    return t("network_sensors_bucket_0")
  },
  get 1() {
    return t("network_sensors_bucket_1")
  },
  get 2() {
    return t("network_sensors_bucket_2")
  },
}

export const TIER_LABEL: Record<MemberTier, string> = {
  get 0() {
    return t("network_tier_0")
  },
  get 1() {
    return t("network_tier_1")
  },
  get 2() {
    return t("network_tier_2")
  },
  get 3() {
    return t("network_tier_3")
  },
  get 4() {
    return t("network_tier_4")
  },
}

export const TARGET_KIND_LABEL: Record<TargetKind, string> = {
  get ip() {
    return t("network_target_kind_ip")
  },
  get url() {
    return t("network_target_kind_url")
  },
  get domain() {
    return t("network_target_kind_domain")
  },
  get sha256() {
    return t("network_target_kind_sha256")
  },
  get c2_ip() {
    return t("network_target_kind_c2_ip")
  },
  get c2_domain() {
    return t("network_target_kind_c2_domain")
  },
}

export const TARGET_STATE_LABEL: Record<TargetState, string> = {
  get confirmed() {
    return t("network_target_state_confirmed")
  },
  get reported() {
    return t("network_target_state_reported")
  },
  get taken_down() {
    return t("network_target_state_taken_down")
  },
  get disputed() {
    return t("network_target_state_disputed")
  },
  get expired() {
    return t("network_target_state_expired")
  },
}

export const STANDING_TEXT: Record<NetworkStanding, { label: string; sentence: string }> = {
  new: {
    get label() {
      return t("network_standing_new_label")
    },
    get sentence() {
      return t("network_standing_new_sentence")
    },
  },
  good: {
    get label() {
      return t("network_standing_good_label")
    },
    get sentence() {
      return t("network_standing_good_sentence")
    },
  },
  low: {
    get label() {
      return t("network_standing_low_label")
    },
    get sentence() {
      return t("network_standing_low_sentence")
    },
  },
}

const WAITING_TEXT: Record<NetworkWaiting, string> = {
  self_address: tk("network_waiting_self_address"),
  egress: tk("network_waiting_egress"),
  settings_key: tk("network_waiting_settings_key"),
  enrolment: tk("network_waiting_enrolment"),
}

export function waitingText(w: NetworkWaiting | null): string | null {
  return w ? t(WAITING_TEXT[w]) : null
}

const ERROR_TEXT: Record<string, string> = {
  guard_failed: tk("network_error_guard_failed"),
  hub_signature: tk("network_error_hub_signature"),
  leave_unconfirmed: tk("network_error_leave_unconfirmed"),
  membership_expired: tk("network_error_membership_expired"),
  no_settings_key: tk("network_error_no_settings_key"),
  egress_closed: tk("network_error_egress_closed"),
  rate_limited: tk("network_error_rate_limited"),
  enrolment_closed: tk("network_error_enrolment_closed"),
}

export function describeNetworkError(code: string | null): string | null {
  if (!code) return null
  const key = ERROR_TEXT[code]
  return key ? t(key) : t("network_error_failed", { code })
}

/** Is this system a member whose figures can be shown? */
export function isMember(s: NetworkStatus | undefined): boolean {
  return !!s && s.state === "member"
}

/** The one sentence at the top of the Overview, whatever the state. */
export function describeStatus(s: NetworkStatus, impact?: NetworkImpact): string {
  if (!s.enabled_env) return t("network_status_env_off")
  if (!s.hub_configured) return t("network_status_no_hub")
  switch (s.state) {
    case "off":
      return t("network_status_off")
    case "enrolling":
      return t("network_status_enrolling")
    case "leaving":
      return t("network_status_leaving")
    case "error":
      return t("network_status_error")
    case "member":
      return impact ? impactFinding(impact) : t("network_status_member")
  }
}

/** "The network took down 141 malware hosts and attack sources in the last 30 days. …" */
export function impactFinding(i: NetworkImpact): string {
  const down = i.network.taken_down_30d
  const mine = i.mine.helped_confirm_30d
  const head = down > 0 ? t("network_impact_down", { count: down }) : t("network_impact_down_none")
  const tail =
    mine > 0
      ? t("network_impact_mine", { mine, confirmed: i.network.confirmed_30d })
      : t("network_impact_mine_none")
  return `${head} ${tail}`
}

/** Before the network can confirm anything it needs five active members. */
export const MIN_ACTIVE_MEMBERS = 5

export function bootstrapSentence(totals: NetworkTotals): string | null {
  if (totals.active_7d >= MIN_ACTIVE_MEMBERS) return null
  return t("network_bootstrap", { min: MIN_ACTIVE_MEMBERS, count: totals.active_7d })
}

/** The takedowns of the latest week against the week before. */
export function weeklyFinding(weekly: readonly NetworkWeek[]): string {
  const last = weekly[weekly.length - 1]
  if (!last) return t("network_weekly_none")
  const prev = weekly[weekly.length - 2]
  if (!prev) return t("network_weekly_latest", { count: last.taken_down })
  if (last.taken_down === prev.taken_down)
    return t("network_weekly_same", { count: last.taken_down })
  return t("network_weekly_change", {
    count: last.taken_down,
    dir: last.taken_down > prev.taken_down ? "up" : "down",
    prev: prev.taken_down,
  })
}

export function membersFinding(totals: NetworkTotals): string {
  return t("network_members_finding", {
    members: totals.members,
    countries: totals.countries,
    active: totals.active_7d,
  })
}

/** "Counts toward consensus from 15 Nov", or since when. */
export function eligibilityText(s: NetworkStatus, today: string = isoDay(new Date())): string {
  if (!s.eligible_from_day) return t("network_eligibility_unknown")
  return s.eligible_from_day > today
    ? t("network_eligibility_from", { date: formatDay(s.eligible_from_day) })
    : t("network_eligibility_now")
}

export function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10)
}

/** Name shown for a member: the pseudonym, or "Node 3f9a1c07". */
export function memberName(m: { pseudonym: string | null; fingerprint: string }): string {
  return m.pseudonym ?? t("network_member_node", { fingerprint: m.fingerprint })
}

/** What a target is, shown: the value, or a short scrambled form while it is unrevealed. */
export function targetLabel(tg: NetworkTarget): string {
  if (tg.value) return tg.value
  return tg.value_b
    ? t("network_target_scrambled", {
        kind: tg.kind === "domain" ? "domain" : "link",
        id: tg.value_b.slice(0, 10),
      })
    : t("common_unknown")
}

/** Link-like values are shown defanged, as text: they are never clickable. */
export function defangValue(v: string): string {
  return v.replace(/^http/i, (m) => (m === m.toUpperCase() ? "HXXP" : "hxxp")).replace(/\./g, "[.]")
}

/** Sentence above the targets list, from the filters in the URL. */
export function targetsFinding(f: { state: string; kind: string; mine: boolean }): string {
  const values = { kind: f.kind, state: f.state, mine: f.mine ? "yes" : "no" }
  return f.state === "all"
    ? t("network_targets_finding_all", values)
    : t("network_targets_finding_latest", values)
}

/** Days from the first sighting to the takedown, or null. */
export function daysToTakedown(tg: NetworkTarget): number | null {
  if (!tg.taken_down_day) return null
  const a = Date.parse(`${tg.first_day}T00:00:00Z`)
  const b = Date.parse(`${tg.taken_down_day}T00:00:00Z`)
  return Number.isNaN(a) || Number.isNaN(b) ? null : Math.max(0, Math.round((b - a) / 86_400_000))
}

// --- Pseudonym ------------------------------------------------------------------------

export const PSEUDONYM_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 _.-]{1,22}[A-Za-z0-9]$/
const RESERVED = new Set([
  "admin",
  "administrator",
  "hub",
  "official",
  "moderator",
  "selfhostr",
  "suckerpot",
])

/** The same rules as the server (docs/dev/design/m29.md 9.7). Empty is fine: it stays anonymous. */
export function validatePseudonym(raw: string): string | null {
  const v = raw.trim()
  if (v === "") return null
  if (v.length < 3 || v.length > 24) return t("network_pseudonym_length")
  if (v.includes("://") || v.includes("@")) return t("network_pseudonym_link")
  if (/\d{4,}/.test(v)) return t("network_pseudonym_digits")
  if (!PSEUDONYM_PATTERN.test(v)) return t("network_pseudonym_chars")
  if (RESERVED.has(v.toLowerCase())) return t("network_pseudonym_reserved")
  return null
}

/** Two-letter codes the country list offers. Never guessed from the network. */
const COUNTRY_CODES =
  "AD AE AL AM AR AT AU AZ BA BD BE BG BH BR BY CA CH CL CN CO CR CY CZ DE DK DO DZ EC EE EG ES FI FR GB GE GR HK HR HU ID IE IL IN IQ IR IS IT JO JP KE KR KW KZ LB LI LK LT LU LV MA MD ME MK MT MX MY NG NL NO NP NZ OM PA PE PH PK PL PT QA RO RS RU SA SE SG SI SK TH TN TR TW UA US UY UZ VN ZA".split(
    " ",
  )

export function countryOptions(): { code: string; name: string }[] {
  return COUNTRY_CODES.map((code) => ({ code, name: countryName(code) ?? code })).sort((a, b) =>
    a.name.localeCompare(b.name),
  )
}

// --- Errors ---------------------------------------------------------------------------

export const NETWORK_MESSAGES = {
  get consent() {
    return t("network_message_consent")
  },
  get taken() {
    return t("network_message_taken")
  },
  get pseudonym() {
    return t("network_message_pseudonym")
  },
  get closed() {
    return t("network_message_closed")
  },
  get unavailable() {
    return t("network_message_unavailable")
  },
  get forbidden() {
    return t("network_message_forbidden")
  },
  get already() {
    return t("network_message_already")
  },
  get notMember() {
    return t("network_message_not_member")
  },
  get generic() {
    return t("network_message_generic")
  },
} as const

function reasonOf(e: ApiError): string | undefined {
  if (e.code) return e.code
  const error = e.body?.error
  if (typeof error === "string") return error
  const detail = e.body?.detail
  return typeof detail === "string" ? detail : e.message
}

/** Maps an API failure to the UserError the shared password dialog shows. */
export function toNetworkError(e: unknown): UserError {
  if (e instanceof UserError) return e
  if (!(e instanceof ApiError)) return new UserError("network")
  const reason = reasonOf(e)
  if (reason === "reauth_failed") return new UserError("wrong-password")
  if (e.status === 401) return new UserError("session")
  if (e.status === 429) return new UserError("rate-limited")
  if (reason === "pseudonym_taken") return new UserError("taken", NETWORK_MESSAGES.taken)
  if (reason === "pseudonym_invalid" || reason === "identity_guard")
    return new UserError("invalid", NETWORK_MESSAGES.pseudonym)
  if (reason === "consent_required") return new UserError("invalid", NETWORK_MESSAGES.consent)
  if (reason === "enrolment_closed") return new UserError("invalid", NETWORK_MESSAGES.closed)
  if (reason === "network_disabled" || e.status === 503)
    return new UserError("invalid", NETWORK_MESSAGES.unavailable)
  if (reason === "already_member") return new UserError("invalid", NETWORK_MESSAGES.already)
  if (reason === "not_member") return new UserError("invalid", NETWORK_MESSAGES.notMember)
  if (e.status === 403) return new UserError("invalid", NETWORK_MESSAGES.forbidden)
  return new UserError("invalid", NETWORK_MESSAGES.generic)
}

// --- Calls ----------------------------------------------------------------------------

export interface JoinInput {
  pseudonym: string
  country: string
  showCountry: boolean
  accept: readonly Consent[]
}

async function guarded<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    throw toNetworkError(e)
  }
}

/** A missing summary (404: never a member, or the first count is not in yet) is not an error. */
async function orNull<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn()
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null
    throw e
  }
}

/** The list endpoints may answer with a bare array or `{ items }`. */
export function itemsOf<T>(raw: unknown): T[] {
  if (Array.isArray(raw)) return raw as T[]
  const items = (raw as { items?: unknown } | null)?.items
  return Array.isArray(items) ? (items as T[]) : []
}

export const networkApi = {
  status: () => getJson<NetworkStatus>("/network/status"),
  summary: () => orNull(() => getJson<NetworkSummary>("/network/summary")),
  impact: () => orNull(() => getJson<NetworkImpact>("/network/impact")),
  targets: (f: TargetFilters, cursor?: string | null, limit = 25) =>
    getJson<Page<NetworkTarget>>("/network/targets", {
      state: f.state,
      kind: f.kind,
      mine: f.mine ? "1" : undefined,
      target: f.target,
      cursor: cursor ?? undefined,
      limit,
    }),
  submissions: async () =>
    itemsOf<NetworkSubmission>(await getJson<unknown>("/network/submissions", { limit: 30 })),
  submission: (day: string) =>
    getJson<NetworkSubmissionDetail>(`/network/submissions/${encodeURIComponent(day)}`),
  /** Joins. Asks for the administrator's password again; `accept` lists all five consents. */
  join: (input: JoinInput, password: string) =>
    guarded(() =>
      sendJson("PUT", "/network/membership", {
        join: true,
        ...(input.pseudonym.trim() ? { pseudonym: input.pseudonym.trim() } : {}),
        ...(input.country ? { country: input.country } : {}),
        show_country: input.country ? input.showCountry : false,
        accept: [...input.accept],
        password,
      }),
    ),
  /** Changes the pseudonym or the country of a member. No password. */
  update: (input: { pseudonym: string; country: string; showCountry: boolean }) =>
    guarded(() =>
      sendJson("PATCH", "/network/membership", {
        pseudonym: input.pseudonym.trim() || null,
        country: input.country || null,
        show_country: input.country ? input.showCountry : false,
      }),
    ),
  /** Leaves: deletes the identity here and asks the hub to delete the node. Password again. */
  leave: (password: string) =>
    guarded(() => sendJson("DELETE", "/network/membership", { password })),
}
