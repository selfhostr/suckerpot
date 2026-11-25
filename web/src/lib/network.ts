/**
 * The SuckerPot network (M29, docs/dev/design/m29.md sections 7 and 9.6): shapes of the node API
 * under `/api/v1/network`, the plain-English sentences of the pages, the consent list and the
 * calls. The mocks in `src/mocks/network.ts` match these types exactly (a test checks it).
 *
 * Joining is strictly opt-in: nothing here ever joins by default, and every wording says what is
 * and what is not shared.
 */
import { ApiError, getJson, sendJson, type Page } from "./api"
import { countryName, formatNumber, plural } from "./format"
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
    title: "Attacker addresses",
    shared:
      "The addresses that attacked my sensors, with the kind of service they hit, a coarse type of activity, behaviour tags and a rounded count (1, 2 to 9, 10 to 99, and so on).",
  },
  {
    id: "payloads",
    title: "Download links",
    shared:
      "Links that attackers tried to download from, sent as blinded links: scrambled, so the real link is revealed only after at least five independent sensors saw the same one.",
  },
  {
    id: "c2",
    title: "Command servers",
    shared:
      "The address and port of a server that a captured malware file called home to, with the malware family. Only when the analysis is highly confident.",
  },
  {
    id: "files",
    title: "Malware file fingerprints",
    shared:
      "The SHA-256 fingerprint of a captured malware file, its family and its file type. The files themselves are never sent.",
  },
  {
    id: "rechecks",
    title: "Takedown checks",
    shared:
      "Whether a reported target still answers: up, down or unknown. Each check is one word per target.",
  },
]

export const ALL_CONSENTS: readonly Consent[] = CONSENTS.map((c) => c.id)

/** Things that never leave this system, whatever you accept. */
export const NEVER_SHARED: readonly string[] = [
  "The usernames and passwords that attackers tried",
  "The commands they typed and the web requests they sent",
  "Ports, and exact times: only the day is sent",
  "Anything from research scanners or harmless visitors",
  "Your own address, domain, host name or dashboard address",
  "Private, reserved and documentation addresses",
  "Anything in your never-block list",
]

/** What the network does with it, and what it keeps. */
export const NETWORK_FACTS: readonly string[] = [
  "A day is sent only after it has ended, plus a random wait of 2 to 20 hours.",
  "A target is confirmed only by consensus: at least five eligible nodes, enrolled at different times, saw it on separate days.",
  "The hub keeps no network address of its own visitors, and deletes what each sensor sent after 14 days.",
  "You can read the exact data of every batch that was sent, and leave with one click: leaving deletes your data at the hub.",
]

export const RESIDUAL_RISK =
  "An attacker who probes many addresses could work out that your address runs a sensor. They can never learn who you are, and they cannot tell which member you are."

export const BENEFIT =
  "One sensor alone rarely gets a malicious host removed. Many independent sensors that agree make one strong report instead of many weak ones, and the network follows the takedown. You gain nothing else by joining: it is a way to help."

// --- Sentences ------------------------------------------------------------------------

const dayFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" })
const dayYearFmt = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  year: "numeric",
  timeZone: "UTC",
})
const monthFmt = new Intl.DateTimeFormat("en-US", {
  month: "short",
  year: "numeric",
  timeZone: "UTC",
})

/** "15 Nov": a calendar day from the hub is a date, not a moment, so no time zone shift. */
export function formatDay(day: string | null | undefined, withYear = false): string {
  if (!day) return "–"
  const d = new Date(`${day}T00:00:00Z`)
  if (Number.isNaN(d.getTime())) return "–"
  return (withYear ? dayYearFmt : dayFmt).format(d)
}

/** "Sep 2026" from "2026-09". */
export function formatMonth(month: string): string {
  const d = new Date(`${month}-01T00:00:00Z`)
  return Number.isNaN(d.getTime()) ? month : monthFmt.format(d)
}

export const SENSORS_BUCKET: Record<0 | 1 | 2, string> = {
  0: "5 to 9 sensors",
  1: "10 to 24 sensors",
  2: "25 or more sensors",
}

export const TIER_LABEL: Record<MemberTier, string> = {
  0: "No items",
  1: "1 to 99 items",
  2: "100 to 999 items",
  3: "1,000 to 9,999 items",
  4: "10,000 or more items",
}

export const TARGET_KIND_LABEL: Record<TargetKind, string> = {
  ip: "Address",
  url: "Link",
  domain: "Domain",
  sha256: "File",
  c2_ip: "Command server",
  c2_domain: "Command domain",
}

export const TARGET_STATE_LABEL: Record<TargetState, string> = {
  confirmed: "Confirmed",
  reported: "Reported",
  taken_down: "Taken down",
  disputed: "Disputed",
  expired: "Expired",
}

export const STANDING_TEXT: Record<NetworkStanding, { label: string; sentence: string }> = {
  new: {
    label: "New",
    sentence:
      "The network is still getting to know this sensor. It starts counting toward confirmations on the date shown under Eligibility, as long as it keeps sending batches.",
  },
  good: {
    label: "Good",
    sentence:
      "This sensor counts toward confirmations. Keep it running and nothing else is needed.",
  },
  low: {
    label: "Low",
    sentence:
      "The network gives this sensor little weight right now, because too much of what it sent was not confirmed by anyone else.",
  },
}

const WAITING_TEXT: Record<NetworkWaiting, string> = {
  self_address:
    "Waiting for your own address: nothing is sent until you confirm it in Settings, Reporting. That check keeps your address out of every batch.",
  egress:
    "Waiting for the VPN: the outbound gate is closed, so nothing is sent yet. See Settings, VPN.",
  settings_key:
    "The settings encryption key is not set, so the node key cannot be stored safely. Nothing is sent.",
  enrolment:
    "The hub is not taking new members right now, or its puzzle is too hard for now. This sensor stays signed up and tries again later by itself.",
}

export function waitingText(w: NetworkWaiting | null): string | null {
  return w ? WAITING_TEXT[w] : null
}

const ERROR_TEXT: Record<string, string> = {
  guard_failed: "The privacy check stopped the last batch, so nothing was sent.",
  hub_signature: "The answer of the hub could not be verified, so it was ignored.",
  leave_unconfirmed: "The hub could not be reached to confirm that your data was deleted.",
  no_settings_key: "The settings encryption key is not set.",
  egress_closed: "The outbound gate is closed.",
  rate_limited: "The hub asked this sensor to slow down. It tries again later.",
  enrolment_closed: "The hub is not accepting new members today. Try again tomorrow.",
}

export function describeNetworkError(code: string | null): string | null {
  if (!code) return null
  return ERROR_TEXT[code] ?? `The last attempt failed (${code}).`
}

/** Is this system a member whose figures can be shown? */
export function isMember(s: NetworkStatus | undefined): boolean {
  return !!s && s.state === "member"
}

/** The one sentence at the top of the Overview, whatever the state. */
export function describeStatus(s: NetworkStatus, impact?: NetworkImpact): string {
  if (!s.enabled_env)
    return "Sharing is switched off in this system's settings (NETWORK_ENABLED=false). Nothing leaves it."
  if (!s.hub_configured) return "No network hub is configured, so the network cannot be joined yet."
  switch (s.state) {
    case "off":
      return "You are not part of the SuckerPot network. Nothing leaves this system."
    case "enrolling":
      return "Joining the SuckerPot network. This can take a few minutes."
    case "leaving":
      return "Leaving the network. Your data is being deleted at the hub."
    case "error":
      return "Joining the network did not work yet. Nothing has been sent."
    case "member":
      return impact ? impactFinding(impact) : "You are part of the SuckerPot network."
  }
}

/** "The network took down 141 malware hosts and attack sources in the last 30 days. …" */
export function impactFinding(i: NetworkImpact): string {
  const down = i.network.taken_down_30d
  const mine = i.mine.helped_confirm_30d
  const head =
    down > 0
      ? `The network took down ${formatNumber(down)} malware ${down === 1 ? "host or attack source" : "hosts and attack sources"} in the last 30 days.`
      : "The network has not taken anything down in the last 30 days yet."
  const tail =
    mine > 0
      ? ` Your sensor helped confirm ${formatNumber(mine)} of the ${formatNumber(i.network.confirmed_30d)} it confirmed.`
      : " Your sensor has not helped confirm any yet."
  return head + tail
}

/** Before the network can confirm anything it needs five active members. */
export const MIN_ACTIVE_MEMBERS = 5

export function bootstrapSentence(totals: NetworkTotals): string | null {
  if (totals.active_7d >= MIN_ACTIVE_MEMBERS) return null
  return `The network needs ${MIN_ACTIVE_MEMBERS} active members before it confirms anything. It has ${formatNumber(totals.active_7d)} now.`
}

/** The takedowns of the latest week against the week before. */
export function weeklyFinding(weekly: readonly NetworkWeek[]): string {
  const last = weekly[weekly.length - 1]
  if (!last) return "There are no weekly figures yet."
  const prev = weekly[weekly.length - 2]
  const noun = (n: number) => plural(n, "target")
  if (!prev)
    return `${noun(last.taken_down)} ${last.taken_down === 1 ? "was" : "were"} taken down in the latest week.`
  if (last.taken_down === prev.taken_down)
    return `${noun(last.taken_down)} were taken down this week, as many as the week before.`
  const dir = last.taken_down > prev.taken_down ? "up" : "down"
  return `${noun(last.taken_down)} ${last.taken_down === 1 ? "was" : "were"} taken down this week, ${dir} from ${formatNumber(prev.taken_down)} the week before.`
}

export function membersFinding(totals: NetworkTotals): string {
  return `${plural(totals.members, "member")} in ${plural(totals.countries, "country", "countries")}; ${formatNumber(totals.active_7d)} active this week.`
}

/** "Counts toward consensus from 15 Nov", or since when. */
export function eligibilityText(s: NetworkStatus, today: string = isoDay(new Date())): string {
  if (!s.eligible_from_day) return "Not known yet"
  return s.eligible_from_day > today
    ? `Counts toward confirmations from ${formatDay(s.eligible_from_day)}`
    : "Counts toward confirmations"
}

export function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10)
}

/** Name shown for a member: the pseudonym, or "Node 3f9a1c07". */
export function memberName(m: { pseudonym: string | null; fingerprint: string }): string {
  return m.pseudonym ?? `Node ${m.fingerprint}`
}

/** What a target is, shown: the value, or a short scrambled form while it is unrevealed. */
export function targetLabel(t: NetworkTarget): string {
  if (t.value) return t.value
  return t.value_b
    ? `Scrambled ${t.kind === "domain" ? "domain" : "link"} ${t.value_b.slice(0, 10)}…`
    : "Unknown"
}

/** Link-like values are shown defanged, as text: they are never clickable. */
export function defangValue(v: string): string {
  return v.replace(/^http/i, (m) => (m === m.toUpperCase() ? "HXXP" : "hxxp")).replace(/\./g, "[.]")
}

/** Sentence above the targets list, from the filters in the URL. */
export function targetsFinding(f: { state: string; kind: string; mine: boolean }): string {
  const what =
    f.state === "taken_down"
      ? "taken down"
      : f.state === "reported"
        ? "reported"
        : f.state === "confirmed"
          ? "confirmed and waiting for a report"
          : "confirmed by the network"
  const whose = f.mine ? "that your sensor helped confirm" : "from all members"
  const kindLabel = (TARGET_KIND_LABEL as Record<string, string | undefined>)[f.kind]
  const kind = kindLabel ? `${kindLabel.toLowerCase()} targets` : "targets"
  return f.state === "all"
    ? `Every ${kind} ${whose}, newest first.`
    : `The latest ${kind} ${what} ${whose}, newest first.`
}

/** Days from the first sighting to the takedown, or null. */
export function daysToTakedown(t: NetworkTarget): number | null {
  if (!t.taken_down_day) return null
  const a = Date.parse(`${t.first_day}T00:00:00Z`)
  const b = Date.parse(`${t.taken_down_day}T00:00:00Z`)
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
  if (v.length < 3 || v.length > 24) return "Use 3 to 24 characters."
  if (v.includes("://") || v.includes("@")) return "A pseudonym cannot contain a link or an @."
  if (/\d{4,}/.test(v))
    return "Avoid 4 digits in a row: they look like a year, a postcode or an address."
  if (!PSEUDONYM_PATTERN.test(v))
    return "Start and end with a letter or digit; inside use letters, digits, spaces, dots, dashes or underscores."
  if (RESERVED.has(v.toLowerCase())) return "That name is reserved. Choose another."
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
  consent: "Tick all five boxes to join. Each one is a separate thing you agree to share.",
  taken: "That pseudonym is already used. Choose another, or leave it empty.",
  pseudonym: "That pseudonym is not allowed. Choose another, or leave it empty.",
  closed: "The network is not accepting new members today. Try again tomorrow.",
  unavailable: "The network is not available on this system. It must be switched on in .env first.",
  forbidden: "Only an administrator can change this.",
  already:
    "This system has already asked to join. It joins at the next check, within 15 minutes. Close this window.",
  notMember: "This system is not part of the network, so there is nothing to change.",
  generic: "The change could not be made. Try again in a moment.",
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
