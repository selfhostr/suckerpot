/**
 * The filters of the Attacks lists (sessions, attackers, attacker networks), as pure functions
 * between the URL query string and what the API takes. Every filter lives in the URL, so a view
 * can be shared as a link and Back/Forward walk through the changes. Values that do not have the
 * shape the API accepts are dropped here, instead of failing there with a 422.
 */
import type { AsnItem, AttackerFilters, AttackerSort, SessionFilters } from "./api"
import { ATTACKER_SORTS } from "./api"
import { FLOOD_PARAM, floodKindFor, floodViewFromParam } from "./floods"
import { countryName } from "./format"
import { parseSensors } from "./sensors"
import { parseInstant, parseStage } from "./story"

// --- Value shapes (the same ones the API accepts) ------------------------------------------

const TAG = /^[a-z0-9-]{1,32}$/
const COUNTRY = /^[A-Za-z]{2}$/
const ASN = /^\d{1,10}$/
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/
const CAMPAIGN = /^\d{1,15}$/
const IP_PREFIX = /^[0-9a-fA-F.:]{1,45}$/
const IP_ADDRESS = /^[0-9a-fA-F.:]{2,45}$/

const only = (re: RegExp, v: string | null) => (v !== null && re.test(v) ? v : undefined)

/** `AS64500`, `as64500` or `64500` as the bare number the API wants; undefined otherwise. */
export function parseAsn(raw: string | null | undefined): string | undefined {
  const v = raw?.trim().replace(/^as\s*/i, "")
  return v && ASN.test(v) ? String(Number(v)) : undefined
}

/** A country as the upper-case code the API wants, from a code or an English name. */
export function parseCountry(raw: string | null | undefined): string | undefined {
  const v = raw?.trim()
  if (!v) return undefined
  if (COUNTRY.test(v)) return v.toUpperCase()
  const lower = v.toLowerCase()
  return allCountries().find((c) => c.name.toLowerCase() === lower)?.code
}

/** The ISO 3166-1 alpha-2 codes (the browser also knows legacy ones, like DD, that are not). */
const ISO_COUNTRIES =
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(
    " ",
  )

let countries: { code: string; name: string }[] | null = null
/** Every country with an ISO code, sorted by English name. */
export function allCountries(): { code: string; name: string }[] {
  if (countries) return countries
  const out: { code: string; name: string }[] = []
  for (const code of ISO_COUNTRIES) {
    const name = countryName(code)
    if (name) out.push({ code, name })
  }
  countries = out.sort((x, y) => x.name.localeCompare(y.name))
  return countries
}

/** A tag as the lower-case slug the API wants. */
export function parseTag(raw: string | null | undefined): string | undefined {
  const v = raw?.trim().toLowerCase().replace(/\s+/g, "-")
  return v && TAG.test(v) ? v : undefined
}

// --- Sessions -------------------------------------------------------------------------------

/** The fields of the sessions search box. The API matches them exactly, not as substrings. */
export const SESSION_SEARCH_FIELDS = [
  { param: "src_ip", label: "IP address", placeholder: "Exact address" },
  { param: "username", label: "Username", placeholder: "Exact username" },
  { param: "command", label: "Command", placeholder: "Exact command" },
  { param: "url", label: "Download URL", placeholder: "Exact URL" },
] as const
export type SessionSearchParam = (typeof SESSION_SEARCH_FIELDS)[number]["param"]

/** The value to send for one search field, or undefined when it cannot be one. */
export function cleanSearchValue(param: string, raw: string): string | undefined {
  const v = raw.trim()
  if (!v || v.length > 256) return undefined
  if (param === "src_ip") return IP_ADDRESS.test(v) ? v.toLowerCase() : undefined
  return v
}

export function parseSessionFilters(p: URLSearchParams): SessionFilters {
  const sensor = parseSensors(p.get("sensor"))
  return {
    sensor: sensor.length ? sensor : undefined,
    src_ip: cleanSearchValue("src_ip", p.get("src_ip") ?? ""),
    username: cleanSearchValue("username", p.get("username") ?? ""),
    command: cleanSearchValue("command", p.get("command") ?? ""),
    url: cleanSearchValue("url", p.get("url") ?? ""),
    tag: only(TAG, p.get("tag")),
    country: parseCountry(p.get("country")),
    asn: parseAsn(p.get("asn")),
    technique: only(TECHNIQUE, p.get("technique")),
    campaign_id: only(CAMPAIGN, p.get("campaign_id")),
    stage: parseStage(p.get("stage")),
    since: parseInstant(p.get("since")),
    until: parseInstant(p.get("until")),
    kind: floodKindFor(floodViewFromParam(p.get(FLOOD_PARAM))),
  }
}

/** Every param the sessions list reads, for "Clear all". */
export const SESSION_PARAMS = [
  "sensor",
  "src_ip",
  "username",
  "command",
  "url",
  "tag",
  "country",
  "asn",
  "technique",
  "campaign_id",
  "stage",
  "since",
  "until",
  FLOOD_PARAM,
] as const

// --- Attackers ------------------------------------------------------------------------------

export const ATTACKER_SORT_LABELS: Record<AttackerSort, string> = {
  last_seen: "Last seen",
  first_seen: "First seen",
  sessions: "Sessions",
  events: "Events",
}

export interface AttackerView {
  filters: AttackerFilters
  sort: AttackerSort
  order: "asc" | "desc"
}

export function parseAttackerFilters(p: URLSearchParams): AttackerView {
  const rawSort = p.get("sort")
  const sort = ATTACKER_SORTS.includes(rawSort as AttackerSort)
    ? (rawSort as AttackerSort)
    : "last_seen"
  const order = p.get("order") === "asc" ? "asc" : "desc"
  const sensor = parseSensors(p.get("sensor"))
  return {
    sort,
    order,
    filters: {
      sort,
      order,
      sensor: sensor.length ? sensor : undefined,
      country: parseCountry(p.get("country")),
      asn: parseAsn(p.get("asn")),
      tag: only(TAG, p.get("tag")),
      q: only(IP_PREFIX, p.get("q")),
    },
  }
}

export const ATTACKER_PARAMS = ["sensor", "q", "country", "asn", "tag"] as const

// --- Attacker networks ----------------------------------------------------------------------

export const ASN_SORTS = [
  { id: "sessions", label: "Sessions" },
  { id: "ips", label: "Addresses" },
  { id: "events", label: "Events" },
] as const
export type AsnSort = (typeof ASN_SORTS)[number]["id"]

export interface NetworkView {
  sort: AsnSort
  /** Free text: an AS number, a network name or a country. Applied here, not by the API. */
  q: string
  country: string | undefined
  since: string | undefined
}

export function parseNetworkView(p: URLSearchParams): NetworkView {
  const sort = ASN_SORTS.find((o) => o.id === p.get("sort"))?.id ?? "sessions"
  return {
    sort,
    q: (p.get("q") ?? "").trim().slice(0, 64),
    country: parseCountry(p.get("country")),
    since: parseInstant(p.get("since")),
  }
}

export const NETWORK_PARAMS = ["q", "country", "since"] as const

/** Networks that match the text (AS number, name or country name) and the country. */
export function filterNetworks(
  items: readonly AsnItem[],
  view: Pick<NetworkView, "q" | "country">,
): AsnItem[] {
  const q = view.q.toLowerCase().replace(/^as\s*(?=\d)/, "")
  return items.filter((n) => {
    if (view.country && n.country !== view.country) return false
    if (!q) return true
    const country = (countryName(n.country) ?? "").toLowerCase()
    return (
      String(n.asn).startsWith(q) ||
      (n.org ?? "").toLowerCase().includes(q) ||
      country.includes(q) ||
      (n.country ?? "").toLowerCase() === q
    )
  })
}

// --- Period ---------------------------------------------------------------------------------

export const PERIOD_PRESETS = [
  { id: "1h", label: "Last hour", ms: 3_600_000 },
  { id: "24h", label: "Last 24 hours", ms: 24 * 3_600_000 },
  { id: "7d", label: "Last 7 days", ms: 7 * 24 * 3_600_000 },
  { id: "30d", label: "Last 30 days", ms: 30 * 24 * 3_600_000 },
] as const

/** The `since` instant of a preset, counted back from `now`. */
export function presetSince(id: string, now = Date.now()): string | undefined {
  const p = PERIOD_PRESETS.find((x) => x.id === id)
  return p ? new Date(now - p.ms).toISOString() : undefined
}

/** `2026-11-12` (a date input) as the start of that day in the browser's time zone. */
export function dayStart(date: string): string | undefined {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return undefined
  const [y, m, d] = date.split("-").map(Number) as [number, number, number]
  const t = new Date(y, m - 1, d)
  return Number.isNaN(t.getTime()) ? undefined : t.toISOString()
}

/** `until` for an inclusive last day: the start of the day after it. */
export function dayAfter(date: string): string | undefined {
  const start = dayStart(date)
  if (!start) return undefined
  const t = new Date(start)
  t.setDate(t.getDate() + 1)
  return t.toISOString()
}

/** The date input value (`YYYY-MM-DD`, local) for an instant. */
export function toDateInput(iso: string | undefined, inclusiveEnd = false): string {
  if (!iso) return ""
  const t = new Date(iso)
  if (Number.isNaN(t.getTime())) return ""
  if (inclusiveEnd) t.setDate(t.getDate() - 1)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())}`
}

// --- Writing the URL ------------------------------------------------------------------------

/** A copy of the params with `patch` applied: null or "" removes a param. Others are kept. */
export function patchParams(
  prev: URLSearchParams,
  patch: Record<string, string | null | undefined>,
): URLSearchParams {
  const next = new URLSearchParams(prev)
  for (const [k, v] of Object.entries(patch)) {
    if (v === null || v === undefined || v === "") next.delete(k)
    else next.set(k, v)
  }
  return next
}

/** The params left after "Clear all": everything but the filters (a sort stays). */
export function clearParams(prev: URLSearchParams, filterParams: readonly string[]) {
  const next = new URLSearchParams(prev)
  filterParams.forEach((k) => next.delete(k))
  return next
}

/** How many filters are on (a period counts once, whatever its two ends). */
export function activeFilterCount(p: URLSearchParams, filterParams: readonly string[]): number {
  const keys = filterParams.filter((k) => k !== "until" && p.get(k))
  return p.get("until") && !p.get("since") ? keys.length + 1 : keys.length
}
