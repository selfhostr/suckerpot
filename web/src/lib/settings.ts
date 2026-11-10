/**
 * Settings page data (`/api/v1/settings/system` and `/settings/enrichment`) and the
 * plain-English findings each card opens with. Pure functions, unit-tested.
 */
import { formatBytes, formatNumber, formatPercent, formatRelative, plural } from "./format"
import { sensorMeta } from "./sensors"

export type SensorState = "active" | "quiet" | "silent"

export interface SensorStatus {
  sensor: string
  last_event_at: string | null
  events_last_hour: number
  status: SensorState
}

export interface DiskGuard {
  state: "ok" | "trimmed" | "critical"
  active: boolean
  size_bytes: number
  max_bytes: number
  percent: number
  last_trim_at?: string | null
  last_trim_chunks?: number | null
}

export interface IngestDisk {
  degraded: boolean
  degraded_writes: number
  size_bytes: number
  max_bytes: number
  percent: number
}

export interface SystemSettings {
  sensors: SensorStatus[]
  retention: {
    raw_days: number | null
    compression_after_days: number | null
    /** Oldest raw event still stored, or null when empty or unavailable. */
    oldest_event_at: string | null
    aggregates: string[]
  }
  disk_guard: DiskGuard | null
  ingest_disk: IngestDisk | null
  database: { size_bytes: number | null; max_bytes: number | null }
}

export interface GeoFile {
  file: string
  bytes: number
  updated_at: string
  age_days?: number | null
}

export type KeySource = "env" | "settings"

export interface KeyTest {
  ok: boolean
  /** no_key | quota_exhausted | auth | rate_limited | error */
  error: string | null
  checked_at: string | null
}

/** Where a provider's key comes from. The key itself never reaches the browser. */
export interface KeyInfo {
  configured: boolean
  source: KeySource | null
  /** Last four characters, only for keys saved in Settings. */
  last4: string | null
  updated_at: string | null
  /** cannot_decrypt | no_encryption_key: a saved key that ingest cannot use. */
  secret_error: string | null
  /** Saved, but ingest has not picked it up yet. */
  pending_apply: boolean
  test: KeyTest | null
  test_pending: boolean
  test_requested_at: string | null
}

export interface KeyEditing {
  enabled: boolean
  reason: string | null
}

export type ProviderId =
  "abuseipdb" | "greynoise" | "maxmind" | "nvd" | "github" | "abusech" | "virustotal"

export interface ReputationProvider extends KeyInfo {
  daily_quota: number | null
  used_today: number
  disabled: string | null
  paused: boolean
  last_error: string | null
}

export interface EnrichmentSettings {
  geoip: {
    /** maxmind | dbip | off | unknown (ingest has not reported yet). */
    provider: string
    available: boolean
    files: Record<string, GeoFile>
    last_error: string | null
    refresh_days: number | null
    attribution: string | null
  }
  abuseipdb: ReputationProvider
  greynoise: ReputationProvider
  abusech: ReputationProvider
  virustotal: ReputationProvider
  maxmind: KeyInfo
  nvd: KeyInfo
  github: KeyInfo
  key_editing: KeyEditing
  reported_at: string | null
}

/** How long a "Test key" may stay pending before the page says ingest did not answer. */
export const TEST_TIMEOUT_MS = 90_000

export function sourceLabel(source: KeySource | null): string {
  if (source === "env") return "From .env"
  if (source === "settings") return "Set in Settings"
  return "No key"
}

export function testTimedOut(k: KeyInfo, now = Date.now()): boolean {
  if (!k.test_pending || !k.test_requested_at) return false
  return now - Date.parse(k.test_requested_at) > TEST_TIMEOUT_MS
}

/** True while a test or a saved change is still on its way through ingest. */
export function keyInFlight(k: KeyInfo, now = Date.now()): boolean {
  return k.pending_apply || (k.test_pending && !testTimedOut(k, now))
}

export interface TestMessage {
  tone: "ok" | "warning" | "pending"
  text: string
}

/** Plain-English outcome of the last key test, or null when there is nothing to say. */
export function testMessage(k: KeyInfo, now = Date.now()): TestMessage | null {
  if (k.test_pending) {
    return testTimedOut(k, now)
      ? { tone: "warning", text: "Ingest did not answer the test. Try again in a moment." }
      : { tone: "pending", text: "Testing the key…" }
  }
  const t = k.test
  if (!t) return null
  if (t.ok) return { tone: "ok", text: "The provider accepted the key." }
  switch (t.error) {
    case "auth":
      return { tone: "warning", text: "The provider rejected the key. Check it and replace it." }
    case "rate_limited":
      return { tone: "warning", text: "The provider is rate limiting this key. Try again later." }
    case "quota_exhausted":
      return { tone: "warning", text: "Today's quota is used up, so the test was not sent." }
    case "no_key":
      return { tone: "warning", text: "There is no key to test." }
    default:
      return { tone: "warning", text: "The test could not reach the provider." }
  }
}

/** One line for a saved key that ingest cannot use, or null. */
export function secretErrorMessage(code: string | null): string | null {
  if (code === "cannot_decrypt")
    return "The saved key cannot be read, probably because SETTINGS_ENCRYPTION_KEY changed. Replace or remove it."
  if (code === "no_encryption_key")
    return "A key is saved but SETTINGS_ENCRYPTION_KEY is not set, so it is not used."
  return null
}

const label = (s: string) => sensorMeta(s)?.label ?? s.toUpperCase()

function joinAnd(parts: string[]): string {
  if (parts.length <= 1) return parts.join("")
  return `${parts.slice(0, -1).join(", ")} and ${parts.at(-1) ?? ""}`
}

export function sensorsFinding(sensors: readonly SensorStatus[], now = Date.now()): string {
  const active = sensors.filter((s) => s.status === "active")
  const silent = sensors.filter((s) => s.status === "silent")
  const quiet = sensors.filter((s) => s.status === "quiet")
  if (sensors.length > 0 && active.length === sensors.length) {
    return sensors.length === 4
      ? "All four sensors reported in the last 15 minutes."
      : `All ${sensors.length} sensors reported in the last 15 minutes.`
  }
  if (silent.length === sensors.length) return "No sensor has reported in the last 24 hours."
  const parts: string[] = []
  if (active.length > 3)
    parts.push(`${active.length} of ${sensors.length} sensors reported in the last 15 minutes`)
  else if (active.length)
    parts.push(`${joinAnd(active.map((x) => label(x.sensor)))} reported in the last 15 minutes`)
  for (const q of quiet) {
    parts.push(
      `${label(q.sensor)} last reported ${q.last_event_at ? formatRelative(q.last_event_at, now) : "earlier today"}`,
    )
  }
  if (silent.length) {
    parts.push(
      `${joinAnd(silent.map((x) => label(x.sensor)))} ${silent.length === 1 ? "has" : "have"} not reported in over 24 hours`,
    )
  }
  const head = parts.join("; ")
  return `${head.charAt(0).toUpperCase()}${head.slice(1)}.`
}

function geoProviderName(p: string): string {
  if (p === "maxmind") return "MaxMind GeoLite2"
  if (p === "dbip") return "DB-IP Lite"
  return p
}

/** Oldest GeoIP file age in days, or null. */
export function geoAgeDays(e: EnrichmentSettings): number | null {
  const ages = Object.values(e.geoip.files)
    .map((f) => f.age_days ?? (Date.now() - Date.parse(f.updated_at)) / 86_400_000)
    .filter((n) => Number.isFinite(n))
  return ages.length ? Math.max(...ages) : null
}

export function enrichmentFinding(e: EnrichmentSettings): string {
  const g = e.geoip
  if (g.provider === "unknown") return "Ingest has not reported its enrichment status yet."
  let geo: string
  if (g.provider === "off" || !g.available) geo = "GeoIP is off, so new sessions are not located"
  else {
    const age = geoAgeDays(e)
    geo = `GeoIP is on (${geoProviderName(g.provider)}${age !== null ? `, ${plural(Math.round(age), "day")} old` : ""})`
  }
  const abuse = e.abuseipdb
  if (abuse.configured && abuse.daily_quota) {
    return `${geo}; AbuseIPDB used ${formatNumber(abuse.used_today)} of ${formatNumber(abuse.daily_quota)} checks today.`
  }
  return `${geo}; no reputation provider is configured.`
}

/** A gap of more than this many days between the window and the oldest event is worth saying. */
const RETENTION_GAP_DAYS = 2

/** True when the size ceiling is the likely cause: data was dropped or the database is near it. */
function ceilingIsLimiting(g: DiskGuard | null): boolean {
  if (!g) return false
  return g.state !== "ok" || Boolean(g.last_trim_at) || g.percent >= 80
}

export function retentionFinding(
  r: SystemSettings["retention"],
  guard: DiskGuard | null = null,
  now = Date.now(),
): string {
  if (!r.raw_days)
    return "Raw events are kept until the disk guard trims them; aggregates are kept forever."
  const days = plural(r.raw_days, "day")
  const agree = `Raw events are kept for ${days}; aggregates are kept forever.`
  const oldest = r.oldest_event_at ? Date.parse(r.oldest_event_at) : Number.NaN
  if (!Number.isFinite(oldest)) return agree
  const age = Math.max(0, Math.floor((now - oldest) / 86_400_000))
  if (r.raw_days - age <= RETENTION_GAP_DAYS) return agree
  const set = `Raw events are set to be kept for ${days}`
  const stored = `the oldest stored event is ${plural(age, "day")} old`
  if (guard && ceilingIsLimiting(guard)) {
    return `${set}, but ${stored}: the ${formatBytes(guard.max_bytes)} size limit removes older data first.`
  }
  return `${set}; ${stored}, so the store has not filled that window yet.`
}

export function storageFinding(s: SystemSettings): string {
  const g = s.disk_guard
  if (g?.state === "critical") {
    return `The database is at ${formatPercent(g.percent / 100)} of its ceiling: new data may be dropped.`
  }
  const size = s.database.size_bytes
  const max = s.database.max_bytes ?? g?.max_bytes ?? null
  if (size === null) return "The database size is not available."
  if (!max) return `The database uses ${formatBytes(size)}.`
  return `The database uses ${formatBytes(size)} of its ${formatBytes(max)} ceiling (${formatPercent(size / max)}).`
}

/** Tone for a used/budget ratio: neutral, then warning from 80 %. Severe is decided by the caller. */
export function usageTone(ratio: number): "neutral" | "warning" {
  return ratio >= 0.8 ? "warning" : "neutral"
}
