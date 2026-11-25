/**
 * Settings page data (`/api/v1/settings/system` and `/settings/enrichment`) and the
 * plain-English findings each card opens with. Pure functions, unit-tested.
 */
import { intlLocale, t } from "@/i18n"
import { formatBytes, formatNumber, formatPercent, formatRelative } from "./format"
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
  if (source === "env") return t("settings_source_env")
  if (source === "settings") return t("settings_source_settings")
  return t("settings_source_none")
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
      ? { tone: "warning", text: t("settings_test_no_answer") }
      : { tone: "pending", text: t("settings_test_pending") }
  }
  const result = k.test
  if (!result) return null
  if (result.ok) return { tone: "ok", text: t("settings_test_ok") }
  switch (result.error) {
    case "auth":
      return { tone: "warning", text: t("settings_test_auth") }
    case "rate_limited":
      return { tone: "warning", text: t("settings_test_rate_limited") }
    case "quota_exhausted":
      return { tone: "warning", text: t("settings_test_quota") }
    case "no_key":
      return { tone: "warning", text: t("settings_test_no_key") }
    default:
      return { tone: "warning", text: t("settings_test_unreachable") }
  }
}

/** One line for a saved key that ingest cannot use, or null. */
export function secretErrorMessage(code: string | null): string | null {
  if (code === "cannot_decrypt") return t("settings_secret_cannot_decrypt")
  if (code === "no_encryption_key") return t("settings_secret_no_encryption_key")
  return null
}

const label = (s: string) => sensorMeta(s)?.label ?? s.toUpperCase()

function joinAnd(parts: string[]): string {
  return new Intl.ListFormat(intlLocale(), { style: "long", type: "conjunction" }).format(parts)
}

export function sensorsFinding(sensors: readonly SensorStatus[], now = Date.now()): string {
  const active = sensors.filter((s) => s.status === "active")
  const silent = sensors.filter((s) => s.status === "silent")
  const quiet = sensors.filter((s) => s.status === "quiet")
  if (sensors.length > 0 && active.length === sensors.length) {
    return t("settings_finding_sensors_all", { count: sensors.length })
  }
  if (silent.length === sensors.length) return t("settings_finding_sensors_none")
  const parts: string[] = []
  if (active.length > 3)
    parts.push(
      t("settings_finding_sensors_some", { active: active.length, total: sensors.length }),
    )
  else if (active.length)
    parts.push(
      t("settings_finding_sensors_named", {
        names: joinAnd(active.map((x) => label(x.sensor))),
      }),
    )
  for (const q of quiet) {
    parts.push(
      q.last_event_at
        ? t("settings_finding_sensor_quiet_at", {
            sensor: label(q.sensor),
            when: formatRelative(q.last_event_at, now),
          })
        : t("settings_finding_sensor_quiet_today", { sensor: label(q.sensor) }),
    )
  }
  if (silent.length) {
    parts.push(
      t("settings_finding_sensors_silent", {
        count: silent.length,
        names: joinAnd(silent.map((x) => label(x.sensor))),
      }),
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
  if (g.provider === "unknown") return t("settings_finding_enrichment_unknown")
  let geo: string
  if (g.provider === "off" || !g.available) geo = t("settings_finding_geo_off")
  else {
    const age = geoAgeDays(e)
    geo =
      age !== null
        ? t("settings_finding_geo_on_age", {
            provider: geoProviderName(g.provider),
            days: Math.round(age),
          })
        : t("settings_finding_geo_on", { provider: geoProviderName(g.provider) })
  }
  const abuse = e.abuseipdb
  if (abuse.configured && abuse.daily_quota) {
    return t("settings_finding_abuse_used", {
      geo,
      used: formatNumber(abuse.used_today),
      quota: formatNumber(abuse.daily_quota),
    })
  }
  return t("settings_finding_no_reputation", { geo })
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
  if (!r.raw_days) return t("settings_finding_retention_guard")
  const days = r.raw_days
  const agree = t("settings_finding_retention_kept", { days })
  const oldest = r.oldest_event_at ? Date.parse(r.oldest_event_at) : Number.NaN
  if (!Number.isFinite(oldest)) return agree
  const age = Math.max(0, Math.floor((now - oldest) / 86_400_000))
  if (r.raw_days - age <= RETENTION_GAP_DAYS) return agree
  if (guard && ceilingIsLimiting(guard)) {
    return t("settings_finding_retention_limited", {
      days,
      age,
      limit: formatBytes(guard.max_bytes),
    })
  }
  return t("settings_finding_retention_young", { days, age })
}

export function storageFinding(s: SystemSettings): string {
  const g = s.disk_guard
  if (g?.state === "critical") {
    return t("settings_finding_storage_critical", { percent: formatPercent(g.percent / 100) })
  }
  const size = s.database.size_bytes
  const max = s.database.max_bytes ?? g?.max_bytes ?? null
  if (size === null) return t("settings_finding_storage_unknown")
  if (!max) return t("settings_finding_storage_size", { size: formatBytes(size) })
  return t("settings_finding_storage_ceiling", {
    size: formatBytes(size),
    max: formatBytes(max),
    percent: formatPercent(size / max),
  })
}

/** Tone for a used/budget ratio: neutral, then warning from 80 %. Severe is decided by the caller. */
export function usageTone(ratio: number): "neutral" | "warning" {
  return ratio >= 0.8 ? "warning" : "neutral"
}
