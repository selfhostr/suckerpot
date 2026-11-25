import { SENSORS, type LiveEvent, type LiveStats, type LiveWindow, type Sensor } from "@/lib/api"
import { t } from "@/i18n"
import { countryName, formatPercent, maskIp } from "@/lib/format"
import { SENSOR_META } from "@/lib/sensors"

/** Counts for the last minute, computed from the buffer when the server sent none (polling). */
export function deriveStats(events: readonly LiveEvent[], now = Date.now()): LiveStats {
  const cutoff = now - 60_000
  const by_sensor: LiveStats["by_sensor"] = {}
  const sessions = new Set<string>()
  const perSensorSessions = new Map<string, Set<string>>()
  let total = 0
  for (const e of events) {
    if (Date.parse(e.ts) < cutoff) continue
    total += 1
    sessions.add(e.session_id)
    const set = perSensorSessions.get(e.sensor) ?? new Set<string>()
    set.add(e.session_id)
    perSensorSessions.set(e.sensor, set)
    const c = by_sensor[e.sensor] ?? { events: 0, sessions: 0 }
    c.events += 1
    by_sensor[e.sensor] = c
  }
  for (const [sensor, set] of perSensorSessions) {
    const c = by_sensor[sensor]
    if (c) c.sessions = set.size
  }
  return {
    window_seconds: 60,
    events_last_minute: total,
    sessions_last_minute: sessions.size,
    by_sensor,
  }
}

/** The last-minute counts of the API's window, in the shape the WebSocket stats use. */
export function statsFromWindow(w: LiveWindow): LiveStats {
  return {
    window_seconds: 60,
    events_last_minute: w.events_last_minute,
    sessions_last_minute: w.sessions_last_minute,
    by_sensor: w.last_minute_by_sensor,
  }
}

export function busiestSensor(stats: LiveStats): { sensor: Sensor; events: number } | null {
  let best: { sensor: Sensor; events: number } | null = null
  for (const sensor of SENSORS) {
    const events = stats.by_sensor[sensor]?.events ?? 0
    if (events > 0 && (!best || events > best.events)) best = { sensor, events }
  }
  return best
}

/** The plain-English sentence that opens the Live page. */
export function liveFinding(stats: LiveStats | null): string {
  if (!stats) return t("live_finding_waiting")
  const best = busiestSensor(stats)
  if (!best) return t("live_finding_quiet")
  const label = SENSOR_META[best.sensor].label
  const active = SENSORS.filter((s) => (stats.by_sensor[s]?.events ?? 0) > 0).length
  return active === 1
    ? t("live_finding_only", { label, count: best.events })
    : t("live_finding_busiest", { label, count: best.events })
}

export function formatSessions(n: number): string {
  return t("live_sessions", { count: n })
}

// --- "Right now" sentences for the Live page (last 15 minutes of the buffer).

/** A located source of the window, as `aggregateSources` returns it. */
interface CountryLike {
  country: string
  events: number
  ips: number
}

/** A ranked address or network, as `rankLeaders` returns it. */
interface LeaderLike {
  key: string
  events: number
  share: number
  country: string | null
  org: string | null
  asn: number | null
}

function countryLabel(code: string | null): string | null {
  return code ? (countryName(code) ?? code.toUpperCase()) : null
}

/**
 * The page headline: the busiest sensor of the last minute, then where most of the
 * last 15 minutes came from. "SSH is the busiest sensor right now: 42 events in the
 * last minute. France sent 38 % of the last 15 minutes."
 */
export function liveHeadline(
  stats: LiveStats | null,
  top: CountryLike | undefined,
  windowEvents: number,
): string {
  const first = liveFinding(stats)
  if (!top || windowEvents <= 0) return first
  const name = countryLabel(top.country) ?? top.country
  return t("live_headline_top", {
    finding: first,
    country: name,
    share: formatPercent(top.events / windowEvents),
  })
}

export function addressFinding(top: LeaderLike | undefined, masked: boolean): string {
  if (!top) return t("live_address_none")
  const where = countryLabel(top.country)
  return t("live_address_finding", {
    ip: masked ? maskIp(top.key) : top.key,
    hasWhere: where ? "yes" : "no",
    where: where ?? "",
    count: top.events,
    share: formatPercent(top.share),
  })
}

export function countryFinding(top: CountryLike | undefined, windowEvents: number): string {
  if (!top || windowEvents <= 0) return t("live_country_none")
  const name = countryLabel(top.country) ?? top.country
  return t("live_country_finding", {
    name,
    share: formatPercent(top.events / windowEvents),
    count: top.ips,
  })
}

export function networkFinding(top: LeaderLike | undefined): string {
  if (!top) return t("live_network_none")
  return t("live_network_finding", {
    hasOrg: top.org ? "yes" : "no",
    org: top.org ?? "",
    asn: top.key,
    share: formatPercent(top.share),
  })
}
