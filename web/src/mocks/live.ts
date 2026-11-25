/**
 * Mock of the live WebSocket (`/api/v1/live`) and of `/events/recent`.
 * Events are cut from the fixtures (documentation addresses only), so a click
 * on a row opens a real fixture session. The wire format mirrors
 * api/api/live.py: backfill, stats, then one event at a time.
 */
import { mockRandom } from "./random"
import { ws } from "msw"
import {
  SENSORS,
  type LiveEvent,
  type LiveStats,
  type LiveWindow,
  type SensorEvent,
} from "@/lib/api"
import { buildFixtures } from "./fixtures"

const pool: SensorEvent[] = buildFixtures().flatMap((f) => f.events)
let nextId = 100_000

function clean(v: unknown, limit = 48): string {
  const s = typeof v === "string" ? v : typeof v === "number" ? String(v) : ""
  return s.length <= limit ? s : `${s.slice(0, limit - 1)}…`
}

/** Same sentences as `build_summary` in api/api/live.py. */
function summarise(type: string, d: Record<string, unknown>): string {
  switch (type) {
    case "connect":
      return "connected"
    case "login_attempt":
      return `login ${clean(d.username)}/${clean(d.password)} ${d.success === true ? "succeeded" : "failed"}`
    case "command":
      return `ran \`${clean(d.input, 100)}\``
    case "http_request": {
      const status = d.status != null ? ` → ${clean(d.status, 6)}` : ""
      return `${clean(d.method ?? "GET", 10)} ${clean(d.path ?? "/", 100)}${status}`
    }
    case "download_attempt":
      return `download ${clean(d.url, 100)}${d.tool ? ` via ${clean(d.tool, 16)}` : ""}`
    case "disconnect":
      return typeof d.duration_s === "number"
        ? `disconnected after ${d.duration_s.toFixed(0)}s`
        : "disconnected"
    case "scan":
      return "probe"
    default:
      return clean(type, 24)
  }
}

function toLive(e: SensorEvent, ts: number): LiveEvent {
  const { data, ...rest } = e
  return {
    ...rest,
    id: nextId++,
    ts: new Date(Math.floor(ts / 1000) * 1000).toISOString().replace(".000Z", "Z"),
    summary: summarise(e.type, data),
  }
}

function sample(rand: () => number): SensorEvent {
  const e = pool[Math.floor(rand() * pool.length)]
  if (!e) throw new Error("empty mock pool")
  return e
}

/** Newest first, spread over the last 13 minutes (the Live map shows a 15-minute window). */
function backfill(count = 180): LiveEvent[] {
  let seed = 11
  const rand = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0
    return seed / 4294967296
  }
  const now = Date.now()
  const out: LiveEvent[] = []
  for (let i = 0; i < count; i++) {
    out.push(toLive(sample(rand), now - (count - i) * 4_500 - rand() * 2_000))
  }
  return out.reverse()
}

/** A plausible busy minute with a little movement from one frame to the next. */
function stats(rand: () => number): LiveStats {
  const base: Record<string, [number, number]> = {
    ssh: [42, 9],
    telnet: [18, 6],
    adb: [4, 2],
    web: [27, 11],
    docker: [7, 2],
    redis: [15, 5],
    mysql: [9, 3],
    mssql: [5, 2],
    rdp: [6, 3],
    smb: [21, 12],
    sip: [3, 2],
    synology: [5, 3],
  }
  const by_sensor: LiveStats["by_sensor"] = {}
  let events = 0
  let sessions = 0
  for (const s of SENSORS) {
    const [e, n] = base[s] ?? [0, 0]
    const counts = {
      events: Math.max(0, e + Math.round((rand() - 0.5) * 6)),
      sessions: Math.max(0, n + Math.round((rand() - 0.5) * 2)),
    }
    by_sensor[s] = counts
    events += counts.events
    sessions += counts.sessions
  }
  return {
    window_seconds: 60,
    events_last_minute: events,
    sessions_last_minute: sessions,
    by_sensor,
  }
}

const link = ws.link("*/api/v1/live")

export const liveHandlers = [
  link.addEventListener("connection", ({ client }) => {
    client.send(JSON.stringify({ kind: "backfill", events: backfill() }))
    client.send(JSON.stringify({ kind: "stats", stats: stats(mockRandom) }))

    const statsTimer = setInterval(() => {
      client.send(JSON.stringify({ kind: "stats", stats: stats(mockRandom) }))
    }, 5_000)

    let stopped = false
    let eventTimer: ReturnType<typeof setTimeout> | undefined
    const tick = () => {
      if (stopped) return
      const event = toLive(sample(mockRandom), Date.now())
      client.send(JSON.stringify({ kind: "event", event }))
      eventTimer = setTimeout(tick, 700 + mockRandom() * 2_300)
    }
    eventTimer = setTimeout(tick, 1_500)

    client.addEventListener("message", (ev) => {
      if (ev.data === "ping") client.send(JSON.stringify({ kind: "pong" }))
    })
    client.addEventListener("close", () => {
      stopped = true
      clearInterval(statsTimer)
      clearTimeout(eventTimer)
    })
  }),
]

export function recentEvents(limit: number): LiveEvent[] {
  return backfill(Math.min(limit, 200))
}

interface CountryAcc {
  events: number
  ips: Set<string>
  perIp: Record<string, number>
  last: string
  s: Record<string, number>
}
interface KeyAcc {
  e: LiveEvent
  events: number
  ips: Set<string>
  s: Record<string, number>
}

/**
 * Mock of `GET /live/window`: the last `minutes` of a busy sensor farm, aggregated like the API
 * does. The ids stop at the newest one handed out so far, so the live events that follow add on top.
 */
export function liveWindow(minutes: number, sensors: readonly string[]): LiveWindow {
  let seed = 23
  const rand = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0
    return seed / 4294967296
  }
  const now = Date.now()
  const count = 100 * minutes
  const events: LiveEvent[] = []
  for (let i = 0; i < count; i++) {
    const ts = now - (count - i) * ((minutes * 60_000) / count) + 500
    events.push(toLive(sample(rand), ts))
  }
  const lastEventId = nextId - 1
  const picked = sensors.length ? events.filter((e) => sensors.includes(e.sensor)) : events
  const minuteAgo = now - 60_000

  const bump = (m: Record<string, number>, k: string) => {
    m[k] = (m[k] ?? 0) + 1
  }
  const by_sensor: Record<string, number> = {}
  const lastMinute: Record<string, { events: number; sessions: Set<string> }> = {}
  const countries = new Map<string, CountryAcc>()
  const addrs = new Map<string, KeyAcc>()
  const nets = new Map<number, KeyAcc>()
  let unlocated = 0
  for (const e of picked) {
    bump(by_sensor, e.sensor)
    if (Date.parse(e.ts) > minuteAgo) {
      const m = (lastMinute[e.sensor] ??= { events: 0, sessions: new Set() })
      m.events += 1
      m.sessions.add(e.session_id)
    }
    if (e.country) {
      const c = countries.get(e.country) ?? {
        events: 0,
        ips: new Set(),
        perIp: {},
        last: e.ts,
        s: {},
      }
      c.events += 1
      c.ips.add(e.src_ip)
      bump(c.perIp, e.src_ip)
      bump(c.s, e.sensor)
      if (e.ts > c.last) c.last = e.ts
      countries.set(e.country, c)
    } else {
      unlocated += 1
    }
    const a = addrs.get(e.src_ip) ?? { e, events: 0, ips: new Set<string>(), s: {} }
    a.events += 1
    bump(a.s, e.sensor)
    addrs.set(e.src_ip, a)
    if (e.asn != null) {
      const n = nets.get(e.asn) ?? { e, events: 0, ips: new Set<string>(), s: {} }
      n.events += 1
      n.ips.add(e.src_ip)
      bump(n.s, e.sensor)
      nets.set(e.asn, n)
    }
  }
  const lm = Object.entries(lastMinute)
  return {
    as_of: new Date(now).toISOString(),
    window_minutes: minutes,
    last_event_id: lastEventId,
    events: picked.length,
    unlocated,
    events_last_minute: lm.reduce((n, [, m]) => n + m.events, 0),
    sessions_last_minute: new Set(lm.flatMap(([, m]) => [...m.sessions])).size,
    last_minute_by_sensor: Object.fromEntries(
      lm.map(([s, m]) => [s, { events: m.events, sessions: m.sessions.size }]),
    ),
    by_sensor,
    countries: [...countries.entries()]
      .sort((x, y) => y[1].events - x[1].events)
      .slice(0, 80)
      .map(([country, c]) => ({
        country,
        events: c.events,
        ips: c.ips.size,
        top_ip: Object.entries(c.perIp).sort((x, y) => y[1] - x[1])[0]?.[0] ?? "",
        top_ip_events: Object.values(c.perIp).reduce((m, n) => Math.max(m, n), 0),
        last_ts: c.last,
        by_sensor: c.s,
      })),
    addresses: [...addrs.entries()]
      .sort((x, y) => y[1].events - x[1].events)
      .slice(0, 10)
      .map(([ip, a]) => ({
        ip,
        events: a.events,
        country: a.e.country,
        asn: a.e.asn,
        org: a.e.org,
        last_ts: a.e.ts,
        by_sensor: a.s,
      })),
    networks: [...nets.entries()]
      .sort((x, y) => y[1].events - x[1].events)
      .slice(0, 10)
      .map(([asn, n]) => ({
        asn,
        events: n.events,
        ips: n.ips.size,
        country: n.e.country,
        org: n.e.org,
        last_ts: n.e.ts,
        by_sensor: n.s,
      })),
  }
}
