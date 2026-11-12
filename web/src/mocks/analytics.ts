/**
 * Mock handlers for the M5 analytics endpoints (stats/timeseries, stats/top,
 * attackers, asns), derived from the same fixtures as the sessions API so the
 * numbers agree across pages. Older history (before the fixtures start) is
 * synthesised deterministically so "previous 24 h" and "30 days" have content.
 */
import { delay, http, HttpResponse } from "msw"
import type {
  AsnItem,
  Attacker,
  AttackerDetail,
  Bucket,
  SensorEvent,
  Timeseries,
  TopField,
  TopItem,
  TopResponse,
} from "@/lib/api"
import { SENSORS, TOP_FIELDS } from "@/lib/api"
import { connectionsOf } from "@/lib/floods"
import type { Fixture } from "./fixtures"

const LATENCY_MS = 160
const BUCKET_MS: Record<Bucket, number> = { "5m": 300_000, "1h": 3_600_000, "1d": 86_400_000 }
const DAY = 86_400_000

function hash(s: string | number): number {
  let h = 2166136261
  for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619)
  return (h >>> 0) / 4294967296
}

function parseTime(raw: string | null, fallback: number): number {
  if (!raw) return fallback
  const t = new Date(raw).getTime()
  return Number.isNaN(t) ? fallback : t
}

const rec = (): Record<string, number> => ({})
const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z")

function offsetCursor(raw: string | null): number {
  if (!raw) return 0
  try {
    const v = JSON.parse(atob(raw)) as { o?: number }
    return typeof v.o === "number" ? v.o : 0
  } catch {
    return 0
  }
}

export function analyticsHandlers(fixtures: readonly Fixture[]) {
  const events: SensorEvent[] = fixtures.flatMap((f) => f.events)
  const oldest = Math.min(...events.map((e) => new Date(e.ts).getTime()))
  const hours = Math.max(1, (Date.now() - oldest) / 3_600_000)
  const hourlyRate = Object.fromEntries(
    SENSORS.map((s) => [s, events.filter((e) => e.sensor === s).length / hours]),
  ) as Record<string, number>
  const sessionRate = Object.fromEntries(
    SENSORS.map((s) => [s, fixtures.filter((f) => f.session.sensor === s).length / hours]),
  ) as Record<string, number>

  // ---- attackers, aggregated from sessions plus synthetic history ----
  const attackers = new Map<string, { a: Attacker; extraEvents: number; fixtures: Fixture[] }>()
  for (const f of fixtures) {
    const s = f.session
    const entry = attackers.get(s.src_ip)
    if (!entry) {
      attackers.set(s.src_ip, {
        a: {
          ip: s.src_ip,
          first_seen: s.started_at,
          last_seen: s.last_event_at,
          sessions: 0,
          events: 0,
          sensors: [],
          login_attempts: 0,
          login_success: 0,
          commands: 0,
          downloads: 0,
          country: s.country,
          city: s.city,
          asn: s.asn,
          org: s.org,
          abuse_score: s.abuse_score,
          known_scanner: s.known_scanner,
          tags: [],
        },
        extraEvents: 0,
        fixtures: [],
      })
    }
    const e = attackers.get(s.src_ip)
    if (!e) continue
    const a = e.a
    e.fixtures.push(f)
    a.sessions += connectionsOf(s)
    a.events += s.event_count
    a.login_attempts += s.login_attempts
    a.login_success += s.login_success ? 1 : 0
    a.commands += s.commands
    a.downloads += s.downloads
    if (!a.sensors.includes(s.sensor)) a.sensors.push(s.sensor)
    for (const t of s.tags) if (!a.tags.includes(t)) a.tags.push(t)
    if (s.started_at < a.first_seen) a.first_seen = s.started_at
    if (s.last_event_at > a.last_seen) a.last_seen = s.last_event_at
  }
  for (const e of attackers.values()) {
    const h = hash(e.a.ip)
    if (h < 0.4) {
      const extra = 2 + Math.floor(h * 30)
      const back = (1 + Math.floor(hash(e.a.ip + "d") * 24)) * DAY
      e.a.sessions += extra
      e.extraEvents = extra * 24
      e.a.events += e.extraEvents
      e.a.login_attempts += extra * 9
      e.a.login_success += Math.floor(extra / 5)
      e.a.commands += Math.floor(extra / 2)
      e.a.downloads += extra % 3 === 0 ? 1 : 0
      e.a.first_seen = iso(new Date(e.a.first_seen).getTime() - back)
      const other = SENSORS[Math.floor(hash(e.a.ip + "s") * SENSORS.length)]
      if (other && !e.a.sensors.includes(other)) e.a.sensors.push(other)
    }
  }
  const list = [...attackers.values()]

  return [
    http.get("/api/v1/stats/timeseries", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const bucket = u.searchParams.get("bucket") as Bucket
      const step = BUCKET_MS[bucket] as number | undefined
      if (!step) return HttpResponse.json({ detail: "invalid bucket" }, { status: 422 })
      const wanted = u.searchParams.getAll("sensor")
      const sensor = (name: string) => wanted.length === 0 || wanted.includes(name)
      const now = Date.now()
      const until = parseTime(u.searchParams.get("until"), now)
      const since = parseTime(u.searchParams.get("since"), until - 24 * 3_600_000)
      const start = Math.floor(since / step) * step
      const n = Math.min(500, Math.ceil((until - start) / step))
      const points = Array.from({ length: n }, (_, i) => {
        const ts = start + i * step
        return {
          ts: iso(ts),
          events: rec(),
          sessions: rec(),
        }
      })
      const at = (ms: number) => points[Math.floor((ms - start) / step)]
      for (const p of points) {
        for (const s of SENSORS) {
          p.events[s] = 0
          p.sessions[s] = 0
        }
      }
      for (const e of events) {
        const p = at(new Date(e.ts).getTime())
        if (p && sensor(e.sensor)) p.events[e.sensor] = (p.events[e.sensor] ?? 0) + 1
      }
      for (const f of fixtures) {
        const p = at(new Date(f.session.started_at).getTime())
        const s = f.session.sensor
        if (p && sensor(s)) p.sessions[s] = (p.sessions[s] ?? 0) + connectionsOf(f.session)
      }
      // Before the fixtures start there is no data: synthesise a plausible past.
      for (const p of points) {
        const t = new Date(p.ts).getTime()
        if (t + step > oldest) continue
        const wave = 0.75 + 0.5 * Math.sin((t / 3_600_000) * 0.45)
        for (const s of SENSORS) {
          if (!sensor(s)) continue
          const k = (0.6 + hash(`${s}${t}`) * 0.8) * wave * (step / 3_600_000)
          p.events[s] = Math.round((hourlyRate[s] ?? 0) * k)
          p.sessions[s] = Math.round((sessionRate[s] ?? 0) * k)
        }
      }
      const body: Timeseries = { bucket, since: iso(start), until: iso(until), points }
      return HttpResponse.json(body)
    }),

    http.get("/api/v1/stats/top", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const field = u.searchParams.get("field") as TopField
      if (!TOP_FIELDS.includes(field))
        return HttpResponse.json({ detail: "invalid field" }, { status: 422 })
      const limit = Number(u.searchParams.get("limit") ?? 10)
      const wanted = u.searchParams.getAll("sensor")
      const until = parseTime(u.searchParams.get("until"), Date.now())
      const since = parseTime(u.searchParams.get("since"), until - 24 * 3_600_000)
      const counts = new Map<string, { n: number; first: string; last: string }>()
      let total = 0
      const sessionFields = ["country", "asn", "org", "tag", "src_ip"]
      const seen = new Set<string>()
      for (const e of events) {
        if (wanted.length && !wanted.includes(e.sensor)) continue
        // These fields count sessions (one per session), the others events.
        if (sessionFields.includes(field)) {
          if (seen.has(e.session_id)) continue
          seen.add(e.session_id)
        }
        const t = new Date(e.ts).getTime()
        if (t < since || t >= until) continue
        const d = e.data
        const vals: (string | null | undefined)[] = []
        switch (field) {
          case "country":
            vals.push(e.country)
            break
          case "asn":
            vals.push(e.asn === null ? null : String(e.asn))
            break
          case "org":
            vals.push(e.org)
            break
          case "src_ip":
            vals.push(e.src_ip)
            break
          case "tag":
            vals.push(...e.tags)
            break
          case "username":
            if (e.type === "login_attempt") vals.push(d.username as string)
            break
          case "password":
            if (e.type === "login_attempt") vals.push(d.password as string)
            break
          case "command":
            if (e.type === "command") vals.push(d.input as string)
            break
          case "url":
            if (e.type === "http_request") vals.push(d.path as string)
            if (e.type === "download_attempt") vals.push(d.url as string)
            break
          case "user_agent":
            if (e.type === "http_request") vals.push(d.user_agent as string)
            break
        }
        for (const v of vals) {
          if (!v) continue
          total += 1
          const c = counts.get(v)
          if (c) {
            c.n += 1
            c.last = e.ts
          } else counts.set(v, { n: 1, first: e.ts, last: e.ts })
        }
      }
      const items: TopItem[] = [...counts.entries()]
        .sort((a, b) => b[1].n - a[1].n || a[0].localeCompare(b[0]))
        .slice(0, limit)
        .map(([value, c]) => ({
          value,
          count: c.n,
          share: total ? c.n / total : 0,
          first_seen: c.first,
          last_seen: c.last,
        }))
      const body: TopResponse = { field, total, items }
      return HttpResponse.json(body)
    }),

    http.get("/api/v1/attackers", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const p = u.searchParams
      const sort = p.get("sort") ?? "last_seen"
      let items = list.map((e) => e.a)
      const country = p.get("country")
      const asn = p.get("asn")
      const sensors = p.getAll("sensor")
      const tag = p.get("tag")
      const q = p.get("q")
      if (country) items = items.filter((a) => a.country === country)
      if (asn) items = items.filter((a) => String(a.asn) === asn)
      if (sensors.length) items = items.filter((a) => a.sensors.some((x) => sensors.includes(x)))
      if (tag) items = items.filter((a) => a.tags.includes(tag))
      if (q) items = items.filter((a) => a.ip.startsWith(q))
      const key = (a: Attacker): number | string =>
        sort === "sessions"
          ? a.sessions
          : sort === "events"
            ? a.events
            : sort === "first_seen"
              ? a.first_seen
              : a.last_seen
      items = [...items].sort((x, y) => {
        const a = key(x)
        const b = key(y)
        return a < b ? 1 : a > b ? -1 : x.ip.localeCompare(y.ip)
      })
      const limit = Math.min(200, Number(p.get("limit") ?? 50))
      const off = offsetCursor(p.get("cursor"))
      const next = off + limit < items.length ? btoa(JSON.stringify({ o: off + limit })) : null
      return HttpResponse.json({ items: items.slice(off, off + limit), next_cursor: next })
    }),

    http.get("/api/v1/attackers/:ip", async ({ params }) => {
      await delay(LATENCY_MS)
      const e = attackers.get(String(params.ip))
      if (!e) return HttpResponse.json({ detail: "attacker not found" }, { status: 404 })
      const count = (pick: (ev: SensorEvent) => string | null) => {
        const m = new Map<string, number>()
        for (const f of e.fixtures)
          for (const ev of f.events) {
            const v = pick(ev)
            if (v) m.set(v, (m.get(v) ?? 0) + 1)
          }
        return [...m.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([value, c]) => ({ value, count: c }))
      }
      const perDay = new Map<string, number>()
      for (const f of e.fixtures)
        for (const ev of f.events) {
          const d = ev.ts.slice(0, 10)
          perDay.set(d, (perDay.get(d) ?? 0) + 1)
        }
      const first = new Date(e.a.first_seen).getTime()
      const oldestFixture = Math.min(
        ...e.fixtures.map((f) => new Date(f.session.started_at).getTime()),
      )
      if (e.extraEvents > 0) {
        const span = Math.max(1, Math.floor((oldestFixture - first) / DAY))
        for (let i = 0; i < 30; i++) {
          const t = first + i * DAY
          if (t >= oldestFixture - DAY * 0.5) break
          const share = hash(`${e.a.ip}${i}`) < 0.55 ? hash(`${e.a.ip}v${i}`) : 0
          perDay.set(iso(t).slice(0, 10), Math.round(share * (e.extraEvents / span) * 3))
        }
      }
      const timeline = [...perDay.entries()]
        .sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .slice(-30)
        .map(([day, n]) => ({ day, events: n }))
      const body: AttackerDetail = {
        attacker: e.a,
        recent_sessions: e.fixtures
          .map((f) => f.session)
          .sort((a, b) => (a.started_at < b.started_at ? 1 : -1))
          .slice(0, 20),
        top_usernames: count((ev) =>
          ev.type === "login_attempt" ? String(ev.data.username) : null,
        ),
        top_commands: count((ev) => (ev.type === "command" ? String(ev.data.input) : null)),
        timeline,
      }
      return HttpResponse.json(body)
    }),

    http.get("/api/v1/asns", async ({ request }) => {
      await delay(LATENCY_MS)
      const p = new URL(request.url).searchParams
      const sort = p.get("sort") ?? "sessions"
      const by = new Map<number, AsnItem & { set: Set<string> }>()
      for (const { a } of list) {
        if (a.asn === null) continue
        const cur = by.get(a.asn) ?? {
          asn: a.asn,
          org: a.org,
          country: a.country,
          ips: 0,
          sessions: 0,
          events: 0,
          last_seen: a.last_seen,
          set: new Set<string>(),
        }
        cur.set.add(a.ip)
        cur.ips = cur.set.size
        cur.sessions += a.sessions
        cur.events += a.events
        if (a.last_seen > cur.last_seen) cur.last_seen = a.last_seen
        by.set(a.asn, cur)
      }
      const key = (x: AsnItem) =>
        sort === "ips" ? x.ips : sort === "events" ? x.events : x.sessions
      const items: AsnItem[] = [...by.values()]
        .map((v) => ({
          asn: v.asn,
          org: v.org,
          country: v.country,
          ips: v.ips,
          sessions: v.sessions,
          events: v.events,
          last_seen: v.last_seen,
        }))
        .sort((a, b) => key(b) - key(a))
        .slice(0, Math.min(200, Number(p.get("limit") ?? 50)))
      return HttpResponse.json({ items })
    }),
  ]
}
