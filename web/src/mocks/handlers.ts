import { delay, http, HttpResponse } from "msw"
import type { Page, Session, SessionCredentials, SessionDetail, StatsSummary } from "@/lib/api"
import { SENSORS } from "@/lib/api"
import { connectionsOf } from "@/lib/floods"
import { analyticsHandlers } from "./analytics"
import { buildBenignFixtures } from "./benign"
import { buildFixtures } from "./fixtures"
import { buildFloodFixtures } from "./floods"
import { buildReplayFixtures } from "./replay-fixture"
import { liveHandlers, liveWindow, recentEvents } from "./live"
import { settingsHandlers } from "./settings"
import { pipelineHandlers } from "./pipeline"
import { siteHandlers } from "./site"
import { cveHandlers } from "./cves"
import { m7Handlers } from "./m7"
import { intelHandlers } from "./intel"
import { userHandlers } from "./users"
import { campaignsHandlers } from "./campaigns"
import { defendHandlers } from "./defend"
import { samplesHandlers } from "./samples"
import { scriptsHandlers } from "./scripts"
import { alertsHandlers } from "./alerts"
import { abuseHandlers } from "./abuse"
import { abuseSendHandlers } from "./abuse-send"
import { repliesHandlers } from "./replies"
import { resultsHandlers } from "./results"
import { takedownHandlers } from "./takedown"
import { vpnHandlers } from "./vpn"
import { networkHandlers } from "./network"
import { networkFeedHandlers } from "./network-feed"
import { setupHandlers } from "./setup"
import { setupWizardHandlers } from "./setup-wizard"
import { searchHandlers } from "./search"
import { todayHandlers } from "./today"
import { parseStage, sessionStage } from "@/lib/story"
import { storyHandlers } from "./story"

const fixtures = [...buildReplayFixtures(), ...buildFixtures()].sort((a, b) =>
  b.session.started_at.localeCompare(a.session.started_at),
)
// Research-scanner sessions (M19) are listed only when the request asks for them.
const benignFixtures = buildBenignFixtures()
// Flood groups (one row for hundreds of plain connections of one address in one hour).
const floodFixtures = buildFloodFixtures()
const listed = [...fixtures, ...floodFixtures].sort((a, b) =>
  b.session.started_at.localeCompare(a.session.started_at),
)
const byId = new Map([...listed, ...benignFixtures].map((f) => [f.session.session_id, f] as const))

/** What the API does for `?at=`: the group whose hour holds the connection that was folded. */
function groupAt(at: string | null): Session | null {
  const t = at ? Date.parse(at) : Number.NaN
  if (Number.isNaN(t)) return null
  const hit = floodFixtures.find(
    (f) =>
      t >= Date.parse(f.session.started_at) - 60_000 &&
      t <= Date.parse(f.session.last_event_at) + 60_000,
  )
  return hit?.session ?? null
}

/** `GET /sessions/{id}/credentials` for a plain session: counted from its events. */
function credentialsOf(events: readonly { type: string; data: Record<string, unknown> }[]) {
  const users = new Map<string, number>()
  const passwords = new Map<string, number>()
  const pairs = new Map<string, number>()
  let attempts = 0
  for (const e of events) {
    if (e.type !== "login_attempt") continue
    attempts += 1
    const u = typeof e.data.username === "string" ? e.data.username : ""
    const p = typeof e.data.password === "string" ? e.data.password : ""
    users.set(u, (users.get(u) ?? 0) + 1)
    passwords.set(p, (passwords.get(p) ?? 0) + 1)
    pairs.set(`${u}\u0000${p}`, (pairs.get(`${u}\u0000${p}`) ?? 0) + 1)
  }
  const top = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
  const body: SessionCredentials = {
    attempts,
    distinct_usernames: users.size,
    distinct_passwords: passwords.size,
    distinct_pairs: pairs.size,
    truncated: false,
    usernames: top(users).map(([value, count]) => ({ value, count })),
    passwords: top(passwords).map(([value, count]) => ({ value, count })),
    pairs: top(pairs).map(([key, count]) => {
      const [username = "", password = ""] = key.split("\u0000")
      return { username, password, count }
    }),
  }
  return body
}

function encodeCursor(offset: number) {
  return btoa(JSON.stringify({ o: offset })).replace(/=+$/, "")
}

function decodeCursor(cursor: string | null): number | null {
  if (!cursor) return 0
  try {
    const v = JSON.parse(atob(cursor)) as { o?: unknown }
    return typeof v.o === "number" && v.o >= 0 ? v.o : null
  } catch {
    return null
  }
}

function parseLimit(raw: string | null, fallback: number) {
  if (raw === null) return fallback
  const n = Number(raw)
  return Number.isInteger(n) && n >= 1 && n <= 200 ? n : null
}

function paginate(items: readonly unknown[], url: URL, fallbackLimit: number) {
  const limit = parseLimit(url.searchParams.get("limit"), fallbackLimit)
  if (limit === null) return HttpResponse.json({ detail: "invalid limit" }, { status: 422 })
  const offset = decodeCursor(url.searchParams.get("cursor"))
  if (offset === null) return HttpResponse.json({ detail: "invalid cursor" }, { status: 400 })
  const slice = items.slice(offset, offset + limit)
  const next = offset + limit < items.length ? encodeCursor(offset + limit) : null
  const page: Page<unknown> = { items: slice, next_cursor: next }
  return HttpResponse.json(page)
}

/** Simulated latency, so loading states are real but short. */
const LATENCY_MS = 180

/**
 * Auth in mock and demo builds: the app treats the visitor as signed in (AUTH_BYPASS), these
 * handlers only exist so the login form can be tried. Password "wrong" fails, "limited" is rate
 * limited, anything else works.
 */
const authHandlers = [
  http.get("/api/v1/auth/csrf", () => HttpResponse.json({ token: "mock-csrf" })),
  http.post("/api/v1/auth/login", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { password?: string }
    if (body.password === "limited") {
      return HttpResponse.json({ detail: "Too many attempts" }, { status: 429 })
    }
    if (body.password === "wrong") {
      return HttpResponse.json({ detail: "Invalid credentials" }, { status: 401 })
    }
    return new HttpResponse(null, { status: 204 })
  }),
  http.post("/api/v1/auth/logout", () => new HttpResponse(null, { status: 204 })),
]

export const handlers = [
  ...authHandlers,
  ...campaignsHandlers(fixtures),
  ...defendHandlers,
  ...samplesHandlers,
  ...abuseSendHandlers,
  ...repliesHandlers,
  ...resultsHandlers,
  ...takedownHandlers,
  ...abuseHandlers,
  ...vpnHandlers,
  ...networkHandlers,
  ...networkFeedHandlers,
  ...setupHandlers,
  ...setupWizardHandlers,
  ...scriptsHandlers,
  ...alertsHandlers,
  ...searchHandlers,
  ...todayHandlers,
  ...storyHandlers,
  ...userHandlers,
  ...liveHandlers,
  ...siteHandlers,
  ...settingsHandlers,
  ...pipelineHandlers,
  ...analyticsHandlers(listed),
  ...m7Handlers(fixtures.map((f) => f.session)),
  ...cveHandlers(),
  ...intelHandlers(fixtures.map((f) => f.session)),

  http.get("/api/v1/events/recent", async ({ request }) => {
    await delay(LATENCY_MS)
    const limit = parseLimit(new URL(request.url).searchParams.get("limit"), 50)
    if (limit === null) return HttpResponse.json({ detail: "invalid limit" }, { status: 422 })
    return HttpResponse.json({ items: recentEvents(limit) })
  }),

  http.get("/api/v1/live/window", async ({ request }) => {
    await delay(LATENCY_MS)
    const params = new URL(request.url).searchParams
    const minutes = Number(params.get("minutes") ?? 15)
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 60) {
      return HttpResponse.json({ detail: "invalid minutes" }, { status: 422 })
    }
    const sensors = params.getAll("sensor").flatMap((s) => s.split(",").filter(Boolean))
    return HttpResponse.json(liveWindow(minutes, sensors))
  }),

  http.get("/api/v1/sessions", async ({ request }) => {
    await delay(LATENCY_MS)
    const url = new URL(request.url)
    const sensors = url.searchParams.getAll("sensor")
    const srcIp = url.searchParams.get("src_ip")
    const since = url.searchParams.get("since")
    const until = url.searchParams.get("until")
    let items: Session[] = listed.map((f) => f.session)
    // Like the API: scanners show with the switch off, or when one address is asked for by name.
    if (url.searchParams.get("include_benign") === "1" || srcIp) {
      items = [...items, ...benignFixtures.map((f) => f.session)].sort((a, b) =>
        b.started_at.localeCompare(a.started_at),
      )
    }
    const kind = url.searchParams.get("kind")
    if (kind === "session" || kind === "burst")
      items = items.filter((s) => (s.kind ?? "session") === kind)
    if (sensors.length) items = items.filter((s) => sensors.includes(s.sensor))
    if (srcIp) items = items.filter((s) => s.src_ip === srcIp)
    const tag = url.searchParams.get("tag")
    const country = url.searchParams.get("country")
    const asn = url.searchParams.get("asn")
    if (tag) items = items.filter((s) => s.tags.includes(tag))
    const stage = parseStage(url.searchParams.get("stage"))
    if (stage) items = items.filter((s) => sessionStage(s) === stage)
    const technique = url.searchParams.get("technique")
    const campaignId = url.searchParams.get("campaign_id")
    if (technique) items = items.filter((s) => s.techniques?.includes(technique))
    if (campaignId) items = items.filter((s) => String(s.campaign_id) === campaignId)
    if (country) items = items.filter((s) => s.country === country.toUpperCase())
    if (asn) items = items.filter((s) => String(s.asn) === asn)
    if (since) items = items.filter((s) => s.started_at >= new Date(since).toISOString())
    if (until) items = items.filter((s) => s.started_at < new Date(until).toISOString())
    return paginate(items, url, 50)
  }),

  http.get("/api/v1/sessions/:id", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    const f = byId.get(id)
    if (f) return HttpResponse.json(f.session)
    // A folded connection has no row of its own: its event time finds the group that holds it.
    const group = groupAt(new URL(request.url).searchParams.get("at"))
    if (!group) return HttpResponse.json({ detail: "session not found" }, { status: 404 })
    const detail: SessionDetail = { ...group, folded_from: id }
    return HttpResponse.json(detail)
  }),

  http.get("/api/v1/sessions/:id/credentials", async ({ params }) => {
    await delay(LATENCY_MS)
    const f = byId.get(String(params.id))
    if (!f) return HttpResponse.json({ detail: "session not found" }, { status: 404 })
    const stored = "credentials" in f ? (f.credentials as SessionCredentials) : null
    return HttpResponse.json(stored ?? credentialsOf(f.events))
  }),

  http.get("/api/v1/sessions/:id/events", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const f = byId.get(String(params.id))
    if (!f) return HttpResponse.json({ detail: "session not found" }, { status: 404 })
    return paginate(f.events, new URL(request.url), 100)
  }),

  http.get("/api/v1/stats/summary", async () => {
    await delay(LATENCY_MS)
    const cutoff = new Date(Date.now() - 24 * 3600 * 1000).toISOString()
    const recent = listed.filter((f) => f.session.started_at >= cutoff)
    const by_sensor: StatsSummary["by_sensor"] = {}
    for (const s of SENSORS) by_sensor[s] = { events: 0, sessions: 0 }
    // Like the API: a session count is the connections behind the rows, so folding changes none.
    for (const { session } of recent) {
      const c = by_sensor[session.sensor]
      if (c) {
        c.sessions += connectionsOf(session)
        c.events += session.event_count
      }
    }
    const floods = recent.filter((f) => f.session.kind === "burst")
    const summary: StatsSummary = {
      window_hours: 24,
      events: recent.reduce((n, f) => n + f.session.event_count, 0),
      sessions: recent.reduce((n, f) => n + connectionsOf(f.session), 0),
      unique_ips: new Set(recent.map((f) => f.session.src_ip)).size,
      sessions_with_commands: recent.filter((f) => f.session.commands > 0).length,
      download_attempts: recent.reduce((n, f) => n + f.session.downloads, 0),
      by_sensor,
      flood_sessions: floods.reduce((n, f) => n + connectionsOf(f.session), 0),
      flood_sources: new Set(floods.map((f) => f.session.src_ip)).size,
    }
    return HttpResponse.json(summary)
  }),
]
