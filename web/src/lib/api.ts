/**
 * Typed client for the SuckerPot REST API (api/api/schemas.py is the source
 * of truth for these shapes). Times are ISO 8601 strings in UTC.
 */

import type {
  HeatmapResponse,
  InsightsResponse,
  MalwareDetail,
  MalwareItem,
  NewField,
  NewResponse,
  TagsResponse,
} from "./trends"
import type { EnrichmentSettings, SystemSettings } from "./settings"
import type { C2Page } from "./c2"
import type { CveDetail, CveFilters, CvePage, CveSync } from "./cves"
import type {
  Campaign,
  CampaignFilters,
  CampaignIndicator,
  CampaignStory,
  CampaignTimeline,
  Matrix,
  TechniqueItem,
} from "./campaigns"
import type {
  IndicatorDetail,
  IndicatorFilters,
  IndicatorItem,
  InfrastructureGraph,
} from "./infrastructure"

// The sensor list lives in the registry (./sensors); re-exported for existing imports.
import { isSensor, SENSORS, type Sensor } from "./sensors"
export { isSensor, SENSORS, type Sensor }

export const EVENT_TYPES = [
  "connect",
  "login_attempt",
  "command",
  "http_request",
  "download_attempt",
  "disconnect",
  "scan",
] as const
export type EventType = (typeof EVENT_TYPES)[number]

export interface Enrichment {
  country: string | null
  city: string | null
  asn: number | null
  org: string | null
  abuse_score: number | null
  known_scanner: boolean | null
  tags: string[]
}

export interface Session extends Enrichment {
  session_id: string
  /** One of SENSORS; typed as string because the API does not narrow it. */
  sensor: string
  src_ip: string
  src_port: number
  dst_port: number
  started_at: string
  ended_at: string | null
  last_event_at: string
  event_count: number
  login_attempts: number
  login_success: boolean
  commands: number
  downloads: number
  http_requests: number
  /** Best-effort client guess (RDP only: "FreeRDP", "nmap", ...); null or absent when unknown. */
  client_tool?: string | null
  /** ATT&CK technique ids the session showed (M15); absent on older responses. */
  techniques?: string[]
  /** The campaign the session belongs to, once ingest has grouped it. */
  campaign_id?: number | null
  /** The deepest step reached (looked ... exploit); absent on older API versions. */
  stage?: string
  /** A known research scanner (harmless crawler); only present when scanners are shown. */
  benign?: boolean
  scanner_name?: string | null
  /**
   * `burst` is a flood group: one row for `connections` plain connections of one source, sensor
   * and port in one UTC hour (its `src_port` is 0). Absent on older API versions: a session.
   */
  kind?: "session" | "burst"
  /** How many connections the row stands for: 1 for a session, N for a flood group. */
  connections?: number
}

/** One session, or the flood group that holds a folded connection (`?at=`). */
export interface SessionDetail extends Session {
  /** Set when the id asked for was folded into this group. */
  folded_from?: string | null
}

/** One value of a credential list and how many times it was tried. */
export interface CredentialCount {
  value: string
  count: number
}

export interface CredentialPair {
  username: string
  password: string
  count: number
}

/** What a session or a flood group tried to log in with (`GET /sessions/{id}/credentials`). */
export interface SessionCredentials {
  attempts: number
  distinct_usernames: number
  distinct_passwords: number
  distinct_pairs: number
  /** The answer covers the first 50,000 attempts only. */
  truncated: boolean
  usernames: CredentialCount[]
  passwords: CredentialCount[]
  pairs: CredentialPair[]
}

export interface SensorEvent extends Enrichment {
  id: number
  ts: string
  sensor: string
  session_id: string
  type: string
  src_ip: string
  src_port: number
  dst_port: number
  data: Record<string, unknown>
}

/** An event as pushed over the live WebSocket (no raw `data`, server-made `summary`). */
export interface LiveEvent extends Enrichment {
  id: number
  ts: string
  sensor: string
  session_id: string
  type: string
  src_ip: string
  src_port: number
  dst_port: number
  /** Server-sanitised plain text. Always render it as text. */
  summary: string
  /** A known research scanner (only delivered when scanners are shown). */
  benign?: boolean
}

export interface LiveStats {
  window_seconds: number
  events_last_minute: number
  sessions_last_minute: number
  by_sensor: Record<string, SensorCounts>
}

/** One country of the live window (`GET /live/window`). */
export interface LiveWindowCountry {
  country: string
  events: number
  ips: number
  top_ip: string
  /** Events that address sent in the window. */
  top_ip_events: number
  last_ts: string
  by_sensor: Record<string, number>
}

export interface LiveWindowAddress {
  ip: string
  events: number
  country: string | null
  asn: number | null
  org: string | null
  last_ts: string
  by_sensor: Record<string, number>
}

export interface LiveWindowNetwork {
  asn: number
  events: number
  ips: number
  country: string | null
  org: string | null
  last_ts: string
  by_sensor: Record<string, number>
}

/** What the sensors saw in the last N minutes, aggregated by the API. */
export interface LiveWindow {
  as_of: string
  window_minutes: number
  /** Newest event id at `as_of`; live events with a higher id are not counted in here. */
  last_event_id: number
  events: number
  unlocated: number
  events_last_minute: number
  sessions_last_minute: number
  last_minute_by_sensor: Record<string, SensorCounts>
  by_sensor: Record<string, number>
  countries: LiveWindowCountry[]
  addresses: LiveWindowAddress[]
  networks: LiveWindowNetwork[]
}

export interface Page<T> {
  items: T[]
  next_cursor: string | null
}

export interface SensorCounts {
  events: number
  sessions: number
}

export interface StatsSummary {
  window_hours: number
  events: number
  sessions: number
  unique_ips: number
  sessions_with_commands: number
  download_attempts: number
  by_sensor: Record<string, SensorCounts>
  /** Of `sessions`: the connections that sit in a flood group. Absent on older API versions. */
  flood_sessions?: number
  /** The addresses that sent them. Absent on older API versions. */
  flood_sources?: number
}

export type Bucket = "5m" | "1h" | "1d"

export interface TimePoint {
  ts: string
  events: Record<string, number>
  sessions: Record<string, number>
}

export interface Timeseries {
  bucket: Bucket
  since: string
  until: string
  points: TimePoint[]
}

export const TOP_FIELDS = [
  "country",
  "asn",
  "org",
  "username",
  "password",
  "command",
  "url",
  "user_agent",
  "tag",
  "src_ip",
] as const
export type TopField = (typeof TOP_FIELDS)[number]

export interface TopItem {
  value: string
  count: number
  /** 0..1 of `total`. */
  share: number
  first_seen?: string
  last_seen?: string
}

export interface TopResponse {
  field: TopField
  total: number
  items: TopItem[]
}

export interface Attacker {
  ip: string
  first_seen: string
  last_seen: string
  sessions: number
  events: number
  sensors: string[]
  login_attempts: number
  /** Number of successful logins (the attacker "got in" this many times). */
  login_success: number
  commands: number
  downloads: number
  country: string | null
  city: string | null
  asn: number | null
  org: string | null
  abuse_score: number | null
  known_scanner: boolean | null
  tags: string[]
}

export interface CountItem {
  value: string
  count: number
}

export interface AttackerDetail {
  attacker: Attacker
  recent_sessions: Session[]
  top_usernames: CountItem[]
  top_commands: CountItem[]
  /** One point per day, UTC, oldest first (at most 30). */
  timeline: { day: string; events: number }[]
}

export interface AsnItem {
  asn: number
  org: string | null
  country: string | null
  ips: number
  sessions: number
  events: number
  last_seen: string
}

export const ATTACKER_SORTS = ["last_seen", "sessions", "events", "first_seen"] as const
export type AttackerSort = (typeof ATTACKER_SORTS)[number]

export interface AttackerFilters {
  sort?: AttackerSort
  country?: string | undefined
  asn?: string | undefined
  /** Sent as repeated `sensor=` params; one sensor is a plain `sensor=ssh`. */
  sensor?: readonly Sensor[] | undefined
  tag?: string | undefined
  q?: string | undefined
}

export interface StatsRange {
  since?: string | undefined
  until?: string | undefined
  sensor?: readonly Sensor[] | undefined
}

export interface SessionFilters {
  sensor?: readonly Sensor[] | undefined
  src_ip?: string | undefined
  tag?: string | undefined
  country?: string | undefined
  asn?: string | undefined
  since?: string | undefined
  until?: string | undefined
  technique?: string | undefined
  campaign_id?: string | undefined
  /** How far the session got: looked, guessed, got_in, commands, download or exploit. */
  stage?: string | undefined
  /** `session` for single connections, `burst` for flood groups; absent for both. */
  kind?: "session" | "burst" | undefined
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** Machine-readable reason from the API (`reauth_failed`, `invalid_key`…), when it sends one. */
    readonly code?: string,
    /** The parsed JSON body of the error answer, when there was one (e.g. guard `reasons`). */
    readonly body?: Record<string, unknown>,
  ) {
    super(message)
    this.name = "ApiError"
  }
}

export const API_BASE = "/api/v1"

/** Called once when any request is answered 401 (session missing or expired). */
let unauthorizedHandler: (() => void) | null = null

export function setUnauthorizedHandler(handler: (() => void) | null) {
  unauthorizedHandler = handler
}

/** With COOKIE_SECURE on the server uses the __Host- prefixed name. */
export const CSRF_COOKIES = ["__Host-sp_csrf", "sp_csrf"] as const

export function readCsrfCookie(): string | null {
  for (const part of document.cookie.split(";")) {
    const [name, ...rest] = part.trim().split("=")
    if ((CSRF_COOKIES as readonly (string | undefined)[]).includes(name))
      return decodeURIComponent(rest.join("="))
  }
  return null
}

/** The CSRF token for unsafe requests: the cookie if present, else a fresh one from the API. */
async function csrfToken(refresh = false): Promise<string> {
  const cached = refresh ? null : readCsrfCookie()
  if (cached) return cached
  const res = await fetch(`${API_BASE}/auth/csrf`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return ((await res.json()) as { token: string }).token
}

async function failure(res: Response, notify: boolean): Promise<ApiError> {
  let detail = res.statusText
  let code: string | undefined
  let parsed: Record<string, unknown> | undefined
  try {
    const body = (await res.json()) as Record<string, unknown>
    parsed = body
    if (typeof body.detail === "string") detail = body.detail
    if (typeof body.code === "string") code = body.code
  } catch {
    // Not JSON: keep the status text.
  }
  if (res.status === 401 && notify) unauthorizedHandler?.()
  return new ApiError(res.status, detail, code, parsed)
}

export type Param = string | number | readonly string[] | undefined

/**
 * Known research scanners (Censys, Shodan...) are hidden by the API unless a request says
 * `include_benign=1`. The sidebar switch "Hide research scanners" flips this one flag, and every
 * request to a list, chart or summary endpoint follows it, so no page has to remember.
 */
let includeBenign = false
const BENIGN_AWARE = [
  "/sessions",
  "/attackers",
  "/asns",
  "/stats/",
  "/events/",
  "/live/window",
  "/insights",
  "/trends",
  "/today",
  "/story",
]

export function setIncludeBenign(on: boolean) {
  includeBenign = on
}

export function getIncludeBenign(): boolean {
  return includeBenign
}

export async function getJson<T>(path: string, params?: Record<string, Param>) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params ?? {})) {
    if (Array.isArray(v)) for (const item of v as readonly string[]) qs.append(k, item)
    else if (v !== undefined && v !== "") qs.set(k, String(v))
  }
  if (includeBenign && BENIGN_AWARE.some((prefix) => path.startsWith(prefix))) {
    qs.set("include_benign", "1")
  }
  const url = `${API_BASE}${path}${qs.size ? `?${qs.toString()}` : ""}`
  const res = await fetch(url, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw await failure(res, true)
  return (await res.json()) as T
}

/**
 * POST with credentials and CSRF, resolving to the response body as a Blob (the sample archive).
 * Errors are the usual ApiError, so `code` ("reauth_failed", ...) is available.
 */
export async function sendForBlob(path: string, body: unknown): Promise<Blob> {
  return (await sendForDownload(path, body)).blob
}

/** Like `sendForBlob`, with the suggested filename and the response headers (X-Excluded, ...). */
export async function sendForDownload(
  path: string,
  body: unknown,
): Promise<{ blob: Blob; filename: string | null; headers: Headers }> {
  const attempt = async (refresh: boolean) =>
    fetch(`${API_BASE}${path}`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/zip, application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": await csrfToken(refresh),
      },
      body: JSON.stringify(body),
    })
  let res = await attempt(false)
  if (res.status === 403) res = await attempt(true)
  if (!res.ok) throw await failure(res, true)
  const m = /filename="?([^";]+)"?/.exec(res.headers.get("Content-Disposition") ?? "")
  return { blob: await res.blob(), filename: m?.[1] ?? null, headers: res.headers }
}

/** GET a file (a guarded download) as a Blob, with the filename the server suggests. */
export async function getBlob(
  path: string,
  params?: Record<string, Param>,
): Promise<{ blob: Blob; filename: string | null }> {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params ?? {}))
    if (v !== undefined && v !== "") qs.set(k, String(v))
  const res = await fetch(`${API_BASE}${path}${qs.size ? `?${qs.toString()}` : ""}`, {
    credentials: "same-origin",
  })
  if (!res.ok) throw await failure(res, true)
  const m = /filename="?([^";]+)"?/.exec(res.headers.get("Content-Disposition") ?? "")
  return { blob: await res.blob(), filename: m?.[1] ?? null }
}

export interface SendOptions {
  /** Add the X-CSRF-Token header (default true; the login call is exempt). */
  csrf?: boolean
  /** Treat a 401 as "session lost" and notify the auth layer (default true). */
  notifyUnauthorized?: boolean
}

/** POST / PUT / PATCH / DELETE with credentials and the CSRF header. Resolves to undefined on 204. */
export async function sendJson<T = undefined>(
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
  { csrf = true, notifyUnauthorized = true }: SendOptions = {},
): Promise<T> {
  const attempt = async (refresh: boolean) => {
    const headers: Record<string, string> = { Accept: "application/json" }
    if (body !== undefined) headers["Content-Type"] = "application/json"
    if (csrf) headers["X-CSRF-Token"] = await csrfToken(refresh)
    return fetch(`${API_BASE}${path}`, {
      method,
      credentials: "same-origin",
      headers,
      body: body === undefined ? null : JSON.stringify(body),
    })
  }
  let res = await attempt(false)
  // A stale CSRF cookie (rotated secret, expired cookie) is fixed by fetching a fresh token once.
  if (res.status === 403 && csrf) res = await attempt(true)
  if (!res.ok) throw await failure(res, notifyUnauthorized)
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export const api = {
  sessions: (filters: SessionFilters, cursor?: string | null, limit = 50) =>
    getJson<Page<Session>>("/sessions", { ...filters, cursor: cursor ?? undefined, limit }),
  /** `at` finds the flood group that holds a folded connection (an event's `ts`). */
  session: (id: string, at?: string | null) =>
    getJson<SessionDetail>(`/sessions/${encodeURIComponent(id)}`, { at: at ?? undefined }),
  sessionCredentials: (id: string, limit = 10) =>
    getJson<SessionCredentials>(`/sessions/${encodeURIComponent(id)}/credentials`, { limit }),
  sessionEvents: (id: string, cursor?: string | null, limit = 200) =>
    getJson<Page<SensorEvent>>(`/sessions/${encodeURIComponent(id)}/events`, {
      cursor: cursor ?? undefined,
      limit,
    }),
  summary: () => getJson<StatsSummary>("/stats/summary"),
  timeseries: (bucket: Bucket, range: StatsRange = {}) =>
    getJson<Timeseries>("/stats/timeseries", { bucket, ...range }),
  top: (field: TopField, range: StatsRange = {}, limit = 10) =>
    getJson<TopResponse>("/stats/top", { field, ...range, limit }),
  attackers: (filters: AttackerFilters, cursor?: string | null, limit = 50) =>
    getJson<Page<Attacker>>("/attackers", {
      ...filters,
      order: "desc",
      cursor: cursor ?? undefined,
      limit,
    }),
  attacker: (ip: string) => getJson<AttackerDetail>(`/attackers/${encodeURIComponent(ip)}`),
  asns: (sort: "sessions" | "ips" | "events" = "sessions", limit = 100) =>
    getJson<{ items: AsnItem[] }>("/asns", { sort, limit }),
  liveWindow: (sensors: readonly string[] = [], minutes = 15) =>
    getJson<LiveWindow>("/live/window", { minutes, sensor: sensors.length ? sensors : undefined }),
  recentEvents: (limit = 50) => getJson<{ items: LiveEvent[] }>("/events/recent", { limit }),
  // M7: insights, trends and malware.
  insights: (range: StatsRange = {}) => getJson<InsightsResponse>("/insights", { ...range }),
  trendsNew: (field: NewField, days = 7, limit = 50) =>
    getJson<NewResponse>("/trends/new", { field, days, limit }),
  trendsTags: (range: StatsRange = {}) =>
    getJson<TagsResponse>("/trends/tags", { bucket: "1d", ...range }),
  heatmap: (range: StatsRange = {}) => getJson<HeatmapResponse>("/stats/heatmap", { ...range }),
  malware: (
    filters: { tool?: string | undefined; q?: string | undefined },
    cursor?: string | null,
    limit = 50,
  ) => getJson<Page<MalwareItem>>("/malware", { ...filters, cursor: cursor ?? undefined, limit }),
  malwareDetail: (url: string) => getJson<MalwareDetail>("/malware/detail", { url }),
  // M12: CVE watch.
  cves: (filters: CveFilters, cursor?: string | null, limit = 25) =>
    getJson<CvePage>("/cves", { ...filters, cursor: cursor ?? undefined, limit }),
  cve: (id: string) => getJson<CveDetail>(`/cves/${encodeURIComponent(id)}`),
  cveSync: () => getJson<CveSync>("/cves/sync"),
  // M13: indicators and infrastructure (passive: nothing is ever fetched from an indicator).
  indicators: (filters: IndicatorFilters, cursor?: string | null, limit = 50) =>
    getJson<Page<IndicatorItem>>("/indicators", { ...filters, cursor: cursor ?? undefined, limit }),
  c2: (cursor?: string | null, limit = 10) =>
    getJson<C2Page>("/indicators/c2", { cursor: cursor ?? undefined, limit }),
  indicator: (id: number) => getJson<IndicatorDetail>(`/indicators/${id}`),
  infrastructureGraph: (hours: number, role?: string) =>
    getJson<InfrastructureGraph>("/infrastructure/graph", { hours, role }),
  // M15: campaigns and MITRE ATT&CK.
  campaigns: (filters: CampaignFilters, cursor?: string | null, limit = 50) =>
    getJson<Page<Campaign>>("/campaigns", { ...filters, cursor: cursor ?? undefined, limit }),
  campaign: (id: number) => getJson<Campaign>(`/campaigns/${id}`),
  campaignStory: (id: number) => getJson<CampaignStory>(`/campaigns/${id}/story`),
  campaignTimeline: (id: number, days = 7) =>
    getJson<CampaignTimeline>(`/campaigns/${id}/timeline`, { days }),
  campaignSessions: (id: number, cursor?: string | null, limit = 10) =>
    getJson<Page<Session>>(`/campaigns/${id}/sessions`, { cursor: cursor ?? undefined, limit }),
  campaignIndicators: (id: number) =>
    getJson<{ items: CampaignIndicator[] }>(`/campaigns/${id}/indicators`),
  attackTechniques: (days: number, sensor?: readonly Sensor[]) =>
    getJson<Page<TechniqueItem> & { days: number }>("/attack/techniques", {
      days,
      sensor,
      limit: 400,
    }),
  attackMatrix: (days: number, sensor?: readonly Sensor[]) =>
    getJson<Matrix>("/attack/matrix", { days, sensor }),
  // M8: read-only settings.
  systemSettings: () => getJson<SystemSettings>("/settings/system"),
  enrichmentSettings: () => getJson<EnrichmentSettings>("/settings/enrichment"),
}

export const queryKeys = {
  sessions: (filters: SessionFilters) => ["sessions", filters] as const,
  session: (id: string, at?: string | null) =>
    (at ? ["session", id, "at", at] : ["session", id]) as readonly unknown[],
  sessionEvents: (id: string) => ["session", id, "events"] as const,
  sessionCredentials: (id: string) => ["session", id, "credentials"] as const,
  summary: ["stats", "summary"] as const,
  timeseries: (bucket: Bucket, range: StatsRange) =>
    ["stats", "timeseries", bucket, range] as const,
  top: (field: TopField, range: StatsRange) => ["stats", "top", field, range] as const,
  attackers: (filters: AttackerFilters) => ["attackers", filters] as const,
  attacker: (ip: string) => ["attacker", ip] as const,
  asns: (sort: string) => ["asns", sort] as const,
  insights: (range: StatsRange) => ["insights", range] as const,
  trendsNew: (field: string, days: number) => ["trends", "new", field, days] as const,
  trendsTags: (range: StatsRange) => ["trends", "tags", range] as const,
  heatmap: (range: StatsRange) => ["stats", "heatmap", range] as const,
  malware: (filters: object) => ["malware", filters] as const,
  malwareDetail: (url: string) => ["malware", "detail", url] as const,
  cves: (filters: object, limit: number) => ["cves", filters, limit] as const,
  cve: (id: string) => ["cves", "detail", id] as const,
  cveSync: ["cves", "sync"] as const,
  c2: () => ["indicators", "c2"] as const,
  indicators: (filters: object) => ["indicators", filters] as const,
  indicator: (id: number) => ["indicators", "detail", id] as const,
  infrastructureGraph: (hours: number, role: string) =>
    ["infrastructure", "graph", hours, role] as const,
  campaigns: (filters: CampaignFilters) => ["campaigns", filters] as const,
  campaign: (id: number) => ["campaigns", "detail", id] as const,
  campaignStory: (id: number) => ["campaigns", "story", id] as const,
  campaignTimeline: (id: number, days: number) => ["campaigns", "timeline", id, days] as const,
  campaignSessions: (id: number) => ["campaigns", "sessions", id] as const,
  campaignIndicators: (id: number) => ["campaigns", "indicators", id] as const,
  attackTechniques: (days: number, sensor: string) =>
    ["attack", "techniques", days, sensor] as const,
  attackMatrix: (days: number, sensor: string) => ["attack", "matrix", days, sensor] as const,
  users: ["users"] as const,
  audit: (filters: object) => ["audit", filters] as const,
  systemSettings: ["settings", "system"] as const,
  enrichmentSettings: ["settings", "enrichment"] as const,
}
