/**
 * MSW handlers for the M29 node API (`/api/v1/network`, docs/dev/design/m29.md section 9.6). Demo data
 * only: documentation addresses, invented pseudonyms, scrambled hashes made up on the spot. Every
 * value is typed with the shared types of `lib/network.ts`, so the mock cannot drift from them.
 *
 * Starting state from the URL (`?network=`): `off` (default: not a member, joining is possible),
 * `member`, `waiting` (member, nothing sent yet because the gate is closed), `enrolling`,
 * `disabled` (NETWORK_ENABLED is false) and `nohub` (no hub configured). Joining and leaving work
 * in every state; the password "wrong" is refused.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { Page } from "@/lib/api"
import {
  ALL_CONSENTS,
  isoDay,
  type MemberTier,
  type NetworkCountry,
  type NetworkImpact,
  type NetworkMember,
  type NetworkStatus,
  type NetworkSubmission,
  type NetworkSubmissionDetail,
  type NetworkSummary,
  type NetworkTarget,
  type NetworkWeek,
  type TargetKind,
} from "@/lib/network"

const LATENCY_MS = 160
const DAY = 86_400_000
const dayAgo = (n: number) => isoDay(new Date(Date.now() - n * DAY))
const dayAhead = (n: number) => isoDay(new Date(Date.now() + n * DAY))
const isoAgo = (ms: number) => new Date(Date.now() - ms).toISOString()

// --- Members ------------------------------------------------------------------------------

/** Invented pseudonyms; roughly half of the members have none (they show as "Node <fingerprint>"). */
const NAMES = [
  "night-owl",
  "quiet-harbor",
  "pine_cone",
  "red.lantern",
  "gray-heron",
  "north-wind",
  "tin-whistle",
  "copper-fox",
  "slow-river",
  "moss",
  "late-bloom",
  "blue-ferry",
  "ash-grove",
  "paper-boat",
  "old-lighthouse",
  "small-comet",
  "dune-walker",
  "birch",
]

const COUNTRIES = ["CH", "DE", "FR", "NL", "GB", "SE", "US", "CA", "AT", "IT", "ES", "JP", "BR"]

function rng(seed: number) {
  let s = seed
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296
    return s / 4294967296
  }
}

function buildMembers(): NetworkMember[] {
  const rand = rng(29)
  const members: NetworkMember[] = []
  for (let i = 0; i < 37; i++) {
    const fingerprint = Math.floor(rand() * 0xffffffff)
      .toString(16)
      .padStart(8, "0")
    const named = i < NAMES.length
    const monthsAgo = Math.floor(rand() * 7)
    const d = new Date()
    d.setUTCMonth(d.getUTCMonth() - monthsAgo)
    const cc = COUNTRIES[Math.floor(rand() * rand() * COUNTRIES.length)]
    members.push({
      fingerprint,
      pseudonym: named ? (NAMES[i] ?? null) : null,
      country: rand() < 0.75 ? (cc ?? null) : null,
      member_since: d.toISOString().slice(0, 7),
      active_days: rand() < 0.2 ? Math.floor(rand() * 4) : 5 + Math.floor(rand() * 3),
      tier: Math.min(4, 1 + Math.floor(rand() * 4)) as MemberTier,
    })
  }
  // Keep the list coherent: a sensor idle all week sent nothing, and this node's own entry matches
  // its status (gray-heron, 3f9a1c07, Switzerland, joined last month).
  for (const m of members) {
    if (m.active_days === 0) m.tier = 0
    if (m.pseudonym === "gray-heron") {
      Object.assign(m, {
        fingerprint: "3f9a1c07",
        country: "CH",
        member_since: dayAgo(23).slice(0, 7),
        active_days: 7,
        tier: 3,
      })
    }
  }
  // k-anonymity, like the hub: a country shows only when at least 3 members share it.
  const count = new Map<string, number>()
  for (const m of members) if (m.country) count.set(m.country, (count.get(m.country) ?? 0) + 1)
  return members.map((m) =>
    m.country && (count.get(m.country) ?? 0) < 3 ? { ...m, country: null } : m,
  )
}

const MEMBERS = buildMembers()

function buildCountries(): NetworkCountry[] {
  const count = new Map<string, number>()
  for (const m of MEMBERS) if (m.country) count.set(m.country, (count.get(m.country) ?? 0) + 1)
  return [...count]
    .map(([cc, members]) => ({ cc, members }))
    .sort((a, b) => b.members - a.members || a.cc.localeCompare(b.cc))
}

/** Monday of the week `n` weeks ago (UTC). */
function mondayAgo(n: number): string {
  const d = new Date()
  const back = (d.getUTCDay() + 6) % 7
  return isoDay(new Date(d.getTime() - (back + n * 7) * DAY))
}

function buildWeekly(): NetworkWeek[] {
  const confirmed = [64, 71, 80, 77, 92, 88, 101, 96]
  const reported = [48, 55, 63, 61, 74, 70, 86, 81]
  const down = [17, 21, 25, 22, 31, 29, 36, 33]
  return confirmed.map((c, i) => ({
    week: mondayAgo(confirmed.length - i),
    confirmed: c,
    reported: reported[i] ?? 0,
    taken_down: down[i] ?? 0,
  }))
}

function buildSummary(): NetworkSummary {
  const countries = buildCountries()
  return {
    generated_day: dayAgo(0),
    totals: {
      members: MEMBERS.length,
      active_7d: MEMBERS.filter((m) => m.active_days > 0).length,
      countries: 9,
      confirmed_30d: 412,
      reported_30d: 318,
      taken_down_30d: 141,
      median_days_to_takedown: 4,
    },
    weekly: buildWeekly(),
    countries,
    members: MEMBERS,
    fetched_at: isoAgo(3 * 3_600_000),
  }
}

const IMPACT: NetworkImpact = {
  network: {
    confirmed_30d: 412,
    reported_30d: 318,
    taken_down_30d: 141,
    median_days_to_takedown: 4,
  },
  mine: { helped_confirm_30d: 23, helped_takedown_30d: 9 },
}

// --- Targets ------------------------------------------------------------------------------

const FAMILIES = ["mirai", "gafgyt", "xmrig", "tsunami", "sshdoor", "kinsing"]
const SERVICES = [["ssh"], ["telnet"], ["ssh", "telnet"], ["web"], ["redis"], ["docker"], ["rdp"]]
const TAGS = [["mirai"], ["crypto-miner"], ["malware-drop"], ["credential-stuffing"], ["php2shell"]]

function buildTargets(): NetworkTarget[] {
  const rand = rng(7)
  const kinds: TargetKind[] = ["ip", "ip", "ip", "url", "domain", "sha256", "c2_ip", "c2_domain"]
  const out: NetworkTarget[] = []
  for (let i = 0; i < 64; i++) {
    const kind = kinds[i % kinds.length] ?? "ip"
    const state: NetworkTarget["state"] =
      i % 5 < 3 ? "taken_down" : i % 5 === 3 ? "reported" : "confirmed"
    const first = 3 + Math.floor(rand() * 25)
    const reported = state === "confirmed" ? null : dayAgo(first - 1 - Math.floor(rand() * 2))
    const down =
      state === "taken_down" ? dayAgo(Math.max(0, first - 3 - Math.floor(rand() * 6))) : null
    const octet = 1 + Math.floor(rand() * 250)
    const range = ["192.0.2", "198.51.100", "203.0.113"][i % 3] ?? "192.0.2"
    const blinded = kind === "url" || kind === "domain" || kind === "c2_domain"
    const revealed = blinded && rand() < 0.5
    const hex = Array.from({ length: 64 }, () => Math.floor(rand() * 16).toString(16)).join("")
    const value =
      kind === "ip" || kind === "c2_ip"
        ? `${range}.${octet}`
        : kind === "sha256"
          ? hex
          : revealed
            ? kind === "url"
              ? `http://${range}.${octet}/bins/x86`
              : `cdn${octet}.example.org`
            : null
    out.push({
      hub_id: `t_${hex.slice(0, 6)}`,
      kind,
      value,
      value_b: blinded ? hex : null,
      state,
      nodes: i % 7 === 0 ? 2 : i % 3 === 0 ? 1 : 0,
      countries: i % 4 === 0 ? null : 3 + (i % 6),
      first_day: dayAgo(first),
      last_day: dayAgo(Math.max(0, first - 2 - (i % 4))),
      services: SERVICES[i % SERVICES.length] ?? ["ssh"],
      activity: ["login", "command", "download"].slice(0, 1 + (i % 3)),
      tags: TAGS[i % TAGS.length] ?? [],
      families: i % 3 === 0 ? [FAMILIES[i % FAMILIES.length] ?? "mirai"] : [],
      reported_day: reported,
      taken_down_day: down,
      mine: i % 6 === 1 || i % 11 === 0,
    })
  }
  return out.sort((a, b) =>
    (b.taken_down_day ?? b.reported_day ?? b.last_day).localeCompare(
      a.taken_down_day ?? a.reported_day ?? a.last_day,
    ),
  )
}

const TARGETS = buildTargets()

// --- Submissions --------------------------------------------------------------------------

function buildSubmissions(): NetworkSubmission[] {
  return [1, 2, 3, 4, 5, 6, 7].map((n) => ({
    day: dayAgo(n),
    batch_id: `q8V0b3Lm${n}XyZk2Rj9wPaQ`,
    sent_at: isoAgo(n * DAY - 9 * 3_600_000),
    status: "sent" as const,
    counts: { sources: 52 - n * 3, payloads: 4 + n, c2: n % 2, files: 3 },
    dropped: { guard: n === 2 ? 1 : 0, cap: 0, self: 0 },
    error_code: null,
  }))
}

function submissionDetail(day: string): NetworkSubmissionDetail | null {
  const row = buildSubmissions().find((s) => s.day === day)
  if (!row) return null
  return {
    ...row,
    payload: {
      protocol: "spn/1",
      batch_id: row.batch_id,
      day,
      sources: [
        {
          ip: "198.51.100.23",
          services: ["ssh"],
          activity: ["login", "command", "download"],
          tags: ["mirai"],
          sessions: 1,
          attempts: 3,
        },
        {
          ip: "203.0.113.57",
          services: ["telnet"],
          activity: ["login"],
          tags: ["credential-stuffing"],
          sessions: 2,
          attempts: 4,
        },
      ],
      payloads: [
        {
          url_b: "9f2c0a41e7b35d86c1f0a2b9d4e63a7f8c15b2e09d7a4c3f6e81b50d29a7c4e1",
          host_ip: "198.51.100.9",
          host_b: null,
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          family: "mirai",
          file_type: "elf-arm",
          fetched: true,
        },
      ],
      c2: [
        {
          ip: "198.51.100.50",
          domain_b: null,
          port: 23,
          family: "mirai",
          via_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
      ],
      files: [
        {
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          family: "mirai",
          file_type: "elf-arm",
        },
      ],
    },
  }
}

// --- State ------------------------------------------------------------------------------

const offStatus = (): NetworkStatus => ({
  enabled_env: true,
  hub_configured: true,
  desired: "off",
  state: "off",
  pseudonym: null,
  country: null,
  show_country: false,
  fingerprint: null,
  enrolled_day: null,
  eligible_from_day: null,
  standing: null,
  last_submit_day: null,
  next_submit_at: null,
  last_error_code: null,
  waiting: null,
})

const memberStatus = (): NetworkStatus => ({
  ...offStatus(),
  desired: "member",
  state: "member",
  pseudonym: "gray-heron",
  country: "CH",
  show_country: true,
  fingerprint: "3f9a1c07",
  enrolled_day: dayAgo(23),
  eligible_from_day: dayAhead(-9),
  standing: "good",
  last_submit_day: dayAgo(1),
  next_submit_at: new Date(Date.now() + 9 * 3_600_000).toISOString(),
})

let state: NetworkStatus | null = null
let isMemberEver = false

function current(): NetworkStatus {
  if (!state) {
    const wanted =
      typeof window === "undefined"
        ? null
        : new URLSearchParams(window.location.search).get("network")
    switch (wanted) {
      case "member":
        state = memberStatus()
        break
      case "waiting":
        state = {
          ...memberStatus(),
          waiting: "self_address",
          last_submit_day: null,
          next_submit_at: null,
        }
        break
      case "enrolling":
        state = { ...offStatus(), desired: "member", state: "enrolling", pseudonym: "gray-heron" }
        break
      case "disabled":
        state = { ...offStatus(), enabled_env: false }
        break
      case "nohub":
        state = { ...offStatus(), hub_configured: false }
        break
      default:
        state = offStatus()
    }
    isMemberEver = state.state === "member"
  }
  return state
}

const refused = () =>
  HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })

function validPseudonym(p: string | undefined): "ok" | "invalid" | "taken" {
  if (!p) return "ok"
  if (NAMES.includes(p.toLowerCase())) return "taken"
  return p.includes("://") || p.includes("@") || /\d{4,}/.test(p) ? "invalid" : "ok"
}

export const networkHandlers: RequestHandler[] = [
  http.get("/api/v1/network/status", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(current())
  }),

  http.get("/api/v1/network/summary", async () => {
    await delay(LATENCY_MS)
    return current().state === "member" || isMemberEver
      ? HttpResponse.json(buildSummary())
      : HttpResponse.json({ detail: "not a member" }, { status: 404 })
  }),

  http.get("/api/v1/network/impact", async () => {
    await delay(LATENCY_MS)
    return current().state === "member"
      ? HttpResponse.json(IMPACT)
      : HttpResponse.json({ detail: "not a member" }, { status: 404 })
  }),

  http.get("/api/v1/network/targets", async ({ request }) => {
    await delay(LATENCY_MS)
    const url = new URL(request.url)
    const wantState = url.searchParams.get("state")
    const kind = url.searchParams.get("kind")
    const target = url.searchParams.get("target")
    const mine = url.searchParams.get("mine") === "1"
    let items = TARGETS
    if (wantState) items = items.filter((t) => t.state === wantState)
    if (kind) items = items.filter((t) => t.kind === kind)
    if (target) items = items.filter((t) => t.hub_id === target)
    if (mine) items = items.filter((t) => t.mine)
    const limit = Number(url.searchParams.get("limit") ?? 25)
    const cursor = url.searchParams.get("cursor")
    const offset = cursor ? Number(atob(cursor)) || 0 : 0
    const page: Page<NetworkTarget> = {
      items: items.slice(offset, offset + limit),
      next_cursor: offset + limit < items.length ? btoa(String(offset + limit)) : null,
    }
    return HttpResponse.json(page)
  }),

  http.get("/api/v1/network/submissions", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ items: buildSubmissions() })
  }),

  http.get("/api/v1/network/submissions/:day", async ({ params }) => {
    await delay(LATENCY_MS)
    const d = submissionDetail(String(params.day))
    return d ? HttpResponse.json(d) : HttpResponse.json({ detail: "not found" }, { status: 404 })
  }),

  http.put("/api/v1/network/membership", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as {
      password?: string
      pseudonym?: string
      country?: string
      show_country?: boolean
      accept?: string[]
    }
    if (!body.password || body.password === "wrong") return refused()
    const accepted = new Set(body.accept ?? [])
    if (!ALL_CONSENTS.every((c) => accepted.has(c)))
      return HttpResponse.json(
        { detail: "consent_required", code: "consent_required" },
        { status: 422 },
      )
    const p = validPseudonym(body.pseudonym)
    if (p === "taken")
      return HttpResponse.json(
        { detail: "pseudonym_taken", code: "pseudonym_taken" },
        { status: 409 },
      )
    if (p === "invalid")
      return HttpResponse.json(
        { detail: "pseudonym_invalid", code: "pseudonym_invalid" },
        { status: 422 },
      )
    state = {
      ...offStatus(),
      desired: "member",
      state: "enrolling",
      pseudonym: body.pseudonym ?? null,
      country: body.country ?? null,
      show_country: !!body.country && !!body.show_country,
    }
    // The worker enrols in the background: a few seconds here.
    setTimeout(() => {
      isMemberEver = true
      state = {
        ...memberStatus(),
        pseudonym: body.pseudonym ?? null,
        country: body.country ?? null,
        show_country: !!body.country && !!body.show_country,
        enrolled_day: dayAgo(0),
        eligible_from_day: dayAhead(14),
        standing: "new",
        last_submit_day: null,
        next_submit_at: null,
        waiting: "self_address",
      }
    }, 3_500)
    return new HttpResponse(null, { status: 204 })
  }),

  http.patch("/api/v1/network/membership", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as {
      pseudonym?: string | null
      country?: string | null
      show_country?: boolean
    }
    const p = validPseudonym(body.pseudonym ?? undefined)
    if (p === "taken")
      return HttpResponse.json(
        { detail: "pseudonym_taken", code: "pseudonym_taken" },
        { status: 409 },
      )
    if (p === "invalid")
      return HttpResponse.json(
        { detail: "pseudonym_invalid", code: "pseudonym_invalid" },
        { status: 422 },
      )
    state = {
      ...current(),
      pseudonym: body.pseudonym ?? null,
      country: body.country ?? null,
      show_country: !!body.country && !!body.show_country,
    }
    return new HttpResponse(null, { status: 204 })
  }),

  http.delete("/api/v1/network/membership", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { password?: string }
    if (!body.password || body.password === "wrong") return refused()
    state = { ...current(), desired: "leave", state: "leaving" }
    setTimeout(() => {
      isMemberEver = false
      state = offStatus()
    }, 2_500)
    return new HttpResponse(null, { status: 204 })
  }),
]
