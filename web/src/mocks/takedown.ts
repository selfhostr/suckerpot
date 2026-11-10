/**
 * MSW handlers for the M27 takedown endpoints (docs/design/m27.md section 11). Demo data only:
 * hosts and URLs are on documentation ranges and example.net, ASNs are AS64496 to AS64511, and the
 * hashes are generated. Targets are built once per page load from a fixed list, so the summary,
 * the curve, the providers and the target pages always agree.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type {
  Channel,
  CheckMethod,
  CurvePoint,
  ProviderRow,
  TakedownCounts,
  TakedownSummary,
  Target,
  TargetCheck,
  TargetDetail,
  TargetKind,
  TargetRole,
  TargetState,
} from "@/lib/results"
import { CURVE_HOURS } from "@/lib/results"
import { PROVIDERS } from "./results"
import { sampleSha } from "./samples"

const LATENCY_MS = 170
const HOUR = 3_600_000
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

interface Seed {
  kind: TargetKind
  role: TargetRole
  value: string
  provider: number
  /** Hours since the report. */
  ageH: number
  /** Hours from the report to the first confirmed down check, or null while up. */
  ttdH: number | null
  channels?: Channel[]
  state?: TargetState
  parent?: number
}

// Index in this list + 1 is the target id.
const SEEDS: Seed[] = [
  {
    kind: "ip",
    role: "payload_host",
    value: "203.0.113.9",
    provider: 64500,
    ageH: 24 * 20,
    ttdH: 6,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://203.0.113.9/bins/arm7",
    provider: 64500,
    ageH: 24 * 20,
    ttdH: 6,
    parent: 1,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://203.0.113.9/bins/mips",
    provider: 64500,
    ageH: 24 * 20,
    ttdH: 7,
    parent: 1,
  },
  {
    kind: "ip",
    role: "payload_host",
    value: "203.0.113.31",
    provider: 64503,
    ageH: 24 * 12,
    ttdH: null,
    state: "changed",
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://203.0.113.31/x.sh",
    provider: 64503,
    ageH: 24 * 12,
    ttdH: null,
    state: "changed",
    parent: 4,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://203.0.113.31/a/w.sh",
    provider: 64503,
    ageH: 24 * 12,
    ttdH: null,
    state: "up",
    parent: 4,
  },
  {
    kind: "domain",
    role: "payload_host",
    value: "dl.example.net",
    provider: 64501,
    ageH: 24 * 9,
    ttdH: 30,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://dl.example.net/p/update.bin",
    provider: 64501,
    ageH: 24 * 9,
    ttdH: 30,
    parent: 7,
  },
  {
    kind: "ip",
    role: "payload_host",
    value: "198.51.100.60",
    provider: 64506,
    ageH: 24 * 7,
    ttdH: 3,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://198.51.100.60/m.sh",
    provider: 64506,
    ageH: 24 * 7,
    ttdH: 3,
    parent: 9,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://198.51.100.60/x86_64",
    provider: 64506,
    ageH: 24 * 7,
    ttdH: 5,
    parent: 9,
  },
  {
    kind: "ip",
    role: "payload_host",
    value: "192.0.2.77",
    provider: 64502,
    ageH: 24 * 5,
    ttdH: 70,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://192.0.2.77/k/sora.sh",
    provider: 64502,
    ageH: 24 * 5,
    ttdH: 70,
    parent: 12,
  },
  {
    kind: "ip",
    role: "payload_host",
    value: "198.51.100.88",
    provider: 64500,
    ageH: 24 * 3,
    ttdH: 12,
    channels: ["mail", "urlhaus"],
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://198.51.100.88/i/armv5",
    provider: 64500,
    ageH: 24 * 3,
    ttdH: 12,
    channels: ["mail", "urlhaus"],
    parent: 14,
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://example.net/files/z.sh",
    provider: 64501,
    ageH: 24 * 2,
    ttdH: null,
    state: "up",
    channels: ["urlhaus"],
  },
  {
    kind: "url",
    role: "payload_url",
    value: "http://203.0.113.140/up.sh",
    provider: 64505,
    ageH: 30,
    ttdH: null,
    state: "up",
    channels: ["urlhaus"],
  },
  {
    kind: "ip",
    role: "attack_source",
    value: "198.51.100.23",
    provider: 64500,
    ageH: 24 * 15,
    ttdH: 24 * 9,
  },
  {
    kind: "ip",
    role: "attack_source",
    value: "198.51.100.24",
    provider: 64500,
    ageH: 24 * 15,
    ttdH: null,
    state: "up",
  },
  {
    kind: "ip",
    role: "attack_source",
    value: "192.0.2.14",
    provider: 64501,
    ageH: 24 * 10,
    ttdH: 24 * 8,
  },
  {
    kind: "ip",
    role: "attack_source",
    value: "192.0.2.55",
    provider: 64507,
    ageH: 24 * 4,
    ttdH: null,
    state: "unknown",
  },
  {
    kind: "ip",
    role: "c2",
    value: "203.0.113.200",
    provider: 64503,
    ageH: 24 * 13,
    ttdH: null,
    state: "up",
    channels: ["mail", "threatfox"],
  },
  {
    kind: "ip",
    role: "c2",
    value: "203.0.113.201",
    provider: 64504,
    ageH: 24 * 6,
    ttdH: null,
    state: "unknown",
    channels: ["threatfox"],
  },
]

const nameOf = (asn: number) => PROVIDERS.find((p) => p.asn === asn)

function stateOf(s: Seed): TargetState {
  if (s.state) return s.state
  return s.ttdH !== null ? "down" : "unknown"
}

function build(): Target[] {
  return SEEDS.map((s, i) => {
    const prov = nameOf(s.provider)
    const down = s.ttdH !== null
    return {
      id: i + 1,
      kind: s.kind,
      role: s.role,
      value: s.value,
      parent_id: s.parent ?? null,
      provider_key: `as${s.provider}`,
      provider_name: prov?.name ?? null,
      asn: s.provider,
      country: prov?.country ?? null,
      reported_at: iso(s.ageH * HOUR),
      channels: s.channels ?? ["mail"],
      state: stateOf(s),
      state_source: s.ttdH !== null ? "http" : null,
      state_since: s.ttdH !== null ? iso((s.ageH - s.ttdH) * HOUR) : null,
      tracking: s.ageH < 24 * 30,
      track_until: iso((s.ageH - 24 * 30) * HOUR),
      http_eligible: s.role === "payload_url" || s.role === "payload_host",
      demo: false,
      last_up_at: down ? iso((s.ageH - (s.ttdH ?? 0) + 2) * HOUR) : iso(1 * HOUR),
      first_down_at: down ? iso((s.ageH - (s.ttdH ?? 0)) * HOUR) : null,
      ttd_s: s.ttdH !== null ? s.ttdH * 3600 : null,
      resurrections: 0,
      down_before_report: false,
      last_check_at: iso(40 * 60_000),
    }
  })
}

const targets = build()

const isUrl = (t: Target) => t.role === "payload_url"
const isHost = (t: Target) => t.role === "payload_host"

function median(xs: number[]): number | null {
  if (xs.length === 0) return null
  const s = [...xs].sort((a, b) => a - b)
  return s[Math.floor(s.length / 2)] ?? null
}

function counts(list: Target[]): TakedownCounts {
  const age = (t: Target) => (Date.now() - Date.parse(t.reported_at)) / 3_600_000
  const within = (t: Target, h: number) => t.ttd_s !== null && t.ttd_s <= h * 3600
  const eligible = (h: number) => list.filter((t) => age(t) >= h || within(t, h)).length
  const down = (h: number) => list.filter((t) => within(t, h)).length
  const ttds = list.flatMap((t) => (t.ttd_s !== null ? [t.ttd_s] : []))
  return {
    tracked: list.length,
    eligible_48h: eligible(48),
    down_48h: down(48),
    eligible_7d: eligible(168),
    down_7d: down(168),
    eligible_30d: eligible(720),
    down_30d: down(720),
    ttd_p50_s: median(ttds),
    ttd_n: ttds.length,
    still_up_30d: list.filter((t) => t.ttd_s === null && age(t) >= 720).length,
  }
}

function curve(list: Target[]): CurvePoint[] {
  const age = (t: Target) => (Date.now() - Date.parse(t.reported_at)) / 3_600_000
  return CURVE_HOURS.map((hours) => {
    const eligible = list.filter(
      (t) => age(t) >= hours || (t.ttd_s !== null && t.ttd_s <= hours * 3600),
    )
    const down = eligible.filter((t) => t.ttd_s !== null && t.ttd_s <= hours * 3600).length
    return {
      hours,
      eligible: eligible.length,
      down,
      percent: eligible.length ? down / eligible.length : null,
    }
  })
}

function providerRows(): ProviderRow[] {
  return PROVIDERS.map((pr) => {
    const mine = targets.filter((t) => t.asn === pr.asn && (isUrl(t) || isHost(t)))
    const c = counts(mine)
    const answered = Object.entries(pr.by_outcome).reduce(
      (n, [k, v]) => (k === "none" || k === "bounce" ? n : n + v),
      0,
    )
    return {
      provider_key: `as${pr.asn}`,
      name: pr.name,
      asn: pr.asn,
      country: pr.country,
      targets: mine.length,
      down_48h: c.down_48h,
      eligible_48h: c.eligible_48h,
      percent_48h: c.eligible_48h ? c.down_48h / c.eligible_48h : null,
      eligible_30d: c.eligible_30d,
      down_30d: c.down_30d,
      percent_30d: c.eligible_30d ? c.down_30d / c.eligible_30d : null,
      ttd_n: c.ttd_n,
      ttd_p50_s: c.ttd_p50_s,
      still_up: mine.filter((t) => t.ttd_s === null).length,
      reports_sent: pr.sent,
      reports_answered: answered,
      percent_answered: pr.sent ? answered / pr.sent : null,
      first_reply_p50_s: pr.p50,
    }
  })
}

const METHOD_FOR: Record<TargetRole, CheckMethod> = {
  payload_url: "http",
  payload_host: "http",
  c2: "threatfox",
  attack_source: "sightings",
}

function checksFor(t: Target): TargetCheck[] {
  const out: TargetCheck[] = []
  const method = METHOD_FOR[t.role]
  const reported = Date.parse(t.reported_at)
  const downAt = t.first_down_at ? Date.parse(t.first_down_at) : null
  const count = 8
  const span = (downAt ?? Date.now()) - reported
  let id = t.id * 100
  for (let i = 0; i <= count; i++) {
    const ts = reported + (span * i) / count
    let outcome: string
    if (t.role === "c2") outcome = i % 3 === 0 ? "new_sample" : "listed"
    else if (t.role === "attack_source") outcome = i < 3 ? "seen" : "not_seen"
    else if (downAt !== null && ts >= downAt) outcome = "http_404"
    else if (t.state === "changed" && i >= count - 2) outcome = "changed"
    else outcome = "same"
    const http = method === "http"
    out.push({
      id: ++id,
      checked_at: new Date(ts).toISOString(),
      method,
      outcome,
      http_status: http ? (outcome === "http_404" ? 404 : 200) : null,
      sha256: http && (outcome === "same" || outcome === "changed") ? sampleSha(t.id + 40) : null,
      bytes: http && outcome !== "http_404" ? 18_432 : null,
      duration_ms: http ? 240 : null,
      detail: {},
    })
  }
  return out.reverse()
}

function detail(t: Target): TargetDetail {
  const kids = targets.filter((x) => x.parent_id === t.id)
  return {
    target: t,
    children: kids,
    links: {
      reports: ["3c4d5e6f-7a8b-4c9d-8e0f-6f7a8b9c0d06"],
    },
    checks: checksFor(t),
    ttd: { seconds: t.ttd_s, down_after: t.last_up_at, down_before: t.first_down_at },
    baseline_sha256: t.http_eligible ? sampleSha(t.id + 40) : null,
    last_sha256: t.http_eligible ? sampleSha(t.id + 40) : null,
  }
}

function summary(): TakedownSummary {
  const urls = targets.filter(isUrl)
  const hosts = targets.filter(isHost)
  const att = targets.filter((t) => t.role === "attack_source")
  const c2 = targets.filter((t) => t.role === "c2")
  const sent = PROVIDERS.reduce((n, p) => n + p.sent, 0)
  return {
    since: iso(24 * 21 * HOUR),
    until: iso(0),
    urls: counts(urls),
    hosts: counts(hosts),
    attack_sources: {
      tracked: att.length,
      quiet: att.filter((t) => t.state === "down").length,
      active: att.filter((t) => t.state === "up").length,
    },
    c2: { tracked: c2.length, still_used: c2.filter((t) => t.state === "up").length },
    reports: { sent, answered: 12, first_reply_p50_s: 3 * 3600 },
  }
}

export const takedownHandlers: RequestHandler[] = [
  http.get("/api/v1/takedown/summary", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(summary())
  }),
  http.get("/api/v1/takedown/curve", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({
      since: iso(24 * 21 * HOUR),
      until: iso(0),
      series: [
        { kind: "url", points: curve(targets.filter(isUrl)) },
        { kind: "host", points: curve(targets.filter(isHost)) },
      ],
    })
  }),
  http.get("/api/v1/takedown/providers", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ items: providerRows() })
  }),
  http.get("/api/v1/takedown/targets", async ({ request }) => {
    await delay(LATENCY_MS)
    const q = new URL(request.url).searchParams
    let items = [...targets].sort((a, b) => b.reported_at.localeCompare(a.reported_at))
    for (const k of ["state", "kind", "role", "channel"] as const) {
      const v = q.get(k)
      if (v)
        items = items.filter((t) =>
          k === "channel"
            ? t.channels.includes(v as Channel)
            : k === "kind" && v === "host"
              ? t.kind === "ip" || t.kind === "domain"
              : t[k] === v,
        )
    }
    const provider = q.get("provider")
    if (provider) items = items.filter((t) => t.provider_key === provider)
    const text = q.get("q")
    if (text) items = items.filter((t) => t.value.includes(text))
    return HttpResponse.json({ items, next_cursor: null })
  }),
  http.get("/api/v1/takedown/targets/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const t = targets.find((x) => x.id === Number(params.id))
    if (!t) return HttpResponse.json({ detail: "not found", code: "not_found" }, { status: 404 })
    return HttpResponse.json(detail(t))
  }),
  http.post("/api/v1/takedown/targets/:id/recheck", async ({ params }) => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ id: Number(params.id), http: true, listing: true })
  }),
  http.post("/api/v1/takedown/targets/:id/stop", async ({ params }) => {
    await delay(LATENCY_MS)
    const t = targets.find((x) => x.id === Number(params.id))
    if (t) t.tracking = false
    return HttpResponse.json({ id: Number(params.id), tracking: false })
  }),
]
