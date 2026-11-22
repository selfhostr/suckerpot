/**
 * MSW handlers for the M26 statistics (docs/dev/design/m26.md section 11): outcomes grouped by
 * provider, country, mailbox or kind, and the weekly timeline. Demo data only: documentation
 * ASNs (AS64496 to AS64511) and invented provider names.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { ReportKind } from "@/lib/abuse"
import type { Outcome } from "@/lib/replies"
import type {
  OutcomeCounts,
  OutcomeGroup,
  OutcomeGroupRow,
  OutcomesResponse,
  OutcomeTimeline,
  OutcomeTotals,
  ReportEffectResponse,
} from "@/lib/results"

const LATENCY_MS = 160
const HOUR = 3600
const WEEK_MS = 7 * 86_400_000

export interface MockProvider {
  asn: number
  name: string
  country: string
  recipient: number
  recipientName: string
  sent: number
  kinds: Partial<Record<ReportKind, number>>
  by_outcome: OutcomeCounts
  /** Median seconds to the first reply, if any answered. */
  p50: number | null
}

export const PROVIDERS: MockProvider[] = [
  p(
    64500,
    "EXAMPLE-NET",
    "NL",
    1,
    "Example Hosting B.V.",
    { attack_source: 5, payload_host: 2 },
    { resolved: 3, ticket_opened: 2, human_reply: 1, none: 1 },
    2 * HOUR,
  ),
  p(
    64501,
    "EXAMPLE-CLOUD",
    "DE",
    2,
    "Example Cloud Ltd",
    { attack_source: 4, c2: 1 },
    { ticket_opened: 2, auto_ack: 1, none: 2 },
    5 * HOUR,
  ),
  p(
    64502,
    "EXAMPLE-CLOUD-2",
    "DE",
    2,
    "Example Cloud Ltd",
    { attack_source: 3 },
    { auto_ack: 2, none: 1 },
    20 * 60,
  ),
  p(
    64503,
    "SAMPLE-TRANSIT",
    "FR",
    3,
    "Sample Transit AS",
    { payload_host: 2, c2: 2 },
    { human_reply: 1, rejected: 1, none: 2 },
    31 * HOUR,
  ),
  p(
    64504,
    "SAMPLE-VPS",
    "US",
    4,
    "Sample VPS Inc.",
    { attack_source: 3 },
    { bounce: 1, none: 2 },
    null,
  ),
  p(64505, "DEMO-BROADBAND", "BR", 5, "Demo Broadband", { attack_source: 2 }, { none: 2 }, null),
  p(
    64506,
    "DEMO-DC",
    "SG",
    6,
    "Demo Datacentre Pte",
    { attack_source: 2, payload_host: 1 },
    { ticket_opened: 1, resolved: 1, none: 1 },
    9 * HOUR,
  ),
  p(
    64507,
    "TEST-ISP",
    "RU",
    7,
    "Test ISP",
    { attack_source: 2 },
    { unknown: 1, none: 1 },
    3 * 86_400,
  ),
]

function p(
  asn: number,
  name: string,
  country: string,
  recipient: number,
  recipientName: string,
  kinds: MockProvider["kinds"],
  by_outcome: OutcomeCounts,
  p50: number | null,
): MockProvider {
  const sent = Object.values(kinds).reduce((a, b) => a + b, 0)
  return { asn, name, country, recipient, recipientName, sent, kinds, by_outcome, p50 }
}

const answeredOf = (c: OutcomeCounts): number =>
  Object.entries(c).reduce((n, [k, v]) => (k === "none" || k === "bounce" ? n : n + v), 0)

function merge(into: OutcomeCounts, from: OutcomeCounts) {
  for (const [k, v] of Object.entries(from)) {
    const key = k as Outcome
    into[key] = (into[key] ?? 0) + v
  }
}

function groups(by: OutcomeGroup): OutcomeGroupRow[] {
  const map = new Map<string, OutcomeGroupRow & { w: number }>()
  for (const pr of PROVIDERS) {
    const entries: [string, string, number][] =
      by === "asn"
        ? [[String(pr.asn), pr.name, pr.sent]]
        : by === "recipient"
          ? [[String(pr.recipient), pr.recipientName, pr.sent]]
          : by === "country"
            ? [
                [
                  pr.country,
                  new Intl.DisplayNames(["en"], { type: "region" }).of(pr.country) ?? pr.country,
                  pr.sent,
                ],
              ]
            : (Object.entries(pr.kinds) as [ReportKind, number][]).map(([k, n]) => [k, k, n])
    for (const [key, label, n] of entries) {
      const g = map.get(key) ?? {
        key,
        label,
        sent: 0,
        eligible: 0,
        answered: 0,
        by_outcome: {},
        first_reply_p50_s: null,
        w: 0,
      }
      const share = n / pr.sent
      g.sent += n
      g.eligible += n
      const scaled: OutcomeCounts = {}
      for (const [k, v] of Object.entries(pr.by_outcome))
        scaled[k as Outcome] = Math.round(v * share)
      merge(g.by_outcome, scaled)
      g.answered += answeredOf(scaled)
      if (pr.p50 != null && n > 0) {
        g.first_reply_p50_s =
          g.first_reply_p50_s == null
            ? pr.p50
            : Math.round((g.first_reply_p50_s * g.w + pr.p50 * n) / (g.w + n))
        g.w += n
      }
      map.set(key, g)
    }
  }
  return [...map.values()]
    .map((g) => ({
      key: g.key,
      label: g.label,
      sent: g.sent,
      eligible: g.eligible,
      answered: g.answered,
      by_outcome: g.by_outcome,
      first_reply_p50_s: g.first_reply_p50_s,
    }))
    .sort((a, b) => b.sent - a.sent)
}

function totals(): OutcomeTotals {
  const by_outcome: OutcomeCounts = {}
  let sent = 0
  for (const pr of PROVIDERS) {
    sent += pr.sent
    merge(by_outcome, pr.by_outcome)
  }
  const answered = answeredOf(by_outcome)
  return {
    sent,
    eligible: sent,
    answered,
    no_answer: by_outcome.none ?? 0,
    by_outcome,
    first_reply_p50_s: 3 * HOUR,
    first_reply_p90_s: 30 * HOUR,
    resolved_p50_s: 22 * HOUR,
  }
}

/** Weekly points for the last 12 weeks. */
function timeline(bucket: "week" | "month"): OutcomeTimeline {
  const weeks = bucket === "week" ? 12 : 6
  const step = bucket === "week" ? WEEK_MS : 30 * 86_400_000
  const shape = [1, 2, 1, 3, 2, 4, 3, 2, 5, 4, 6, 3]
  const points = Array.from({ length: weeks }, (_, i) => {
    const d = new Date(Date.now() - (weeks - 1 - i) * step)
    d.setUTCHours(0, 0, 0, 0)
    const n = (shape[i % shape.length] ?? 1) * (bucket === "month" ? 3 : 1)
    const sent = {
      attack_source: n,
      payload_host: Math.round(n / 3),
      c2: i % 3 === 0 ? 1 : 0,
    }
    return {
      start: d.toISOString(),
      sent,
      sent_total: sent.attack_source + sent.payload_host + sent.c2,
      answered: Math.round(n * 0.45),
      resolved: Math.round(n * 0.15),
    }
  })
  return {
    bucket,
    since: points[0]?.start ?? new Date().toISOString(),
    until: new Date().toISOString(),
    points,
  }
}

/** M38: the demo node is still below the minimum at 30 days, measured at 7. */
function effect(horizon: 7 | 30): ReportEffectResponse {
  const enough = horizon === 7
  return {
    since: new Date(Date.now() - 90 * 86_400_000).toISOString(),
    until: new Date().toISOString(),
    available: true,
    running: true,
    effect: enough
      ? {
          horizon,
          verdict: "no_clear_difference",
          pairs: 84,
          needed: 30,
          discordant: 30,
          needed_discordant: 10,
          seen_reported: 44 / 84,
          seen_control: 46 / 84,
          difference: -2 / 84,
          lo: -0.15,
          hi: 0.1,
          sentence:
            "No clear difference yet: 52 % of reported sources and 55 % of similar unreported sources were still seen a week later (84 pairs). The gap could be chance.",
          interval: "between 15 points lower and 10 points higher for reported sources",
        }
      : {
          horizon,
          verdict: "not_enough_data",
          pairs: 12,
          needed: 30,
          discordant: 5,
          needed_discordant: 10,
          seen_reported: null,
          seen_control: null,
          difference: null,
          lo: null,
          hi: null,
          sentence: "Not enough data yet to tell whether reports help: 12 of 30 comparable pairs.",
          interval: null,
        },
    method: {
      pairs_made: 97,
      tiers: { A: 41, B: 30, C: 26 },
      waiting: 9,
      not_observed: 3,
      control_reported: 1,
      network_reported: 0,
      unmatched: 14,
      unmatched_reasons: { no_control: 11, no_activity: 3 },
      holdout_pct: 0,
      held_now: 0,
    },
  }
}

export const resultsHandlers: RequestHandler[] = [
  http.get("/api/v1/results/effect", async ({ request }) => {
    await delay(LATENCY_MS)
    const h = new URL(request.url).searchParams.get("horizon") === "30" ? 30 : 7
    return HttpResponse.json(effect(h))
  }),
  http.get("/api/v1/abuse/outcomes/timeline", async ({ request }) => {
    await delay(LATENCY_MS)
    const b = new URL(request.url).searchParams.get("bucket")
    return HttpResponse.json(timeline(b === "month" ? "month" : "week"))
  }),
  http.get("/api/v1/abuse/outcomes", async ({ request }) => {
    await delay(LATENCY_MS)
    const group = (new URL(request.url).searchParams.get("group") ?? "asn") as OutcomeGroup
    const res: OutcomesResponse = {
      since: new Date(Date.now() - 90 * 86_400_000).toISOString(),
      until: new Date().toISOString(),
      group,
      totals: totals(),
      groups: groups(group),
    }
    return HttpResponse.json(res)
  }),
]
