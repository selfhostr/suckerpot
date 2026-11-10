import { describe, expect, it } from "vitest"
import type { ReportOutcome } from "./replies"
import {
  defang,
  describeAnswers,
  describeBounds,
  describeCurve,
  describeDelay,
  describeOutcome,
  describeRepliesToCheck,
  describeSentOverTime,
  describeTakedownHeader,
  describeTakedownProviders,
  describeTarget,
  describeTtd,
  longDelay,
  shortDelay,
} from "./results-sentences"
import type {
  OutcomeGroupRow,
  OutcomeTotals,
  ProviderRow,
  TakedownCounts,
  TakedownSummary,
  TargetDetail,
  TimelinePoint,
} from "./results"

const H = 3600

const totals = (over: Partial<OutcomeTotals> = {}): OutcomeTotals => ({
  sent: 23,
  eligible: 23,
  answered: 9,
  no_answer: 10,
  by_outcome: {},
  first_reply_p50_s: 3 * H,
  first_reply_p90_s: 30 * H,
  resolved_p50_s: null,
  ...over,
})

const group = (over: Partial<OutcomeGroupRow>): OutcomeGroupRow => ({
  key: "64500",
  label: "AS64500",
  sent: 2,
  eligible: 2,
  answered: 0,
  by_outcome: {},
  first_reply_p50_s: null,
  ...over,
})

const point = (start: string, n: number): TimelinePoint => ({
  start,
  sent: { attack_source: n, payload_host: 0, c2: 0 },
  sent_total: n,
  answered: 0,
  resolved: 0,
})

const counts = (over: Partial<TakedownCounts> = {}): TakedownCounts => ({
  tracked: 31,
  eligible_48h: 31,
  down_48h: 12,
  eligible_7d: 28,
  down_7d: 16,
  eligible_30d: 20,
  down_30d: 19,
  ttd_p50_s: 19 * H,
  ttd_n: 12,
  still_up_30d: 3,
  ...over,
})

const summary = (over: Partial<TakedownSummary> = {}): TakedownSummary => ({
  since: "2026-09-12T12:00:00Z",
  until: "2026-11-01T12:00:00Z",
  urls: counts(),
  hosts: counts({ tracked: 8 }),
  attack_sources: { tracked: 4, quiet: 3, active: 1 },
  c2: { tracked: 2, still_used: 1 },
  reports: { sent: 23, answered: 9, first_reply_p50_s: 3 * H },
  ...over,
})

describe("delays", () => {
  it("picks the shortest honest unit", () => {
    expect(shortDelay(40 * 60)).toBe("40 min")
    expect(shortDelay(19 * H)).toBe("19 h")
    expect(shortDelay(5 * 86_400)).toBe("5 days")
    expect(longDelay(3 * H)).toBe("3 hours")
    expect(longDelay(H)).toBe("1 hour")
  })
})

describe("defang", () => {
  it("never leaves a live link", () => {
    expect(defang("http://198.51.100.9/x.sh")).toBe("hxxp://198[.]51[.]100[.]9/x[.]sh")
    expect(defang("https://example.org/a")).toBe("hxxps://example[.]org/a")
  })
})

describe("describeSentOverTime", () => {
  const now = new Date(2026, 9, 20)
  it("compares with the previous month", () => {
    const pts = [
      point("2026-09-07T00:00:00", 9),
      point("2026-10-05T00:00:00", 6),
      point("2026-10-12T00:00:00", 8),
    ]
    expect(describeSentOverTime(pts, now)).toBe("You sent 14 so far in October (September: 9).")
  })
  it("says fewer and handles no previous month", () => {
    expect(
      describeSentOverTime([point("2026-09-07T00:00:00", 9), point("2026-10-05T00:00:00", 2)], now),
    ).toBe("You sent 2 so far in October (September: 9).")
    expect(describeSentOverTime([point("2026-10-05T00:00:00", 1)], now)).toBe(
      "You sent 1 report in October.",
    )
  })
  it("handles nothing sent", () => {
    expect(describeSentOverTime([], now)).toBe("No report was sent in this period.")
  })
})

describe("describeAnswers", () => {
  it("counts providers, tickets and actions", () => {
    const groups = [
      ...Array.from({ length: 4 }, (_, i) =>
        group({ key: `t${i}`, answered: 1, by_outcome: { ticket_opened: 1 } }),
      ),
      group({ key: "r1", answered: 1, by_outcome: { resolved: 1 } }),
      group({ key: "r2", answered: 1, by_outcome: { resolved: 1 } }),
      ...Array.from({ length: 3 }, (_, i) => group({ key: `h${i}`, answered: 1 })),
      ...Array.from({ length: 14 }, (_, i) => group({ key: `n${i}` })),
    ]
    expect(describeAnswers(totals(), groups)).toBe(
      "9 of 23 providers answered; 4 opened a ticket and 2 said they acted.",
    )
  })
  it("waits for reports to be old enough", () => {
    expect(describeAnswers(totals({ eligible: 0, answered: 0 }), [])).toMatch(/too recent/)
  })
  it("handles nobody answering and nothing sent", () => {
    expect(describeAnswers(totals(), [group({}), group({ key: "2" })])).toBe(
      "None of the 2 providers has answered yet.",
    )
    expect(describeAnswers(totals({ sent: 0 }), [])).toBe("No report has been sent in this period.")
  })
})

describe("describeDelay", () => {
  it("states the median", () => {
    expect(describeDelay(totals())).toBe(
      "Half of the first answers came within 3 hours, nine in ten within 30 hours.",
    )
    expect(describeDelay(totals({ first_reply_p50_s: null }))).toMatch(
      /No report has been answered/,
    )
  })
})

describe("describeOutcome", () => {
  const sentAt = "2026-10-20T10:00:00Z"
  const base: ReportOutcome = {
    effective: "ticket_opened",
    auto: "ticket_opened",
    manual: null,
    no_answer: false,
    first_reply_after_s: 3600,
    manual_by: null,
    manual_at: null,
    note: null,
    needs_review: false,
    reply_count: 2,
    first_reply_at: "2026-10-20T11:00:00Z",
    first_human_at: null,
    ticket_at: "2026-10-20T12:00:00Z",
    resolved_at: null,
    rejected_at: null,
    bounced_at: null,
    ticket_id: "48213",
  }
  it("names the ticket and the delay", () => {
    expect(describeOutcome(base, sentAt)).toBe(
      "The provider opened ticket 48213, 2 hours after you sent this report.",
    )
  })
  it("says how long nothing came back", () => {
    const none = { ...base, effective: "none" as const }
    expect(describeOutcome(none, sentAt, new Date("2026-11-05T10:00:00Z"))).toBe(
      "No answer after 16 days.",
    )
    expect(describeOutcome(none, sentAt, new Date("2026-10-21T10:00:00Z"))).toMatch(/No answer yet/)
  })
  it("explains a bounce", () => {
    const b = { ...base, effective: "bounce" as const, bounced_at: "2026-10-20T10:05:00Z" }
    expect(describeOutcome(b, sentAt)).toMatch(/^Your report bounced, 5 minutes after/)
  })
})

describe("describeRepliesToCheck", () => {
  it("agrees in number", () => {
    expect(describeRepliesToCheck(3)).toBe("3 replies need a look.")
    expect(describeRepliesToCheck(1)).toBe("1 reply needs a look.")
  })
})

describe("takedown sentences", () => {
  it("opens the page with the headline", () => {
    expect(describeTakedownHeader(summary(), null)).toMatch(
      /^Since .+ you reported 31 malware URLs; 12 of the \d+ followed for 48 hours went down within that time, and 19 within 30 days\.$/,
    )
  })
  it("covers disabled and empty", () => {
    expect(describeTakedownHeader({ ...summary(), enabled: false }, null)).toBe(
      "Takedown tracking is off (TAKEDOWN_ENABLED).",
    )
    const empty = summary({
      urls: counts({ tracked: 0 }),
      hosts: counts({ tracked: 0 }),
      reports: { sent: 0, answered: null, first_reply_p50_s: null },
    })
    expect(describeTakedownHeader(empty, null)).toBe(
      "Nothing reported yet. Takedowns appear here after your first report.",
    )
  })
  it("describes the curve with censoring", () => {
    expect(describeCurve(summary())).toBe("12 of 31 reported malware URLs went down within 48 h.")
    expect(describeCurve(summary({ urls: counts({ eligible_48h: 0 }) }))).toMatch(/too early/)
  })
  it("needs five values for a median", () => {
    expect(describeTtd({ ttd_p50_s: 19 * H, ttd_n: 12 })).toBe("Across 12 URLs taken down")
    expect(describeTtd({ ttd_p50_s: 19 * H, ttd_n: 3 })).toBe("Not enough data yet")
  })
  it("names the fastest provider", () => {
    const row: ProviderRow = {
      provider_key: "as64500",
      name: "EXAMPLE-NET",
      asn: 64500,
      country: "NL",
      targets: 6,
      eligible_48h: 6,
      down_48h: 4,
      percent_48h: 4 / 6,
      eligible_30d: 6,
      down_30d: 5,
      percent_30d: 5 / 6,
      ttd_p50_s: 7 * H,
      ttd_n: 5,
      still_up: 1,
      reports_sent: 4,
      reports_answered: 2,
      percent_answered: 0.5,
      first_reply_p50_s: 2 * H,
    }
    expect(describeTakedownProviders([row])).toBe(
      "EXAMPLE-NET (AS64500) took down 5 of 6 targets, the fastest median in your reports (7 h).",
    )
  })
  it("never promises a C2 takedown", () => {
    const t = {
      target: { role: "c2", reported_at: "2026-10-01T00:00:00Z" },
      checks: [],
    } as unknown as TargetDetail
    expect(describeTarget(t)).toMatch(/never contact C2 servers/)
  })
  it("reads the state of a payload URL", () => {
    const t = {
      target: { role: "payload_url", state: "up", reported_at: "2026-10-27T10:00:00Z" },
      checks: [],
    } as unknown as TargetDetail
    expect(describeTarget(t, new Date("2026-10-30T10:00:00Z"))).toBe(
      "Still serving the same file 3 days after the report.",
    )
  })
  it("gives the bounds of a takedown", () => {
    expect(
      describeBounds({ seconds: 19 * H, down_after: "a", down_before: "b" }, (s) =>
        s === "a" ? "14:00" : "20:00",
      ),
    ).toBe("down between 14:00 and 20:00, 19 h after the report")
    expect(
      describeBounds({ seconds: null, down_after: null, down_before: null }, String),
    ).toBeNull()
  })
})
