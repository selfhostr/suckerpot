/**
 * The plain-English sentences of the Results page, the outcome card and the target page
 * (docs/design/m26.md section 12, docs/design/m27.md section 12). Pure functions: every card opens
 * with one of these, and the tests pin the wording.
 */
import { plural } from "./format"
import { NO_ANSWER_DAYS, OUTCOME_LABEL, type Outcome, type ReportOutcome } from "./replies"
import type {
  OutcomeGroupRow,
  OutcomeTotals,
  ProviderRow,
  TakedownSummary,
  TargetDetail,
  TimelinePoint,
} from "./results"

const HOUR = 3600
const DAY = 86_400

/** "defanged" text for a URL, host or address: never a live link. */
export function defang(value: string): string {
  return value.replace(/^http(s?):\/\//i, (_, s: string) => `hxxp${s}://`).replace(/\./g, "[.]")
}

/** "40 min", "19 h", "3 days": a delay in the shortest honest unit. */
export function shortDelay(seconds: number): string {
  const s = Math.max(0, seconds)
  if (s < HOUR) return `${Math.max(1, Math.round(s / 60))} min`
  if (s < 48 * HOUR) return `${Math.round(s / HOUR)} h`
  return `${Math.round(s / DAY)} days`
}

/** "40 minutes", "3 hours", "2 days": the same, spelled out for a sentence. */
export function longDelay(seconds: number): string {
  const s = Math.max(0, seconds)
  if (s < HOUR) return plural(Math.max(1, Math.round(s / 60)), "minute")
  if (s < 48 * HOUR) return plural(Math.round(s / HOUR), "hour")
  return plural(Math.round(s / DAY), "day")
}

const monthName = new Intl.DateTimeFormat("en-US", { month: "long" })
const dayMonth = new Intl.DateTimeFormat("en-US", { day: "numeric", month: "long" })

/** "12 September", in the browser time zone. */
export function formatDayMonth(iso: string): string {
  return dayMonth.format(new Date(iso))
}

// --- M26 ----------------------------------------------------------------------------

const sentIn = (p: TimelinePoint) => p.sent_total

/** "You sent 14 reports in October, 5 more than in September." */
export function describeSentOverTime(points: readonly TimelinePoint[], now: Date): string {
  const byMonth = new Map<string, number>()
  for (const p of points) {
    const d = new Date(p.start)
    const key = `${d.getFullYear()}-${String(d.getMonth()).padStart(2, "0")}`
    byMonth.set(key, (byMonth.get(key) ?? 0) + sentIn(p))
  }
  const keyOf = (d: Date) => `${d.getFullYear()}-${String(d.getMonth()).padStart(2, "0")}`
  const total = [...byMonth.values()].reduce((a, b) => a + b, 0)
  if (total === 0) return "No report was sent in this period."
  // The current month, or the latest earlier month that has reports.
  let cursor = new Date(now.getFullYear(), now.getMonth(), 1)
  for (let i = 0; i < 24 && !(byMonth.get(keyOf(cursor)) ?? 0); i++)
    cursor = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1)
  const n = byMonth.get(keyOf(cursor)) ?? 0
  const prevDate = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1)
  const prev = byMonth.get(keyOf(prevDate))
  const head = `You sent ${plural(n, "report")} in ${monthName.format(cursor)}`
  const running = keyOf(cursor) === keyOf(now)
  if (running && prev !== undefined && prev > 0)
    return `You sent ${n} so far in ${monthName.format(cursor)} (${monthName.format(prevDate)}: ${prev}).`
  if (prev === undefined || prev === 0) return `${head}.`
  const diff = n - prev
  if (diff === 0) return `${head}, as many as in ${monthName.format(prevDate)}.`
  return `${head}, ${Math.abs(diff)} ${diff > 0 ? "more" : "fewer"} than in ${monthName.format(prevDate)}.`
}

/** "9 of 23 providers answered; 4 opened a ticket and 2 said they acted." */
export function describeAnswers(totals: OutcomeTotals, groups: readonly OutcomeGroupRow[]): string {
  if (totals.sent === 0) return "No report has been sent in this period."
  if (totals.eligible === 0)
    return "Your reports are too recent to judge: answers are counted after 3 days."
  const judged = groups.filter((g) => g.eligible > 0)
  const providers = judged.length
  const answered = judged.filter((g) => g.answered > 0).length
  const tickets = judged.filter((g) => (g.by_outcome.ticket_opened ?? 0) > 0).length
  const acted = judged.filter((g) => (g.by_outcome.resolved ?? 0) > 0).length
  if (providers === 0) {
    return `${totals.answered} of ${plural(totals.eligible, "report")} sent at least 3 days ago got an answer.`
  }
  if (answered === 0) {
    return `None of the ${plural(providers, "provider")} has answered yet.`
  }
  const parts: string[] = []
  if (tickets > 0) parts.push(`${tickets} opened a ticket`)
  if (acted > 0) parts.push(`${acted} said they acted`)
  return `${answered} of ${plural(providers, "provider")} answered${parts.length ? `; ${parts.join(" and ")}` : ""}.`
}

/** "Half of the first answers came within 3 hours." */
export function describeDelay(totals: OutcomeTotals): string {
  if (totals.first_reply_p50_s == null)
    return "No report has been answered yet, so there is no delay to show."
  const half = `Half of the first answers came within ${longDelay(totals.first_reply_p50_s)}`
  if (totals.first_reply_p90_s == null) return `${half}.`
  return `${half}, nine in ten within ${longDelay(totals.first_reply_p90_s)}.`
}

/** The opening sentence of a providers table of M26. */
export function describeProviderAnswers(rows: readonly OutcomeGroupRow[]): string {
  const withReply = rows.filter((r) => r.first_reply_p50_s != null && r.sent >= 2)
  if (rows.length === 0) return "No provider has received a report yet."
  const best = [...withReply].sort(
    (a, b) => (a.first_reply_p50_s ?? 0) - (b.first_reply_p50_s ?? 0),
  )[0]
  if (best?.first_reply_p50_s == null)
    return `${plural(rows.length, "provider")} received reports; none has answered twice yet.`
  return `${best.label} answers fastest: half of its answers came within ${longDelay(best.first_reply_p50_s)}.`
}

/** Outcome card of one report. `sentAt` is the send time; `now` is injected for tests. */
export function describeOutcome(
  o: ReportOutcome | null | undefined,
  sentAt: string | null,
  now: Date = new Date(),
): string {
  const sent = sentAt ? Date.parse(sentAt) : null
  const after = (iso: string | null) =>
    iso && sent != null
      ? `, ${longDelay((Date.parse(iso) - sent) / 1000)} after you sent this report`
      : ""
  if (!o || o.effective === "none") {
    if (sent == null) return "This report was not sent yet."
    const days = Math.floor((now.getTime() - sent) / (DAY * 1000))
    if (o?.no_answer || days >= NO_ANSWER_DAYS) return `No answer after ${plural(days, "day")}.`
    return "No answer yet. Replies appear here when they arrive."
  }
  switch (o.effective) {
    case "resolved":
      return `The provider said it acted${after(o.resolved_at)}.`
    case "rejected":
      return `The provider rejected this report${after(o.rejected_at)}.`
    case "ticket_opened":
      return `The provider opened ${o.ticket_id ? `ticket ${o.ticket_id}` : "a ticket"}${after(o.ticket_at)}.`
    case "human_reply":
      return `A person at the provider answered${after(o.first_human_at)}.`
    case "auto_ack":
      return `Only an automatic receipt came back${after(o.first_reply_at)}.`
    case "bounce":
      return `Your report bounced${after(o.bounced_at)}. Try another mailbox for this provider.`
    default:
      return `A reply arrived${after(o.first_reply_at)}, but it was not understood. Read it below.`
  }
}

/** Short label for an outcome in a column. */
export function outcomeWord(o: Outcome, sentAt?: string | null, now: Date = new Date()): string {
  if (o === "none" && sentAt) {
    const days = (now.getTime() - Date.parse(sentAt)) / (DAY * 1000)
    if (days >= NO_ANSWER_DAYS) return "No answer"
  }
  return OUTCOME_LABEL[o]
}

/** Banner above the reports: "3 replies need a look." */
export function describeRepliesToCheck(n: number): string {
  return `${plural(n, "reply", "replies")} ${n === 1 ? "needs" : "need"} a look.`
}

// --- M27 ----------------------------------------------------------------------------

/** The header finding of the Results page. */
export function describeTakedownHeader(
  s: TakedownSummary | undefined,
  since: string | null,
): string {
  if (!s) return "Reports you send, the answers you get and what comes down."
  if (s.enabled === false) return "Takedown tracking is off (TAKEDOWN_ENABLED)."
  const c = s.urls
  if (c.tracked === 0 && s.hosts.tracked === 0 && s.reports.sent === 0)
    return "Nothing reported yet. Takedowns appear here after your first report."
  if (c.tracked === 0)
    return `Since ${formatDayMonth(since ?? s.since)} you sent ${plural(s.reports.sent, "report")}; no payload URL is tracked yet.`
  return `Since ${formatDayMonth(since ?? s.since)} you reported ${plural(c.tracked, "malware URL")}; ${c.down_48h} of the ${c.eligible_48h} followed for 48 hours went down within that time, and ${c.down_30d} within 30 days.`
}

/** "12 of 31 reported malware URLs went down within 48 h." */
export function describeCurve(s: TakedownSummary | undefined): string {
  if (!s) return "How fast reported malware URLs go down."
  const c = s.urls
  if (c.eligible_48h === 0)
    return "It is too early to say: no reported URL has been followed for 48 hours yet."
  return `${c.down_48h} of ${c.eligible_48h} reported malware ${c.eligible_48h === 1 ? "URL" : "URLs"} went down within 48 h.`
}

/** Hint of the "median time to takedown" tile; the tile shows the value itself. */
export function describeTtd(c: { ttd_p50_s: number | null; ttd_n: number }): string {
  if (c.ttd_p50_s == null || c.ttd_n < 5) return "Not enough data yet"
  return `Across ${plural(c.ttd_n, "URL")} taken down`
}

/** "AS64500 took down 5 of 6 URLs, the fastest median in your reports (7 h)." */
export function describeTakedownProviders(rows: readonly ProviderRow[]): string {
  const ranked = rows.filter((r) => r.ttd_p50_s != null && r.targets >= 3)
  if (rows.length === 0) return "No provider has a tracked target yet."
  const best = [...ranked].sort((a, b) => (a.ttd_p50_s ?? 0) - (b.ttd_p50_s ?? 0))[0]
  if (best?.ttd_p50_s == null)
    return `${plural(rows.length, "provider")} host reported targets; none has three taken down yet.`
  const name = best.asn != null ? `${best.name} (AS${best.asn})` : best.name
  const down = Math.round((best.percent_30d ?? 0) * best.targets)
  return `${name} took down ${down} of ${plural(best.targets, "target")}, the fastest median in your reports (${shortDelay(best.ttd_p50_s)}).`
}

/** The sentence of a target page. */
export function describeTarget(d: TargetDetail, now: Date = new Date()): string {
  const t = d.target
  if (t.role === "c2")
    return "We never contact C2 servers; this shows whether new malware still points to it."
  if (t.role === "attack_source") {
    if (t.state === "up") return "Still attacking after the report."
    if (t.state === "down") return "Quiet since the report: nothing seen from this address."
    return "Not enough activity to say whether it stopped."
  }
  const days = Math.floor((now.getTime() - Date.parse(t.reported_at)) / (DAY * 1000))
  if (t.state === "changed") {
    const last = d.checks.find((c) => c.outcome === "changed" || c.outcome === "new_sample")
    return last
      ? `Serves a different file since ${formatDayMonth(last.checked_at)} (a new sample).`
      : "Serves a different file than the one reported."
  }
  if (t.state === "down") {
    return t.ttd_s != null
      ? `Down ${shortDelay(t.ttd_s)} after the report.`
      : "Down since the report."
  }
  if (t.state === "up")
    return days >= 1
      ? `Still serving the same file ${plural(days, "day")} after the report.`
      : "Still serving the same file."
  return "Not checked yet."
}

/** "down between 14:00 and 20:00, 19 h after the report" */
export function describeBounds(
  t: TargetDetail["ttd"],
  clock: (iso: string) => string,
): string | null {
  if (t.seconds == null) return null
  const range =
    t.down_after && t.down_before
      ? `down between ${clock(t.down_after)} and ${clock(t.down_before)}, `
      : "down "
  return `${range}${shortDelay(t.seconds)} after the report`
}

/** "1 h", "2 days", "30 days" for a tick of the curve. */
export function hoursLabel(h: number): string {
  if (h < 24) return `${h} h`
  const d = Math.round(h / 24)
  return `${d} ${d === 1 ? "day" : "days"}`
}
