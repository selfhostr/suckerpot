/**
 * The plain-English sentences of the Results page, the outcome card and the target page
 * (docs/dev/design/m26.md section 12, docs/dev/design/m27.md section 12). Pure functions: every card opens
 * with one of these, and the tests pin the wording.
 */
import { intlLocale, t } from "@/i18n"
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
  if (s < HOUR) return t("results_delay_short_min", { count: Math.max(1, Math.round(s / 60)) })
  if (s < 48 * HOUR) return t("results_delay_short_hour", { count: Math.round(s / HOUR) })
  return t("results_delay_short_day", { count: Math.round(s / DAY) })
}

/** "40 minutes", "3 hours", "2 days": the same, spelled out for a sentence. */
export function longDelay(seconds: number): string {
  const s = Math.max(0, seconds)
  if (s < HOUR) return t("results_delay_long_min", { count: Math.max(1, Math.round(s / 60)) })
  if (s < 48 * HOUR) return t("results_delay_long_hour", { count: Math.round(s / HOUR) })
  return t("results_delay_long_day", { count: Math.round(s / DAY) })
}

const monthName = (d: Date): string =>
  new Intl.DateTimeFormat(intlLocale(), { month: "long" }).format(d)

/** "12 September", in the browser time zone. */
export function formatDayMonth(iso: string): string {
  return new Intl.DateTimeFormat(intlLocale(), { day: "numeric", month: "long" }).format(
    new Date(iso),
  )
}

// --- M26 ----------------------------------------------------------------------------

const sentIn = (p: TimelinePoint) => p.sent_total

/** Reports sent in the current month (or the latest one with reports) and in the month before. */
export function monthComparison(
  points: readonly TimelinePoint[],
  now: Date,
): { month: string; sent: number; previousMonth: string; previous: number; running: boolean } {
  const keyOf = (d: Date) => `${d.getFullYear()}-${d.getMonth()}`
  const byMonth = new Map<string, number>()
  for (const p of points) {
    const k = keyOf(new Date(p.start))
    byMonth.set(k, (byMonth.get(k) ?? 0) + sentIn(p))
  }
  let cursor = new Date(now.getFullYear(), now.getMonth(), 1)
  for (let i = 0; i < 24 && !(byMonth.get(keyOf(cursor)) ?? 0); i++)
    cursor = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1)
  const prev = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1)
  return {
    month: monthName(cursor),
    sent: byMonth.get(keyOf(cursor)) ?? 0,
    previousMonth: monthName(prev),
    previous: byMonth.get(keyOf(prev)) ?? 0,
    running: keyOf(cursor) === keyOf(now),
  }
}

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
  if (total === 0) return t("results_sent_none")
  // The current month, or the latest earlier month that has reports.
  let cursor = new Date(now.getFullYear(), now.getMonth(), 1)
  for (let i = 0; i < 24 && !(byMonth.get(keyOf(cursor)) ?? 0); i++)
    cursor = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1)
  const n = byMonth.get(keyOf(cursor)) ?? 0
  const prevDate = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1)
  const prev = byMonth.get(keyOf(prevDate))
  const month = monthName(cursor)
  const previousMonth = monthName(prevDate)
  const running = keyOf(cursor) === keyOf(now)
  if (running && prev !== undefined && prev > 0)
    return t("results_sent_running", { count: n, month, previousMonth, previous: prev })
  if (prev === undefined || prev === 0) return t("results_sent_only", { count: n, month })
  const diff = n - prev
  if (diff === 0) return t("results_sent_same", { count: n, month, previousMonth })
  return diff > 0
    ? t("results_sent_more", { count: n, month, previousMonth, diff: Math.abs(diff) })
    : t("results_sent_fewer", { count: n, month, previousMonth, diff: Math.abs(diff) })
}

/** "9 of 23 providers answered; 4 opened a ticket and 2 said they acted." */
export function describeAnswers(totals: OutcomeTotals, groups: readonly OutcomeGroupRow[]): string {
  if (totals.sent === 0) return t("results_answers_none_sent")
  if (totals.eligible === 0) return t("results_answers_too_recent")
  const judged = groups.filter((g) => g.eligible > 0)
  const providers = judged.length
  const answered = judged.filter((g) => g.answered > 0).length
  const tickets = judged.filter((g) => (g.by_outcome.ticket_opened ?? 0) > 0).length
  const acted = judged.filter((g) => (g.by_outcome.resolved ?? 0) > 0).length
  if (providers === 0) {
    return t("results_answers_by_reports", { answered: totals.answered, count: totals.eligible })
  }
  if (answered === 0) {
    return t("results_answers_none_yet", { count: providers })
  }
  const detail =
    tickets > 0 && acted > 0 ? "both" : tickets > 0 ? "tickets" : acted > 0 ? "acted" : "none"
  return t("results_answers_summary", { answered, count: providers, detail, tickets, acted })
}

/** The opening sentence of a providers table of M26. */
export function describeProviderAnswers(rows: readonly OutcomeGroupRow[]): string {
  const withReply = rows.filter((r) => r.first_reply_p50_s != null && r.sent >= 2)
  if (rows.length === 0) return t("results_providers_none")
  const best = [...withReply].sort(
    (a, b) => (a.first_reply_p50_s ?? 0) - (b.first_reply_p50_s ?? 0),
  )[0]
  if (best?.first_reply_p50_s == null)
    return t("results_providers_none_twice", { count: rows.length })
  return t("results_providers_fastest", {
    label: best.label,
    delay: longDelay(best.first_reply_p50_s),
  })
}

/** Outcome card of one report. `sentAt` is the send time; `now` is injected for tests. */
export function describeOutcome(
  o: ReportOutcome | null | undefined,
  sentAt: string | null,
  now: Date = new Date(),
): string {
  const sent = sentAt ? Date.parse(sentAt) : null
  const after = (iso: string | null) => ({
    after: iso && sent != null ? "yes" : "no",
    delay: iso && sent != null ? longDelay((Date.parse(iso) - sent) / 1000) : "",
  })
  if (!o || o.effective === "none") {
    if (sent == null) return t("results_outcome_unsent")
    const days = Math.floor((now.getTime() - sent) / (DAY * 1000))
    if (o?.no_answer || days >= NO_ANSWER_DAYS)
      return t("results_outcome_no_answer_after", { count: days })
    return t("results_outcome_no_answer_yet")
  }
  switch (o.effective) {
    case "resolved":
      return t("results_outcome_resolved", after(o.resolved_at))
    case "rejected":
      return t("results_outcome_rejected", after(o.rejected_at))
    case "ticket_opened":
      return t("results_outcome_ticket", {
        ...after(o.ticket_at),
        hasId: o.ticket_id ? "yes" : "no",
        id: o.ticket_id ?? "",
      })
    case "human_reply":
      return t("results_outcome_human", after(o.first_human_at))
    case "auto_ack":
      return t("results_outcome_auto_ack", after(o.first_reply_at))
    case "bounce":
      return t("results_outcome_bounce", after(o.bounced_at))
    default:
      return t("results_outcome_unknown", after(o.first_reply_at))
  }
}

/** Short label for an outcome in a column. */
export function outcomeWord(o: Outcome, sentAt?: string | null, now: Date = new Date()): string {
  if (o === "none" && sentAt) {
    const days = (now.getTime() - Date.parse(sentAt)) / (DAY * 1000)
    if (days >= NO_ANSWER_DAYS) return t("results_outcome_no_answer")
  }
  return OUTCOME_LABEL[o]
}

/** Banner above the reports: "3 replies need a look." */
export function describeRepliesToCheck(n: number): string {
  return t("results_replies_to_check", { count: n })
}

// --- M27 ----------------------------------------------------------------------------

/** The header finding of the Results page. */
export function describeTakedownHeader(
  s: TakedownSummary | undefined,
  since: string | null,
): string {
  if (!s) return t("results_header_default")
  if (s.enabled === false) return t("results_header_off")
  const c = s.urls
  if (c.tracked === 0 && s.hosts.tracked === 0 && s.reports.sent === 0)
    return t("results_header_nothing")
  const date = formatDayMonth(since ?? s.since)
  if (c.tracked === 0) return t("results_header_no_urls", { date, count: s.reports.sent })
  return t("results_header_summary", {
    date,
    count: c.tracked,
    down48: c.down_48h,
    eligible48: c.eligible_48h,
    down30: c.down_30d,
  })
}

/** Hint of the "median time to takedown" tile; the tile shows the value itself. */
export function describeTtd(c: { ttd_p50_s: number | null; ttd_n: number }): string {
  if (c.ttd_p50_s == null || c.ttd_n < 5) return t("results_ttd_not_enough")
  return t("results_ttd_across", { count: c.ttd_n })
}

/** "AS64500 took down 5 of 6 URLs, the fastest median in your reports (7 h)." */
export function describeTakedownProviders(rows: readonly ProviderRow[]): string {
  const ranked = rows.filter((r) => r.ttd_p50_s != null && r.targets >= 3)
  if (rows.length === 0) return t("results_takedown_providers_none")
  const best = [...ranked].sort((a, b) => (a.ttd_p50_s ?? 0) - (b.ttd_p50_s ?? 0))[0]
  if (best?.ttd_p50_s == null)
    return t("results_takedown_providers_none_three", { count: rows.length })
  const name = best.asn != null ? `${best.name} (AS${best.asn})` : best.name
  const down = Math.round((best.percent_30d ?? 0) * best.targets)
  return t("results_takedown_providers_best", {
    name,
    down,
    count: best.targets,
    delay: shortDelay(best.ttd_p50_s),
  })
}

/** The sentence of a target page. */
export function describeTarget(d: TargetDetail, now: Date = new Date()): string {
  const tg = d.target
  if (tg.role === "c2") return t("results_target_c2")
  if (tg.role === "attack_source") {
    if (tg.state === "up") return t("results_target_attack_up")
    if (tg.state === "down") return t("results_target_attack_down")
    return t("results_target_attack_unknown")
  }
  const days = Math.floor((now.getTime() - Date.parse(tg.reported_at)) / (DAY * 1000))
  if (tg.state === "changed") {
    const last = d.checks.find((c) => c.outcome === "changed" || c.outcome === "new_sample")
    return last
      ? t("results_target_changed_since", { date: formatDayMonth(last.checked_at) })
      : t("results_target_changed")
  }
  if (tg.state === "down") {
    return tg.ttd_s != null
      ? t("results_target_down_after", { delay: shortDelay(tg.ttd_s) })
      : t("results_target_down")
  }
  if (tg.state === "up")
    return days >= 1 ? t("results_target_up_days", { count: days }) : t("results_target_up")
  return t("results_target_unchecked")
}

/** "down between 14:00 and 20:00, 19 h after the report" */
export function describeBounds(
  tt: TargetDetail["ttd"],
  clock: (iso: string) => string,
): string | null {
  if (tt.seconds == null) return null
  const delay = shortDelay(tt.seconds)
  return tt.down_after && tt.down_before
    ? t("results_bounds_between", { from: clock(tt.down_after), to: clock(tt.down_before), delay })
    : t("results_bounds_after", { delay })
}
