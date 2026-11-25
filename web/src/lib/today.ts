/** The Today page: types mirror api/api/today.py. */
import type { OutboxItem } from "./alerts"
import { getJson } from "./api"
import { tk, t } from "@/i18n"
import { formatRelative } from "./format"

export type TodayCardId = "happened" | "forms" | "campaigns" | "act" | "new_week" | "exposure"
export type TodayItemKind =
  "sensor" | "country" | "tag" | "campaign" | "host" | "session" | "service" | "new"

export interface TodayItem {
  kind: TodayItemKind
  value: string
  label: string
  detail: string | null
  count: number | null
  /** A UI route with its filters. */
  to: string
}

export interface TodayCardData {
  id: TodayCardId
  /** One plain-English sentence written by the API. */
  sentence: string
  items: TodayItem[]
  action: { label: string; to: string }
  empty: boolean
}

export interface FormQueueCount {
  reports: number
  providers: number
}

export interface TodayResponse {
  generated_at: string
  window_hours: number
  hidden_benign: number
  cards: TodayCardData[]
  /** Form reports still to submit (M38). Admins only; null or absent when none waits. */
  form_queue?: FormQueueCount | null
}

export interface BenignCount {
  window_hours: number
  sessions: number
  sources: number
}

export const todayApi = {
  today: () => getJson<TodayResponse>("/today"),
  benignCount: () => getJson<BenignCount>("/stats/benign"),
}

export const todayKeys = {
  today: ["today"] as const,
  benign: ["stats", "benign"] as const,
}

/**
 * The cards' small headings, as message keys (render them with t()); the sentence below each one
 * carries the finding.
 */
export const CARD_TITLE: Record<TodayCardId, string> = {
  happened: tk("today_card_happened"),
  forms: tk("today_card_forms"),
  campaigns: tk("today_card_campaigns"),
  act: tk("today_card_act"),
  new_week: tk("today_card_new_week"),
  exposure: tk("today_card_exposure"),
}

/** What needs doing first: form reports that wait on the owner, then servers to block. */
const TODO_ORDER: readonly TodayCardId[] = ["forms", "act", "campaigns", "new_week", "exposure"]

/** At most this many to-do items on Today: a glance, not a list. */
export const TODO_LIMIT = 3

/**
 * The to-do items of Today, from the cards of GET /today: "what happened" is the page itself, so
 * it is left out; cards with something to report come before the quiet ones, each group in
 * TODO_ORDER; at most `limit`.
 */
export function pickTodo(cards: readonly TodayCardData[], limit = TODO_LIMIT): TodayCardData[] {
  const rank = (c: TodayCardData) => TODO_ORDER.indexOf(c.id)
  return cards
    .filter((c) => rank(c) >= 0)
    .sort((a, b) => Number(a.empty) - Number(b.empty) || rank(a) - rank(b))
    .slice(0, limit)
}

const DAY_MS = 86_400_000

/** "2 sent in the last 24 hours, the latest 14 min. ago: Malware was dropped on the honeypot." */
export function alertsSentence(items: readonly OutboxItem[], now = Date.now()): string {
  const recent = items.filter(
    (i) => i.state !== "suppressed" && now - Date.parse(i.created_at) < DAY_MS,
  )
  const latest = recent[0]
  if (!latest) return t("today_alerts_none")
  const failed = recent.filter((i) => i.state === "failed").length
  return t("today_alerts_sentence", {
    count: recent.length,
    failed,
    when: formatRelative(latest.created_at, now),
    hasTitle: latest.title ? "yes" : "no",
    title: latest.title ?? "",
  })
}
