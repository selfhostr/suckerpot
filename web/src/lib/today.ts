/** The Today page: types mirror api/api/today.py. */
import { getJson } from "./api"
import { plural } from "./format"

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

/** The cards' small headings; the sentence below each one carries the finding. */
export const CARD_TITLE: Record<TodayCardId, string> = {
  happened: "What happened",
  forms: "To submit by form",
  campaigns: "New campaigns",
  act: "Act now",
  new_week: "New this week",
  exposure: "Your exposure",
}

/** Where the form queue lives: Abuse reports, To submit by form. */
export const FORM_QUEUE_LINK = "/abuse?status=forms"

/** "3 reports to submit by web form, for 2 providers" (the API's wording); "" when none waits. */
export function formQueueSentence(count: FormQueueCount | null | undefined): string {
  if (!count || count.reports <= 0) return ""
  return `${plural(count.reports, "report")} to submit by web form, for ${plural(count.providers, "provider")}`
}
