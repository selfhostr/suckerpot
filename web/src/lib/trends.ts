/**
 * Pure helpers for the Trends, Malware and Insights views: API shapes (M7
 * contract), the defanged URL form, and the finding
 * sentences. No React in here, so everything is unit-tested.
 */
import type { Session, TopItem, TopResponse } from "./api"
import { SEVERE_TAGS, type Severity } from "./severity"
import { formatNumber, formatPercent, plural } from "./format"

// --- API shapes (M7 contract) -------------------------------------------------

export type InsightKind =
  "surge" | "new_value" | "campaign" | "exploit" | "success" | "geo_shift" | "brute_force"

/** Short name of each insight kind (screen readers, tooltips). */
export const INSIGHT_KIND_LABEL: Record<InsightKind, string> = {
  surge: "Surge",
  new_value: "New value",
  campaign: "Campaign",
  exploit: "Exploit",
  success: "Successful login",
  geo_shift: "New origin",
  brute_force: "Brute force",
}

export interface Insight {
  id: string
  kind: InsightKind
  severity: Severity
  sentence: string
  evidence: { metric: string; current: number; previous: number; ratio: number }
  /** Relative UI link with filters, e.g. "/attacks?tag=php2shell". */
  link: string
}

export interface InsightsResponse {
  generated_at: string
  items: Insight[]
}

export const NEW_FIELDS = ["username", "password", "command", "url", "asn", "user_agent"] as const
export type NewField = (typeof NEW_FIELDS)[number]

export interface NewItem {
  value: string
  count: number
  first_seen: string
}

export interface NewResponse {
  field: NewField
  items: NewItem[]
}

export interface TagPoint {
  ts: string
  tags: Record<string, number>
}

export interface TagsResponse {
  bucket: string
  since: string
  until: string
  /** Tag names, most frequent first; "other" last. */
  series: string[]
  points: TagPoint[]
}

export type FetchStatus =
  | "fetched"
  | "pending"
  | "failed"
  | "gone"
  | "refused"
  | "too_large"
  | "unsupported"
  | "quarantine_full"

export interface MalwareItem {
  url: string
  host: string
  first_seen: string
  last_seen: string
  attempts: number
  sessions: number
  ips: number
  tools: string[]
  sensors: string[]
  sha256: string | null
  size: number | null
  virustotal_url: string | null
  /** M21: state of the collector's fetch of this URL; null when never queued. */
  fetch_status?: FetchStatus | null
}

export interface MalwareDetail {
  item: MalwareItem
  recent_sessions: Session[]
}

// --- Defanged URLs ------------------------------------------------------------

/**
 * "http://malware.example.net/x.sh" -> "hxxp://malware[.]example[.]net/x.sh".
 * Safe to paste into a ticket or chat: it can never turn into a live link.
 */
export function defangUrl(raw: string): string {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is.exec(raw)
  if (!m) return raw.replace(/^([^/?#]*)/, (h) => h.replaceAll(".", "[.]"))
  const [, proto = "", host = "", rest = ""] = m
  const SCHEMES: Record<string, string> = { http: "hxxp", https: "hxxps", ftp: "fxp" }
  const safeProto = SCHEMES[proto.toLowerCase()] ?? proto
  return `${safeProto}://${host.replaceAll(".", "[.]")}${rest}`
}

// --- Findings ----------------------------------------------------------------

export interface Finding {
  finding: string
  detail?: string
}

export function tagTotals(points: readonly TagPoint[]): [string, number][] {
  const totals = new Map<string, number>()
  for (const p of points)
    for (const [tag, n] of Object.entries(p.tags)) totals.set(tag, (totals.get(tag) ?? 0) + n)
  return [...totals.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

/** Compare the second half of the window with the first for one tag. */
export function tagChange(
  points: readonly TagPoint[],
  tag: string,
): { first: number; second: number } {
  const mid = Math.floor(points.length / 2)
  const sum = (ps: readonly TagPoint[]) => ps.reduce((a, p) => a + (p.tags[tag] ?? 0), 0)
  return { first: sum(points.slice(0, mid)), second: sum(points.slice(mid)) }
}

/** `"php2shell" is the most common tag: 412 events (42%), up from 131 in the first half.` */
export function describeTags(points: readonly TagPoint[], days: number): Finding {
  const named = tagTotals(points).filter(([t]) => t !== "other")
  const all = tagTotals(points).reduce((a, [, n]) => a + n, 0)
  const top = named[0]
  if (!top || all === 0) return { finding: `No tagged activity in the last ${days} days.` }
  const [tag, n] = top
  const { first, second } = tagChange(points, tag)
  let trend = ""
  if (first > 0 && second >= first * 2) trend = `, at least doubling in the second half`
  else if (second > 0 && first >= second * 2) trend = `, less than half as active lately`
  else if (first === 0 && second > 0) trend = `, all of it in the second half of the period`
  return {
    finding: `"${tag}" is the most common tag: ${plural(n, "event")} (${formatPercent(n / all)})${trend}.`,
    detail: `${plural(named.length, "tag")} seen over ${days} days${SEVERE_TAGS.has(tag) ? "; this one marks a payload" : ""}.`,
  }
}

type TopKind = "username" | "password" | "command" | "url"
const KIND_WORD: Record<TopKind, { one: string; many: string; unit: string }> = {
  username: { one: "username", many: "usernames", unit: "login attempts" },
  password: { one: "password", many: "passwords", unit: "login attempts" },
  command: { one: "command", many: "commands", unit: "commands" },
  url: { one: "URL", many: "URLs", unit: "requests and downloads" },
}

/** `"root" was the most tried username in the last 7 days, in 42% of login attempts.` */
export function describeTop(kind: TopKind, top: TopResponse | undefined, days: number): Finding {
  const w = KIND_WORD[kind]
  const [first, second] = top?.items ?? []
  if (!first) return { finding: `No ${w.many} recorded in the last ${days} days.` }
  const shown = first.value.length > 60 ? `${first.value.slice(0, 57)}…` : first.value
  const tail = second
    ? `, ahead of ${second.value.length > 40 ? "the runner-up" : `"${second.value}"`} (${formatPercent(second.share)})`
    : ""
  return {
    finding: `"${shown}" was the most seen ${w.one} in the last ${days} days, in ${formatPercent(first.share)} of ${w.unit}${tail}.`,
    detail: `${formatNumber(top?.total ?? 0)} ${w.unit} in all.`,
  }
}

/** "14 usernames were never seen before this week; the most used was "admin1" (88 times)." */
export function describeNew(field: NewField, items: readonly NewItem[], days: number): Finding {
  const word = field === "asn" ? "networks" : field === "user_agent" ? "user agents" : `${field}s`
  const one = field === "asn" ? "network" : field === "user_agent" ? "user agent" : field
  const period = days === 7 ? "this week" : `in the last ${days} days`
  if (items.length === 0)
    return { finding: `No new ${word} ${period}: every one has been seen before.` }
  const top = [...items].sort((a, b) => b.count - a.count)[0]
  if (!top) return { finding: `No new ${word} ${period}.` }
  const shown = top.value.length > 50 ? `${top.value.slice(0, 47)}…` : top.value
  return {
    finding: `${items.length === 1 ? `1 ${one} was` : `${formatNumber(items.length)} ${word} were`} never seen before ${period}; the most used is "${shown}" (${plural(top.count, "time")}).`,
  }
}

/** Is this tag one of the severe ones (gets the red marker)? */
export const isSevereTag = (tag: string) => SEVERE_TAGS.has(tag)

/** Keep the share bar honest: top items only. */
export function topItems(top: TopResponse | undefined): TopItem[] {
  return top?.items ?? []
}
