/**
 * Script library: shapes of `/api/v1/scripts` (api/api/scripts.py is the source of truth), the
 * plain-English sentences of the two pages, and the calls. The sentences are pure and tested.
 */

import { getJson, type Param, type Session } from "./api"
import { formatNumber, plural } from "./format"
import type { Severity } from "./severity"

export type ScriptSort = "recent" | "common" | "newest"
export const SCRIPT_SORTS: readonly ScriptSort[] = ["recent", "common", "newest"]

export interface ScriptItem {
  id: number
  fingerprint: string
  summary: string | null
  preview: string[]
  line_count: number
  first_seen: string
  last_seen: string
  sessions: number
  sources: number
  sensors: string[]
  techniques: string[]
  campaign_id: number | null
  campaign_name: string | null
  risk: Severity | null
  is_new: boolean
}

export interface ScriptPage {
  items: ScriptItem[]
  next_cursor: string | null
}

export interface ScriptsSummary {
  total: number
  new_this_week: number
  seen_today: number
  with_campaign: number
  top_id: number | null
  top_summary: string | null
  top_sessions: number | null
}

export interface ExplainedLine {
  n: number
  text: string
  raw: string | null
  explanation: string
  risk: Severity | null
  technique: string | null
  technique_name: string | null
  rule: string | null
}

export interface TechniqueRef {
  id: string
  name: string
  tactic: string | null
  url: string | null
}

export interface ScriptDetail {
  item: ScriptItem
  lines: ExplainedLine[]
  unexplained: number
  techniques_detail: TechniqueRef[]
  campaign: { id: number; name: string; status: string } | null
  demo: boolean
}

export interface ScriptFilters {
  sort?: ScriptSort | undefined
  sensor?: readonly string[] | undefined
  technique?: string | undefined
  campaign_id?: string | undefined
  q?: string | undefined
  days?: string | undefined
  new?: string | undefined
}

export const scriptsApi = {
  list: (filters: ScriptFilters, cursor?: string | null, limit = 50) =>
    getJson<ScriptPage>("/scripts", {
      ...(filters as Record<string, Param>),
      cursor: cursor ?? undefined,
      limit,
    }),
  summary: () => getJson<ScriptsSummary>("/scripts/summary"),
  detail: (id: number) => getJson<ScriptDetail>(`/scripts/${id}`),
  sessions: (id: number, cursor?: string | null, limit = 25) =>
    getJson<{ items: Session[]; next_cursor: string | null }>(`/scripts/${id}/sessions`, {
      cursor: cursor ?? undefined,
      limit,
    }),
}

export const scriptKeys = {
  list: (filters: object) => ["scripts", filters] as const,
  summary: ["scripts", "summary"] as const,
  detail: (id: number) => ["scripts", "detail", id] as const,
  sessions: (id: number) => ["scripts", "sessions", id] as const,
}

/** Words for a risk level, as used in the row tooltips and the legend. */
export const RISK_WORDS: Record<Severity, string> = {
  info: "Harmless looking around",
  notice: "Changes things a little",
  warning: "Weakens or hides something",
  severe: "Drops or runs code",
}

function lower(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1)
}

/** The sentence under the Scripts title. */
export function describeScripts(s: ScriptsSummary): string {
  if (s.total === 0) return "No attacker has typed a command sequence yet."
  const head = `${plural(s.total, "distinct script")} so far`
  const fresh =
    s.new_this_week === 0
      ? "none of them new this week"
      : `${formatNumber(s.new_this_week)} new this week`
  const tail =
    s.top_summary && s.top_sessions
      ? `. The most common one ${lower(s.top_summary)
          .replace(/^a \d+-step script that /, "")
          .replace(/\.$/, "")} (seen ${plural(s.top_sessions, "time")}).`
      : "."
  return `${head}, ${fresh}${tail}`
}

/** The opening sentence of a script page: what it does, how often, how widely. */
export function describeScript(item: ScriptItem, summary: string | null): string {
  const seen = `Seen ${plural(item.sessions, "time")} from ${plural(item.sources, "address", "addresses")}`
  const what = summary
    ? summary
        .replace(/^A (\d+)-step script that /, "This $1-step script ")
        .replace(
          /^A (\d+)-step script; none of .*$/,
          "This $1-step script has no built-in explanation yet.",
        )
    : `This ${item.line_count}-step script has no built-in explanation yet.`
  return `${what} ${seen}${item.campaign_name ? `, as part of the campaign "${item.campaign_name}"` : ""}.`
}

/** What to do about it, in one line. Advice, never a command to run. */
export function nextStep(lines: readonly ExplainedLine[]): string {
  const download = lines.some((l) => l.rule === "download" || l.rule === "download-and-run")
  const persist = lines.some((l) => l.risk === "severe" && l.technique?.startsWith("T1098"))
  if (download)
    return "Block the download host at your firewall or proxy, and check that your servers cannot fetch and run files from the internet."
  if (persist)
    return "Check authorized_keys files, scheduled jobs and new accounts on exposed servers."
  if (lines.every((l) => l.risk === "info" || l.risk === null))
    return "This only looks around. Nothing to fix by itself, but it shows what attackers check first."
  return "Review whether the commands above could run on your exposed systems, and restrict shell access."
}
