/**
 * Script library: shapes of `/api/v1/scripts` (api/api/scripts.py is the source of truth), the
 * plain-English sentences of the two pages, and the calls. The sentences are pure and tested.
 */

import { getJson, type Param, type Session } from "./api"
import { t } from "@/i18n"
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
  get info() {
    return t("scripts_risk_info")
  },
  get notice() {
    return t("scripts_risk_notice")
  },
  get warning() {
    return t("scripts_risk_warning")
  },
  get severe() {
    return t("scripts_risk_severe")
  },
}

function lower(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1)
}

/** The sentence under the Scripts title. */
export function describeScripts(s: ScriptsSummary): string {
  if (s.total === 0) return t("scripts_summary_empty")
  const top =
    s.top_summary && s.top_sessions
      ? lower(s.top_summary)
          .replace(/^a \d+-step script that /, "")
          .replace(/\.$/, "")
      : ""
  return t("scripts_summary", {
    total: s.total,
    fresh: s.new_this_week,
    withTop: top ? "yes" : "no",
    top,
    times: s.top_sessions ?? 0,
  })
}

/** The opening sentence of a script page: what it does, how often, how widely. */
export function describeScript(item: ScriptItem, summary: string | null): string {
  const what = summary
    ? summary
        .replace(/^A (\d+)-step script that /, "This $1-step script ")
        .replace(/^A (\d+)-step script; none of .*$/, (_m, n: string) =>
          t("scripts_no_explanation", { count: Number(n) }),
        )
    : t("scripts_no_explanation", { count: item.line_count })
  return t("scripts_describe", {
    what,
    sessions: item.sessions,
    sources: item.sources,
    withCampaign: item.campaign_name ? "yes" : "no",
    campaign: item.campaign_name ?? "",
  })
}

/** What to do about it, in one line. Advice, never a command to run. */
export function nextStep(lines: readonly ExplainedLine[]): string {
  const download = lines.some((l) => l.rule === "download" || l.rule === "download-and-run")
  const persist = lines.some((l) => l.risk === "severe" && l.technique?.startsWith("T1098"))
  if (download)
    return t("scripts_next_download")
  if (persist)
    return t("scripts_next_persist")
  if (lines.every((l) => l.risk === "info" || l.risk === null))
    return t("scripts_next_harmless")
  return t("scripts_next_review")
}
