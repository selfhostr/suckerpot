/**
 * Campaigns and MITRE ATT&CK (M15): API shapes (api/api/campaigns.py and attack.py are the
 * source of truth), the six stages every attack is told in, and the sentences the pages open
 * with. No React in here, so everything is unit-tested.
 */
import type { Severity } from "./severity"
import { formatNumber, plural } from "./format"
import type { Sensor } from "./sensors"

export type CampaignStatus = "active" | "quiet" | "merged"

export interface Campaign {
  id: number
  name: string
  status: CampaignStatus
  merged_into: number | null
  first_seen: string
  last_seen: string
  sessions: number
  sources: number
  countries: string[]
  asns: number[]
  sensors: string[]
  techniques: string[]
  stages: Stage[]
  tags: string[]
  families: string[]
  severity: Severity
  rep_session_id: string | null
  demo: boolean
}

export interface CampaignFilters {
  status?: CampaignStatus | undefined
  sensor?: readonly Sensor[] | undefined
  technique?: string | undefined
  family?: string | undefined
  days?: number | undefined
  q?: string | undefined
}

/** The story stages, in the order an attack unfolds. */
export const STAGES = [
  "recon",
  "access",
  "execution",
  "persistence",
  "tool_transfer",
  "objective",
] as const
export type Stage = (typeof STAGES)[number]

export const STAGE_META: Record<Stage, { label: string; question: string }> = {
  recon: { label: "Looking around", question: "What did they check first?" },
  access: { label: "Getting in", question: "How did they get in?" },
  execution: { label: "Running code", question: "What did they run?" },
  persistence: { label: "Staying in", question: "How did they try to stay?" },
  tool_transfer: { label: "Bringing tools", question: "What did they bring along?" },
  objective: { label: "The goal", question: "What did they want?" },
}

export function isStage(value: string): value is Stage {
  return (STAGES as readonly string[]).includes(value)
}

export interface StoryTechnique {
  id: string
  name: string
  url: string
  plain: string
}

export interface StoryStage {
  stage: Stage
  label: string
  summary: string
  techniques: StoryTechnique[]
}

export interface ExcerptLine {
  kind: "login" | "command" | "request" | "download"
  text: string
}

export interface Excerpt {
  session_id: string
  sensor: string
  lines: ExcerptLine[]
}

export interface CampaignStory {
  campaign_id: number
  headline: string
  stages: StoryStage[]
  excerpt: Excerpt | null
  counts: {
    sessions: number
    sources: number
    countries: number
    networks: number
    sensors: number
    days_active: number
  }
  what_to_do: string[]
}

export interface CampaignTimeline {
  since: string
  until: string
  bucket_seconds: number
  linked: number
  points: { ts: string; sessions: number }[]
}

export type CampaignKeyKind = "script" | "payload_host" | "hash" | "family" | "exploit" | "credlist"

export interface CampaignIndicator {
  kind: CampaignKeyKind
  value: string
  defanged: string
  sources: number
  /** "low": seen from fewer sources than the clustering rule needs, do not block on it alone. */
  confidence: "normal" | "low"
  first_seen: string
  last_seen: string
}

export const KEY_KIND_LABEL: Record<CampaignKeyKind, string> = {
  payload_host: "Payload server",
  hash: "File hash",
  family: "Malware family",
  script: "Script fingerprint",
  exploit: "Exploit fingerprint",
  credlist: "Password list fingerprint",
}

export interface TechniqueItem {
  id: string
  name: string
  tactic: string
  stage: Stage
  stage_label: string
  url: string
  plain: string
  sessions: number
  events: number
  sources: number
  last_day: string | null
}

export interface MatrixRow {
  id: string
  name: string
  tactic: string
  stage: Stage
  url: string
  plain: string
  total_sessions: number
  total_events: number
  /** Sessions per day, aligned with `Matrix.days`. */
  counts: number[]
}

export interface Matrix {
  since: string
  until: string
  days: string[]
  stages: { stage: Stage; label: string }[]
  rows: MatrixRow[]
}

// --- sentences --------------------------------------------------------------------------------

export const CAMPAIGN_WINDOWS = [
  { value: "7", label: "7 days", days: 7 },
  { value: "30", label: "30 days", days: 30 },
  { value: "90", label: "90 days", days: 90 },
  { value: "all", label: "All time", days: 0 },
] as const

export function windowDays(value: string | null, fallback = 30): number {
  const found = CAMPAIGN_WINDOWS.find((w) => w.value === value)
  return found ? found.days : fallback
}

export function windowPhrase(days: number): string {
  return days === 0 ? "on record" : `in the last ${days} days`
}

/** The one sentence a campaigns page opens with. */
export function describeCampaigns(
  items: readonly Campaign[],
  opts: { days: number; more: boolean },
): string {
  const when = windowPhrase(opts.days)
  if (items.length === 0) return `No campaigns ${when}.`
  const n = `${formatNumber(items.length)}${opts.more ? "+" : ""}`
  const active = items.filter((c) => c.status === "active").length
  const noun = items.length === 1 && !opts.more ? "campaign" : "campaigns"
  const lead = `${n} ${noun} ${when}`
  if (active === 0) return `${lead}, all quiet now.`
  return `${lead}, ${active === items.length && !opts.more ? "all" : formatNumber(active)} still active.`
}

/** "87 sessions from 23 addresses in 6 countries". */
export function describeScale(c: Pick<Campaign, "sessions" | "sources" | "countries">): string {
  const where =
    c.countries.length > 0 ? ` in ${plural(c.countries.length, "country", "countries")}` : ""
  return `${plural(c.sessions, "session")} from ${plural(c.sources, "address", "addresses")}${where}`
}

/** The playbook in one line: stage labels joined with arrows. */
export function stageTrailText(stages: readonly string[]): string {
  const labels = STAGES.filter((s) => stages.includes(s)).map((s) => STAGE_META[s].label)
  return labels.length ? labels.join(" → ") : "No stages recorded"
}

export function statusLabel(status: CampaignStatus): string {
  return status === "active" ? "Active" : status === "quiet" ? "Quiet" : "Merged"
}

// --- the techniques table -------------------------------------------------------------------

export const TECHNIQUE_WINDOWS = [
  { value: "7", label: "7 days", days: 7 },
  { value: "30", label: "30 days", days: 30 },
  { value: "90", label: "90 days", days: 90 },
] as const

export function techniqueDays(value: string | null): number {
  return TECHNIQUE_WINDOWS.find((w) => w.value === value)?.days ?? 30
}

export function describeMatrix(matrix: Matrix, catalogue: number | null): string {
  const used = matrix.rows.length
  const days = matrix.days.length
  if (used === 0) return `No techniques were seen in the last ${days} days.`
  const top = [...matrix.rows].sort((a, b) => b.total_sessions - a.total_sessions)[0]
  const of = catalogue ? ` of the ${catalogue} we watch for` : ""
  const lead = `Attackers used ${plural(used, "technique")}${of} in the last ${days} days`
  return top ? `${lead}. Most often they ${top.plain}.` : `${lead}.`
}

export function formatDay(day: string): string {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }).format(new Date(`${day}T00:00:00Z`))
}

/** Hourly points to one point per UTC day, oldest first, with quiet days filled in. */
export function dailyFromHourly(
  points: readonly { ts: string; sessions: number }[],
  days: number,
  now = Date.now(),
): { day: string; events: number }[] {
  const byDay = new Map<string, number>()
  for (const p of points) {
    const day = p.ts.slice(0, 10)
    byDay.set(day, (byDay.get(day) ?? 0) + p.sessions)
  }
  const today = new Date(now)
  today.setUTCHours(0, 0, 0, 0)
  return Array.from({ length: days }, (_, i) => {
    const day = new Date(today.getTime() - (days - 1 - i) * 86_400_000).toISOString().slice(0, 10)
    return { day, events: byDay.get(day) ?? 0 }
  })
}

/** The playbook in a few words, for lists: "3 stages, up to bringing tools". */
export function stageReach(stages: readonly string[]): string {
  const seen = STAGES.filter((s) => stages.includes(s))
  const last = seen.at(-1)
  if (!last) return "No stages recorded"
  const name = STAGE_META[last].label.toLowerCase()
  return seen.length === 1 ? `1 stage: ${name}` : `${seen.length} stages, up to ${name}`
}

/** Consecutive identical lines become one line with a count ("whoami" four times: "× 4"). */
export function foldRepeats(lines: readonly ExcerptLine[]): { line: ExcerptLine; times: number }[] {
  const out: { line: ExcerptLine; times: number }[] = []
  for (const line of lines) {
    const prev = out.at(-1)
    if (prev?.line.kind === line.kind && prev.line.text === line.text) prev.times += 1
    else out.push({ line, times: 1 })
  }
  return out
}
