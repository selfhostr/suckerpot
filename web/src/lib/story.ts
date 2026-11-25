/**
 * The Today story: types mirror GET /api/v1/story, plus the pure helpers that turn the funnel
 * into a Sankey, a mobile list and the one-sentence caption of a timeline bucket.
 */
import {
  Bug,
  Download,
  Eye,
  KeyRound,
  LogIn,
  Plug,
  Radar,
  SquareTerminal,
  Unplug,
  UserCheck,
  type LucideIcon,
} from "lucide-react"
import { intlLocale, t, tk } from "@/i18n"
import { getJson } from "./api"
import type { TermId } from "./glossary"
import { SENSORS, sensorMeta } from "./sensors"
import { EXPLOIT_TAGS, type Severity } from "./severity"
import { withText } from "./t-getters"

export const STAGES = ["looked", "guessed", "got_in", "commands", "download", "exploit"] as const
export type Stage = (typeof STAGES)[number]

export const STEP_KINDS = [
  "connect",
  "scan",
  "guess",
  "login",
  "command",
  "download",
  "exploit",
  "disconnect",
] as const
export type StepKind = (typeof STEP_KINDS)[number]

export type FlowColumn = "origin" | "door" | "stage"

export interface StoryTotals {
  sessions: number
  sources: number
  countries: number
  guessed: number
  got_in: number
  ran_commands: number
  downloads: number
  exploits: number
}

export interface FlowNode {
  id: string
  column: FlowColumn
  key: string
  label: string
  technical: string
  sessions: number
  href: string
}

export interface FlowLink {
  source: string
  target: string
  value: number
}

export interface TimelineBucket {
  start: string
  sessions: number
  by_door: Record<string, number>
  by_stage: Record<string, number>
  severe: number
}

export interface StoryStep {
  ts: string
  kind: StepKind
  plain: string
  technical: string
  count: number
}

export interface StoryItem {
  session_id: string
  started_at: string
  ended_at: string | null
  src_ip: string
  country: string | null
  country_name: string | null
  asn: number | null
  org: string | null
  sensor: string
  stage: Stage
  severity: string
  title: string
  summary: string
  steps: StoryStep[]
  tags: string[]
  techniques: { id: string; name: string }[]
  campaign: { id: number; name: string } | null
  href: string
}

export interface StoryResponse {
  as_of: string
  hours: number
  headline: string
  totals: StoryTotals
  flow: { nodes: FlowNode[]; links: FlowLink[] }
  timeline: TimelineBucket[]
  stories: StoryItem[]
}

export const storyApi = {
  story: (hours = 24) => getJson<StoryResponse>("/story", { hours }),
}

export const storyKeys = {
  story: (hours: number) => ["story", hours] as const,
}

// --- Stages -------------------------------------------------------------------------------

export interface StageMeta {
  label: string
  /** One plain sentence for the legend. */
  sentence: string
  /** Severity token (red only for the last two). */
  cssVar: string
  icon: LucideIcon
  /** Glossary word the legend underlines. */
  term?: TermId
}

const STAGE_BASE: Record<Stage, StageMeta> = {
  looked: {
    label: tk("story_stage_looked_label"),
    sentence: tk("story_stage_looked_sentence"),
    cssVar: "var(--fg-subtle)",
    icon: Eye,
    term: "scanner",
  },
  guessed: {
    label: tk("story_stage_guessed_label"),
    sentence: tk("story_stage_guessed_sentence"),
    cssVar: "var(--fg-muted)",
    icon: KeyRound,
    term: "brute-force",
  },
  got_in: {
    label: tk("story_stage_got_in_label"),
    sentence: tk("story_stage_got_in_sentence"),
    cssVar: "var(--sev-warning)",
    icon: UserCheck,
  },
  commands: {
    label: tk("story_stage_commands_label"),
    sentence: tk("story_stage_commands_sentence"),
    cssVar: "var(--sev-warning)",
    icon: SquareTerminal,
  },
  download: {
    label: tk("story_stage_download_label"),
    sentence: tk("story_stage_download_sentence"),
    cssVar: "var(--sev-severe)",
    icon: Download,
    term: "malware",
  },
  exploit: {
    label: tk("story_stage_exploit_label"),
    sentence: tk("story_stage_exploit_sentence"),
    cssVar: "var(--sev-severe)",
    icon: Bug,
    term: "exploit",
  },
}

/** `label` and `sentence` read through t() every time, so they follow the language. */
export const STAGE_META: Record<Stage, StageMeta> = Object.fromEntries(
  STAGES.map((stage) => [
    stage,
    withText(STAGE_BASE[stage], {
      label: STAGE_BASE[stage].label,
      sentence: STAGE_BASE[stage].sentence,
    }),
  ]),
) as Record<Stage, StageMeta>

export function isStage(v: string): v is Stage {
  return (STAGES as readonly string[]).includes(v)
}

/** Parse a `?stage=` value; anything but one of the six stages is ignored. */
export function parseStage(raw: string | null | undefined): Stage | undefined {
  return raw && isStage(raw) ? raw : undefined
}

/** The stage of a session from its counters, for sessions the API did not label. */
export function sessionStage(s: {
  stage?: string | undefined
  tags: readonly string[]
  downloads: number
  commands: number
  login_success: boolean
  login_attempts: number
}): Stage {
  if (s.stage && isStage(s.stage)) return s.stage
  if (s.tags.some((t) => EXPLOIT_TAGS.has(t))) return "exploit"
  if (s.downloads > 0 || s.tags.includes("malware-drop")) return "download"
  if (s.commands > 0) return "commands"
  if (s.login_success) return "got_in"
  if (s.login_attempts > 0) return "guessed"
  return "looked"
}

/** The API's story severity on the UI scale. Unknown values read as "info". */
export function storySeverity(v: string): Severity {
  const map: Record<string, Severity> = {
    info: "info",
    low: "notice",
    medium: "warning",
    high: "severe",
  }
  return map[v] ?? "info"
}

export function stageRank(key: string): number {
  const i = (STAGES as readonly string[]).indexOf(key)
  return i < 0 ? STAGES.length : i
}

export interface StepMeta {
  icon: LucideIcon
  /** Red is reserved for these two. */
  severe: boolean
}

export const STEP_META: Record<StepKind, StepMeta> = {
  connect: { icon: Plug, severe: false },
  scan: { icon: Radar, severe: false },
  guess: { icon: KeyRound, severe: false },
  login: { icon: LogIn, severe: false },
  command: { icon: SquareTerminal, severe: false },
  download: { icon: Download, severe: true },
  exploit: { icon: Bug, severe: true },
  disconnect: { icon: Unplug, severe: false },
}

/** An unknown step kind from a newer API falls back to the "connect" icon. */
export function stepMeta(kind: string): StepMeta {
  return (STEP_META as Record<string, StepMeta | undefined>)[kind] ?? STEP_META.connect
}

// --- Flow shaping -------------------------------------------------------------------------

const COLUMN_ORDER: Record<FlowColumn, number> = { origin: 0, door: 1, stage: 2 }

function doorRank(key: string): number {
  const i = (SENSORS as readonly string[]).indexOf(key)
  return i < 0 ? SENSORS.length : i
}

/**
 * Nodes in drawing order: origins by size ("other" last), doors in registry order, stages from
 * "only looked" to "sent an exploit". Empty nodes and empty or dangling links are dropped.
 */
export function orderFlow(flow: StoryResponse["flow"]): { nodes: FlowNode[]; links: FlowLink[] } {
  const nodes = flow.nodes
    .filter((n) => n.sessions > 0)
    .sort((a, b) => {
      if (a.column !== b.column) return COLUMN_ORDER[a.column] - COLUMN_ORDER[b.column]
      if (a.column === "stage") return stageRank(a.key) - stageRank(b.key)
      if (a.column === "door") return doorRank(a.key) - doorRank(b.key)
      if (a.key === "other" || b.key === "other") return a.key === "other" ? 1 : -1
      return b.sessions - a.sessions
    })
  const ids = new Set(nodes.map((n) => n.id))
  const links = flow.links.filter((l) => l.value > 0 && ids.has(l.source) && ids.has(l.target))
  return { nodes, links }
}

export interface SankeyShape {
  nodes: (FlowNode & { name: string })[]
  links: { source: number; target: number; value: number }[]
}

/** The index-based shape recharts' Sankey wants. */
export function sankeyData(flow: StoryResponse["flow"]): SankeyShape {
  const { nodes, links } = orderFlow(flow)
  const index = new Map(nodes.map((n, i) => [n.id, i]))
  return {
    nodes: nodes.map((n) => ({ ...n, name: n.label })),
    links: links.map((l) => ({
      source: index.get(l.source) ?? 0,
      target: index.get(l.target) ?? 0,
      value: l.value,
    })),
  }
}

export interface DoorRow {
  node: FlowNode
  total: number
  /** How far its visitors got, in stage order; empty stages left out. */
  segments: { stage: Stage; label: string; value: number; href: string }[]
}

/** Mobile fallback: one stacked bar per door, split by how far its visitors got. */
export function doorRows(flow: StoryResponse["flow"]): DoorRow[] {
  const { nodes, links } = orderFlow(flow)
  const byId = new Map(nodes.map((n) => [n.id, n]))
  return nodes
    .filter((n) => n.column === "door")
    .map((door) => {
      const segments = links
        .filter((l) => l.source === door.id)
        .flatMap((l) => {
          const t = byId.get(l.target)
          return t?.column === "stage" && isStage(t.key)
            ? [{ stage: t.key, label: t.label, value: l.value, href: t.href }]
            : []
        })
        .sort((a, b) => stageRank(a.stage) - stageRank(b.stage))
      const total = segments.reduce((sum, x) => sum + x.value, 0)
      return { node: door, total: total || door.sessions, segments }
    })
    .sort((a, b) => b.total - a.total)
}

/** Mobile fallback for the first column: the biggest origins first, "other" last. */
export function originRows(flow: StoryResponse["flow"]): FlowNode[] {
  return orderFlow(flow).nodes.filter((n) => n.column === "origin")
}

/**
 * Where a flow link leads: the node it ends in (its filtered Attacks view), narrowed to the
 * door it passes through, so "SSH to guessed passwords" does not show the other doors.
 */
export function linkHref(source: FlowNode, target: FlowNode): string {
  const door = source.column === "door" ? source : target.column === "door" ? target : null
  const base = source.column === "origin" ? source.href : target.href
  if (!door) return base
  const url = new URL(base, "http://local")
  if (!url.searchParams.has("sensor")) url.searchParams.set("sensor", door.key)
  return `${url.pathname}${url.search}`
}

/** The finding that opens the flow card. Numbers only; the API's headline carries the story. */
export function flowFinding(t_: StoryTotals): string {
  if (t_.sessions === 0) return t("story_flow_finding_none")
  const stopped = Math.max(0, t_.sessions - t_.got_in - t_.exploits)
  return t("story_flow_finding", {
    share: Math.round((stopped / t_.sessions) * 100),
    gotIn: t_.got_in,
    worse: t_.downloads + t_.exploits,
  })
}

// --- Time window -------------------------------------------------------------------------

/** A `since`/`until` URL value as an ISO instant, or undefined when it is not a date. */
export function parseInstant(raw: string | null | undefined): string | undefined {
  if (!raw || raw.length > 40) return undefined
  const t = Date.parse(raw)
  return Number.isNaN(t) ? undefined : new Date(t).toISOString()
}

/** Start of the story's window: `as_of` minus `hours`. */
export function windowSince(asOf: string, hours: number): string {
  return new Date(Date.parse(asOf) - hours * 3_600_000).toISOString()
}

/** `href` limited to a time window, so the list counts what the story counted. */
export function withWindow(href: string, since: string, until?: string): string {
  const url = new URL(href, "http://local")
  url.searchParams.set("since", since)
  if (until) url.searchParams.set("until", until)
  return `${url.pathname}${url.search}`
}

/** The whole flow with every node link limited to the story's window. */
export function scopeFlow(flow: StoryResponse["flow"], since: string): StoryResponse["flow"] {
  return { ...flow, nodes: flow.nodes.map((n) => ({ ...n, href: withWindow(n.href, since) })) }
}

/** The chip text for a window: "Last 24 hours", "Between 14:00 and 15:00", "Since ...". */
export function windowLabel(
  since: string | undefined,
  until: string | undefined,
  now = Date.now(),
) {
  if (since && until) return t("story_window_between", { from: hhmm(since), to: hhmm(until) })
  if (since) {
    const hours = Math.round((now - Date.parse(since)) / 3_600_000)
    if (hours >= 48 && hours <= 168 && hours % 24 === 0)
      return t("story_window_last_days", { count: hours / 24 })
    if (hours >= 1 && hours <= 168) return t("story_window_last_hours", { count: hours })
    return t("story_window_since", { time: hhmm(since) })
  }
  return until ? t("story_window_before", { time: hhmm(until) }) : ""
}

// --- Timeline -----------------------------------------------------------------------------

const clockFormats = new Map<string, Intl.DateTimeFormat>()

/** "14:00" in the browser's time zone. */
export function hhmm(d: string | Date): string {
  const locale = intlLocale()
  let fmt = clockFormats.get(locale)
  if (!fmt) {
    fmt = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" })
    clockFormats.set(locale, fmt)
  }
  return fmt.format(typeof d === "string" ? new Date(d) : d)
}

/** Length of one bucket in ms: from the first two starts, one hour when unknown. */
export function bucketMs(timeline: readonly TimelineBucket[]): number {
  const a = timeline[0]
  const b = timeline[1]
  if (!a || !b) return 3_600_000
  const d = Date.parse(b.start) - Date.parse(a.start)
  return d > 0 ? d : 3_600_000
}

/** Index of the busiest bucket (the latest one on a tie), or -1 for an empty timeline. */
export function busiestBucket(timeline: readonly TimelineBucket[]): number {
  let best = -1
  let max = -1
  timeline.forEach((b, i) => {
    if (b.sessions >= max) {
      max = b.sessions
      best = i
    }
  })
  return best
}

/** "Between 14:00 and 15:00, 912 visits came in, mostly to SSH. 3 tried to install ..." */
export function bucketSentence(bucket: TimelineBucket, ms: number): string {
  const from = hhmm(bucket.start)
  const to = hhmm(new Date(Date.parse(bucket.start) + ms))
  if (bucket.sessions === 0) return t("story_bucket_empty", { from, to })
  const top = Object.entries(bucket.by_door).sort((a, b) => b[1] - a[1])[0]
  return t("story_bucket_sentence", {
    from,
    to,
    sessions: bucket.sessions,
    door: top ? (sensorMeta(top[0])?.noun ?? top[0]) : "none",
    severe: bucket.severe,
  })
}
