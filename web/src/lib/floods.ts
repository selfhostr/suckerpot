/**
 * Flood groups. A source that opens many plain connections in one UTC hour has them merged into
 * one session row (`kind: "burst"`, `connections: N`). Everything the UI needs to read, filter and
 * link such a row lives here; the sentence that tells it is in `describe-session.ts`.
 */
import type { Session, SessionCredentials, StatsSummary } from "./api"
import { browserTimeZone, formatNumber, formatPercent, formatWindow, plural } from "./format"

type FloodShape = Pick<Session, "kind" | "connections">

/** Whether the row is a flood group (one row for many connections). */
export function isFlood(s: FloodShape): boolean {
  return s.kind === "burst"
}

/** How many connections the row stands for: 1 for a session, N for a flood group. */
export function connectionsOf(s: FloodShape): number {
  return Math.max(1, s.connections ?? 1)
}

/** Total connections behind a list of rows (what a count of sessions means). */
export function totalConnections(rows: readonly FloodShape[]): number {
  return rows.reduce((n, s) => n + connectionsOf(s), 0)
}

// --- The Floods control: All / Hide / Only, mapped to `?kind=` ----------------------------

export const FLOOD_VIEWS = ["all", "hide", "only"] as const
export type FloodView = (typeof FLOOD_VIEWS)[number]

/** The URL parameter the control writes: absent for All, `session` for Hide, `burst` for Only. */
export const FLOOD_PARAM = "kind"

const VIEW_TO_KIND = { all: undefined, hide: "session", only: "burst" } as const

export function floodViewFromParam(value: string | null): FloodView {
  return value === "burst" ? "only" : value === "session" ? "hide" : "all"
}

/** The value of `?kind=` for a view, or null when the parameter is dropped (All). */
export function floodParamFor(view: FloodView): "session" | "burst" | null {
  return VIEW_TO_KIND[view] ?? null
}

/** The `kind` filter the sessions API takes for a view; undefined lists both. */
export function floodKindFor(view: FloodView): "session" | "burst" | undefined {
  return VIEW_TO_KIND[view]
}

// --- Sentences ---------------------------------------------------------------------------

/** "96%": a share that is not zero never reads as 0% (or as 100% unless it is all of them). */
function sharePhrase(part: number, whole: number): string {
  const ratio = whole > 0 ? part / whole : 0
  if (ratio > 0 && ratio < 0.01) return "Less than 1%"
  if (ratio < 1 && ratio > 0.995) return "More than 99%"
  return formatPercent(ratio)
}

/**
 * The flood part of the Attacks headline, from the 24 h summary: "96% of them in floods from 20
 * addresses". Null when there was no flood, or the API predates flood groups.
 */
export function floodShareClause(
  summary: Pick<StatsSummary, "sessions" | "flood_sessions" | "flood_sources">,
): string | null {
  const floods = summary.flood_sessions ?? 0
  if (floods <= 0) return null
  const sources = Math.max(1, summary.flood_sources ?? 1)
  return `${sharePhrase(floods, summary.sessions)} of them in floods from ${plural(sources, "address", "addresses")}`
}

/**
 * The Attacks headline for a Floods view without other filters, or null to use the usual one.
 * `all` adds the flood share to the totals; `hide` and `only` say what the list leaves out or keeps.
 */
export function floodHeadline(view: FloodView, summary: StatsSummary): string | null {
  const floods = summary.flood_sessions ?? 0
  const sources = Math.max(1, summary.flood_sources ?? 1)
  const addresses = plural(sources, "address", "addresses")
  const hours = summary.window_hours
  if (view === "only") {
    return floods > 0
      ? `${plural(floods, "connection")} came in floods from ${addresses} in the last ${hours} hours, one row per address and hour.`
      : `No address flooded the sensors in the last ${hours} hours.`
  }
  if (view === "hide") {
    const rest = Math.max(0, summary.sessions - floods)
    return floods > 0
      ? `${plural(rest, "session")} in the last ${hours} hours, without the ${plural(floods, "connection")} that came in floods.`
      : `${plural(rest, "session")} in the last ${hours} hours, none of them in a flood.`
  }
  const clause = floodShareClause(summary)
  if (!clause) return null
  return `${formatNumber(summary.sessions)} sessions from ${formatNumber(summary.unique_ips)} addresses in the last ${hours} hours, ${clause}.`
}

/** "of which 1,456 in floods" on an attacker profile; "at least" when the list was cut short. */
export function floodSentence(connections: number, atLeast = false): string {
  return `of which ${atLeast ? "at least " : ""}${formatNumber(connections)} in floods`
}

// --- Time --------------------------------------------------------------------------------

const clockFmt = new Intl.DateTimeFormat("en-US", {
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
})

/** "14:02–14:58" in the browser's time zone: first to last connection of a flood group. */
export function floodSpan(s: Pick<Session, "started_at" | "last_event_at">): string {
  const a = clockFmt.format(new Date(s.started_at))
  const b = clockFmt.format(new Date(s.last_event_at))
  return a === b ? a : `${a}–${b}`
}

/** The same span with its date and time zone, for a tooltip or a screen reader. */
export function floodSpanLong(s: Pick<Session, "started_at" | "last_event_at">): string {
  return `${formatWindow(s.started_at, s.last_event_at)} (${browserTimeZone()})`
}

/** The UTC hour a group belongs to: `[start, end)` as ISO instants. */
export function floodHour(startedAt: string): { since: string; until: string } {
  const t = Math.floor(Date.parse(startedAt) / 3_600_000) * 3_600_000
  return { since: new Date(t).toISOString(), until: new Date(t + 3_600_000).toISOString() }
}

// --- Links -------------------------------------------------------------------------------

/**
 * The address of a session page. An event link passes the event's time as `at`: a connection that
 * was folded into a flood group has no page of its own, and the API finds its group from it.
 */
export function sessionHref(sessionId: string, at?: string | null): string {
  const base = `/attacks/${encodeURIComponent(sessionId)}`
  return at ? `${base}?at=${encodeURIComponent(at)}` : base
}

const AT_SHAPE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/

/** The `?at=` of a session link when it is an ISO instant with a time zone, else undefined. */
export function parseAt(value: string | null): string | undefined {
  return value && AT_SHAPE.test(value) && !Number.isNaN(Date.parse(value)) ? value : undefined
}

// --- The group page ----------------------------------------------------------------------

/** One sentence that says what a flood group is, and what it is not. */
export function floodFinding(s: Pick<Session, "connections" | "kind">): string {
  const n = connectionsOf(s)
  return `None of the ${formatNumber(n)} connections got in, ran a command or downloaded a file. They are shown as one row because one address opened this many in the same hour.`
}

/** The finding of the "Credentials tried" card. */
export function credentialsFinding(c: SessionCredentials): string {
  if (c.attempts <= 0) return "No login was tried."
  const users = plural(c.distinct_usernames, "username")
  // A client that sends a hash (RDP with NLA) leaves the password empty.
  const [only] = c.passwords
  if (c.passwords.length === 1 && only?.value === "") {
    return `${plural(c.attempts, "attempt")} with ${users}, and no password was captured.`
  }
  const secrets = plural(c.distinct_passwords, "password")
  const head = `${plural(c.attempts, "attempt")}, ${users} and ${secrets}`
  if (c.attempts > 1 && c.distinct_pairs === c.attempts) return `${head}: no pair was tried twice.`
  if (c.distinct_pairs * 2 <= c.attempts) {
    return `${head}: ${plural(c.distinct_pairs, "pair")} tried over and over.`
  }
  return `${head}.`
}
