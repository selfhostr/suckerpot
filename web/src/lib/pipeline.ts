/**
 * Pipeline health (`GET /api/v1/settings/pipeline`): is the service that stores events running?
 * Pure helpers, unit-tested. An older API (404) or a network error counts as `unknown`.
 */
import { getJson } from "./api"
import { plural } from "./format"

export type PipelineState = "ok" | "stalled" | "unknown"

export interface PipelineStatus {
  status: PipelineState
  last_ok_at: string | null
  stalled_for_seconds: number
  failing_since: string | null
  last_error: string | null
  parked_events: number
}

export const pipelineKey = ["settings", "pipeline"] as const

export const UNKNOWN_PIPELINE: PipelineStatus = {
  status: "unknown",
  last_ok_at: null,
  stalled_for_seconds: 0,
  failing_since: null,
  last_error: null,
  parked_events: 0,
}

/** Never throws: any failure (404 on an older API, network, bad body) is `unknown`. */
export async function fetchPipeline(): Promise<PipelineStatus> {
  try {
    const raw = await getJson<Partial<PipelineStatus>>("/settings/pipeline")
    if (raw.status !== "ok" && raw.status !== "stalled") return UNKNOWN_PIPELINE
    return {
      status: raw.status,
      last_ok_at: raw.last_ok_at ?? null,
      stalled_for_seconds: Math.max(0, Number(raw.stalled_for_seconds) || 0),
      failing_since: raw.failing_since ?? null,
      last_error: raw.last_error ?? null,
      parked_events: Math.max(0, Number(raw.parked_events) || 0),
    }
  } catch {
    return UNKNOWN_PIPELINE
  }
}

/** "less than a minute", "42 minutes", "3 hours", "2 days". */
export function formatStalledFor(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  if (s < 60) return "less than a minute"
  if (s < 3600) {
    const m = Math.floor(s / 60)
    return plural(m, "minute")
  }
  if (s < 86_400) {
    const h = Math.floor(s / 3600)
    return plural(h, "hour")
  }
  const d = Math.floor(s / 86_400)
  return plural(d, "day")
}

export function stalledSentence(seconds: number): string {
  const d = formatStalledFor(seconds)
  return `Events have not been stored for ${d}. They are waiting in a queue for now, but once it fills up, the oldest attacks are lost.`
}

export function parkedSentence(n: number): string {
  return `${plural(n, "event")} could not be stored and ${n === 1 ? "was" : "were"} set aside.`
}

/** Settings finding sentence. */
export function pipelineFinding(p: PipelineStatus): string {
  if (p.status === "stalled")
    return `Ingest has not checked in for ${formatStalledFor(p.stalled_for_seconds)}.`
  if (p.status === "ok")
    return p.parked_events > 0
      ? `Events are being stored, but ${plural(p.parked_events, "event")} had to be set aside.`
      : "Events are being stored normally."
  return "The pipeline status is not available."
}

const DISMISS_KEY = "suckerpot.pipeline.parked-dismissed"

export function parkedDismissed(count: number): boolean {
  try {
    return sessionStorage.getItem(DISMISS_KEY) === String(count)
  } catch {
    return false
  }
}

export function dismissParked(count: number): void {
  try {
    sessionStorage.setItem(DISMISS_KEY, String(count))
  } catch {
    // Private mode: the notice simply comes back on the next page load.
  }
}
