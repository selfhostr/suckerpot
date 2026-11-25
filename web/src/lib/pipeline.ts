/**
 * Pipeline health (`GET /api/v1/settings/pipeline`): is the service that stores events running?
 * Pure helpers, unit-tested. An older API (404) or a network error counts as `unknown`.
 */
import { getJson } from "./api"
import { t } from "@/i18n"

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

/** The duration as a unit and a count, for the `{unit, select, ...}` of the messages below. */
function stalledParts(seconds: number): { unit: string; n: number } {
  const s = Math.max(0, Math.floor(seconds))
  if (s < 60) return { unit: "under_minute", n: 0 }
  if (s < 3600) return { unit: "minute", n: Math.floor(s / 60) }
  if (s < 86_400) return { unit: "hour", n: Math.floor(s / 3600) }
  return { unit: "day", n: Math.floor(s / 86_400) }
}

/** "less than a minute", "42 minutes", "3 hours", "2 days". */
export function formatStalledFor(seconds: number): string {
  return t("pipeline_stalled_for", stalledParts(seconds))
}

export function stalledSentence(seconds: number): string {
  return t("pipeline_stalled_sentence", stalledParts(seconds))
}

export function parkedSentence(n: number): string {
  return t("pipeline_parked_sentence", { count: n })
}

/** Settings finding sentence. */
export function pipelineFinding(p: PipelineStatus): string {
  if (p.status === "stalled") {
    return t("pipeline_finding_stalled", stalledParts(p.stalled_for_seconds))
  }
  if (p.status === "ok")
    return p.parked_events > 0
      ? t("pipeline_finding_ok_parked", { count: p.parked_events })
      : t("pipeline_finding_ok")
  return t("pipeline_finding_unknown")
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
