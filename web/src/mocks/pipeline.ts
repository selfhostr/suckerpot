import { delay, http, HttpResponse } from "msw"
import type { PipelineStatus } from "@/lib/pipeline"

export type PipelineVariant = "ok" | "stalled" | "parked" | "unknown"

declare global {
  interface Window {
    /** Tests and screenshots: force a pipeline state before the request. */
    __SUCKERPOT_PIPELINE__?: PipelineVariant
  }
}

/** `?pipeline=stalled|parked|unknown` on the page address, or the window hook. Default `ok`. */
function variant(): PipelineVariant {
  const fromWindow = window.__SUCKERPOT_PIPELINE__
  if (fromWindow) return fromWindow
  const q = new URLSearchParams(window.location.search).get("pipeline")
  return q === "stalled" || q === "parked" || q === "unknown" ? q : "ok"
}

export function pipelineStatus(v: PipelineVariant, now = Date.now()): PipelineStatus {
  const ago = (s: number) => new Date(now - s * 1000).toISOString()
  const base: PipelineStatus = {
    status: "ok",
    last_ok_at: ago(4),
    stalled_for_seconds: 0,
    failing_since: null,
    last_error: null,
    parked_events: 0,
  }
  if (v === "stalled")
    return {
      ...base,
      status: "stalled",
      last_ok_at: ago(42 * 60),
      stalled_for_seconds: 42 * 60,
      failing_since: ago(42 * 60),
      last_error: "57014 QueryCanceledError on events:ssh",
    }
  if (v === "parked") return { ...base, parked_events: 3 }
  return base
}

export const pipelineHandlers = [
  http.get("/api/v1/settings/pipeline", async () => {
    await delay(100)
    const v = variant()
    if (v === "unknown") return new HttpResponse(null, { status: 404 })
    return HttpResponse.json(pipelineStatus(v))
  }),
]
