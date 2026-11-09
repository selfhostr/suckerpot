import { afterEach, describe, expect, it, vi } from "vitest"
import {
  fetchPipeline,
  formatStalledFor,
  parkedSentence,
  pipelineFinding,
  stalledSentence,
  UNKNOWN_PIPELINE,
} from "./pipeline"

describe("formatStalledFor", () => {
  it("uses minutes, hours and days", () => {
    expect(formatStalledFor(20)).toBe("less than a minute")
    expect(formatStalledFor(60)).toBe("1 minute")
    expect(formatStalledFor(42 * 60)).toBe("42 minutes")
    expect(formatStalledFor(3600)).toBe("1 hour")
    expect(formatStalledFor(11 * 3600 + 120)).toBe("11 hours")
    expect(formatStalledFor(2 * 86_400 + 5)).toBe("2 days")
  })
})

describe("sentences", () => {
  it("tells the loss in plain words", () => {
    expect(stalledSentence(42 * 60)).toBe(
      "Events have not been stored for 42 minutes. Attacks reaching your sensors are being lost.",
    )
    expect(parkedSentence(1)).toBe("1 event could not be stored and was set aside.")
    expect(parkedSentence(1200)).toBe("1,200 events could not be stored and were set aside.")
  })
  it("has a finding for every state", () => {
    expect(pipelineFinding(UNKNOWN_PIPELINE)).toMatch(/not available/)
    expect(pipelineFinding({ ...UNKNOWN_PIPELINE, status: "ok" })).toMatch(/normally/)
  })
})

describe("fetchPipeline", () => {
  afterEach(() => vi.unstubAllGlobals())
  it("maps a 404 and a network error to unknown", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(null, { status: 404 }))),
    )
    expect((await fetchPipeline()).status).toBe("unknown")
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new TypeError("offline"))),
    )
    expect((await fetchPipeline()).status).toBe("unknown")
  })
  it("reads a stalled answer", async () => {
    const body = {
      status: "stalled",
      stalled_for_seconds: 90,
      last_error: "boom",
      parked_events: 2,
    }
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify(body)))),
    )
    const p = await fetchPipeline()
    expect(p).toMatchObject({ status: "stalled", stalled_for_seconds: 90, last_error: "boom" })
  })
})
