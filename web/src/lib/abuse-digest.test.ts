import { describe, expect, it, vi } from "vitest"
import { ApiError } from "./api"
import {
  describeDue,
  describeReport,
  describeSources,
  kindLabel,
  localToUtcMinute,
  SAME_DAY_QUESTION,
  utcMinuteToLocal,
  withSameDayConfirm,
  type ReportItem,
} from "./abuse"

describe("daily digests", () => {
  it("counts the sources of a digest by kind", () => {
    expect(
      describeSources({
        kind: "digest",
        subject_count: 12,
        kinds: { attack_source: 9, payload_host: 3 },
      }),
    ).toBe("12 sources (9 attack sources, 3 payload hosts)")
    expect(describeSources({ kind: "digest", subject_count: 1, kinds: { c2: 1 } })).toBe(
      "1 source (1 command server)",
    )
    // An older report of one kind keeps a plain count.
    expect(describeSources({ kind: "payload_host", subject_count: 2 })).toBe("2 payload hosts")
    expect(kindLabel("digest")).toBe("Daily digest")
    expect(kindLabel("c2")).toBe("C2 server")
  })

  it("says when a digest goes, in local time", () => {
    const now = new Date(2026, 10, 21, 6, 0)
    const at = (h: number, m: number, day = 21) => new Date(2026, 10, day, h, m).toISOString()
    expect(describeDue({ status: "draft", due_at: at(7, 42) }, now)).toBe("goes at 07:42")
    expect(describeDue({ status: "reviewed", due_at: at(7, 42, 22) }, now)).toBe(
      "goes tomorrow at 07:42",
    )
    expect(describeDue({ status: "draft", due_at: at(7, 42, 24) }, now)).toBe(
      "waiting for a later day",
    )
    expect(describeDue({ status: "sent", due_at: at(7, 42) }, now)).toBeNull()
    expect(describeDue({ status: "draft", due_at: null }, now)).toBeNull()
  })

  it("describes a digest report on its page", () => {
    const r = {
      kind: "digest",
      subject_count: 3,
      kinds: { attack_source: 2, c2: 1 },
      asns: [{ asn: 64500, name: null }],
      recipient: { id: 1, name: "Example Hosting", mailbox: null, source: "rdap", muted: false },
    } as unknown as ReportItem
    expect(describeReport(r)).toBe(
      "3 sources (2 attack sources, 1 command server) in 1 network, reported to Example Hosting.",
    )
  })

  it("converts the digest hour between UTC minutes and local time", () => {
    const on = new Date(2026, 10, 21, 12, 0)
    for (const minute of [0, 462, 539, 1439]) {
      expect(localToUtcMinute(utcMinuteToLocal(minute, on), on)).toBe(minute)
    }
    expect(localToUtcMinute("7:40")).toBeNull()
    expect(localToUtcMinute("25:00")).toBeNull()
  })
})

describe("withSameDayConfirm", () => {
  const sameDay = new ApiError(
    409,
    "This provider already got a report today.",
    "recipient_sent_today",
  )

  it("asks once and retries with the confirmation", async () => {
    const run = vi.fn((confirm: boolean) =>
      confirm ? Promise.resolve("sent") : Promise.reject(sameDay),
    )
    const ask = vi.fn(() => true)
    await expect(withSameDayConfirm(run, ask)).resolves.toBe("sent")
    expect(ask).toHaveBeenCalledWith(SAME_DAY_QUESTION)
    expect(run.mock.calls).toEqual([[false], [true]])
  })

  it("sends nothing more when the owner says no", async () => {
    const run = vi.fn(() => Promise.reject(sameDay))
    await expect(withSameDayConfirm(run, () => false)).rejects.toBe(sameDay)
    expect(run).toHaveBeenCalledTimes(1)
  })

  it("does not ask for any other error", async () => {
    const other = new ApiError(409, "changed", "revision_mismatch")
    const ask = vi.fn(() => true)
    await expect(withSameDayConfirm(() => Promise.reject(other), ask)).rejects.toBe(other)
    expect(ask).not.toHaveBeenCalled()
  })
})
