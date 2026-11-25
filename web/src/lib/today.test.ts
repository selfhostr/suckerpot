import { describe, expect, it } from "vitest"
import type { OutboxItem } from "./alerts"
import { alertsSentence, pickTodo, type TodayCardData } from "./today"

const card = (id: TodayCardData["id"], empty = false): TodayCardData => ({
  id,
  sentence: id,
  items: [],
  action: { label: id, to: `/${id}` },
  empty,
})

describe("pickTodo", () => {
  it("leaves out what happened, puts news first, keeps the order and caps at three", () => {
    const cards = [
      card("happened"),
      card("exposure"),
      card("act", true),
      card("new_week"),
      card("campaigns"),
      card("forms"),
    ]
    expect(pickTodo(cards).map((c) => c.id)).toEqual(["forms", "campaigns", "new_week"])
  })

  it("falls back to the quiet cards, in order", () => {
    expect(pickTodo([card("campaigns", true), card("act", true)]).map((c) => c.id)).toEqual([
      "act",
      "campaigns",
    ])
  })
})

describe("alertsSentence", () => {
  const now = Date.parse("2026-11-25T12:00:00Z")
  const item = (minutes: number, over: Partial<OutboxItem> = {}): OutboxItem => ({
    id: minutes,
    rule_kind: "malware_drop",
    channel_id: 1,
    channel_name: "Discord",
    state: "sent",
    attempts: 1,
    created_at: new Date(now - minutes * 60_000).toISOString(),
    sent_at: null,
    error_code: null,
    severity: "severe",
    title: "Malware was dropped on the honeypot",
    summary: null,
    ...over,
  })

  it("counts the last 24 hours and names the latest", () => {
    expect(alertsSentence([item(14), item(90, { state: "failed" }), item(2000)], now)).toBe(
      "2 sent in the last 24 hours (1 not delivered), the latest 14 min. ago: Malware was dropped on the honeypot.",
    )
  })

  it("says when none was sent", () => {
    expect(alertsSentence([item(2000)], now)).toBe("None in the last 24 hours.")
    expect(alertsSentence([], now)).toBe("None in the last 24 hours.")
  })
})
