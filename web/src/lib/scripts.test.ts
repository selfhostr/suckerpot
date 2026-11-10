import { describe, expect, it } from "vitest"
import {
  describeScript,
  describeScripts,
  nextStep,
  type ExplainedLine,
  type ScriptItem,
  type ScriptsSummary,
} from "./scripts"

const summary: ScriptsSummary = {
  total: 1234,
  new_this_week: 3,
  seen_today: 20,
  with_campaign: 4,
  top_id: 1,
  top_summary: "A 4-step script that downloads a file and runs it.",
  top_sessions: 212,
}

const item: ScriptItem = {
  id: 7,
  fingerprint: "ab".repeat(32),
  summary: "A 3-step script that downloads a file, makes it executable and runs it.",
  preview: [],
  line_count: 3,
  first_seen: "2026-10-20T10:00:00Z",
  last_seen: "2026-10-23T10:00:00Z",
  sessions: 1,
  sources: 1,
  sensors: ["ssh"],
  techniques: [],
  campaign_id: null,
  campaign_name: null,
  risk: "severe",
  is_new: false,
}

const line = (over: Partial<ExplainedLine>): ExplainedLine => ({
  n: 1,
  text: "ls",
  raw: "ls",
  explanation: "x",
  risk: "info",
  technique: null,
  technique_name: null,
  rule: null,
  ...over,
})

describe("describeScripts", () => {
  it("says how many, how many are new and what the most common one does", () => {
    expect(describeScripts(summary)).toBe(
      "1,234 distinct scripts so far, 3 new this week. The most common one downloads a file and runs it (seen 212 times).",
    )
  })
  it("handles the empty and the quiet cases", () => {
    expect(describeScripts({ ...summary, total: 0 })).toMatch(/No attacker has typed/)
    expect(describeScripts({ ...summary, total: 1, new_this_week: 0, top_summary: null })).toBe(
      "1 distinct script so far, none of them new this week.",
    )
  })
})

describe("describeScript", () => {
  it("opens with what the script does and how widely it was seen", () => {
    expect(describeScript(item, item.summary)).toBe(
      "This 3-step script downloads a file, makes it executable and runs it. Seen 1 time from 1 address.",
    )
  })
  it("names the campaign and admits when nothing is known", () => {
    const text = describeScript(
      { ...item, sessions: 12, sources: 4, campaign_name: "Dropper wave" },
      null,
    )
    expect(text).toBe(
      'This 3-step script has no built-in explanation yet. Seen 12 times from 4 addresses, as part of the campaign "Dropper wave".',
    )
  })
})

describe("nextStep", () => {
  it("is advice, by what the script does", () => {
    expect(nextStep([line({ rule: "download", risk: "severe" })])).toMatch(
      /Block the download host/,
    )
    expect(nextStep([line({ risk: "severe", technique: "T1098.004" })])).toMatch(/authorized_keys/)
    expect(nextStep([line({}), line({ risk: null })])).toMatch(/only looks around/)
    expect(nextStep([line({ risk: "warning" })])).toMatch(/Review whether/)
  })
})
