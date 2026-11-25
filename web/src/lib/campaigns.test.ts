import { describe, expect, it } from "vitest"
import {
  dailyFromHourly,
  describeCampaigns,
  describeMatrix,
  describeScale,
  foldRepeats,
  stageReach,
  stageTrailText,
  techniqueDays,
  windowDays,
  type Campaign,
  type Matrix,
  type MatrixRow,
} from "./campaigns"

function campaign(over: Partial<Campaign> = {}): Campaign {
  return {
    id: 1,
    name: "Mirai-style loader over Telnet #1",
    status: "active",
    merged_into: null,
    first_seen: "2026-10-20T10:00:00Z",
    last_seen: "2026-10-24T10:00:00Z",
    sessions: 87,
    sources: 23,
    countries: ["FR", "DE", "NL"],
    asns: [64496],
    sensors: ["telnet"],
    techniques: ["T1110"],
    stages: ["access"],
    tags: [],
    families: [],
    severity: "severe",
    rep_session_id: null,
    demo: false,
    ...over,
  }
}

function row(
  id: string,
  stage: MatrixRow["stage"],
  counts: number[],
  plain = "did a thing",
): MatrixRow {
  return {
    id,
    name: id,
    tactic: "x",
    stage,
    url: "https://attack.example/",
    plain,
    total_sessions: counts.reduce((a, b) => a + b, 0),
    total_events: 0,
    counts,
  }
}

describe("describeCampaigns", () => {
  it("opens with a count and how many are still active", () => {
    const items = [campaign(), campaign({ id: 2, status: "quiet" })]
    expect(describeCampaigns(items, { days: 30, more: false })).toBe(
      "2 campaigns in the last 30 days, 1 still active.",
    )
  })

  it("says so when everything is active, or nothing is", () => {
    expect(describeCampaigns([campaign()], { days: 7, more: false })).toBe(
      "1 campaign in the last 7 days, all still active.",
    )
    expect(describeCampaigns([campaign({ status: "quiet" })], { days: 0, more: false })).toBe(
      "1 campaign on record, all quiet now.",
    )
    expect(describeCampaigns([], { days: 30, more: false })).toBe(
      "No campaigns in the last 30 days.",
    )
  })

  it("does not claim a total while more pages exist", () => {
    expect(describeCampaigns([campaign()], { days: 30, more: true })).toBe(
      "1+ campaigns in the last 30 days, 1 still active.",
    )
  })
})

describe("describeScale", () => {
  it("reads as one phrase", () => {
    expect(describeScale(campaign())).toBe("87 sessions from 23 addresses in 3 countries")
    expect(describeScale(campaign({ sessions: 1, sources: 1, countries: ["FR"] }))).toBe(
      "1 session from 1 address in 1 country",
    )
    expect(describeScale(campaign({ countries: [] }))).toBe("87 sessions from 23 addresses")
  })
})

describe("stageTrailText", () => {
  it("is always in story order", () => {
    expect(stageTrailText(["objective", "recon", "access"])).toBe(
      "Looking around → Getting in → The goal",
    )
    expect(stageTrailText([])).toBe("No stages recorded")
  })
})

describe("windows", () => {
  it("falls back to 30 days", () => {
    expect(windowDays(null)).toBe(30)
    expect(windowDays("all")).toBe(0)
    expect(windowDays("junk")).toBe(30)
    expect(techniqueDays("90")).toBe(90)
    expect(techniqueDays("all")).toBe(30)
  })
})

describe("matrix helpers", () => {
  const matrix: Matrix = {
    since: "2026-10-18",
    until: "2026-10-24",
    days: ["2026-10-22", "2026-10-23", "2026-10-24"],
    stages: [],
    rows: [
      row("T1110", "access", [4, 6, 10], "guessed passwords"),
      row("T1082", "recon", [1, 1, 1]),
      row("T1078", "access", [0, 1, 1]),
    ],
  }

  it("opens with the most common move", () => {
    expect(describeMatrix(matrix, 33)).toBe(
      "Attackers used 3 techniques of the 33 we watch for in the last 3 days. Most often they guessed passwords.",
    )
    expect(describeMatrix({ ...matrix, rows: [] }, 33)).toBe(
      "No techniques were seen in the last 3 days.",
    )
  })
})

describe("dailyFromHourly", () => {
  it("sums hours into UTC days and fills quiet days", () => {
    const now = Date.parse("2026-10-24T12:00:00Z")
    const points = [
      { ts: "2026-10-24T09:00:00Z", sessions: 2 },
      { ts: "2026-10-24T10:00:00Z", sessions: 3 },
      { ts: "2026-10-22T10:00:00Z", sessions: 1 },
    ]
    expect(dailyFromHourly(points, 3, now)).toEqual([
      { day: "2026-10-22", events: 1 },
      { day: "2026-10-23", events: 0 },
      { day: "2026-10-24", events: 5 },
    ])
  })
})

describe("stageReach", () => {
  it("says how far the playbook went, in words", () => {
    expect(stageReach(["tool_transfer", "access", "execution"])).toBe(
      "3 stages, up to bringing tools",
    )
    expect(stageReach(["access"])).toBe("1 stage: getting in")
    expect(stageReach([])).toBe("No stages recorded")
  })
})

describe("foldRepeats", () => {
  it("folds back-to-back repeats only", () => {
    const folded = foldRepeats([
      { kind: "command", text: "whoami" },
      { kind: "command", text: "whoami" },
      { kind: "command", text: "uname -a" },
      { kind: "command", text: "whoami" },
    ])
    expect(folded.map((f) => [f.line.text, f.times])).toEqual([
      ["whoami", 2],
      ["uname -a", 1],
      ["whoami", 1],
    ])
  })
})
