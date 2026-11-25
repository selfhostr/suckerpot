import { describe, expect, it } from "vitest"
import type { Attacker } from "./api"
import { attackerSeverity, describeAttacker, describeAttackerText } from "./describe-attacker"

const base: Attacker = {
  ip: "203.0.113.9",
  first_seen: "2026-10-18T10:00:00Z",
  last_seen: "2026-10-24T10:00:00Z",
  sessions: 14,
  events: 400,
  sensors: ["ssh", "telnet"],
  login_attempts: 120,
  login_success: 2,
  commands: 9,
  downloads: 1,
  country: "NL",
  city: "Amsterdam",
  asn: 64496,
  org: "Example Hosting",
  abuse_score: null,
  known_scanner: null,
  tags: [],
}

describe("describeAttacker", () => {
  it("tells the whole story in one line", () => {
    expect(describeAttackerText(base)).toBe(
      "203.0.113.9 · Netherlands, Example Hosting: 14 sessions over 6 days on SSH and Telnet, got in twice, ran 9 commands, tried to download 1 file",
    )
  })
  it("keeps a single probe short", () => {
    const a = {
      ...base,
      sessions: 1,
      sensors: ["web"],
      login_attempts: 0,
      login_success: 0,
      commands: 0,
      downloads: 0,
    }
    expect(describeAttacker(a)).toBe("1 session on Web")
  })
  it("says when nobody got in", () => {
    const a = {
      ...base,
      login_success: 0,
      commands: 0,
      downloads: 0,
      last_seen: "2026-10-18T20:00:00Z",
    }
    expect(describeAttacker(a)).toBe("14 sessions within a day on SSH and Telnet, never got in")
  })
})

describe("attackerSeverity", () => {
  it("is severe on downloads, warning on a shell, notice on attempts", () => {
    expect(attackerSeverity(base)).toBe("severe")
    expect(attackerSeverity({ ...base, downloads: 0 })).toBe("warning")
    expect(attackerSeverity({ ...base, downloads: 0, login_success: 0, commands: 0 })).toBe(
      "notice",
    )
  })
})
