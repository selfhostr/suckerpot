import { describe, expect, it } from "vitest"
import { ApiError } from "./api"
import {
  ALL_CONSENTS,
  bootstrapSentence,
  CONSENTS,
  daysToTakedown,
  defangValue,
  eligibilityText,
  formatDay,
  impactFinding,
  memberName,
  neverShared,
  targetsFinding,
  toNetworkError,
  validatePseudonym,
  waitingText,
  weeklyFinding,
  type NetworkImpact,
  type NetworkStatus,
  type NetworkTarget,
  type NetworkTotals,
} from "./network"

const IMPACT: NetworkImpact = {
  network: {
    confirmed_30d: 412,
    reported_30d: 318,
    taken_down_30d: 141,
    median_days_to_takedown: 4,
  },
  mine: { helped_confirm_30d: 23, helped_takedown_30d: 9 },
}

describe("consent", () => {
  it("lists all five things, each with a plain description", () => {
    expect(ALL_CONSENTS).toEqual(["sources", "payloads", "c2", "files", "rechecks"])
    for (const c of CONSENTS) expect(c.shared.length).toBeGreaterThan(40)
  })

  it("says what is never shared, including credentials and exact times", () => {
    const text = neverShared().join(" ").toLowerCase()
    for (const word of ["passwords", "commands", "ports", "exact times", "your own address"])
      expect(text).toContain(word)
  })

  it("never names the old product", () => {
    const all = JSON.stringify([CONSENTS, neverShared()])
    expect(all).not.toMatch(/suckerpot/i)
  })
})

describe("pseudonym", () => {
  it("accepts empty (anonymous) and simple names", () => {
    expect(validatePseudonym("")).toBeNull()
    expect(validatePseudonym("  ")).toBeNull()
    expect(validatePseudonym("night-owl")).toBeNull()
    expect(validatePseudonym("Gray Heron 7")).toBeNull()
  })

  it("refuses what the server refuses", () => {
    expect(validatePseudonym("ab")).toMatch(/3 to 24/)
    expect(validatePseudonym("x".repeat(25))).toMatch(/3 to 24/)
    expect(validatePseudonym("me@example.org")).toMatch(/@/)
    expect(validatePseudonym("see http://example.org")).toMatch(/link/)
    expect(validatePseudonym("owl2026")).toMatch(/4 digits/)
    expect(validatePseudonym("-owl-")).not.toBeNull()
    expect(validatePseudonym("Admin")).toMatch(/reserved/)
  })
})

describe("sentences", () => {
  it("opens the overview with what the network did and what the sensor did", () => {
    expect(impactFinding(IMPACT)).toBe(
      "The network took down 141 malware hosts and attack sources in the last 30 days. Your sensor helped confirm 23 of the 412 it confirmed.",
    )
  })

  it("is honest when nothing happened yet", () => {
    const none: NetworkImpact = {
      network: {
        confirmed_30d: 0,
        reported_30d: 0,
        taken_down_30d: 0,
        median_days_to_takedown: null,
      },
      mine: { helped_confirm_30d: 0, helped_takedown_30d: 0 },
    }
    expect(impactFinding(none)).toBe(
      "The network has not taken anything down in the last 30 days yet. Your sensor has not helped confirm any yet.",
    )
  })

  it("asks for five active members before the network confirms anything", () => {
    const totals = { active_7d: 3 } as NetworkTotals
    expect(bootstrapSentence(totals)).toBe(
      "The network needs 5 active members before it confirms anything. It has 3 now.",
    )
    expect(bootstrapSentence({ active_7d: 5 } as NetworkTotals)).toBeNull()
  })

  it("compares the last two weeks", () => {
    const w = (taken_down: number, week: string) => ({
      week,
      confirmed: 1,
      reported: 1,
      taken_down,
    })
    expect(weeklyFinding([w(29, "2026-10-12"), w(36, "2026-10-19")])).toBe(
      "36 targets were taken down this week, up from 29 the week before.",
    )
    expect(weeklyFinding([w(36, "2026-10-12"), w(29, "2026-10-19")])).toContain("down from 36")
    expect(weeklyFinding([])).toBe("There are no weekly figures yet.")
  })

  it("describes the filters of the targets list", () => {
    expect(targetsFinding({ state: "taken_down", kind: "all", mine: false })).toBe(
      "The latest targets taken down from all members, newest first.",
    )
    expect(targetsFinding({ state: "reported", kind: "ip", mine: true })).toContain(
      "that your sensor helped confirm",
    )
  })

  it("shows days as days, in UTC", () => {
    expect(formatDay("2026-11-15")).toBe("Nov 15")
    expect(formatDay("2026-11-15", true)).toBe("Nov 15, 2026")
    expect(formatDay(null)).toBe("–")
  })

  it("says from when a young node counts", () => {
    const s = { eligible_from_day: "2026-11-15" } as NetworkStatus
    expect(eligibilityText(s, "2026-11-01")).toBe("Counts toward confirmations from Nov 15")
    expect(eligibilityText(s, "2026-11-20")).toBe("Counts toward confirmations")
  })
})

describe("members and targets", () => {
  it("lists a member by pseudonym or node number", () => {
    expect(memberName({ pseudonym: "night-owl", fingerprint: "3f9a1c07" })).toBe("night-owl")
    expect(memberName({ pseudonym: null, fingerprint: "3f9a1c07" })).toBe("Node 3f9a1c07")
  })

  it("defangs links so they cannot be clicked by mistake", () => {
    expect(defangValue("http://198.51.100.9/bins/x86")).toBe("hxxp://198[.]51[.]100[.]9/bins/x86")
    expect(defangValue("cdn.example.org")).toBe("cdn[.]example[.]org")
  })

  it("counts days from first sighting to takedown", () => {
    const t = { first_day: "2026-10-26", taken_down_day: "2026-10-30" } as NetworkTarget
    expect(daysToTakedown(t)).toBe(4)
    expect(daysToTakedown({ ...t, taken_down_day: null })).toBeNull()
  })
})

describe("errors", () => {
  it("maps the API failures to readable ones", () => {
    expect(toNetworkError(new ApiError(403, "x", "reauth_failed")).reason).toBe("wrong-password")
    expect(toNetworkError(new ApiError(409, "x", "pseudonym_taken")).reason).toBe("taken")
    expect(toNetworkError(new ApiError(422, "x", "consent_required")).detail).toMatch(/five boxes/)
    expect(toNetworkError(new ApiError(429, "x")).reason).toBe("rate-limited")
    expect(toNetworkError(new ApiError(409, "x", "already_member")).detail).toMatch(/already asked/)
    expect(toNetworkError(new ApiError(409, "x", "not_member")).detail).toMatch(/not part/)
    expect(toNetworkError(new Error("offline")).reason).toBe("network")
  })
})

describe("waiting", () => {
  it("says the enrolment wait is temporary and handled by the sensor", () => {
    expect(waitingText("enrolment")).toMatch(/tries again later by itself/)
    expect(waitingText(null)).toBeNull()
  })
})
