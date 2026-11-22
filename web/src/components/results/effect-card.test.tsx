import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import type { ReportEffect, ReportEffectResponse } from "@/lib/results"
import { EffectCard } from "./effect-card"

const FORBIDDEN = /\b(effective|works|worked|caused?|causes)\b/i

const progress: ReportEffect = {
  horizon: 7,
  verdict: "not_enough_data",
  pairs: 12,
  needed: 30,
  discordant: 4,
  needed_discordant: 10,
  seen_reported: null,
  seen_control: null,
  difference: null,
  lo: null,
  hi: null,
  sentence: "Not enough data yet to tell whether reports help: 12 of 30 comparable pairs.",
  interval: null,
}

const lower: ReportEffect = {
  horizon: 7,
  verdict: "lower",
  pairs: 84,
  needed: 30,
  discordant: 31,
  needed_discordant: 10,
  seen_reported: 32 / 84,
  seen_control: 51 / 84,
  difference: -19 / 84,
  lo: -0.37,
  hi: -0.09,
  sentence:
    "Reported sources were less often seen attacking a week later: 38 % against 61 % for similar sources that were not reported (84 pairs; the difference is between 9 and 37 points). This compares two groups; it does not prove that the reports made the difference.",
  interval: "between 9 and 37 points lower for reported sources",
}

const response = (effect: ReportEffect, over: Partial<ReportEffectResponse> = {}) =>
  ({
    since: "2026-08-24T00:00:00Z",
    until: "2026-11-22T00:00:00Z",
    available: true,
    running: true,
    effect,
    method: {
      pairs_made: 97,
      tiers: { A: 41, B: 30, C: 26 },
      waiting: 9,
      not_observed: 3,
      control_reported: 1,
      network_reported: 0,
      unmatched: 14,
      unmatched_reasons: { no_control: 11, no_activity: 3 },
      holdout_pct: 0,
      held_now: 0,
    },
    ...over,
  }) satisfies ReportEffectResponse

describe("EffectCard", () => {
  it("shows only the progress below the minimum, never a percentage", () => {
    const { container } = render(<EffectCard week={response(progress)} />)
    expect(screen.getByRole("heading", { level: 3 })).toHaveTextContent(
      "Not enough data yet to tell whether reports help: 12 of 30 comparable pairs.",
    )
    const meter = screen.getByRole("meter", { name: "Pairs measured so far" })
    expect(meter).toHaveAttribute("aria-valuenow", "12")
    expect(meter).toHaveAttribute("aria-valuemax", "30")
    // The disclosure mentions "21 days" and counts, but no share: no "%" anywhere.
    expect(container.textContent).not.toMatch(/%/)
    expect(screen.queryByText("Reported")).not.toBeInTheDocument()
  })

  it("counts discordant pairs once there are enough pairs", () => {
    const stuck = { ...progress, pairs: 100, discordant: 9 }
    render(<EffectCard week={response(stuck)} />)
    const meter = screen.getByRole("meter")
    expect(meter).toHaveAttribute("aria-valuenow", "9")
    expect(meter).toHaveAttribute("aria-valuemax", "10")
  })

  it("shows two neutral bars and the interval above the minimum", () => {
    const { container } = render(<EffectCard week={response(lower)} />)
    expect(screen.getByText("38 %")).toBeInTheDocument()
    expect(screen.getByText("61 %")).toBeInTheDocument()
    expect(
      screen.getByText(/between 9 and 37 points lower for reported sources/),
    ).toBeInTheDocument()
    expect(container.innerHTML).not.toMatch(/sev-|text-red|bg-red|text-green|bg-green/)
    expect(container.textContent).not.toMatch(FORBIDDEN)
  })

  it("adds the 30-day row only when that horizon has enough data", () => {
    const month = response({ ...lower, horizon: 30, sentence: "x" })
    render(<EffectCard week={response(lower)} month={month} />)
    expect(screen.getByText("After a month")).toBeInTheDocument()
    const short = response({ ...progress, horizon: 30 })
    render(<EffectCard week={response(lower)} month={short} />)
    expect(screen.getAllByText("After a month")).toHaveLength(1)
  })

  it("says how it is measured, including when the tracker is off", () => {
    render(<EffectCard week={response(progress, { running: false })} />)
    expect(screen.getByText("How this is measured")).toBeInTheDocument()
    expect(screen.getByText(/TAKEDOWN_ENABLED/)).toBeInTheDocument()
    expect(screen.getByText(/Random holdout:/)).toHaveTextContent("Random holdout: off")
  })
})
