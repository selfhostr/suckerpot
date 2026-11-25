import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { Logo } from "./logo"

describe("Logo", () => {
  it("draws the official mark with its fixed colours", () => {
    const { container } = render(<Logo />)
    const svg = container.querySelector("svg")
    expect(svg?.getAttribute("viewBox")).toBe("0 0 64 64")
    const fills = Array.from(container.querySelectorAll("[fill]")).map((el) =>
      el.getAttribute("fill"),
    )
    expect(fills).toEqual(["#111419", "#a78bfa", "#111419", "#eceef1"])
  })

  it("shows the wordmark unless withName is off", () => {
    const { rerender } = render(<Logo />)
    expect(screen.getByText("SuckerPot")).toBeTruthy()
    rerender(<Logo withName={false} />)
    expect(screen.getByText("SuckerPot").className).toContain("sr-only")
  })
})
