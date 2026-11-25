import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { Collapse } from "./collapse"

describe("Collapse", () => {
  it("mounts its content on the first open only", () => {
    const { rerender } = render(<Collapse open={false}>Details</Collapse>)
    expect(screen.queryByText("Details")).not.toBeInTheDocument()
    rerender(<Collapse open>Details</Collapse>)
    expect(screen.getByText("Details")).toBeInTheDocument()
  })

  it("keeps the content, inert, after closing so the close can animate", () => {
    const { container, rerender } = render(<Collapse open>Details</Collapse>)
    rerender(<Collapse open={false}>Details</Collapse>)
    const panel = container.firstElementChild as HTMLElement
    expect(screen.getByText("Details")).toBeInTheDocument()
    expect(panel).toHaveAttribute("inert")
    expect(panel).not.toHaveAttribute("data-open")
  })
})
