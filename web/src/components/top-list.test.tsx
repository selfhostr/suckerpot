import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { TopList, type TopListItem } from "./top-list"

const item = (name: string, count: number, share: number): TopListItem => ({
  key: name,
  name,
  label: name,
  count,
  share,
  href: `/trends?password=${name}`,
})

function mount(items: TopListItem[], scale?: "max" | "total") {
  return render(
    <MemoryRouter>
      <TopList items={items} scale={scale} />
    </MemoryRouter>,
  )
}

const barWidths = (container: HTMLElement) =>
  [...container.querySelectorAll<HTMLElement>("[style]")].map((b) => b.style.width)

describe("TopList", () => {
  it("never prints a share that is not zero as 0%", () => {
    mount([item("Spring2026!", 1, 1 / 812)])
    expect(screen.getByText("<1%")).toBeInTheDocument()
    expect(screen.queryByText("0%")).not.toBeInTheDocument()
    expect(screen.getByRole("link", { name: /^Spring2026!: 1, <1%/ })).toBeInTheDocument()
  })

  it("stretches the bars against the busiest row by default", () => {
    const { container } = mount([item("a", 2, 0.2), item("b", 1, 0.1)])
    expect(barWidths(container)).toEqual(["100%", "50%"])
  })

  it("draws each share as printed with scale total, so tied rows are not full bars", () => {
    const { container } = mount([item("a", 1, 0.25), item("b", 1, 0.25)], "total")
    expect(barWidths(container)).toEqual(["25%", "25%"])
  })
})
