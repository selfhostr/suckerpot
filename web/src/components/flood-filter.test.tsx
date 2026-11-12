import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, useLocation } from "react-router"
import { describe, expect, it } from "vitest"
import { FloodFilter } from "./flood-filter"

function Where() {
  const { search } = useLocation()
  return <output aria-label="query string">{search}</output>
}

function mount(url: string) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <FloodFilter />
      <Where />
    </MemoryRouter>,
  )
}

const search = () => screen.getByLabelText("query string").textContent

describe("FloodFilter", () => {
  it("starts on All when the URL has no kind", () => {
    mount("/attacks")
    expect(screen.getByRole("radiogroup", { name: "Floods" })).toBeInTheDocument()
    expect(screen.getByRole("radio", { name: "Show everything, floods included" })).toBeChecked()
  })

  it("reads the choice from the URL", () => {
    mount("/attacks?kind=burst")
    expect(screen.getByRole("radio", { name: "Show only floods" })).toBeChecked()
  })

  it("reads Hide from kind=session", () => {
    mount("/attacks?kind=session")
    expect(screen.getByRole("radio", { name: "Hide floods" })).toBeChecked()
  })

  it("writes kind=session for Hide and kind=burst for Only, and drops it for All", async () => {
    const user = userEvent.setup()
    mount("/attacks?sensor=rdp")
    await user.click(screen.getByRole("radio", { name: "Hide floods" }))
    expect(search()).toBe("?sensor=rdp&kind=session")
    await user.click(screen.getByRole("radio", { name: "Show only floods" }))
    expect(search()).toBe("?sensor=rdp&kind=burst")
    await user.click(screen.getByRole("radio", { name: "Show everything, floods included" }))
    // The other filters stay.
    expect(search()).toBe("?sensor=rdp")
  })

  it("works with the keyboard", async () => {
    const user = userEvent.setup()
    mount("/attacks")
    await user.tab()
    await user.keyboard("{ArrowRight}")
    await user.keyboard("{Enter}")
    expect(search()).toBe("?kind=session")
  })
})
