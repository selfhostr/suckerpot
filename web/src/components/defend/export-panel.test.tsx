import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { ExportPanel } from "./export-panel"

function mount() {
  return render(
    <MemoryRouter>
      <ExportPanel summary={undefined} initialKind="ip" />
    </MemoryRouter>,
  )
}

describe("ExportPanel", () => {
  it("keeps the firewall steps out of the panel until asked", async () => {
    const user = userEvent.setup()
    mount()
    expect(screen.getByRole("link", { name: /Download IP addresses/ })).toBeInTheDocument()
    expect(screen.queryByText(/Name it suckerpot_block/)).not.toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Firewall steps" }))
    const sheet = screen.getByRole("dialog", { name: "Keep a firewall up to date" })
    const steps = within(sheet).getByRole("list", { name: "OPNsense steps" })
    expect(within(steps).getAllByRole("listitem")).toHaveLength(6)
    expect(within(sheet).getByText(/Firewall > Aliases, then Add/)).toBeInTheDocument()

    await user.click(within(sheet).getByRole("radio", { name: "pfSense" }))
    expect(within(sheet).getByRole("list", { name: "pfSense steps" })).toBeInTheDocument()
    expect(within(sheet).getByText(/Firewall > Aliases > URLs, then Add/)).toBeInTheDocument()
    expect(
      within(sheet).getByRole("button", { name: "Copy firewall instructions" }),
    ).toBeInTheDocument()
  })
})
