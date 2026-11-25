import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, useLocation } from "react-router"
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { searchApi, type SearchResponse } from "@/lib/search"
import { stubResizeObserver } from "@/test/dom-stubs"
import { SearchPaletteProvider, SearchTrigger } from "./search-palette"

beforeAll(() => {
  stubResizeObserver()
  Element.prototype.scrollIntoView = () => undefined // cmdk scrolls the selected item into view
})

const RESULT: SearchResponse = {
  q: "203.0.113.7",
  groups: [
    {
      kind: "ip",
      more: false,
      hits: [
        {
          kind: "ip",
          value: "203.0.113.7",
          label: "203.0.113.7",
          detail: "NL · Polder Cloud BV",
          count: 12,
          last_seen: "2026-10-24T10:00:00Z",
          benign: false,
        },
      ],
    },
    {
      kind: "campaign",
      more: true,
      hits: [
        {
          kind: "campaign",
          value: "41",
          label: "Mirai loader over Telnet #41",
          detail: "9 sources, active",
          count: 37,
          last_seen: null,
          benign: false,
        },
      ],
    },
  ],
}

function Where() {
  return <output aria-label="location">{useLocation().pathname}</output>
}

function mount() {
  return render(
    <MemoryRouter>
      <IpMaskProvider>
        <QueryClientProvider
          client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
        >
          <SearchPaletteProvider>
            <SearchTrigger />
            <Where />
          </SearchPaletteProvider>
        </QueryClientProvider>
      </IpMaskProvider>
    </MemoryRouter>,
  )
}

describe("search palette", () => {
  const search = vi.spyOn(searchApi, "search")

  beforeEach(() => {
    localStorage.clear()
    search.mockReset()
    search.mockResolvedValue(RESULT)
  })
  afterEach(() => vi.clearAllMocks())

  it("opens with Ctrl+K and from the header box, and closes with Escape", async () => {
    const user = userEvent.setup()
    mount()
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    await user.keyboard("{Control>}k{/Control}")
    expect(await screen.findByRole("dialog", { name: "Search" })).toBeVisible()
    await user.keyboard("{Escape}")
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Search" }))
    expect(await screen.findByRole("dialog")).toBeVisible()
    expect(screen.getByRole("combobox", { name: "Search" })).toHaveFocus()
  })

  it("also answers the Cmd+K of a Mac", async () => {
    const user = userEvent.setup()
    mount()
    await user.keyboard("{Meta>}k{/Meta}")
    expect(await screen.findByRole("dialog")).toBeVisible()
  })

  it("waits for two characters, then shows grouped hits and opens one with Enter", async () => {
    const user = userEvent.setup()
    mount()
    await user.keyboard("{Control>}k{/Control}")
    await screen.findByRole("combobox", { name: "Search" })
    await user.keyboard("2")
    expect(screen.getByText(/Type at least two characters/)).toBeInTheDocument()
    expect(search).not.toHaveBeenCalled()

    await user.keyboard("03.0.113.7")
    expect(await screen.findByText("Addresses")).toBeInTheDocument()
    expect(search).toHaveBeenLastCalledWith("203.0.113.7")
    expect(screen.getByText("Campaigns")).toBeInTheDocument()
    expect(screen.getByText("12 sessions")).toBeInTheDocument()
    expect(screen.getByText(/More matches exist/)).toBeInTheDocument()

    await user.keyboard("{Enter}")
    await waitFor(() =>
      expect(screen.getByLabelText("location")).toHaveTextContent("/attackers/203.0.113.7"),
    )
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    // The next time, the search is offered again.
    await user.keyboard("{Control>}k{/Control}")
    await screen.findByRole("combobox", { name: "Search" })
    expect(await screen.findByText("203.0.113.7", { selector: "span" })).toBeInTheDocument()
  })

  it("says so when nothing matches", async () => {
    search.mockResolvedValue({ q: "zzzz", groups: [] })
    const user = userEvent.setup()
    mount()
    await user.keyboard("{Control>}k{/Control}")
    await screen.findByRole("combobox", { name: "Search" })
    await user.keyboard("zzzz")
    expect(await screen.findByText(/Nothing matches/)).toBeInTheDocument()
  })

  it("masks addresses in the results when screenshot mode is on", async () => {
    localStorage.setItem("suckerpot.maskIps", "1")
    const user = userEvent.setup()
    mount()
    await user.keyboard("{Control>}k{/Control}")
    await screen.findByRole("combobox", { name: "Search" })
    await user.keyboard("203.0.113.7")
    await screen.findByText("Addresses")
    expect(screen.getByText("203.0.x.x")).toBeInTheDocument()
    expect(screen.queryByText("203.0.113.7", { selector: "span" })).not.toBeInTheDocument()
  })
})
