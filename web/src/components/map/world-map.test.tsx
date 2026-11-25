import { act, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import type { Source } from "./activity"
import { project } from "./projection"
import { MAP_PRESETS, WorldMap } from "./world-map"

const KEY = "suckerpot.map.preset"

function mount(extra: Partial<React.ComponentProps<typeof WorldMap>> = {}) {
  return render(
    <MemoryRouter>
      <WorldMap
        {...extra}
        activity={{ sources: [], events: 0, unlocated: 0 }}
        events={[]}
        home={{ lat: 46.8, lon: 8.2 }}
        homeLabel="Switzerland"
        paused={false}
        now={Date.now()}
      />
    </MemoryRouter>,
  )
}

afterEach(() => {
  localStorage.clear()
  delete (window as unknown as { __SUCKERPOT_MAP__?: unknown }).__SUCKERPOT_MAP__
})

/** Radix Select leans on pointer capture and scrolling, which jsdom lacks. */
function polyfillSelect() {
  const proto = Element.prototype as unknown as Record<string, unknown>
  proto.hasPointerCapture ??= () => false
  proto.setPointerCapture ??= () => {}
  proto.releasePointerCapture ??= () => {}
  proto.scrollIntoView ??= () => {}
}

/** Picks a continent in the dropdown. */
async function pickContinent(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(screen.getByRole("combobox", { name: "Continent" }))
  await user.click(await screen.findByRole("option", { name }))
}

describe("WorldMap presets", () => {
  beforeEach(polyfillSelect)

  it("opens on the World view by default", () => {
    mount()
    expect(screen.getByRole("button", { name: "World" })).toHaveAttribute("aria-pressed", "true")
    expect(screen.getByRole("combobox", { name: "Continent" })).toHaveTextContent("Continent")
    expect(screen.getByText("Switzerland")).toBeInTheDocument()
  })

  it("remembers Europe once chosen, and World again after a reset", async () => {
    const user = userEvent.setup()
    const { unmount } = mount()
    await pickContinent(user, "Europe")
    expect(localStorage.getItem(KEY)).toBe("europe")
    unmount()
    mount()
    expect(screen.getByRole("combobox", { name: "Continent" })).toHaveTextContent("Europe")
    expect(screen.getByRole("button", { name: "World" })).toHaveAttribute("aria-pressed", "false")
    // The 0 key (reset) goes back to the world.
    screen.getByRole("group", { name: /Map of attack origins/ }).focus()
    await user.keyboard("0")
    expect(localStorage.getItem(KEY)).toBe("world")
  })
})

describe("WorldMap regions", () => {
  beforeEach(polyfillSelect)

  it("offers a World toggle and a dropdown of the six continents", async () => {
    const user = userEvent.setup()
    mount()
    const group = screen.getByRole("group", { name: "Region" })
    expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["World"])
    await user.click(screen.getByRole("combobox", { name: "Continent" }))
    expect((await screen.findAllByRole("option")).map((o) => o.textContent)).toEqual([
      "Europe",
      "North America",
      "South America",
      "Africa",
      "Asia",
      "Oceania",
    ])
  })

  it("picks a continent, and the World toggle goes back", async () => {
    const user = userEvent.setup()
    mount()
    await pickContinent(user, "Oceania")
    expect(localStorage.getItem(KEY)).toBe("oceania")
    expect(screen.getByRole("combobox", { name: "Continent" })).toHaveTextContent("Oceania")
    expect(screen.getByRole("button", { name: "World" })).toHaveAttribute("aria-pressed", "false")
    await user.click(screen.getByRole("button", { name: "World" }))
    expect(localStorage.getItem(KEY)).toBe("world")
    expect(screen.getByRole("button", { name: "World" })).toHaveAttribute("aria-pressed", "true")
  })

  it("reads a stored choice, and falls back to the world for an unknown one", () => {
    localStorage.setItem(KEY, "africa")
    const first = mount()
    expect(screen.getByRole("combobox", { name: "Continent" })).toHaveTextContent("Africa")
    first.unmount()
    localStorage.setItem(KEY, "atlantis")
    mount()
    expect(screen.getByRole("button", { name: "World" })).toHaveAttribute("aria-pressed", "true")
  })

  it("keeps the whole north and south of every region inside the map area", () => {
    // Latitudes of the land each region must show: [south, north].
    const LAND: Record<(typeof MAP_PRESETS)[number], [number, number]> = {
      world: [-55.5, 83.5],
      europe: [35, 71],
      "north-america": [8, 83.5],
      "south-america": [-55.5, 12.5],
      africa: [-34.9, 37.3],
      asia: [-10.5, 77.7],
      oceania: [-47.5, 2],
    }
    for (const p of MAP_PRESETS) {
      localStorage.setItem(KEY, p)
      const { container, unmount } = mount()
      const [, y = 0, , h = 0] = (
        container.querySelector("use")?.closest("svg")?.getAttribute("viewBox") ?? ""
      )
        .split(" ")
        .map(Number)
      const [south, north] = LAND[p]
      expect(y, p).toBeLessThan(project(north, 0)[1])
      expect(y + h, p).toBeGreaterThan(project(south, 0)[1])
      unmount()
    }
  })

  it("shows an expand button, or a close one in the expanded view", async () => {
    const user = userEvent.setup()
    const onExpand = vi.fn()
    const first = mount({ onExpand })
    await user.click(screen.getByRole("button", { name: "Expand the map" }))
    expect(onExpand).toHaveBeenCalledOnce()
    first.unmount()
    const onClose = vi.fn()
    mount({ onClose })
    expect(screen.queryByRole("button", { name: "Expand the map" })).toBeNull()
    await user.click(screen.getByRole("button", { name: "Close" }))
    expect(onClose).toHaveBeenCalledOnce()
  })
})

const NOW = Date.parse("2026-11-25T12:00:00Z")

function source(country: string, ageMs: number): Source {
  return {
    country,
    point: { lat: 52.5, lon: 13.4 },
    events: 12,
    ips: 3,
    topIp: "203.0.113.7",
    sensors: ["ssh"],
    family: "shell",
    last: NOW - ageMs,
    lastId: 1,
  }
}

function mountWith(sources: Source[]) {
  return render(
    <MemoryRouter>
      <WorldMap
        activity={{ sources, events: 12 * sources.length, unlocated: 0 }}
        events={[]}
        home={{ lat: 46.8, lon: 8.2 }}
        homeLabel="Switzerland"
        paused={false}
        now={NOW}
      />
    </MemoryRouter>,
  )
}

const rings = (c: HTMLElement) => c.querySelectorAll(".animate-map-pulse").length

describe("WorldMap layers", () => {
  it("draws land and borders from the static map asset, not from inline paths", () => {
    const { container } = mountWith([])
    const hrefs = [...container.querySelectorAll("use")].map((u) => u.getAttribute("href"))
    expect(hrefs).toHaveLength(2)
    expect(hrefs[0]).toMatch(/world\.svg#land$/)
    expect(hrefs[1]).toMatch(/world\.svg#borders$/)
  })

  it("pulses home and the sources active in the last minute, as HTML rings", () => {
    const { container } = mountWith([source("DE", 10_000), source("FR", 5 * 60_000)])
    // Home and DE; FR is older than a minute.
    expect(rings(container)).toBe(2)
    expect(container.querySelector("svg .animate-map-pulse")).toBeNull()
  })

  it("does not pulse when motion is frozen", () => {
    ;(window as unknown as { __SUCKERPOT_MAP__: { freeze: boolean } }).__SUCKERPOT_MAP__ = {
      freeze: true,
    }
    const { container } = mountWith([source("DE", 10_000)])
    expect(rings(container)).toBe(0)
    // The picture itself is the same: the dot is still there.
    expect(container.querySelectorAll("circle").length).toBeGreaterThanOrEqual(3)
  })

  it("stops pulsing while the tab is hidden", () => {
    const { container } = mountWith([source("DE", 10_000)])
    expect(rings(container)).toBe(2)
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" })
    try {
      act(() => {
        document.dispatchEvent(new Event("visibilitychange"))
      })
      expect(rings(container)).toBe(0)
    } finally {
      // Back to the prototype's getter.
      delete (document as unknown as { visibilityState?: unknown }).visibilityState
    }
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"))
    })
    expect(rings(container)).toBe(2)
  })
})
