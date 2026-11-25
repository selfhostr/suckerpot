import { act, render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, describe, expect, it } from "vitest"
import type { Source } from "./activity"
import { WorldMap } from "./world-map"

const KEY = "suckerpot.map.preset"

function mount() {
  return render(
    <MemoryRouter>
      <WorldMap
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

describe("WorldMap presets", () => {
  it("opens on the World view by default", () => {
    mount()
    expect(screen.getByRole("button", { name: "World" })).toHaveAttribute("aria-pressed", "true")
    expect(screen.getByRole("button", { name: "Europe" })).toHaveAttribute("aria-pressed", "false")
    expect(screen.getByText("Switzerland")).toBeInTheDocument()
  })

  it("remembers Europe once chosen, and World again after a reset", async () => {
    const user = userEvent.setup()
    const { unmount } = mount()
    await user.click(screen.getByRole("button", { name: "Europe" }))
    expect(localStorage.getItem(KEY)).toBe("europe")
    unmount()
    mount()
    expect(screen.getByRole("button", { name: "Europe" })).toHaveAttribute("aria-pressed", "true")
    // The 0 key (reset) goes back to the world.
    screen.getByRole("group", { name: /Map of attack origins/ }).focus()
    await user.keyboard("0")
    expect(localStorage.getItem(KEY)).toBe("world")
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
