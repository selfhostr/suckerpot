import { act, render, renderHook, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import { stubResizeObserver } from "@/test/dom-stubs"
import {
  NAV_SECTIONS,
  SETTINGS_PAGE,
  activePage,
  allPages,
  crumbsFor,
  entryHome,
  sectionPages,
  switchFor,
} from "./nav"
import { PageSwitch } from "./page-switch"
import { Sidebar, type SidebarVariant } from "./sidebar"
import { SECTIONS_KEY, SIDEBAR_KEY, readClosedSections, useSidebarCollapsed } from "./sidebar-state"

vi.mock("./account-menu", () => ({ AccountMenu: () => <button type="button">Account</button> }))
vi.mock("./use-live-status", () => ({ useLiveStatus: () => ({ status: "live" }) }))
vi.mock("@/hooks/use-version", () => ({ useVersion: () => ({ data: undefined }) }))

function mount(variant: SidebarVariant, path = "/attackers/192.0.2.1", onToggle = vi.fn()) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <TooltipProvider>
        <Sidebar variant={variant} onToggle={onToggle} />
      </TooltipProvider>
    </MemoryRouter>,
  )
  return onToggle
}

describe("navigation table", () => {
  it("has three sections, nine entries and eighteen pages", () => {
    expect(NAV_SECTIONS.map((s) => s.label)).toEqual(["Observe", "Understand", "Defend"])
    expect(NAV_SECTIONS.map((s) => s.entries.map((e) => e.label))).toEqual([
      ["Today", "Attacks"],
      ["Campaigns", "Payloads", "Patterns"],
      ["Block", "Exposure", "Reports", "Network"],
    ])
    expect(NAV_SECTIONS.flatMap(sectionPages)).toHaveLength(18)
    const labels = NAV_SECTIONS.flatMap(sectionPages).map((p) => p.label)
    expect(new Set(labels).size).toBe(labels.length)
  })

  it("leads each entry to its first page", () => {
    const homes = NAV_SECTIONS.flatMap((s) => s.entries.map(entryHome))
    expect(homes).toEqual([
      "/",
      "/attacks",
      "/campaigns",
      "/scripts",
      "/trends",
      "/defend/blocklists",
      "/defend/exposure",
      "/defend/abuse",
      "/network",
    ])
  })

  it("draws the page switch on the pages of an entry, not on its detail routes", () => {
    const at = (path: string) => {
      const found = switchFor(path)
      return found && [found.entry.label, found.current.to]
    }
    expect(at("/attackers")).toEqual(["Attacks", "/attackers"])
    expect(at("/infrastructure")).toEqual(["Payloads", "/infrastructure"])
    expect(at("/network/members")).toEqual(["Network", "/network/members"])
    expect(at("/trends")).toBeUndefined()
    expect(at("/attackers/192.0.2.1")).toBeUndefined()
    expect(at("/")).toBeUndefined()
    expect(at("/settings")).toBeUndefined()
  })

  it("keeps every individual page reachable", () => {
    const routes = allPages().map((p) => p.to)
    for (const r of [
      "/",
      "/attacks",
      "/attackers",
      "/networks",
      "/infrastructure",
      "/campaigns",
      "/techniques",
      "/scripts",
      "/malware",
      "/trends",
      "/defend/blocklists",
      "/defend/detections",
      "/defend/exposure",
      "/cves",
      "/defend/abuse",
      "/defend/results",
      "/network",
      "/network/members",
      "/settings",
      "/styleguide",
    ])
      expect(routes).toContain(r)
  })

  it.each([
    ["/attacks/abc", "/attacks", "observe"],
    ["/trends", "/trends", "understand"],
    ["/attackers/192.0.2.1", "/attackers", "observe"],
    ["/networks", "/networks", "observe"],
    ["/campaigns/7", "/campaigns", "understand"],
    ["/scripts/deadbeef", "/scripts", "understand"],
    ["/malware/samples/abc", "/malware", "understand"],
    ["/cves", "/cves", "defend"],
    ["/defend/results/targets/4", "/defend/results", "defend"],
    ["/network", "/network", "defend"],
    ["/network/members", "/network/members", "defend"],
    ["/", "/", "observe"],
  ])("%s is the %s page of %s", (path, to, section) => {
    const active = activePage(path)
    expect(active?.page.to).toBe(to)
    expect(active?.section?.id).toBe(section)
  })

  it("counts the styleguide as Settings, and matches no sibling prefix", () => {
    expect(activePage("/styleguide")?.page).toBe(SETTINGS_PAGE)
    expect(activePage("/reports/2026-W43")?.page).toBe(SETTINGS_PAGE)
    expect(activePage("/settings")?.section).toBeUndefined()
    expect(activePage("/attackers-x")).toBeUndefined()
    expect(activePage("/setup")).toBeUndefined()
  })

  it("says where you are in the header", () => {
    expect(crumbsFor("/attackers")).toEqual([
      { label: "Observe" },
      { label: "Attacks" },
      { label: "Attackers" },
    ])
    expect(crumbsFor("/attackers/192.0.2.1")).toEqual([
      { label: "Observe" },
      { label: "Attacks" },
      { label: "Attackers", to: "/attackers" },
    ])
    // An entry named after its first page is said once.
    expect(crumbsFor("/campaigns")).toEqual([{ label: "Understand" }, { label: "Campaigns" }])
    expect(crumbsFor("/defend/results")).toEqual([
      { label: "Defend" },
      { label: "Reports" },
      { label: "Results" },
    ])
    expect(crumbsFor("/trends")).toEqual([{ label: "Understand" }, { label: "Patterns" }])
    expect(crumbsFor("/reports/2026-W43")).toEqual([
      { label: "Settings", to: "/settings?tab=alert-rules" },
      { label: "Weekly report" },
    ])
    expect(crumbsFor("/")).toEqual([{ label: "Observe" }, { label: "Today" }])
    expect(crumbsFor("/settings")).toEqual([{ label: "Settings" }])
    expect(crumbsFor("/styleguide")).toEqual([
      { label: "Settings", to: "/settings" },
      { label: "Styleguide" },
    ])
    expect(crumbsFor("/setup")).toEqual([])
  })
})

describe("sidebar", () => {
  // The rail's flyouts are Radix menus, which measure themselves.
  beforeEach(() => {
    stubResizeObserver()
    localStorage.clear()
  })

  it("lists every section open, one row per entry, the current entry marked", () => {
    mount("expanded")
    const observe = screen.getByRole("group", { name: "Observe" })
    expect(within(observe).getByRole("button", { name: "Observe" })).toHaveAttribute(
      "aria-expanded",
      "true",
    )
    expect(
      within(observe)
        .getAllByRole("link")
        .map((l) => l.textContent),
    ).toEqual(["Today, feed connected", "Attacks"])
    // On an attacker's profile, the Attacks entry is current.
    const attacks = screen.getByRole("link", { name: "Attacks" })
    expect(attacks).toHaveAttribute("aria-current", "page")
    expect(attacks).toHaveAttribute("href", "/attacks")
    expect(screen.queryByRole("link", { name: "Attackers" })).toBeNull()
    expect(screen.getAllByRole("link", { current: "page" })).toHaveLength(1)
    expect(
      within(screen.getByRole("group", { name: "Understand" }))
        .getAllByRole("link")
        .map((l) => l.textContent),
    ).toEqual(["Campaigns", "Payloads", "Patterns"])
    // Settings, Docs and GitHub share one row of icons.
    expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /Documentation/ })).toHaveAttribute(
      "href",
      "https://suckerpot.selfhostr.io/docs/",
    )
    expect(screen.getByRole("link", { name: /GitHub/ })).toHaveAttribute(
      "href",
      "https://github.com/selfhostr/suckerpot",
    )
    expect(screen.queryByRole("link", { name: "Styleguide" })).toBeNull()
  })

  it("folds a section and remembers it", async () => {
    const user = userEvent.setup()
    mount("expanded")
    await user.click(screen.getByRole("button", { name: "Defend" }))
    expect(screen.getByRole("button", { name: "Defend" })).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByRole("link", { name: "Block" })).toBeNull()
    expect(readClosedSections()).toEqual(["defend"])
    expect(localStorage.getItem(SECTIONS_KEY)).toBe('["defend"]')
  })

  it("asks to collapse from the expanded head", async () => {
    const user = userEvent.setup()
    const onToggle = mount("expanded")
    await user.click(screen.getByRole("button", { name: "Collapse sidebar" }))
    expect(onToggle).toHaveBeenCalledOnce()
  })

  it("folded, shows one icon per section and the foot as icons", async () => {
    const user = userEvent.setup()
    const onToggle = mount("rail")
    const nav = screen.getByRole("navigation", { name: "Main" })
    expect(
      within(nav)
        .getAllByRole("button")
        .map((b) => b.getAttribute("aria-label")),
    ).toEqual(["Observe", "Understand", "Defend"])
    expect(screen.queryByRole("link", { name: "Attacks" })).toBeNull()
    expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /Documentation/ })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /GitHub/ })).toBeInTheDocument()
    // The flyout lists the section's entries.
    await user.click(within(nav).getByRole("button", { name: "Observe" }))
    const menu = await screen.findByRole("menu")
    expect(within(menu).getByRole("menuitem", { name: "Attacks" })).toHaveAttribute(
      "aria-current",
      "page",
    )
    await user.keyboard("{Escape}")
    await user.click(screen.getByRole("button", { name: "Expand sidebar" }))
    expect(onToggle).toHaveBeenCalledOnce()
  })

  it("starts expanded when nothing is stored", () => {
    expect(localStorage.getItem(SIDEBAR_KEY)).toBeNull()
    expect(readClosedSections()).toEqual([])
    localStorage.setItem(SECTIONS_KEY, "not json")
    expect(readClosedSections()).toEqual([])
    localStorage.setItem(SECTIONS_KEY, '["observe","nope"]')
    expect(readClosedSections()).toEqual(["observe"])
  })

  it("remembers the folded sidebar per browser", () => {
    const first = renderHook(() => useSidebarCollapsed())
    expect(first.result.current[0]).toBe(false)
    act(() => first.result.current[1](true))
    expect(first.result.current[0]).toBe(true)
    expect(localStorage.getItem(SIDEBAR_KEY)).toBe("collapsed")
    first.unmount()
    const again = renderHook(() => useSidebarCollapsed())
    expect(again.result.current[0]).toBe(true)
    act(() => again.result.current[1](false))
    expect(localStorage.getItem(SIDEBAR_KEY)).toBeNull()
  })
})

describe("page switch", () => {
  function mountSwitch(path: string, search = "") {
    render(
      <MemoryRouter initialEntries={[path + search]}>
        <PageSwitch pathname={path} />
      </MemoryRouter>,
    )
  }

  it("links the pages of the entry, the current one marked", () => {
    mountSwitch("/networks")
    const nav = screen.getByRole("navigation", { name: "Attacks pages" })
    expect(
      within(nav)
        .getAllByRole("link")
        .map((l) => [l.textContent, l.getAttribute("href")]),
    ).toEqual([
      ["Sessions", "/attacks"],
      ["Attackers", "/attackers"],
      ["Networks", "/networks"],
    ])
    expect(within(nav).getByRole("link", { name: "Networks" })).toHaveAttribute(
      "aria-current",
      "page",
    )
  })

  it("is not drawn on a detail route or a page of its own", () => {
    mountSwitch("/attacks/abc")
    expect(screen.queryByRole("navigation")).toBeNull()
  })

  it("carries the filters the next tab also applies", () => {
    mountSwitch("/attacks", "?country=NL&sensor=ssh&since=2026-11-01T00:00:00.000Z&src_ip=1.2.3.4")
    const nav = screen.getByRole("navigation", { name: "Attacks pages" })
    expect(within(nav).getByRole("link", { name: "Attackers" })).toHaveAttribute(
      "href",
      "/attackers?sensor=ssh&country=NL",
    )
    expect(within(nav).getByRole("link", { name: "Networks" })).toHaveAttribute(
      "href",
      "/networks?country=NL&since=2026-11-01T00%3A00%3A00.000Z",
    )
  })
})
