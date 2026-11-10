import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { HubTabs } from "@/components/hub-tabs"
import { NAV_ITEMS, activeTab, allPages, buildNav, hubForPath, itemForPath } from "./nav"

describe("navigation", () => {
  it("has twelve sidebar entries in production and thirteen in development", () => {
    const count = (dev: boolean) => buildNav(dev).reduce((n, g) => n + g.items.length, 0)
    expect(count(false)).toBe(12)
    expect(count(true)).toBe(13)
    expect(buildNav(false).flatMap((g) => g.items.map((i) => i.to))).not.toContain("/styleguide")
  })

  it("keeps every individual page reachable", () => {
    const routes = allPages().map((p) => p.to)
    for (const r of [
      "/",
      "/live",
      "/attacks",
      "/attackers",
      "/networks",
      "/infrastructure",
      "/campaigns",
      "/techniques",
      "/scripts",
      "/malware",
      "/overview",
      "/trends",
      "/defend/blocklists",
      "/defend/detections",
      "/defend/exposure",
      "/cves",
      "/defend/alerts",
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
    ["/attacks/abc", "/attacks"],
    ["/attackers/192.0.2.1", "/attacks"],
    ["/networks", "/attacks"],
    ["/infrastructure", "/scripts"],
    ["/campaigns/7", "/campaigns"],
    ["/scripts/deadbeef", "/scripts"],
    ["/malware", "/scripts"],
    ["/trends", "/overview"],
    ["/cves", "/defend/exposure"],
    ["/reports/2026-W43", "/defend/alerts"],
    ["/defend/alerts", "/defend/alerts"],
    ["/defend/results/targets/4", "/defend/abuse"],
    ["/", "/"],
  ])("%s lights up the %s entry", (path, to) => {
    expect(itemForPath(path)?.to).toBe(to)
  })

  it("does not treat a sibling prefix as a match", () => {
    expect(itemForPath("/attackers-x")).toBeUndefined()
    expect(hubForPath("/live")).toBeUndefined()
  })

  it("renders tabs with aria-current on the active one, also on a detail route", () => {
    const hub = NAV_ITEMS.find((i) => i.label === "Attacks")
    if (!hub) throw new Error("Attacks hub missing")
    render(
      <MemoryRouter>
        <HubTabs hub={hub} pathname="/attackers/192.0.2.1" />
      </MemoryRouter>,
    )
    expect(screen.getAllByRole("link").map((l) => l.textContent)).toEqual([
      "Sessions",
      "Attackers",
      "Networks",
    ])
    expect(screen.getByRole("link", { name: "Attackers" }).getAttribute("aria-current")).toBe(
      "page",
    )
    expect(screen.getByRole("link", { name: "Sessions" }).getAttribute("aria-current")).toBeNull()
    expect(activeTab(hub, "/attacks/1")?.label).toBe("Sessions")
  })
})
