import { matchRoutes } from "react-router"
import { describe, expect, it } from "vitest"
import { PAGE_WIDTH_CLASS, pageWidth } from "./page-width"
import { appRoutes } from "./router"

const widthAt = (path: string) => {
  const matches = matchRoutes([appRoutes()], path) ?? []
  return pageWidth(matches.map((m) => ({ handle: m.route.handle as unknown })))
}

describe("page width", () => {
  it("takes the deepest route that declares one, reading width otherwise", () => {
    expect(pageWidth([])).toBe("prose")
    expect(pageWidth([{ handle: { width: "wide" } }, { handle: undefined }])).toBe("wide")
    expect(pageWidth([{ handle: { width: "wide" } }, { handle: { width: "full" } }])).toBe("full")
    expect(pageWidth([{ handle: { width: "huge" } }])).toBe("prose")
  })

  it("gives Live the whole screen", () => {
    expect(widthAt("/live")).toBe("full")
  })

  it("widens lists, hubs and dashboards", () => {
    for (const path of [
      "/",
      "/attacks",
      "/attackers",
      "/networks",
      "/overview",
      "/trends",
      "/campaigns",
      "/techniques",
      "/scripts",
      "/malware",
      "/infrastructure",
      "/defend/blocklists",
      "/defend/detections",
      "/defend/exposure",
      "/cves",
      "/defend/alerts",
      "/defend/abuse",
      "/defend/results",
      "/network",
      "/network/members",
    ]) {
      expect(widthAt(path), path).toBe("wide")
    }
  })

  it("keeps Settings and detail pages at reading width", () => {
    for (const path of [
      "/settings",
      "/setup",
      "/attacks/42",
      "/attackers/203.0.113.7",
      "/campaigns/7",
      "/scripts/3",
      "/malware/samples/abc",
      "/defend/abuse/R-1",
      "/defend/results/targets/1",
      "/reports/2026-W40",
      "/nowhere",
    ]) {
      expect(widthAt(path), path).toBe("prose")
    }
  })

  it("maps every width to a container class", () => {
    expect(Object.keys(PAGE_WIDTH_CLASS).sort()).toEqual(["full", "prose", "wide"])
  })
})
