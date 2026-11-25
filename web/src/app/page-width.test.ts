import { matchRoutes } from "react-router"
import { describe, expect, it } from "vitest"
import { PAGE_FRAME_CLASS, PAGE_WIDTH_CLASS, pageWidth } from "./page-width"
import { appRoutes } from "./router"

const widthAt = (path: string) => {
  const matches = matchRoutes([appRoutes()], path) ?? []
  return pageWidth(matches.map((m) => ({ handle: m.route.handle as unknown })))
}

describe("page width", () => {
  it("takes the deepest route that declares one, the full column otherwise", () => {
    expect(pageWidth([])).toBe("wide")
    expect(pageWidth([{ handle: { width: "prose" } }, { handle: undefined }])).toBe("prose")
    expect(pageWidth([{ handle: { width: "prose" } }, { handle: { width: "wide" } }])).toBe("wide")
    expect(pageWidth([{ handle: { width: "huge" } }])).toBe("wide")
  })

  it("fills the column on lists, hubs, dashboards and detail pages", () => {
    for (const path of [
      "/",
      "/attacks",
      "/attackers",
      "/networks",
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
      "/defend/abuse",
      "/defend/results",
      "/network",
      "/network/members",
      "/settings",
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
      expect(widthAt(path), path).toBe("wide")
    }
  })

  it("keeps the setup form at reading width", () => {
    expect(widthAt("/setup")).toBe("prose")
  })

  it("caps the frame only for ultra-wide screens, and the column only for prose", () => {
    expect(PAGE_FRAME_CLASS).toBe("max-w-page-wide")
    expect(PAGE_WIDTH_CLASS).toEqual({ wide: "", prose: "max-w-page-prose" })
  })
})
