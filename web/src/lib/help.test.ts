import { describe, expect, it } from "vitest"
import { allPages } from "@/app/nav"
import { HELP, HELP_IDS, settingsHelpId, type HelpId } from "./help"

// Every page file, as text: the test reads which help id each page header asks for.
const pages = import.meta.glob<string>("/src/pages/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
})

/** Pages that have no PageHeader on purpose (sign-in screens, the 404). */
const NO_HEADER = ["login", "not-found", "set-password"]

function sentences(text: string): number {
  return text.split(/(?<=[.!?])\s+/).filter(Boolean).length
}

describe("page help texts", () => {
  it("gives every text a title and two or three sentences", () => {
    for (const id of HELP_IDS) {
      const t = HELP[id]
      expect(t.title, id).not.toBe("")
      expect(sentences(t.body), `${id}: ${t.body}`).toBeGreaterThanOrEqual(2)
      expect(sentences(t.body), `${id}: ${t.body}`).toBeLessThanOrEqual(3)
    }
  })

  it("never contains an address", () => {
    for (const id of HELP_IDS) expect(HELP[id].body).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/)
  })

  it("covers every page: each page file asks for a help id that exists", () => {
    const used = new Set<string>()
    for (const [path, source] of Object.entries(pages)) {
      const name = /\/([^/]+)\.tsx$/.exec(path)?.[1] ?? path
      if (name.endsWith(".test") || NO_HEADER.includes(name)) continue
      const ids = [...source.matchAll(/help="([a-z-]+)"/g)].map((m) => m[1] ?? "")
      const dynamic = source.includes("help={") || source.includes("<PageHelp id=")
      expect(ids.length > 0 || dynamic, `${name} has no help`).toBe(true)
      for (const id of ids) {
        expect(HELP_IDS, `${name}: unknown help id ${id}`).toContain(id)
        used.add(id)
      }
    }
    // Ids set from code rather than from a literal.
    for (const id of ["networks", "attackers", "campaign", "session"]) used.add(id)
    for (const tab of [
      "general",
      "keys",
      "users",
      "audit",
      "ports",
      "alerts",
      "feeds",
      "reporting",
      "vpn",
      "network",
    ])
      used.add(settingsHelpId(tab))
    expect([...used].sort()).toEqual([...HELP_IDS].sort())
  })

  it("has a text for every page in the navigation", () => {
    const byRoute: Record<string, HelpId> = {
      "/": "today",
      "/live": "live",
      "/attacks": "attacks",
      "/attackers": "attackers",
      "/networks": "networks",
      "/campaigns": "campaigns",
      "/techniques": "techniques",
      "/scripts": "scripts",
      "/malware": "malware",
      "/infrastructure": "infrastructure",
      "/overview": "activity",
      "/trends": "patterns",
      "/defend/blocklists": "blocklists",
      "/defend/detections": "detections",
      "/defend/exposure": "exposure",
      "/cves": "cves",
      "/defend/alerts": "alerts",
      "/defend/abuse": "abuse",
      "/defend/results": "abuse-results",
      "/network": "network",
      "/network/members": "network-members",
      "/settings": "settings-general",
      "/styleguide": "styleguide",
    }
    for (const p of allPages()) expect(byRoute[p.to], `no help for ${p.to}`).toBeDefined()
    for (const id of Object.values(byRoute)) expect(HELP[id]).toBeDefined()
  })

  it("maps a Settings tab to its own text and falls back to General", () => {
    expect(settingsHelpId("vpn")).toBe("settings-vpn")
    expect(settingsHelpId("alerts")).toBe("settings-alerts")
    expect(settingsHelpId("nope")).toBe("settings-general")
  })
})
