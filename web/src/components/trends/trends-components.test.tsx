import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { TooltipProvider } from "@/components/ui/tooltip"
import { InsightRow } from "@/components/insights/insights-card"
import { describeChange, TagTable } from "@/components/trends/tag-table"
import type { Insight, TagPoint } from "@/lib/trends"

function wrap(ui: React.ReactNode) {
  return render(
    <MemoryRouter>
      <IpMaskProvider>
        <TooltipProvider>{ui}</TooltipProvider>
      </IpMaskProvider>
    </MemoryRouter>,
  )
}

describe("InsightRow", () => {
  const insight: Insight = {
    id: "x",
    kind: "surge",
    severity: "severe",
    sentence: "Exploit attempts tripled (412 vs 131).",
    evidence: { metric: "tag:php2shell", current: 412, previous: 131, ratio: 3.1 },
    link: "/attacks?tag=php2shell",
  }
  it("links to the filtered view and names its severity", () => {
    wrap(<InsightRow insight={insight} />)
    const link = screen.getByRole("link")
    expect(link).toHaveAttribute("href", "/attacks?tag=php2shell")
    expect(link).toHaveTextContent("Severe")
    expect(link).toHaveTextContent("Exploit attempts tripled")
  })
})

describe("TagTable", () => {
  const points: TagPoint[] = [
    { ts: "2026-11-20T00:00:00Z", tags: { php2shell: 10, "crypto-miner": 5 } },
    { ts: "2026-11-21T00:00:00Z", tags: { php2shell: 30, "crypto-miner": 5 } },
  ]
  it("lists the tags with their totals and a link to the sessions", () => {
    wrap(<TagTable points={points} />)
    const link = screen.getByRole("link", { name: /php2shell/ })
    expect(link).toHaveAttribute("href", "/attacks?tag=php2shell")
    expect(link).toHaveTextContent("40")
    expect(link).toHaveTextContent("+200%")
  })

  it("says New when a tag was absent from the first half", () => {
    expect(describeChange(0, 4)).toBe("New")
    expect(describeChange(0, 0)).toBe("None")
    expect(describeChange(10, 10)).toBe("No change")
    expect(describeChange(10, 5)).toBe("\u221250%")
  })
})
