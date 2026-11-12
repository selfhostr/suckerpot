import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import { liveEvent } from "@/lib/live-messages.test"
import { LiveEventRow } from "./live-event-row"

function renderRow(ui: React.ReactElement) {
  return render(
    <MemoryRouter>
      <TooltipProvider>{ui}</TooltipProvider>
    </MemoryRouter>,
  )
}

describe("LiveEventRow", () => {
  it("links to the session and to the filtered attacks view", () => {
    renderRow(<LiveEventRow event={liveEvent(1, { session_id: "abc 1", country: "NL" })} />)
    const links = screen.getAllByRole("link")
    const hrefs = links.map((a) => a.getAttribute("href"))
    // The event time rides along: a connection folded into a flood group finds its group from it.
    expect(hrefs).toContain("/attacks/abc%201?at=2026-10-24T18%3A02%3A16Z")
    expect(hrefs).toContain("/attacks?src_ip=192.0.2.45")
  })

  it("renders attacker text as text, never as markup", () => {
    const evil = '<img src=x onerror="alert(1)"> <b>bold</b>'
    const { container } = renderRow(<LiveEventRow event={liveEvent(2, { summary: evil })} />)
    expect(container.querySelector("img[onerror]")).toBeNull()
    expect(container.querySelector("b")).toBeNull()
    expect(screen.getAllByText(evil).length).toBeGreaterThan(0)
  })

  it("marks download attempts as severe with text, not colour alone", () => {
    renderRow(
      <LiveEventRow
        event={liveEvent(3, { type: "download_attempt", summary: "download http://203.0.113.9/x" })}
      />,
    )
    expect(screen.getAllByText("Download attempt (severe)").length).toBeGreaterThan(0)
  })

  it("keeps red for the severe event itself, not for every event of a tagged session", () => {
    renderRow(
      <LiveEventRow event={liveEvent(4, { type: "login_attempt", tags: ["malware-drop"] })} />,
    )
    expect(screen.queryAllByText("Login attempt (severe)")).toHaveLength(0)
    renderRow(<LiveEventRow event={liveEvent(5, { type: "http_request", tags: ["php2shell"] })} />)
    expect(screen.getAllByText("HTTP request (severe)").length).toBeGreaterThan(0)
  })
})
