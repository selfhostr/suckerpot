import { render, screen, within } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { Session } from "@/lib/api"
import { SessionRow } from "./session-row"

function session(o: Partial<Session> = {}): Session {
  return {
    session_id: "k3J9x2_a7Qe",
    sensor: "rdp",
    src_ip: "203.0.113.7",
    src_port: 51422,
    dst_port: 3389,
    started_at: "2026-11-12T14:02:11Z",
    ended_at: "2026-11-12T14:02:19Z",
    last_event_at: "2026-11-12T14:02:19Z",
    event_count: 4,
    login_attempts: 1,
    login_success: false,
    commands: 0,
    downloads: 0,
    http_requests: 0,
    country: "NL",
    city: null,
    asn: null,
    org: "Polder Cloud BV",
    abuse_score: null,
    known_scanner: null,
    tags: [],
    kind: "session",
    connections: 1,
    ...o,
  }
}

const flood = (o: Partial<Session> = {}) =>
  session({
    session_id: "burst-3f9c0a77e1d24b58a6c01e92",
    src_port: 0,
    started_at: "2026-11-12T14:02:11Z",
    ended_at: "2026-11-12T14:58:30Z",
    last_event_at: "2026-11-12T14:58:30Z",
    event_count: 2436,
    login_attempts: 812,
    tags: ["rdp-cleartext"],
    kind: "burst",
    connections: 812,
    ...o,
  })

function renderRow(ui: React.ReactElement) {
  return render(
    <MemoryRouter>
      <IpMaskProvider>
        <TooltipProvider>{ui}</TooltipProvider>
      </IpMaskProvider>
    </MemoryRouter>,
  )
}

describe("SessionRow", () => {
  it("tells a flood group as one story with a neutral chip, never red", () => {
    const { container } = renderRow(<SessionRow session={flood()} />)
    // The story counts connections instead of telling each one.
    expect(
      screen.getAllByText(/opened 812 RDP connections, one login each/).length,
    ).toBeGreaterThan(0)
    // The chip says it with an icon, the word and the count, so colour carries nothing.
    const chip = screen.getAllByTitle(/812 connections from one address in one hour/)[0]
    if (!chip) throw new Error("no flood chip")
    expect(within(chip).getByText("flood")).toBeInTheDocument()
    expect(within(chip).getByText("x812")).toBeInTheDocument()
    expect(chip.querySelector("svg")).not.toBeNull()
    expect(chip.className).not.toMatch(/sev-severe|tint-severe/)
    // The row opens the group, and the hours it ran are part of the accessible name.
    const open = screen.getAllByRole("link", { name: /opened 812 RDP connections/ })[0]
    expect(open).toHaveAttribute("href", "/attacks/burst-3f9c0a77e1d24b58a6c01e92")
    expect(open?.getAttribute("aria-label")).toMatch(/between \d{2}:\d{2}–\d{2}:\d{2}$/)
    // The hour range is a real time element with the full window on hover.
    const range = container.querySelector("time[title]")
    expect(range?.textContent).toMatch(/^\d{2}:\d{2}–\d{2}:\d{2}$/)
    expect(range?.getAttribute("title")).toMatch(/Nov 12/)
  })

  it("keeps a plain session free of flood marks", () => {
    renderRow(<SessionRow session={session({ login_attempts: 3 })} />)
    expect(screen.getAllByText(/tried 3 RDP logins/).length).toBeGreaterThan(0)
    expect(screen.queryByText("flood")).not.toBeInTheDocument()
  })

  it("leaves a group's tags to its page, so the story keeps its room", () => {
    renderRow(<SessionRow session={flood({ tags: ["rdp-cleartext", "credential-stuffing"] })} />)
    expect(screen.queryAllByText("rdp-cleartext")).toHaveLength(0)
    expect(screen.queryAllByText("credential-stuffing")).toHaveLength(0)
    // A single connection still shows its tags.
    renderRow(<SessionRow session={session({ tags: ["credential-stuffing"] })} />)
    expect(screen.getAllByText("credential-stuffing").length).toBeGreaterThan(0)
  })

  it("hides the address on a profile page and still reads as a flood", () => {
    renderRow(<SessionRow session={flood()} showSource={false} />)
    expect(screen.getAllByText("flood").length).toBeGreaterThan(0)
    expect(screen.queryByText("203.0.113.7")).not.toBeInTheDocument()
  })
})
