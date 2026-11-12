import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, useLocation } from "react-router"
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { TooltipProvider } from "@/components/ui/tooltip"
import { api, type Page, type Session, type StatsSummary } from "@/lib/api"
import { stubResizeObserver } from "@/test/dom-stubs"
import { AttacksPage } from "./attacks"

beforeAll(stubResizeObserver)
afterEach(() => vi.restoreAllMocks())

function row(o: Partial<Session> = {}): Session {
  return {
    session_id: "k3J9x2_a7Qe",
    sensor: "ssh",
    src_ip: "198.51.100.23",
    src_port: 51422,
    dst_port: 22,
    started_at: "2026-11-12T14:02:11Z",
    ended_at: "2026-11-12T14:02:19Z",
    last_event_at: "2026-11-12T14:02:19Z",
    event_count: 4,
    login_attempts: 3,
    login_success: false,
    commands: 0,
    downloads: 0,
    http_requests: 0,
    country: null,
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
    kind: "session",
    connections: 1,
    ...o,
  }
}

const flood = row({
  session_id: "burst-3f9c0a77e1d24b58a6c01e92",
  sensor: "rdp",
  src_ip: "203.0.113.7",
  src_port: 0,
  dst_port: 3389,
  login_attempts: 812,
  event_count: 2436,
  kind: "burst",
  connections: 812,
})

const summary: StatsSummary = {
  window_hours: 24,
  events: 90_000,
  sessions: 5_000,
  unique_ips: 310,
  sessions_with_commands: 40,
  download_attempts: 9,
  by_sensor: {},
  flood_sessions: 4_800,
  flood_sources: 20,
}

const page = (items: Session[]): Page<Session> => ({ items, next_cursor: null })

function Where() {
  const { search } = useLocation()
  return <output aria-label="query string">{search}</output>
}

function mount(url: string, items: Session[]) {
  const sessions = vi.spyOn(api, "sessions").mockResolvedValue(page(items))
  vi.spyOn(api, "summary").mockResolvedValue(summary)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[url]}>
        <IpMaskProvider>
          <TooltipProvider>
            <AttacksPage />
            <Where />
          </TooltipProvider>
        </IpMaskProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return sessions
}

describe("AttacksPage and floods", () => {
  it("opens with the share of floods in its headline", async () => {
    mount("/attacks", [flood, row()])
    expect(
      await screen.findByText(
        "5,000 sessions from 310 addresses in the last 24 hours, 96% of them in floods from 20 addresses.",
      ),
    ).toBeInTheDocument()
  })

  it("counts connections, not rows, at the end of the list", async () => {
    mount("/attacks", [flood, row()])
    expect(await screen.findByText("End of the list · 813 sessions in 2 rows")).toBeInTheDocument()
    // The group reads as one story with its chip.
    const list = screen.getByRole("list", { name: "Sessions" })
    expect(within(list).getAllByText(/opened 812 RDP connections/).length).toBeGreaterThan(0)
  })

  it("sends the Floods choice to the API as kind", async () => {
    const user = userEvent.setup()
    const sessions = mount("/attacks", [flood, row()])
    await screen.findByRole("list", { name: "Sessions" })
    // All sends no kind at all, so the API lists sessions and flood groups together.
    expect(sessions.mock.lastCall?.[0].kind).toBeUndefined()

    await user.click(screen.getByRole("radio", { name: "Show only floods" }))
    expect(screen.getByLabelText("query string")).toHaveTextContent("?kind=burst")
    expect(
      await screen.findByText(
        "4,800 connections came in floods from 20 addresses in the last 24 hours, one row per address and hour.",
      ),
    ).toBeInTheDocument()
    expect(sessions).toHaveBeenLastCalledWith(expect.objectContaining({ kind: "burst" }), null, 50)

    await user.click(screen.getByRole("radio", { name: "Hide floods" }))
    expect(screen.getByLabelText("query string")).toHaveTextContent("?kind=session")
    expect(
      await screen.findByText(
        "200 sessions in the last 24 hours, without the 4,800 connections that came in floods.",
      ),
    ).toBeInTheDocument()
    expect(sessions).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: "session" }),
      null,
      50,
    )
  })

  it("starts from the shared link", async () => {
    const sessions = mount("/attacks?kind=burst&sensor=rdp", [flood])
    await screen.findByRole("list", { name: "Sessions" })
    expect(sessions).toHaveBeenCalledWith(
      expect.objectContaining({ kind: "burst", sensor: ["rdp"] }),
      null,
      50,
    )
    expect(screen.getByRole("radio", { name: "Show only floods" })).toBeChecked()
    // "Clear filters" resets the Floods choice as well.
    await userEvent.setup().click(screen.getByRole("button", { name: "Clear filters" }))
    expect(screen.getByLabelText("query string").textContent).toBe("")
  })
})
