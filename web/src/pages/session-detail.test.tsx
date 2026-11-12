import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, Route, Routes } from "react-router"
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { TooltipProvider } from "@/components/ui/tooltip"
import {
  api,
  type Page,
  type SensorEvent,
  type Session,
  type SessionCredentials,
  type SessionDetail,
} from "@/lib/api"
import { stubResizeObserver } from "@/test/dom-stubs"
import { SessionDetailPage } from "./session-detail"

beforeAll(stubResizeObserver)
afterEach(() => vi.restoreAllMocks())

const GROUP_ID = "burst-3f9c0a77e1d24b58a6c01e92"

function group(o: Partial<SessionDetail> = {}): SessionDetail {
  return {
    session_id: GROUP_ID,
    sensor: "rdp",
    src_ip: "203.0.113.7",
    src_port: 0,
    dst_port: 3389,
    started_at: "2026-11-12T14:02:11Z",
    ended_at: "2026-11-12T14:58:30Z",
    last_event_at: "2026-11-12T14:58:30Z",
    event_count: 2436,
    login_attempts: 812,
    login_success: false,
    commands: 0,
    downloads: 0,
    http_requests: 0,
    country: "NL",
    city: null,
    asn: 64496,
    org: "Polder Cloud BV",
    abuse_score: 74,
    known_scanner: false,
    client_tool: "FreeRDP",
    tags: ["rdp-cleartext"],
    kind: "burst",
    connections: 812,
    ...o,
  }
}

function plain(o: Partial<Session> = {}): Session {
  return {
    ...group(),
    session_id: "k3J9x2_a7Qe",
    src_port: 51422,
    kind: "session",
    connections: 1,
    ...o,
  }
}

function event(id: number, type: string, data: Record<string, unknown> = {}): SensorEvent {
  return {
    id,
    ts: new Date(Date.parse("2026-11-12T14:02:00Z") + id * 1000).toISOString(),
    sensor: "rdp",
    session_id: `c${id}`,
    type,
    src_ip: "203.0.113.7",
    src_port: 40000 + id,
    dst_port: 3389,
    data,
    country: "NL",
    city: null,
    asn: 64496,
    org: "Polder Cloud BV",
    abuse_score: 74,
    known_scanner: false,
    tags: [],
  }
}

const credentials: SessionCredentials = {
  attempts: 812,
  distinct_usernames: 1,
  distinct_passwords: 812,
  distinct_pairs: 812,
  truncated: false,
  usernames: [{ value: "Administrator", count: 812 }],
  passwords: [
    { value: "Spring2026!", count: 1 },
    { value: "Summer2026!", count: 1 },
  ],
  pairs: [],
}

const page = <T,>(items: T[]): Page<T> => ({ items, next_cursor: null })

function stub(
  session: SessionDetail,
  extra: { siblings?: Session[]; credentials?: SessionCredentials } = {},
) {
  const getSession = vi.spyOn(api, "session").mockResolvedValue(session)
  vi.spyOn(api, "sessionEvents").mockResolvedValue(
    page([
      event(1, "connect"),
      event(2, "login_attempt", { username: "Administrator", password: "Spring2026!" }),
      event(3, "disconnect", { duration_s: 1 }),
    ]),
  )
  const creds = vi
    .spyOn(api, "sessionCredentials")
    .mockResolvedValue(extra.credentials ?? credentials)
  const sessions = vi.spyOn(api, "sessions").mockResolvedValue(page(extra.siblings ?? []))
  return { getSession, creds, sessions }
}

function mount(url: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[url]}>
        <IpMaskProvider>
          <TooltipProvider>
            <Routes>
              <Route path="/attacks/:sessionId" element={<SessionDetailPage />} />
            </Routes>
          </TooltipProvider>
        </IpMaskProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe("SessionDetailPage for a flood group", () => {
  it("tells the group as one story, with a finding and the key figures", async () => {
    stub(group())
    mount(`/attacks/${GROUP_ID}`)

    const h1 = await screen.findByRole("heading", { level: 1 })
    expect(h1).toHaveTextContent(/opened 812 RDP connections with FreeRDP, one login each/)
    expect(screen.getByText(/None of the 812 connections got in/)).toBeInTheDocument()
    // The chip is on the page too, with its word and its count.
    expect(screen.getAllByText("flood").length).toBeGreaterThan(0)

    const figures = document.querySelector("dl")
    if (!figures) throw new Error("no key figures")
    expect(within(figures).getByText("Connections").nextSibling).toHaveTextContent("812")
    expect(within(figures).getByText("Logins tried").nextSibling).toHaveTextContent("812")
    expect(within(figures).getByText("Events").nextSibling).toHaveTextContent("2,436")
    // Only the target port: a group has no source port to show.
    expect(within(figures).getByText("Port").nextSibling).toHaveTextContent(/^3389$/)
    expect(within(figures).queryByText("Ports")).not.toBeInTheDocument()
    expect(within(figures).queryByText(/→/)).not.toBeInTheDocument()
  })

  it("lists the credentials tried and links them to the Trends filters", async () => {
    const { creds } = stub(group())
    mount(`/attacks/${GROUP_ID}`)

    const card = await screen.findByRole("heading", {
      name: "812 attempts, 1 username and 812 passwords: no pair was tried twice.",
    })
    expect(card).toBeInTheDocument()
    expect(creds).toHaveBeenCalledWith(GROUP_ID, 10)
    expect(await screen.findByRole("link", { name: /^Administrator: 812/ })).toHaveAttribute(
      "href",
      "/trends?username=Administrator",
    )
    expect(screen.getByRole("link", { name: /^Spring2026!: 1/ })).toHaveAttribute(
      "href",
      "/trends?password=Spring2026!",
    )
    expect(screen.getByText("Top 2 of 812 different passwords")).toBeInTheDocument()
  })

  it("shows the first events with the timeline, and no terminal replay", async () => {
    stub(group({ sensor: "ssh" }))
    mount(`/attacks/${GROUP_ID}`)

    expect(
      await screen.findByRole("heading", {
        name: "The first 3 of 2,436 events of the group, in time order.",
      }),
    ).toBeInTheDocument()
    expect(screen.getByText("First events")).toBeInTheDocument()
    expect(screen.getByRole("list", { name: "Events" })).toBeInTheDocument()
    expect(screen.queryByText("Terminal replay")).not.toBeInTheDocument()
  })

  it("opens on the first 40 events and shows all the loaded ones on request", async () => {
    stub(group())
    const many = Array.from({ length: 60 }, (_, i) =>
      event(i + 1, i % 3 === 0 ? "connect" : i % 3 === 1 ? "login_attempt" : "disconnect", {
        username: "Administrator",
        password: `pw${i}`,
      }),
    )
    vi.spyOn(api, "sessionEvents").mockResolvedValue(page(many))
    mount(`/attacks/${GROUP_ID}`)

    const timeline = await screen.findByRole("list", { name: "Events" })
    expect(within(timeline).getAllByRole("listitem")).toHaveLength(40)
    expect(screen.getByText("Showing the first 40 of 60 loaded events.")).toBeInTheDocument()
    const more = screen.getByRole("button", { name: "Show all 60" })
    expect(more).toHaveAttribute("aria-expanded", "false")
    await userEvent.setup().click(more)
    expect(
      within(screen.getByRole("list", { name: "Events" })).getAllByRole("listitem").length,
    ).toBeGreaterThan(40)
    expect(screen.getByText("All 60 loaded events are shown.")).toBeInTheDocument()
  })

  it("lists the other groups of the same hour and links to every session of the address", async () => {
    const sibling = group({
      session_id: "burst-aaaaaaaaaaaaaaaaaaaaaaaa",
      connections: 96,
      login_attempts: 0,
      tags: ["scanner"],
    })
    const { sessions } = stub(group(), { siblings: [group(), sibling] })
    mount(`/attacks/${GROUP_ID}`)

    const same = await screen.findByRole("list", { name: "Flood groups of the same hour" })
    // The group itself is not its own sibling.
    expect(within(same).getAllByRole("listitem")).toHaveLength(1)
    expect(within(same).getAllByText(/opened 96 RDP connections/).length).toBeGreaterThan(0)
    expect(sessions).toHaveBeenCalledWith(
      expect.objectContaining({
        src_ip: "203.0.113.7",
        kind: "burst",
        since: "2026-11-12T14:00:00.000Z",
        until: "2026-11-12T15:00:00.000Z",
      }),
      null,
      50,
    )
    expect(screen.getByRole("link", { name: "All sessions from this address" })).toHaveAttribute(
      "href",
      "/attacks?src_ip=203.0.113.7",
    )
  })

  it("skips the credentials card for a group that never tried to log in", async () => {
    const { creds } = stub(group({ login_attempts: 0 }))
    mount(`/attacks/${GROUP_ID}`)
    await screen.findByRole("heading", { level: 1 })
    expect(screen.queryByText("Credentials tried")).not.toBeInTheDocument()
    expect(creds).not.toHaveBeenCalled()
  })

  it("resolves a folded connection to its group through ?at= and says so", async () => {
    const { getSession } = stub(group({ folded_from: "k3J9x2_a7Qe" }))
    mount(`/attacks/k3J9x2_a7Qe?at=${encodeURIComponent("2026-11-12T14:30:00Z")}`)

    expect(await screen.findByText(/The connection you opened/)).toHaveTextContent(
      "The connection you opened (k3J9x2_a7Qe) is one of them.",
    )
    expect(getSession).toHaveBeenCalledWith("k3J9x2_a7Qe", "2026-11-12T14:30:00Z")
    // Everything else is read from the group the API returned, not from the folded id.
    expect(api.sessionEvents).toHaveBeenCalledWith(GROUP_ID, null, 200)
    expect(api.sessionCredentials).toHaveBeenCalledWith(GROUP_ID, 10)
  })

  it("ignores an ?at= that is not an instant, instead of failing with a 422", async () => {
    const { getSession } = stub(group())
    mount(`/attacks/${GROUP_ID}?at=yesterday`)
    await screen.findByRole("heading", { level: 1 })
    expect(getSession).toHaveBeenCalledWith(GROUP_ID, undefined)
  })
})

describe("SessionDetailPage for a single session", () => {
  it("keeps the ports, the session id and no group cards", async () => {
    stub(plain({ login_attempts: 3, event_count: 5 }))
    mount("/attacks/k3J9x2_a7Qe")
    await screen.findByRole("heading", { level: 1 })
    expect(screen.getByText("Ports")).toBeInTheDocument()
    expect(screen.getByText("Session ID")).toBeInTheDocument()
    expect(screen.queryByText("Credentials tried")).not.toBeInTheDocument()
    expect(screen.queryByText("flood")).not.toBeInTheDocument()
    expect(screen.queryByText("Same hour")).not.toBeInTheDocument()
    expect(api.sessionCredentials).not.toHaveBeenCalled()
  })
})
