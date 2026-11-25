import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { LiveFeedProvider } from "@/app/live-feed"
import { TooltipProvider } from "@/components/ui/tooltip"
import { alertsApi } from "@/lib/alerts"
import { api, type LiveEvent, type LiveWindow } from "@/lib/api"
import { liveEvent } from "@/lib/live-messages.test"
import { storyApi } from "@/lib/story"
import { todayApi, type TodayCardData, type TodayResponse } from "@/lib/today"
import { buildStory } from "@/mocks/story"
import { stubResizeObserver } from "@/test/dom-stubs"
import { TodayPage } from "./today"

// The map itself (SVG, ResizeObserver) has its own tests: a stub shows what the page hands it.
vi.mock("@/components/map/world-map", () => ({
  WorldMap: (p: { focus: string | null; activity: { sources: unknown[] } }) => (
    <div data-testid="map" data-focus={p.focus ?? ""} data-sources={p.activity.sources.length} />
  ),
}))
vi.mock("@/components/map/use-site", () => ({
  useSiteHome: () => ({ data: { lat: 46.8, lon: 8.2, label: "Switzerland" } }),
}))

class Socket {
  static current: Socket | null = null
  readyState = 1
  onopen: (() => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onclose: ((ev: { code: number }) => void) | null = null
  onerror: (() => void) | null = null
  constructor() {
    Socket.current = this
    queueMicrotask(() => this.onopen?.())
  }
  send() {
    return
  }
  close() {
    return
  }
  push(v: unknown) {
    this.onmessage?.({ data: JSON.stringify(v) })
  }
}

function mount(path = "/") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <IpMaskProvider>
          <TooltipProvider>
            <LiveFeedProvider
              options={{
                createSocket: () => new Socket() as unknown as WebSocket,
                fetchRecent: () => Promise.resolve([]),
              }}
            >
              <TodayPage />
            </LiveFeedProvider>
          </TooltipProvider>
        </IpMaskProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const card = (id: TodayCardData["id"], sentence: string, empty = false): TodayCardData => ({
  id,
  sentence,
  items: [],
  action: { label: `Open ${id}`, to: `/${id}` },
  empty,
})

const TODAY: TodayResponse = {
  generated_at: new Date().toISOString(),
  window_hours: 24,
  hidden_benign: 0,
  cards: [
    card("happened", "1,204 attacks came from 312 addresses."),
    card("exposure", "Attackers went after 2 of your 3 services.", true),
    card("campaigns", "2 new campaigns this week."),
    card("new_week", "9 things showed up for the first time."),
    card("act", "2 servers hand out malware."),
    card("forms", "1 report to submit by web form, for 1 provider."),
  ],
}

/** The API's window for the last 15 minutes: Brazil bursted 12 minutes ago, past the live buffer. */
const WINDOW: LiveWindow = {
  as_of: new Date().toISOString(),
  window_minutes: 15,
  last_event_id: 50,
  events: 80,
  unlocated: 0,
  events_last_minute: 5,
  sessions_last_minute: 2,
  last_minute_by_sensor: { ssh: { events: 5, sessions: 2 } },
  by_sensor: { ssh: 80 },
  countries: [
    {
      country: "BR",
      events: 70,
      ips: 4,
      top_ip: "198.51.100.77",
      top_ip_events: 40,
      last_ts: new Date(Date.now() - 12 * 60_000).toISOString(),
      by_sensor: { ssh: 70 },
    },
    {
      country: "FR",
      events: 10,
      ips: 1,
      top_ip: "203.0.113.5",
      top_ip_events: 10,
      last_ts: new Date(Date.now() - 30_000).toISOString(),
      by_sensor: { ssh: 10 },
    },
  ],
  addresses: [],
  networks: [],
}

/** A recent event (inside the 15-minute window). */
function recent(id: number, over: Partial<LiveEvent> = {}): LiveEvent {
  return liveEvent(id, { ts: new Date(Date.now() - (100 - id) * 1_000).toISOString(), ...over })
}

const FR = { country: "FR", asn: 64505, org: "Hexagone Serveurs" }
const DE = { country: "DE", asn: 64499, org: "Rhein Compute GmbH" }

beforeAll(stubResizeObserver)
afterEach(() => vi.restoreAllMocks())
beforeEach(() => {
  Socket.current = null
  vi.spyOn(storyApi, "story").mockResolvedValue(buildStory(24))
  vi.spyOn(todayApi, "today").mockResolvedValue(TODAY)
  vi.spyOn(alertsApi, "outbox").mockResolvedValue({ items: [], next_cursor: null })
  // No window by default: the page falls back to the live buffer alone.
  vi.spyOn(api, "liveWindow").mockRejectedValue(new Error("offline"))
})

describe("TodayPage: the day", () => {
  it("opens with the day's sentence, five numbers and the hours of the day", async () => {
    mount()
    expect(await screen.findByText(/machines from 38 countries knocked/)).toBeInTheDocument()
    const day = screen.getByRole("region", { name: "Last 24 hours" })
    for (const label of ["Visits", "Machines", "Countries", "Got in", "Tried to install"])
      expect(within(day).getByText(label)).toBeInTheDocument()
    const hours = within(day).getByRole("group", { name: "Visits per hour, last 24 hours" })
    const columns = within(hours).getAllByRole("link")
    expect(columns).toHaveLength(24)
    // Each hour opens its visits; the chart is one tab stop.
    expect(columns[0]?.getAttribute("href")).toMatch(/^\/attacks\?since=.+&until=/)
    expect(columns.filter((c) => c.tabIndex === 0)).toHaveLength(1)
  })

  it("moves between hours with the arrow keys", async () => {
    const user = userEvent.setup()
    mount()
    const hours = await screen.findByRole("group", { name: "Visits per hour, last 24 hours" })
    const first = within(hours)
      .getAllByRole("link")
      .find((c) => c.tabIndex === 0)
    if (!first) throw new Error("no focusable hour")
    first.focus()
    await user.keyboard("{Home}")
    expect(within(hours).getAllByRole("link")[0]).toHaveFocus()
    await user.keyboard("{ArrowRight}")
    expect(within(hours).getAllByRole("link")[1]).toHaveFocus()
  })

  it("lists the three most pressing things to do, the ones with news first", async () => {
    mount()
    const list = await screen.findByRole("list", { name: "To do" })
    const rows = within(list).getAllByRole("link")
    expect(rows.map((r) => r.getAttribute("href"))).toEqual(["/forms", "/act", "/campaigns"])
    expect(rows[0]).toHaveAccessibleName(/^To submit by form: 1 report to submit by web form/)
  })

  it("ends the list with one line for the alerts sent lately", async () => {
    vi.spyOn(alertsApi, "outbox").mockResolvedValue({
      items: [
        {
          id: 1,
          rule_kind: "malware_drop",
          channel_id: 1,
          channel_name: "Discord",
          state: "sent",
          attempts: 1,
          created_at: new Date(Date.now() - 5 * 60_000).toISOString(),
          sent_at: null,
          error_code: null,
          severity: "severe",
          title: "Malware was dropped on the honeypot",
          summary: null,
        },
      ],
      next_cursor: null,
    })
    mount()
    const line = await screen.findByRole("link", {
      name: /^Alerts: 1 sent in the last 24 hours, the latest/,
    })
    expect(line).toHaveAttribute("href", "/settings?tab=alert-rules")
  })

  it("says so when nothing needs the operator", async () => {
    vi.spyOn(todayApi, "today").mockResolvedValue({
      ...TODAY,
      cards: [card("act", "Nothing urgent today.", true), card("campaigns", "No new one.", true)],
    })
    mount()
    expect(await screen.findByText("Nothing needs you right now.")).toBeInTheDocument()
  })

  it("tells a quiet day in its sentence", async () => {
    const empty = buildStory(24)
    empty.totals = { ...empty.totals, sessions: 0 }
    vi.spyOn(storyApi, "story").mockResolvedValue(empty)
    mount()
    expect(await screen.findByText(/A quiet day: nobody knocked/)).toBeInTheDocument()
  })

  it("keeps the live map running when the day cannot be loaded", async () => {
    vi.spyOn(storyApi, "story").mockRejectedValue(new Error("down"))
    mount()
    expect(
      await screen.findByText("The numbers of the day could not be loaded."),
    ).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument()
    expect(screen.getByTestId("map")).toBeInTheDocument()
  })
})

describe("TodayPage: the live map", () => {
  it("seeds the map from the API window and adds only newer live events", async () => {
    vi.spyOn(api, "liveWindow").mockResolvedValue(WINDOW)
    mount()
    await act(() => Promise.resolve())
    await waitFor(() => expect(screen.getByTestId("map")).toHaveAttribute("data-sources", "2"))
    act(() => {
      Socket.current?.push({
        kind: "backfill",
        events: [
          recent(51, { country: "DE", src_ip: "198.51.100.23" }),
          recent(49, { country: "DE", src_ip: "198.51.100.24" }),
        ],
      })
    })
    // Event 49 is older than the snapshot, so only 51 adds a third country.
    expect(screen.getByTestId("map")).toHaveAttribute("data-sources", "3")
  })

  it("shows a waiting note, then the ticker and the rankings", async () => {
    const user = userEvent.setup()
    mount()
    await act(() => Promise.resolve())
    expect(screen.getByText(/Nothing has arrived yet/)).toBeInTheDocument()

    act(() => {
      Socket.current?.push({
        kind: "backfill",
        events: [
          recent(4, { ...FR, src_ip: "203.0.113.77" }),
          recent(3, { ...FR, src_ip: "203.0.113.77" }),
          recent(2, { ...FR, src_ip: "198.51.100.41" }),
          recent(1, { ...DE, src_ip: "198.51.100.23" }),
        ],
      })
    })
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(4)

    // One ranking at a time, addresses first; the countries are on the map.
    expect(screen.queryByRole("list", { name: "Top countries" })).toBeNull()
    const addresses = screen.getByRole("list", { name: "Top addresses" })
    expect(within(addresses).getAllByRole("link")[0]).toHaveAttribute(
      "href",
      "/attacks?src_ip=203.0.113.77",
    )
    expect(
      screen.getByText("203.0.113.77 (France) is the busiest address: 2 events, 50% of the total."),
    ).toBeInTheDocument()

    await user.click(screen.getByRole("radio", { name: "Networks" }))
    expect(
      screen.getByText("Hexagone Serveurs (AS64505) sends the most: 75% of events."),
    ).toBeInTheDocument()
    expect(
      within(screen.getByRole("list", { name: "Top networks" })).getAllByRole("link")[0],
    ).toHaveAttribute("href", "/attacks?asn=64505")
    expect(screen.getByTestId("map")).toHaveAttribute("data-sources", "2")
  })

  it("lights a country on the map while its row is hovered", async () => {
    const user = userEvent.setup()
    mount()
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({
        kind: "backfill",
        events: [
          recent(3, { ...DE, src_ip: "198.51.100.23" }),
          recent(2, { ...DE, src_ip: "198.51.100.23" }),
          recent(1, FR),
        ],
      })
    })
    const addresses = screen.getByRole("list", { name: "Top addresses" })
    const [first] = within(addresses).getAllByRole("link")
    if (!first) throw new Error("no address row")
    await user.hover(first)
    expect(screen.getByTestId("map")).toHaveAttribute("data-focus", "DE")
    await user.unhover(first)
    expect(screen.getByTestId("map")).toHaveAttribute("data-focus", "")
  })

  it("holds new events behind a resume pill while paused", async () => {
    const user = userEvent.setup()
    mount()
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({ kind: "backfill", events: [recent(1)] })
    })
    await user.click(screen.getByRole("button", { name: "Pause" }))
    act(() => {
      Socket.current?.push({ kind: "event", event: recent(2) })
      Socket.current?.push({ kind: "event", event: recent(3) })
    })
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(1)
    await user.click(screen.getByRole("button", { name: "2 new events" }))
    expect(screen.queryByRole("button", { name: "2 new events" })).toBeNull()
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument()
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(3)
  })

  it("filters by the sensor in the URL", async () => {
    mount("/?sensor=web")
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({ kind: "backfill", events: [recent(1, { sensor: "ssh" })] })
    })
    expect(screen.getByText("No events from this sensor yet.")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Show all sensors" })).toHaveAttribute("href", "/")
  })

  it("shows events per minute per family, and a family toggle filters the page", async () => {
    const user = userEvent.setup()
    mount("/?sensor=redis,mysql,mssql")
    await act(() => Promise.resolve())
    act(() => {
      Socket.current?.push({
        kind: "stats",
        stats: {
          window_seconds: 60,
          events_last_minute: 9,
          sessions_last_minute: 3,
          by_sensor: { redis: { events: 7, sessions: 2 }, smb: { events: 2, sessions: 1 } },
        },
      })
      Socket.current?.push({ kind: "backfill", events: [recent(1, { sensor: "ssh" })] })
    })
    expect(screen.getByText("No events from these sensors yet.")).toBeInTheDocument()
    expect(screen.getByText(/Nothing from the databases is in the live buffer/)).toBeInTheDocument()

    // Two strips are rendered (overlay on wide cards, grid on narrow ones); CSS shows one.
    const [strip] = screen.getAllByRole("region", { name: "Events in the last minute" })
    if (!strip) throw new Error("no strip")
    const databases = within(strip).getByRole("button", { name: /^Databases: 7 events/ })
    expect(databases).toHaveAttribute("aria-pressed", "true")
    await user.click(databases)
    expect(within(strip).getByRole("button", { name: /^Databases: 7 events/ })).toHaveAttribute(
      "aria-pressed",
      "false",
    )
    // Every sensor again: the ssh event is back in the ticker.
    expect(
      within(screen.getByRole("list", { name: "Latest events" })).getAllByRole("link"),
    ).toHaveLength(1)

    await user.click(within(strip).getByRole("button", { name: /^Windows & VoIP: 2 events/ }))
    expect(
      within(strip).getByRole("button", { name: /^Windows & VoIP: 2 events/ }),
    ).toHaveAttribute("aria-pressed", "true")
    expect(screen.getByText("No events from these sensors yet.")).toBeInTheDocument()
  })
})
