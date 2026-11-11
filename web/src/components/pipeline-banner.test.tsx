import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { PipelineBanner } from "./pipeline-banner"

const BASE = {
  status: "ok",
  last_ok_at: "2026-11-09T20:12:07Z",
  stalled_for_seconds: 0,
  failing_since: null,
  last_error: null,
  parked_events: 0,
}

function stub(answer: () => Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve(answer())),
  )
}

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <PipelineBanner />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

const json = (o: object) => new Response(JSON.stringify(o), { status: 200 })

describe("PipelineBanner", () => {
  beforeEach(() => sessionStorage.clear())
  afterEach(() => vi.unstubAllGlobals())

  it("shows a severe alert with the duration, the error and the hint when stalled", async () => {
    stub(() =>
      json({ ...BASE, status: "stalled", stalled_for_seconds: 42 * 60, last_error: "57014 boom" }),
    )
    mount()
    expect(await screen.findByRole("alert")).toHaveTextContent("Events are not being stored.")
    const alert = await screen.findByTestId("pipeline-stalled")
    expect(alert).toHaveTextContent("Events have not been stored for 42 minutes.")
    expect(alert).toHaveTextContent("57014 boom")
    expect(alert).toHaveTextContent("docker compose logs ingest")
  })

  it("omits the error line when there is none", async () => {
    stub(() => json({ ...BASE, status: "stalled", stalled_for_seconds: 3 * 3600 }))
    mount()
    expect(await screen.findByRole("alert")).toHaveTextContent("Events are not being stored.")
    const alert = await screen.findByTestId("pipeline-stalled")
    expect(alert).toHaveTextContent("for 3 hours")
    expect(alert).not.toHaveTextContent("Last error")
  })

  it("renders nothing when ok", async () => {
    stub(() => json(BASE))
    const { container } = mount()
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it("renders nothing on a 404", async () => {
    stub(() => new Response(null, { status: 404 }))
    const { container } = mount()
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it("shows a quiet dismissible notice for parked events, remembered per count", async () => {
    stub(() => json({ ...BASE, parked_events: 3 }))
    const first = mount()
    expect(await screen.findByRole("status")).toHaveTextContent(
      "3 events could not be stored and were set aside.",
    )
    expect(screen.getByRole("link", { name: "See Settings" })).toHaveAttribute("href", "/settings")
    await userEvent.click(screen.getByRole("button", { name: "Dismiss this notice" }))
    expect(screen.queryByRole("status")).toBeNull()
    first.unmount()

    // Same count after a reload: stays dismissed.
    const again = mount()
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(2))
    expect(again.container).toBeEmptyDOMElement()
    again.unmount()

    // A larger count shows it again.
    stub(() => json({ ...BASE, parked_events: 5 }))
    mount()
    expect(await screen.findByRole("status")).toHaveTextContent("5 events")
  })
})
