import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { localToUtcMinute, utcMinuteToLocal } from "@/lib/abuse"
import { DigestCard } from "./digest-card"

function stub(digest: { enabled: boolean; minute: number | null }) {
  const puts: unknown[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  let current = { ...digest }
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (url.endsWith("/abuse/digest")) {
        if (method === "PUT") {
          const b = JSON.parse(init?.body as string) as { enabled: boolean; minute?: number }
          puts.push(b)
          current = { enabled: b.enabled, minute: b.minute ?? current.minute }
        }
        return Promise.resolve(json(200, current))
      }
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return puts
}

function renderCard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <DigestCard />
    </QueryClientProvider>,
  )
}

class NoopResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}

beforeEach(() => vi.stubGlobal("ResizeObserver", NoopResizeObserver))
afterEach(() => vi.unstubAllGlobals())

describe("DigestCard", () => {
  it("shows the digest hour in local time and saves it in UTC minutes", async () => {
    const puts = stub({ enabled: true, minute: 462 })
    renderCard()
    const hour = await screen.findByLabelText("Digest hour")
    expect(hour).toHaveValue(utcMinuteToLocal(462))
    expect(screen.getByRole("switch", { name: /One mail per provider per day/ })).toBeChecked()
    expect(screen.getByText(/at most 100 sources/)).toBeInTheDocument()
    expect(screen.getByText(/The daily limit counts mails/)).toBeInTheDocument()
    await userEvent.clear(hour)
    await userEvent.type(hour, "08:15")
    await userEvent.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toEqual({ enabled: true, minute: localToUtcMinute("08:15") })
    expect(await screen.findByText("Saved.")).toBeInTheDocument()
  })

  it("turns digests off", async () => {
    const puts = stub({ enabled: true, minute: 400 })
    renderCard()
    await userEvent.click(
      await screen.findByRole("switch", { name: /One mail per provider per day/ }),
    )
    await userEvent.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toMatchObject({ enabled: false })
    expect(
      await screen.findByText("Daily digests are off: each report goes after the waiting time."),
    ).toBeInTheDocument()
  })

  it("disables the hour until SMTP is set up and saves only the switch", async () => {
    const puts = stub({ enabled: true, minute: null })
    renderCard()
    const hour = await screen.findByLabelText("Digest hour")
    expect(hour).toBeDisabled()
    expect(screen.getByText(/Set up SMTP above first/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toEqual({ enabled: true })
  })
})
