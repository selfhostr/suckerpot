import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ImapCard } from "./imap-card"

const ME = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}

function config(hint: unknown, trusted: string | null = null) {
  return {
    configured: true,
    worker_enabled: true,
    enabled: true,
    password_set: true,
    host: "imap.example.net",
    port: 993,
    security: "ssl",
    username: "reports@example.org",
    folder: "INBOX",
    processed_action: "mark_read",
    move_folder: null,
    poll_minutes: 15,
    since: "2026-10-01",
    trusted_authserv_id: trusted,
    shared_mailbox: false,
    state: {
      last_poll_at: null,
      last_ok_at: null,
      last_error: null,
      move_supported: true,
      counters: {},
      authserv_hint: hint,
    },
    last_test: null,
  }
}

function stub(imap: unknown, testHint?: unknown) {
  const puts: unknown[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, ME))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (url.endsWith("/abuse/imap")) {
        if (method === "PUT") puts.push(JSON.parse(init?.body as string))
        return Promise.resolve(json(200, imap))
      }
      if (url.endsWith("/abuse/imap/test")) return Promise.resolve(json(202, { id: 9 }))
      if (url.endsWith("/abuse/imap/requests/9"))
        return Promise.resolve(
          json(200, {
            id: 9,
            kind: "test",
            status: "done",
            error_code: null,
            result: { ok: true, messages: 20, move_supported: true, authserv_hint: testHint },
            requested_at: "2026-11-01T10:00:00Z",
            done_at: "2026-11-01T10:00:05Z",
          }),
        )
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return puts
}

function renderCard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TooltipProvider>
            <AuthProvider>
              <ImapCard />
            </AuthProvider>
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

const field = () => screen.findByRole("textbox", { name: /Mail provider name/ })

class NoopResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}

beforeEach(() => vi.stubGlobal("ResizeObserver", NoopResizeObserver))
afterEach(() => vi.unstubAllGlobals())

describe("ImapCard provider hint", () => {
  it("suggests the provider name from a connection test and fills the field without saving", async () => {
    const puts = stub(config(null), { id: "mx.example.net", seen: 18, of: 20 })
    renderCard()
    const input = await field()
    expect(screen.queryByRole("button", { name: "Use it" })).toBeNull()
    await userEvent.click(screen.getByRole("button", { name: "Test connection" }))
    expect(
      await screen.findByText(/Your provider signs as/, undefined, { timeout: 3000 }),
    ).toHaveTextContent("Your provider signs as mx.example.net (seen on 18 of 20 recent messages).")
    await userEvent.click(screen.getByRole("button", { name: "Use it" }))
    expect(input).toHaveValue("mx.example.net")
    expect(screen.queryByRole("button", { name: "Use it" })).toBeNull()
    expect(puts).toHaveLength(0)
  })

  it("shows the hint the last poll recorded", async () => {
    stub(config({ id: "MX.Example.net", seen: 3, of: 4 }))
    renderCard()
    await field()
    expect(screen.getByText(/Your provider signs as/)).toHaveTextContent(
      "mx.example.net (seen on 3 of 4 recent messages)",
    )
  })

  it("never shows a hint that is not a valid name", async () => {
    stub(config({ id: "<img src=x onerror=alert(1)>", seen: 3, of: 4 }))
    renderCard()
    await field()
    await waitFor(() => expect(screen.queryByText(/Your provider signs as/)).toBeNull())
    expect(screen.queryByText(/onerror/)).toBeNull()
  })

  it("hides the hint once the field holds that name", async () => {
    stub(config({ id: "mx.example.net", seen: 3, of: 4 }, "mx.example.net"))
    renderCard()
    await field()
    expect(screen.queryByText(/Your provider signs as/)).toBeNull()
  })
})
