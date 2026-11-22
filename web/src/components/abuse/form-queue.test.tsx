import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { FormQueueItem, Kit } from "@/lib/abuse-forms"
import type { AuthUser } from "@/lib/auth-api"
import { FormQueue } from "./form-queue"

const ADMIN: AuthUser = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}

const ID = "8b8b8b8b-0000-4000-8000-000000000001"

const item = (over: Partial<FormQueueItem> = {}): FormQueueItem => ({
  public_id: ID,
  revision: 4,
  status: "draft",
  recipient: {
    id: 3,
    name: "Example Hosting",
    mailbox: "abuse@example.net",
    source: "rdap",
    muted: false,
  },
  week: "2026-11-16",
  subject_count: 2,
  stale_count: 1,
  window_start: "2026-11-16T10:00:00Z",
  window_end: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:00:00Z",
  guard: { ok: true, codes: [] },
  form_host: "www.example.net",
  form_origin: "directory",
  ...over,
})

const kit = (over: Partial<Kit> = {}): Kit => ({
  public_id: ID,
  revision: 4,
  status: "draft",
  provider: "Example Hosting",
  mailbox: "abuse@example.net",
  week: "2026-11-16",
  warning:
    "The provider sees the address of the browser that submits the form. Open it through your VPN or the Tor Browser.",
  links: [
    {
      url: "https://www.example.net/abuse",
      host: "www.example.net",
      origin: "directory",
      clickable: true,
      checked_on: "2026-11-01",
      stale: false,
    },
  ],
  links_differ: false,
  email: "reports@example.org",
  name: "",
  abuse_type: "Login attack",
  addresses: "198.51.100.23\n198.51.100.24",
  first_seen: "2026-11-16T10:00Z",
  last_seen: "2026-11-20T10:00Z",
  description: "198.51.100.23 (AS64500)\nref 0123456789ab",
  log_excerpt: "2026-11-20T10:00Z 198.51.100.23:41022 TCP/22 (ssh) Login attempts: 412",
  evidence: { name: "evidence.csv", media_type: "text/csv", content: "source\r\n" },
  sources: [
    {
      kind: "attack_source",
      subject_type: "ip",
      value: "198.51.100.23",
      abuse_type: "Login attack",
      first_seen: "2026-11-16T10:00Z",
      last_seen: "2026-11-20T10:00Z",
      description: "one",
      log_excerpt: "line",
      stale: false,
    },
    {
      kind: "attack_source",
      subject_type: "ip",
      value: "198.51.100.24",
      abuse_type: "Exploit attempt",
      first_seen: "2026-11-10T10:00Z",
      last_seen: "2026-11-11T10:00Z",
      description: "two",
      log_excerpt: "line",
      stale: true,
    },
  ],
  one_ip_per_submission: false,
  max_chars: 1000,
  labels: { description: "Comments" },
  guard: { ok: true, codes: [] },
  ...over,
})

interface Answer {
  status: number
  body: unknown
}

function stub(items: FormQueueItem[], answer: Answer = { status: 200, body: kit() }) {
  const calls: { method: string; url: string; body: unknown }[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : undefined
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, ADMIN))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (method !== "GET") calls.push({ method, url, body })
      if (url.includes("/abuse/forms")) return Promise.resolve(json(200, { items, missing: [] }))
      if (url.endsWith("/kit")) return Promise.resolve(json(answer.status, answer.body))
      if (url.endsWith("/submitted"))
        return Promise.resolve(
          json(200, { public_id: ID, submitted: 1, left: 1, sent_at: "2026-11-21T10:00:00Z" }),
        )
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return calls
}

function renderQueue() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TooltipProvider>
            <AuthProvider>
              <FormQueue />
            </AuthProvider>
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

class NoopResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}

beforeEach(() => vi.stubGlobal("ResizeObserver", NoopResizeObserver))
afterEach(() => vi.unstubAllGlobals())

async function openKit() {
  await userEvent.click(await screen.findByRole("button", { name: "Open the kit" }))
}

describe("FormQueue", () => {
  it("lists one card per provider and week", async () => {
    stub([item()])
    renderQueue()
    expect(await screen.findByText("Example Hosting")).toBeInTheDocument()
    expect(screen.getByText(/Week of 16 Nov 2026/)).toBeInTheDocument()
    expect(screen.getByText(/2 addresses, 1 older than 7 days/)).toBeInTheDocument()
  })

  it("says when there is nothing to submit", async () => {
    stub([])
    renderQueue()
    expect(await screen.findByText("Nothing to submit by form")).toBeInTheDocument()
  })

  it("opens the kit with the fixed warning first and a link that leaks no referrer", async () => {
    stub([item()])
    renderQueue()
    await openKit()
    const warning = await screen.findByText(/sees the address of the browser/)
    expect(warning).toHaveTextContent("Tor Browser")
    const link = screen.getByRole("link", { name: /Open the form/ })
    expect(link).toHaveAttribute("href", "https://www.example.net/abuse")
    expect(link).toHaveAttribute("rel", "noopener noreferrer")
    expect(link).toHaveAttribute("referrerpolicy", "no-referrer")
    expect(link).toHaveAttribute("target", "_blank")
    expect(
      within(screen.getByRole("region", { name: "Form link" })).getByText("www.example.net"),
    ).toBeInTheDocument()
    expect(screen.getByText(/From the shared directory, checked 2026-11-01/)).toBeInTheDocument()
    // Every field has its own copy button, with the form's own label when known.
    expect(screen.getByLabelText("Your email")).toHaveTextContent("reports@example.org")
    expect(screen.getByLabelText("Description (the form says “Comments”)")).toHaveTextContent(
      "ref 0123456789ab",
    )
    expect(screen.getByRole("button", { name: "Copy addresses" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /Download evidence.csv/ })).toBeInTheDocument()
  })

  it("never makes a link of a form address the server did not allow", async () => {
    stub([item()], {
      status: 200,
      body: kit({
        links: [
          {
            url: "https://forms.example.org/abuse",
            host: "forms.example.org",
            origin: "reply",
            clickable: false,
          },
        ],
      }),
    })
    renderQueue()
    await openKit()
    expect(await screen.findByText("Not opened as a link")).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /Open the form/ })).toBeNull()
    expect(screen.getByText(/From a reply: check the address/)).toBeInTheDocument()
  })

  it("never makes a link when the host shown is not the host opened", async () => {
    stub([item()], {
      status: 200,
      body: kit({
        links: [
          {
            url: "https://evil.example.org/abuse",
            host: "www.example.net",
            origin: "directory",
            clickable: true,
          },
        ],
      }),
    })
    renderQueue()
    await openKit()
    expect(await screen.findByText("Not opened as a link")).toBeInTheDocument()
  })

  it("shows why a blocked kit is blocked, with no copy button", async () => {
    stub([item()], {
      status: 409,
      body: {
        detail: "The identity check blocked this content.",
        code: "identity_guard_failed",
        reasons: ["self_address"],
      },
    })
    renderQueue()
    await openKit()
    expect(await screen.findByText("The identity check blocked this kit")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /^Copy/ })).toBeNull()
    expect(screen.queryByRole("button", { name: "Submitted" })).toBeNull()
  })

  it("marks only the ticked addresses as submitted", async () => {
    const calls = stub([item()])
    renderQueue()
    await openKit()
    const second = await screen.findByRole("checkbox", { name: /198\.51\.100\.24/ })
    await userEvent.click(second)
    expect(screen.getByText(/The others wait for the next form report/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole("button", { name: "Submitted" }))
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/submitted"))).toBe(true))
    const post = calls.find((c) => c.url.endsWith("/submitted"))
    expect(post?.body).toEqual({
      revision: 4,
      subjects: [{ kind: "attack_source", subject_type: "ip", value: "198.51.100.23" }],
    })
  })

  it("sends no list when every address was submitted", async () => {
    const calls = stub([item()])
    renderQueue()
    await openKit()
    await userEvent.click(await screen.findByRole("button", { name: "Submitted" }))
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/submitted"))).toBe(true))
    expect(calls.find((c) => c.url.endsWith("/submitted"))?.body).toEqual({ revision: 4 })
  })

  it("starts with nothing ticked for a form that takes one address at a time", async () => {
    stub([item()], { status: 200, body: kit({ one_ip_per_submission: true }) })
    renderQueue()
    await openKit()
    const button = await screen.findByRole("button", { name: "Submitted" })
    expect(button).toBeDisabled()
    const list = screen.getByRole("group")
    expect(within(list).getAllByLabelText("Address")).toHaveLength(2)
    await userEvent.click(screen.getByRole("checkbox", { name: /198\.51\.100\.23/ }))
    expect(button).toBeEnabled()
  })
})
