import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ReportingCard } from "./reporting-card"

const ME = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}

const BARE = {
  reply_contact: "reports@example.net",
  signature: null,
  intro: null,
  outro: null,
  xarf_user_agent: null,
  note: null,
  subject_template: null,
  round_times: true,
  default_options: {
    defang: true,
    include_usernames: true,
    include_reply_contact: true,
    distinct_sources: 1,
  },
  default_tlp: "green",
  reference_style: "subject",
  revision: 4,
}

/** `refuse`: the 409 body of a settings save the identity check turns down. */
function stub(settings: unknown, refuse?: Record<string, unknown>) {
  const puts: unknown[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, ME))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (url.endsWith("/abuse/settings")) {
        if (method === "PUT") {
          puts.push(JSON.parse(init?.body as string))
          if (refuse) return Promise.resolve(json(409, refuse))
        }
        return Promise.resolve(json(200, settings))
      }
      if (url.includes("/abuse/self-terms")) return Promise.resolve(json(200, []))
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
        <MemoryRouter initialEntries={["/settings?tab=reporting"]}>
          <TooltipProvider>
            <AuthProvider>
              <ReportingCard />
            </AuthProvider>
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

/** The text of every alert on the page (other cards keep empty ones). */
const alertText = () =>
  screen
    .getAllByRole("alert")
    .map((a) => a.textContent)
    .join(" ")

class NoopResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}

beforeEach(() => vi.stubGlobal("ResizeObserver", NoopResizeObserver))
afterEach(() => vi.unstubAllGlobals())

describe("ReportingCard", () => {
  it("marks the wording fields optional and saves them empty", async () => {
    const puts = stub(BARE)
    renderCard()
    await screen.findByRole("textbox", { name: /Reply contact/ })
    // Signature, Introduction, Closing, X-ARF user agent, Note and Subject template.
    expect(screen.getAllByText("Optional")).toHaveLength(6)
    expect(screen.getAllByText(/Leave empty to send only the facts/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/Required: write this/)).toBeNull()
    expect(screen.queryByText(/start empty on purpose/)).toBeNull()
    await userEvent.click(screen.getByRole("button", { name: /^save/i }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toMatchObject({
      reply_contact: "reports@example.net",
      intro: null,
      outro: null,
      note: null,
      signature: null,
      subject_template: null,
      xarf_user_agent: null,
    })
  })

  it("says what blocks every report, field by field, when the saved text does", async () => {
    stub({
      ...BARE,
      reply_contact: "reports@named.example.net",
      intro: "A text kept from an older version.",
      field_issues: { reply_contact: ["project_term"], intro: ["default_wording"] },
    })
    renderCard()
    const reply = await screen.findByRole("textbox", { name: /Reply contact/ })
    expect(
      screen.getByText(
        "This reply address names the project, so every report would reveal the honeypot. Use a neutral address.",
      ),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/The introduction uses wording that older versions shipped/),
    ).toBeInTheDocument()
    expect(screen.getByText(/Some of these texts block every report/)).toBeInTheDocument()
    expect(reply).toHaveAttribute("aria-invalid", "true")
    expect(reply).toHaveAccessibleDescription(/names the project/)
    expect(alertText()).toMatch(/The texts marked below block every report/)
    // No raw code is ever shown.
    expect(screen.queryByText(/project_term|default_wording/)).toBeNull()
  })

  it("clears a field's message once it is edited, and saves without the answer-only data", async () => {
    const puts = stub({
      ...BARE,
      reply_contact: "reports@named.example.net",
      field_issues: { reply_contact: ["project_term"] },
    })
    renderCard()
    const reply = await screen.findByRole("textbox", { name: /Reply contact/ })
    await userEvent.clear(reply)
    await userEvent.type(reply, "reports@example.org")
    expect(screen.queryByText(/names the project/)).toBeNull()
    expect(reply).not.toHaveAttribute("aria-invalid")
    await userEvent.click(screen.getByRole("button", { name: /^save/i }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toMatchObject({ reply_contact: "reports@example.org", revision: 4 })
    expect(puts[0]).not.toHaveProperty("field_issues")
  })

  it("explains a refused save field by field and says nothing was saved", async () => {
    stub(BARE, {
      detail: "These settings would block every report, so they were not saved.",
      code: "identity_guard_failed",
      reasons: ["default_wording", "self_name"],
      fields: { signature: ["self_name"], note: ["default_wording"] },
    })
    renderCard()
    await screen.findByRole("textbox", { name: /Reply contact/ })
    await userEvent.type(screen.getByRole("textbox", { name: /Signature/ }), "Sent from a host")
    await userEvent.click(screen.getByRole("button", { name: /^save/i }))
    expect(
      await screen.findByText(
        /The signature names your monitored system, so every report would reveal it\. Reword it, or leave it empty\./,
      ),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/The note uses wording that older versions shipped/),
    ).toBeInTheDocument()
    expect(alertText()).toMatch(/Nothing was saved\. The texts marked below block every report\./)
    expect(screen.queryByText("Saved.")).toBeNull()
  })
})
