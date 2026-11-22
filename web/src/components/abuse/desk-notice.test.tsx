import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { afterEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { safeFormUrl, type Recipient } from "@/lib/abuse"
import type { AuthUser } from "@/lib/auth-api"
import { DeskNotice } from "./desk-notice"

const ADMIN: AuthUser = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}

const recipient = (over: Partial<Recipient> = {}): Recipient => ({
  id: 7,
  name: "Example Hosting",
  mailbox: "abuse@example.net",
  source: "rdap",
  muted: false,
  ...over,
})

function stub() {
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
      return Promise.resolve(json(200, {}))
    }),
  )
  return calls
}

function show(r: Recipient, onChanged = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <AuthProvider>
          <MemoryRouter>
            <DeskNotice recipient={r} onChanged={onChanged} asns={[64500]} />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
  return onChanged
}

afterEach(() => vi.unstubAllGlobals())

describe("safeFormUrl", () => {
  it("accepts https only", () => {
    expect(safeFormUrl("https://support.example.net/form")).toBe("https://support.example.net/form")
    expect(safeFormUrl("http://support.example.net/form")).toBeNull()
    expect(safeFormUrl("javascript:alert(1)")).toBeNull()
    expect(safeFormUrl(null)).toBeNull()
  })
})

describe("DeskNotice", () => {
  it("renders nothing for a normal desk", () => {
    stub()
    show(recipient())
    expect(screen.queryByRole("note")).toBeNull()
  })

  it("says the desk only accepts its web form and links to it", async () => {
    stub()
    show(
      recipient({
        form_only: true,
        form_url: "https://support.example.net/abuse",
        form_url_clickable: true,
      }),
    )
    expect(await screen.findByText(/only accepts its web form/)).toBeInTheDocument()
    const link = screen.getByRole("link", { name: /Open the form/ })
    expect(link).toHaveAttribute("href", "https://support.example.net/abuse")
    expect(link).toHaveAttribute("rel", "noopener noreferrer")
    expect(link).toHaveAttribute("referrerpolicy", "no-referrer")
    expect(link).toHaveAttribute("target", "_blank")
    expect(screen.getByText("(support.example.net)")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "To submit by form" })).toHaveAttribute(
      "href",
      "/defend/abuse?status=forms",
    )
  })

  it("offers the suggestion text for a link from a verified reply, and nothing else", async () => {
    stub()
    show(
      recipient({
        form_only: true,
        form_source: "reply",
        form_url: "https://support.example.net/abuse",
        form_url_clickable: true,
      }),
    )
    expect(await screen.findByText("Suggest for the shared directory")).toBeInTheDocument()
    const text = screen.getByLabelText("Suggestion").textContent
    expect(text).toContain("Provider: Example Hosting")
    expect(text).toContain("Abuse mailbox domain: example.net")
    expect(text).toContain("ASN: AS64500")
    expect(text).toContain("Form link: https://support.example.net/abuse")
    expect(text).toContain("Learned from a verified reply.")
    expect(text).not.toContain("abuse@")
    expect(screen.getByText(/links that account to reporting this provider/)).toBeInTheDocument()
    const issue = screen.getByRole("link", { name: /Open a new issue/ })
    expect(issue).toHaveAttribute("rel", "noopener noreferrer")
    expect(issue.getAttribute("href")).toMatch(
      /^https:\/\/github\.com\/selfhostr\/suckerpot\/issues\/new/,
    )
  })

  it("never puts a reply link's query in the suggestion, and shows it as text only", async () => {
    stub()
    show(
      recipient({
        form_only: true,
        form_source: "reply",
        form_url:
          "https://support.example.net:8443/ticket/123456/form?ticket=T-4711&email=me@example.org",
        form_url_clickable: false,
      }),
    )
    expect(await screen.findByText("Suggest for the shared directory")).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /Open the form/ })).toBeNull()
    expect(screen.getByText(/not opened as a link/)).toBeInTheDocument()
    const text = screen.getByLabelText("Suggestion").textContent
    expect(text).toContain(
      "Provider site (the form link was left out, find the form page there): https://support.example.net/",
    )
    expect(text).not.toContain("ticket")
    expect(text).not.toContain("123456")
    expect(text).not.toContain("/form")
    expect(text).not.toContain("T-4711")
    expect(text).not.toContain("me@example.org")
    expect(text).not.toContain("8443")
    expect(screen.getByText(/Find the form page on the provider/)).toBeInTheDocument()
  })

  it("shows a link the server did not allow as text only", async () => {
    stub()
    show(
      recipient({
        form_only: true,
        form_url: "https://forms.example.org/abuse",
        form_url_clickable: false,
      }),
    )
    expect(await screen.findByText(/only accepts its web form/)).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /Open the form/ })).toBeNull()
    expect(screen.getByText("https://forms.example.org/abuse")).toBeInTheDocument()
  })

  it("does not offer a suggestion for a directory desk", async () => {
    stub()
    show(
      recipient({
        form_only: true,
        form_source: "directory",
        form_url: "https://support.example.net/abuse",
      }),
    )
    expect(await screen.findByText(/shared directory of abuse forms says so/)).toBeInTheDocument()
    expect(screen.queryByText("Suggest for the shared directory")).toBeNull()
  })

  it("never links a URL that is not https", async () => {
    stub()
    show(recipient({ form_only: true, form_url: "http://support.example.net/abuse" }))
    expect(await screen.findByText(/only accepts its web form/)).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /Open the form/ })).toBeNull()
  })

  it("lets the owner clear the flag", async () => {
    const calls = stub()
    const onChanged = show(recipient({ form_only: true }))
    await userEvent.click(await screen.findByRole("button", { name: "Clear this flag" }))
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    const patch = calls.find((c) => c.method === "PATCH")
    expect(patch?.url).toContain("/abuse/recipients/7")
    expect(patch?.body).toEqual({ form_only: false })
  })

  it("says a dead address was skipped", async () => {
    stub()
    show(recipient({ undeliverable: true }))
    expect(await screen.findByText(/bounced for good/)).toBeInTheDocument()
  })
})
