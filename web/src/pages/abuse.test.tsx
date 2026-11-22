import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, Route, Routes } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { AbuseStatus, ReportDetail } from "@/lib/abuse"
import type { AuthUser } from "@/lib/auth-api"
import { AbuseDetailPage } from "./abuse-detail"
import { AbusePage } from "./abuse"

const ADMIN: AuthUser = {
  username: "admin",
  display_name: "Admin",
  role: "admin",
  is_owner: true,
  must_change_password: false,
  read_only: false,
  last_login_at: null,
}
const VIEWER: AuthUser = {
  ...ADMIN,
  username: "viewer",
  role: "viewer",
  is_owner: false,
  read_only: true,
}

const ID = "7b1f3a52-9c0e-4d2a-8f61-1a2b3c4d5e01"

function report(over: Partial<ReportDetail> = {}): ReportDetail {
  return {
    public_id: ID,
    kind: "attack_source",
    status: "draft",
    demo: false,
    recipient: {
      id: 1,
      name: "Example Hosting B.V.",
      mailbox: "abuse@example.net",
      source: "rdap",
      muted: false,
    },
    asns: [{ asn: 64500, name: "EXAMPLE-NET" }],
    subject_count: 1,
    window_start: "2026-10-30T10:00:00Z",
    window_end: "2026-10-30T12:00:00Z",
    updated_at: "2026-10-30T12:00:00Z",
    revision: 3,
    guard: { ok: true, codes: [] },
    subjects: [
      {
        subject_type: "ip",
        value: "198.51.100.23",
        asn: 64500,
        network: "EXAMPLE-NET",
        handle: "NET-1",
        sessions: 4,
        events: 120,
        first_ts: "2026-10-30T10:00:00Z",
        last_ts: "2026-10-30T12:00:00Z",
        link: "/attacks?src_ip=198.51.100.23",
      },
    ],
    redaction: { masked: 2, removed: 1 },
    options: {
      defang: true,
      time_precision: "minute",
      include_usernames: true,
      include_reply_contact: true,
      show_redaction_counts: false,
    },
    notes: null,
    history: [{ ts: "2026-10-30T12:00:00Z", actor: "ingest", from: null, to: "draft" }],
    missing: [],
    previously_reported: null,
    reviewed_at: null,
    sent_at: null,
    closed_at: null,
    ...over,
  }
}

interface Call {
  method: string
  url: string
  body: unknown
}

function stub(
  opts: {
    me?: AuthUser
    report?: ReportDetail
    status?: Partial<AbuseStatus>
    statusAnswer?: Response
    settings?: Record<string, unknown>
    /** Answer the first "sent" with 409 recipient_sent_today. */
    sameDay?: boolean
  } = {},
) {
  const calls: Call[] = []
  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), { status })
  const r = opts.report ?? report()
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET"
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : undefined
      if (url.endsWith("/auth/me")) return Promise.resolve(json(200, opts.me ?? ADMIN))
      if (url.endsWith("/auth/csrf")) return Promise.resolve(json(200, { token: "t" }))
      if (method !== "GET") calls.push({ method, url, body })
      if (url.endsWith("/abuse/status"))
        return Promise.resolve(
          json(200, {
            enabled: true,
            gate: "open",
            rdap_quota: { used: 1, limit: 1000 },
            self_address_known: true,
            self_address_fresh: true,
            counts: { draft: 1, reviewed: 0, sent: 0, closed: 0, discarded: 0, superseded: 0 },
            waiting_for_contact: 0,
            ...opts.status,
          }),
        )
      if (url.includes("/abuse/reports?"))
        return Promise.resolve(json(200, { items: [r], next_cursor: null }))
      if (url.includes("/render") && url.includes("format=xarf")) {
        return Promise.resolve(
          json(200, {
            to: "abuse@example.net",
            subject: "Abuse report",
            body: "Hello",
            attachments: r.subjects.map((x) => ({
              name: x.xarf_file ?? "xarf.json",
              media_type: "application/json",
              content: `{"source_identifier": "${x.value}"}\n`,
            })),
            revision: r.revision,
            guard: r.guard,
          }),
        )
      }
      if (url.includes("/render")) {
        if (!r.guard.ok)
          return Promise.resolve(
            json(409, { detail: "blocked", code: "identity_guard_failed", reasons: r.guard.codes }),
          )
        return Promise.resolve(
          json(200, {
            to: "abuse@example.net",
            subject: "Abuse report: SSH brute force from 198.51.100.23",
            body: "Hello,\n\nThe addresses below attacked a monitored system.",
            attachments: [],
            revision: r.revision,
            guard: r.guard,
          }),
        )
      }
      if (url.endsWith("/status") && method === "POST") {
        const b = body as { revision: number; to: string; confirm_same_day?: boolean }
        if (b.revision !== r.revision)
          return Promise.resolve(json(409, { detail: "changed", code: "revision_mismatch" }))
        if (opts.sameDay && b.to === "sent" && !b.confirm_same_day)
          return Promise.resolve(
            json(409, {
              detail: "This provider already got a report today.",
              code: "recipient_sent_today",
            }),
          )
        if (b.to === "sent") return Promise.resolve(json(200, { ...r, status: "sent" }))
        return Promise.resolve(json(200, { ...r, status: "reviewed" }))
      }
      if (url.endsWith(`/abuse/reports/${ID}`)) return Promise.resolve(json(200, r))
      if (url.includes("/abuse/recipients")) return Promise.resolve(json(200, []))
      if (url.includes("/abuse/smtp"))
        return Promise.resolve(json(200, { configured: false, mode: "off" }))
      if (url.endsWith("/abuse/settings"))
        return Promise.resolve(json(200, { default_tlp: "green", ...opts.settings }))
      return Promise.resolve(json(404, { detail: "nope" }))
    }),
  )
  return calls
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[path]}>
          <TooltipProvider>
            <AuthProvider>
              <Routes>
                <Route path="/defend/abuse" element={<AbusePage />} />
                <Route path="/defend/abuse/:publicId" element={<AbuseDetailPage />} />
              </Routes>
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

describe("AbusePage", () => {
  it("opens with a sentence and groups reports by provider", async () => {
    stub()
    renderAt("/defend/abuse")
    expect(await screen.findByText("1 draft to review.")).toBeInTheDocument()
    expect(await screen.findByRole("heading", { name: "Example Hosting B.V." })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /AS64500/ })).toHaveAttribute(
      "href",
      "/attackers?asn=64500",
    )
  })

  it("explains why reports are locked when no address of the monitored system is known", async () => {
    stub({ status: { self_address_known: false } })
    renderAt("/defend/abuse")
    expect(await screen.findByText(/reports are locked/)).toBeInTheDocument()
  })

  const BLOCKED = {
    blocked_drafts: { count: 2, reasons: { project_term: 2, default_wording: 1 } },
  }
  const BLOCKED_REPORT = report({
    guard: { ok: false, codes: ["default_wording", "project_term"] },
  })

  it("says how many drafts are blocked, why, and what to do about each reason", async () => {
    stub({
      report: BLOCKED_REPORT,
      status: BLOCKED,
      settings: { field_issues: { reply_contact: ["project_term"] } },
    })
    renderAt("/defend/abuse")
    expect(
      await screen.findByText(
        "2 drafts are blocked by the identity check: they cannot be reviewed, copied or sent until the cause is fixed.",
      ),
    ).toBeInTheDocument()
    // One sentence per reason, with its count and its next step.
    expect(screen.getByText(/The text contains the name of this project/)).toBeInTheDocument()
    expect(
      screen.getByText(/2 drafts\. Use a neutral reply address and neutral wording/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/The text contains wording shipped with the software/),
    ).toBeInTheDocument()
    expect(screen.getByText(/1 draft\. Write the introduction, closing, note/)).toBeInTheDocument()
    // The cause in the owner's own settings, with a way to fix it.
    expect(
      await screen.findByText(
        "This reply address names the project, so every report would reveal the honeypot. Use a neutral address.",
      ),
    ).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Open Reporting settings" })).toHaveAttribute(
      "href",
      "/settings?tab=reporting#reporting-message",
    )
    // Each row says why in a few words.
    expect(screen.getByText("Why: uses old default wording, names the project")).toBeInTheDocument()
    // No raw code reaches the page.
    expect(screen.queryByText(/project_term|default_wording/)).toBeNull()
  })

  it("shows a viewer the reasons but not the owner's settings", async () => {
    stub({
      me: VIEWER,
      report: BLOCKED_REPORT,
      status: BLOCKED,
      settings: { field_issues: { reply_contact: ["project_term"] } },
    })
    renderAt("/defend/abuse")
    expect(
      await screen.findByText(/2 drafts are blocked by the identity check/),
    ).toBeInTheDocument()
    expect(screen.getByText(/The text contains the name of this project/)).toBeInTheDocument()
    expect(screen.queryByText(/This reply address/)).toBeNull()
    expect(screen.queryByRole("link", { name: "Open Reporting settings" })).toBeNull()
  })

  it("shows no notice when nothing is blocked", async () => {
    stub({ status: { blocked_drafts: { count: 0, reasons: {} } } })
    renderAt("/defend/abuse")
    await screen.findByRole("heading", { name: "Example Hosting B.V." })
    expect(screen.queryByText(/blocked by the identity check/)).toBeNull()
  })
})

describe("AbuseDetailPage", () => {
  it("has a copy button for the recipient, the subject and the body", async () => {
    stub()
    const writeText = vi.fn(() => Promise.resolve())
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true })
    renderAt(`/defend/abuse/${ID}`)
    await screen.findByLabelText("Body")
    await userEvent.click(screen.getByRole("button", { name: "Copy to" }))
    await userEvent.click(screen.getByRole("button", { name: "Copy subject" }))
    await userEvent.click(screen.getByRole("button", { name: "Copy body" }))
    expect(writeText.mock.calls.map((c) => (c as unknown as string[])[0])).toEqual([
      "abuse@example.net",
      "Abuse report: SSH brute force from 198.51.100.23",
      "Hello,\n\nThe addresses below attacked a monitored system.",
    ])
  })

  it("marks the report reviewed with the revision that was read", async () => {
    const calls = stub()
    renderAt(`/defend/abuse/${ID}`)
    await userEvent.click(await screen.findByRole("button", { name: "Mark reviewed" }))
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/status"))).toBe(true))
    expect(calls.find((c) => c.url.endsWith("/status"))?.body).toEqual({
      to: "reviewed",
      revision: 3,
    })
  })

  it("refuses to review without a reply contact", async () => {
    stub({ report: report({ missing: ["reply_contact"] }) })
    renderAt(`/defend/abuse/${ID}`)
    const button = await screen.findByRole("button", { name: "Mark reviewed" })
    expect(button).toBeDisabled()
    expect(screen.getByRole("link", { name: "Open Settings" })).toHaveAttribute(
      "href",
      "/settings?tab=reporting",
    )
  })

  it("reloads and explains a revision conflict", async () => {
    const r = report()
    stub({ report: r })
    renderAt(`/defend/abuse/${ID}`)
    // The page read revision 3; the server has moved on.
    r.revision = 4
    await userEvent.click(await screen.findByRole("button", { name: "Mark reviewed" }))
    expect(await screen.findAllByText(/changed while you were reading it/)).not.toHaveLength(0)
  })

  it("is read-only for a viewer", async () => {
    stub({ me: VIEWER })
    renderAt(`/defend/abuse/${ID}`)
    await screen.findByLabelText("Body")
    for (const name of ["Mark reviewed", "Discard", "Regenerate", "Mark sent", "Close"])
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument()
    expect(screen.getByText(/Only an administrator changes a report/)).toBeInTheDocument()
  })

  it("shows the demo banner and offers no Mark sent", async () => {
    stub({ report: report({ demo: true, status: "reviewed" }) })
    renderAt(`/defend/abuse/${ID}`)
    expect(await screen.findByText("Demo data, do not send.")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Mark sent" })).not.toBeInTheDocument()
  })

  it("explains a blocked identity check in plain English without the matched text", async () => {
    stub({ report: report({ guard: { ok: false, codes: ["project_term"] } }) })
    renderAt(`/defend/abuse/${ID}`)
    const card = (await screen.findByText("Identity check")).closest("div") as HTMLElement
    expect(card).toBeTruthy()
    expect(await screen.findByText(/name of this project/)).toBeInTheDocument()
    expect(screen.queryByLabelText("Body")).not.toBeInTheDocument()
    expect(within(document.body).getByRole("button", { name: "Mark reviewed" })).toBeDisabled()
  })

  it("tells the owner what to do about each reason and where the cause is", async () => {
    stub({
      report: report({ guard: { ok: false, codes: ["project_term", "default_wording"] } }),
      settings: { field_issues: { reply_contact: ["project_term"] } },
    })
    renderAt(`/defend/abuse/${ID}`)
    expect(
      await screen.findByText(/Use a neutral reply address and neutral wording/),
    ).toBeInTheDocument()
    expect(screen.getByText(/Write the introduction, closing, note, signature/)).toBeInTheDocument()
    expect(
      await screen.findByText(
        "This reply address names the project, so every report would reveal the honeypot. Use a neutral address.",
      ),
    ).toBeInTheDocument()
    expect(
      screen.getByRole("link", { name: "Fix them in the Reporting settings" }),
    ).toHaveAttribute("href", "/settings?tab=reporting#reporting-message")
    expect(screen.getByText(/Nothing is sent while a draft is blocked/)).toBeInTheDocument()
    expect(screen.queryByText(/project_term|default_wording/)).toBeNull()
  })

  it("does not show the owner's settings to a viewer", async () => {
    stub({
      me: VIEWER,
      report: report({ guard: { ok: false, codes: ["project_term"] } }),
      settings: { field_issues: { reply_contact: ["project_term"] } },
    })
    renderAt(`/defend/abuse/${ID}`)
    expect(
      await screen.findByText(/Use a neutral reply address and neutral wording/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/This reply address/)).toBeNull()
  })
})

const DIGEST = report({
  kind: "digest",
  subject_count: 3,
  kinds: { attack_source: 2, payload_host: 1 },
  due_at: new Date(Date.now() + 2 * 3_600_000).toISOString(),
  part: 2,
  subjects: [
    {
      subject_type: "ip",
      value: "198.51.100.23",
      asn: 64500,
      network: "EXAMPLE-NET",
      handle: null,
      sessions: 4,
      events: 120,
      first_ts: "2026-10-30T10:00:00Z",
      last_ts: "2026-10-30T12:00:00Z",
      link: "/attacks?src_ip=198.51.100.23",
      kind: "attack_source",
      xarf_file: "xarf-001.json",
      outcome: "resolved",
    },
    {
      subject_type: "ip",
      value: "198.51.100.24",
      asn: 64500,
      network: "EXAMPLE-NET",
      handle: null,
      sessions: 1,
      events: 2,
      first_ts: "2026-10-20T10:00:00Z",
      last_ts: "2026-10-20T12:00:00Z",
      link: "/attacks?src_ip=198.51.100.24",
      kind: "attack_source",
      xarf_file: "xarf-002.json",
      stale: true,
    },
    {
      subject_type: "domain",
      value: "files.example.org",
      asn: null,
      network: null,
      handle: null,
      sessions: 1,
      events: 1,
      first_ts: "2026-10-30T10:00:00Z",
      last_ts: "2026-10-30T11:00:00Z",
      link: "/malware?q=files.example.org",
      kind: "payload_host",
      xarf_file: "xarf-003.json",
    },
  ],
})

describe("daily digests", () => {
  it("shows one row per digest with its sources by kind, due time and part", async () => {
    stub({ report: DIGEST })
    renderAt("/defend/abuse")
    expect(
      await screen.findByText("3 sources (2 attack sources, 1 payload host)"),
    ).toBeInTheDocument()
    expect(screen.getByText("Daily digest")).toBeInTheDocument()
    expect(screen.getByText("part 2")).toBeInTheDocument()
    expect(screen.getByText(/^goes (tomorrow )?at \d\d:\d\d$/)).toBeInTheDocument()
  })

  it("groups the sources by kind with their outcome, age and X-ARF file", async () => {
    stub({ report: DIGEST })
    renderAt(`/defend/abuse/${ID}`)
    const attack = await screen.findByRole("region", { name: "Attack sources (2)" })
    expect(within(attack).getAllByText("Resolved").length).toBeGreaterThan(0)
    expect(within(attack).getAllByText("older than 7 days").length).toBeGreaterThan(0)
    expect(within(attack).getAllByText("xarf-002.json").length).toBeGreaterThan(0)
    const payload = screen.getByRole("region", { name: "Payload hosts (1)" })
    expect(within(payload).getAllByText("files.example.org").length).toBeGreaterThan(0)
    expect(screen.queryByRole("region", { name: /Command servers/ })).toBeNull()
  })

  it("lists one X-ARF JSON per source in the X-ARF tab", async () => {
    stub({ report: DIGEST })
    renderAt(`/defend/abuse/${ID}`)
    await screen.findByLabelText("Body")
    await userEvent.click(screen.getByRole("radio", { name: "X-ARF" }))
    expect(await screen.findByLabelText("xarf-001.json (198.51.100.23)")).toHaveTextContent(
      '{"source_identifier": "198.51.100.23"}',
    )
    expect(screen.getByLabelText("xarf-003.json (files.example.org)")).toBeInTheDocument()
    expect(screen.getAllByRole("button", { name: /^Download xarf-00\d\.json$/ })).toHaveLength(3)
  })

  it("asks before a second mail to the same provider today, then confirms", async () => {
    const calls = stub({ report: report({ status: "reviewed" }), sameDay: true })
    const ask = vi.spyOn(window, "confirm").mockReturnValue(true)
    renderAt(`/defend/abuse/${ID}`)
    await userEvent.click(await screen.findByRole("button", { name: "Mark sent" }))
    const dialog = await screen.findByRole("dialog")
    await userEvent.click(within(dialog).getByRole("button", { name: "Mark as sent" }))
    await waitFor(() =>
      expect(calls.filter((c) => c.url.endsWith("/status")).map((c) => c.body)).toEqual([
        expect.objectContaining({ to: "sent", revision: 3 }),
        expect.objectContaining({ to: "sent", revision: 3, confirm_same_day: true }),
      ]),
    )
    expect(ask).toHaveBeenCalledWith("This provider already got a report today. Send anyway?")
    ask.mockRestore()
  })

  it("keeps the report unsent when the owner declines", async () => {
    const calls = stub({ report: report({ status: "reviewed" }), sameDay: true })
    const ask = vi.spyOn(window, "confirm").mockReturnValue(false)
    renderAt(`/defend/abuse/${ID}`)
    await userEvent.click(await screen.findByRole("button", { name: "Mark sent" }))
    const dialog = await screen.findByRole("dialog")
    await userEvent.click(within(dialog).getByRole("button", { name: "Mark as sent" }))
    expect(
      await within(dialog).findByText("This provider already got a report today."),
    ).toBeInTheDocument()
    expect(calls.filter((c) => c.url.endsWith("/status"))).toHaveLength(1)
    ask.mockRestore()
  })

  it("switches one mail per source for the provider", async () => {
    const calls = stub()
    renderAt(`/defend/abuse/${ID}`)
    const toggle = await screen.findByRole("switch", {
      name: /One mail per source \(strict X-ARF\)/,
    })
    expect(toggle).not.toBeChecked()
    expect(screen.getByText(/Every mail counts against the daily cap/)).toBeInTheDocument()
    await userEvent.click(toggle)
    await waitFor(() =>
      expect(calls).toContainEqual({
        method: "PATCH",
        url: "/api/v1/abuse/recipients/1",
        body: { xarf_strict: true },
      }),
    )
  })

  it("offers no strict switch to a viewer", async () => {
    stub({ me: VIEWER })
    renderAt(`/defend/abuse/${ID}`)
    await screen.findByLabelText("Body")
    expect(screen.queryByRole("switch", { name: /strict X-ARF/ })).toBeNull()
  })
})
