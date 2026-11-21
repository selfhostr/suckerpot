/**
 * MSW handlers for the M26 endpoints (docs/dev/design/m26.md section 11): the IMAP profile, replies
 * and the outcome of a report. Demo data only: mailboxes are on example.* domains and no real
 * message appears. State lives for the page load. The password "wrong" fails re-authentication.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type {
  ImapConfig,
  ImapRequest,
  Outcome,
  Reply,
  ReplyClass,
  ReportOutcome,
} from "@/lib/replies"

const LATENCY_MS = 140
const HOUR = 3_600_000
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

/** The mock reports that were sent (ids from mocks/abuse.ts). */
const SENT = "3c4d5e6f-7a8b-4c9d-8e0f-6f7a8b9c0d06"
const CLOSED = "1d2e3f40-5a6b-4c7d-9e8f-7a8b9c0d1e07"

type Seed = Omit<
  Reply,
  | "source"
  | "sent_at"
  | "subject"
  | "auth"
  | "dsn_status"
  | "truncated"
  | "attachments"
  | "excerpt_purged"
  | "reviewed_at"
  | "reviewed_by"
  | "rule_id"
> & { rule: string | null }

const seeds: Seed[] = [
  {
    id: 5,
    report: SENT,
    received_at: iso(57 * HOUR),
    from_domain: "example.net",
    from_address: "abuse-desk@example.net",
    classification: "ticket_opened",
    classification_source: "rule",
    rule: "A ticket number is quoted in the subject",
    match_method: "token",
    verified: true,
    needs_review: false,
    ticket_id: "48213",
    excerpt:
      "Thank you for your report. We opened ticket 48213 and the abuse team will look at the address you listed.",
  },
  {
    id: 4,
    report: SENT,
    received_at: iso(59 * HOUR),
    from_domain: "example.net",
    from_address: "noreply@example.net",
    classification: "auto_ack",
    classification_source: "rule",
    rule: "Automatic receipt (Auto-Submitted header)",
    match_method: "token",
    verified: true,
    needs_review: false,
    ticket_id: null,
    excerpt: "This is an automatic confirmation that we received your message.",
  },
  {
    id: 3,
    report: CLOSED,
    received_at: iso(100 * HOUR),
    from_domain: "example.org",
    from_address: "security@example.org",
    classification: "resolved",
    classification_source: "rule",
    rule: "The sender says the content was removed",
    match_method: "in_reply_to",
    verified: true,
    needs_review: false,
    ticket_id: null,
    excerpt: "The customer was notified and the files were removed from the server.",
  },
  {
    id: 2,
    report: null,
    received_at: iso(5 * HOUR),
    from_domain: "example.com",
    from_address: "helpdesk@example.com",
    classification: "human_reply",
    classification_source: "rule",
    rule: "A person signs the message",
    match_method: "none",
    verified: false,
    needs_review: true,
    ticket_id: null,
    excerpt: "Hello, which of our addresses are you talking about? Please send the log lines.",
  },
  {
    id: 1,
    report: CLOSED,
    received_at: iso(30 * HOUR),
    from_domain: "example.net",
    from_address: null,
    classification: "unknown",
    classification_source: "rule",
    rule: null,
    match_method: "sender",
    verified: false,
    needs_review: true,
    ticket_id: null,
    excerpt: "Re: your message (no text part).",
  },
]

const RULE_IDS: Record<string, string> = {
  "A ticket number is quoted in the subject": "ticket-opened",
  "Automatic receipt (Auto-Submitted header)": "auto-ack",
  "The sender says the content was removed": "resolved-action-taken",
  "A person signs the message": "generic-ticket",
}

/** Rule ids are short codes; the descriptions above are kept as the demo wording. */
const replies: Reply[] = seeds.map(({ rule, ...x }) => ({
  source: "imap",
  sent_at: x.received_at,
  subject: "Re: Abuse report",
  auth: x.verified ? "pass" : "none",
  dsn_status: x.classification === "bounce" ? "5.1.1" : null,
  truncated: false,
  attachments: { count: 0, types: [], bytes: 0 },
  excerpt_purged: false,
  reviewed_at: null,
  reviewed_by: null,
  rule_id: rule ? (RULE_IDS[rule] ?? "ticket-opened") : null,
  ...x,
}))

const manual = new Map<string, { outcome: Outcome; at: string; note: string | null }>()

function derive(report: string): Outcome {
  const order: ReplyClass[] = [
    "resolved",
    "rejected",
    "ticket_opened",
    "human_reply",
    "auto_ack",
    "bounce",
    "unknown",
  ]
  const mine = replies.filter((r) => r.report === report && r.verified)
  return order.find((c) => mine.some((r) => r.classification === c)) ?? "none"
}

function earliest(report: string, ...classes: ReplyClass[]): string | null {
  const t = replies
    .filter((r) => r.report === report && r.verified && classes.includes(r.classification))
    .map((r) => r.received_at)
    .sort()
  return t[0] ?? null
}

/** The outcome of a report for the report page and the list; null while it was not sent. */
export function outcomeFor(report: string, sent: boolean): ReportOutcome | null {
  if (!sent) return null
  const auto = derive(report)
  const m = manual.get(report)
  const mine = replies.filter((r) => r.report === report)
  return {
    effective: m?.outcome ?? auto,
    auto,
    manual: m?.outcome ?? null,
    manual_at: m?.at ?? null,
    note: m?.note ?? null,
    needs_review: mine.some((r) => r.needs_review),
    reply_count: mine.length,
    first_reply_at: earliest(
      report,
      "auto_ack",
      "human_reply",
      "ticket_opened",
      "rejected",
      "resolved",
    ),
    first_human_at: earliest(report, "human_reply", "ticket_opened", "rejected", "resolved"),
    ticket_at: earliest(report, "ticket_opened"),
    resolved_at: earliest(report, "resolved"),
    rejected_at: earliest(report, "rejected"),
    bounced_at: earliest(report, "bounce"),
    ticket_id: replies.find((r) => r.report === report && r.ticket_id)?.ticket_id ?? null,
    no_answer: false,
    first_reply_after_s: null,
    manual_by: m ? "admin" : null,
  }
}

/** The latest replies of a report, newest first. */
export const repliesFor = (report: string): Reply[] =>
  replies
    .filter((r) => r.report === report)
    .sort((a, b) => b.received_at.localeCompare(a.received_at))

export const checkCount = (): number =>
  replies.filter((r) => r.report === null || !r.verified).length

export function repliesStatus() {
  return {
    enabled: true,
    configured: true,
    last_poll_at: iso(7 * 60_000),
    last_error: null,
    unmatched: replies.filter((r) => r.report === null).length,
    needs_review: replies.filter((r) => r.needs_review).length,
  }
}

const imap: ImapConfig = {
  worker_enabled: true,
  last_test: null,
  enabled: true,
  configured: true,
  host: "imap.example.net",
  port: 993,
  security: "ssl",
  username: "reports@example.org",
  password_set: true,
  folder: "INBOX",
  processed_action: "mark_read",
  move_folder: null,
  poll_minutes: 15,
  since: "2026-10-01",
  trusted_authserv_id: "mx.example.net",
  shared_mailbox: false,
  state: {
    last_poll_at: iso(7 * 60_000),
    last_ok_at: iso(7 * 60_000),
    last_error: null,
    move_supported: true,
    counters: { fetched: 14, relevant: 5, matched: 3, ignored: 9, oversize: 0 },
  },
}

/**
 * `?imap=` on the page URL picks a demo state for screenshots: `shared` (free or shared mailbox,
 * no provider name yet, last check failed), `password` (the server asks for the mailbox password
 * again when saving).
 */
const demoState = (): string | null =>
  typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("imap")

const requests = new Map<number, ImapRequest>()
let requestId = 300
let importId = 700

const reauthFailed = () =>
  HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })

async function body(request: Request): Promise<Record<string, unknown>> {
  return ((await request.json().catch(() => ({}))) ?? {}) as Record<string, unknown>
}

const str = (v: unknown, fallback: string): string => (typeof v === "string" ? v : fallback)
const num = (v: unknown, fallback: number): number => (typeof v === "number" ? v : fallback)

const passwordOk = (b: Record<string, unknown>) =>
  typeof b.current_password === "string" &&
  b.current_password !== "" &&
  b.current_password !== "wrong"

function settle(id: number, result: ImapRequest["result"], error: string | null = null) {
  setTimeout(() => {
    const r = requests.get(id)
    if (!r) return
    requests.set(id, { ...r, status: error ? "failed" : "done", error_code: error, result })
    if (!error) imap.state.last_poll_at = new Date().toISOString()
  }, 1200)
}

export const repliesHandlers: RequestHandler[] = [
  http.get("/api/v1/abuse/imap", async () => {
    await delay(LATENCY_MS)
    if (demoState() === "shared")
      return HttpResponse.json({
        ...imap,
        host: "imap.example.com",
        username: "reports.example@example.com",
        trusted_authserv_id: null,
        shared_mailbox: true,
        state: {
          ...imap.state,
          last_error: "tls_failed",
          last_ok_at: iso(26 * HOUR),
          counters: {},
          authserv_hint: { id: "mx.example.com", seen: 9, of: 11 },
        },
      })
    return HttpResponse.json(imap)
  }),
  http.put("/api/v1/abuse/imap", async ({ request }) => {
    await delay(LATENCY_MS)
    const b = await body(request)
    if (!passwordOk(b)) return reauthFailed()
    if (demoState() === "password" && typeof b.password !== "string")
      return HttpResponse.json(
        { detail: "password required", code: "password_required" },
        { status: 422 },
      )
    Object.assign(imap, {
      enabled: Boolean(b.enabled),
      configured: true,
      host: str(b.host, ""),
      port: num(b.port, 993),
      security: b.security === "starttls" ? "starttls" : "ssl",
      username: str(b.username, ""),
      password_set: imap.password_set || typeof b.password === "string",
      folder: str(b.folder, "INBOX"),
      processed_action: b.processed_action === "move" ? "move" : "mark_read",
      move_folder: typeof b.move_folder === "string" ? b.move_folder : null,
      poll_minutes: num(b.poll_minutes, 15),
      since: typeof b.since === "string" ? b.since : null,
      trusted_authserv_id: typeof b.trusted_authserv_id === "string" ? b.trusted_authserv_id : null,
    })
    return HttpResponse.json(imap)
  }),
  http.delete("/api/v1/abuse/imap", async ({ request }) => {
    await delay(LATENCY_MS)
    if (!passwordOk(await body(request))) return reauthFailed()
    Object.assign(imap, {
      enabled: false,
      configured: false,
      host: "",
      username: "",
      password_set: false,
    })
    return new HttpResponse(null, { status: 204 })
  }),
  http.post("/api/v1/abuse/imap/test", async () => {
    await delay(LATENCY_MS)
    const id = ++requestId
    requests.set(id, {
      id,
      kind: "test",
      status: "pending",
      error_code: null,
      result: {},
      requested_at: new Date().toISOString(),
      done_at: null,
    })
    settle(id, {
      ok: true,
      messages: 14,
      move_supported: true,
      folders: ["INBOX", "Reports", "Archive"],
      authserv_hint: { id: "mx.example.net", seen: 12, of: 14 },
    })
    return HttpResponse.json({ id }, { status: 202 })
  }),
  http.post("/api/v1/abuse/imap/poll", async () => {
    await delay(LATENCY_MS)
    const id = ++requestId
    requests.set(id, {
      id,
      kind: "poll",
      status: "pending",
      error_code: null,
      result: {},
      requested_at: new Date().toISOString(),
      done_at: null,
    })
    settle(id, { ok: true, messages: 2, move_supported: true, folders: [] })
    return HttpResponse.json({ id }, { status: 202 })
  }),
  http.get("/api/v1/abuse/imap/requests/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const r = requests.get(Number(params.id))
    if (!r) return HttpResponse.json({ detail: "not found", code: "not_found" }, { status: 404 })
    return HttpResponse.json(r)
  }),

  http.get("/api/v1/abuse/replies", async ({ request }) => {
    await delay(LATENCY_MS)
    const p = new URL(request.url).searchParams
    let items = [...replies].sort((a, b) => b.received_at.localeCompare(a.received_at))
    const report = p.get("report")
    if (report) items = items.filter((r) => r.report === report)
    const cls = p.get("classification")
    if (cls) items = items.filter((r) => r.classification === cls)
    if (p.get("matched") === "false") items = items.filter((r) => r.report === null)
    if (p.get("matched") === "true") items = items.filter((r) => r.report !== null)
    if (p.get("needs_review") === "true") items = items.filter((r) => r.needs_review)
    return HttpResponse.json({ items, next_cursor: null })
  }),
  http.patch("/api/v1/abuse/replies/:id", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const r = replies.find((x) => x.id === Number(params.id))
    if (!r) return HttpResponse.json({ detail: "not found", code: "not_found" }, { status: 404 })
    const b = await body(request)
    if ("report" in b) {
      r.report = typeof b.report === "string" ? b.report : null
      r.match_method = r.report ? "manual" : "none"
    }
    if (typeof b.classification === "string") {
      r.classification = b.classification as ReplyClass
      r.classification_source = "manual"
    }
    if (typeof b.verified === "boolean") r.verified = b.verified
    if (b.trust_domain === true && !r.from_address)
      return HttpResponse.json({ detail: "no address", code: "no_address" }, { status: 422 })
    if (b.trust_domain === true) r.verified = true
    r.needs_review = !r.report || !r.verified
    return HttpResponse.json(r)
  }),
  http.post("/api/v1/abuse/replies/import", async ({ request }) => {
    await delay(LATENCY_MS)
    const b = await body(request)
    const raw = typeof b.raw === "string" ? b.raw : ""
    if (raw.length > 256 * 1024)
      return HttpResponse.json({ detail: "too large", code: "too_large" }, { status: 413 })
    if (!/^[A-Za-z-]+:/m.test(raw))
      return HttpResponse.json({ detail: "not a message", code: "not_a_message" }, { status: 422 })
    const id = ++importId
    replies.unshift({
      id: 100 + id,
      report: typeof b.report === "string" ? b.report : null,
      received_at: new Date().toISOString(),
      from_domain: "example.net",
      from_address: "abuse@example.net",
      classification: "human_reply",
      classification_source: "rule",
      source: "paste",
      sent_at: null,
      subject: "Re: Abuse report",
      auth: "none",
      rule_id: "person_signs",
      dsn_status: null,
      truncated: false,
      attachments: { count: 0, types: [], bytes: 0 },
      excerpt_purged: false,
      reviewed_at: null,
      reviewed_by: null,
      match_method: typeof b.report === "string" ? "manual" : "none",
      verified: typeof b.report === "string",
      needs_review: typeof b.report !== "string",
      ticket_id: null,
      excerpt: raw
        .replace(/^[A-Za-z-]+:.*\n/gm, "")
        .trim()
        .slice(0, 300),
    })
    return HttpResponse.json({ id }, { status: 202 })
  }),
  http.get("/api/v1/abuse/replies/imports/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    return HttpResponse.json({
      id: Number(params.id),
      status: "done",
      error_code: null,
      reply_id: 100 + Number(params.id),
    })
  }),

  http.put("/api/v1/abuse/reports/:id/outcome", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    if (id !== SENT && id !== CLOSED)
      return HttpResponse.json({ detail: "not sent", code: "not_sent" }, { status: 409 })
    const b = await body(request)
    manual.set(id, {
      outcome: b.outcome as Outcome,
      at: typeof b.at === "string" ? b.at : new Date().toISOString(),
      note: typeof b.note === "string" && b.note ? b.note : null,
    })
    return HttpResponse.json(outcomeFor(id, true))
  }),
  http.delete("/api/v1/abuse/reports/:id/outcome", async ({ params }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    manual.delete(id)
    return HttpResponse.json(outcomeFor(id, true))
  }),
]
