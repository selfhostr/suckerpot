/**
 * MSW handlers for the M25 sending endpoints (docs/dev/design/m25.md): the send queue, the optional
 * SMTP profile and the send routes. Stateful for the page load. Hosts and mailboxes are on
 * example.* domains; no real address appears. The password "wrong" fails the re-authentication.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { QueueItem, SendRequest, SmtpConfig, SmtpForm, SmtpTest } from "@/lib/abuse-send"
import { outcomeFor, repliesFor } from "./replies"
import { find, missingSettings, pub, renderBody, rows, type Row } from "./abuse"

const LATENCY_MS = 140
const MINUTE = 60_000

const smtp: SmtpConfig = {
  configured: true,
  password_set: true,
  host: "smtp.example.net",
  port: 587,
  security: "starttls",
  username: "reports@example.org",
  from_address: "reports@example.org",
  from_name: "",
  mode: "click",
  auto_hold_minutes: 60,
  daily_cap: 20,
  sent_today: 3,
  last_test: {
    status: "sent",
    error_code: null,
    requested_at: new Date(Date.now() - 91 * MINUTE).toISOString(),
    done_at: new Date(Date.now() - 90 * MINUTE).toISOString(),
  },
}

const requests = new Map<string, SendRequest>()
const scheduled = new Map<string, number>()
let requestId = 100

/** The mock report whose send always fails, to show the error sentence. */
const FAILING = "9a8b7c6d-5e4f-4a3b-9c2d-5e6f7a8b9c05"

const ready = (r: Row): boolean =>
  (r.status === "draft" || r.status === "reviewed") &&
  r.guard.ok &&
  !r.demo &&
  Boolean(r.recipient.mailbox) &&
  missingSettings().length === 0

function items(): QueueItem[] {
  return rows.filter(ready).map((r) => {
    const m = renderBody(r, "text")
    if (
      smtp.mode === "auto" &&
      !scheduled.has(r.public_id) &&
      requests.get(r.public_id)?.status !== "cancelled"
    )
      scheduled.set(r.public_id, Date.now() + smtp.auto_hold_minutes * MINUTE)
    return {
      id: r.public_id,
      recipient: m.to,
      subject: m.subject,
      body_text: m.body,
      scheduled_at:
        smtp.mode === "auto" && scheduled.has(r.public_id)
          ? new Date(scheduled.get(r.public_id) ?? 0).toISOString()
          : null,
      last_request: requests.get(r.public_id) ?? null,
    }
  })
}

const reauthFailed = () =>
  HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })

async function password(request: Request): Promise<{ body: Record<string, unknown>; ok: boolean }> {
  const body = ((await request.json().catch(() => ({}))) ?? {}) as Record<string, unknown>
  const p = body.current_password
  return { body, ok: typeof p === "string" && p !== "" && p !== "wrong" }
}

function settle(id: string) {
  setTimeout(() => {
    const r = find(id)
    const req = requests.get(id)
    if (!r || req?.status !== "pending") return
    const done_at = new Date().toISOString()
    if (id === FAILING) {
      requests.set(id, { status: "failed", error_code: "refused", done_at })
      return
    }
    requests.set(id, { status: "sent", error_code: null, done_at })
    r.status = "sent"
    r.sent_at = done_at
    r.updated_at = done_at
    smtp.sent_today++
  }, 1500)
}

export const abuseSendHandlers: RequestHandler[] = [
  http.get("/api/v1/abuse/send-queue", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ items: items(), next_cursor: null, mode: smtp.mode, missing: [] })
  }),
  http.get("/api/v1/abuse/reports/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    const r = find(id)
    if (!r)
      return HttpResponse.json({ detail: "Report not found.", code: "not_found" }, { status: 404 })
    return HttpResponse.json({
      ...pub(r),
      outcome: outcomeFor(id, r.sent_at !== null),
      replies: repliesFor(id),
      reply_token: r.sent_at ? "a3f9c01b7d42" : null,
      send_state: {
        scheduled_at:
          smtp.mode === "auto" && scheduled.has(id)
            ? new Date(scheduled.get(id) ?? 0).toISOString()
            : null,
        last_request: requests.get(id) ?? null,
      },
    })
  }),
  http.post("/api/v1/abuse/reports/:id/send", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const sent = (await request.json().catch(() => ({}))) as { revision?: number } | null
    const id = String(params.id)
    const r = find(id)
    const conflict = (code: string) => HttpResponse.json({ detail: code, code }, { status: 409 })
    if (!r)
      return HttpResponse.json({ detail: "Report not found.", code: "not_found" }, { status: 404 })
    if (!smtp.configured) return conflict("smtp_not_configured")
    if (smtp.mode === "off") return conflict("smtp_off")
    if (sent?.revision !== undefined && sent.revision !== r.revision)
      return conflict("revision_mismatch")
    if (r.demo) return conflict("demo_report")
    if (!ready(r)) return conflict("report_not_ready")
    if (requests.get(id)?.status === "pending") return conflict("already_queued")
    requests.set(id, { status: "pending", error_code: null, done_at: null })
    scheduled.delete(id)
    settle(id)
    return HttpResponse.json(
      { id: ++requestId, status: "pending", scheduled_at: null },
      { status: 202 },
    )
  }),
  http.post("/api/v1/abuse/reports/:id/send/cancel", async ({ params }) => {
    await delay(LATENCY_MS)
    const id = String(params.id)
    scheduled.delete(id)
    requests.set(id, { status: "cancelled", error_code: null, done_at: new Date().toISOString() })
    return HttpResponse.json({ cancelled: 1 })
  }),
  http.get("/api/v1/abuse/smtp", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(smtp)
  }),
  http.put("/api/v1/abuse/smtp", async ({ request }) => {
    await delay(LATENCY_MS)
    const { body, ok } = await password(request)
    if (!ok) return reauthFailed()
    const b = body as unknown as Partial<SmtpForm>
    const problems: string[] = []
    if ((b.from_address ?? "").endsWith("@owner.example"))
      return HttpResponse.json(
        { detail: "blocked", code: "identity_guard_failed", reasons: ["owner_domain"] },
        { status: 422 },
      )
    if (!b.host || /^[\d.]+$/.test(b.host) || !b.host.includes(".")) problems.push("invalid_host")
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(b.from_address ?? ""))
      problems.push("invalid_from_address")
    if (!smtp.password_set && !b.password) problems.push("password_required")
    if (problems.length > 0)
      return HttpResponse.json({ detail: "invalid", code: problems[0], problems }, { status: 422 })
    Object.assign(smtp, {
      configured: true,
      password_set: true,
      host: b.host,
      port: b.port,
      security: b.security,
      username: b.username ?? "",
      from_address: b.from_address,
      from_name: b.from_name ?? "",
      mode: b.mode ?? "off",
      auto_hold_minutes: b.auto_hold_minutes ?? 60,
      daily_cap: b.daily_cap ?? 20,
    })
    scheduled.clear()
    return HttpResponse.json(smtp)
  }),
  http.delete("/api/v1/abuse/smtp", async ({ request }) => {
    await delay(LATENCY_MS)
    const { ok } = await password(request)
    if (!ok) return reauthFailed()
    Object.assign(smtp, {
      configured: false,
      password_set: false,
      host: "",
      port: 587,
      security: "starttls",
      username: "",
      from_address: "",
      from_name: "",
      mode: "off",
      last_test: null,
    })
    scheduled.clear()
    return new HttpResponse(null, { status: 204 })
  }),
  http.post("/api/v1/abuse/smtp/test", async ({ request }) => {
    await delay(LATENCY_MS)
    const { ok } = await password(request)
    if (!ok) return reauthFailed()
    if (!smtp.configured)
      return HttpResponse.json({ detail: "x", code: "smtp_not_configured" }, { status: 409 })
    const now = new Date().toISOString()
    const test: SmtpTest = { status: "sent", error_code: null, requested_at: now, done_at: now }
    smtp.last_test = test
    return HttpResponse.json(
      { id: ++requestId, status: "pending", scheduled_at: null },
      { status: 202 },
    )
  }),
]
