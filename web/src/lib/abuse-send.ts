/**
 * Sending abuse reports (M25, docs/dev/design/m25.md): shapes of the send queue and the optional SMTP
 * profile, the plain-English sentences for every error code, and the calls. By default nothing is
 * sent: mail leaves only after the owner sets up SMTP and picks a sending mode. The sentences and
 * the `mailto:` builder are pure and tested.
 */
import { ApiError, getJson, sendJson } from "./api"
import { t, tk } from "@/i18n"
import { formatClock } from "./format"

// --- Shapes -----------------------------------------------------------------------

export type SendStatus = "pending" | "sending" | "sent" | "failed" | "cancelled"

/** On its way: waiting for the worker, or being sent right now (no Cancel in either case). */
export const inFlight = (s: SendStatus | null | undefined): boolean =>
  s === "pending" || s === "sending"

export interface SendRequest {
  status: SendStatus
  error_code: string | null
  requested_at?: string | null
  done_at: string | null
}

/** What the report page knows about sending (`send_state` of the report). */
export interface SendState {
  scheduled_at: string | null
  last_request: SendRequest | null
}

export interface QueueItem {
  /** The public id of the report. */
  id: string
  recipient: string
  subject: string
  body_text: string
  /** When the automatic mode will send it, or null. */
  scheduled_at: string | null
  last_request: SendRequest | null
}

export type SendMode = "off" | "click" | "auto"
export type SmtpSecurity = "starttls" | "ssl"

export interface SmtpTest {
  status: SendStatus
  error_code: string | null
  requested_at: string | null
  done_at: string | null
}

export interface SmtpConfig {
  configured: boolean
  password_set: boolean
  host: string
  port: number
  security: SmtpSecurity
  username: string
  from_address: string
  from_name: string
  mode: SendMode
  auto_hold_minutes: number
  daily_cap: number
  sent_today: number
  last_test: SmtpTest | null
  /** The digest hour (M38), minutes after 00:00 UTC; null before the first save. */
  digest_minute?: number | null
}

/** What the owner edits. The password is write-only: empty keeps the stored one. */
export interface SmtpForm {
  host: string
  port: number
  security: SmtpSecurity
  username: string
  from_address: string
  from_name: string
  mode: SendMode
  auto_hold_minutes: number
  daily_cap: number
  password: string
}

export const MODE_OPTIONS = [
  {
    value: "off",
    get label() {
      return t("common_off")
    },
  },
  {
    value: "click",
    get label() {
      return t("send_mode_click")
    },
  },
  {
    value: "auto",
    get label() {
      return t("send_mode_auto")
    },
  },
] as const

export const MODE_EXPLANATION: Record<SendMode, string> = {
  get off() {
    return t("send_mode_off_explanation")
  },
  get click() {
    return t("send_mode_click_explanation")
  },
  get auto() {
    return t("send_mode_auto_explanation")
  },
}

export const autoWarning = (): string => t("send_auto_warning")

export const HOLD_RANGE = { min: 10, max: 1440, fallback: 60 } as const
export const CAP_RANGE = { min: 1, max: 200, fallback: 20 } as const

/** The Proton preset: a paid plan with a custom domain. */
export const PROTON_PRESET = {
  host: "smtp.protonmail.ch",
  port: 587,
  security: "starttls",
} as const satisfies Pick<SmtpForm, "host" | "port" | "security">

// --- Sentences ---------------------------------------------------------------------

/** Why a send or a test failed, from the short code the worker records. */
export const SEND_ERROR: Record<string, string> = {
  auth_failed: tk("send_error_auth_failed"),
  tls_failed: tk("send_error_tls_failed"),
  refused: tk("send_error_refused"),
  deferred: tk("send_error_deferred"),
  timeout: tk("send_error_timeout"),
  egress_closed: tk("send_error_egress_closed"),
  network: tk("send_error_network"),
  not_configured: tk("send_error_not_configured"),
  mode_off: tk("send_error_mode_off"),
  mode_changed: tk("send_error_mode_changed"),
  too_old: tk("send_error_too_old"),
  shared_host: tk("send_error_shared_host"),
  form_only: tk("send_error_form_only"),
  undeliverable: tk("send_error_undeliverable"),
  not_ready: tk("send_error_not_ready"),
  internal: tk("send_error_internal"),
  unknown_outcome: tk("send_error_unknown_outcome"),
  xarf_invalid: tk("send_error_xarf_invalid"),
  digest_enabled: tk("send_error_digest_enabled"),
  digest_migration: tk("send_error_digest_migration"),
  superseded: tk("send_error_superseded"),
}

/** A guard failure carries its codes after a colon: `guard_failed:no_self_address`. */
export function describeSendErrorCode(code: string | null | undefined): string {
  if (code?.startsWith("guard_failed")) {
    return code.includes("no_self_address")
      ? t("send_error_guard_no_address")
      : t("send_error_guard")
  }
  // A refusal carries the server's reply code after a colon: `refused:550`, `deferred:451`.
  const [base, reply] = (code ?? "").split(":", 2)
  const key = base ? SEND_ERROR[base] : undefined
  if (!key) return t("send_error_unknown")
  return reply && /^[2-5][0-9][0-9]$/.test(reply)
    ? t("send_error_with_code", { text: t(key), code: reply })
    : t(key)
}

/** One sentence about the last request of a report, or null when there is nothing to say. */
export function describeRequest(r: SendRequest | null): string | null {
  if (!r) return null
  switch (r.status) {
    case "pending":
    case "sending":
      return r.error_code === "egress_closed"
        ? describeSendErrorCode("egress_closed")
        : t("send_request_sending")
    case "sent":
      return r.done_at
        ? t("send_request_sent_at", { time: formatClock(r.done_at) })
        : t("send_request_sent")
    case "failed":
      return t("send_request_failed", { reason: describeSendErrorCode(r.error_code) })
    case "cancelled":
      return t("send_request_cancelled")
  }
}

/** Constant words for the 409 answers of the send, cancel and test routes. */
const SEND_CONFLICT: Record<string, string> = {
  smtp_not_configured: tk("send_conflict_smtp_not_configured"),
  smtp_off: tk("send_conflict_smtp_off"),
  revision_mismatch: tk("send_conflict_revision_mismatch"),
  demo_report: tk("send_conflict_demo_report"),
  report_not_ready: tk("send_conflict_report_not_ready"),
  already_queued: tk("send_conflict_already_queued"),
  settings_incomplete: tk("send_conflict_settings_incomplete"),
  identity_guard_failed: tk("send_conflict_identity_guard_failed"),
  evidence_invalid: tk("send_conflict_evidence_invalid"),
  nothing_to_cancel: tk("send_conflict_nothing_to_cancel"),
  recipient_sent_today: tk("send_conflict_recipient_sent_today"),
  already_sending: tk("send_conflict_already_sending"),
}

/** Codes of a 422 answer on the SMTP profile. */
const SMTP_PROBLEM: Record<string, string> = {
  password_required: tk("send_smtp_problem_password_required"),
  invalid_host: tk("send_smtp_problem_invalid_host"),
  invalid_from_address: tk("send_smtp_problem_invalid_from_address"),
  invalid_from_name: tk("send_smtp_problem_invalid_from_name"),
  invalid_credentials: tk("send_smtp_problem_invalid_credentials"),
  identity_guard_failed: tk("send_smtp_problem_identity_guard_failed"),
}

/** The codes a 422 names: its own code plus any listed problems. */
export function problemsOf(e: unknown): string[] {
  if (!(e instanceof ApiError) || e.status !== 422) return []
  const p = e.body?.problems
  const listed = Array.isArray(p) ? p.filter((x): x is string => typeof x === "string") : []
  return [...new Set([...(e.code ? [e.code] : []), ...listed])]
}

/** A readable message for a failed send, cancel, SMTP save or test. */
export function describeSendError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return t("send_error_reauth_failed")
    if (e.status === 503 && e.code === "editing_disabled")
      return t("send_error_editing_disabled", { file: ".env" })
    const conflict = e.status === 409 && e.code ? SEND_CONFLICT[e.code] : undefined
    if (conflict) return t(conflict)
    const problems = problemsOf(e)
      .map((c) => SMTP_PROBLEM[c])
      .filter((s): s is string => s !== undefined)
    if (problems.length > 0) return problems.map((k) => t(k)).join(" ")
    if (e.status === 422) return t("send_error_invalid_settings")
    if (e.status === 404) return t("send_error_report_gone")
    if (e.status === 429) return t("abuse_error_too_many")
    if (e.status === 403) return t("abuse_error_admin_only")
  }
  return t("abuse_error_generic")
}

/** The sentence over the queue. */
export function describeQueue(n: number): string {
  if (n === 0) return t("send_queue_empty")
  return t("send_queue_count", { count: n })
}

/** The hint under the waiting time and the daily limit. */
export const capHint = (): string => t("send_cap_hint")

/** Daily counter shown next to the cap. */
export function describeSentToday(
  c: Pick<SmtpConfig, "sent_today" | "daily_cap" | "mode">,
): string {
  return c.mode === "auto"
    ? t("send_sent_today_of_cap", { sent: c.sent_today, cap: c.daily_cap })
    : t("send_sent_today", { sent: c.sent_today })
}

// --- mailto ------------------------------------------------------------------------

export const MAILTO_LIMIT = 1800

/**
 * A `mailto:` link with recipient and subject; the body joins only when the whole link stays under
 * the limit. Returns whether the body made it so the page can say what the clipboard is for.
 */
export function buildMailto(
  to: string,
  subject: string,
  body: string,
): { href: string; bodyIncluded: boolean } {
  const base = `mailto:${encodeURIComponent(to).replace(/%40/g, "@")}?subject=${encodeURIComponent(subject)}`
  const full = `${base}&body=${encodeURIComponent(body.replace(/\r?\n/g, "\r\n"))}`
  return full.length < MAILTO_LIMIT
    ? { href: full, bodyIncluded: true }
    : { href: base, bodyIncluded: false }
}

// --- Calls -------------------------------------------------------------------------

export interface QueuePage {
  items: QueueItem[]
  next_cursor: string | null
  mode: SendMode
  /** Reporting settings still missing, when the queue is empty because of them. */
  missing: string[]
}

export type QueueData = Pick<QueuePage, "items" | "mode" | "missing">

export const sendKeys = {
  queue: ["abuse", "send-queue"] as const,
  smtp: ["abuse", "smtp"] as const,
}

export const sendApi = {
  /** Every page of the queue: a page can hold fewer items than asked, so follow the cursor. */
  queue: async (): Promise<QueueData> => {
    const items: QueueItem[] = []
    let cursor: string | undefined
    let mode: SendMode = "off"
    let missing: string[] = []
    for (let page = 0; page < 40; page++) {
      const r = await getJson<QueuePage>("/abuse/send-queue", { limit: 25, cursor })
      items.push(...r.items)
      mode = r.mode
      missing = r.missing
      if (!r.next_cursor) break
      cursor = r.next_cursor
    }
    return { items, mode, missing }
  },
  send: (id: string, revision?: number, confirmSameDay = false) =>
    sendJson<{ id: number; status: SendStatus; scheduled_at: string | null }>(
      "POST",
      `/abuse/reports/${id}/send`,
      revision === undefined && !confirmSameDay
        ? undefined
        : {
            ...(revision === undefined ? {} : { revision }),
            ...(confirmSameDay ? { confirm_same_day: true } : {}),
          },
    ),
  cancel: (id: string) =>
    sendJson<{ cancelled: number }>("POST", `/abuse/reports/${id}/send/cancel`),
  smtp: () => getJson<SmtpConfig>("/abuse/smtp"),
  saveSmtp: (form: SmtpForm, currentPassword: string) => {
    const { password, ...rest } = form
    return sendJson<SmtpConfig>("PUT", "/abuse/smtp", {
      ...rest,
      ...(password ? { password } : {}),
      current_password: currentPassword,
    })
  },
  removeSmtp: (currentPassword: string) =>
    sendJson("DELETE", "/abuse/smtp", { current_password: currentPassword }),
  testSmtp: (currentPassword: string) =>
    sendJson("POST", "/abuse/smtp/test", { current_password: currentPassword }),
}

/** Refetch interval while something is on its way: a request pending or a send scheduled. */
export function queueRefetch(items: QueueItem[] | undefined): number | false {
  const busy = items?.some((i) => inFlight(i.last_request?.status) || i.scheduled_at)
  return busy ? 4000 : false
}
