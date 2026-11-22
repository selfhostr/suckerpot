/**
 * Sending abuse reports (M25, docs/dev/design/m25.md): shapes of the send queue and the optional SMTP
 * profile, the plain-English sentences for every error code, and the calls. By default nothing is
 * sent: mail leaves only after the owner sets up SMTP and picks a sending mode. The sentences and
 * the `mailto:` builder are pure and tested.
 */
import { ApiError, getJson, sendJson } from "./api"
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
  { value: "off", label: "Off" },
  { value: "click", label: "Send on click" },
  { value: "auto", label: "Automatic" },
] as const

export const MODE_EXPLANATION: Record<SendMode, string> = {
  off: "Nothing is sent by SuckerPot. You copy each report or open it in your mail app from the To send queue.",
  click:
    "A Send now button appears on a ready report. Nothing leaves until you confirm for that report.",
  auto: "Ready reports are sent after a waiting time, with a Cancel button while they wait.",
}

export const AUTO_WARNING =
  "Reports that pass the identity check are sent without you reading them. Use it only when you trust your wording and your settings."

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
  auth_failed:
    "The mail server refused the username or password. Check them, or create a new SMTP token.",
  tls_failed:
    "The secure connection to the mail server could not be set up. Check the host, the port and the security setting.",
  refused: "The mail server refused the message or the recipient.",
  deferred:
    "The mail server asked to try later (often a limit on mails per minute or per hour). An automatic send is tried again by itself.",
  timeout: "The mail server did not answer in time.",
  egress_closed: "Waiting for the VPN: it is sent when the tunnel is back.",
  network: "The mail server could not be reached.",
  not_configured: "SMTP is not set up.",
  mode_off: "Sending was switched off before this went out.",
  mode_changed: "The sending mode changed before this went out.",
  too_old:
    "The activity is more than 7 days old: automatic sending skips it, because the provider can no longer check it. You can still send it by hand. It is scheduled again once the draft gets new activity.",
  shared_host:
    "The report names a shared service (a video site, a URL shortener, a file host) or an address on the never list. It is not sent: the service is not the attacker. It is scheduled again once the next build leaves that entry out.",
  form_only:
    "This desk only accepts its web form, so automatic sending skips it. Open the report to find the link and submit it by hand. Once you clear the flag, the draft is scheduled again.",
  undeliverable:
    "Mail to this address bounced for good, so automatic sending skips it. Type another address, or clear the flag if the address works again. The draft is then scheduled again.",
  not_ready: "The report was no longer ready to send.",
  internal: "Something went wrong inside SuckerPot. Try again.",
  unknown_outcome:
    "The server stopped answering mid-send: the mail may or may not have left. Check your sent folder before sending again.",
  xarf_invalid:
    "An X-ARF part did not pass the format check, so nothing was sent. This is a bug: please report it. It is tried again once the draft changes.",
  digest_migration:
    "Cancelled when daily digests came in. Its sources moved into the provider's new daily digest.",
}

/** A guard failure carries its codes after a colon: `guard_failed:no_self_address`. */
export function describeSendErrorCode(code: string | null | undefined): string {
  if (code?.startsWith("guard_failed")) {
    return code.includes("no_self_address")
      ? "Blocked by the identity check: confirm your own address in Settings → Reporting."
      : "Blocked by the identity check."
  }
  // A refusal carries the server's reply code after a colon: `refused:550`, `deferred:451`.
  const [base, reply] = (code ?? "").split(":", 2)
  const text = base ? SEND_ERROR[base] : undefined
  if (!text) return "The message could not be sent."
  return reply && /^[2-5][0-9][0-9]$/.test(reply) ? `${text} (server code ${reply})` : text
}

/** One sentence about the last request of a report, or null when there is nothing to say. */
export function describeRequest(r: SendRequest | null): string | null {
  if (!r) return null
  switch (r.status) {
    case "pending":
    case "sending":
      return r.error_code === "egress_closed" ? describeSendErrorCode("egress_closed") : "Sending…"
    case "sent":
      return r.done_at ? `Sent at ${formatClock(r.done_at)}.` : "Sent."
    case "failed":
      return `Not sent. ${describeSendErrorCode(r.error_code)}`
    case "cancelled":
      return "Cancelled. It will not be sent."
  }
}

/** Constant words for the 409 answers of the send, cancel and test routes. */
export const SEND_CONFLICT: Record<string, string> = {
  smtp_not_configured:
    "SMTP is not set up yet. Add the server details in Settings, under Reporting.",
  smtp_off: "Sending is switched off. Choose a sending mode in Settings, under Reporting.",
  revision_mismatch:
    "The report changed while you were reading it. It was reloaded: read it again, then retry.",
  demo_report: "This is a demo report. It can be reviewed but never sent.",
  report_not_ready:
    "This report is not ready: the identity check, the settings or the status block it.",
  already_queued: "This is already queued to be sent.",
  settings_incomplete: "Finish the Reporting settings first.",
  identity_guard_failed: "The identity check blocked this report.",
  evidence_invalid: "The stored evidence for this report is not valid.",
  nothing_to_cancel: "There is nothing to cancel: it was already sent or cancelled.",
  recipient_sent_today: "This provider already got a report today.",
  already_sending: "It is already being sent, so it cannot be cancelled.",
}

/** Codes of a 422 answer on the SMTP profile. */
export const SMTP_PROBLEM: Record<string, string> = {
  password_required: "Enter the SMTP password or token.",
  invalid_host: "The host must be a name such as smtp.example.net, not an address.",
  invalid_from_address: "The from address is not a valid mailbox.",
  invalid_from_name: "The from name is not valid.",
  invalid_credentials: "The username or password is not valid.",
  identity_guard_failed: "The sender name or address matches one of your own terms.",
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
    if (e.code === "reauth_failed") return "That password is not right."
    if (e.status === 503 && e.code === "editing_disabled")
      return "Encryption key missing on the server: set it in .env."
    const conflict = e.status === 409 && e.code ? SEND_CONFLICT[e.code] : undefined
    if (conflict) return conflict
    const problems = problemsOf(e)
      .map((c) => SMTP_PROBLEM[c])
      .filter((s): s is string => s !== undefined)
    if (problems.length > 0) return problems.join(" ")
    if (e.status === 422) return "Some of these settings are not valid."
    if (e.status === 404) return "That report no longer exists."
    if (e.status === 429) return "Too many requests. Wait a moment and try again."
    if (e.status === 403) return "Only an administrator can do this."
  }
  return "That did not work. Check the connection and try again."
}

/** The sentence over the queue. */
export function describeQueue(n: number): string {
  if (n === 0) return "Nothing is waiting to be sent."
  return n === 1 ? "1 report is ready to send." : `${n} reports are ready to send.`
}

/** Daily counter shown next to the cap. */
/** The hint under the waiting time and the daily limit. */
export const CAP_HINT =
  "The daily limit counts automatic sends only. A report over the limit waits until the next UTC day."

export function describeSentToday(
  c: Pick<SmtpConfig, "sent_today" | "daily_cap" | "mode">,
): string {
  return c.mode === "auto"
    ? `${c.sent_today} of ${c.daily_cap} sent today (UTC day).`
    : `${c.sent_today} sent today (UTC day).`
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
