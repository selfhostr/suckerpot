/**
 * Replies and outcomes of abuse reports (M26, docs/dev/design/m26.md section 11): shapes of the IMAP
 * profile, the replies and the outcome of a report, the plain-English labels and the calls.
 * Reply text is hostile input: it is shown as text only, never as HTML, and links stay inert.
 */
import { t, tk } from "@/i18n"
import { ApiError, getJson, sendJson, type Page } from "./api"

// --- Vocabulary -------------------------------------------------------------------

/** What a report led to. Precedence, highest first: resolved, rejected, ticket_opened, ... */
export type Outcome =
  | "none"
  | "unknown"
  | "bounce"
  | "auto_ack"
  | "human_reply"
  | "ticket_opened"
  | "rejected"
  | "resolved"

export const OUTCOME_LABEL: Record<Outcome, string> = {
  get none() {
    return t("outcome_label_none")
  },
  get unknown() {
    return t("outcome_label_unknown")
  },
  get bounce() {
    return t("outcome_label_bounce")
  },
  get auto_ack() {
    return t("outcome_label_auto_ack")
  },
  get human_reply() {
    return t("outcome_label_human_reply")
  },
  get ticket_opened() {
    return t("outcome_label_ticket_opened")
  },
  get rejected() {
    return t("outcome_label_rejected")
  },
  get resolved() {
    return t("outcome_label_resolved")
  },
}

/** Rejected and bounced read in the warning tone, never red. */
export const outcomeIsWarning = (o: Outcome): boolean => o === "rejected" || o === "bounce"

/** Outcomes the owner can set by hand. */
export const MANUAL_OUTCOMES = [
  "human_reply",
  "ticket_opened",
  "resolved",
  "rejected",
  "bounce",
  "auto_ack",
  "none",
] as const satisfies readonly Outcome[]

/** Days without any reply before a sent report counts as unanswered (ABUSE_NO_ANSWER_DAYS). */
export const NO_ANSWER_DAYS = 14

export type ReplyClass = Exclude<Outcome, "none">

export const REPLY_CLASS_LABEL: Record<ReplyClass, string> = {
  get unknown() {
    return t("outcome_class_unknown")
  },
  get bounce() {
    return t("outcome_class_bounce")
  },
  get auto_ack() {
    return t("outcome_class_auto_ack")
  },
  get human_reply() {
    return t("outcome_class_human_reply")
  },
  get ticket_opened() {
    return t("outcome_class_ticket_opened")
  },
  get rejected() {
    return t("outcome_class_rejected")
  },
  get resolved() {
    return t("outcome_class_resolved")
  },
}

/** How a reply was tied to its report; the API sends a short code. */
const MATCH_LABEL: Record<string, string> = {
  token: tk("replies_match_token"),
  xarf_id: tk("replies_match_xarf_id"),
  in_reply_to: tk("replies_match_in_reply_to"),
  references: tk("replies_match_references"),
  sender: tk("replies_match_sender"),
  manual: tk("replies_match_manual"),
}

export const matchLabel = (code: string): string | null =>
  code === "none" ? null : MATCH_LABEL[code] ? t(MATCH_LABEL[code]) : code.replaceAll("_", " ")

const RULE_LABEL: Record<string, string> = {
  "bounce-dsn": tk("replies_rule_bounce_dsn"),
  "bounce-daemon": tk("replies_rule_bounce_daemon"),
  "generic-ticket": tk("replies_rule_generic_ticket"),
  "ticket-opened": tk("replies_rule_ticket_opened"),
  "auto-ack": tk("replies_rule_auto_ack"),
  "resolved-action-taken": tk("replies_rule_resolved_action_taken"),
  "not-our-customer": tk("replies_rule_not_our_customer"),
  "insufficient-evidence": tk("replies_rule_insufficient_evidence"),
  "form-required": tk("replies_rule_form_required"),
}

/** A short human label for a rule id; an unknown id is spelled out, never shown raw. */
export function ruleLabel(id: string): string {
  const known = RULE_LABEL[id]
  if (known) return t(known)
  const words = id.replace(/[^A-Za-z0-9]+/g, " ").trim()
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : t("replies_rule_unknown")
}

// --- Shapes -----------------------------------------------------------------------

export interface Reply {
  id: number
  source: "imap" | "paste"
  received_at: string
  /** The Date header, as the sender wrote it. */
  sent_at: string | null
  from_domain: string | null
  /** Administrators only. */
  from_address: string | null
  subject: string | null
  /** Whether the sender's domain passed authentication. */
  auth: "pass" | "fail" | "none"
  /** Public id of the report it belongs to, or null while unmatched. */
  report: string | null
  match_method: string
  /** The reply carries the reply token or comes from a trusted domain of the recipient. */
  verified: boolean
  needs_review: boolean
  classification: ReplyClass
  classification_source: "rule" | "manual"
  /** Id of the rule that decided the class, if one did. */
  rule_id: string | null
  ticket_id: string | null
  dsn_status: string | null
  truncated: boolean
  attachments: { count: number; types: string[]; bytes: number }
  /** Administrators only. Plain text, shortened. */
  excerpt: string | null
  /** The text was deleted after its retention period. */
  excerpt_purged: boolean
  reviewed_at: string | null
  reviewed_by: string | null
}

/** The outcome of a sent or closed report; null for any other report. */
export interface ReportOutcome {
  effective: Outcome
  auto: Outcome
  manual: Outcome | null
  /** Nothing came back and the report is older than the no-answer delay. */
  no_answer: boolean
  needs_review: boolean
  reply_count: number
  first_reply_at: string | null
  first_human_at: string | null
  ticket_at: string | null
  resolved_at: string | null
  rejected_at: string | null
  bounced_at: string | null
  ticket_id: string | null
  /** Seconds from sending to the first answer. */
  first_reply_after_s: number | null
  manual_at: string | null
  manual_by: string | null
  note: string | null
}

export type ImapSecurity = "ssl" | "starttls"
export type ProcessedAction = "mark_read" | "move"

/** The provider name seen on the top-most Authentication-Results of recent mail. */
export interface AuthservHint {
  id: string
  /** Messages that carried it. */
  seen: number
  /** Messages read. */
  of: number
}

/** The rule of the "Mail provider name" field (the API checks the same one). */
export const AUTHSERV_RE = /^[A-Za-z0-9.-]{1,255}$/

/** A hint fit to show: a valid provider name with sane counts, else null. */
export function validHint(h: AuthservHint | null | undefined): AuthservHint | null {
  if (!h || typeof h.id !== "string" || !AUTHSERV_RE.test(h.id)) return null
  if (!Number.isInteger(h.seen) || !Number.isInteger(h.of) || h.seen < 1 || h.seen > h.of)
    return null
  return { id: h.id.toLowerCase(), seen: h.seen, of: h.of }
}

export interface ImapState {
  last_poll_at: string | null
  last_ok_at: string | null
  /** A constant code, never server text. */
  last_error: string | null
  move_supported: boolean | null
  counters: Record<string, number>
  /** Set by the poll while no provider name is saved. */
  authserv_hint?: AuthservHint | null
}

export type RequestState = "pending" | "done" | "failed"
export interface ImapRequest {
  id: number
  kind: "test" | "poll"
  status: RequestState
  error_code: string | null
  result: {
    ok?: boolean
    messages?: number
    move_supported?: boolean
    folders?: string[]
    authserv_hint?: AuthservHint | null
  }
  requested_at: string
  done_at: string | null
}

export interface ImapConfig {
  configured: boolean
  /** ABUSE_REPLIES_ENABLED on this server. */
  worker_enabled: boolean
  enabled: boolean
  password_set: boolean
  host: string
  port: number
  security: ImapSecurity
  username: string
  folder: string
  processed_action: ProcessedAction
  move_folder: string | null
  poll_minutes: number
  /** Date (YYYY-MM-DD): mail received earlier is ignored. */
  since: string | null
  /** The name the mail provider writes at the start of Authentication-Results. */
  trusted_authserv_id: string | null
  /** The mailbox looks free or shared: replies cannot be trusted by domain. */
  shared_mailbox: boolean
  state: ImapState
  last_test: ImapRequest | null
}

export interface ImapForm {
  enabled: boolean
  host: string
  port: number
  security: ImapSecurity
  username: string
  password: string
  folder: string
  processed_action: ProcessedAction
  move_folder: string
  poll_minutes: number
  since: string
  trusted_authserv_id: string
}

export const POLL_RANGE = { min: 5, max: 1440 } as const

/** Replies waiting for the owner, from `GET /abuse/status`. */
export interface RepliesStatus {
  enabled: boolean
  configured: boolean
  last_poll_at: string | null
  last_error: string | null
  unmatched: number
  needs_review: number
}

// --- Sentences --------------------------------------------------------------------

const IMAP_ERRORS: Record<string, string> = {
  auth_failed: tk("imap_error_auth_failed"),
  connect_failed: tk("imap_error_connect_failed"),
  tls_failed: tk("imap_error_tls_failed"),
  folder_missing: tk("imap_error_folder_missing"),
  move_unsupported: tk("imap_error_move_unsupported"),
  timeout: tk("imap_error_timeout"),
  quota: tk("imap_error_quota"),
  gate_closed: tk("imap_error_gate_closed"),
}

export function describeImapError(code: string | null): string | null {
  if (!code) return null
  return t(IMAP_ERRORS[code] ?? tk("imap_error_other"))
}

/** A readable message for a failed call. */
export function describeRepliesError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return t("replies_error_reauth_failed")
    if (e.code === "not_sent") return t("replies_error_not_sent")
    if (e.code === "password_required") return t("replies_error_password_required")
    if (e.code === "no_address") return t("replies_error_no_address")
    if (e.code === "replies_disabled")
      return t("replies_error_disabled", { setting: "ABUSE_REPLIES_ENABLED" })
    if (e.code === "imap_not_configured") return t("replies_error_not_configured")
    if (e.code === "already_queued" || e.code === "polling") return t("replies_error_polling")
    if (e.code === "rate_limited") return t("replies_error_rate_limited")
    if (e.code === "empty") return t("replies_error_empty")
    if (e.code === "bad_report") return t("replies_error_bad_report")
    if (e.code === "in_future") return t("replies_error_in_future")
    if (e.code === "before_sent") return t("replies_error_before_sent")
    if (e.code === "too_large") return t("replies_error_too_large", { size: "256 KiB" })
    if (e.code === "not_a_message") return t("replies_error_not_a_message")
    if (e.status === 429) return t("abuse_error_too_many")
    if (e.status === 403) return t("abuse_error_admin_only")
    if (e.status === 422 && e.message) return e.message
  }
  return t("abuse_error_generic")
}

// --- Calls ------------------------------------------------------------------------

export interface ReplyFilters {
  report?: string
  classification?: ReplyClass
  matched?: boolean
  needs_review?: boolean
}

export const repliesKeys = {
  imap: ["abuse", "imap"] as const,
  request: (id: number) => ["abuse", "imap", "request", id] as const,
  list: (f: ReplyFilters) => ["abuse", "replies", f] as const,
  importState: (id: number) => ["abuse", "replies", "import", id] as const,
}

export interface ImportState {
  id: number
  status: RequestState
  error_code: string | null
  reply_id: number | null
}

export const repliesApi = {
  imap: () => getJson<ImapConfig>("/abuse/imap"),
  saveImap: (form: ImapForm, currentPassword: string) => {
    const { password, move_folder, since, trusted_authserv_id, ...rest } = form
    return sendJson<ImapConfig>("PUT", "/abuse/imap", {
      ...rest,
      move_folder: move_folder || null,
      since: since || null,
      trusted_authserv_id: trusted_authserv_id.trim() || null,
      ...(password ? { password } : {}),
      current_password: currentPassword,
    })
  },
  removeImap: (currentPassword: string) =>
    sendJson("DELETE", "/abuse/imap", { current_password: currentPassword }),
  test: () => sendJson<{ id: number }>("POST", "/abuse/imap/test"),
  poll: () => sendJson<{ id: number }>("POST", "/abuse/imap/poll"),
  request: (id: number) => getJson<ImapRequest>(`/abuse/imap/requests/${id}`),
  replies: (f: ReplyFilters, cursor?: string | null) =>
    getJson<Page<Reply>>("/abuse/replies", {
      report: f.report,
      classification: f.classification,
      matched: f.matched === undefined ? undefined : String(f.matched),
      needs_review: f.needs_review === undefined ? undefined : String(f.needs_review),
      cursor: cursor ?? undefined,
      limit: 50,
    }),
  patch: (
    id: number,
    body: {
      report?: string | null
      classification?: ReplyClass
      ticket_id?: string | null
      verified?: boolean
      trust_domain?: boolean
    },
  ) => sendJson<Reply>("PATCH", `/abuse/replies/${id}`, body),
  importReply: (raw: string, report?: string) =>
    sendJson<{ id: number }>("POST", "/abuse/replies/import", { raw, report }),
  importState: (id: number) => getJson<ImportState>(`/abuse/replies/imports/${id}`),
  setOutcome: (report: string, body: { outcome: Outcome; at?: string; note?: string }) =>
    sendJson<ReportOutcome>("PUT", `/abuse/reports/${report}/outcome`, body),
  clearOutcome: (report: string) =>
    sendJson<ReportOutcome>("DELETE", `/abuse/reports/${report}/outcome`),
}
