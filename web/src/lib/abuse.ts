/**
 * Abuse reports (M22): shapes of `/api/v1/abuse/*` (docs/dev/design/m22.md section 9.1 is the
 * contract), the plain-English sentences of the pages, and the calls. Nothing here sends mail:
 * the owner copies the draft into his own webmail. The sentences are pure and tested.
 */
import { ApiError, getBlob, getJson, sendJson, type Page } from "./api"
import { intlLocale, t, tk } from "@/i18n"
import type { Outcome, RepliesStatus, Reply, ReportOutcome } from "./replies"

// --- Vocabulary -------------------------------------------------------------------

export type ReportKind = "attack_source" | "payload_host" | "c2"
/** A report holds one kind of source, or every kind for one provider (a daily digest, M38). */
export type ReportItemKind = ReportKind | "digest"
export const KIND_LABEL: Record<ReportKind, string> = {
  get attack_source() {
    return t("abuse_kind_attack_source")
  },
  get payload_host() {
    return t("abuse_kind_payload_host")
  },
  get c2() {
    return t("abuse_kind_c2")
  },
}
/** The order and headings of the sections of a digest. */
export const KINDS: readonly ReportKind[] = ["attack_source", "payload_host", "c2"]
export const KIND_HEADING: Record<ReportKind, string> = {
  get attack_source() {
    return t("abuse_kind_heading_attack_source")
  },
  get payload_host() {
    return t("abuse_kind_heading_payload_host")
  },
  get c2() {
    return t("abuse_kind_heading_c2")
  },
}
/** "3 attack sources", "1 payload host": the count and the noun of one kind. */
function kindCount(kind: ReportKind, n: number): string {
  switch (kind) {
    case "attack_source":
      return t("abuse_kind_count_attack_source", { count: n })
    case "payload_host":
      return t("abuse_kind_count_payload_host", { count: n })
    case "c2":
      return t("abuse_kind_count_c2", { count: n })
  }
}

/**
 * A label in the middle of a sentence: lower case, except in German where nouns keep their capital
 * ("Entwurf", not "entwurf").
 */
export function lowerNoun(label: string): string {
  const locale = intlLocale()
  return locale.startsWith("de") ? label : label.toLocaleLowerCase(locale)
}

/** "Digest" for a daily digest, else the kind of its sources. */
export function kindLabel(kind: ReportItemKind): string {
  return kind === "digest" ? t("abuse_kind_digest") : KIND_LABEL[kind]
}

/** "12 sources (9 attack sources, 3 payload hosts)", or the plain count of an older report. */
export function describeSources(r: Pick<ReportItem, "kind" | "subject_count" | "kinds">): string {
  const kinds = r.kinds ?? {}
  const parts = KINDS.filter((k) => (kinds[k] ?? 0) > 0).map((k) => kindCount(k, kinds[k] ?? 0))
  const total = parts.length > 0 ? KINDS.reduce((n, k) => n + (kinds[k] ?? 0), 0) : r.subject_count
  if (r.kind !== "digest") return kindCount(r.kind, total)
  const head = t("abuse_sources_count", { count: total })
  return parts.length > 0 ? t("abuse_sources_with_kinds", { head, kinds: parts.join(", ") }) : head
}

/**
 * When a digest goes, in local time: "goes at 07:42" today, "goes tomorrow at 07:42", or "waiting
 * for tomorrow" further out. Null when it is not waiting (no due time, or not draft or reviewed).
 */
export function describeDue(
  r: Pick<ReportItem, "due_at" | "status">,
  now: Date = new Date(),
): string | null {
  if (!r.due_at || (r.status !== "draft" && r.status !== "reviewed")) return null
  const due = new Date(r.due_at)
  if (Number.isNaN(due.getTime())) return null
  const clock = `${String(due.getHours()).padStart(2, "0")}:${String(due.getMinutes()).padStart(2, "0")}`
  const day = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
  const days = Math.round((day(due) - day(now)) / 86_400_000)
  if (days <= 0)
    return due.getTime() <= now.getTime() ? t("abuse_due_soon") : t("abuse_due_at", { clock })
  if (days === 1) return t("abuse_due_tomorrow", { clock })
  return t("abuse_due_later")
}

export type ReportStatus = "draft" | "reviewed" | "sent" | "closed" | "discarded" | "superseded"
/** The tabs of the list, in workflow order. `superseded` is never shown. */
export const LIST_STATUSES = ["draft", "reviewed", "sent", "closed", "discarded"] as const
export type ListStatus = (typeof LIST_STATUSES)[number]
export const STATUS_LABEL: Record<ReportStatus, string> = {
  get draft() {
    return t("abuse_status_draft")
  },
  get reviewed() {
    return t("abuse_status_reviewed")
  },
  get sent() {
    return t("abuse_status_sent")
  },
  get closed() {
    return t("abuse_status_closed")
  },
  get discarded() {
    return t("abuse_status_discarded")
  },
  get superseded() {
    return t("abuse_status_superseded")
  },
}
export const TAB_LABEL: Record<ListStatus, string> = {
  get draft() {
    return t("abuse_tab_draft")
  },
  get reviewed() {
    return t("abuse_tab_reviewed")
  },
  get sent() {
    return t("abuse_tab_sent")
  },
  get closed() {
    return t("abuse_tab_closed")
  },
  get discarded() {
    return t("abuse_tab_discarded")
  },
}
/** The four steps of the stepper (discarded and replaced are side exits). */
export const STEPS = ["draft", "reviewed", "sent", "closed"] as const

export type MessageFormat = "text" | "xarf" | "eml"
export const FORMAT_OPTIONS = [
  {
    value: "text",
    get label() {
      return t("abuse_format_text")
    },
  },
  { value: "xarf", label: "X-ARF" },
  { value: "eml", label: ".eml" },
] as const

export type Tlp = "clear" | "green" | "amber" | "red"
export const TLP_OPTIONS = [
  { value: "green", label: "TLP:GREEN" },
  { value: "amber", label: "TLP:AMBER" },
  { value: "clear", label: "TLP:CLEAR" },
] as const
export const DEFAULT_TLP: Tlp = "green"

export type ReferenceStyle = "subject" | "subject_and_body" | "off"
export const REFERENCE_STYLE_OPTIONS = [
  {
    value: "subject",
    get label() {
      return t("abuse_reference_subject")
    },
  },
  {
    value: "subject_and_body",
    get label() {
      return t("abuse_reference_subject_and_body")
    },
  },
  {
    value: "off",
    get label() {
      return t("common_off")
    },
  },
] as const satisfies readonly { value: ReferenceStyle; label: string }[]

/** Reason codes of the identity check. They never carry the matched value. */
const GUARD_REASON: Record<string, string> = {
  self_address: tk("abuse_guard_reason_self_address"),
  self_name: tk("abuse_guard_reason_self_name"),
  owner_domain: tk("abuse_guard_reason_owner_domain"),
  vpn_address: tk("abuse_guard_reason_vpn_address"),
  project_term: tk("abuse_guard_reason_project_term"),
  private_address: tk("abuse_guard_reason_private_address"),
  documentation_address: tk("abuse_guard_reason_documentation_address"),
  dashboard_path: tk("abuse_guard_reason_dashboard_path"),
  internal_id: tk("abuse_guard_reason_internal_id"),
  default_wording: tk("abuse_guard_reason_default_wording"),
  no_self_address: tk("abuse_guard_reason_no_self_address"),
  self_terms_unavailable: tk("abuse_guard_reason_self_terms_unavailable"),
  settings_incomplete: tk("abuse_guard_reason_settings_incomplete"),
  evidence_invalid: tk("abuse_guard_reason_evidence_invalid"),
  eml_invalid_recipient: tk("abuse_guard_reason_eml_invalid_recipient"),
  bad_reply_token: tk("abuse_guard_reason_bad_reply_token"),
}

export function guardReason(code: string): string {
  return t(GUARD_REASON[code] ?? tk("abuse_guard_reason_other"))
}

/**
 * What to do about each reason, in plain English. A blocked draft is re-checked on its own about
 * a minute after the settings are saved, so the settings advice never says "regenerate".
 */
const GUARD_FIX: Record<string, string> = {
  project_term: tk("abuse_guard_fix_project_term"),
  self_name: tk("abuse_guard_fix_self_name"),
  owner_domain: tk("abuse_guard_fix_owner_domain"),
  self_address: tk("abuse_guard_fix_self_address"),
  vpn_address: tk("abuse_guard_fix_vpn_address"),
  private_address: tk("abuse_guard_fix_private_address"),
  documentation_address: tk("abuse_guard_fix_documentation_address"),
  dashboard_path: tk("abuse_guard_fix_dashboard_path"),
  internal_id: tk("abuse_guard_fix_internal_id"),
  default_wording: tk("abuse_guard_fix_default_wording"),
  no_self_address: tk("abuse_guard_fix_no_self_address"),
  self_terms_unavailable: tk("abuse_guard_fix_self_terms_unavailable"),
  settings_incomplete: tk("abuse_guard_fix_settings_incomplete"),
  evidence_invalid: tk("abuse_guard_fix_evidence_invalid"),
  eml_invalid_recipient: tk("abuse_guard_fix_eml_invalid_recipient"),
  bad_reply_token: tk("abuse_guard_fix_bad_reply_token"),
}

/** A few words for one draft row: why it is held back. */
const GUARD_SHORT: Record<string, string> = {
  self_address: tk("abuse_guard_short_self_address"),
  self_name: tk("abuse_guard_short_self_name"),
  owner_domain: tk("abuse_guard_short_owner_domain"),
  vpn_address: tk("abuse_guard_short_vpn_address"),
  project_term: tk("abuse_guard_short_project_term"),
  private_address: tk("abuse_guard_short_private_address"),
  documentation_address: tk("abuse_guard_short_documentation_address"),
  dashboard_path: tk("abuse_guard_short_dashboard_path"),
  internal_id: tk("abuse_guard_short_internal_id"),
  default_wording: tk("abuse_guard_short_default_wording"),
  no_self_address: tk("abuse_guard_short_no_self_address"),
  self_terms_unavailable: tk("abuse_guard_short_self_terms_unavailable"),
  settings_incomplete: tk("abuse_guard_short_settings_incomplete"),
  evidence_invalid: tk("abuse_guard_short_evidence_invalid"),
  eml_invalid_recipient: tk("abuse_guard_short_eml_invalid_recipient"),
  bad_reply_token: tk("abuse_guard_short_bad_reply_token"),
}

/** One reason as two sentences: what was found, and what to do about it. */
export function guardAdvice(code: string): { why: string; fix: string } {
  return {
    why: guardReason(code),
    fix: t(GUARD_FIX[code] ?? tk("abuse_guard_fix_other")),
  }
}

/** "Why: names the project, uses old default wording" for a blocked row, or null. */
export function describeBlockedRow(guard: GuardResult): string | null {
  if (guard.ok) return null
  const words = guard.codes.map((c) => t(GUARD_SHORT[c] ?? tk("abuse_guard_short_other")))
  if (words.length === 0) return t("abuse_blocked_row_none")
  return t("abuse_blocked_row", {
    shown: words.slice(0, 2).join(", "),
    more: Math.max(0, words.length - 2),
  })
}

/**
 * The sentence above the blocked drafts: how many, why, and that nothing leaves while they are
 * blocked. Reasons are sorted by how many drafts they hold back.
 */
export function describeBlockedDrafts(blocked: BlockedDrafts): string {
  const n = blocked.count
  return t("abuse_blocked_drafts", { count: n })
}

/** The reasons of the blocked drafts, most common first, each with its fix. */
export function blockedReasons(
  blocked: BlockedDrafts,
): { code: string; drafts: number; why: string; fix: string }[] {
  return Object.entries(blocked.reasons)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([code, drafts]) => ({ code, drafts, ...guardAdvice(code) }))
}

// --- The settings texts ------------------------------------------------------------

/** How a sentence about one setting names it. */
const SETTINGS_SUBJECT: Record<string, string> = {
  reply_contact: tk("abuse_settings_subject_reply_contact"),
  signature: tk("abuse_settings_subject_signature"),
  intro: tk("abuse_settings_subject_intro"),
  outro: tk("abuse_settings_subject_outro"),
  note: tk("abuse_settings_subject_note"),
  subject_template: tk("abuse_settings_subject_subject_template"),
  xarf_user_agent: tk("abuse_settings_subject_xarf_user_agent"),
  xarf_org: tk("abuse_settings_subject_xarf_org"),
  form_name: tk("abuse_settings_subject_form_name"),
}

/** What a reason means for a text that ends up in every report. */
const SETTINGS_CONSEQUENCE: Record<string, string> = {
  project_term: tk("abuse_settings_issue_project_term"),
  self_name: tk("abuse_settings_issue_self_name"),
  owner_domain: tk("abuse_settings_issue_owner_domain"),
  self_address: tk("abuse_settings_issue_self_address"),
  vpn_address: tk("abuse_settings_issue_vpn_address"),
  private_address: tk("abuse_settings_issue_private_address"),
  documentation_address: tk("abuse_settings_issue_documentation_address"),
  dashboard_path: tk("abuse_settings_issue_dashboard_path"),
  internal_id: tk("abuse_settings_issue_internal_id"),
  default_wording: tk("abuse_settings_issue_default_wording"),
  self_terms_unavailable: tk("abuse_settings_issue_self_terms_unavailable"),
}

/**
 * One sentence per field: what is wrong with this text and what to do. It says what blocks every
 * report, never the matched text (the server sends reason codes only).
 */
export function describeSettingsIssue(field: string, codes: string[]): string {
  const subject = t(SETTINGS_SUBJECT[field] ?? tk("abuse_settings_subject_other"))
  const parts = codes.map((c, i) =>
    t(SETTINGS_CONSEQUENCE[c] ?? tk("abuse_settings_issue_other"), {
      first: i === 0 ? "yes" : "no",
      subject,
    }),
  )
  const fix =
    field === "reply_contact" ? t("abuse_settings_fix_address") : t("abuse_settings_fix_text")
  return `${parts.join(" ")} ${fix}`
}

/** Field name to reason codes of a 409 `identity_guard_failed` answer to a settings save, or null. */
export function settingsIssuesOf(e: unknown): Record<string, string[]> | null {
  if (!(e instanceof ApiError) || e.code !== "identity_guard_failed") return null
  const raw = e.body?.fields
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null
  const out: Record<string, string[]> = {}
  for (const [field, codes] of Object.entries(raw)) {
    if (Array.isArray(codes)) out[field] = codes.filter((c): c is string => typeof c === "string")
  }
  return Object.keys(out).length > 0 ? out : null
}

export interface SendRequestShape {
  status: "pending" | "sending" | "sent" | "failed" | "cancelled"
  error_code: string | null
  requested_at?: string | null
  done_at: string | null
}

// --- Shapes -----------------------------------------------------------------------

export interface Recipient {
  id: number
  name: string
  /** The mailbox the report goes to; null while no contact was found. */
  mailbox: string | null
  source: "rdap" | "manual"
  muted: boolean
  /** A free or shared mailbox: replies are trusted by exact address only. */
  shared_mailbox?: boolean
  /** Replies said this desk takes reports only through its web form (automatic sending skips it). */
  form_only?: boolean
  /** The form link found in the reply (https only), when there was one. */
  form_url?: string | null
  /** Mail to this address bounced for good (automatic sending skips it). */
  undeliverable?: boolean
  /** One spec-shaped X-ARF mail per source instead of a daily digest (M38). */
  xarf_strict?: boolean
  /** Where form_only came from (M38): a reply, the shared directory, the owner; or cleared. */
  form_source?: "reply" | "directory" | "manual" | "cleared" | null
  /**
   * The server's verdict on the reply's form link: https on the provider's own domain, with no
   * port and no query string. Only then is it a link, or suggested in full for the directory.
   */
  form_url_clickable?: boolean
  /**
   * A reply said the desk reads mail but suggests its web form: a hint only, mail keeps going.
   * form_url is then the optional form link.
   */
  form_preferred?: boolean
}

/** The form link is shown only when it is a plain https URL (the server checks it too). */
export function safeFormUrl(url: string | null | undefined): string | null {
  if (!url?.startsWith("https://")) return null
  try {
    return new URL(url).protocol === "https:" ? url : null
  } catch {
    return null
  }
}

export interface AsnRef {
  asn: number
  name: string | null
}

export interface GuardResult {
  ok: boolean
  /** Constant codes only, never the matched text. */
  codes: string[]
}

export interface ReportItem {
  public_id: string
  kind: ReportItemKind
  status: ReportStatus
  demo: boolean
  recipient: Recipient
  asns: AsnRef[]
  subject_count: number
  window_start: string
  window_end: string
  updated_at: string
  revision: number
  guard: GuardResult
  /** Sent and closed reports only (M26). */
  outcome?: ReportOutcome | null
  /** When a daily digest is due (M38); null when it goes after the waiting time, or by hand. */
  due_at?: string | null
  /** Its part number that day (a provider with more than 100 sources gets up to 3). */
  part?: number
  channel?: string
  /** How many sources of each kind it holds. */
  kinds?: Partial<Record<ReportKind, number>>
  /** A form report (M38): the Monday of its ISO week. */
  week?: string | null
}

export interface ReportSubject {
  subject_type: "ip" | "url" | "domain"
  value: string
  asn: number | null
  network: string | null
  handle: string | null
  sessions: number
  events: number
  first_ts: string
  last_ts: string
  /** The internal dashboard view of this subject. Used by the UI only, never in the text. */
  link: string
  /** The kind of this source (a digest holds every kind). */
  kind?: ReportKind
  /** The name of its X-ARF JSON in the mail, such as xarf-003.json. */
  xarf_file?: string | null
  /** Its X-ARF report id. Administrators only. */
  xarf_id?: string | null
  /** The best verified reply that names this source. */
  outcome?: Exclude<Outcome, "none" | "bounce"> | null
  ticket_id?: string | null
  /** Older than 7 days: only a send started by hand carries it. */
  stale?: boolean
}

export interface HistoryEntry {
  ts: string
  actor: string
  from: ReportStatus | null
  to: ReportStatus
}

export interface ReportOptions {
  defang: boolean
  time_precision: "second" | "minute"
  include_usernames: boolean
  include_reply_contact: boolean
  /** The counter line "N values masked, M lines left out". Off unless asked for. */
  show_redaction_counts: boolean
}

export interface ReportDetail extends ReportItem {
  subjects: ReportSubject[]
  /** Counters only: how many values were masked and how many lines left out. */
  redaction: { masked: number; removed: number }
  options: ReportOptions
  notes: string | null
  history: HistoryEntry[]
  /** Required settings still empty (only the reply contact). Review needs none. */
  missing: string[]
  /** When the same subjects were reported before, if so. */
  previously_reported: string | null
  reviewed_at: string | null
  sent_at: string | null
  closed_at: string | null
  /** Optional sending (M25): the planned time and the last request, when sending is set up. */
  send_state?: { scheduled_at: string | null; last_request: SendRequestShape | null }
  /** Latest replies of a sent report (M26); text fields are for administrators only. */
  replies?: Reply[]
  /** The token that ties replies to this report. Administrators only. */
  reply_token?: string | null
}

export interface Attachment {
  name: string
  media_type: string
  content: string
}

export interface RenderedMessage {
  to: string
  subject: string
  body: string
  attachments: Attachment[]
  revision: number
  guard: GuardResult
}

export interface AbuseStatus {
  enabled: boolean
  gate: "open" | "closed"
  rdap_quota: { used: number; limit: number }
  self_address_known: boolean
  /** False when the learned address is stale: reports stay blocked until a fresh one is known. */
  self_address_fresh: boolean
  counts: Record<ReportStatus, number>
  waiting_for_contact: number
  /** The replies mailbox (M26). */
  replies?: RepliesStatus
  /** Open drafts held back by the identity check, and how many carry each reason. */
  blocked_drafts?: BlockedDrafts
}

export interface BlockedDrafts {
  count: number
  reasons: Record<string, number>
}

export interface WaitingRecipient {
  id: number
  name: string
  asns: AsnRef[]
  subject_count: number
}

export interface ReportSettings {
  reply_contact: string | null
  signature: string | null
  /** Optional: empty means the part is left out of the report. */
  intro: string | null
  outro: string | null
  xarf_user_agent: string | null
  /** Optional. The organisation in X-ARF reports; empty uses the domain of the reply contact. */
  xarf_org?: string | null
  /** One mail per provider per day (M38). Edited in the Sending card. */
  digest_enabled?: boolean
  /** Optional. "Your name" in the copy kit of web forms (M38); empty by default. */
  form_name?: string | null
  /** Optional. A sentence about the withheld destination and the source ports, if wanted. */
  note: string | null
  /** Optional. Empty uses the plain subject "Abuse report for {value}". */
  subject_template: string | null
  /** Round times to the minute (the default). Off sends exact times. */
  round_times: boolean
  default_options: Pick<
    ReportOptions,
    "defang" | "include_usernames" | "include_reply_contact" | "show_redaction_counts"
  >
  default_tlp: Tlp
  /** Where the reply reference is printed. */
  reference_style: ReferenceStyle
  revision: number
  /**
   * Answer only: the saved texts that would block every report today, by field name, as reason
   * codes. Never sent back.
   */
  field_issues?: Record<string, string[]>
}

export interface SelfTerm {
  id: number
  kind: "address" | "cidr" | "name" | "text"
  /** Masked unless revealed. */
  value: string
  source: "learned" | "manual" | "sensor"
  confirmed: boolean
  distinct_sources: number
}

export interface ReportFilters {
  status?: ListStatus
  kind?: ReportItemKind
  recipient?: number
}

// --- Sentences ---------------------------------------------------------------------

/**
 * The sentence above the list. It counts what the tabs count: drafts, reports ready to send (the
 * To send queue) and replies to check.
 */
export function describeReports(
  status: AbuseStatus | undefined,
  extra: { toSend?: number; replies?: number } = {},
): string {
  if (!status) return t("abuse_reports_intro")
  if (!status.enabled) return t("abuse_reports_off")
  const drafts = status.counts.draft
  const toSend = extra.toSend ?? status.counts.reviewed
  const replies = extra.replies ?? 0
  if (drafts === 0 && toSend === 0 && replies === 0) return t("abuse_reports_nothing")
  const parts: string[] = []
  if (drafts > 0) parts.push(t("abuse_reports_drafts_to_review", { count: drafts }))
  if (toSend > 0) parts.push(t("abuse_reports_ready_to_send", { count: toSend }))
  if (replies > 0) parts.push(t("abuse_reports_replies_to_check", { count: replies }))
  return t("abuse_reports_summary", { parts: parts.join(", ") })
}

/** Why the list cannot be used yet, or null. The message is one sentence. */
export function blockedReason(status: AbuseStatus | undefined): string | null {
  if (!status) return null
  if (!status.enabled)
    return t("abuse_blocked_worker_off", { setting: "ABUSE_REPORTS_ENABLED=true", file: ".env" })
  if (!status.self_address_known)
    return t("abuse_blocked_address_unknown")
  if (!status.self_address_fresh)
    return t("abuse_blocked_address_stale")
  if (status.gate === "closed")
    return t("abuse_blocked_gate_closed")
  return null
}

/** "3 addresses in 2 networks" for the first line of a report page. */
export function describeReport(r: ReportItem): string {
  const nets = new Set(r.asns.map((a) => a.asn)).size
  const name = r.recipient.name
  const stop = name.endsWith(".") ? "" : "."
  if (r.kind === "digest")
    return t("abuse_report_line_digest", { sources: describeSources(r), nets, name, stop })
  const n = r.subject_count
  const values = { count: n, nets, name, stop }
  if (r.kind === "attack_source") return t("abuse_report_line_attack_source", values)
  if (r.kind === "payload_host") return t("abuse_report_line_payload_host", values)
  return t("abuse_report_line_c2", values)
}

/** The finding of the identity check card. */
export function describeGuard(guard: GuardResult, redaction: { masked: number; removed: number }) {
  if (!guard.ok) return t("abuse_guard_blocked")
  if (redaction.masked > 0 && redaction.removed > 0)
    return t("abuse_guard_clean_both", { masked: redaction.masked, removed: redaction.removed })
  if (redaction.masked > 0) return t("abuse_guard_clean_masked", { masked: redaction.masked })
  if (redaction.removed > 0) return t("abuse_guard_clean_removed", { removed: redaction.removed })
  return t("abuse_guard_clean")
}

/** What the next step needs, or null when nothing blocks it. */
export function reviewBlocker(r: ReportDetail): string | null {
  if (!r.guard.ok) return t("abuse_review_blocker_guard")
  if (!r.recipient.mailbox) return t("abuse_no_mailbox")
  if (r.missing.length > 0) return t("abuse_review_blocker_contact")
  return null
}

/** Allowed next statuses from the current one, per the workflow. */
export function nextActions(
  status: ReportStatus,
): ("reviewed" | "sent" | "closed" | "discarded" | "draft")[] {
  switch (status) {
    case "draft":
      return ["reviewed", "discarded"]
    case "reviewed":
      return ["sent", "draft", "discarded"]
    case "sent":
      return ["closed"]
    default:
      return []
  }
}

const settingsIncompleteText = () => t("abuse_settings_incomplete")

/** A readable message for a failed call. */
export function describeAbuseError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "revision_mismatch" || (e.status === 409 && e.code === "stale"))
      return t("abuse_error_stale")
    if (e.code === "invalid_transition") return t("abuse_error_invalid_transition")
    if (e.code === "settings_incomplete") return settingsIncompleteText()
    if (e.code === "demo_report") return t("abuse_error_demo")
    if (e.code === "no_mailbox") return t("abuse_no_mailbox")
    if (e.code === "evidence_invalid") return t("abuse_error_evidence_invalid")
    if (e.code === "xarf_unavailable") return t("abuse_error_xarf_unavailable")
    if (e.code === "xarf_invalid") return t("abuse_error_xarf_invalid")
    if (e.code === "xarf_subject_required") return t("abuse_error_xarf_subject_required")
    if (e.code === "xarf_kind_required") return t("abuse_error_xarf_kind_required")
    if (e.code === "not_sent_with_xarf_v4") return t("abuse_error_not_sent_with_xarf_v4")
    if (e.code === "reply_contact_not_email") return t("abuse_error_reply_contact_not_email")
    if (e.code === SAME_DAY) return sameDayText()
    if (e.code === "identity_guard_failed") return t("abuse_error_guard_failed")
    if (e.code === "reauth_failed") return t("abuse_error_reauth_failed")
    if (e.status === 429) return t("abuse_error_too_many")
    if (e.status === 403) return t("abuse_error_admin_only")
    if (e.status === 422 && e.message) return e.message
  }
  return t("abuse_error_generic")
}

/** Field names listed by a 409 `settings_incomplete` answer (`missing`), or []. */
export function missingSettingsOf(e: unknown): string[] {
  if (!(e instanceof ApiError) || e.code !== "settings_incomplete") return []
  const m = e.body?.missing
  return Array.isArray(m) ? m.filter((x): x is string => typeof x === "string") : []
}

/** Reason codes of a 409 `identity_guard_failed` answer, or null for any other error. */
export function guardReasonsOf(e: unknown): string[] | null {
  if (!(e instanceof ApiError) || e.code !== "identity_guard_failed") return null
  const reasons = e.body?.reasons
  return Array.isArray(reasons) ? reasons.filter((r): r is string => typeof r === "string") : []
}

export function isStale(e: unknown): boolean {
  return e instanceof ApiError && e.status === 409 && e.code === "revision_mismatch"
}

// --- Calls -------------------------------------------------------------------------

export const abuseKeys = {
  all: ["abuse"] as const,
  status: ["abuse", "status"] as const,
  list: (f: ReportFilters) => ["abuse", "reports", f] as const,
  report: (id: string) => ["abuse", "report", id] as const,
  render: (id: string, format: MessageFormat, revision: number) =>
    ["abuse", "render", id, format, revision] as const,
  waiting: ["abuse", "waiting"] as const,
  settings: ["abuse", "settings"] as const,
  terms: (reveal: boolean) => ["abuse", "terms", reveal] as const,
}

export const abuseApi = {
  status: () => getJson<AbuseStatus>("/abuse/status"),
  list: (f: ReportFilters, cursor?: string | null) =>
    getJson<Page<ReportItem>>("/abuse/reports", {
      status: f.status,
      kind: f.kind,
      recipient: f.recipient,
      cursor: cursor ?? undefined,
      limit: 50,
    }),
  report: (id: string) => getJson<ReportDetail>(`/abuse/reports/${id}`),
  render: (id: string, format: MessageFormat) =>
    getJson<RenderedMessage>(`/abuse/reports/${id}/render`, { format }),
  waiting: () => getJson<WaitingRecipient[]>("/abuse/recipients", { waiting: "true" }),
  setStatus: (
    id: string,
    body: { to: ReportStatus; revision: number; sent_at?: string; confirm_same_day?: boolean },
  ) => sendJson<ReportDetail>("POST", `/abuse/reports/${id}/status`, body),
  patch: (id: string, body: { notes?: string | null; options?: Partial<ReportOptions> }) =>
    sendJson<ReportDetail>("PATCH", `/abuse/reports/${id}`, body),
  regenerate: (id: string) => sendJson("POST", `/abuse/reports/${id}/regenerate`),
  setMailbox: (recipientId: number, mailbox: string) =>
    sendJson("PATCH", `/abuse/recipients/${recipientId}`, { override_mailbox: mailbox }),
  /** The owner clears what replies taught the node about a desk. */
  clearDesk: (recipientId: number, flag: "form_only" | "undeliverable") =>
    sendJson("PATCH", `/abuse/recipients/${recipientId}`, { [flag]: false }),
  /** One mail per source for a desk that parses X-ARF strictly (M38). */
  setStrict: (recipientId: number, on: boolean) =>
    sendJson("PATCH", `/abuse/recipients/${recipientId}`, { xarf_strict: on }),
  settings: () => getJson<ReportSettings>("/abuse/settings"),
  saveSettings: (body: ReportSettings) => {
    // `field_issues` is an answer, not an input: the server refuses unknown keys.
    const payload = { ...body }
    delete payload.field_issues
    return sendJson<ReportSettings>("PUT", "/abuse/settings", payload)
  },
  terms: (reveal: boolean) =>
    getJson<SelfTerm[]>("/abuse/self-terms", { reveal: reveal ? "true" : undefined }),
  addTerm: (kind: SelfTerm["kind"], value: string) =>
    sendJson<SelfTerm>("POST", "/abuse/self-terms", { kind, value }),
  confirmTerm: (id: number) => sendJson("PATCH", `/abuse/self-terms/${id}`, { confirmed: true }),
  deleteTerm: (id: number) => sendJson("DELETE", `/abuse/self-terms/${id}`),
}

export type FileFormat = "txt" | "eml" | "evidence_csv" | "xarf_json"

/**
 * A guarded file of one report. A blocked check rejects with the 409 and its reason codes.
 * `subject` picks the source of an X-ARF file when the report holds more than one.
 */
export const downloadFile = (
  id: string,
  format: FileFormat,
  subject?: string,
  subjectKind?: string,
) => getBlob(`/abuse/reports/${id}/download`, { format, subject, subject_kind: subjectKind })

// --- One mail per provider per day (M38) ---------------------------------------------

/** The 409 code when another report already went to the same provider today (UTC). */
export const SAME_DAY = "recipient_sent_today"
const sameDayText = () => t("abuse_same_day")
/** The confirm question when another report already went to the same provider today. */
export const sameDayQuestion = () => t("abuse_same_day_question")

export function isSameDay(e: unknown): boolean {
  return e instanceof ApiError && e.status === 409 && e.code === SAME_DAY
}

/**
 * Run a send or a "mark sent". When the provider already got a report today, ask first and run it
 * again with the confirmation. A "no" ends with an error that says why nothing happened.
 */
export async function withSameDayConfirm<T>(
  run: (confirm: boolean) => Promise<T>,
  ask: (question: string) => boolean = (q) => window.confirm(q),
): Promise<T> {
  try {
    return await run(false)
  } catch (e) {
    if (!isSameDay(e) || !ask(sameDayQuestion())) throw e
    return run(true)
  }
}

export interface DigestSettings {
  enabled: boolean
  /** Minutes after 00:00 UTC; null while there is no SMTP profile. */
  minute: number | null
}

/** UTC minutes of the day to "HH:MM" in the browser's time zone (for an `<input type="time">`). */
export function utcMinuteToLocal(minute: number, on: Date = new Date()): string {
  const d = new Date(
    Date.UTC(
      on.getUTCFullYear(),
      on.getUTCMonth(),
      on.getUTCDate(),
      Math.floor(minute / 60),
      minute % 60,
    ),
  )
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`
}

/** "HH:MM" in the browser's time zone to minutes after 00:00 UTC, or null when not a time. */
export function localToUtcMinute(value: string, on: Date = new Date()): number | null {
  const m = /^(\d{2}):(\d{2})$/.exec(value)
  if (!m) return null
  const h = Number(m[1])
  const min = Number(m[2])
  if (h > 23 || min > 59) return null
  const d = new Date(on.getFullYear(), on.getMonth(), on.getDate(), h, min)
  return (d.getUTCHours() * 60 + d.getUTCMinutes()) % 1440
}

export const digestKeys = { digest: ["abuse", "digest"] as const }
export const digestApi = {
  get: () => getJson<DigestSettings>("/abuse/digest"),
  save: (body: { enabled: boolean; minute?: number }) =>
    sendJson<DigestSettings>("PUT", "/abuse/digest", body),
}

/** What a CERT export covers. */
export type ExportScope = { report: string } | { campaign: number } | { since: string }

export const exportFile = (
  kind: "stix" | "misp",
  scope: ExportScope,
  tlp: Tlp,
  description?: string,
) => getBlob(`/abuse/exports/${kind}`, { ...scope, tlp, description })
