/**
 * Abuse reports (M22): shapes of `/api/v1/abuse/*` (docs/design/m22.md section 9.1 is the
 * contract), the plain-English sentences of the pages, and the calls. Nothing here sends mail:
 * the owner copies the draft into his own webmail. The sentences are pure and tested.
 */
import { ApiError, getBlob, getJson, sendJson, type Page } from "./api"
import { plural } from "./format"
import type { RepliesStatus, Reply, ReportOutcome } from "./replies"

// --- Vocabulary -------------------------------------------------------------------

export type ReportKind = "attack_source" | "payload_host" | "c2"
export const KIND_LABEL: Record<ReportKind, string> = {
  attack_source: "Attack source",
  payload_host: "Payload host",
  c2: "C2 server",
}

export type ReportStatus = "draft" | "reviewed" | "sent" | "closed" | "discarded" | "superseded"
/** The tabs of the list, in workflow order. `superseded` is never shown. */
export const LIST_STATUSES = ["draft", "reviewed", "sent", "closed", "discarded"] as const
export type ListStatus = (typeof LIST_STATUSES)[number]
export const STATUS_LABEL: Record<ReportStatus, string> = {
  draft: "Draft",
  reviewed: "Reviewed",
  sent: "Sent",
  closed: "Closed",
  discarded: "Discarded",
  superseded: "Replaced",
}
export const TAB_LABEL: Record<ListStatus, string> = {
  draft: "Drafts",
  reviewed: "Reviewed",
  sent: "Sent",
  closed: "Closed",
  discarded: "Discarded",
}
/** The four steps of the stepper (discarded and replaced are side exits). */
export const STEPS = ["draft", "reviewed", "sent", "closed"] as const

export type MessageFormat = "text" | "xarf" | "eml"
export const FORMAT_OPTIONS = [
  { value: "text", label: "Plain text" },
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
  { value: "subject", label: "In the subject" },
  { value: "subject_and_body", label: "Subject and body" },
  { value: "off", label: "Off" },
] as const satisfies readonly { value: ReferenceStyle; label: string }[]

/** Reason codes of the identity check. They never carry the matched value. */
export const GUARD_REASON: Record<string, string> = {
  self_address: "The text contains the public address of the monitored system.",
  self_name: "The text contains a name that belongs to the monitored system.",
  owner_domain: "The text contains a domain that belongs to you.",
  vpn_address: "The text contains the address that outbound traffic leaves from.",
  project_term: "The text contains the name of this project or a word that gives it away.",
  private_address: "The text contains a private or reserved network address.",
  documentation_address: "The text contains an example address that real reports must not use.",
  dashboard_path: "The text contains a link or path into this dashboard.",
  internal_id: "The text contains an internal identifier that links back to the dashboard.",
  default_wording: "The text contains wording shipped with the software.",
  no_self_address:
    "The address of the monitored system is not known yet, so nothing can be checked. Reports stay locked until traffic teaches it, or you add it in Settings.",
  self_terms_unavailable:
    "The list of things that must never appear could not be read, so nothing is released.",
  // Set by the draft builder, not by the guard itself.
  settings_incomplete: "No reply contact is set, so the report cannot be written.",
  evidence_invalid: "The stored evidence of this draft is not valid.",
  eml_invalid_recipient: "The abuse mailbox of this provider is not a valid address.",
  bad_reply_token: "The reply reference of this draft is not valid.",
}

export function guardReason(code: string): string {
  return GUARD_REASON[code] ?? "The identity check refused this text."
}

/**
 * What to do about each reason, in plain English. A blocked draft is re-checked on its own about
 * a minute after the settings are saved, so the settings advice never says "regenerate".
 */
export const GUARD_FIX: Record<string, string> = {
  project_term:
    "Use a neutral reply address and neutral wording. An address on a domain that names the project counts. Saved changes are checked again within a minute.",
  self_name:
    "Use a reply address and texts that do not contain that name. If the name is not yours, delete it under Never in a report.",
  owner_domain: "Use a reply address on a domain that does not belong to you.",
  self_address:
    "Remove it from your texts in the Reporting settings. If it still shows up, the captured traffic contains it: discard the draft.",
  vpn_address:
    "Remove it from your texts in the Reporting settings. If it still shows up, discard the draft.",
  private_address:
    "Regenerate the draft. If it is blocked again, the captured traffic contains it: discard the draft.",
  documentation_address:
    "Regenerate the draft. If it is blocked again, the captured traffic contains it: discard the draft.",
  dashboard_path: "Remove the link from your texts in the Reporting settings, then regenerate.",
  internal_id:
    "Regenerate the draft. If it is blocked again, the captured traffic contains it: discard the draft.",
  default_wording:
    "Write the introduction, closing, note, signature and subject template in your own words, or leave them empty. Saved changes are checked again within a minute.",
  no_self_address: "Wait until traffic teaches the address, or add it under Never in a report.",
  self_terms_unavailable: "Try again in a minute. If it lasts, check that the database is healthy.",
  settings_incomplete: "Set a reply contact in the Reporting settings.",
  evidence_invalid: "Regenerate the draft, or discard it.",
  eml_invalid_recipient: "Type a valid mailbox for this provider in the list of recipients.",
  bad_reply_token: "Regenerate the draft, or discard it.",
}

/** A few words for one draft row: why it is held back. */
export const GUARD_SHORT: Record<string, string> = {
  self_address: "has your address",
  self_name: "names your system",
  owner_domain: "uses your domain",
  vpn_address: "has your outbound address",
  project_term: "names the project",
  private_address: "has a private address",
  documentation_address: "has an example address",
  dashboard_path: "links into the dashboard",
  internal_id: "has an internal identifier",
  default_wording: "uses old default wording",
  no_self_address: "your address is not known yet",
  self_terms_unavailable: "the deny list could not be read",
  settings_incomplete: "no reply contact is set",
  evidence_invalid: "its evidence is not valid",
  eml_invalid_recipient: "its mailbox is not valid",
  bad_reply_token: "its reply reference is not valid",
}

/** One reason as two sentences: what was found, and what to do about it. */
export function guardAdvice(code: string): { why: string; fix: string } {
  return {
    why: guardReason(code),
    fix: GUARD_FIX[code] ?? "Regenerate the draft, or discard it.",
  }
}

/** "Why: names the project, uses old default wording" for a blocked row, or null. */
export function describeBlockedRow(guard: GuardResult): string | null {
  if (guard.ok) return null
  const words = guard.codes.map((c) => GUARD_SHORT[c] ?? "was refused by the check")
  if (words.length === 0) return "Why: the identity check refused it"
  const shown = words.slice(0, 2).join(", ")
  const more = words.length > 2 ? ` and ${words.length - 2} more` : ""
  return `Why: ${shown}${more}`
}

/**
 * The sentence above the blocked drafts: how many, why, and that nothing leaves while they are
 * blocked. Reasons are sorted by how many drafts they hold back.
 */
export function describeBlockedDrafts(blocked: BlockedDrafts): string {
  const n = blocked.count
  return `${plural(n, "draft")} ${n === 1 ? "is" : "are"} blocked by the identity check: ${n === 1 ? "it" : "they"} cannot be reviewed, copied or sent until the cause is fixed.`
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
  reply_contact: "This reply address",
  signature: "The signature",
  intro: "The introduction",
  outro: "The closing",
  note: "The note",
  subject_template: "The subject template",
  xarf_user_agent: "The X-ARF user agent",
}

/** What a reason means for a text that ends up in every report. */
const SETTINGS_CONSEQUENCE: Record<string, string> = {
  project_term: "names the project, so every report would reveal the honeypot.",
  self_name: "names your monitored system, so every report would reveal it.",
  owner_domain: "uses a domain that belongs to you, so every report would point back to you.",
  self_address:
    "contains the public address of the monitored system, so every report would reveal it.",
  vpn_address:
    "contains the address your outbound traffic leaves from, so every report would reveal it.",
  private_address: "contains a private or reserved network address, so every report is blocked.",
  documentation_address:
    "contains an example address that real reports must not use, so every report is blocked.",
  dashboard_path: "contains a link into this dashboard, so every report would reveal it.",
  internal_id: "contains an internal identifier, so every report is blocked.",
  default_wording:
    "uses wording that older versions shipped as a default, so every report could be recognised.",
  self_terms_unavailable:
    "could not be checked, because the list of things that must never appear could not be read.",
}

/**
 * One sentence per field: what is wrong with this text and what to do. It says what blocks every
 * report, never the matched text (the server sends reason codes only).
 */
export function describeSettingsIssue(field: string, codes: string[]): string {
  const subject = SETTINGS_SUBJECT[field] ?? "This text"
  const parts = codes.map(
    (c, i) =>
      `${i === 0 ? subject : "It also"} ${SETTINGS_CONSEQUENCE[c] ?? "would be refused by the identity check, so every report is blocked."}`,
  )
  const fix = field === "reply_contact" ? "Use a neutral address." : "Reword it, or leave it empty."
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
  kind: ReportKind
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
  kind?: ReportKind
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
  if (!status) return "Reports to the networks that host the attackers, for you to review and send."
  if (!status.enabled)
    return "Abuse reports are switched off on this server, so no drafts are written."
  const drafts = status.counts.draft
  const toSend = extra.toSend ?? status.counts.reviewed
  const replies = extra.replies ?? 0
  if (drafts === 0 && toSend === 0 && replies === 0)
    return "Nothing to report: no source crossed the thresholds this week."
  const parts: string[] = []
  if (drafts > 0) parts.push(`${plural(drafts, "draft")} to review`)
  if (toSend > 0) parts.push(`${plural(toSend, "report")} ready to send`)
  if (replies > 0) parts.push(`${plural(replies, "reply", "replies")} to check`)
  return `${parts.join(", ")}.`
}

/** Why the list cannot be used yet, or null. The message is one sentence. */
export function blockedReason(status: AbuseStatus | undefined): string | null {
  if (!status) return null
  if (!status.enabled)
    return "The reporting worker is off. Set ABUSE_REPORTS_ENABLED=true in .env and restart to get drafts."
  if (!status.self_address_known)
    return "The public address of the monitored system is not known yet, so reports are locked. Traffic teaches it within a day, or you can add it in Settings."
  if (!status.self_address_fresh)
    return "The learned address of the monitored system is out of date, so reports are blocked until a fresh one is known. Traffic refreshes it, or you can enter it by hand in Settings."
  if (status.gate === "closed")
    return "Outbound traffic is closed, so abuse contacts cannot be looked up. Drafts already written still open."
  return null
}

/** "3 addresses in 2 networks" for the first line of a report page. */
export function describeReport(r: ReportItem): string {
  const nets = new Set(r.asns.map((a) => a.asn)).size
  const noun =
    r.kind === "attack_source"
      ? "address"
      : r.kind === "payload_host"
        ? "payload host"
        : "C2 server"
  const where = nets > 0 ? ` in ${plural(nets, "network")}` : ""
  const n = r.subject_count
  const what = noun === "address" ? plural(n, "address", "addresses") : plural(n, noun)
  const name = r.recipient.name
  return `${what}${where}, reported to ${name}${name.endsWith(".") ? "" : "."}`
}

/** The finding of the identity check card. */
export function describeGuard(guard: GuardResult, redaction: { masked: number; removed: number }) {
  if (!guard.ok) {
    return "Blocked: this report would reveal something it must not. It cannot be copied or downloaded."
  }
  const parts: string[] = []
  if (redaction.masked > 0) parts.push(`${plural(redaction.masked, "address", "addresses")} masked`)
  if (redaction.removed > 0) parts.push(`${plural(redaction.removed, "line")} removed`)
  return `Nothing identifying found.${parts.length ? ` ${capitalize(parts.join(", "))}.` : ""}`
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** What the next step needs, or null when nothing blocks it. */
export function reviewBlocker(r: ReportDetail): string | null {
  if (!r.guard.ok) return "The identity check blocked this report, so it cannot be reviewed."
  if (!r.recipient.mailbox) return "There is no abuse mailbox for this provider yet."
  if (r.missing.length > 0) return "Set a reply contact in Settings first."
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

export const SETTINGS_INCOMPLETE = "Set the reply contact in the Reporting settings first"

/** A readable message for a failed call. */
export function describeAbuseError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "revision_mismatch" || (e.status === 409 && e.code === "stale"))
      return "The draft changed while you were reading it. It was reloaded: read it again, then retry."
    if (e.code === "invalid_transition") return "That step is not possible from the current status."
    if (e.code === "settings_incomplete") return SETTINGS_INCOMPLETE
    if (e.code === "demo_report") return "This is a demo report. It can be reviewed but never sent."
    if (e.code === "no_mailbox") return "There is no abuse mailbox for this provider yet."
    if (e.code === "evidence_invalid") return "The stored evidence for this report is not valid."
    if (e.code === "xarf_unavailable") return "This report cannot be written as X-ARF."
    if (e.code === "identity_guard_failed") return "The identity check blocked this text."
    if (e.code === "reauth_failed") return "That password is not right."
    if (e.status === 429) return "Too many requests. Wait a moment and try again."
    if (e.status === 403) return "Only an administrator can do this."
    if (e.status === 422 && e.message) return e.message
  }
  return "That did not work. Check the connection and try again."
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
  setStatus: (id: string, body: { to: ReportStatus; revision: number; sent_at?: string }) =>
    sendJson<ReportDetail>("POST", `/abuse/reports/${id}/status`, body),
  patch: (id: string, body: { notes?: string | null; options?: Partial<ReportOptions> }) =>
    sendJson<ReportDetail>("PATCH", `/abuse/reports/${id}`, body),
  regenerate: (id: string) => sendJson("POST", `/abuse/reports/${id}/regenerate`),
  setMailbox: (recipientId: number, mailbox: string) =>
    sendJson("PATCH", `/abuse/recipients/${recipientId}`, { override_mailbox: mailbox }),
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

export type FileFormat = "txt" | "eml" | "evidence_csv" | "xarf_yaml"

/** A guarded file of one report. A blocked check rejects with the 409 and its reason codes. */
export const downloadFile = (id: string, format: FileFormat) =>
  getBlob(`/abuse/reports/${id}/download`, { format })

/** What a CERT export covers. */
export type ExportScope = { report: string } | { campaign: number } | { since: string }

export const exportFile = (
  kind: "stix" | "misp",
  scope: ExportScope,
  tlp: Tlp,
  description?: string,
) => getBlob(`/abuse/exports/${kind}`, { ...scope, tlp, description })
