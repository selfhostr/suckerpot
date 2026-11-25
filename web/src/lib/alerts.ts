/**
 * Alert channels, rules, recent alerts and weekly reports (M18).
 *
 * Nothing secret ever comes back from the API: a channel shows a short hint of where it goes.
 * Creating a channel or changing where it goes asks for the administrator's password again.
 */
import { ApiError, API_BASE, sendJson, type Page } from "@/lib/api"
import { intlLocale, t } from "@/i18n"
import type { Severity } from "@/lib/severity"

export type ChannelKind = "discord" | "teams" | "email"
export type RuleKind =
  "new_campaign" | "new_download_host" | "malware_drop" | "watched_cve_seen" | "weekly_report"
export type OutboxState = "pending" | "sent" | "failed" | "suppressed"

export interface LastTest {
  state: "queued" | "done" | "refused" | "failed"
  detail: string | null
  requested_at: string
}

export interface AlertChannel {
  id: number
  kind: ChannelKind
  name: string
  enabled: boolean
  /** Not secret: the host of a webhook, or a partly hidden e-mail address. */
  target_hint: string
  mask_ips: boolean
  created_by: string
  created_at: string
  updated_at: string
  last_test: LastTest | null
}

export interface AlertRule {
  kind: RuleKind
  enabled: boolean
  channel_ids: number[]
  min_severity: Severity
}

export interface WatchedCve {
  cve_id: string
  added_by: string
  added_at: string
}

export interface OutboxItem {
  id: number
  rule_kind: RuleKind
  channel_id: number
  channel_name: string | null
  state: OutboxState
  attempts: number
  created_at: string
  sent_at: string | null
  error_code: string | null
  severity: Severity | null
  title: string | null
  summary: string | null
}

export interface AlertStatus {
  alerts: {
    enabled: boolean
    smtp_configured: boolean
    can_decrypt: boolean
    last_error: string | null
    updated_at: string | null
  }
  reports_enabled: boolean
  editing_enabled: boolean
  editing_reason: string | null
  channels: number
  limits: { per_minute: number; per_day: number; all_channels_per_day: number }
}

export interface ReportItem {
  week_start: string
  week_end: string | null
  headline: string | null
  sessions: number
  sources: number
  malware: number
  change_pct: number | null
  created_at: string
}

/** The stored summary, as ingest writes it (`ingest/reports/build.py`). Every field is optional:
 * older or partial reports still render, with an empty section instead of an error. */
export interface ReportSummary {
  headline?: string
  week_end?: string
  timezone?: string
  actions?: string[]
  totals?: {
    sessions?: number
    sources?: number
    with_commands?: number
    malware?: number
    previous_sessions?: number
    change_pct?: number | null
  }
  by_sensor?: { sensor: string; sessions: number }[]
  countries?: { country: string; sessions: number }[]
  tags?: { tag: string; sessions: number }[]
  campaigns?: { id: number; name: string; severity: string; sessions: number; sources: number }[]
  download_hosts?: { host: string; sightings: number }[]
  watched_cves?: { cve_id: string; sessions: number }[]
}

export interface ReportDetail {
  week_start: string
  created_at: string
  summary: ReportSummary
}

export const KIND_LABEL: Record<ChannelKind, string> = {
  get discord() {
    return t("channels_kind_discord")
  },
  get teams() {
    return t("channels_kind_teams")
  },
  get email() {
    return t("channels_kind_email")
  },
}

export const KIND_OPTIONS = [
  {
    value: "discord",
    get label() {
      return t("channels_kind_option_discord")
    },
  },
  {
    value: "teams",
    get label() {
      return t("channels_kind_option_teams")
    },
  },
  {
    value: "email",
    get label() {
      return t("channels_kind_option_email")
    },
  },
] as const

export const TARGET_LABEL: Record<ChannelKind, { label: string; hint: string; example: string }> = {
  discord: {
    get label() {
      return t("channels_target_webhook_label")
    },
    get hint() {
      return t("channels_target_discord_hint")
    },
    example: "https://discord.com/api/webhooks/…",
  },
  teams: {
    get label() {
      return t("channels_target_webhook_label")
    },
    get hint() {
      return t("channels_target_teams_hint")
    },
    example: "https://….logic.azure.com/workflows/…",
  },
  email: {
    get label() {
      return t("channels_target_email_label")
    },
    get hint() {
      return t("channels_target_email_hint")
    },
    example: "security@example.org",
  },
}

export interface RuleInfo {
  kind: RuleKind
  title: string
  /** One plain sentence: when does this fire. */
  when: string
}

/** In the order they are shown. Texts are read lazily so they follow the active language. */
export const RULES: readonly RuleInfo[] = [
  {
    kind: "new_campaign",
    get title() {
      return t("rules_new_campaign_title")
    },
    get when() {
      return t("rules_new_campaign_when")
    },
  },
  {
    kind: "malware_drop",
    get title() {
      return t("rules_malware_drop_title")
    },
    get when() {
      return t("rules_malware_drop_when")
    },
  },
  {
    kind: "new_download_host",
    get title() {
      return t("rules_new_download_host_title")
    },
    get when() {
      return t("rules_new_download_host_when")
    },
  },
  {
    kind: "watched_cve_seen",
    get title() {
      return t("rules_watched_cve_seen_title")
    },
    get when() {
      return t("rules_watched_cve_seen_when")
    },
  },
  {
    kind: "weekly_report",
    get title() {
      return t("rules_weekly_report_title")
    },
    get when() {
      return t("rules_weekly_report_when")
    },
  },
]

export const RULE_TITLE: Record<RuleKind, string> = {
  get new_campaign() {
    return t("rules_new_campaign_title")
  },
  get malware_drop() {
    return t("rules_malware_drop_title")
  },
  get new_download_host() {
    return t("rules_new_download_host_title")
  },
  get watched_cve_seen() {
    return t("rules_watched_cve_seen_title")
  },
  get weekly_report() {
    return t("rules_weekly_report_title")
  },
}

export const SEVERITY_OPTIONS = [
  {
    value: "info",
    get label() {
      return t("rules_severity_any")
    },
  },
  {
    value: "warning",
    get label() {
      return t("rules_severity_warning")
    },
  },
  {
    value: "severe",
    get label() {
      return t("rules_severity_severe")
    },
  },
] as const

export const STATE_LABEL: Record<OutboxState, string> = {
  get pending() {
    return t("outbox_state_pending")
  },
  get sent() {
    return t("outbox_state_sent")
  },
  get failed() {
    return t("outbox_state_failed")
  },
  get suppressed() {
    return t("outbox_state_suppressed")
  },
}

/** Shown for an error code the server reports (`error_code`). One literal key per code. */
function errorText(code: string): string | null {
  switch (code) {
    case "blocked_target":
      return t("alerts_error_blocked_target")
    case "private_address":
      return t("alerts_error_private_address")
    case "dns":
      return t("alerts_error_dns")
    case "timeout":
      return t("alerts_error_timeout")
    case "network":
      return t("alerts_error_network")
    case "tls":
      return t("alerts_error_tls")
    case "redirect":
      return t("alerts_error_redirect")
    case "http_429":
      return t("alerts_error_http_429")
    case "http_5xx":
      return t("alerts_error_http_5xx")
    case "http_400":
      return t("alerts_error_http_400")
    case "http_401":
    case "http_403":
      return t("alerts_error_http_credentials")
    case "http_404":
      return t("alerts_error_http_404")
    case "smtp_auth":
      return t("alerts_error_smtp_auth")
    case "smtp_recipient":
      return t("alerts_error_smtp_recipient")
    case "smtp_error":
      return t("alerts_error_smtp_error")
    case "smtp_not_configured":
      return t("alerts_error_smtp_not_configured")
    case "cannot_decrypt":
      return t("alerts_error_cannot_decrypt")
    case "no_encryption_key":
      return t("alerts_error_no_encryption_key")
    case "too_large":
      return t("alerts_error_too_large")
    case "digested":
      return t("alerts_error_digested")
    case "daily_limit":
      return t("alerts_error_daily_limit")
    case "channel_disabled":
      return t("alerts_error_channel_disabled")
    case "channel_missing":
      return t("alerts_error_channel_missing")
    default:
      return null
  }
}

export function describeError(code: string | null | undefined): string {
  if (!code) return ""
  // A guard failure carries its codes after a colon: `guard_failed:no_self_address`.
  if (code.startsWith("guard_failed"))
    return code.includes("no_self_address")
      ? t("alerts_error_guard_self_address")
      : t("alerts_error_guard_identity")
  return errorText(code) ?? t("alerts_error_generic")
}

/** What the last test says, in a sentence. */
export function describeTest(test: LastTest | null): string | null {
  if (!test) return null
  if (test.state === "queued") return t("alerts_test_queued")
  if (test.state === "done") return t("alerts_test_done")
  return t("alerts_test_failed", { reason: describeError(test.detail) }).trim()
}

export function testInFlight(channels: readonly AlertChannel[] | undefined): boolean {
  return (channels ?? []).some((c) => c.last_test?.state === "queued")
}

export function channelsFinding(status: AlertStatus | undefined, channels: AlertChannel[]): string {
  if (status && !status.alerts.enabled) return t("alerts_finding_channels_off")
  if (channels.length === 0) return t("alerts_finding_channels_none")
  const on = channels.filter((c) => c.enabled).length
  const broken = channels.filter(
    (c) => c.last_test && (c.last_test.state === "failed" || c.last_test.state === "refused"),
  ).length
  return broken > 0
    ? t("alerts_finding_channels_broken", { on, broken })
    : t("alerts_finding_channels_ready", { on })
}

export function rulesFinding(
  rules: readonly AlertRule[],
  channels: readonly AlertChannel[],
): string {
  const on = rules.filter((r) => r.enabled).length
  if (on === 0)
    return channels.length === 0
      ? t("alerts_finding_rules_no_channel")
      : t("alerts_finding_rules_all_off")
  return t("alerts_finding_rules_on", { on })
}

export function outboxFinding(items: readonly OutboxItem[]): string {
  if (items.length === 0) return t("alerts_finding_outbox_empty")
  const sent = items.filter((i) => i.state === "sent").length
  const failed = items.filter((i) => i.state === "failed").length
  return failed > 0
    ? t("alerts_finding_outbox_failed", { sent, failed })
    : t("alerts_finding_outbox_sent", { sent })
}

export function reportsFinding(items: readonly ReportItem[]): string {
  const first = items[0]
  if (!first) return t("alerts_finding_reports_none")
  return first.headline ?? t("alerts_finding_reports_latest", { week: weekLabel(first.week_start) })
}

/** "Oct 12 to Oct 18" for a Monday (date-only strings are UTC dates, shown as written). */
export function weekLabel(weekStart: string, weekEnd?: string | null): string {
  const fmt = (iso: string) =>
    new Intl.DateTimeFormat(intlLocale(), {
      month: "short",
      day: "numeric",
      timeZone: "UTC",
    }).format(new Date(`${iso}T00:00:00Z`))
  const end =
    weekEnd ??
    new Date(Date.parse(`${weekStart}T00:00:00Z`) + 6 * 86_400_000).toISOString().slice(0, 10)
  return t("alerts_week_range", { start: fmt(weekStart), end: fmt(end) })
}

export const CVE_PATTERN = /^CVE-\d{4}-\d{4,10}$/

/* --- Errors ------------------------------------------------------------------------------- */

export type AlertErrorReason =
  | "wrong-password"
  | "password-required"
  | "invalid-target"
  | "editing-disabled"
  | "alerts-disabled"
  | "rate-limited"
  | "too-many"
  | "no-channel"
  | "not-found"
  | "session"
  | "network"

export const ALERT_MESSAGES: Record<AlertErrorReason, string> = {
  get "wrong-password"() {
    return t("alerts_msg_wrong_password")
  },
  get "password-required"() {
    return t("alerts_msg_password_required")
  },
  get "invalid-target"() {
    return t("alerts_msg_invalid_target")
  },
  get "editing-disabled"() {
    return t("alerts_msg_editing_disabled")
  },
  get "alerts-disabled"() {
    return t("alerts_msg_alerts_disabled")
  },
  get "rate-limited"() {
    return t("alerts_msg_rate_limited")
  },
  get "too-many"() {
    return t("alerts_msg_too_many")
  },
  get "no-channel"() {
    return t("alerts_msg_no_channel")
  },
  get "not-found"() {
    return t("alerts_msg_not_found")
  },
  get session() {
    return t("alerts_msg_session")
  },
  get network() {
    return t("alerts_msg_network")
  },
}

export class AlertError extends Error {
  constructor(
    readonly reason: AlertErrorReason,
    detail?: string,
  ) {
    super(detail ?? ALERT_MESSAGES[reason])
    this.name = "AlertError"
  }
}

export function toAlertError(e: unknown): AlertError {
  if (e instanceof AlertError) return e
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return new AlertError("wrong-password")
    if (e.code === "password_required") return new AlertError("password-required")
    if (e.code === "invalid_target") return new AlertError("invalid-target", e.message)
    if (e.code === "editing_disabled") return new AlertError("editing-disabled")
    if (e.code === "alerts_disabled") return new AlertError("alerts-disabled")
    if (e.code === "no_channel" || e.code === "bad_channels") return new AlertError("no-channel")
    if (e.code === "too_many") return new AlertError("too-many")
    if (e.code === "not_found") return new AlertError("not-found")
    if (e.status === 429) return new AlertError("rate-limited")
    if (e.status === 401) return new AlertError("session")
  }
  return new AlertError("network")
}

async function run<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    throw toAlertError(e)
  }
}

/* --- Requests ----------------------------------------------------------------------------- */

async function getJson<T>(path: string, params: Record<string, string | undefined> = {}) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v)
  const res = await fetch(`${API_BASE}${path}${qs.size ? `?${qs.toString()}` : ""}`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return (await res.json()) as T
}

export const alertKeys = {
  status: ["alerts", "status"] as const,
  channels: ["alerts", "channels"] as const,
  rules: ["alerts", "rules"] as const,
  watched: ["alerts", "watched"] as const,
  outbox: ["alerts", "outbox"] as const,
  reports: ["reports"] as const,
  report: (week: string) => ["reports", week] as const,
}

export const alertsApi = {
  status: () => getJson<AlertStatus>("/alerts/status"),
  channels: () => getJson<AlertChannel[]>("/alerts/channels"),
  rules: () => getJson<AlertRule[]>("/alerts/rules"),
  watched: () => getJson<WatchedCve[]>("/alerts/watched-cves"),
  outbox: (cursor?: string | null) =>
    getJson<Page<OutboxItem>>("/alerts/outbox", { cursor: cursor ?? undefined, limit: "10" }),
  reports: (cursor?: string | null) =>
    getJson<Page<ReportItem>>("/reports", { cursor: cursor ?? undefined, limit: "12" }),
  report: (week: string) => getJson<ReportDetail>(`/reports/${encodeURIComponent(week)}`),
}

/** The printable page (served by the API under its own strict policy). */
export const reportHtmlUrl = (week: string) =>
  `${API_BASE}/reports/${encodeURIComponent(week)}/html`

export interface NewChannel {
  kind: ChannelKind
  name: string
  target: string
  maskIps: boolean
}

export function createChannel(input: NewChannel, password: string): Promise<AlertChannel> {
  return run(() =>
    sendJson<AlertChannel>("POST", "/alerts/channels", {
      kind: input.kind,
      name: input.name.trim(),
      target: input.target.trim(),
      mask_ips: input.maskIps,
      password,
    }),
  )
}

export function updateChannel(
  id: number,
  changes: { name?: string; enabled?: boolean; mask_ips?: boolean },
): Promise<AlertChannel> {
  return run(() => sendJson<AlertChannel>("PATCH", `/alerts/channels/${id}`, changes))
}

export function changeChannelTarget(
  id: number,
  target: string,
  password: string,
): Promise<AlertChannel> {
  return run(() =>
    sendJson<AlertChannel>("PATCH", `/alerts/channels/${id}`, { target: target.trim(), password }),
  )
}

export function deleteChannel(id: number): Promise<void> {
  return run(() => sendJson("DELETE", `/alerts/channels/${id}`))
}

export function requestChannelTest(id: number): Promise<void> {
  return run(async () => {
    await sendJson("POST", `/alerts/channels/${id}/test`)
  })
}

export function saveRule(
  kind: RuleKind,
  rule: { enabled: boolean; channel_ids: number[]; min_severity: Severity },
): Promise<AlertRule> {
  return run(() => sendJson<AlertRule>("PUT", `/alerts/rules/${kind}`, rule))
}

export function watchCve(id: string): Promise<WatchedCve> {
  return run(() => sendJson<WatchedCve>("PUT", `/alerts/watched-cves/${encodeURIComponent(id)}`))
}

export function unwatchCve(id: string): Promise<void> {
  return run(() => sendJson("DELETE", `/alerts/watched-cves/${encodeURIComponent(id)}`))
}
