/**
 * Results of abuse reports (M26 outcomes, M27 takedown tracking; docs/dev/design/m26.md section 11 and
 * docs/dev/design/m27.md section 11): shapes, vocabulary and calls. Percentages are ratios (0 to 1);
 * durations are seconds. Target values (URLs, hosts) are shown defanged and never as links.
 */
import { t, tk } from "@/i18n"
import { getJson, sendJson, type Page } from "./api"
import type { ReportKind } from "./abuse"
import type { Outcome } from "./replies"

// --- M26: outcomes ------------------------------------------------------------------

export type OutcomeGroup = "kind" | "asn" | "country" | "recipient"
export type OutcomeCounts = Partial<Record<Outcome, number>>

export interface OutcomeTotals {
  sent: number
  /** Reports sent at least 3 days before the end of the period: the base of the answered rate. */
  eligible: number
  /** Among the eligible ones: an effective outcome other than none or bounce. */
  answered: number
  no_answer: number
  by_outcome: OutcomeCounts
  first_reply_p50_s: number | null
  first_reply_p90_s: number | null
  resolved_p50_s: number | null
}

export interface OutcomeGroupRow {
  /** Group key: a kind, an ASN number, a country code or a recipient id. */
  key: string
  label: string
  sent: number
  eligible: number
  answered: number
  by_outcome: OutcomeCounts
  first_reply_p50_s: number | null
}

export interface OutcomesResponse {
  since: string
  until: string
  group: OutcomeGroup
  totals: OutcomeTotals
  groups: OutcomeGroupRow[]
}

export interface TimelinePoint {
  /** Start of the bucket (ISO date). */
  start: string
  sent: Partial<Record<ReportKind, number>>
  sent_total: number
  answered: number
  resolved: number
}

export interface OutcomeTimeline {
  bucket: "week" | "month"
  since: string
  until: string
  points: TimelinePoint[]
}

/** Outcomes shown in "Did anyone answer?", best first. Rejected and bounce use the warning tone. */
export const ANSWER_ROWS = [
  "resolved",
  "ticket_opened",
  "human_reply",
  "auto_ack",
  "rejected",
  "bounce",
  "unknown",
  "none",
] as const satisfies readonly Outcome[]

export const GROUP_OPTIONS = [
  {
    value: "asn",
    get label() {
      return t("results_group_asn")
    },
  },
  {
    value: "recipient",
    get label() {
      return t("results_group_recipient")
    },
  },
  {
    value: "country",
    get label() {
      return t("results_group_country")
    },
  },
  {
    value: "kind",
    get label() {
      return t("results_group_kind")
    },
  },
] as const satisfies readonly { value: OutcomeGroup; label: string }[]

// --- M27: takedown ------------------------------------------------------------------

export type TargetKind = "url" | "ip" | "domain"
export type TargetRole = "payload_url" | "payload_host" | "c2" | "attack_source"
export type TargetState = "up" | "down" | "changed" | "unknown"
export type Channel = "mail" | "form" | "urlhaus" | "threatfox"

export const CHANNEL_LABEL: Record<Channel, string> = {
  get mail() {
    return t("results_channel_mail")
  },
  /** Submitted by hand through the provider's web form (M38). */
  get form() {
    return t("results_channel_form")
  },
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
}
export const ROLE_LABEL: Record<TargetRole, string> = {
  get payload_url() {
    return t("results_role_payload_url")
  },
  get payload_host() {
    return t("results_role_payload_host")
  },
  get c2() {
    return t("results_role_c2")
  },
  get attack_source() {
    return t("results_role_attack_source")
  },
}

/** Counts behind "N of M went down within H". Eligible = old enough to judge (right-censoring). */
export interface TakedownCounts {
  tracked: number
  eligible_48h: number
  down_48h: number
  eligible_7d: number
  down_7d: number
  eligible_30d: number
  down_30d: number
  ttd_p50_s: number | null
  ttd_n: number
  still_up_30d: number
}

export interface TakedownSummary {
  /** Only ever false when the server says tracking is off. */
  enabled?: boolean
  since: string
  until: string
  urls: TakedownCounts
  hosts: TakedownCounts
  attack_sources: { tracked: number; quiet: number; active: number }
  c2: { tracked: number; still_used: number }
  /** `answered` is null while reply tracking (M26) is not available. */
  reports: { sent: number; answered: number | null; first_reply_p50_s: number | null }
}

export interface CurvePoint {
  hours: number
  eligible: number
  down: number
  /** Share of eligible targets that were down by then (0 to 1); null when none is eligible. */
  percent: number | null
}

export interface CurveSeries {
  kind: "url" | "host"
  points: CurvePoint[]
}

export interface TakedownCurve {
  since: string
  until: string
  series: CurveSeries[]
}

export interface ProviderRow {
  provider_key: string
  name: string | null
  asn: number | null
  country: string | null
  targets: number
  eligible_48h: number
  down_48h: number
  percent_48h: number | null
  eligible_30d: number
  down_30d: number
  percent_30d: number | null
  ttd_p50_s: number | null
  ttd_n: number
  still_up: number
  reports_sent: number
  reports_answered: number | null
  percent_answered: number | null
  first_reply_p50_s: number | null
}

export interface Target {
  id: number
  kind: TargetKind
  role: TargetRole
  /** Raw value; the UI defangs it. */
  value: string
  parent_id: number | null
  provider_key: string
  provider_name: string | null
  asn: number | null
  country: string | null
  reported_at: string
  channels: Channel[]
  state: TargetState
  state_source: string | null
  state_since: string | null
  tracking: boolean
  track_until: string
  http_eligible: boolean
  demo: boolean
  /** Already down when the report was written: left out of the statistics. */
  down_before_report: boolean
  last_up_at: string | null
  first_down_at: string | null
  /** Seconds from report to the first confirmed down check, an upper bound. */
  ttd_s: number | null
  resurrections: number
  last_check_at: string | null
}

export type CheckMethod = "http" | "urlhaus" | "threatfox" | "abuseipdb" | "sightings" | "samples"

export interface TargetCheck {
  id: number
  checked_at: string
  method: CheckMethod
  /** A short code such as `same`, `http_404` or `online`; see RESULT_WORD. */
  outcome: string
  http_status: number | null
  sha256: string | null
  bytes: number | null
  duration_ms: number | null
  detail: Record<string, unknown>
}

export const METHOD_LABEL: Record<CheckMethod, string> = {
  get http() {
    return t("results_method_http")
  },
  get urlhaus() {
    return t("results_method_urlhaus")
  },
  get threatfox() {
    return t("results_method_threatfox")
  },
  get abuseipdb() {
    return t("results_method_abuseipdb")
  },
  get sightings() {
    return t("results_method_sightings")
  },
  get samples() {
    return t("results_method_samples")
  },
}

/** What a check found, in words (message keys). Unknown codes fall back to the code itself. */
export const RESULT_WORD: Record<string, string> = {
  same: tk("results_word_same"),
  changed: tk("results_word_changed"),
  changed_not_stored: tk("results_word_changed_not_stored"),
  up_unhashed: tk("results_word_up_unhashed"),
  http_404: tk("results_word_http_404"),
  http_410: tk("results_word_http_410"),
  http_4xx: tk("results_word_http_4xx"),
  http_5xx: tk("results_word_http_5xx"),
  suspended_page: tk("results_word_suspended_page"),
  empty: tk("results_word_empty"),
  unreachable: tk("results_word_unreachable"),
  timeout: tk("results_word_timeout"),
  refused: tk("results_word_refused"),
  redirect_limit: tk("results_word_redirect_limit"),
  bad_redirect: tk("results_word_bad_redirect"),
  online: tk("results_word_online"),
  offline: tk("results_word_offline"),
  listed: tk("results_word_listed"),
  seen: tk("results_word_seen"),
  not_seen: tk("results_word_not_seen"),
  new_sample: tk("results_word_new_sample"),
}

export const resultWord = (code: string): string => {
  const key = RESULT_WORD[code]
  return key ? t(key) : code.replaceAll("_", " ")
}

/** Results that mean the target is gone or quiet. */
export const DOWN_RESULTS: readonly string[] = [
  "http_404",
  "http_410",
  "http_4xx",
  "suspended_page",
  "empty",
  "unreachable",
  "timeout",
  "http_5xx",
  "offline",
  "not_seen",
]

export interface TargetDetail {
  target: Target
  children: Target[]
  links: { reports: string[] }
  /** Newest first, at most 200. */
  checks: TargetCheck[]
  ttd: {
    seconds: number | null
    /** The last time it was seen up. */
    down_after: string | null
    /** The first confirmed down. */
    down_before: string | null
  }
  baseline_sha256: string | null
  last_sha256: string | null
}

export interface TargetFilters {
  state?: TargetState
  kind?: string
  role?: TargetRole
  provider?: string
  channel?: Channel
  q?: string
}

/** The hours of the curve: tick labels. */
export const CURVE_HOURS = [1, 6, 24, 48, 72, 168, 336, 720] as const

// --- M38: do reports make a difference? ---------------------------------------------

export type EffectVerdict = "not_enough_data" | "lower" | "no_clear_difference" | "higher"

/** One horizon of the effect measure. Shares and bounds are null below the minimum. */
export interface ReportEffect {
  horizon: 7 | 30
  verdict: EffectVerdict
  /** Observed pairs, and the minimum before any number is shown. */
  pairs: number
  needed: number
  /** Pairs where one source was seen and the other was not, and their minimum. */
  discordant: number
  needed_discordant: number
  seen_reported: number | null
  seen_control: number | null
  difference: number | null
  lo: number | null
  hi: number | null
  /** The verdict sentence, fixed wording from the server. */
  sentence: string
  /** "between 9 and 37 points lower for reported sources", or null. */
  interval: string | null
}

export interface ReportEffectMethod {
  pairs_made: number
  tiers: Partial<Record<"H" | "A" | "B" | "C", number>>
  waiting: number
  not_observed: number
  control_reported: number
  network_reported: number
  unmatched: number
  unmatched_reasons: Partial<Record<"no_control" | "no_activity" | "network_reported", number>>
  holdout_pct: number
  held_now: number
}

export interface ReportEffectResponse {
  since: string
  until: string
  available: boolean
  running: boolean
  effect: ReportEffect
  method: ReportEffectMethod
}

/** A share as a whole percentage, half up (the server rounds the same way). */
export const wholePercent = (share: number): string =>
  t("results_percent_whole", { n: Math.floor(share * 100 + 0.5) })

// --- Calls --------------------------------------------------------------------------

export interface ResultFilters {
  since?: string
  until?: string
  kind?: string
  channel?: Channel
  provider?: string
}

export const resultKeys = {
  all: ["results"] as const,
  outcomes: (f: object) => ["results", "outcomes", f] as const,
  timeline: (bucket: string) => ["results", "timeline", bucket] as const,
  summary: (f: object) => ["results", "summary", f] as const,
  curve: (f: object) => ["results", "curve", f] as const,
  providers: (f: object) => ["results", "providers", f] as const,
  targets: (f: object) => ["results", "targets", f] as const,
  target: (id: number) => ["results", "target", id] as const,
  effect: (f: object) => ["results", "effect", f] as const,
}

export const resultsApi = {
  outcomes: (p: { since?: string; until?: string; group: OutcomeGroup }) =>
    getJson<OutcomesResponse>("/abuse/outcomes", p),
  timeline: (bucket: "week" | "month") =>
    getJson<OutcomeTimeline>("/abuse/outcomes/timeline", { bucket }),
  summary: (f: ResultFilters) => getJson<TakedownSummary>("/takedown/summary", { ...f }),
  curve: (f: ResultFilters) => getJson<TakedownCurve>("/takedown/curve", { ...f }),
  providers: (f: ResultFilters, sort?: string) =>
    getJson<{ items: ProviderRow[] }>("/takedown/providers", { ...f, sort, limit: 200 }),
  targets: (f: TargetFilters & ResultFilters, cursor?: string | null) =>
    getJson<Page<Target>>("/takedown/targets", {
      ...f,
      cursor: cursor ?? undefined,
      limit: 50,
    }),
  target: (id: number) => getJson<TargetDetail>(`/takedown/targets/${id}`),
  effect: (p: { since?: string; until?: string; horizon: 7 | 30 }) =>
    getJson<ReportEffectResponse>("/results/effect", p),
  recheck: (id: number) =>
    sendJson<{ id: number; http: boolean; listing: boolean }>(
      "POST",
      `/takedown/targets/${id}/recheck`,
    ),
  stop: (id: number) =>
    sendJson<{ id: number; tracking: boolean }>("POST", `/takedown/targets/${id}/stop`),
}
