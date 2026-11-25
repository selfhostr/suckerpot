/**
 * Defend (M16): blocklists, detection rules, the exposure check and the feed tokens. Everything
 * here is derived from what the honeypot recorded; nothing is scanned or contacted. The sentence
 * builders are pure so they can be unit-tested.
 */
import { ApiError, API_BASE, getJson, sendJson, type Page } from "@/lib/api"
import { sensorMeta } from "@/lib/sensors"
import { intlLocale, t, tk } from "@/i18n"

/**
 * A table of texts that are translated when they are read, not when the module loads: `t()` must
 * not run at import time, and a language change shows at once. Reading `table.label` is a call to
 * `t()`, so it only works inside render (or code called from render).
 */
export function lazyText<K extends string, X extends object = object>(
  keys: Record<K, string>,
  extra?: X,
): Record<K, string> & X {
  const out = { ...extra } as Record<K, string> & X
  for (const name of Object.keys(keys) as K[]) {
    const key = keys[name]
    Object.defineProperty(out, name, { enumerable: true, get: () => t(key) })
  }
  return out
}

/** "a, b and c" in the active language ("and" is the locale's own word). */
export function joinList(items: readonly string[]): string {
  const locale = intlLocale()
  return new Intl.ListFormat(locale === "en" ? "en-GB" : locale, {
    style: "long",
    type: "conjunction",
  }).format(items)
}

/* --- Blocklists --------------------------------------------------------- */

export const BLOCK_KINDS = ["ip", "domain", "url", "hash"] as const
export type BlockKind = (typeof BLOCK_KINDS)[number]

export function isBlockKind(v: unknown): v is BlockKind {
  return typeof v === "string" && (BLOCK_KINDS as readonly string[]).includes(v)
}

export const KIND_META: Record<
  BlockKind,
  {
    /** Plural title: tiles, segmented controls, buttons. */
    label: string
    /** Singular title: form labels ("IP address"). */
    singular: string
    /** Plural inside a sentence ("IP addresses and domains"). */
    phrase: string
  }
> = {
  ip: lazyText({
    label: tk("kinds_ip_label"),
    singular: tk("kinds_ip_singular"),
    phrase: tk("kinds_ip_phrase"),
  }),
  domain: lazyText({
    label: tk("kinds_domain_label"),
    singular: tk("kinds_domain_singular"),
    phrase: tk("kinds_domain_phrase"),
  }),
  url: lazyText({
    label: tk("kinds_url_label"),
    singular: tk("kinds_url_singular"),
    phrase: tk("kinds_url_phrase"),
  }),
  hash: lazyText({
    label: tk("kinds_hash_label"),
    singular: tk("kinds_hash_singular"),
    phrase: tk("kinds_hash_phrase"),
  }),
}

/** "1 address", "12 addresses": a count with the noun of the kind, as one plural message. */
export function kindCount(kind: BlockKind, count: number): string {
  switch (kind) {
    case "ip":
      return t("kinds_ip_count", { count })
    case "domain":
      return t("kinds_domain_count", { count })
    case "url":
      return t("kinds_url_count", { count })
    case "hash":
      return t("kinds_hash_count", { count })
  }
}

/** Scores: "listed" entries go to the firewall, "high" ones are the surest. */
export const LISTED_SCORE = 50
export const HIGH_SCORE = 70
/** The floor of the "Everything" preset: below it an entry was barely seen. */
export const EVERYTHING_SCORE = 20
export const DEFAULT_MIN_SCORE = LISTED_SCORE

/**
 * The three minimum-score choices, the same everywhere: the list filter, the export and the feed
 * tokens. "Balanced" is the default.
 */
export const SCORE_PRESETS = [
  lazyText(
    {
      label: tk("defend_preset_high_label"),
      hint: tk("defend_preset_high_hint"),
    },
    { score: HIGH_SCORE },
  ),
  lazyText(
    {
      label: tk("defend_preset_balanced_label"),
      hint: tk("defend_preset_balanced_hint"),
    },
    { score: LISTED_SCORE },
  ),
  lazyText(
    {
      label: tk("defend_preset_everything_label"),
      hint: tk("defend_preset_everything_hint"),
    },
    { score: EVERYTHING_SCORE },
  ),
] as const

export type ScorePreset = (typeof SCORE_PRESETS)[number]

export function scorePreset(score: number): ScorePreset | undefined {
  return SCORE_PRESETS.find((p) => p.score === score)
}

/** Segmented-control options: "High confidence 70+", "Balanced 50+", "Everything 20+". */
export const SCORE_OPTIONS = SCORE_PRESETS.map((p) => ({
  value: String(p.score),
  get label() {
    return t("defend_score_option", { label: p.label, score: String(p.score) })
  },
}))

/** A minimum score from the URL: a preset, else the default. */
export function parseMinScore(raw: string | null): number {
  const n = Number(raw)
  return raw !== null && scorePreset(n) ? n : DEFAULT_MIN_SCORE
}

export interface KindSummary {
  kind: BlockKind
  total: number
  high: number
  listed: number
}

export interface DefendSummary {
  computed_at: string | null
  /** False: the worker is switched off. Null: it has not reported yet. */
  worker_enabled: boolean | null
  feeds_enabled: boolean
  kinds: KindSummary[]
  top_reasons: { reason: string; count: number }[]
  demo_entries: number
  overrides: number
}

export type OverrideAction = "allow" | "block"

export interface BlockEntry {
  kind: BlockKind
  value: string
  score: number
  reasons: string[]
  first_seen: string
  last_seen: string
  sessions: number
  sources: number
  campaign_ids: number[]
  benign: boolean
  demo: boolean
  override: OverrideAction | null
}

export interface OverrideItem {
  id: number
  kind: BlockKind
  value: string
  action: OverrideAction
  note: string | null
  created_by: string
  created_at: string
  expires_at: string | null
}

export interface BlocklistFilters {
  kind?: BlockKind | undefined
  min_score: number
  q?: string | undefined
  reason?: string | undefined
  include_benign?: boolean | undefined
}

/** Plain-English labels for the reason codes the scorer writes. */
export const REASON_LABELS: Record<string, { label: string; sentence: string }> = {
  "brute-force": lazyText({
    label: tk("defend_reason_brute_force_label"),
    sentence: tk("defend_reason_brute_force_sentence"),
  }),
  "login-succeeded": lazyText({
    label: tk("defend_reason_login_succeeded_label"),
    sentence: tk("defend_reason_login_succeeded_sentence"),
  }),
  "ran-commands": lazyText({
    label: tk("defend_reason_ran_commands_label"),
    sentence: tk("defend_reason_ran_commands_sentence"),
  }),
  "dropped-malware": lazyText({
    label: tk("defend_reason_dropped_malware_label"),
    sentence: tk("defend_reason_dropped_malware_sentence"),
  }),
  "exploit-attempt": lazyText({
    label: tk("defend_reason_exploit_attempt_label"),
    sentence: tk("defend_reason_exploit_attempt_sentence"),
  }),
  "reported-abusive": lazyText({
    label: tk("defend_reason_reported_abusive_label"),
    sentence: tk("defend_reason_reported_abusive_sentence"),
  }),
  "multi-sensor": lazyText({
    label: tk("defend_reason_multi_sensor_label"),
    sentence: tk("defend_reason_multi_sensor_sentence"),
  }),
  campaign: lazyText({
    label: tk("defend_reason_campaign_label"),
    sentence: tk("defend_reason_campaign_sentence"),
  }),
  "repeat-visitor": lazyText({
    label: tk("defend_reason_repeat_visitor_label"),
    sentence: tk("defend_reason_repeat_visitor_sentence"),
  }),
  "mass-scanner": lazyText({
    label: tk("defend_reason_mass_scanner_label"),
    sentence: tk("defend_reason_mass_scanner_sentence"),
  }),
  "download-source": lazyText({
    label: tk("defend_reason_download_source_label"),
    sentence: tk("defend_reason_download_source_sentence"),
  }),
  "contacted-by-attacker": lazyText({
    label: tk("defend_reason_contacted_by_attacker_label"),
    sentence: tk("defend_reason_contacted_by_attacker_sentence"),
  }),
  "known-malware": lazyText({
    label: tk("defend_reason_known_malware_label"),
    sentence: tk("defend_reason_known_malware_sentence"),
  }),
  "malware-family": lazyText({
    label: tk("defend_reason_malware_family_label"),
    sentence: tk("defend_reason_malware_family_sentence"),
  }),
  "seen-from-many-sources": lazyText({
    label: tk("defend_reason_seen_from_many_sources_label"),
    sentence: tk("defend_reason_seen_from_many_sources_sentence"),
  }),
  "file-hash": lazyText({
    label: tk("defend_reason_file_hash_label"),
    sentence: tk("defend_reason_file_hash_sentence"),
  }),
  "probable-c2": lazyText({
    label: tk("defend_reason_probable_c2_label"),
    sentence: tk("defend_reason_probable_c2_sentence"),
  }),
  "manual-block": lazyText({
    label: tk("defend_reason_manual_block_label"),
    sentence: tk("defend_reason_manual_block_sentence"),
  }),
  "network-confirmed": lazyText({
    label: tk("defend_reason_network_confirmed_label"),
    sentence: tk("defend_reason_network_confirmed_sentence"),
  }),
}

export function reasonLabel(code: string): string {
  return REASON_LABELS[code]?.label ?? code.replace(/-/g, " ")
}

export function reasonSentence(code: string): string {
  return REASON_LABELS[code]?.sentence ?? reasonLabel(code)
}

/** The word that goes with a score, so the meter's tone is never the only cue. */
export function scoreBand(score: number): "high" | "listed" | "seen" {
  return score >= HIGH_SCORE ? "high" : score >= LISTED_SCORE ? "listed" : "seen"
}

export const BAND_LABEL = lazyText({
  high: tk("defend_band_high"),
  listed: tk("defend_band_listed"),
  seen: tk("defend_band_seen"),
})

/** "12 addresses, 3 domains and 2 URLs scored 50 or higher are ready for your firewall." */
export function blocklistSentence(s: DefendSummary | undefined): string {
  if (!s) return t("defend_blocklist_sentence_loading")
  const counts: { n: number; text: string }[] = []
  for (const kind of BLOCK_KINDS) {
    const k = s.kinds.find((x) => x.kind === kind)
    if (k && k.listed > 0) counts.push({ n: k.listed, text: kindCount(kind, k.listed) })
  }
  if (counts.length === 0) return t("defend_blocklist_sentence_none", { score: LISTED_SCORE })
  const list = joinList(counts.map((c) => c.text))
  const single = counts.length === 1 && counts[0]?.n === 1
  return t(single ? "defend_blocklist_sentence_one" : "defend_blocklist_sentence_many", {
    list,
    score: LISTED_SCORE,
  })
}

export interface ExportParams {
  kind: BlockKind
  format: "txt" | "alias" | "csv"
  minScore: number
  includeBenign?: boolean
}

/** The download link; a plain anchor, so the browser saves the file. Demo entries are never exported. */
export function exportUrl({ kind, format, minScore, includeBenign = false }: ExportParams): string {
  const qs = new URLSearchParams({
    kind,
    format: format === "alias" && kind !== "ip" ? "txt" : format,
    min_score: String(minScore),
  })
  if (includeBenign) qs.set("include_benign", "true")
  return `${API_BASE}/defend/export?${qs.toString()}`
}

export type Firewall = "opnsense" | "pfsense"

export const FIREWALL_LABEL: Record<Firewall, string> = {
  opnsense: "OPNsense",
  pfsense: "pfSense",
}

/** Step-by-step text for a URL-table alias; the same text is shown and copied. */
export function firewallInstructions(firewall: Firewall, feedUrlText: string): string[] {
  const where =
    firewall === "opnsense" ? "Firewall > Aliases, then Add" : "Firewall > Aliases > URLs, then Add"
  return [
    t("firewall_step_token", { url: feedUrlText }),
    t("firewall_step_open", { where }),
    t("firewall_step_name"),
    t("firewall_step_paste"),
    t("firewall_step_save"),
    t("firewall_step_log"),
  ]
}

export function instructionsText(firewall: Firewall, feedUrlText: string): string {
  return [
    t("firewall_instructions_title", { firewall: FIREWALL_LABEL[firewall] }),
    ...firewallInstructions(firewall, feedUrlText).map((s, i) => `${i + 1}. ${s}`),
  ].join("\n")
}

export const defendKeys = {
  summary: ["defend", "summary"] as const,
  blocklist: (f: object, limit: number) => ["defend", "blocklist", f, limit] as const,
  overrides: ["defend", "overrides"] as const,
  tokens: ["defend", "feed-tokens"] as const,
  detections: (kind: string, days: number) => ["defend", "detections", kind, days] as const,
  guidance: (days: number) => ["defend", "guidance", days] as const,
  inventory: ["defend", "inventory"] as const,
  exposure: (days: number) => ["defend", "exposure", days] as const,
}

/* --- Detections and guidance ------------------------------------------- */

export type RuleKind = "sigma" | "suricata"
export const RULE_KINDS: RuleKind[] = ["sigma", "suricata"]
export const PERIOD_DAYS = [7, 30, 90] as const
export const DEFAULT_DAYS = 30

export function parseDays(raw: string | null): number {
  const n = Number(raw)
  return (PERIOD_DAYS as readonly number[]).includes(n) ? n : DEFAULT_DAYS
}

export const RULE_KIND_META: Record<RuleKind, { label: string; hint: string; ext: string }> = {
  sigma: lazyText({ hint: tk("rule_kind_sigma_hint") }, { label: "Sigma", ext: ".yml" }),
  suricata: lazyText({ hint: tk("rule_kind_suricata_hint") }, { label: "Suricata", ext: ".rules" }),
}

export type RuleSource = "web-paths" | "commands" | "domains" | "urls" | "hashes" | "static"

export const SOURCE_LABELS: Record<RuleSource, string> = lazyText({
  "web-paths": tk("rule_source_web_paths"),
  commands: tk("rule_source_commands"),
  domains: tk("rule_source_domains"),
  urls: tk("rule_source_urls"),
  hashes: tk("rule_source_hashes"),
  static: tk("rule_source_static"),
})

export interface DetectionRule {
  id: string
  kind: RuleKind
  title: string
  severity: "notice" | "warning" | "severe"
  source: RuleSource
  rationale: string
  sessions: number
  sources: number
  text: string
}

export interface DetectionPage extends Page<DetectionRule> {
  generated_at: string
  days: number
  total: number
}

export interface GuidanceItem {
  tag: string
  title: string
  what: string
  look: string[]
  fix: string[]
  severity: "notice" | "warning" | "severe"
  seen: { sessions: number; sources: number; last_seen: string | null }
}

export function detectionsSentence(total: number | undefined, days: number): string {
  if (total === undefined) return t("rule_detections_lede")
  if (total === 0) return t("rule_detections_none", { days })
  return t("rule_detections_summary", { total, days })
}

export function evidenceLine(sessions: number, sources: number): string {
  return t("rule_evidence", { sessions, sources })
}

export function detectionsExportUrl(kind: RuleKind, days: number): string {
  return `${API_BASE}/defend/detections/export?kind=${kind}&days=${days}`
}

/* --- Exposure ----------------------------------------------------------- */

export type Exposure = "internet" | "vpn" | "internal"
export const EXPOSURE_OPTIONS: { value: Exposure; label: string }[] = [
  {
    value: "internet",
    get label() {
      return t("exposure_option_internet")
    },
  },
  {
    value: "vpn",
    get label() {
      return t("exposure_option_vpn")
    },
  },
  {
    value: "internal",
    get label() {
      return t("exposure_option_internal")
    },
  },
]
export const EXPOSURE_LABEL: Record<Exposure, string> = lazyText({
  internet: tk("exposure_label_internet"),
  vpn: tk("exposure_label_vpn"),
  internal: tk("exposure_label_internal"),
})

export interface InventoryItem {
  id: number
  name: string
  service: string
  product: string | null
  version: string | null
  exposure: Exposure
  notes: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface InventoryInput {
  name: string
  service: string
  product?: string | null
  version?: string | null
  exposure: Exposure
  notes?: string | null
}

export type Verdict = "internet_targeted" | "internet_quiet" | "private_targeted" | "private_quiet"

export const VERDICT_SENTENCE: Record<Verdict, string> = lazyText({
  internet_targeted: tk("exposure_verdict_internet_targeted"),
  internet_quiet: tk("exposure_verdict_internet_quiet"),
  private_targeted: tk("exposure_verdict_private_targeted"),
  private_quiet: tk("exposure_verdict_private_quiet"),
})

export interface ExposureService {
  item: InventoryItem
  label: string
  verdict: Verdict
  attacks: {
    sessions: number
    sources: number
    deep_sessions: number
    previous_sessions: number
    last_attack_at: string | null
  }
  top_tags: { tag: string; sessions: number }[]
  cves: { cve_id: string; title: string | null; cvss_score: number | null; in_kev: boolean }[]
  checks: string[]
}

export interface UnlistedService {
  service: string
  label: string
  sessions: number
  sources: number
  checks: string[]
}

export interface ExposureReport {
  days: number
  generated_at: string
  services: ExposureService[]
  unlisted: UnlistedService[]
}

/** "You told us you run 6 services; 4 of them face the internet and were targeted 1,204 times ..." */
export function exposureSentence(r: ExposureReport | undefined, days: number): string {
  if (!r) return t("exposure_sentence_loading")
  const n = r.services.length
  if (n === 0) {
    const seen = r.unlisted.reduce((sum, u) => sum + u.sessions, 0)
    return t("exposure_sentence_empty", { seen, days })
  }
  const facing = r.services.filter((s) => s.item.exposure === "internet")
  const hits = facing.reduce((sum, s) => sum + s.attacks.sessions, 0)
  return t("exposure_sentence_summary", { n, facing: facing.length, hits, days })
}

/** "up 20% from 120 before". Neutral words: more attacks are neither good nor bad news here. */
export function previousComparison(current: number, previous: number): string {
  if (previous === 0)
    return current === 0 ? t("exposure_prev_none_either") : t("exposure_prev_none")
  const change = (current - previous) / previous
  if (Math.abs(change) < 0.05) return t("exposure_prev_same", { previous })
  return t(change > 0 ? "exposure_prev_up" : "exposure_prev_down", {
    percent: Math.round(Math.abs(change) * 100),
    previous,
  })
}

/** Placeholder product and version for the inventory form, so the example fits the kind. */
export const PRODUCT_EXAMPLE: Record<string, { product: string; version: string }> = {
  ssh: { product: "OpenSSH", version: "9.6" },
  telnet: { product: "BusyBox", version: "1.36" },
  adb: { product: "Android", version: "13" },
  web: { product: "Apache", version: "2.4.58" },
  docker: { product: "Docker Engine", version: "27.3" },
  redis: { product: "Redis", version: "7.2" },
  mysql: { product: "MySQL", version: "8.0" },
  mssql: { product: "SQL Server", version: "2022" },
  rdp: { product: "Windows Server", version: "2022" },
  smb: { product: "Samba", version: "4.19" },
  sip: { product: "Asterisk", version: "20" },
  synology: { product: "Synology DSM", version: "7.2" },
}

export function serviceLabel(service: string): string {
  return sensorMeta(service)?.label ?? service.toUpperCase()
}

export function validateInventory(input: InventoryInput): { name?: string } {
  const name = input.name.trim()
  if (!name) return { name: t("inventory_name_required") }
  if (name.length > 80) return { name: t("inventory_name_too_long") }
  return {}
}

/* --- Feeds -------------------------------------------------------------- */

/**
 * What a feed token may read: the four blocklists, and the verified local mirror of the
 * community lists (M30; api/api/feed_tokens.py TOKEN_KINDS).
 */
export const TOKEN_KINDS = [...BLOCK_KINDS, "network"] as const
export type TokenKind = (typeof TOKEN_KINDS)[number]

const blockTokenKind = (k: BlockKind) => ({
  get label() {
    return KIND_META[k].label
  },
  get phrase() {
    return KIND_META[k].phrase
  },
})

export const TOKEN_KIND_META: Record<TokenKind, { label: string; phrase: string }> = {
  ip: blockTokenKind("ip"),
  domain: blockTokenKind("domain"),
  url: blockTokenKind("url"),
  hash: blockTokenKind("hash"),
  network: lazyText({
    label: tk("defend_token_kind_network_label"),
    phrase: tk("defend_token_kind_network_phrase"),
  }),
}

export interface FeedToken {
  id: number
  name: string
  hint: string
  kinds: TokenKind[]
  min_score: number
  include_benign: boolean
  created_by: string
  created_at: string
  expires_at: string | null
  revoked_at: string | null
  last_used_at: string | null
  last_used_ip: string | null
  use_count: number
  state: "active" | "revoked" | "expired"
}

export interface FeedTokenList {
  enabled: boolean
  items: FeedToken[]
}

export interface NewFeedToken {
  name: string
  kinds: TokenKind[]
  minScore: number
  includeBenign: boolean
  expiresInDays: number | null
}

export const EXPIRY_OPTIONS = [
  {
    value: "none",
    get label() {
      return t("defend_expiry_never")
    },
    days: null,
  },
  {
    value: "30",
    get label() {
      return t("defend_expiry_days", { count: 30 })
    },
    days: 30,
  },
  {
    value: "90",
    get label() {
      return t("defend_expiry_days", { count: 90 })
    },
    days: 90,
  },
  {
    value: "365",
    get label() {
      return t("defend_expiry_year")
    },
    days: 365,
  },
] as const

export function feedsSentence(list: FeedTokenList | undefined): string {
  if (!list) return t("defend_feeds_lede")
  if (!list.enabled) return t("defend_feeds_off")
  const active = list.items.filter((x) => x.state === "active").length
  if (active === 0) return t("defend_feeds_no_token")
  return t("defend_feeds_active", { count: active })
}

/** The kinds a token covers, as words: "IP addresses and domains". */
export function kindsPhrase(kinds: readonly TokenKind[]): string {
  const names = TOKEN_KINDS.filter((k) => kinds.includes(k)).map((k) => TOKEN_KIND_META[k].phrase)
  if (names.length <= 1) return names[0] ?? t("defend_kinds_nothing")
  return joinList(names)
}

/** The URL form works for firewalls that cannot send headers (OPNsense, pfSense URL tables). */
export function feedUrl(origin: string, token: string, kind: BlockKind = "ip"): string {
  return `${origin.replace(/\/+$/, "")}/feeds/${token}/${kind}.txt`
}

/** The local mirror of a community list, in URL form (the token covers "network"). */
export function networkFeedUrl(origin: string, token: string, list = "outbound"): string {
  return `${origin.replace(/\/+$/, "")}/feeds/${token}/network/${list}.txt`
}

export function networkFeedCurl(origin: string, token: string, list = "outbound"): string {
  return `curl -H "Authorization: Bearer ${token}" ${origin.replace(/\/+$/, "")}/feeds/network/${list}.txt`
}

export function feedCurl(origin: string, token: string, kind: BlockKind = "ip"): string {
  return `curl -H "Authorization: Bearer ${token}" ${origin.replace(/\/+$/, "")}/feeds/${kind}.txt`
}

/* --- Errors ------------------------------------------------------------- */

export type DefendFailure =
  "wrong-password" | "rate-limited" | "session" | "feeds-disabled" | "limit" | "invalid" | "network"

const FAILURE_MESSAGES: Record<DefendFailure, string> = lazyText({
  "wrong-password": tk("defend_error_wrong_password"),
  "rate-limited": tk("defend_error_rate_limited"),
  session: tk("defend_error_session"),
  "feeds-disabled": tk("defend_error_feeds_disabled"),
  limit: tk("defend_error_limit"),
  invalid: tk("defend_error_invalid"),
  network: tk("defend_error_network"),
})

export function classifyFailure(e: unknown): DefendFailure {
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return "wrong-password"
    if (e.code === "session_revoked" || e.status === 401) return "session"
    if (e.code === "feeds_disabled") return "feeds-disabled"
    if (e.code === "limit_reached") return "limit"
    if (e.status === 429) return "rate-limited"
    if (e.status === 422) return "invalid"
  }
  return "network"
}

/** A sentence for the person; for an invalid value the API's own explanation comes first. */
export function describeDefendError(e: unknown): string {
  const kind = classifyFailure(e)
  if (kind === "invalid" && e instanceof ApiError && e.message.length > 0 && e.code)
    return e.message
  return FAILURE_MESSAGES[kind]
}

/* --- Fetchers ------------------------------------------------------------ */

const cursorParams = (cursor: string | null | undefined, limit: number) => ({
  cursor: cursor ?? undefined,
  limit,
})

export const defendApi = {
  summary: () => getJson<DefendSummary>("/defend/summary"),
  blocklist: (f: BlocklistFilters, cursor: string | null | undefined, limit = 50) =>
    getJson<Page<BlockEntry>>("/defend/blocklist", {
      kind: f.kind,
      min_score: f.min_score,
      q: f.q,
      reason: f.reason,
      include_benign: f.include_benign ? "true" : undefined,
      ...cursorParams(cursor, limit),
    }),
  overrides: () => getJson<Page<OverrideItem>>("/defend/overrides", { limit: 200 }),
  feedTokens: () => getJson<FeedTokenList>("/defend/feed-tokens"),
  detections: (kind: RuleKind, days: number, cursor: string | null | undefined, limit = 10) =>
    getJson<DetectionPage>("/defend/detections", { kind, days, ...cursorParams(cursor, limit) }),
  guidance: (days: number) =>
    getJson<{ days: number; items: GuidanceItem[] }>("/defend/guidance", { days }),
  inventory: () => getJson<Page<InventoryItem>>("/defend/inventory", { limit: 200 }),
  exposure: (days: number) => getJson<ExposureReport>("/defend/exposure", { days }),
}

export function createOverride(input: {
  kind: BlockKind
  value: string
  action: OverrideAction
  note?: string
  expiresInDays?: number | null
  password: string
}): Promise<OverrideItem> {
  const body: Record<string, unknown> = {
    kind: input.kind,
    value: input.value,
    action: input.action,
    password: input.password,
  }
  if (input.note?.trim()) body.note = input.note.trim()
  if (input.expiresInDays) body.expires_in_days = input.expiresInDays
  return sendJson<OverrideItem>("POST", "/defend/overrides", body)
}

export const deleteOverride = (id: number, password: string) =>
  sendJson("DELETE", `/defend/overrides/${id}`, { password })

function inventoryBody(input: Partial<InventoryInput>) {
  const body: Record<string, unknown> = {}
  if (input.name !== undefined) body.name = input.name.trim()
  if (input.service !== undefined) body.service = input.service
  if (input.exposure !== undefined) body.exposure = input.exposure
  for (const key of ["product", "version", "notes"] as const) {
    const v = input[key]
    if (v !== undefined) body[key] = v?.trim() ? v.trim() : null
  }
  return body
}

export const createInventory = (input: InventoryInput) =>
  sendJson<InventoryItem>("POST", "/defend/inventory", inventoryBody(input))
export const updateInventory = (id: number, input: Partial<InventoryInput>) =>
  sendJson<InventoryItem>("PATCH", `/defend/inventory/${id}`, inventoryBody(input))
export const deleteInventory = (id: number) => sendJson("DELETE", `/defend/inventory/${id}`)

/** Creates a token. The secret is in the answer once and is never kept by this module. */
export function createFeedToken(
  input: NewFeedToken,
  password: string,
): Promise<{ token: string; item: FeedToken }> {
  const body: Record<string, unknown> = {
    name: input.name.trim(),
    kinds: input.kinds,
    min_score: input.minScore,
    include_benign: input.includeBenign,
    password,
  }
  if (input.expiresInDays) body.expires_in_days = input.expiresInDays
  return sendJson<{ token: string; item: FeedToken }>("POST", "/defend/feed-tokens", body)
}

export const revokeFeedToken = (id: number) =>
  sendJson<FeedToken>("POST", `/defend/feed-tokens/${id}/revoke`)
