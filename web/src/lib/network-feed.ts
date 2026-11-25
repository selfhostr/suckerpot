/**
 * The SuckerPot community lists (M30, docs/dev/design/m30.md sections 4, 6 and 10.5): shapes of the
 * node API under `/api/v1/network/feed`, the plain-English sentences of the Network tab of the
 * Blocklists page and the calls. The mocks in `src/mocks/network-feed.ts` match these types
 * exactly (a test checks it).
 *
 * The lists are public and optional. Nothing here contacts the feed host: the node API serves
 * what the ingest worker verified and stored, and the URLs are only shown, to copy.
 */
import { getJson, type Page } from "./api"
import { lazyText } from "./defend"
import { t, tk } from "@/i18n"

// --- Shapes ------------------------------------------------------------------------

export type FeedState = "disabled" | "never" | "ok" | "stale" | "error"
export type FeedListId = "inbound" | "outbound" | "outbound-domains"
export type FeedDirection = "inbound" | "outbound"
export type FeedFormat = "txt" | "v4" | "v6" | "nft" | "ipset" | "rsc" | "csv" | "json" | "stix"
export type FeedTier = "standard" | "high"

export const FEED_STATES: readonly FeedState[] = ["disabled", "never", "ok", "stale", "error"]
export const FEED_LIST_IDS: readonly FeedListId[] = ["inbound", "outbound", "outbound-domains"]
export const FEED_FORMATS: readonly FeedFormat[] = [
  "txt",
  "v4",
  "v6",
  "nft",
  "ipset",
  "rsc",
  "csv",
  "json",
  "stix",
]

/** One downloadable file of a list. */
export interface FeedFile {
  name: string
  format: FeedFormat
  /** `high` for the `-high` files (the subset confirmed by more sensors), else `standard`. */
  tier: FeedTier
  /** The public address, built from the fixed file names: it exists even when fetching is off. */
  url: string
}

export interface FeedList {
  id: FeedListId
  direction: FeedDirection
  entries: number
  /** Entries of the high tier (a subset of `entries`). */
  high: number
  /** Entries whose value reached this sensor in the last 30 days. */
  seen_here: number
  /** Entries this sensor helped confirm. `null` unless this system is a network member. */
  helped: number | null
  files: FeedFile[]
}

/** `GET /api/v1/network/feed/status` (any signed-in user). Never 404. */
export interface FeedStatus {
  /** `NETWORK_FEED_ENABLED` in .env. */
  enabled_env: boolean
  /** Whether the feed address and key are set. */
  configured: boolean
  state: FeedState
  error_code: string | null
  serial: number | null
  generated_at: string | null
  valid_until: string | null
  last_ok_at: string | null
  signature: "verified" | null
  /** Whether this system is a member of the network (M29). */
  member: boolean
  /** The public base address of the lists, e.g. "https://feeds.example.org/v1". */
  public_base_url: string | null
  lists: FeedList[]
  local_mirror: { feeds_enabled: boolean }
}

/**
 * One row of `GET /api/v1/network/feed/entries`. Mirrors the stored columns of
 * `network_feed_entries` (section 10.3); the feed itself never carries who confirmed an entry.
 */
export interface FeedEntry {
  list: FeedListId
  /** One address or one host name. */
  value: string
  /** 4 or 6 for an address, `null` for a host name. */
  family: 4 | 6 | null
  tier: FeedTier
  categories: string[]
  services: string[]
  tags: string[]
  families: string[]
  ports: number[]
  /** YYYY-MM-DD */
  first_seen: string
  last_seen: string
  expires: string
  reported: boolean
  seen_here: boolean
  /** `true` when this sensor helped confirm it. `null` unless this system is a member. */
  helped: boolean | null
}

export interface FeedFilters {
  list?: FeedListId | undefined
  tier?: FeedTier | undefined
  q?: string | undefined
  seen_here?: boolean | undefined
}

export const feedKeys = {
  status: ["network", "feed", "status"] as const,
  entries: (f: FeedFilters) => ["network", "feed", "entries", f] as const,
}

export const feedApi = {
  status: () => getJson<FeedStatus>("/network/feed/status"),
  entries: (f: FeedFilters, cursor?: string | null, limit = 50) =>
    getJson<Page<FeedEntry>>("/network/feed/entries", {
      list: f.list,
      tier: f.tier,
      q: f.q,
      seen_here: f.seen_here ? "1" : undefined,
      cursor: cursor ?? undefined,
      limit,
    }),
}

// --- Words -------------------------------------------------------------------------

/** Number of independent sensors that must confirm a host before it is listed. */
export const MIN_CONFIRMING_SENSORS = 5

export interface ListMeta {
  title: string
  /** What the list does for a firewall, said in words and never by colour. */
  directionLabel: string
  purpose: string
  startHere: boolean
}

export const LIST_META: Record<FeedListId, ListMeta> = {
  outbound: lazyText(
    {
      title: tk("netfeed_list_outbound_title"),
      directionLabel: tk("netfeed_list_outbound_direction"),
      purpose: tk("netfeed_list_outbound_purpose"),
    },
    { startHere: true },
  ),
  inbound: lazyText(
    {
      title: tk("netfeed_list_inbound_title"),
      directionLabel: tk("netfeed_list_inbound_direction"),
      purpose: tk("netfeed_list_inbound_purpose"),
    },
    { startHere: false },
  ),
  "outbound-domains": lazyText(
    {
      title: tk("netfeed_list_domains_title"),
      directionLabel: tk("netfeed_list_domains_direction"),
      purpose: tk("netfeed_list_domains_purpose"),
    },
    { startHere: false },
  ),
}

export const FORMAT_LABEL: Record<FeedFormat, string> = lazyText({
  txt: tk("netfeed_format_txt"),
  v4: tk("netfeed_format_v4"),
  v6: tk("netfeed_format_v6"),
  nft: tk("netfeed_format_nft"),
  ipset: tk("netfeed_format_ipset"),
  rsc: tk("netfeed_format_rsc"),
  csv: tk("netfeed_format_csv"),
  json: tk("netfeed_format_json"),
  stix: tk("netfeed_format_stix"),
})

export const CATEGORY_LABEL: Record<string, string> = lazyText({
  payload_host: tk("netfeed_category_payload_host"),
  c2: tk("netfeed_category_c2"),
  attack_source: tk("netfeed_category_attack_source"),
  scanner: tk("netfeed_category_scanner"),
  bruteforce: tk("netfeed_category_bruteforce"),
})

/** Categories that mean harm done, shown with the severe marker (shape and word, not colour). */
export const SEVERE_CATEGORIES: readonly string[] = ["payload_host", "c2"]

export function categoryLabel(category: string): string {
  return CATEGORY_LABEL[category] ?? category.replace(/_/g, " ")
}

/** The tier of a file, as the API says it. */
export function fileTier(file: FeedFile): FeedTier {
  return file.tier
}

/** Files of one tier in the order of FEED_FORMATS. */
export function formatsOf(list: FeedList, tier: FeedTier): FeedFile[] {
  return FEED_FORMATS.flatMap((fmt) =>
    list.files.filter((f) => f.format === fmt && fileTier(f) === tier),
  )
}

export function listById(s: FeedStatus | undefined, id: FeedListId): FeedList | undefined {
  return s?.lists.find((l) => l.id === id)
}

export function totalEntries(s: FeedStatus): number {
  return s.lists.reduce((n, l) => n + l.entries, 0)
}

/** True when the lists exist but nobody confirmed anything yet. */
export function isEmptyForNow(s: FeedStatus): boolean {
  return s.state === "ok" && totalEntries(s) === 0
}

export const FEED_ERROR_TEXT: Record<string, string> = lazyText({
  not_configured: tk("netfeed_error_not_configured"),
  egress_closed: tk("netfeed_error_egress_closed"),
  bad_signature: tk("netfeed_error_bad_signature"),
  feed_rollback: tk("netfeed_error_feed_rollback"),
  feed_expired: tk("netfeed_error_feed_expired"),
  feed_invalid: tk("netfeed_error_feed_invalid"),
  too_large: tk("netfeed_error_too_large"),
  unreachable: tk("netfeed_error_unreachable"),
})

export function describeFeedError(code: string | null): string | null {
  if (!code) return null
  const known = FEED_ERROR_TEXT[code]
  if (known) return known
  return code.startsWith("http_")
    ? t("netfeed_error_http", { code: code.slice(5) })
    : t("netfeed_error_generic")
}

/** The sentence at the top of the tab. */
export function feedSentence(s: FeedStatus): string {
  const hosts =
    (listById(s, "outbound")?.entries ?? 0) + (listById(s, "outbound-domains")?.entries ?? 0)
  const sources = listById(s, "inbound")?.entries ?? 0
  if (hosts + sources === 0) return t("netfeed_sentence_empty", { min: MIN_CONFIRMING_SENSORS })
  const seen = s.lists.reduce((n, l) => n + l.seen_here, 0)
  return t("netfeed_sentence_summary", { hosts, sources, min: MIN_CONFIRMING_SENSORS, seen })
}

export type FeedTone = "ok" | "warning"

/** The one-line status next to the sentence: what it is, and whether it needs a look. */
export function feedStatusLine(
  s: FeedStatus,
  fmt: (iso: string) => string,
): { tone: FeedTone; label: string; detail: string | null } {
  switch (s.state) {
    case "ok":
      return {
        tone: "ok",
        label: s.last_ok_at
          ? t("netfeed_status_updated_at", { when: fmt(s.last_ok_at) })
          : t("netfeed_status_updated"),
        detail: s.signature === "verified" ? t("netfeed_status_verified") : null,
      }
    case "stale":
      return {
        tone: "warning",
        label: t("netfeed_status_stale"),
        detail: s.last_ok_at
          ? t("netfeed_status_stale_since", { when: fmt(s.last_ok_at) })
          : t("netfeed_status_stale_late"),
      }
    case "error":
      return {
        tone: "warning",
        label: t("netfeed_status_failed"),
        detail: describeFeedError(s.error_code),
      }
    case "never":
      return {
        tone: "ok",
        label: t("netfeed_status_never"),
        detail: t("netfeed_status_never_detail"),
      }
    default:
      return { tone: "ok", label: t("netfeed_status_off"), detail: null }
  }
}

/** Sentence above the entries table, from the filters in the URL. */
export function entriesFinding(f: FeedFilters): string {
  return t("netfeed_entries_finding", {
    tier: f.tier === "high" ? "high" : "any",
    list: f.list === "outbound-domains" ? "domains" : (f.list ?? "all"),
    seen: f.seen_here ? "yes" : "no",
  })
}

export type FirewallApp = "opnsense" | "pfsense" | "nftables"

/** The fields to fill for a firewall, from the real file address. */
export function usageSteps(app: FirewallApp, url: string): string[] {
  switch (app) {
    case "opnsense":
      return [
        t("netfeed_step_opnsense_open"),
        t("netfeed_step_opnsense_type"),
        t("netfeed_step_content", { url }),
        t("netfeed_step_opnsense_rule"),
      ]
    case "pfsense":
      return [
        t("netfeed_step_pfsense_open"),
        t("netfeed_step_pfsense_type"),
        t("netfeed_step_pfsense_url", { url }),
        t("netfeed_step_pfsense_rule"),
      ]
    case "nftables":
      return [
        t("netfeed_step_nft_fetch", {
          command: `curl -fsS -o /etc/nftables.d/suckerpot-outbound.nft ${url}`,
        }),
        t("netfeed_step_nft_load", { command: "nft -f /etc/nftables.d/suckerpot-outbound.nft" }),
        t("netfeed_step_nft_rule"),
      ]
  }
}

const PLACEHOLDER_BASE = "https://feeds.example.org/v1"

/** The address of the outbound list for an app, from the status (or a placeholder). */
export function addressFor(app: FirewallApp, status: FeedStatus | undefined): string {
  const outbound = status?.lists.find((l) => l.id === "outbound")
  const wanted = app === "nftables" ? "nft" : "txt"
  const found = outbound?.files.find((f) => f.format === wanted && fileTier(f) === "standard")
  return found?.url ?? `${status?.public_base_url ?? PLACEHOLDER_BASE}/outbound.${wanted}`
}
