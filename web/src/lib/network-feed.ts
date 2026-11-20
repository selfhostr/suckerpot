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
import { formatNumber, plural } from "./format"

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
  outbound: {
    title: "Outbound",
    directionLabel: "Blocks traffic leaving your network",
    purpose:
      "Malware download hosts and command servers. If a device inside your network reaches one, it is probably infected.",
    startHere: true,
  },
  inbound: {
    title: "Inbound",
    directionLabel: "Blocks traffic coming in",
    purpose:
      "Addresses that attacked several sensors. Useful in front of services you expose to the internet.",
    startHere: false,
  },
  "outbound-domains": {
    title: "Outbound domains",
    directionLabel: "Blocks names your devices look up",
    purpose: "The same kind of hosts, by name. For DNS filters such as Pi-hole or AdGuard Home.",
    startHere: false,
  },
}

export const FORMAT_LABEL: Record<FeedFormat, string> = {
  txt: "Plain text (one per line)",
  v4: "Plain text, IPv4 only",
  v6: "Plain text, IPv6 only",
  nft: "nftables",
  ipset: "ipset",
  rsc: "MikroTik script",
  csv: "CSV with details",
  json: "JSON with details",
  stix: "STIX 2.1",
}

export const CATEGORY_LABEL: Record<string, string> = {
  payload_host: "Malware host",
  c2: "Command server",
  attack_source: "Attack source",
  scanner: "Scanner",
  bruteforce: "Password guessing",
}

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

export const FEED_ERROR_TEXT: Record<string, string> = {
  not_configured: "The address or the key of the lists is not set.",
  egress_closed: "Outbound access is closed, so the lists could not be fetched.",
  bad_signature: "The signature did not verify, so the new lists were refused.",
  feed_rollback: "The lists offered were older than the ones already stored, so they were refused.",
  feed_expired: "The lists have expired and no fresh copy has been published.",
  feed_invalid: "The lists failed a check and were refused.",
  too_large: "The lists were larger than allowed and were refused.",
  unreachable: "The list server could not be reached.",
}

export function describeFeedError(code: string | null): string | null {
  if (!code) return null
  const known = FEED_ERROR_TEXT[code]
  if (known) return known
  return code.startsWith("http_")
    ? `The list server answered with an error (${code.slice(5)}).`
    : "The last fetch failed."
}

/** The sentence at the top of the tab. */
export function feedSentence(s: FeedStatus): string {
  const hosts =
    (listById(s, "outbound")?.entries ?? 0) + (listById(s, "outbound-domains")?.entries ?? 0)
  const sources = listById(s, "inbound")?.entries ?? 0
  if (hosts + sources === 0)
    return `The community lists are empty for now: no host has been confirmed by ${MIN_CONFIRMING_SENSORS} independent sensors yet.`
  const seen = s.lists.reduce((n, l) => n + l.seen_here, 0)
  const tail =
    seen > 0
      ? ` ${formatNumber(seen)} of them also reached this sensor.`
      : " None of them has reached this sensor yet."
  return `The SuckerPot network lists ${plural(hosts, "malware and command host")} and ${plural(sources, "attack source")}, each confirmed by at least ${MIN_CONFIRMING_SENSORS} independent sensors.${tail}`
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
        label: s.last_ok_at ? `Updated ${fmt(s.last_ok_at)}` : "Updated",
        detail: s.signature === "verified" ? "Signature verified" : null,
      }
    case "stale":
      return {
        tone: "warning",
        label: "Out of date",
        detail: `${s.last_ok_at ? `No fresh copy since ${fmt(s.last_ok_at)}. ` : "No fresh copy arrived in time. "}The entries stay readable here, but this dashboard stopped serving its copy to firewalls.`,
      }
    case "error":
      return {
        tone: "warning",
        label: "Last fetch failed",
        detail: describeFeedError(s.error_code),
      }
    case "never":
      return {
        tone: "ok",
        label: "Waiting for the first fetch",
        detail: "The worker fetches the lists about once an hour.",
      }
    default:
      return { tone: "ok", label: "Not fetched here", detail: null }
  }
}

/** Sentence above the entries table, from the filters in the URL. */
export function entriesFinding(f: FeedFilters): string {
  const tier = f.tier === "high" ? "high-tier " : ""
  const where =
    f.list === "outbound"
      ? "outbound"
      : f.list === "inbound"
        ? "inbound"
        : f.list === "outbound-domains"
          ? "outbound domain"
          : "community list"
  const here = f.seen_here ? " that also reached this sensor" : ""
  return `Every ${tier}${where} entry${here}, newest first.`
}

export type FirewallApp = "opnsense" | "pfsense" | "nftables"

/** The fields to fill for a firewall, from the real file address. */
export function usageSteps(app: FirewallApp, url: string): string[] {
  switch (app) {
    case "opnsense":
      return [
        "Open Firewall, then Aliases, and add an alias.",
        "Type: URL Table (IPs). Refresh frequency: 6 hours.",
        `Content: ${url}`,
        "Add a Block rule on your LAN interface with this alias as the destination, above the allow rule. Turn on Log: a hit means a device inside is infected.",
      ]
    case "pfsense":
      return [
        "Open Firewall, then Aliases, then URLs, and add one.",
        "Type: URL Table (IPs). Update frequency: 1 day.",
        `URL: ${url}`,
        "Add a Block rule on LAN with this alias as the destination, at the top. Turn on Log.",
      ]
    case "nftables":
      return [
        `Fetch the file on a timer: curl -fsS -o /etc/nftables.d/suckerpot-outbound.nft ${url}`,
        "Load it in one step: nft -f /etc/nftables.d/suckerpot-outbound.nft",
        "The file defines the sets. Add a rule in the same table that rejects traffic to them.",
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
