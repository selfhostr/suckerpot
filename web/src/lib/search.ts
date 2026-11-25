/**
 * Global search (header box and Ctrl/Cmd+K palette). Types mirror api/api/search.py.
 * The API does the matching; this module only types the answer and decides where a hit leads.
 */
import { tk } from "@/i18n"
import { getJson } from "./api"
import { withText } from "./utils"

export const SEARCH_KINDS = ["ip", "campaign", "cve", "hash", "domain"] as const
export type SearchKind = (typeof SEARCH_KINDS)[number]

export interface SearchHit {
  kind: SearchKind
  /** The address, the CVE id, or the indicator or campaign id. */
  value: string
  /** The headline. Indicators arrive defanged and are rendered as text, never as links. */
  label: string
  detail: string | null
  count: number | null
  last_seen: string | null
  benign: boolean
}

export interface SearchGroup {
  kind: SearchKind
  hits: SearchHit[]
  more: boolean
}

export interface SearchResponse {
  q: string
  groups: SearchGroup[]
}

export const MIN_QUERY = 2
export const MAX_QUERY = 128

export const searchApi = {
  search: (q: string) => getJson<SearchResponse>("/search", { q }),
}

/** Group titles, in the order the palette shows them. */
export const GROUP_LABEL: Record<SearchKind, string> = withText(
  {
    ip: tk("search_group_ip"),
    campaign: tk("search_group_campaign"),
    cve: tk("search_group_cve"),
    hash: tk("search_group_hash"),
    domain: tk("search_group_domain"),
  },
  {},
)

/** Where a hit opens: always an existing, filterable view, never an external site. */
export function hitHref(hit: Pick<SearchHit, "kind" | "value">): string {
  const v = encodeURIComponent(hit.value)
  switch (hit.kind) {
    case "ip":
      return `/attackers/${v}`
    case "campaign":
      return `/campaigns/${v}`
    case "cve":
      return `/cves?cve=${v}`
    case "hash":
    case "domain":
      return `/infrastructure?indicator=${v}`
  }
}

/** Palette order: the groups the API found, in a fixed order so the list does not reshuffle. */
export function orderedGroups(response: SearchResponse | undefined): SearchGroup[] {
  if (!response) return []
  return SEARCH_KINDS.flatMap((kind) =>
    response.groups.filter((g) => g.kind === kind && g.hits.length > 0),
  )
}

/** Clean what the user typed before it is sent: trim, collapse blanks, cap the length. */
export function cleanQuery(raw: string): string {
  return raw.replace(/\s+/g, " ").trim().slice(0, MAX_QUERY)
}

const RECENT_KEY = "suckerpot.recentSearches"
const RECENT_MAX = 5

export function loadRecent(): string[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]")
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter((x): x is string => typeof x === "string" && x.length <= MAX_QUERY)
      .slice(0, RECENT_MAX)
  } catch {
    return []
  }
}

export function clearRecentSearches(): void {
  try {
    localStorage.removeItem(RECENT_KEY)
  } catch {
    // Storage blocked: nothing was kept.
  }
}

export function rememberSearch(q: string): string[] {
  const next = [q, ...loadRecent().filter((x) => x !== q)].slice(0, RECENT_MAX)
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(next))
  } catch {
    // Storage blocked: recent searches last for this tab only.
  }
  return next
}
