/**
 * Collected samples (M21): shapes of `/api/v1/samples` and `/api/v1/egress` (docs/dev/design/m21.md
 * section 7.2 is the contract), the plain-English sentences of the pages, and the calls.
 * The sentences are pure and tested.
 */

import { ApiError, getJson, sendForBlob, type Page, type Param, type Session } from "./api"
import { intlLocale, t, tk } from "@/i18n"
import { formatBytes } from "./format"
import type { Severity } from "./severity"
import type { FetchStatus } from "./trends"
import { UserError } from "./users"

const DAY = 86_400_000

// --- Fetch status ----------------------------------------------------------------

export const FETCH_STATUS: Record<FetchStatus, { label: string; explain: string }> = {
  fetched: {
    get label() {
      return t("samples_fetch_fetched_label")
    },
    get explain() {
      return t("samples_fetch_fetched_explain")
    },
  },
  pending: {
    get label() {
      return t("samples_fetch_pending_label")
    },
    get explain() {
      return t("samples_fetch_pending_explain")
    },
  },
  failed: {
    get label() {
      return t("samples_fetch_failed_label")
    },
    get explain() {
      return t("samples_fetch_failed_explain")
    },
  },
  gone: {
    get label() {
      return t("samples_fetch_gone_label")
    },
    get explain() {
      return t("samples_fetch_gone_explain")
    },
  },
  refused: {
    get label() {
      return t("samples_fetch_refused_label")
    },
    get explain() {
      return t("samples_fetch_refused_explain")
    },
  },
  too_large: {
    get label() {
      return t("samples_fetch_too_large_label")
    },
    get explain() {
      return t("samples_fetch_too_large_explain")
    },
  },
  unsupported: {
    get label() {
      return t("samples_fetch_unsupported_label")
    },
    get explain() {
      return t("samples_fetch_unsupported_explain")
    },
  },
  quarantine_full: {
    get label() {
      return t("samples_fetch_quarantine_full_label")
    },
    get explain() {
      return t("samples_fetch_quarantine_full_explain")
    },
  },
}

/** TFTP URLs are never fetched: say so with the protocol, as the design asks. */
export function fetchStatusLabel(status: FetchStatus, url?: string): string {
  if (status === "unsupported" && url && /^tftp:/i.test(url)) return t("samples_fetch_tftp_label")
  return FETCH_STATUS[status].label
}

// --- Samples ---------------------------------------------------------------------

export type SampleStatus = "pending" | "done" | "failed" | "timeout"
export const SAMPLE_STATUSES: readonly SampleStatus[] = ["pending", "done", "failed", "timeout"]

export interface SampleItem {
  sha256: string
  kind: string | null
  arch: string | null
  bits: number | null
  family: string | null
  severity: Severity
  size: number
  /** Distinct URLs that served it. */
  sources: number
  sessions: number
  first_seen: string
  last_seen: string
  /** Names of the YARA rules that matched. */
  yara: string[]
  stored: boolean
  analysis_status: SampleStatus
  /** `network_verify`: fetched only to verify a link other nodes reported, it did not attack this node. */
  origin: SampleOrigin
  /**
   * Reached only by following links found in other web content; no attacker asked for it (no
   * typed URL, not linked from a script or a binary).
   */
  crawled: boolean
}

export type SampleOrigin = "local" | "network_verify"

/** Plain-English label and explanation of a sample origin. Only the network check is flagged. */
export const NETWORK_CHECK = {
  get label() {
    return t("samples_network_check_label")
  },
  /** Always visible next to the label, so touch users do not need a hover. */
  get qualifier() {
    return t("samples_network_check_qualifier")
  },
  get explain() {
    return t("samples_network_check_explain")
  },
} as const

export interface SampleFilters {
  kind?: string
  arch?: string
  family?: string
  yara?: string
  status?: string
  q?: string
  since?: string
}

export interface YaraHit {
  rule: string
  namespace: string
  tags: string[]
  meta: Record<string, string>
}

export interface DeobStep {
  step: string
  detail: string | null
}

export interface SampleAnalysis {
  analyzed_at: string
  elapsed_ms: number | null
  yara: YaraHit[]
  strings: string[]
  deobfuscated: string | null
  deob_steps: DeobStep[]
  errors: string[]
}

export interface SampleSource {
  url: string
  host: string
  first_fetched: string
  last_fetched: string
  sessions: number
  ips: number
  sensors: string[]
}

export type LinkKind = "next_url" | "c2_ip" | "c2_domain" | "c2_url"

export interface SampleLink {
  kind: LinkKind
  value: string
  port: number | null
  source: string
  confidence: string
}

export interface SampleDetail {
  item: SampleItem
  sha1: string
  md5: string
  tlsh: string | null
  endian: string | null
  linking: string | null
  packer: string | null
  virustotal_url: string
  analysis: SampleAnalysis | null
  sources: SampleSource[]
  links: SampleLink[]
  /** The latest 20 sessions that fetched it. */
  recent_sessions: Session[]
}

export type ChainNodeKind = "session" | "url" | "sample" | "c2"

export interface ChainNode {
  id: string
  kind: ChainNodeKind
  /** Session id, URL, short hash or C2 address, ready to show. */
  label: string
  /** Set on `sample` nodes. */
  sha256?: string | null
  /** Set on `sample` nodes: "Mirai" or the file kind. */
  family?: string | null
  /** Set on `session` nodes. */
  session_id?: string | null
}

export interface ChainEdge {
  from: string
  to: string
}

export interface SampleChain {
  nodes: ChainNode[]
  edges: ChainEdge[]
}

export function sampleKey(s: SampleItem): string {
  return s.sha256
}

/**
 * Plain-English names of the kinds the analyzer gives to ordinary web content (a page, an image,
 * a style sheet, a data document, the script of a page).
 */
export const WEB_KIND_LABEL: Readonly<Record<string, string>> = {
  get html() {
    return t("samples_web_web_page")
  },
  get svg() {
    return t("samples_web_svg")
  },
  get xml() {
    return t("samples_web_xml")
  },
  get css() {
    return t("samples_web_css")
  },
  get json() {
    return t("samples_web_json")
  },
  get javascript() {
    return t("samples_web_js")
  },
}

/** The label of a web kind, or null for any other kind (including null). */
export function webKindLabel(kind: string | null | undefined): string | null {
  if (!kind) return null
  const key = kind.toLowerCase()
  return Object.hasOwn(WEB_KIND_LABEL, key) ? (WEB_KIND_LABEL[key] ?? null) : null
}

/**
 * Plain web content: a web kind that no detection rule matched (the lowest severity, no family)
 * and that the collector reached only by following links found in other web content. Such a file
 * is kept for reference; its links are not followed. Web content an attacker asked for is never
 * plain. The same condition as the database's `plain_web_sample` (`suckerpot_db.sample_kinds`).
 */
export function isPlainWeb(
  s: Pick<SampleItem, "kind" | "family" | "severity" | "crawled">,
): boolean {
  return webKindLabel(s.kind) !== null && s.severity === "info" && !s.family && s.crawled
}

/** "ELF ARM 32-bit", "Shell script", "Web page", "Unknown file". */
export function describeKind(s: Pick<SampleItem, "kind" | "arch" | "bits">): string {
  const web = webKindLabel(s.kind)
  if (web) return web
  const kind = s.kind ?? t("samples_kind_unknown")
  const arch = s.arch ? ` ${s.arch}` : ""
  const bits = s.bits ? ` ${t("samples_kind_bits", { bits: s.bits })}` : ""
  return `${kind}${arch}${bits}`
}

/** The family, else the plain name of a web kind, else "Unknown". */
export function familyLabel(family: string | null, kind?: string | null): string {
  return family ?? webKindLabel(kind) ?? t("samples_family_unknown")
}

export function shortHash(sha256: string): string {
  return sha256.slice(0, 12)
}

export function isBinary(kind: string | null): boolean {
  return kind === "ELF" || kind === "PE"
}

function joinList(items: readonly string[]): string {
  return new Intl.ListFormat(intlLocale(), { style: "long", type: "conjunction" }).format(items)
}

/**
 * "12 new binaries this week, 9 of them Mirai builds for ARM and MIPS". Built from the rows on
 * screen, so with more pages to come it says "at least".
 */
export function describeSamples(
  items: readonly SampleItem[],
  more: boolean,
  now: number = Date.now(),
): string {
  if (items.length === 0) return t("samples_summary_empty")
  const atLeast = more ? "yes" : "no"
  const web = items.filter(isPlainWeb).length
  if (web > 0 && web === items.length) return t("samples_summary_web_only", { count: web, atLeast })
  const files = items.filter((s) => !isPlainWeb(s))
  const fresh = files.filter((s) => now - Date.parse(s.first_seen) < 7 * DAY)
  if (fresh.length === 0) return t("samples_summary_none_new", { count: files.length, atLeast })
  const byFamily = new Map<string, SampleItem[]>()
  for (const s of fresh) {
    if (!s.family) continue
    byFamily.set(s.family, [...(byFamily.get(s.family) ?? []), s])
  }
  const top = [...byFamily.entries()].sort((a, b) => b[1].length - a[1].length)[0]
  if (!top) return t("samples_summary_no_family", { count: fresh.length, atLeast })
  const [family, rows] = top
  const archs = [...new Set(rows.map((r) => r.arch).filter((a): a is string => Boolean(a)))]
  return t("samples_summary_family", {
    count: fresh.length,
    atLeast,
    n: rows.length,
    family,
    withArch: archs.length > 0 ? "yes" : "no",
    archs: joinList(archs),
  })
}

/** Header sentence of a sample page. */
export function describeSample(d: SampleDetail): string {
  const s = d.item
  const served = t("samples_served", { sources: s.sources, sessions: s.sessions })
  const size = formatBytes(s.size)
  if (isPlainWeb(s)) return t("samples_describe_plain_web", { size, served })
  const what = s.family
    ? t("samples_describe_family", { family: s.family })
    : t("samples_describe_unclassified")
  return t("samples_describe_file", { what, kind: describeKind(s), size, served })
}

export function describeYara(hits: readonly YaraHit[], status: SampleStatus): string {
  if (hits.length > 0) return t("samples_yara_matched", { count: hits.length })
  if (status === "pending") return t("samples_yara_pending")
  if (status === "done") return t("samples_yara_none")
  return t("samples_yara_unfinished")
}

/** C2 values are shown with their port when there is one. */
export function linkLabel(l: SampleLink): string {
  return l.port ? `${l.value}:${l.port}` : l.value
}

export const LINK_KIND_LABEL: Record<LinkKind, string> = {
  get next_url() {
    return t("samples_link_next_url")
  },
  get c2_ip() {
    return t("samples_link_c2_ip")
  },
  get c2_domain() {
    return t("samples_link_c2_domain")
  },
  get c2_url() {
    return t("samples_link_c2_url")
  },
}

/**
 * The chain as ordered steps: nodes sorted by their distance from a root (a node with no edge in),
 * so the list reads session, script, binary, C2. Cycles and strays are tolerated.
 */
export function orderChain(chain: SampleChain): ChainNode[] {
  const incoming = new Map<string, number>()
  for (const n of chain.nodes) incoming.set(n.id, 0)
  for (const e of chain.edges) incoming.set(e.to, (incoming.get(e.to) ?? 0) + 1)
  const depth = new Map<string, number>()
  let frontier = chain.nodes.filter((n) => (incoming.get(n.id) ?? 0) === 0).map((n) => n.id)
  for (const id of frontier) depth.set(id, 0)
  for (let d = 1; d <= chain.nodes.length && frontier.length > 0; d++) {
    const next: string[] = []
    for (const id of frontier)
      for (const e of chain.edges)
        if (e.from === id && !depth.has(e.to)) {
          depth.set(e.to, d)
          next.push(e.to)
        }
    frontier = next
  }
  return [...chain.nodes].sort(
    (a, b) => (depth.get(a.id) ?? 99) - (depth.get(b.id) ?? 99) || a.label.localeCompare(b.label),
  )
}

export function describeChain(chain: SampleChain): string {
  const count = (k: ChainNodeKind) => chain.nodes.filter((n) => n.kind === k).length
  const values = {
    sessions: count("session"),
    urls: count("url"),
    files: count("sample"),
    servers: count("c2"),
  }
  return t(values.servers > 0 ? "samples_chain_with_c2" : "samples_chain", values)
}

// --- Egress ----------------------------------------------------------------------

export interface EgressGate {
  state: "open" | "closed"
  /** Machine code of the reason when closed ("tunnel_down", "exit_not_allowed", ...). */
  reason: string | null
  checked_at: string | null
}

export interface Egress {
  ingest: EgressGate
  collector: EgressGate
  /** Whether the current exit address is on the allow-list; null before the first check. */
  exit_ip_allowed: boolean | null
  /** Shown only after a click; null when unknown. */
  exit_ip: string | null
  collector_quota: { used: number; limit: number }
  quarantine: { used_bytes: number; max_bytes: number }
}

/** Gate reason codes, as `suckerpot_egress` and the API write them (docs/dev/design/m21.md §3.4). */
const REASONS: Record<string, string> = {
  no_vpn: tk("samples_reason_no_vpn"),
  tunnel_down: tk("samples_reason_tunnel_down"),
  ip_not_allowed: tk("samples_reason_ip_not_allowed"),
  ip_mismatch: tk("samples_reason_ip_mismatch"),
  ip_not_global: tk("samples_reason_ip_not_global"),
  no_public_ip: tk("samples_reason_no_public_ip"),
  echo_failed: tk("samples_reason_echo_failed"),
  echo_disagree: tk("samples_reason_echo_disagree"),
  check_error: tk("samples_reason_check_error"),
  stale: tk("samples_reason_stale"),
  not_checked: tk("samples_reason_not_checked"),
  no_status: tk("samples_reason_not_checked"),
}

export function egressReason(code: string | null): string {
  if (!code) return t("samples_reason_gate_closed")
  const key = REASONS[code]
  return key ? t(key) : code.replaceAll("_", " ")
}

export function egressOpen(e: Egress): boolean {
  return e.ingest.state === "open" && e.collector.state === "open"
}

export function describeEgress(e: Egress): string {
  if (egressOpen(e)) return t("samples_egress_open")
  const closed = e.ingest.state === "closed" ? e.ingest : e.collector
  return t("samples_egress_paused", { reason: egressReason(closed.reason) })
}

/**
 * The note on the download-URL list while no file has been collected: why only URLs are
 * recorded. Files are fetched by the separate collector, through the VPN, once
 * `COLLECTOR_ENABLED` is true; ingest never fetches them.
 */
export function describeCollector(
  e: Egress | undefined,
  statuses: readonly (FetchStatus | null | undefined)[] = [],
): { finding: string; detail: string } {
  const known = statuses.filter((x): x is FetchStatus => Boolean(x))
  if (
    known.length > 0 &&
    known.length === statuses.length &&
    known.every((x) => x === "unsupported")
  )
    return {
      finding: t("samples_collector_unsupported_finding"),
      detail: t("samples_collector_unsupported_detail"),
    }
  if (!e || e.collector.reason === "no_status" || e.collector.reason === "not_checked")
    return {
      finding: t("samples_collector_off_finding"),
      detail: t("samples_collector_off_detail"),
    }
  if (e.collector.state === "closed")
    return {
      finding: t("samples_collector_paused_finding", { reason: egressReason(e.collector.reason) }),
      detail: t("samples_collector_paused_detail"),
    }
  if (known.length > 0)
    return {
      finding: t("samples_collector_none_finding"),
      detail: t("samples_collector_working_detail"),
    }
  return {
    finding: t("samples_collector_none_finding"),
    detail: t("samples_collector_up_detail"),
  }
}

// --- Calls -----------------------------------------------------------------------

export const sampleKeys = {
  all: ["samples"] as const,
  list: (filters: object) => ["samples", "list", filters] as const,
  detail: (sha256: string) => ["samples", "detail", sha256] as const,
  chain: (sha256: string) => ["samples", "chain", sha256] as const,
  egress: ["egress"] as const,
}

export const samplesApi = {
  list: (filters: SampleFilters, cursor: string | null, limit = 50) =>
    getJson<Page<SampleItem>>("/samples", {
      ...(filters as Record<string, Param>),
      cursor: cursor ?? undefined,
      limit,
    }),
  detail: (sha256: string) => getJson<SampleDetail>(`/samples/${sha256}`),
  chain: (sha256: string) => getJson<SampleChain>(`/samples/${sha256}/chain`),
  egress: () => getJson<Egress>("/egress"),
  /** Admin only; the server asks for the password again. Resolves to the encrypted zip. */
  archive: async (sha256: string, password: string): Promise<Blob> => {
    try {
      return await sendForBlob(`/samples/${sha256}/archive`, { password })
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.code === "reauth_failed") throw new UserError("wrong-password")
        if (e.status === 429) throw new UserError("rate-limited")
        if (e.status === 404) throw new UserError("unavailable")
        if (e.status === 401) throw new UserError("session")
      }
      throw new UserError("network")
    }
  },
}

/** Hands a blob to the browser as a download. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}
