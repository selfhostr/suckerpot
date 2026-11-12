/**
 * Collected samples (M21): shapes of `/api/v1/samples` and `/api/v1/egress` (docs/design/m21.md
 * section 7.2 is the contract), the plain-English sentences of the pages, and the calls.
 * The sentences are pure and tested.
 */

import { ApiError, getJson, sendForBlob, type Page, type Param, type Session } from "./api"
import { formatBytes, formatNumber, plural } from "./format"
import type { Severity } from "./severity"
import type { FetchStatus } from "./trends"
import { UserError } from "./users"

const DAY = 86_400_000

// --- Fetch status ----------------------------------------------------------------

export const FETCH_STATUS: Record<FetchStatus, { label: string; explain: string }> = {
  fetched: { label: "Fetched", explain: "The file was downloaded and stored for analysis." },
  pending: { label: "Pending", explain: "Waiting for the collector to fetch it." },
  failed: { label: "Failed", explain: "The server did not answer or refused the connection." },
  gone: { label: "Gone", explain: "The server answered, but the file no longer exists." },
  refused: { label: "Refused", explain: "The address was not allowed, so it was never contacted." },
  too_large: {
    label: "Too large",
    explain: "The file is bigger than the size cap, so it was dropped.",
  },
  unsupported: {
    label: "Not fetched",
    explain: "This protocol (for example TFTP) is not fetched.",
  },
  quarantine_full: {
    label: "Quarantine full",
    explain: "The quarantine volume is full, so nothing more is stored.",
  },
}

/** TFTP URLs are never fetched: say so with the protocol, as the design asks. */
export function fetchStatusLabel(status: FetchStatus, url?: string): string {
  if (status === "unsupported" && url && /^tftp:/i.test(url)) return "Not fetched (TFTP)"
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
}

export type SampleOrigin = "local" | "network_verify"

/** Plain-English label and explanation of a sample origin. Only the network check is flagged. */
export const NETWORK_CHECK = {
  label: "Network check",
  /** Always visible next to the label, so touch users do not need a hover. */
  qualifier: "not seen here",
  explain:
    "Fetched to verify a link that other nodes in the network reported. It did not attack this node.",
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
 * a style sheet, a data document, the script of a page). Such a file is kept for reference; its
 * links are never followed.
 */
export const WEB_KIND_LABEL: Readonly<Record<string, string>> = {
  html: "Web page",
  svg: "Image (SVG)",
  xml: "Data (XML)",
  css: "Stylesheet",
  json: "Data (JSON)",
  javascript: "Script (web)",
}

/** The label of a web kind, or null for any other kind (including null). */
export function webKindLabel(kind: string | null | undefined): string | null {
  if (!kind) return null
  const key = kind.toLowerCase()
  return Object.hasOwn(WEB_KIND_LABEL, key) ? (WEB_KIND_LABEL[key] ?? null) : null
}

/**
 * Ordinary web content that no detection rule matched: a web kind with the lowest severity and no
 * family. The same condition as the database's "benign web sample" (`suckerpot_db.sample_kinds`).
 */
export function isPlainWeb(s: Pick<SampleItem, "kind" | "family" | "severity">): boolean {
  return webKindLabel(s.kind) !== null && s.severity === "info" && !s.family
}

/** "ELF ARM 32-bit", "Shell script", "Web page", "Unknown file". */
export function describeKind(s: Pick<SampleItem, "kind" | "arch" | "bits">): string {
  const web = webKindLabel(s.kind)
  if (web) return web
  const kind = s.kind ?? "Unknown file"
  const arch = s.arch ? ` ${s.arch}` : ""
  const bits = s.bits ? ` ${s.bits}-bit` : ""
  return `${kind}${arch}${bits}`
}

/** The family, else the plain name of a web kind, else "Unknown". */
export function familyLabel(family: string | null, kind?: string | null): string {
  return family ?? webKindLabel(kind) ?? "Unknown"
}

export function shortHash(sha256: string): string {
  return sha256.slice(0, 12)
}

export function isBinary(kind: string | null): boolean {
  return kind === "ELF" || kind === "PE"
}

function joinList(items: readonly string[]): string {
  if (items.length <= 1) return items.join("")
  return `${items.slice(0, -1).join(", ")} and ${items.at(-1) ?? ""}`
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
  if (items.length === 0) return "No samples collected yet."
  const lead = more ? "At least " : ""
  const web = items.filter(isPlainWeb).length
  if (web > 0 && web === items.length)
    return `${lead}${plural(web, "sample")} collected, all ordinary web content (pages, images, style sheets), nothing to flag.`
  const files = items.filter((s) => !isPlainWeb(s))
  const fresh = files.filter((s) => now - Date.parse(s.first_seen) < 7 * DAY)
  if (fresh.length === 0)
    return `${lead}${plural(files.length, "sample")} collected, none of them new this week.`
  const byFamily = new Map<string, SampleItem[]>()
  for (const s of fresh) {
    if (!s.family) continue
    byFamily.set(s.family, [...(byFamily.get(s.family) ?? []), s])
  }
  const top = [...byFamily.entries()].sort((a, b) => b[1].length - a[1].length)[0]
  const head = `${lead}${formatNumber(fresh.length)} new ${fresh.length === 1 ? "file" : "files"} this week`
  if (!top) return `${head}, none of them matched a known family.`
  const [family, rows] = top
  const archs = [...new Set(rows.map((r) => r.arch).filter((a): a is string => Boolean(a)))]
  const forArch = archs.length > 0 ? ` for ${joinList(archs)}` : ""
  return `${head}, ${formatNumber(rows.length)} of them ${family} builds${forArch}.`
}

/** Header sentence of a sample page. */
export function describeSample(d: SampleDetail): string {
  const s = d.item
  const where = plural(s.sources, "address", "addresses")
  const served = `Served from ${where} in ${plural(s.sessions, "session")}.`
  if (isPlainWeb(s))
    return `Ordinary web content, ${formatBytes(s.size)}. ${served} It is kept for reference and its links are not followed.`
  const what = s.family ? `${s.family} sample` : "Unclassified file"
  return `${what}, ${describeKind(s)}, ${formatBytes(s.size)}. ${served}`
}

export function describeYara(hits: readonly YaraHit[], status: SampleStatus): string {
  if (hits.length > 0) return `${plural(hits.length, "detection rule")} matched this file.`
  if (status === "pending") return "The analysis has not run yet."
  if (status === "done") return "No detection rule matched this file."
  return "The analysis did not finish, so no rules were checked."
}

/** C2 values are shown with their port when there is one. */
export function linkLabel(l: SampleLink): string {
  return l.port ? `${l.value}:${l.port}` : l.value
}

export const LINK_KIND_LABEL: Record<LinkKind, string> = {
  next_url: "Next download",
  c2_ip: "Command server (address)",
  c2_domain: "Command server (domain)",
  c2_url: "Command server (URL)",
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
  const parts = [
    plural(count("session"), "session"),
    plural(count("url"), "URL"),
    plural(count("sample"), "file"),
  ]
  const c2 = count("c2")
  if (c2 > 0) parts.push(plural(c2, "command server"))
  return `The chain links ${joinList(parts)}.`
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

/** Gate reason codes, as `suckerpot_egress` and the API write them (docs/design/m21.md §3.4). */
const REASONS: Record<string, string> = {
  no_vpn: "the VPN is not reachable",
  tunnel_down: "the VPN tunnel is down",
  ip_not_allowed: "the exit address is not on the allow-list",
  ip_mismatch: "the exit address does not match what the VPN reports",
  ip_not_global: "the exit address is not a public one",
  no_public_ip: "the VPN did not report its exit address",
  echo_failed: "the exit address could not be checked",
  echo_disagree: "the exit address checks disagree",
  check_error: "the last check failed",
  stale: "the last check is too old",
  not_checked: "no check has run yet",
  no_status: "no check has run yet",
}

export function egressReason(code: string | null): string {
  if (!code) return "the gate is closed"
  return REASONS[code] ?? code.replaceAll("_", " ")
}

export function egressOpen(e: Egress): boolean {
  return e.ingest.state === "open" && e.collector.state === "open"
}

export function describeEgress(e: Egress): string {
  if (egressOpen(e)) return "Outbound traffic leaves through the VPN."
  const closed = e.ingest.state === "closed" ? e.ingest : e.collector
  if (closed.reason === "tunnel_down") return "Outbound traffic is paused: the VPN tunnel is down."
  return `Outbound traffic is paused: ${egressReason(closed.reason)}.`
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
      finding:
        "These downloads use TFTP or FTP, which are never fetched, so only URLs are recorded.",
      detail: "The collector fetches HTTP and HTTPS URLs only, through the VPN.",
    }
  const none =
    "nothing is downloaded from these hosts, so there are no file hashes or analyses yet."
  if (!e || e.collector.reason === "no_status" || e.collector.reason === "not_checked")
    return {
      finding: "The sample collector is off, so only URLs are recorded.",
      detail: `It fetches files through the VPN once COLLECTOR_ENABLED is true. Until then ${none}`,
    }
  if (e.collector.state === "closed")
    return {
      finding: `The sample collector is paused (${egressReason(e.collector.reason)}), so only URLs are recorded.`,
      detail: `It fetches files only through the VPN and waits while the tunnel is not safe; ${none}`,
    }
  if (known.length > 0)
    return {
      finding: "No file has been collected yet, so only URLs are recorded.",
      detail:
        "The collector is working through these URLs, through the VPN. A fetched file shows its hash, which opens the analysis.",
    }
  return {
    finding: "No file has been collected yet, so only URLs are recorded.",
    detail:
      "The VPN is up. If COLLECTOR_ENABLED is true, new URLs are fetched shortly and show a hash that opens the analysis.",
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
