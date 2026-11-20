/**
 * MSW handlers for the M30 community lists (`/api/v1/network/feed`, docs/dev/design/m30.md section
 * 10.5). Demo data only: documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
 * 2001:db8::/32) and example.org names. Every value is typed with `lib/network-feed.ts`, and a
 * test checks the shapes, so the mock cannot drift from the contract.
 *
 * Starting state from the URL (`?feed=`): `ok` (default), `off` (the flag is false), `unconfigured`
 * (no address or key), `never` (on, nothing fetched yet), `empty` (fetched, no entry yet because
 * too few members), `stale` and `error`. `?network=member` makes this system a network member.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { Page } from "@/lib/api"
import { isoDay } from "@/lib/network"
import {
  FEED_LIST_IDS,
  type FeedEntry,
  type FeedFile,
  type FeedFormat,
  type FeedList,
  type FeedListId,
  type FeedStatus,
  type FeedTier,
} from "@/lib/network-feed"

const LATENCY_MS = 160
const DAY = 86_400_000
const dayAgo = (n: number) => isoDay(new Date(Date.now() - n * DAY))
const dayAhead = (n: number) => isoDay(new Date(Date.now() + n * DAY))

export const FEED_BASE_URL = "https://feeds.example.org/v1"

function rng(seed: number) {
  let s = seed
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296
    return s / 4294967296
  }
}

const pick = <T>(rand: () => number, items: readonly T[]): T =>
  items[Math.floor(rand() * items.length)] as T

// --- Entries -----------------------------------------------------------------------

const V4_PREFIXES = ["192.0.2", "198.51.100", "203.0.113"] as const
const FAMILIES = ["mirai", "gafgyt", "xmrig", "tsunami", "mozi"] as const
const SERVICES = ["ssh", "telnet", "http", "rdp", "smb"] as const
const TAGS = [
  "malware-drop",
  "php2shell",
  "crypto-miner",
  "mirai",
  "recon",
  "ssh-bruteforce",
] as const
const PORTS = [22, 23, 80, 443, 445, 3389, 8080] as const

function build(): FeedEntry[] {
  const rand = rng(30)
  const rows: FeedEntry[] = []
  const common = (list: FeedListId, i: number) => {
    const first = 2 + Math.floor(rand() * 25)
    const tier: FeedTier = i % 3 === 0 ? "high" : "standard"
    return {
      list,
      tier,
      services: [pick(rand, SERVICES)],
      ports: [pick(rand, PORTS)],
      first_seen: dayAgo(first),
      last_seen: dayAgo(Math.floor(rand() * Math.min(first, 4))),
      expires: dayAhead(2 + Math.floor(rand() * 12)),
      reported: rand() < 0.35,
      seen_here: rand() < 0.2,
      helped: null,
    }
  }
  for (let i = 0; i < 64; i++) {
    const c2 = i % 4 === 0
    const v6 = i % 9 === 0
    rows.push({
      ...common("outbound", i),
      value: v6
        ? `2001:db8:${(0x100 + i).toString(16)}::${(i + 1).toString(16)}`
        : `${pick(rand, V4_PREFIXES)}.${1 + Math.floor(rand() * 253)}`,
      family: v6 ? 6 : 4,
      categories: [c2 ? "c2" : "payload_host"],
      tags: c2 ? ["mirai"] : ["malware-drop"],
      families: [pick(rand, FAMILIES)],
    })
  }
  for (let i = 0; i < 140; i++) {
    const v6 = i % 11 === 0
    rows.push({
      ...common("inbound", i),
      value: v6
        ? `2001:db8:${(0x2000 + i).toString(16)}::${(i + 1).toString(16)}`
        : `${pick(rand, V4_PREFIXES)}.${1 + Math.floor(rand() * 253)}`,
      family: v6 ? 6 : 4,
      categories: ["attack_source"],
      tags: [pick(rand, TAGS)],
      families: [],
    })
  }
  const labels = ["cdn", "dl", "update", "files", "mirror", "get", "static", "cache"] as const
  for (let i = 0; i < 24; i++) {
    const c2 = i % 3 === 0
    rows.push({
      ...common("outbound-domains", i),
      value: `${pick(rand, labels)}${i}.${c2 ? "c2" : "drop"}.example.org`,
      family: null,
      categories: [c2 ? "c2" : "payload_host"],
      tags: c2 ? ["mirai"] : ["malware-drop"],
      families: [pick(rand, FAMILIES)],
    })
  }
  // Newest first, like the API.
  return rows.sort(
    (a, b) => b.last_seen.localeCompare(a.last_seen) || a.value.localeCompare(b.value),
  )
}

export const ENTRIES: FeedEntry[] = build()

// --- Files and lists ---------------------------------------------------------------

function filesFor(id: FeedListId): FeedFile[] {
  const formats: [FeedFormat, string][] =
    id === "outbound-domains"
      ? [
          ["txt", "txt"],
          ["csv", "csv"],
          ["json", "json"],
        ]
      : [
          ["txt", "txt"],
          ["v4", "v4.txt"],
          ["v6", "v6.txt"],
          ["nft", "nft"],
          ["ipset", "ipset"],
          ["rsc", "rsc"],
          ["csv", "csv"],
          ["json", "json"],
          ...(id === "outbound" ? ([["stix", "stix.json"]] as [FeedFormat, string][]) : []),
        ]
  const names: [string, FeedTier][] =
    id === "outbound-domains"
      ? [[id, "standard"]]
      : [
          [id, "standard"],
          [`${id}-high`, "high"],
        ]
  return names.flatMap(([base, tier]) =>
    formats.map(([format, ext]) => ({
      name: `${base}.${ext}`,
      format,
      tier,
      url: `${FEED_BASE_URL}/${base}.${ext}`,
    })),
  )
}

function buildLists(member: boolean, empty: boolean): FeedList[] {
  return FEED_LIST_IDS.map((id) => {
    const rows = empty ? [] : ENTRIES.filter((e) => e.list === id)
    return {
      id,
      direction: id === "inbound" ? "inbound" : "outbound",
      entries: rows.length,
      high: rows.filter((e) => e.tier === "high").length,
      seen_here: rows.filter((e) => e.seen_here).length,
      helped: member ? rows.filter((e) => helped(e)).length : null,
      files: filesFor(id),
    }
  })
}

/** A member helped confirm about one entry in six. */
function helped(e: FeedEntry): boolean {
  let h = 0
  for (const ch of e.value) h = (h * 31 + ch.charCodeAt(0)) % 997
  return h % 6 === 0
}

export type FeedScenario = "ok" | "off" | "unconfigured" | "never" | "empty" | "stale" | "error"

export function buildStatus(scenario: FeedScenario = "ok", member = false): FeedStatus {
  const base: FeedStatus = {
    enabled_env: true,
    configured: true,
    state: "ok",
    error_code: null,
    serial: 4812,
    generated_at: new Date(Date.now() - 3 * 3_600_000).toISOString(),
    valid_until: new Date(Date.now() + 69 * 3_600_000).toISOString(),
    last_ok_at: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    signature: "verified",
    member,
    public_base_url: FEED_BASE_URL,
    lists: buildLists(member, scenario === "empty"),
    local_mirror: { feeds_enabled: true },
  }
  switch (scenario) {
    case "off":
      return {
        ...base,
        enabled_env: false,
        state: "disabled",
        serial: null,
        generated_at: null,
        valid_until: null,
        last_ok_at: null,
        signature: null,
        lists: buildLists(member, true),
      }
    case "unconfigured":
      return {
        ...buildStatus("off", member),
        configured: false,
        public_base_url: null,
        lists: buildLists(member, true).map((l) => ({ ...l, files: [] })),
      }
    case "never":
      return {
        ...base,
        state: "never",
        serial: null,
        generated_at: null,
        valid_until: null,
        last_ok_at: null,
        signature: null,
        lists: buildLists(member, true),
      }
    case "stale":
      return {
        ...base,
        state: "stale",
        valid_until: new Date(Date.now() - 5 * 3_600_000).toISOString(),
        last_ok_at: new Date(Date.now() - 77 * 3_600_000).toISOString(),
        signature: "verified",
      }
    case "error":
      return { ...base, state: "error", error_code: "bad_signature", signature: null }
    default:
      return base
  }
}

function scenarioFromUrl(): FeedScenario {
  if (typeof window === "undefined") return "ok"
  const wanted = new URLSearchParams(window.location.search).get("feed")
  return wanted === "off" ||
    wanted === "unconfigured" ||
    wanted === "never" ||
    wanted === "empty" ||
    wanted === "stale" ||
    wanted === "error"
    ? wanted
    : "ok"
}

function memberFromUrl(): boolean {
  return (
    typeof window !== "undefined" &&
    new URLSearchParams(window.location.search).get("network") === "member"
  )
}

let status: FeedStatus | null = null

function current(): FeedStatus {
  status ??= buildStatus(scenarioFromUrl(), memberFromUrl())
  return status
}

export const networkFeedHandlers: RequestHandler[] = [
  http.get("/api/v1/network/feed/status", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(current())
  }),

  http.get("/api/v1/network/feed/entries", async ({ request }) => {
    await delay(LATENCY_MS)
    const url = new URL(request.url)
    const list = url.searchParams.get("list")
    const tier = url.searchParams.get("tier")
    const q = url.searchParams.get("q")?.toLowerCase()
    const seenHere = url.searchParams.get("seen_here") === "1"
    const member = current().member
    const empty = current().lists.every((l) => l.entries === 0)
    let items = empty ? [] : ENTRIES
    if (list) items = items.filter((e) => e.list === list)
    // The high tier is a subset of the list: a standard entry is not in it.
    if (tier === "high") items = items.filter((e) => e.tier === "high")
    if (q) items = items.filter((e) => e.value.toLowerCase().includes(q))
    if (seenHere) items = items.filter((e) => e.seen_here)
    items = items.map((e) => ({ ...e, helped: member ? helped(e) : null }))
    const limit = Number(url.searchParams.get("limit") ?? 50)
    const cursor = url.searchParams.get("cursor")
    const offset = cursor ? Number(atob(cursor)) || 0 : 0
    const page: Page<FeedEntry> = {
      items: items.slice(offset, offset + limit),
      next_cursor: offset + limit < items.length ? btoa(String(offset + limit)) : null,
    }
    return HttpResponse.json(page)
  }),
]
