/**
 * Mock handlers for the M7 endpoints (insights, trends/new, trends/tags,
 * malware). Only synthetic data: documentation addresses
 * (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and example domains.
 */
import { delay, http, HttpResponse } from "msw"
import type { Session } from "@/lib/api"
import type { Insight, MalwareItem, NewField, NewItem, TagsResponse } from "@/lib/trends"
import { NEW_FIELDS } from "@/lib/trends"
import { mockFetchState } from "./samples"

const LATENCY_MS = 170
const DAY = 86_400_000

function hash(s: string | number): number {
  let h = 2166136261
  for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619)
  return (h >>> 0) / 4294967296
}

const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z")

const INSIGHTS: Insight[] = [
  {
    id: "surge-tag-php2shell",
    kind: "exploit",
    severity: "severe",
    sentence: "PHP2Shell exploit attempts tripled since Tuesday (412 vs 131).",
    evidence: { metric: "tag:php2shell", current: 412, previous: 131, ratio: 3.1 },
    link: "/attacks?tag=php2shell",
  },
  {
    id: "campaign-asn-64500",
    kind: "campaign",
    severity: "warning",
    sentence: "One network, AS64500 (Example Hosting), sent 38% of all SSH sessions this week.",
    evidence: { metric: "asn:64500", current: 1180, previous: 0, ratio: 0.38 },
    link: "/attackers?asn=64500",
  },
  {
    id: "new-values-passwords",
    kind: "new_value",
    severity: "notice",
    sentence: '14 passwords were tried for the first time this week, led by "Summer2026!".',
    evidence: { metric: "new:password", current: 14, previous: 0, ratio: 0 },
    link: "/trends?field=password",
  },
]

const WORDS: Record<NewField, string[]> = {
  username: ["svc_backup", "oracle2", "deploy-bot", "pi-hole", "minecraft", "jenkins2", "grafana"],
  password: [
    "Summer2026!",
    "changeme-2026",
    "Passw0rd#1",
    "letmein2026",
    "P@ssw0rd123",
    "welcome-7",
  ],
  command: [
    "uname -s -v -n -r -m",
    "cat /proc/cpuinfo | grep name | wc -l",
    "crontab -l; echo done",
    "ls -la /tmp /var/tmp",
  ],
  url: [
    "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
    "/cgi-bin/luci/;stok=/locale",
    "/.env.bak",
    "/actuator/gateway/routes",
  ],
  asn: ["64500", "64511", "64496"],
  user_agent: [
    "Mozilla/5.0 zgrab/0.x",
    "curl/8.9.1",
    "python-requests/2.32.3",
    "Go-http-client/1.1",
  ],
}

function newItems(field: NewField, days: number, limit: number, now: number): NewItem[] {
  return WORDS[field].slice(0, limit).map((value, i) => ({
    value,
    count: Math.round(5 + hash(`${field}${value}`) * 90) + (WORDS[field].length - i) * 3,
    first_seen: iso(now - Math.floor(hash(`f${value}`) * days * DAY)),
  }))
}

const TAGS = ["php2shell", "recon", "brute-force", "malware-drop", "crypto-miner", "mirai", "other"]

function malwareItems(now: number): MalwareItem[] {
  const hosts = [
    "files.example.net",
    "cdn.example.org",
    "198.51.100.23",
    "dl.example.com",
    "203.0.113.200:8080",
    "mirror.example.net",
  ]
  const tools = [["wget", "curl"], ["wget"], ["tftp"], ["curl"], ["wget", "ftpget"]]
  const files = ["x86.sh", "bins/arm7", "update.php", "payload.bin", "ld.so", "kworker", "cron.sh"]
  return Array.from({ length: 140 }, (_, i) => {
    const host = hosts[i % hosts.length] ?? "files.example.net"
    const attempts = Math.max(1, Math.round(300 * Math.pow(hash(`a${i}`), 3)))
    const last = now - Math.floor(hash(`l${i}`) * 6 * DAY) - i * 60_000
    return {
      url: `http://${host}/${files[i % files.length]}${i >= files.length ? `.${i}` : ""}`,
      host: host.replace(/:\d+$/, ""),
      first_seen: iso(last - Math.floor(hash(`s${i}`) * 20 * DAY)),
      last_seen: iso(last),
      attempts,
      sessions: Math.max(1, Math.round(attempts * 0.8)),
      ips: Math.max(1, Math.round(attempts * 0.3)),
      tools: tools[i % tools.length] ?? [],
      sensors: (
        [["ssh", "telnet"], ["telnet"], ["web"], ["redis"], ["adb"], ["docker"], ["mssql"]] as const
      )[i % 7]?.slice() ?? ["ssh"],
      ...mockFetchState(i, tools[i % tools.length] ?? []),
    }
  }).sort((a, b) => b.last_seen.localeCompare(a.last_seen))
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

export function m7Handlers(sessions: readonly Session[]) {
  const now = Date.now()
  const malware = malwareItems(now)
  return [
    http.get("/api/v1/insights", async () => {
      await delay(LATENCY_MS)
      return HttpResponse.json({ generated_at: iso(now), items: INSIGHTS })
    }),

    http.get("/api/v1/trends/new", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const field = u.searchParams.get("field") as NewField
      if (!NEW_FIELDS.includes(field))
        return HttpResponse.json({ detail: "invalid field" }, { status: 422 })
      const days = Number(u.searchParams.get("days") ?? 7)
      const limit = Number(u.searchParams.get("limit") ?? 50)
      return HttpResponse.json({ field, items: newItems(field, days, limit, now) })
    }),

    http.get("/api/v1/trends/tags", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const until = new Date(u.searchParams.get("until") ?? now).getTime()
      const since = new Date(u.searchParams.get("since") ?? until - 7 * DAY).getTime()
      const days = Math.max(1, Math.round((until - since) / DAY))
      const body: TagsResponse = {
        bucket: "1d",
        since: iso(since),
        until: iso(until),
        series: TAGS,
        points: Array.from({ length: days }, (_, d) => {
          const ts = Math.floor((since + d * DAY) / DAY) * DAY
          const tags: Record<string, number> = {}
          TAGS.forEach((t, i) => {
            // php2shell ramps up, the rest stay steady.
            const base = t === "php2shell" ? 20 + (d / days) * 120 : 60 / (i + 1)
            tags[t] = Math.round(base * (0.6 + hash(`${t}${d}`) * 0.8))
          })
          return { ts: iso(ts), tags }
        }),
      }
      return HttpResponse.json(body)
    }),

    http.get("/api/v1/malware", async ({ request }) => {
      await delay(LATENCY_MS)
      const u = new URL(request.url)
      const tool = u.searchParams.get("tool")
      const q = (u.searchParams.get("q") ?? "").toLowerCase()
      const limit = Math.min(200, Number(u.searchParams.get("limit") ?? 50))
      const all = malware.filter(
        (m) => (!tool || m.tools.includes(tool)) && (!q || m.url.toLowerCase().includes(q)),
      )
      const offset = decodeCursor(u.searchParams.get("cursor"))
      return HttpResponse.json({
        items: all.slice(offset, offset + limit),
        next_cursor: offset + limit < all.length ? encodeCursor(offset + limit) : null,
      })
    }),

    http.get("/api/v1/malware/detail", async ({ request }) => {
      await delay(LATENCY_MS)
      const url = new URL(request.url).searchParams.get("url")
      const item = malware.find((m) => m.url === url)
      if (!item) return HttpResponse.json({ detail: "url not found" }, { status: 404 })
      return HttpResponse.json({
        item,
        recent_sessions: sessions.filter((s) => s.downloads > 0).slice(0, 6),
      })
    }),
  ]
}
