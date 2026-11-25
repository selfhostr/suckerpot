/**
 * Mock Defend endpoints (blocklists, detections, exposure, feed tokens). Demo data only:
 * addresses come from the documentation ranges and hosts from example.* names. Overrides,
 * tokens and the inventory are stateful, so the write flows work in screenshots.
 */
import { mockRandom } from "./random"
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type {
  BlockEntry,
  BlockKind,
  DefendSummary,
  DetectionRule,
  ExposureReport,
  FeedToken,
  GuidanceItem,
  InventoryItem,
  OverrideItem,
} from "@/lib/defend"

/** Mock-only switch for the "feeds are off" screenshot: localStorage "suckerpot-mock-feeds" = "off". */
function mockFeedsOff(): boolean {
  try {
    return window.localStorage.getItem("suckerpot-mock-feeds") === "off"
  } catch {
    return false
  }
}

const LATENCY_MS = 160
const HOUR = 3_600_000
const DAY = 24 * HOUR

const ago = (ms: number) => new Date(Date.now() - ms).toISOString()

function encodeCursor(offset: number) {
  return btoa(JSON.stringify({ o: offset })).replace(/=+$/, "")
}

function decodeCursor(cursor: string | null): number {
  if (!cursor) return 0
  try {
    const v = JSON.parse(atob(cursor)) as { o?: unknown }
    return typeof v.o === "number" && v.o >= 0 ? v.o : 0
  } catch {
    return 0
  }
}

function page<T>(items: readonly T[], url: URL, fallback: number) {
  const requested = Number(url.searchParams.get("limit") ?? fallback)
  const limit = Number.isInteger(requested) && requested >= 1 ? Math.min(requested, 200) : fallback
  const offset = decodeCursor(url.searchParams.get("cursor"))
  const next = offset + limit < items.length ? encodeCursor(offset + limit) : null
  return { items: items.slice(offset, offset + limit), next_cursor: next }
}

/* --- Blocklist entries -------------------------------------------------- */

let seed = 7
function rnd() {
  seed = (seed * 1664525 + 1013904223) % 4294967296
  return seed / 4294967296
}
const pick = <T>(list: readonly T[]): T => list[Math.floor(rnd() * list.length)] as T

const REASON_SETS: string[][] = [
  ["brute-force", "ran-commands", "dropped-malware", "multi-sensor"],
  ["brute-force", "login-succeeded", "ran-commands"],
  ["exploit-attempt", "campaign", "repeat-visitor"],
  ["brute-force", "reported-abusive", "repeat-visitor"],
  ["brute-force", "reported-abusive"],
  ["exploit-attempt", "multi-sensor"],
  ["mass-scanner"],
  ["brute-force"],
]
const SCORES = [96, 91, 88, 84, 79, 75, 72, 68, 63, 58, 54, 47, 38, 29, 18]

function buildEntries(): BlockEntry[] {
  const out: BlockEntry[] = []
  const ranges = ["192.0.2", "198.51.100", "203.0.113"]
  for (let i = 0; i < 72; i++) {
    const reasons = pick(REASON_SETS)
    const scanner = reasons.includes("mass-scanner")
    out.push({
      kind: "ip",
      value: `${pick(ranges)}.${10 + ((i * 7) % 240)}`,
      score: scanner ? 22 : pick(SCORES),
      reasons,
      first_seen: ago((2 + Math.floor(rnd() * 25)) * DAY),
      last_seen: ago(Math.floor(rnd() * 70) * HOUR + 120_000),
      sessions: 2 + Math.floor(rnd() * 90),
      sources: 1,
      campaign_ids: reasons.includes("campaign") ? [3] : [],
      benign: scanner,
      demo: i % 9 === 0,
      override: null,
    })
  }
  const domains = ["cdn-update", "files-mirror", "dl-static", "get-tools", "pool-stat", "node-sync"]
  domains.forEach((d, i) => {
    out.push({
      kind: "domain",
      value: `${d}.example.net`,
      score: [93, 86, 78, 66, 52, 41][i] ?? 40,
      reasons: i % 2 ? ["download-source", "seen-from-many-sources"] : ["contacted-by-attacker"],
      first_seen: ago((3 + i) * DAY),
      last_seen: ago((i + 1) * 5 * HOUR),
      sessions: 4 + i * 11,
      sources: 2 + i,
      campaign_ids: [],
      benign: false,
      demo: i === 5,
      override: null,
    })
  })
  const paths = ["bins/arm7", "x/miner.sh", "update.php", "t/stage2", "pkg/agent.bin", "r/run.sh"]
  paths.forEach((p, i) => {
    out.push({
      kind: "url",
      value: `http://${pick(ranges)}.${40 + i}:8080/${p}`,
      score: [97, 90, 82, 74, 60, 51][i] ?? 50,
      reasons: ["download-source", ...(i < 3 ? ["known-malware"] : []), "dropped-malware"],
      first_seen: ago((1 + i) * DAY),
      last_seen: ago((i + 1) * 3 * HOUR),
      sessions: 3 + i * 6,
      sources: 1 + (i % 3),
      campaign_ids: i < 2 ? [3] : [],
      benign: false,
      demo: false,
      override: null,
    })
  })
  for (let i = 0; i < 4; i++) {
    out.push({
      kind: "hash",
      value: Array.from(
        { length: 64 },
        (_, k) => "0123456789abcdef"[(k * (i + 3) + i * 5) % 16],
      ).join(""),
      score: [95, 89, 77, 61][i] ?? 60,
      reasons: ["file-hash", "malware-family", ...(i < 2 ? ["known-malware"] : [])],
      first_seen: ago((4 + i) * DAY),
      last_seen: ago((i + 2) * 7 * HOUR),
      sessions: 5 + i * 8,
      sources: 2 + i,
      campaign_ids: [],
      benign: false,
      demo: false,
      override: null,
    })
  }
  return out.sort((a, b) => b.score - a.score || a.value.localeCompare(b.value))
}

const entries = buildEntries()

const overrides: OverrideItem[] = [
  {
    id: 1,
    kind: "ip",
    value: "198.51.100.77",
    action: "allow",
    note: "Our vulnerability scanner",
    created_by: "admin",
    created_at: ago(6 * DAY),
    expires_at: null,
  },
  {
    id: 2,
    kind: "domain",
    value: "tracker.example.org",
    action: "block",
    note: "Seen in a phishing mail",
    created_by: "admin",
    created_at: ago(2 * DAY),
    expires_at: ago(-28 * DAY),
  },
]
let nextOverrideId = 3

function withOverrides(): BlockEntry[] {
  return entries.map((e) => {
    const o = overrides.find((x) => x.kind === e.kind && x.value === e.value)
    return { ...e, override: o ? o.action : null }
  })
}

function summary(): DefendSummary {
  const kinds = (["ip", "domain", "url", "hash"] as BlockKind[]).map((kind) => {
    const list = entries.filter((e) => e.kind === kind && !e.benign)
    return {
      kind,
      total: entries.filter((e) => e.kind === kind).length,
      listed: list.filter((e) => e.score >= 50).length,
      high: list.filter((e) => e.score >= 70).length,
    }
  })
  const counts = new Map<string, number>()
  for (const e of entries) for (const r of e.reasons) counts.set(r, (counts.get(r) ?? 0) + 1)
  return {
    computed_at: ago(14 * 60_000),
    worker_enabled: true,
    feeds_enabled: !mockFeedsOff(),
    kinds,
    top_reasons: [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([reason, count]) => ({ reason, count })),
    demo_entries: entries.filter((e) => e.demo).length,
    overrides: overrides.length,
  }
}

const VALID_IP = /^(\d{1,3}\.){3}\d{1,3}$/

/* --- Detections --------------------------------------------------------- */

const SIGMA = (title: string, id: string, selection: string, level: string) =>
  `title: ${title}
id: ${id}
status: experimental
description: Written from decoy traffic. Review before you deploy it.
logsource:
  category: webserver
detection:
  selection:
${selection}
  condition: selection
falsepositives:
  - Authorized security testing
level: ${level}
`

const SURICATA = (msg: string, content: string, sid: number) =>
  `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"${msg}"; flow:established,to_server; http.uri; content:"${content}"; nocase; classtype:web-application-attack; sid:${sid}; rev:1;)\n`

const RULES: DetectionRule[] = [
  {
    id: "sigma-web-upload-progress",
    kind: "sigma",
    title: "Web request probing PHP upload progress",
    severity: "severe",
    source: "web-paths",
    rationale: "Attackers sent crafted upload-progress requests to the fake PHP stack.",
    sessions: 214,
    sources: 38,
    text: SIGMA(
      "Web request probing PHP upload progress",
      "7c1d1c2a-0f4e-4c5b-9a41-2f7e8d000001",
      "    cs-uri-query|contains: 'PHP_SESSION_UPLOAD_PROGRESS'",
      "high",
    ),
  },
  {
    id: "sigma-shell-miner",
    kind: "sigma",
    title: "Shell command that fetches and runs a script",
    severity: "severe",
    source: "commands",
    rationale: "Sessions that logged in then piped a download straight into a shell.",
    sessions: 167,
    sources: 52,
    text: SIGMA(
      "Shell command that fetches and runs a script",
      "7c1d1c2a-0f4e-4c5b-9a41-2f7e8d000002",
      "    CommandLine|re: '(wget|curl) .*\\| *(sh|bash)'",
      "high",
    ),
  },
  {
    id: "sigma-env-probe",
    kind: "sigma",
    title: "Request for a dotenv or git config file",
    severity: "warning",
    source: "web-paths",
    rationale: "Scanners looked for leaked secrets in common file locations.",
    sessions: 903,
    sources: 121,
    text: SIGMA(
      "Request for a dotenv or git config file",
      "7c1d1c2a-0f4e-4c5b-9a41-2f7e8d000003",
      "    cs-uri-stem|endswith:\n      - '/.env'\n      - '/.git/config'",
      "medium",
    ),
  },
  {
    id: "sigma-cron-persist",
    kind: "sigma",
    title: "Shell command that edits the crontab",
    severity: "warning",
    source: "commands",
    rationale: "Attackers tried to stay on the host by adding a scheduled job.",
    sessions: 58,
    sources: 19,
    text: SIGMA(
      "Shell command that edits the crontab",
      "7c1d1c2a-0f4e-4c5b-9a41-2f7e8d000004",
      "    CommandLine|contains: 'crontab'",
      "medium",
    ),
  },
  {
    id: "sigma-ssh-keys",
    kind: "sigma",
    title: "Shell command that adds an SSH key",
    severity: "warning",
    source: "commands",
    rationale: "Attackers appended their own key to authorized_keys.",
    sessions: 44,
    sources: 12,
    text: SIGMA(
      "Shell command that adds an SSH key",
      "7c1d1c2a-0f4e-4c5b-9a41-2f7e8d000005",
      "    CommandLine|contains: 'authorized_keys'",
      "medium",
    ),
  },
  {
    id: "sigma-domain-example",
    kind: "sigma",
    title: "DNS lookup of a download host seen in attacks",
    severity: "notice",
    source: "domains",
    rationale: "Several attackers pointed their tools at the same download hosts.",
    sessions: 31,
    sources: 6,
    text: SIGMA(
      "DNS lookup of a download host seen in attacks",
      "7c1d1c2a-0f4e-4c5b-9a41-2f7e8d000006",
      "    QueryName|endswith:\n      - '.example.net'",
      "low",
    ),
  },
  {
    id: "sigma-hash",
    kind: "sigma",
    title: "File with a hash of a dropped binary",
    severity: "notice",
    source: "hashes",
    rationale: "A file that attackers dropped on more than one decoy.",
    sessions: 27,
    sources: 5,
    text: SIGMA(
      "File with a hash of a dropped binary",
      "7c1d1c2a-0f4e-4c5b-9a41-2f7e8d000007",
      "    Hashes|contains: 'SHA256=0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0'",
      "low",
    ),
  },
  ...(
    [
      ["Request for a PHP upload-progress path", "PHP_SESSION_UPLOAD_PROGRESS", "severe", 214, 38],
      ["Request for a dotenv file", "/.env", "warning", 903, 121],
      ["Request for a git config file", "/.git/config", "warning", 611, 88],
      ["Request for an admin login page", "/wp-login.php", "notice", 480, 94],
      ["Request for a shell upload path", "/shell.php", "severe", 96, 21],
      ["Request for a backup archive", "/backup.zip", "notice", 74, 30],
    ] as const
  ).map(([msg, content, severity, sessions, sources], i): DetectionRule => ({
    id: `suricata-${i}`,
    kind: "suricata",
    title: msg,
    severity,
    source: i === 0 ? "static" : "web-paths",
    rationale: "Seen in HTTP requests to the web decoy from several unrelated sources.",
    sessions,
    sources,
    text: SURICATA(`SuckerPot ${msg}`, content, 9100100 + i),
  })),
  {
    id: "suricata-download",
    kind: "suricata",
    title: "HTTP download from a host seen in attacks",
    severity: "severe",
    source: "urls",
    rationale: "Attackers repeatedly fetched tools from the same address.",
    sessions: 88,
    sources: 14,
    text: `alert http $HOME_NET any -> 203.0.113.41 any (msg:"SuckerPot download from a host seen in attacks"; flow:established,to_server; classtype:trojan-activity; sid:9100200; rev:1;)\n`,
  },
]

const GUIDANCE: GuidanceItem[] = [
  {
    tag: "ssh-brute-force",
    title: "Password guessing against SSH",
    severity: "warning",
    what: "Bots try thousands of username and password pairs against every SSH server they find, mostly root, admin and ubuntu.",
    look: [
      "Many failed logins from one address in sshd or auth logs.",
      "A successful login right after a long run of failures.",
    ],
    fix: [
      "Turn off password logins and use keys.",
      "Do not expose SSH to the internet; use a VPN or a bastion host.",
      "Rate-limit or ban repeated failures with a tool such as fail2ban.",
    ],
    seen: { sessions: 1840, sources: 412, last_seen: ago(4 * 60_000) },
  },
  {
    tag: "php2shell",
    title: "Remote code execution through PHP upload progress",
    severity: "severe",
    what: "Attackers send crafted multipart requests to PHP pages hoping an unpatched PHP runs their code.",
    look: [
      "Requests with PHP_SESSION_UPLOAD_PROGRESS in the form data.",
      "New .php files in upload or temp folders.",
      "The web server process starting a shell.",
    ],
    fix: [
      "Update PHP to a fixed release.",
      "Turn off upload progress tracking if you do not use it.",
      "Run the web server as an unprivileged user with a read-only application folder.",
    ],
    seen: { sessions: 214, sources: 38, last_seen: ago(26 * 60_000) },
  },
  {
    tag: "crypto-miner",
    title: "Crypto miners dropped after a login",
    severity: "severe",
    what: "Once inside, attackers download a mining program and run it in the background.",
    look: [
      "A process that uses most of the CPU with an odd name.",
      "Outbound connections to mining pool ports such as 3333 or 4444.",
      "New cron jobs or systemd units you did not create.",
    ],
    fix: [
      "Block outbound traffic that servers do not need.",
      "Rebuild a host from a clean image if a miner ran on it.",
    ],
    seen: { sessions: 167, sources: 52, last_seen: ago(2 * HOUR) },
  },
  {
    tag: "recon",
    title: "Scanning for exposed files and admin pages",
    severity: "notice",
    what: "Scanners request well-known paths looking for secrets, backups and admin consoles.",
    look: [
      "Requests for /.env, /.git/config, /wp-login.php or /phpmyadmin in your web logs.",
      "A burst of 404 answers from one address.",
    ],
    fix: [
      "Keep secrets and backups out of the web root.",
      "Put admin pages behind a VPN or single sign-on.",
    ],
    seen: { sessions: 903, sources: 121, last_seen: ago(9 * 60_000) },
  },
]

/* --- Exposure ------------------------------------------------------------ */

const inventory: InventoryItem[] = [
  inv(1, "Jump host", "ssh", "OpenSSH", "9.6", "internet", "Used by the ops team"),
  inv(2, "Company website", "web", "Apache", "2.4.58", "internet", "Runs the marketing site"),
  inv(3, "Shop backend", "web", "PHP", "8.3.30", "internet", null),
  inv(4, "Remote desktop gateway", "rdp", "Windows Server", "2022", "vpn", null),
  inv(5, "Session cache", "redis", "Redis", "7.2", "internal", "Only the app servers connect"),
]
let nextInventoryId = 6

function inv(
  id: number,
  name: string,
  service: string,
  product: string | null,
  version: string | null,
  exposure: InventoryItem["exposure"],
  notes: string | null,
): InventoryItem {
  return {
    id,
    name,
    service,
    product,
    version,
    exposure,
    notes,
    created_by: "admin",
    created_at: ago(12 * DAY),
    updated_at: ago(3 * DAY),
  }
}

const STATS: Record<string, { sessions: number; previous: number; deep: number; sources: number }> =
  {
    ssh: { sessions: 1840, previous: 1520, deep: 212, sources: 412 },
    web: { sessions: 1290, previous: 1410, deep: 97, sources: 266 },
    rdp: { sessions: 188, previous: 120, deep: 0, sources: 74 },
    redis: { sessions: 64, previous: 70, deep: 9, sources: 23 },
    mysql: { sessions: 92, previous: 61, deep: 4, sources: 31 },
    smb: { sessions: 140, previous: 133, deep: 0, sources: 52 },
    synology: { sessions: 58, previous: 21, deep: 6, sources: 19 },
  }

const CHECKS: Record<string, string[]> = {
  ssh: [
    "Confirm password logins are off in sshd_config.",
    "Check that no account has an empty or default password.",
    "Review authorized_keys files for keys you do not recognise.",
  ],
  web: [
    "Compare your PHP version with the fixed releases for the upload-progress flaw.",
    "Search your web logs for requests to /.env and /.git/config.",
  ],
  rdp: [
    "Make sure Remote Desktop is only reachable through the VPN.",
    "Require network level authentication and multi-factor sign-in.",
  ],
  redis: ["Check that Redis requires a password and listens on a private address only."],
  mysql: ["Check that the database port is not reachable from the internet."],
  smb: ["Make sure file sharing is blocked at the firewall and SMBv1 is off."],
  synology: [
    "Update DSM to the release fixed in Synology-SA-26:13 and turn on automatic updates.",
    "Keep the DSM ports (5000 and 5001) off the internet and use the VPN instead.",
  ],
}

const TAGS: Record<string, { tag: string; sessions: number }[]> = {
  ssh: [
    { tag: "brute-force", sessions: 1650 },
    { tag: "crypto-miner", sessions: 120 },
    { tag: "persistence", sessions: 44 },
  ],
  web: [
    { tag: "recon", sessions: 903 },
    { tag: "php2shell", sessions: 214 },
  ],
  rdp: [{ tag: "recon", sessions: 150 }],
  redis: [{ tag: "redis-rogue-master", sessions: 9 }],
}

function exposureReport(days: number): ExposureReport {
  const scale = days / 30
  const listed = new Set(inventory.map((i) => i.service))
  return {
    days,
    generated_at: ago(60_000),
    services: inventory.map((item) => {
      const s = STATS[item.service] ?? { sessions: 0, previous: 0, deep: 0, sources: 0 }
      const internet = item.exposure === "internet"
      const sessions = Math.round(s.sessions * scale)
      return {
        item,
        label: item.service.toUpperCase(),
        verdict: internet
          ? sessions > 0
            ? "internet_targeted"
            : "internet_quiet"
          : sessions > 0
            ? "private_targeted"
            : "private_quiet",
        attacks: {
          sessions,
          sources: Math.round(s.sources * Math.sqrt(scale)),
          deep_sessions: Math.round(s.deep * scale),
          previous_sessions: Math.round(s.previous * scale),
          last_attack_at: sessions > 0 ? ago(11 * 60_000) : null,
        },
        top_tags: TAGS[item.service] ?? [],
        cves:
          item.service === "web" && item.product === "PHP"
            ? [
                {
                  cve_id: "CVE-2026-109618",
                  title: "PHP upload-progress remote code execution",
                  cvss_score: 9.2,
                  in_kev: true,
                },
                {
                  cve_id: "CVE-2026-109619",
                  title: "PHP upload-progress session takeover",
                  cvss_score: 9.2,
                  in_kev: false,
                },
              ]
            : [],
        checks: CHECKS[item.service] ?? [],
      }
    }),
    unlisted: ["mysql", "smb"]
      .filter((s) => !listed.has(s))
      .map((service) => {
        const s = STATS[service] ?? { sessions: 0, previous: 0, deep: 0, sources: 0 }
        return {
          service,
          label: service.toUpperCase(),
          sessions: Math.round(s.sessions * scale),
          sources: Math.round(s.sources * Math.sqrt(scale)),
          checks: CHECKS[service] ?? [],
        }
      }),
  }
}

/* --- Feed tokens --------------------------------------------------------- */

const tokens: FeedToken[] = [
  {
    id: 1,
    name: "OPNsense edge firewall",
    hint: "starts with k3Jx9a",
    kinds: ["ip"],
    min_score: 70,
    include_benign: false,
    created_by: "admin",
    created_at: ago(18 * DAY),
    expires_at: null,
    revoked_at: null,
    last_used_at: ago(3 * HOUR),
    last_used_ip: "198.51.100.5",
    use_count: 431,
    state: "active",
  },
  {
    id: 2,
    name: "Web proxy",
    hint: "starts with Qm7Lp2",
    kinds: ["domain", "url"],
    min_score: 50,
    include_benign: false,
    created_by: "admin",
    created_at: ago(40 * DAY),
    expires_at: ago(-50 * DAY),
    revoked_at: null,
    last_used_at: ago(20 * HOUR),
    last_used_ip: "198.51.100.9",
    use_count: 58,
    state: "active",
  },
  {
    id: 3,
    name: "Old test token",
    hint: "starts with Zt0b8c",
    kinds: ["ip", "domain"],
    min_score: 50,
    include_benign: true,
    created_by: "admin",
    created_at: ago(90 * DAY),
    expires_at: null,
    revoked_at: ago(30 * DAY),
    last_used_at: ago(31 * DAY),
    last_used_ip: "203.0.113.200",
    use_count: 12,
    state: "revoked",
  },
  {
    id: 4,
    name: "Contractor laptop",
    hint: "starts with Vd4e6h",
    kinds: ["ip"],
    min_score: 50,
    include_benign: false,
    created_by: "admin",
    created_at: ago(60 * DAY),
    expires_at: ago(5 * DAY),
    revoked_at: null,
    last_used_at: null,
    last_used_ip: null,
    use_count: 0,
    state: "expired",
  },
]
let nextTokenId = 5

function randomToken() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
  let out = ""
  for (let i = 0; i < 43; i++) out += alphabet.charAt(Math.floor(mockRandom() * alphabet.length))
  return out
}

/* --- Handlers ------------------------------------------------------------ */

export const defendHandlers: RequestHandler[] = [
  http.get("/api/v1/defend/summary", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(summary())
  }),

  http.get("/api/v1/defend/blocklist", async ({ request }) => {
    await delay(LATENCY_MS)
    const url = new URL(request.url)
    const kind = url.searchParams.get("kind")
    const min = Number(url.searchParams.get("min_score") ?? 10)
    const q = (url.searchParams.get("q") ?? "").toLowerCase()
    const reason = url.searchParams.get("reason")
    const benign = url.searchParams.get("include_benign") === "true"
    const items = withOverrides().filter(
      (e) =>
        (!kind || e.kind === kind) &&
        e.score >= min &&
        (benign || !e.benign) &&
        (!reason || e.reasons.includes(reason)) &&
        (!q || e.value.toLowerCase().includes(q)),
    )
    return HttpResponse.json(page(items, url, 50))
  }),

  http.get("/api/v1/defend/export", ({ request }) => {
    const url = new URL(request.url)
    const kind = url.searchParams.get("kind") ?? "ip"
    const min = Number(url.searchParams.get("min_score") ?? 50)
    const csv = url.searchParams.get("format") === "csv"
    const rows = entries.filter((e) => e.kind === kind && e.score >= min && !e.benign && !e.demo)
    const body = csv
      ? ["value,score", ...rows.map((e) => `${e.value},${e.score}`)].join("\n")
      : rows.map((e) => e.value).join("\n")
    return new HttpResponse(`${body}\n`, {
      headers: {
        "Content-Type": csv ? "text/csv" : "text/plain",
        "Content-Disposition": `attachment; filename="${kind}-export.${csv ? "csv" : "txt"}"`,
      },
    })
  }),

  http.get("/api/v1/defend/overrides", async ({ request }) => {
    await delay(LATENCY_MS)
    return HttpResponse.json(page(overrides, new URL(request.url), 50))
  }),
  http.post("/api/v1/defend/overrides", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as {
      kind: BlockKind
      value: string
      action: "allow" | "block"
      note?: string
      expires_in_days?: number
    }
    const value = body.value.trim()
    if (
      body.kind === "ip" &&
      (!VALID_IP.test(value) || value.startsWith("10.") || value.startsWith("192.168."))
    ) {
      return HttpResponse.json(
        { detail: "That address is private and cannot be blocked.", code: "invalid_value" },
        { status: 422 },
      )
    }
    const index = overrides.findIndex((o) => o.kind === body.kind && o.value === value)
    if (index >= 0) overrides.splice(index, 1)
    const item: OverrideItem = {
      id: nextOverrideId++,
      kind: body.kind,
      value,
      action: body.action,
      note: body.note ?? null,
      created_by: "admin",
      created_at: new Date().toISOString(),
      expires_at: body.expires_in_days ? ago(-body.expires_in_days * DAY) : null,
    }
    overrides.unshift(item)
    return HttpResponse.json(item, { status: 201 })
  }),
  http.delete("/api/v1/defend/overrides/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const index = overrides.findIndex((o) => o.id === Number(params.id))
    if (index >= 0) overrides.splice(index, 1)
    return new HttpResponse(null, { status: 204 })
  }),

  http.get("/api/v1/defend/feed-tokens", async () => {
    await delay(LATENCY_MS)
    if (mockFeedsOff()) return HttpResponse.json({ enabled: false, items: [] })
    return HttpResponse.json({ enabled: true, items: tokens })
  }),
  http.post("/api/v1/defend/feed-tokens", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as {
      name: string
      kinds: BlockKind[]
      min_score: number
      include_benign: boolean
      expires_in_days?: number
      password: string
    }
    if (body.password === "wrong")
      return HttpResponse.json({ detail: "Wrong password", code: "reauth_failed" }, { status: 403 })
    if (body.password === "limited")
      return HttpResponse.json({ detail: "Too many attempts" }, { status: 429 })
    const token = randomToken()
    const item: FeedToken = {
      id: nextTokenId++,
      name: body.name,
      hint: `starts with ${token.slice(0, 6)}`,
      kinds: body.kinds,
      min_score: body.min_score,
      include_benign: body.include_benign,
      created_by: "admin",
      created_at: new Date().toISOString(),
      expires_at: body.expires_in_days ? ago(-body.expires_in_days * DAY) : null,
      revoked_at: null,
      last_used_at: null,
      last_used_ip: null,
      use_count: 0,
      state: "active",
    }
    tokens.unshift(item)
    return HttpResponse.json({ token, item }, { status: 201 })
  }),
  http.post("/api/v1/defend/feed-tokens/:id/revoke", async ({ params }) => {
    await delay(LATENCY_MS)
    const item = tokens.find((t) => t.id === Number(params.id))
    if (!item) return HttpResponse.json({ detail: "Not found", code: "not_found" }, { status: 404 })
    item.state = "revoked"
    item.revoked_at = new Date().toISOString()
    return HttpResponse.json(item)
  }),

  http.get("/api/v1/defend/detections", async ({ request }) => {
    await delay(LATENCY_MS)
    const url = new URL(request.url)
    const kind = url.searchParams.get("kind") === "suricata" ? "suricata" : "sigma"
    const days = Number(url.searchParams.get("days") ?? 30)
    const scale = Math.max(0.2, days / 30)
    const items = RULES.filter((r) => r.kind === kind).map((r) => ({
      ...r,
      sessions: Math.max(2, Math.round(r.sessions * scale)),
    }))
    return HttpResponse.json({
      generated_at: ago(30 * 60_000),
      days,
      total: items.length,
      ...page(items, url, 25),
    })
  }),
  http.get("/api/v1/defend/detections/export", ({ request }) => {
    const kind = new URL(request.url).searchParams.get("kind") === "suricata" ? "suricata" : "sigma"
    const text = RULES.filter((r) => r.kind === kind)
      .map((r) => r.text)
      .join(kind === "sigma" ? "---\n" : "")
    return new HttpResponse(text, {
      headers: {
        "Content-Type": "text/plain",
        "Content-Disposition": `attachment; filename="${kind === "sigma" ? "sigma-rules.yml" : "suricata.rules"}"`,
      },
    })
  }),
  http.get("/api/v1/defend/guidance", async ({ request }) => {
    await delay(LATENCY_MS)
    const days = Number(new URL(request.url).searchParams.get("days") ?? 30)
    return HttpResponse.json({ days, items: GUIDANCE })
  }),

  http.get("/api/v1/defend/inventory", async ({ request }) => {
    await delay(LATENCY_MS)
    return HttpResponse.json(page(inventory, new URL(request.url), 200))
  }),
  http.post("/api/v1/defend/inventory", async ({ request }) => {
    await delay(LATENCY_MS)
    const b = (await request.json()) as Partial<InventoryItem>
    const item = inv(
      nextInventoryId++,
      b.name ?? "Unnamed",
      b.service ?? "ssh",
      b.product ?? null,
      b.version ?? null,
      b.exposure ?? "internet",
      b.notes ?? null,
    )
    item.created_at = item.updated_at = new Date().toISOString()
    inventory.push(item)
    return HttpResponse.json(item, { status: 201 })
  }),
  http.patch("/api/v1/defend/inventory/:id", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const item = inventory.find((i) => i.id === Number(params.id))
    if (!item) return HttpResponse.json({ detail: "Not found", code: "not_found" }, { status: 404 })
    Object.assign(item, await request.json(), { updated_at: new Date().toISOString() })
    return HttpResponse.json(item)
  }),
  http.delete("/api/v1/defend/inventory/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const index = inventory.findIndex((i) => i.id === Number(params.id))
    if (index >= 0) inventory.splice(index, 1)
    return new HttpResponse(null, { status: 204 })
  }),
  http.get("/api/v1/defend/exposure", async ({ request }) => {
    await delay(LATENCY_MS)
    const days = Number(new URL(request.url).searchParams.get("days") ?? 30)
    return HttpResponse.json(exposureReport(days))
  }),
]
