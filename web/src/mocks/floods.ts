/**
 * Flood groups for the mock API and the demo build: a source that opened hundreds of plain
 * connections in one UTC hour is one row (`kind: "burst"`, `connections: N`), exactly as the API
 * returns it. Documentation addresses only (RFC 5737) and private-use ASNs (RFC 5398); every name
 * and password below is made up. Times are relative to `now`, so the groups always sit inside the
 * last day.
 */
import type { SensorEvent, Session, SessionCredentials } from "@/lib/api"
import type { Fixture } from "./fixtures"

const HOUR = 3_600_000
/** Events the mock stores per group; the real API pages through all of them. */
const STORED_EVENTS = 220

export interface FloodFixture extends Fixture {
  credentials: SessionCredentials
}

interface Origin {
  country: string
  city: string
  asn: number
  org: string
}

interface FloodSpec {
  ip: string
  origin: Origin
  sensor: "rdp" | "telnet" | "ssh" | "web"
  dstPort: number
  /** Hours before the current UTC hour: 0 is the hour in progress. */
  hourOffset: number
  connections: number
  /** Login attempts per connection (0: connect and leave). */
  perConnection: number
  tags: string[]
  tool?: string
  abuse: number
  usernames: [string, number][]
  passwords: [string, number][]
  distinctPasswords: number
  distinctPairs: number
  /** Cleartext RDP carries the password; NTLM would not. */
  method: "rdp-nla-off" | "password"
}

const NL: Origin = { country: "NL", city: "Amsterdam", asn: 64496, org: "Polder Cloud BV" }
const CN: Origin = { country: "CN", city: "Shenzhen", asn: 64498, org: "Sample Telecom" }
const FR: Origin = { country: "FR", city: "Roubaix", asn: 64505, org: "Hexagone Serveurs" }
const US: Origin = { country: "US", city: "Ashburn", asn: 64497, org: "Example Hosting LLC" }

const SPRAY = [
  "Spring2026!",
  "Summer2026!",
  "Welcome2026",
  "Passw0rd!",
  "Admin@123",
  "Company#2026",
  "Winter2026?",
  "Changeme1",
  "P@ssword1",
  "Letmein!2026",
]

const SPECS: FloodSpec[] = [
  {
    ip: "198.51.100.200",
    origin: NL,
    sensor: "rdp",
    dstPort: 3389,
    hourOffset: 2,
    connections: 812,
    perConnection: 1,
    tags: ["rdp-cleartext"],
    tool: "FreeRDP",
    abuse: 74,
    usernames: [["Administrator", 812]],
    passwords: SPRAY.map((p) => [p, 1]),
    distinctPasswords: 812,
    distinctPairs: 812,
    method: "rdp-nla-off",
  },
  {
    // Same address and hour as the group above: it only connected and left.
    ip: "198.51.100.200",
    origin: NL,
    sensor: "rdp",
    dstPort: 3389,
    hourOffset: 2,
    connections: 96,
    perConnection: 0,
    tags: ["scanner"],
    abuse: 74,
    usernames: [],
    passwords: [],
    distinctPasswords: 0,
    distinctPairs: 0,
    method: "rdp-nla-off",
  },
  {
    ip: "198.51.100.200",
    origin: NL,
    sensor: "rdp",
    dstPort: 3389,
    hourOffset: 3,
    connections: 644,
    perConnection: 1,
    tags: ["rdp-cleartext"],
    tool: "FreeRDP",
    abuse: 74,
    usernames: [["Administrator", 644]],
    passwords: SPRAY.map((p) => [p, 1]),
    distinctPasswords: 644,
    distinctPairs: 644,
    method: "rdp-nla-off",
  },
  {
    ip: "192.0.2.201",
    origin: CN,
    sensor: "telnet",
    dstPort: 23,
    hourOffset: 1,
    connections: 1204,
    perConnection: 1,
    tags: ["credential-stuffing"],
    abuse: 91,
    usernames: [
      ["root", 612],
      ["admin", 301],
      ["support", 120],
      ["user", 94],
      ["guest", 77],
    ],
    passwords: [
      ["xc3511", 190],
      ["vizxv", 160],
      ["123456", 141],
      ["admin", 130],
      ["default", 96],
      ["888888", 81],
      ["juantech", 74],
      ["54321", 62],
      ["12345", 55],
      ["password", 48],
    ],
    distinctPasswords: 24,
    distinctPairs: 31,
    method: "password",
  },
  {
    ip: "192.0.2.201",
    origin: CN,
    sensor: "telnet",
    dstPort: 23,
    hourOffset: 0,
    connections: 143,
    perConnection: 1,
    tags: ["credential-stuffing"],
    abuse: 91,
    usernames: [
      ["root", 80],
      ["admin", 63],
    ],
    passwords: [
      ["xc3511", 40],
      ["vizxv", 31],
      ["123456", 26],
      ["admin", 22],
      ["default", 24],
    ],
    distinctPasswords: 9,
    distinctPairs: 11,
    method: "password",
  },
  {
    ip: "203.0.113.202",
    origin: FR,
    sensor: "ssh",
    dstPort: 22,
    hourOffset: 5,
    connections: 438,
    perConnection: 2,
    tags: ["credential-stuffing"],
    abuse: 58,
    usernames: [
      ["root", 700],
      ["admin", 120],
      ["ubuntu", 56],
    ],
    passwords: [
      ["123456", 90],
      ["password", 71],
      ["root", 64],
      ["admin", 58],
      ["qwerty", 41],
      ["raspberry", 33],
      ["P@ssw0rd", 29],
      ["changeme", 27],
      ["letmein", 22],
      ["12345678", 19],
    ],
    distinctPasswords: 211,
    distinctPairs: 340,
    method: "password",
  },
  {
    ip: "192.0.2.203",
    origin: US,
    sensor: "web",
    dstPort: 80,
    hourOffset: 7,
    connections: 300,
    perConnection: 0,
    tags: [],
    abuse: 12,
    usernames: [],
    passwords: [],
    distinctPasswords: 0,
    distinctPairs: 0,
    method: "password",
  },
]

/** FNV-1a over the whole seed, then one more round per 8 hex characters wanted. */
function hex(seed: string, length: number): string {
  let h = 0x811c9dc5
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  let out = ""
  while (out.length < length) {
    h ^= out.length + 0x9e37
    h = Math.imul(h, 0x01000193) >>> 0
    out += h.toString(16).padStart(8, "0")
  }
  return out.slice(0, length)
}

function iso(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z")
}

/** The ids of single connections are 11 characters of [A-Za-z0-9_-], like the sensors make them. */
function connectionId(seed: string): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
  const h = hex(seed, 22)
  let out = ""
  for (let i = 0; i < 11; i++) out += chars.charAt(parseInt(h.slice(i * 2, i * 2 + 2), 16) % 64)
  return out
}

function buildOne(spec: FloodSpec, now: number, eventId: number): FloodFixture {
  const hourStart = Math.floor(now / HOUR) * HOUR - spec.hourOffset * HOUR
  const startedAt = hourStart + Math.min(3 * 60_000, Math.floor((now - hourStart) / 4))
  const lastAt = spec.hourOffset === 0 ? now - 90_000 : hourStart + 57 * 60_000
  const id = `burst-${hex(`${spec.ip}|${spec.sensor}|${spec.hourOffset}|${spec.perConnection}`, 24)}`
  const attempts = spec.connections * spec.perConnection
  const base = {
    sensor: spec.sensor,
    src_ip: spec.ip,
    dst_port: spec.dstPort,
    country: spec.origin.country,
    city: spec.origin.city,
    asn: spec.origin.asn,
    org: spec.origin.org,
    abuse_score: spec.abuse,
    known_scanner: false,
  }

  const events: SensorEvent[] = []
  const step = Math.max(1, Math.floor((lastAt - startedAt) / spec.connections))
  for (let k = 0; events.length < STORED_EVENTS && k < spec.connections; k++) {
    const sid = connectionId(`${id}-${k}`)
    const srcPort = 32768 + ((k * 7919) % 28000)
    let ts = startedAt + k * step
    const push = (type: string, data: Record<string, unknown>, after: number) => {
      ts += after
      events.push({
        ...base,
        id: eventId + events.length,
        ts: iso(ts),
        session_id: sid,
        src_port: srcPort,
        tags: [],
        type,
        data,
      })
    }
    push("connect", spec.sensor === "ssh" ? { client_version: "SSH-2.0-libssh_0.9.6" } : {}, 0)
    for (let a = 0; a < spec.perConnection; a++) {
      const user = spec.usernames[(k + a) % Math.max(1, spec.usernames.length)]?.[0] ?? "admin"
      const secret = SPRAY[(k * 3 + a) % SPRAY.length] ?? "123456"
      push(
        "login_attempt",
        spec.sensor === "rdp"
          ? {
              username: user,
              password: `${secret}${k}`,
              success: false,
              method: spec.method,
              client_tool: spec.tool ?? null,
              domain: "WORKGROUP",
            }
          : { username: user, password: `${secret}${k}`, success: false, method: spec.method },
        300 + a * 200,
      )
    }
    push("disconnect", { duration_s: 1, reason: "eof" }, 800)
  }

  const session: Session = {
    ...base,
    session_id: id,
    src_port: 0,
    started_at: iso(startedAt),
    ended_at: iso(lastAt),
    last_event_at: iso(lastAt),
    event_count: spec.connections * 2 + attempts,
    login_attempts: attempts,
    login_success: false,
    commands: 0,
    downloads: 0,
    http_requests: 0,
    client_tool: spec.tool ?? null,
    tags: spec.tags,
    kind: "burst",
    connections: spec.connections,
  }
  const credentials: SessionCredentials = {
    attempts,
    distinct_usernames: spec.usernames.length,
    distinct_passwords: spec.distinctPasswords,
    distinct_pairs: spec.distinctPairs,
    truncated: false,
    usernames: spec.usernames.map(([value, count]) => ({ value, count })),
    passwords: spec.passwords.map(([value, count]) => ({ value, count })),
    pairs: [],
  }
  return { session, events, credentials }
}

/** The flood groups, newest first. */
export function buildFloodFixtures(now = Date.now()): FloodFixture[] {
  return SPECS.map((spec, i) => buildOne(spec, now, 700_000 + i * 1_000)).sort(
    (a, b) => Date.parse(b.session.started_at) - Date.parse(a.session.started_at),
  )
}
