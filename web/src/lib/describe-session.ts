import type { Session } from "./api"
import { countryName, formatNumber, plural } from "./format"
import { connectionsOf, isFlood } from "./floods"
import { sensorMeta } from "./sensors"

/**
 * The pieces of a one-line session story. The UI renders `subject` as an
 * IP chip and `origin` in a muted tone; `describeSessionText` joins them.
 */
export interface SessionStoryParts {
  subject: string
  origin: string | null
  predicate: string
}

/** Tags that change how the story reads, from strongest to weakest. */
const INSTALL_TAGS: readonly (readonly [string, string])[] = [
  ["crypto-miner", "a crypto-miner"],
  ["mirai", "a Mirai botnet loader"],
  ["malware-drop", "malware"],
]
const EXPLOIT_TAGS: readonly (readonly [string, string])[] = [
  ["php2shell", "a PHP2Shell exploit"],
  ["container-escape", "a container escape"],
]
/** Exploits that ride on commands (SQL). EternalBlue rides on a bare SMB probe: see idleClause. */
const COMMAND_EXPLOITS: readonly (readonly [string, string])[] = [
  ["sql-rce", "code execution through SQL"],
]

function firstTag(tags: string[], table: readonly (readonly [string, string])[]) {
  return table.find(([tag]) => tags.includes(tag))?.[1] ?? null
}

function joinAnd(parts: string[]): string {
  if (parts.length <= 1) return parts.join("")
  return `${parts.slice(0, -1).join(", ")} and ${parts.at(-1) ?? ""}`
}

export function sessionOrigin(s: Pick<Session, "country" | "org">): string | null {
  const country = s.country ? (countryName(s.country) ?? s.country) : null
  const parts = [country, s.org].filter((p): p is string => Boolean(p))
  return parts.length ? parts.join(", ") : null
}

/** " with FreeRDP" for a session whose sensor guessed the client; "" otherwise. */
export function clientToolClause(s: Pick<Session, "sensor" | "client_tool">): string {
  const tool = s.client_tool?.trim()
  return s.sensor === "rdp" && tool && tool !== "unknown" ? ` with ${tool}` : ""
}

function accessClause(s: Session, noun: string): string | null {
  if (s.login_attempts <= 0) return null
  const tool = clientToolClause(s)
  if (s.login_success && s.login_attempts === 1)
    return `logged in to ${noun} on the first try${tool}`
  const what = sensorMeta(s.sensor)?.credential ?? "login"
  const tried = `tried ${plural(s.login_attempts, `${noun} ${what}`)}${tool}`
  return s.login_success ? `${tried} and got in` : tried
}

function actionClauses(s: Session): string[] {
  const out: string[] = []
  if (s.http_requests > 0) {
    const exploit = firstTag(s.tags, EXPLOIT_TAGS)
    const kind = s.sensor === "docker" ? "Docker API request" : "HTTP request"
    const requests = `sent ${plural(s.http_requests, kind)}`
    out.push(exploit ? `${requests}, including ${exploit}` : requests)
  }
  if (s.commands > 0) {
    const install = firstTag(s.tags, INSTALL_TAGS)
    const rce = firstTag(s.tags, COMMAND_EXPLOITS)
    const ran = `ran ${plural(s.commands, "command")}`
    out.push(install ? `${ran} to install ${install}` : rce ? `${ran}, trying ${rce}` : ran)
  }
  if (s.downloads > 0) out.push(`tried to download ${plural(s.downloads, "file")}`)
  if (s.sensor === "rdp" && s.tags.includes("bluekeep")) out.push("probed for BlueKeep")
  return out
}

function idleClause(s: Session, noun: string): string {
  if (s.ended_at === null) return `is connected to ${noun}`
  if (s.sensor === "web" || s.sensor === "docker")
    return "opened a connection without sending a request"
  if (s.tags.includes("eternalblue")) return `sent an EternalBlue exploit to ${noun}`
  if (s.sensor === "smb" || s.sensor === "sip") return `probed the ${noun} service and left`
  return `connected to ${noun} and left without logging in`
}

/** The Synology DSM sensor: a login page, a web API and a few signature exploits. */
function synologyPredicate(s: Session): string {
  const nas = "the Synology NAS"
  const ransom = s.tags.includes("c3rb3r")
  const forged = s.tags.includes("synology-exploit")
  const out: string[] = []
  if (s.login_attempts > 0) {
    const tried = `tried ${plural(s.login_attempts, "DSM admin password")} on ${nas}`
    out.push(s.login_success ? `${tried} and got in` : tried)
  }
  if (s.http_requests > 0 && !forged && !ransom)
    out.push(`sent ${plural(s.http_requests, "HTTP request")} to ${nas}`)
  if (forged) out.push("sent a forged DSM session (CVE-2026-13639)")
  if (ransom) out.push("dropped a C3RB3R ransom note")
  else if (s.downloads > 0) out.push(`tried to download ${plural(s.downloads, "file")}`)
  const [first, ...rest] = out
  if (first) return rest.length ? `${first}, then ${joinAnd(rest)}` : first
  if (s.ended_at === null) return `is connected to ${nas}`
  return `probed ${nas} and left`
}

/**
 * The story of a flood group: one address opened many plain connections in an hour, so the row
 * counts them instead of telling each one. "opened 812 RDP connections, one login each", or
 * "opened 438 SSH connections, about 2 passwords each (876 tried)".
 */
function floodPredicate(s: Session): string {
  const n = connectionsOf(s)
  const nas = s.sensor === "synology"
  const noun = sensorMeta(s.sensor)?.noun ?? s.sensor.toUpperCase()
  const tool = nas ? "" : clientToolClause(s)
  const opened = nas
    ? `opened ${plural(n, "connection")} to the Synology NAS`
    : `opened ${plural(n, `${noun} connection`)}${tool}`
  if (s.login_attempts <= 0) {
    if (s.sensor === "web" || s.sensor === "docker") return `${opened} without sending a request`
    if (s.sensor === "smb" || s.sensor === "sip") return `${opened} and left`
    return `${opened} and left without logging in`
  }
  const what = sensorMeta(s.sensor)?.credential ?? "login"
  // Exactly one each: the count is already said, the row does not repeat it a third time.
  if (s.login_attempts === n) return `${opened}, one ${what} each`
  const each = Math.round(s.login_attempts / n)
  const share = each <= 1 ? `about one ${what} each` : `about ${plural(each, what)} each`
  return `${opened}, ${share} (${formatNumber(s.login_attempts)} tried)`
}

/** Build the plain-English story of a session. Pure: no I/O, no clock. */
export function describeSession(s: Session): SessionStoryParts {
  if (isFlood(s))
    return { subject: s.src_ip, origin: sessionOrigin(s), predicate: floodPredicate(s) }
  if (s.sensor === "synology")
    return { subject: s.src_ip, origin: sessionOrigin(s), predicate: synologyPredicate(s) }
  const noun = sensorMeta(s.sensor)?.noun ?? s.sensor.toUpperCase()
  const access = accessClause(s, noun)
  const actions = actionClauses(s)

  let predicate: string
  if (access && actions.length) predicate = `${access}, then ${joinAnd(actions)}`
  else if (access) predicate = access
  else if (actions.length) predicate = joinAnd(actions)
  else predicate = idleClause(s, noun)

  return { subject: s.src_ip, origin: sessionOrigin(s), predicate }
}

export function describeSessionText(s: Session): string {
  const { subject, origin, predicate } = describeSession(s)
  return `${subject}${origin ? ` (${origin})` : ""} ${predicate}`
}
