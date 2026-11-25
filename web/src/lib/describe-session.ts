import { t } from "@/i18n"
import type { Session } from "./api"
import { countryName } from "./format"
import { connectionsOf, isFlood } from "./floods"
import { listAnd, sensorMeta } from "./sensors"

/**
 * The pieces of a one-line session story. The UI renders `subject` as an
 * IP chip and `origin` in a muted tone; `describeSessionText` joins them.
 */
export interface SessionStoryParts {
  subject: string
  origin: string | null
  predicate: string
}

/** Tags that change how the story reads, from strongest to weakest: tag, then the message variant. */
const INSTALL_TAGS: readonly (readonly [string, string])[] = [
  ["crypto-miner", "miner"],
  ["mirai", "mirai"],
  ["malware-drop", "malware"],
]
const EXPLOIT_TAGS: readonly (readonly [string, string])[] = [
  ["php2shell", "php2shell"],
  ["container-escape", "escape"],
]
/** Exploits that ride on commands (SQL). EternalBlue rides on a bare SMB probe: see idleClause. */
const COMMAND_EXPLOITS: readonly (readonly [string, string])[] = [["sql-rce", "sql"]]

function firstTag(tags: string[], table: readonly (readonly [string, string])[]): string {
  return table.find(([tag]) => tags.includes(tag))?.[1] ?? "none"
}

function joinAnd(parts: string[]): string {
  return listAnd(parts)
}

export function sessionOrigin(s: Pick<Session, "country" | "org">): string | null {
  const country = s.country ? (countryName(s.country) ?? s.country) : null
  const parts = [country, s.org].filter((p): p is string => Boolean(p))
  return parts.length ? parts.join(", ") : null
}

/** The guessed client of an RDP session, or "none" (the select value the messages test for). */
function clientTool(s: Pick<Session, "sensor" | "client_tool">): string {
  const tool = s.client_tool?.trim()
  return s.sensor === "rdp" && tool && tool !== "unknown" ? tool : "none"
}

function credentialKind(s: Session): "password" | "login" {
  return sensorMeta(s.sensor)?.credential ?? "login"
}

function accessClause(s: Session, noun: string): string | null {
  if (s.login_attempts <= 0) return null
  const tool = clientTool(s)
  if (s.login_success && s.login_attempts === 1)
    return t("session_story_access_first", { noun, tool })
  return t("session_story_access_tried", {
    count: s.login_attempts,
    noun,
    credential: credentialKind(s),
    tool,
    success: s.login_success ? "yes" : "no",
  })
}

function actionClauses(s: Session): string[] {
  const out: string[] = []
  if (s.http_requests > 0) {
    out.push(
      t("session_story_http", {
        count: s.http_requests,
        kind: s.sensor === "docker" ? "docker" : "http",
        exploit: firstTag(s.tags, EXPLOIT_TAGS),
      }),
    )
  }
  if (s.commands > 0) {
    const install = firstTag(s.tags, INSTALL_TAGS)
    const rce = firstTag(s.tags, COMMAND_EXPLOITS)
    const extra = install !== "none" ? install : rce
    out.push(t("session_story_commands", { count: s.commands, extra }))
  }
  if (s.downloads > 0) out.push(t("session_story_downloads", { count: s.downloads }))
  if (s.sensor === "rdp" && s.tags.includes("bluekeep")) out.push(t("session_story_bluekeep"))
  return out
}

function idleClause(s: Session, noun: string): string {
  if (s.ended_at === null) return t("session_story_idle_connected", { noun })
  if (s.sensor === "web" || s.sensor === "docker") return t("session_story_idle_no_request")
  if (s.tags.includes("eternalblue")) return t("session_story_idle_eternalblue", { noun })
  if (s.sensor === "smb" || s.sensor === "sip") return t("session_story_idle_probed", { noun })
  return t("session_story_idle_left", { noun })
}

/** The Synology DSM sensor: a login page, a web API and a few signature exploits. */
function synologyPredicate(s: Session): string {
  const ransom = s.tags.includes("c3rb3r")
  const forged = s.tags.includes("synology-exploit")
  const out: string[] = []
  if (s.login_attempts > 0)
    out.push(
      t("session_story_synology_tried", {
        count: s.login_attempts,
        success: s.login_success ? "yes" : "no",
      }),
    )
  if (s.http_requests > 0 && !forged && !ransom)
    out.push(t("session_story_synology_http", { count: s.http_requests }))
  if (forged) out.push(t("session_story_synology_forged"))
  if (ransom) out.push(t("session_story_synology_ransom"))
  else if (s.downloads > 0) out.push(t("session_story_downloads", { count: s.downloads }))
  const [first, ...rest] = out
  if (first) return rest.length ? t("session_story_then", { first, rest: joinAnd(rest) }) : first
  if (s.ended_at === null) return t("session_story_synology_connected")
  return t("session_story_synology_probed")
}

/**
 * The story of a flood group: one address opened many plain connections in an hour, so the row
 * counts them instead of telling each one. "opened 812 RDP connections, one login each", or
 * "opened 438 SSH connections, about 2 passwords each (876 tried)".
 */
function floodPredicate(s: Session): string {
  const n = connectionsOf(s)
  const noun = sensorMeta(s.sensor)?.noun ?? s.sensor.toUpperCase()
  const opened =
    s.sensor === "synology"
      ? t("session_flood_opened_synology", { count: n })
      : t("session_flood_opened", { count: n, noun, tool: clientTool(s) })
  if (s.login_attempts <= 0) {
    if (s.sensor === "web" || s.sensor === "docker")
      return t("session_flood_no_request", { opened })
    if (s.sensor === "smb" || s.sensor === "sip") return t("session_flood_left", { opened })
    return t("session_flood_left_no_login", { opened })
  }
  const credential = credentialKind(s)
  // Exactly one each: the count is already said, the row does not repeat it a third time.
  if (s.login_attempts === n) return t("session_flood_one_each", { opened, credential })
  return t("session_flood_about_each", {
    opened,
    credential,
    each: Math.max(1, Math.round(s.login_attempts / n)),
    tried: s.login_attempts,
  })
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
  if (access && actions.length)
    predicate = t("session_story_then", { first: access, rest: joinAnd(actions) })
  else if (access) predicate = access
  else if (actions.length) predicate = joinAnd(actions)
  else predicate = idleClause(s, noun)

  return { subject: s.src_ip, origin: sessionOrigin(s), predicate }
}

export function describeSessionText(s: Session): string {
  const { subject, origin, predicate } = describeSession(s)
  return t("session_story_text", {
    subject,
    hasOrigin: origin ? "yes" : "no",
    origin: origin ?? "",
    predicate,
  })
}
