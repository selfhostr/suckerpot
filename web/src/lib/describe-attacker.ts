import { t } from "@/i18n"
import type { Attacker } from "./api"
import { countryName } from "./format"
import { listAnd, listPlain, sensorMeta } from "./sensors"
import { SEVERE_TAGS, WARNING_TAGS, type Severity } from "./severity"

export function attackerOrigin(a: Pick<Attacker, "country" | "org">): string | null {
  const country = a.country ? (countryName(a.country) ?? a.country) : null
  const parts = [country, a.org].filter((p): p is string => Boolean(p))
  return parts.length ? parts.join(", ") : null
}

/** Whole days between the first and the last sighting. */
export function activeDays(a: Pick<Attacker, "first_seen" | "last_seen">): number {
  const ms = new Date(a.last_seen).getTime() - new Date(a.first_seen).getTime()
  return Math.max(0, Math.round(ms / 86_400_000))
}

/**
 * The profile predicate: "14 sessions over 6 days on SSH and Telnet, got in
 * twice, tried to download 1 file". The IP and origin are rendered separately.
 */
export function describeAttacker(a: Attacker): string {
  const sensors = listAnd(a.sensors.map((s) => sensorMeta(s)?.label ?? s.toUpperCase()))
  const days = activeDays(a)
  const clauses = [
    t("attacker_describe_head", {
      sessions: a.sessions,
      span: a.sessions > 1 ? (days >= 1 ? "over" : "within") : "none",
      days,
      sensors: sensors || "none",
    }),
  ]
  if (a.login_success > 0) clauses.push(t("attacker_describe_got_in", { count: a.login_success }))
  else if (a.login_attempts > 0) clauses.push(t("attacker_describe_never_got_in"))
  if (a.commands > 0) clauses.push(t("attacker_describe_commands", { count: a.commands }))
  if (a.downloads > 0) clauses.push(t("session_story_downloads", { count: a.downloads }))
  return listPlain(clauses)
}

export function describeAttackerText(a: Attacker): string {
  const origin = attackerOrigin(a)
  return t("attacker_describe_text", {
    ip: a.ip,
    hasOrigin: origin ? "yes" : "no",
    origin: origin ?? "",
    description: describeAttacker(a),
  })
}

/** Same scale as sessions: a download or payload tag is severe, a shell is a warning. */
export function attackerSeverity(a: Attacker): Severity {
  if (a.downloads > 0 || a.tags.some((t) => SEVERE_TAGS.has(t))) return "severe"
  if (a.login_success > 0 || a.commands > 0 || a.tags.some((t) => WARNING_TAGS.has(t)))
    return "warning"
  if (a.login_attempts > 0 || a.events > 0) return "notice"
  return "info"
}
