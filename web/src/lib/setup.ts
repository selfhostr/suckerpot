/**
 * The setup checklist (M24, docs/dev/design/m24.md section 3): shape of `GET /api/v1/setup/status`
 * (administrators only), the words for each item and the one-sentence summary.
 */
import { getJson } from "./api"

export type SetupState = "ok" | "todo" | "warning" | "off"

export interface SetupItem {
  id: string
  state: SetupState
  /** One sentence from the server: what is wrong, or what is on. */
  detail: string
  /** Where to fix it: an in-app path such as "/settings?tab=vpn". */
  href: string | null
}

export const setupKeys = { status: ["setup", "status"] as const }

/** Titles in the order the checklist shows them; unknown ids are listed after, by their id. */
const TITLES: Record<string, string> = {
  sensors: "Sensor traffic",
  vpn: "Outbound gate",
  collector: "Payload collector",
  reporting_settings: "Report settings",
  self_address: "Your own address",
  abuse_worker: "Abuse report drafts",
  alerts: "Alert channel",
  provider_keys: "Reputation keys",
  network: "SuckerPot network",
  network_feed: "Community lists",
}
const ORDER = Object.keys(TITLES)

export function setupTitle(id: string): string {
  return TITLES[id] ?? id.replace(/_/g, " ")
}

/** Word shown with the icon, so the state never rests on colour alone. */
export const SETUP_STATE_LABEL: Record<SetupState, string> = {
  ok: "Done",
  todo: "To do",
  warning: "Needs attention",
  off: "Off",
}

/** The server may answer with the list itself or wrapped in `{ items }`. */
export function normalizeSetup(raw: unknown): SetupItem[] {
  const list = Array.isArray(raw)
    ? raw
    : raw && typeof raw === "object" && Array.isArray((raw as { items?: unknown }).items)
      ? (raw as { items: unknown[] }).items
      : []
  const items = list.filter(
    (i): i is SetupItem =>
      !!i &&
      typeof i === "object" &&
      typeof (i as SetupItem).id === "string" &&
      ["ok", "todo", "warning", "off"].includes((i as SetupItem).state),
  )
  const rank = (id: string) => {
    const at = ORDER.indexOf(id)
    return at === -1 ? ORDER.length : at
  }
  return [...items].sort((a, b) => rank(a.id) - rank(b.id))
}

/** An in-app path only: never follow an absolute URL the server sends. */
export function safeHref(href: string | null | undefined): string | null {
  return href && /^\/(?![/\\])/.test(href) ? href : null
}

/** "5 of 8 steps are done, 1 needs attention." */
export function describeSetup(items: readonly SetupItem[]): string {
  if (items.length === 0) return "There is nothing to check yet."
  const ok = items.filter((i) => i.state === "ok").length
  const warning = items.filter((i) => i.state === "warning").length
  const todo = items.filter((i) => i.state === "todo").length
  if (ok === items.length) return "Everything is set up."
  const parts = [`${ok} of ${items.length} steps ${ok === 1 ? "is" : "are"} done`]
  if (warning > 0) parts.push(`${warning} ${warning === 1 ? "needs" : "need"} attention`)
  if (todo > 0) parts.push(`${todo} ${todo === 1 ? "is" : "are"} still to do`)
  return `${parts.join(", ")}.`
}

export const setupApi = {
  status: async () => normalizeSetup(await getJson<unknown>("/setup/status")),
}
