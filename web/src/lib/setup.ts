/**
 * The setup checklist (M24, docs/dev/design/m24.md section 3): shape of `GET /api/v1/setup/status`
 * (administrators only), the words for each item and the one-sentence summary.
 */
import { t } from "@/i18n"
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

/** Ids in the order the checklist shows them; unknown ids are listed after, by their id. */
const ORDER = [
  "sensors",
  "vpn",
  "collector",
  "reporting_settings",
  "self_address",
  "abuse_worker",
  "alerts",
  "provider_keys",
  "network",
  "network_feed",
]

export function setupTitle(id: string): string {
  switch (id) {
    case "sensors":
      return t("checklist_title_sensors")
    case "vpn":
      return t("checklist_title_vpn")
    case "collector":
      return t("checklist_title_collector")
    case "reporting_settings":
      return t("checklist_title_reporting_settings")
    case "self_address":
      return t("checklist_title_self_address")
    case "abuse_worker":
      return t("checklist_title_abuse_worker")
    case "alerts":
      return t("checklist_title_alerts")
    case "provider_keys":
      return t("checklist_title_provider_keys")
    case "network":
      return t("checklist_title_network")
    case "network_feed":
      return t("checklist_title_network_feed")
    default:
      return id.replace(/_/g, " ")
  }
}

/** Word shown with the icon, so the state never rests on colour alone. */
export const SETUP_STATE_LABEL: Record<SetupState, string> = {
  get ok() {
    return t("checklist_state_ok")
  },
  get todo() {
    return t("checklist_state_todo")
  },
  get warning() {
    return t("checklist_state_warning")
  },
  get off() {
    return t("checklist_state_off")
  },
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
  if (items.length === 0) return t("checklist_summary_empty")
  const ok = items.filter((i) => i.state === "ok").length
  const warning = items.filter((i) => i.state === "warning").length
  const todo = items.filter((i) => i.state === "todo").length
  if (ok === items.length) return t("checklist_summary_all")
  const values = { ok, total: items.length, warning, todo }
  if (warning > 0 && todo > 0) return t("checklist_summary_warning_todo", values)
  if (warning > 0) return t("checklist_summary_warning", values)
  if (todo > 0) return t("checklist_summary_todo", values)
  return t("checklist_summary_done", values)
}

export const setupApi = {
  status: async () => normalizeSetup(await getJson<unknown>("/setup/status")),
}
