/**
 * The first-run setup (M28, docs/dev/design/m28.md section 4): shapes of `GET/PUT /api/v1/setup/progress`
 * and `GET /api/v1/setup/ports`, the step list, and the host commands the dashboard shows but never
 * runs (it does not edit `.env`).
 */
import { t } from "@/i18n"
import { getJson, sendJson } from "./api"
import { isSensor, SENSORS, type Sensor } from "./sensors"

export type WizardState = "new" | "in_progress" | "finished" | "skipped"
export type StepStatus = "done" | "skipped"

export interface WizardProgress {
  state: WizardState
  steps: Record<string, StepStatus>
  /** True while the setup should be offered: the state is `new` or `in_progress`. */
  show: boolean
}

export type PortState = "receiving" | "waiting" | "off"

export interface PortItem {
  sensor: string
  label: string
  enabled: boolean
  protocols: ("tcp" | "udp")[]
  /** The standard service port: the one to open on the router. */
  external_port: number
  /** The port on this machine the router forwards to. */
  host_port: number
  env_var: string
  state: PortState
  last_event_at: string | null
}

export interface PortsAnswer {
  dashboard_port: number
  items: PortItem[]
}

export type ProgressChange =
  { step: string; status: StepStatus } | { finish: true } | { skip: true } | { reopen: true }

export const wizardKeys = {
  progress: ["setup", "progress"] as const,
  ports: ["setup", "ports"] as const,
  network: ["network", "status"] as const,
}

export interface WizardStep {
  id: string
  /** Short name in the step list. */
  title: string
  /** The one plain sentence the step opens with. */
  sentence: string
  /** Optional steps offer "Skip for now" until they are done. */
  optional: boolean
  /** What skipping this step means, in plain words. Null when there is nothing to skip. */
  skip: string | null
  /** What this step does, phrased for the step before it ("What happens next"). */
  teaser: string
}

/** "What happens next" on the last step, where there is no next step to announce. */
export function afterSetup(): string {
  return t("setup_after")
}

/**
 * Order of the steps. `network` (M29) shows only when the network status endpoint answers.
 * The texts are getters, read when a step renders, so they follow the active language.
 */
export const WIZARD_STEPS: readonly WizardStep[] = [
  {
    id: "welcome",
    get title() {
      return t("setup_step_welcome_title")
    },
    get sentence() {
      return t("setup_step_welcome_sentence")
    },
    optional: false,
    get skip() {
      return t("setup_step_welcome_skip")
    },
    get teaser() {
      return t("setup_step_welcome_teaser")
    },
  },
  {
    id: "sensors",
    get title() {
      return t("setup_step_sensors_title")
    },
    get sentence() {
      return t("setup_step_sensors_sentence")
    },
    optional: false,
    get skip() {
      return t("setup_step_sensors_skip")
    },
    get teaser() {
      return t("setup_step_sensors_teaser")
    },
  },
  {
    id: "ports",
    get title() {
      return t("setup_step_ports_title")
    },
    get sentence() {
      return t("setup_step_ports_sentence")
    },
    optional: false,
    get skip() {
      return t("setup_step_ports_skip")
    },
    get teaser() {
      return t("setup_step_ports_teaser")
    },
  },
  {
    id: "vpn",
    get title() {
      return t("setup_step_vpn_title")
    },
    get sentence() {
      return t("setup_step_vpn_sentence")
    },
    optional: true,
    get skip() {
      return t("setup_step_vpn_skip")
    },
    get teaser() {
      return t("setup_step_vpn_teaser")
    },
  },
  {
    id: "self",
    get title() {
      return t("setup_step_self_title")
    },
    get sentence() {
      return t("setup_step_self_sentence")
    },
    optional: true,
    get skip() {
      return t("setup_step_self_skip")
    },
    get teaser() {
      return t("setup_step_self_teaser")
    },
  },
  {
    id: "reporting",
    get title() {
      return t("setup_step_reporting_title")
    },
    get sentence() {
      return t("setup_step_reporting_sentence")
    },
    optional: true,
    get skip() {
      return t("setup_step_reporting_skip")
    },
    get teaser() {
      return t("setup_step_reporting_teaser")
    },
  },
  {
    id: "alerts",
    get title() {
      return t("setup_step_alerts_title")
    },
    get sentence() {
      return t("setup_step_alerts_sentence")
    },
    optional: true,
    get skip() {
      return t("setup_step_alerts_skip")
    },
    get teaser() {
      return t("setup_step_alerts_teaser")
    },
  },
  {
    id: "network",
    get title() {
      return t("setup_step_network_title")
    },
    get sentence() {
      return t("setup_step_network_sentence")
    },
    optional: true,
    get skip() {
      return t("setup_step_network_skip")
    },
    get teaser() {
      return t("setup_step_network_teaser")
    },
  },
  {
    id: "done",
    get title() {
      return t("setup_step_done_title")
    },
    get sentence() {
      return t("setup_step_done_sentence")
    },
    optional: false,
    skip: null,
    get teaser() {
      return t("setup_step_done_teaser")
    },
  },
]

export function stepIndex(id: string | null | undefined, steps: readonly WizardStep[]): number {
  const at = steps.findIndex((s) => s.id === id)
  return at === -1 ? 0 : at
}

/** The first step that is neither done nor skipped; the last one when all are. */
export function firstOpenStep(
  progress: Pick<WizardProgress, "steps"> | undefined,
  steps: readonly WizardStep[],
): number {
  if (!progress) return 0
  const at = steps.findIndex((s) => s.id !== "done" && !progress.steps[s.id])
  return at === -1 ? steps.length - 1 : at
}

/** "2 of 7 setup steps are done" for the resume card. */
export function describeProgress(progress: WizardProgress, steps: readonly WizardStep[]): string {
  const real = steps.filter((s) => s.id !== "done")
  const done = real.filter((s) => progress.steps[s.id]).length
  if (progress.state === "finished") return t("setup_progress_finished")
  if (progress.state === "skipped") return t("setup_progress_skipped")
  if (done === 0) return t("setup_progress_not_started")
  return t("setup_progress_done", { done, total: real.length })
}

const STATES: readonly string[] = ["new", "in_progress", "finished", "skipped"]

export function normalizeProgress(raw: unknown): WizardProgress {
  const o = raw && typeof raw === "object" ? (raw as Partial<Record<string, unknown>>) : {}
  const state = (STATES.includes(o.state as string) ? o.state : "finished") as WizardState
  const steps: Record<string, StepStatus> = {}
  const given = o.steps && typeof o.steps === "object" ? (o.steps as Record<string, unknown>) : {}
  for (const [k, v] of Object.entries(given)) {
    if (v === "done" || v === "skipped") steps[k] = v
  }
  return { state, steps, show: o.show === true && (state === "new" || state === "in_progress") }
}

export const wizardApi = {
  progress: async () => normalizeProgress(await getJson<unknown>("/setup/progress")),
  change: async (body: ProgressChange) =>
    normalizeProgress(await sendJson<unknown>("PUT", "/setup/progress", body)),
  ports: async (): Promise<PortsAnswer> => {
    const raw = await getJson<Partial<PortsAnswer>>("/setup/ports")
    return {
      dashboard_port: typeof raw.dashboard_port === "number" ? raw.dashboard_port : 8443,
      items: Array.isArray(raw.items) ? raw.items : [],
    }
  },
}

/* --- Ports ---------------------------------------------------------------- */

export const PORT_STATE_LABEL: Record<PortState, string> = {
  get receiving() {
    return t("setup_port_state_receiving")
  },
  get waiting() {
    return t("setup_port_state_waiting")
  },
  get off() {
    return t("common_off")
  },
}

/** "TCP 22", "UDP + TCP 5060". Port numbers are never grouped with thousands separators. */
export function describePort(p: Pick<PortItem, "protocols" | "external_port">): string {
  const protocols = p.protocols.map((x) => x.toUpperCase()).join(" + ")
  return `${protocols || "TCP"} ${p.external_port}`
}

/** One sentence for the top of the ports table. */
export function describePorts(items: readonly PortItem[]): string {
  const on = items.filter((i) => i.enabled)
  if (on.length === 0) return t("setup_ports_none_on")
  const receiving = on.filter((i) => i.state === "receiving").length
  const waiting = on.length - receiving
  if (waiting === 0) return t("setup_ports_all_receiving", { count: on.length })
  if (receiving === 0) return t("setup_ports_none_receiving", { count: on.length })
  return t("setup_ports_some_receiving", { receiving, total: on.length, waiting })
}

/* --- Host commands (copied by the owner; the dashboard never runs them) ---- */

/** Registry order, so the same selection always gives the same command. */
export function orderedSensors(ids: Iterable<string>): Sensor[] {
  const set = new Set(ids)
  return SENSORS.filter((s) => set.has(s))
}

export function sensorsCommand(ids: Iterable<string>): string {
  const list = orderedSensors(ids)
  return list.length > 0 ? `just sensors ${list.join(",")}` : "just sensors"
}

export function setCommand(key: string, value: string): string {
  return `just set ${key}=${value}`
}

export function enabledSensors(items: readonly PortItem[]): Sensor[] {
  return orderedSensors(items.filter((i) => i.enabled && isSensor(i.sensor)).map((i) => i.sensor))
}

/* --- Once per browser session ---------------------------------------------- */

export const REDIRECT_KEY = "selfhostr.setup.offered"

function safeSession(): Storage | undefined {
  try {
    return window.sessionStorage
  } catch {
    return undefined
  }
}

/** True the first time it is asked in this browser session; the setup opens by itself only once. */
export function takeSetupOffer(storage: Storage | undefined = safeSession()): boolean {
  if (!storage) return false
  try {
    if (storage.getItem(REDIRECT_KEY)) return false
    storage.setItem(REDIRECT_KEY, "1")
    return true
  } catch {
    return false
  }
}
