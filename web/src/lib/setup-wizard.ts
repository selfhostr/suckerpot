/**
 * The first-run setup (M28, docs/dev/design/m28.md section 4): shapes of `GET/PUT /api/v1/setup/progress`
 * and `GET /api/v1/setup/ports`, the step list, and the host commands the dashboard shows but never
 * runs (it does not edit `.env`).
 */
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
export const AFTER_SETUP =
  "Go to Today to watch attacks arrive, or take the tour. Settings keeps this checklist."

/** Order of the steps. `network` (M29) shows only when the network status endpoint answers. */
export const WIZARD_STEPS: readonly WizardStep[] = [
  {
    id: "welcome",
    title: "Welcome",
    sentence: "SuckerPot is a trap: fake servers that attackers find on the internet.",
    optional: false,
    skip: "Yes. Nothing is set here: this step only explains what SuckerPot is.",
    teaser: "Read the three rules that keep your network safe.",
  },
  {
    id: "sensors",
    title: "Your sensors",
    sentence: "Each sensor pretends to be one service, so pick the ones you want to catch.",
    optional: false,
    skip: "Yes. The sensors already switched on keep running.",
    teaser: "Pick which fake services to run.",
  },
  {
    id: "ports",
    title: "Open the ports",
    sentence: "Attackers only reach a sensor once your router forwards its port to this machine.",
    optional: false,
    skip: "Yes, but attackers cannot reach a sensor until its port is forwarded. The same table stays under Settings, Sensors & ports.",
    teaser: "Forward the sensor ports on your router, and only those.",
  },
  {
    id: "vpn",
    title: "Anonymous egress",
    sentence:
      "Every lookup and download leaves through a VPN, so none of them uses your home address.",
    optional: true,
    skip: "Yes. The sensors keep recording attacks, and nothing leaves this machine: lookups, payload fetching and alerts wait for a VPN.",
    teaser: "Set up the VPN, so nothing ever leaves from your home address.",
  },
  {
    id: "self",
    title: "Your own address",
    sentence: "SuckerPot must know your own address so it never ends up in a report or an alert.",
    optional: true,
    skip: "Yes. Abuse reports and alerts stay locked until one address is confirmed.",
    teaser: "Confirm your own address, so it never ends up in a report or an alert.",
  },
  {
    id: "reporting",
    title: "Abuse reports",
    sentence:
      "Abuse reports are drafts you send yourself, and they need one thing: a reply contact.",
    optional: true,
    skip: "Yes. Reports are optional, and nothing is sent without you.",
    teaser: "Choose where abuse desks can answer you, if you want to send reports.",
  },
  {
    id: "alerts",
    title: "Alerts",
    sentence: "Alerts tell you when something matters, by Discord, Teams or email.",
    optional: true,
    skip: "Yes. Attacks still show on the dashboard; no message is sent.",
    teaser: "Choose where alerts reach you: Discord, Teams or email.",
  },
  {
    id: "network",
    title: "The SuckerPot network",
    sentence: "Joining the network is recommended, and always your choice.",
    optional: true,
    skip: "Yes. Nothing is shared unless you join, and you can join or leave later in Settings, Network.",
    teaser: "Decide whether to join the SuckerPot network.",
  },
  {
    id: "done",
    title: "You are set",
    sentence: "That is everything: here is what is left, and the tour if you want it.",
    optional: false,
    skip: null,
    teaser: "See what is done and what is left, then open the dashboard.",
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
  if (progress.state === "finished") return "The setup is finished."
  if (progress.state === "skipped") return "The setup was skipped."
  if (done === 0) return "The setup has not been started yet."
  return `${done} of ${real.length} setup steps ${done === 1 ? "is" : "are"} done.`
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
  receiving: "Receiving",
  waiting: "Waiting for the first connection",
  off: "Off",
}

/** "TCP 22", "UDP + TCP 5060". Port numbers are never grouped with thousands separators. */
export function describePort(p: Pick<PortItem, "protocols" | "external_port">): string {
  const protocols = p.protocols.map((x) => x.toUpperCase()).join(" + ")
  return `${protocols || "TCP"} ${p.external_port}`
}

/** One sentence for the top of the ports table. */
export function describePorts(items: readonly PortItem[]): string {
  const on = items.filter((i) => i.enabled)
  if (on.length === 0) return "No sensor is switched on, so there is nothing to open yet."
  const receiving = on.filter((i) => i.state === "receiving").length
  const waiting = on.length - receiving
  if (waiting === 0)
    return `All ${on.length} enabled ${on.length === 1 ? "sensor is" : "sensors are"} receiving traffic.`
  if (receiving === 0)
    return `None of the ${on.length} enabled ${on.length === 1 ? "sensor has" : "sensors have"} had a connection yet: open the ports below on your router.`
  return `${receiving} of ${on.length} enabled sensors are receiving traffic, ${waiting} ${waiting === 1 ? "is" : "are"} still waiting for a first connection.`
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
