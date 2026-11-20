/**
 * MSW handlers for the M28 first-run setup (docs/dev/design/m28.md section 4.2): setup progress, the
 * ports table and the version. Demo data only; the shapes match the spec exactly.
 *
 * `?wizard=new|progress|finished|skipped` picks the starting state (default: finished, so the
 * other pages are never redirected); `?update=1` shows an available update, `?update=dev` a
 * development build, `?update=off` a switched-off check. `/network/status` is mocked in `network.ts`.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import { SENSORS, SENSOR_META } from "@/lib/sensors"
import type { PortItem, WizardProgress, WizardState } from "@/lib/setup-wizard"
import type { VersionInfo } from "@/lib/version"

const LATENCY_MS = 120
const MINUTE = 60_000
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

function param(name: string): string | null {
  return typeof window === "undefined"
    ? null
    : new URLSearchParams(window.location.search).get(name)
}

const START: Record<string, WizardState> = {
  new: "new",
  progress: "in_progress",
  finished: "finished",
  skipped: "skipped",
}

let progress: WizardProgress | null = null

function current(): WizardProgress {
  if (progress) return progress
  const state = START[param("wizard") ?? ""] ?? "finished"
  progress = {
    state,
    steps:
      state === "in_progress"
        ? { welcome: "done", sensors: "done", ports: "done", vpn: "skipped" }
        : state === "finished"
          ? { welcome: "done", sensors: "done", ports: "done", vpn: "done", self: "done" }
          : {},
    show: state === "new" || state === "in_progress",
  }
  return progress
}

const ENABLED = new Set(["ssh", "telnet", "web", "redis", "docker", "adb"])
/** The SSH sensor sits on 2222 because the host's own sshd keeps 22. */
const HOST_PORT: Record<string, number> = { ssh: 2222, telnet: 2323, web: 8080 }
const RECEIVING: Record<string, number> = {
  ssh: 2 * MINUTE,
  telnet: 9 * MINUTE,
  web: 1 * MINUTE,
  redis: 38 * MINUTE,
}

function ports(): PortItem[] {
  return SENSORS.map((s) => {
    const meta = SENSOR_META[s]
    const enabled = ENABLED.has(s)
    const ago = RECEIVING[s]
    return {
      sensor: s,
      label: meta.label,
      enabled,
      protocols: meta.transport === "udp" ? ["udp", "tcp"] : ["tcp"],
      external_port: meta.port,
      host_port: HOST_PORT[s] ?? meta.port,
      env_var: `${s.toUpperCase()}_HOST_PORT`,
      state: !enabled ? "off" : ago ? "receiving" : "waiting",
      last_event_at: enabled && ago ? iso(ago) : null,
    }
  })
}

function version(): VersionInfo {
  const mode = param("update")
  const base: VersionInfo = {
    version: "v0.8.0",
    build: "image",
    commit: "0badc0d",
    latest: "v0.8.0",
    update_available: false,
    checked_at: iso(3 * 60 * MINUTE),
    check: "ok",
    release_url: "https://example.org/suckerpot/releases/tag/v0.8.0",
  }
  if (mode === "1")
    return {
      ...base,
      latest: "v0.9.0",
      update_available: true,
      release_url: "https://example.org/suckerpot/releases/tag/v0.9.0",
    }
  if (mode === "dev")
    return { ...base, version: "v0.8.0-14-g0badc0d", build: "source", latest: null, check: "ok" }
  if (mode === "off") return { ...base, latest: null, checked_at: null, check: "off" }
  return base
}

function applyChange(body: Record<string, unknown>): WizardProgress {
  const p = current()
  if (body.reopen === true) progress = { ...p, state: "in_progress", show: true }
  else if (body.skip === true) progress = { ...p, state: "skipped", show: false }
  else if (body.finish === true) progress = { ...p, state: "finished", show: false }
  else if (typeof body.step === "string" && (body.status === "done" || body.status === "skipped")) {
    progress = {
      ...p,
      state: "in_progress",
      show: true,
      steps: { ...p.steps, [body.step]: body.status },
    }
  }
  return current()
}

export const setupWizardHandlers: RequestHandler[] = [
  http.get("/api/v1/setup/progress", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(current())
  }),
  http.put("/api/v1/setup/progress", async ({ request }) => {
    await delay(LATENCY_MS)
    return HttpResponse.json(applyChange((await request.json()) as Record<string, unknown>))
  }),
  http.get("/api/v1/setup/ports", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ dashboard_port: 8443, items: ports() })
  }),
  http.get("/api/v1/version", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(version())
  }),
]
