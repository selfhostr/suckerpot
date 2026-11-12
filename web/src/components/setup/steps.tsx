import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CircleCheck, CircleDashed, TriangleAlert } from "lucide-react"
import { useId, useState } from "react"
import { Link } from "react-router"
import { AddChannelDialog } from "@/components/alerts/channel-dialogs"
import { NeverInReport } from "@/components/abuse/reporting-card"
import { Field, FormError } from "@/components/form-parts"
import { FindingCard } from "@/components/finding-card"
import { SensorBadge } from "@/components/sensor-badge"
import { FirewallNote, SetupItems } from "@/components/setup-checklist"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { UploadCard } from "@/components/vpn/vpn-tab"
import { useSetupStatus } from "@/hooks/use-setup-status"
import {
  abuseApi,
  abuseKeys,
  describeAbuseError,
  describeSettingsIssue,
  settingsIssuesOf,
} from "@/lib/abuse"
import { alertKeys, alertsApi } from "@/lib/alerts"
import { plural } from "@/lib/format"
import { SENSOR_META, SENSORS, type Sensor } from "@/lib/sensors"
import { describeSetup } from "@/lib/setup"
import {
  describePort,
  enabledSensors,
  orderedSensors,
  sensorsCommand,
  setCommand,
  wizardApi,
  wizardKeys,
  type PortItem,
} from "@/lib/setup-wizard"
import { describeVpn, vpnApi, vpnKeys, type VpnStatus } from "@/lib/vpn"
import { CommandBox } from "./command-box"
import { NetworkStep as NetworkJoinStep } from "./network-step"
import { PortsCard } from "./ports-table"

/** The three warnings of docs/getting-started.md, in plain words. */
const WARNINGS = [
  {
    title: "Use a dedicated machine",
    body: "SuckerPot is attacked on purpose. Run it on a machine or virtual machine that holds nothing else you care about.",
  },
  {
    title: "Leave no credentials on it",
    body: "Treat every password, key and token stored there as possibly exposed. Never reuse one from somewhere else.",
  },
  {
    title: "Never expose the dashboard",
    body: "Only the sensor ports face the internet. Reach the dashboard on the local network, through an SSH tunnel or behind an access proxy.",
  },
] as const

export function WelcomeStep() {
  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-fg-muted">
        SuckerPot runs fake services and records everything attackers try against them. Three rules
        keep the rest of your network safe:
      </p>
      <ol className="grid gap-3 sm:grid-cols-3">
        {WARNINGS.map((w, i) => (
          <li key={w.title} className="rounded-lg border bg-surface p-4">
            <p className="flex items-center gap-2 text-sm font-medium text-fg">
              <span
                aria-hidden
                className="inline-flex size-5 items-center justify-center rounded-full border text-2xs tabular-nums"
              >
                {i + 1}
              </span>
              {w.title}
            </p>
            <p className="mt-2 text-xs text-pretty text-fg-muted">{w.body}</p>
          </li>
        ))}
      </ol>
    </div>
  )
}

/* --- Sensors ---------------------------------------------------------------- */

function SensorPicker({ items }: { items: readonly PortItem[] }) {
  const current = enabledSensors(items)
  const [picked, setPicked] = useState<Set<Sensor>>(() => new Set(current))
  const chosen = orderedSensors(picked)
  const same = chosen.join() === current.join()
  const toggle = (s: Sensor, on: boolean) =>
    setPicked((p) => {
      const next = new Set(p)
      if (on) next.add(s)
      else next.delete(s)
      return next
    })
  const byId = new Map(items.map((i) => [i.sensor, i]))
  return (
    <div className="space-y-5">
      <ul aria-label="Sensors" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {SENSORS.map((s) => {
          const meta = SENSOR_META[s]
          const item = byId.get(s)
          const on = picked.has(s)
          const id = `pick-${s}`
          return (
            <li
              key={s}
              className={`flex items-start gap-3 rounded-lg border p-3 ${on ? "bg-surface" : "border-dashed"}`}
            >
              <Switch
                id={id}
                checked={on}
                onCheckedChange={(v) => toggle(s, v)}
                className="mt-1"
                aria-describedby={`${id}-desc`}
              />
              <div className="min-w-0 space-y-1.5">
                <label htmlFor={id} className="flex flex-wrap items-center gap-2">
                  <SensorBadge sensor={s} />
                  <span className="font-mono text-xs text-fg-muted tabular-nums">
                    {item ? describePort(item) : `${meta.transport.toUpperCase()} ${meta.port}`}
                  </span>
                </label>
                <p id={`${id}-desc`} className="text-xs text-pretty text-fg-muted">
                  {meta.description}
                </p>
              </div>
            </li>
          )
        })}
      </ul>
      {same ? (
        <p className="text-sm text-fg-muted">
          {plural(current.length, "sensor")} {current.length === 1 ? "is" : "are"} switched on. Flip
          a switch to build the command for a different selection.
        </p>
      ) : chosen.length === 0 ? (
        <p role="status" className="text-sm text-fg">
          Pick at least one sensor to get a command.
        </p>
      ) : (
        <div className="space-y-2">
          <p role="status" className="text-sm text-fg">
            Run this on the machine that hosts SuckerPot to switch to {chosen.length}{" "}
            {chosen.length === 1 ? "sensor" : "sensors"}:
          </p>
          <CommandBox
            command={sensorsCommand(chosen)}
            label="Command to change the sensors"
            hint="It changes .env, checks the ports and restarts the sensors. The dashboard never edits .env itself."
          />
        </div>
      )}
    </div>
  )
}

export function SensorsStep() {
  const q = useQuery({ queryKey: wizardKeys.ports, queryFn: wizardApi.ports })
  if (q.data)
    return (
      <FindingCard
        eyebrow="Sensors"
        finding={`${plural(q.data.items.filter((i) => i.enabled).length, "sensor")} switched on, ${q.data.items.filter((i) => !i.enabled).length} off.`}
        detail="Fewer sensors use less memory. Switching one on or off later changes nothing else."
      >
        <SensorPicker items={q.data.items} />
      </FindingCard>
    )
  return (
    <FindingCard
      eyebrow="Sensors"
      finding={q.isError ? "The sensor list is not available right now." : "Checking the sensors…"}
    >
      {q.isPending ? <SkeletonText lines={4} /> : null}
    </FindingCard>
  )
}

export function PortsStep() {
  return <PortsCard eyebrow="Ports" />
}

/* --- VPN -------------------------------------------------------------------- */

/** True when no tunnel is up and there is nothing to trust: the first-run state. */
function vpnIdle(v: VpnStatus): boolean {
  return v.gate.state === "closed" && !v.trust_candidate && !v.trust_blocked
}

export function VpnStep() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: vpnKeys.status, queryFn: vpnApi.status, refetchInterval: 5_000 })
  const v = q.data
  const open = v?.gate.state === "open"
  const idle = v ? vpnIdle(v) : false
  return (
    <div className="space-y-4">
      <FindingCard
        eyebrow="Outbound gate"
        finding={
          v
            ? idle
              ? "No VPN yet, so nothing leaves this machine."
              : describeVpn(v)
            : q.isError
              ? "The VPN status is not available."
              : "Checking the VPN…"
        }
        detail="The VPN stays idle until a WireGuard file is uploaded. Until then nothing leaves this machine: enrichment, payload fetching and alerts wait, and the sensors keep recording attacks."
        action={
          open ? (
            <span className="inline-flex items-center gap-1.5 text-sm font-medium text-status-ok">
              <CircleCheck aria-hidden className="size-4" />
              Gate open
            </span>
          ) : idle ? (
            <span className="inline-flex items-center gap-1.5 text-sm font-medium text-fg-muted">
              <CircleDashed aria-hidden className="size-4" />
              Idle
            </span>
          ) : v ? (
            <span className="inline-flex items-center gap-1.5 text-sm font-medium text-sev-warning">
              <TriangleAlert aria-hidden className="size-4" />
              Gate closed
            </span>
          ) : null
        }
      >
        {v && !open && v.trust_candidate ? (
          <p className="text-sm text-fg-muted">
            The new exit has to be trusted once, with your password, on the{" "}
            <Link
              to="/settings?tab=vpn"
              className="font-medium text-fg underline underline-offset-4"
            >
              VPN tab
            </Link>
            .
          </p>
        ) : v && open ? (
          <p className="text-sm text-fg-muted">
            Nothing to do here. You can still replace the tunnel with another WireGuard file below.
          </p>
        ) : v ? (
          <ol className="list-decimal space-y-1 pl-4 text-sm text-fg-muted marker:text-fg-subtle">
            <li>
              Download a WireGuard file (<code className="font-mono text-fg">.conf</code>) from your
              VPN provider.
            </li>
            <li>Upload it below. The tunnel starts by itself.</li>
            <li>This page shows the exit address as soon as the gate opens.</li>
          </ol>
        ) : (
          <SkeletonText lines={2} />
        )}
      </FindingCard>
      <UploadCard
        onUploaded={() => void qc.invalidateQueries({ queryKey: vpnKeys.status })}
        disabled={v ? !v.config_writable : false}
        first={idle}
      />
    </div>
  )
}

/* --- Own address ------------------------------------------------------------ */

export function SelfStep() {
  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-fg-muted">
        Until one address is confirmed, abuse reports, alerts and the network stay locked. SuckerPot
        learns the address from the traffic it sees and asks you to confirm it. You can also add it
        by hand. It is never looked up on the internet.
      </p>
      <NeverInReport />
    </div>
  )
}

/* --- Reporting -------------------------------------------------------------- */

function ReplyContactForm() {
  const qc = useQueryClient()
  const id = useId()
  const q = useQuery({ queryKey: abuseKeys.settings, queryFn: abuseApi.settings })
  const [draft, setDraft] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const save = useMutation({
    mutationFn: (contact: string) => {
      if (!q.data) throw new Error("not loaded")
      return abuseApi.saveSettings({ ...q.data, reply_contact: contact.trim() || null })
    },
    onSuccess: (d) => {
      setError(null)
      setSaved(true)
      qc.setQueryData(abuseKeys.settings, d)
    },
    onError: (e) => {
      setSaved(false)
      const found = settingsIssuesOf(e)
      setError(
        found
          ? Object.entries(found)
              .map(([field, codes]) => describeSettingsIssue(field, codes))
              .join(" ")
          : describeAbuseError(e),
      )
    },
  })
  if (!q.data)
    return q.isError ? (
      <FormError id={`${id}-err`} message="The reporting settings could not be loaded." />
    ) : (
      <SkeletonText lines={2} />
    )
  const value = draft ?? q.data.reply_contact ?? ""
  // The saved address may already block every report (the rules grow): say so before a save.
  const stored = draft === null ? q.data.field_issues?.reply_contact : undefined
  return (
    <form
      noValidate
      className="grid gap-3 sm:max-w-md"
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate(value)
      }}
    >
      <Field
        id={id}
        label="Reply contact"
        hint="An address where an abuse desk can answer you. It goes into the reports you choose to send."
        error={stored ? describeSettingsIssue("reply_contact", stored) : undefined}
      >
        <Input
          id={id}
          type="email"
          autoComplete="off"
          inputMode="email"
          value={value}
          maxLength={254}
          placeholder="you@example.org"
          onChange={(e) => {
            setSaved(false)
            setDraft(e.target.value)
          }}
        />
      </Field>
      <FormError id={`${id}-err`} message={error} />
      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={save.isPending || value.trim() === ""}>
          {save.isPending ? "Saving…" : "Save"}
        </Button>
        <span role="status" className="text-sm text-fg-muted">
          {saved ? "Saved." : ""}
        </span>
      </div>
    </form>
  )
}

export function ReportingStep() {
  const status = useSetupStatus()
  const worker = status.data?.find((i) => i.id === "abuse_worker")
  return (
    <div className="space-y-4">
      <FindingCard
        eyebrow="Reply contact"
        finding="Reports are optional, and nothing is sent without you."
        detail="By default you copy a draft into your own mailbox. The texts around the facts can stay empty; you can fill them in later under Settings, Reporting."
      >
        <ReplyContactForm />
      </FindingCard>
      <FindingCard
        eyebrow="Report drafts"
        finding={worker?.detail ?? "Report drafts are off until you switch them on."}
        detail="The switch lives in .env, so the dashboard shows the command instead of changing it."
      >
        <CommandBox
          command={setCommand("ABUSE_REPORTS_ENABLED", "true")}
          label="Command to switch report drafts on"
          hint="Run it on the machine that hosts SuckerPot. It restarts the services that need the change."
        />
      </FindingCard>
    </div>
  )
}

/* --- Alerts ----------------------------------------------------------------- */

export function AlertsStep() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: alertKeys.channels, queryFn: alertsApi.channels })
  const n = q.data?.length ?? 0
  return (
    <FindingCard
      eyebrow="Alert channels"
      finding={
        q.data
          ? n > 0
            ? `${plural(n, "channel")} set up. Rules and a weekly report can now reach you.`
            : "No channel yet, so no alert can reach you."
          : q.isError
            ? "The alert channels are not available right now."
            : "Checking the alert channels…"
      }
      detail="Messages are sent by the server through the VPN, never by your browser. The webhook address is stored encrypted."
    >
      <div className="flex flex-wrap items-center gap-3">
        <AddChannelDialog
          onDone={() => void qc.invalidateQueries({ queryKey: alertKeys.channels })}
          trigger={<Button size="sm">Add an alert channel</Button>}
        />
        <Link
          to="/settings?tab=alerts"
          className="rounded-sm text-sm font-medium text-fg-muted underline underline-offset-4 hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          Open the alert channels
        </Link>
      </div>
    </FindingCard>
  )
}

/* --- Network (M29) ----------------------------------------------------------- */

/**
 * The optional network step. Joining is never forced: the wizard's own "Skip for now" is the way
 * on, and joining only starts after the join dialog (password again, five consents). When this
 * system has nothing to offer (sharing off in .env and no hub), the step only says so.
 */
export function NetworkStep() {
  return (
    <NetworkJoinStep
      fallback={
        <FindingCard
          eyebrow="The SuckerPot network"
          finding="Sharing is switched off in this system's settings (NETWORK_ENABLED=false), so nothing is shared."
          detail="There is nothing to decide now. If you switch it on later, you can join in Settings, Network."
        />
      }
    />
  )
}

/* --- Done ------------------------------------------------------------------- */

/** The checklist. Its actions ("Go to Today", "Take the tour") live in the wizard's action bar. */
export function DoneStep() {
  const q = useSetupStatus()
  return (
    <FindingCard
      eyebrow="Setup checklist"
      finding={
        q.data
          ? describeSetup(q.data)
          : q.isError
            ? "The setup status is not available right now."
            : "Checking the setup…"
      }
      detail="Each line is computed from the running stack, so it keeps up with changes you make later."
      bodyClassName="px-0 sm:px-0 pt-3 pb-0 sm:pb-0"
      footer={<FirewallNote />}
    >
      {q.data ? (
        <SetupItems items={q.data} />
      ) : q.isPending ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <SkeletonText lines={4} />
        </div>
      ) : null}
    </FindingCard>
  )
}
