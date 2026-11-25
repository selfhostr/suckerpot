import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CircleCheck, CircleDashed, TriangleAlert } from "lucide-react"
import { useId, useState } from "react"
import { Link } from "react-router"
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
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
    titleKey: tk("setup_warning_machine_title"),
    bodyKey: tk("setup_warning_machine_body"),
  },
  {
    titleKey: tk("setup_warning_credentials_title"),
    bodyKey: tk("setup_warning_credentials_body"),
  },
  {
    titleKey: tk("setup_warning_dashboard_title"),
    bodyKey: tk("setup_warning_dashboard_body"),
  },
] as const

export function WelcomeStep() {
  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-fg-muted">
        {t("setup_welcome_intro")}
      </p>
      <ol className="grid gap-3 sm:grid-cols-3">
        {WARNINGS.map((w, i) => (
          <li key={w.titleKey} className="rounded-lg border bg-surface p-4">
            <p className="flex items-center gap-2 text-sm font-medium text-fg">
              <span
                aria-hidden
                className="inline-flex size-5 items-center justify-center rounded-full border text-2xs tabular-nums"
              >
                {i + 1}
              </span>
              {t(w.titleKey)}
            </p>
            <p className="mt-2 text-xs text-pretty text-fg-muted">{t(w.bodyKey)}</p>
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
      <ul aria-label={t("setup_sensors_title")} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
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
          {t("setup_sensors_switched_on", { count: current.length })}
        </p>
      ) : chosen.length === 0 ? (
        <p role="status" className="text-sm text-fg">
          {t("setup_sensors_pick_one")}
        </p>
      ) : (
        <div className="space-y-2">
          <p role="status" className="text-sm text-fg">
            {t("setup_sensors_run_command", { count: chosen.length })}
          </p>
          <CommandBox
            command={sensorsCommand(chosen)}
            label={t("setup_sensors_command_label")}
            hint={t("setup_sensors_command_hint")}
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
        eyebrow={t("setup_sensors_title")}
        finding={t("setup_sensors_finding", {
          on: q.data.items.filter((i) => i.enabled).length,
          off: q.data.items.filter((i) => !i.enabled).length,
        })}
        detail={t("setup_sensors_detail")}
      >
        <SensorPicker items={q.data.items} />
      </FindingCard>
    )
  return (
    <FindingCard
      eyebrow={t("setup_sensors_title")}
      finding={q.isError ? t("setup_sensors_unavailable") : t("setup_sensors_checking")}
    >
      {q.isPending ? <SkeletonText lines={4} /> : null}
    </FindingCard>
  )
}

export function PortsStep() {
  return <PortsCard eyebrow={t("setup_ports_title")} />
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
        eyebrow={t("setup_vpn_title")}
        finding={
          v
            ? idle
              ? t("setup_vpn_none")
              : describeVpn(v)
            : q.isError
              ? t("setup_vpn_unavailable")
              : t("setup_vpn_checking")
        }
        detail={t("setup_vpn_detail")}
        action={
          open ? (
            <span className="inline-flex items-center gap-1.5 text-sm font-medium text-status-ok">
              <CircleCheck aria-hidden className="size-4" />
              {t("setup_vpn_gate_open")}
            </span>
          ) : idle ? (
            <span className="inline-flex items-center gap-1.5 text-sm font-medium text-fg-muted">
              <CircleDashed aria-hidden className="size-4" />
              {t("setup_vpn_idle")}
            </span>
          ) : v ? (
            <span className="inline-flex items-center gap-1.5 text-sm font-medium text-sev-warning">
              <TriangleAlert aria-hidden className="size-4" />
              {t("setup_vpn_gate_closed")}
            </span>
          ) : null
        }
      >
        {v && !open && v.trust_candidate ? (
          <p className="text-sm text-fg-muted">
            {tNodes(
              "setup_vpn_trust",
              {},
              {
                link: (
                  <Link
                    to="/settings?tab=vpn"
                    className="font-medium text-fg underline underline-offset-4"
                  >
                    {t("setup_vpn_tab")}
                  </Link>
                ),
              },
            )}
          </p>
        ) : v && open ? (
          <p className="text-sm text-fg-muted">
            {t("setup_vpn_nothing")}
          </p>
        ) : v ? (
          <ol className="list-decimal space-y-1 pl-4 text-sm text-fg-muted marker:text-fg-subtle">
            <li>
              {tNodes(
                "setup_vpn_step_download",
                {},
                { file: <code className="font-mono text-fg">.conf</code> },
              )}
            </li>
            <li>{t("setup_vpn_step_upload")}</li>
            <li>{t("setup_vpn_step_exit")}</li>
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
        {t("setup_self_intro")}
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
      <FormError id={`${id}-err`} message={t("setup_reporting_load_error")} />
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
        label={t("setup_reply_contact")}
        hint={t("setup_reply_contact_hint")}
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
        <Button type="submit" disabled={save.isPending || value.trim() === ""}>
          {save.isPending ? t("setup_saving") : t("common_save")}
        </Button>
        <span role="status" className="text-sm text-fg-muted">
          {saved ? t("setup_saved") : ""}
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
        eyebrow={t("setup_reply_contact")}
        finding={t("setup_reporting_finding")}
        detail={t("setup_reporting_detail")}
      >
        <ReplyContactForm />
      </FindingCard>
      <FindingCard
        eyebrow={t("setup_drafts_title")}
        finding={worker?.detail ?? t("setup_drafts_off")}
        detail={t("setup_drafts_detail")}
      >
        <CommandBox
          command={setCommand("ABUSE_REPORTS_ENABLED", "true")}
          label={t("setup_drafts_command_label")}
          hint={t("setup_drafts_command_hint")}
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
      eyebrow={t("setup_alerts_title")}
      finding={
        q.data
          ? n > 0
            ? t("setup_alerts_ready", { count: n })
            : t("setup_alerts_none")
          : q.isError
            ? t("setup_alerts_unavailable")
            : t("setup_alerts_checking")
      }
      detail={t("setup_alerts_detail")}
    >
      <div className="flex flex-wrap items-center gap-3">
        <AddChannelDialog
          onDone={() => void qc.invalidateQueries({ queryKey: alertKeys.channels })}
          trigger={<Button size="sm">{t("setup_alerts_add")}</Button>}
        />
        <Link
          to="/settings?tab=alerts"
          className="rounded-sm text-sm font-medium text-fg-muted underline underline-offset-4 hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {t("setup_alerts_open")}
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
          eyebrow={t("setup_network_title")}
          finding={t("setup_network_off_finding")}
          detail={t("setup_network_off_detail")}
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
      eyebrow={t("setup_done_title")}
      finding={
        q.data
          ? describeSetup(q.data)
          : q.isError
            ? t("setup_done_unavailable")
            : t("setup_done_checking")
      }
      detail={t("setup_done_detail")}
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
