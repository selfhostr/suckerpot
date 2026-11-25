import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Check, Plus, X } from "lucide-react"
import { useId, useState, type SyntheticEvent } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import {
  alertKeys,
  alertsApi,
  CVE_PATTERN,
  RULES,
  rulesFinding,
  saveRule,
  SEVERITY_OPTIONS,
  unwatchCve,
  watchCve,
  type AlertChannel,
  type AlertRule,
  type RuleInfo,
} from "@/lib/alerts"
import type { Severity } from "@/lib/severity"
import { cn } from "@/lib/utils"

/** Where a rule sends: one toggle per channel, a check when on, a dashed "+" when off. */
export function ChannelPicker({
  channels,
  selected,
  disabled,
  onChange,
}: {
  channels: AlertChannel[]
  selected: number[]
  disabled: boolean
  onChange: (ids: number[]) => void
}) {
  return (
    <div role="group" aria-label="Send to" className="flex flex-wrap items-center gap-1.5">
      <span aria-hidden className="mr-1 text-xs text-fg-subtle">
        Send to
      </span>
      {channels.map((c) => {
        const on = selected.includes(c.id)
        return (
          <button
            key={c.id}
            type="button"
            disabled={disabled || !c.enabled}
            aria-pressed={on}
            title={c.enabled ? undefined : "This channel is switched off"}
            onClick={() => onChange(on ? selected.filter((i) => i !== c.id) : [...selected, c.id])}
            className={cn(
              "inline-flex h-(--control-sm) items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors duration-150",
              "disabled:cursor-not-allowed disabled:opacity-50",
              on
                ? "border-border-strong bg-surface-hover text-fg"
                : "border-dashed bg-transparent text-fg-muted hover:border-border-strong hover:text-fg",
            )}
          >
            {on ? (
              <Check aria-hidden className="size-3.5" strokeWidth={2.25} />
            ) : (
              <Plus aria-hidden className="size-3.5 text-fg-subtle" />
            )}
            {c.name}
          </button>
        )
      })}
    </div>
  )
}

function RuleRow({
  info,
  rule,
  channels,
  writable,
  onChanged,
  onError,
}: {
  info: RuleInfo
  rule: AlertRule
  channels: AlertChannel[]
  writable: boolean
  onChanged: () => void
  onError: (message: string) => void
}) {
  const [busy, setBusy] = useState(false)
  const usable = channels.filter((c) => c.enabled)
  const id = useId()

  async function save(next: Partial<Pick<AlertRule, "enabled" | "channel_ids" | "min_severity">>) {
    if (busy) return
    setBusy(true)
    try {
      let channel_ids = next.channel_ids ?? rule.channel_ids
      const enabled = next.enabled ?? rule.enabled
      // Switching a rule on without a destination would be refused: use every ready channel.
      if (enabled && channel_ids.length === 0) channel_ids = usable.map((c) => c.id)
      await saveRule(info.kind, {
        enabled,
        channel_ids,
        min_severity: next.min_severity ?? rule.min_severity,
      })
      onChanged()
    } catch (e) {
      onError(e instanceof Error ? e.message : "The change could not be saved.")
    } finally {
      setBusy(false)
    }
  }

  const noChannel = usable.length === 0
  return (
    <li className="space-y-3 px-4 py-3.5 sm:px-5">
      <div className="flex items-start gap-3">
        <Switch
          id={id}
          size="sm"
          className="mt-1"
          checked={rule.enabled}
          disabled={!writable || busy || (noChannel && !rule.enabled)}
          onCheckedChange={(enabled) => void save({ enabled })}
        />
        <label htmlFor={id} className="min-w-0 flex-1 text-sm font-medium text-fg">
          {info.title}
          <span className="block text-xs font-normal text-fg-muted">{info.when}</span>
        </label>
      </div>
      {rule.enabled ? (
        <div className="flex animate-slide-in flex-wrap items-center gap-x-5 gap-y-2 pl-9">
          <ChannelPicker
            channels={channels}
            selected={rule.channel_ids}
            disabled={!writable || busy}
            onChange={(ids) =>
              void save(
                ids.length === 0 ? { channel_ids: ids, enabled: false } : { channel_ids: ids },
              )
            }
          />
          {info.kind !== "weekly_report" && info.kind !== "malware_drop" ? (
            <div className="flex items-center gap-2">
              <span aria-hidden className="text-xs text-fg-subtle">
                Severity
              </span>
              <SegmentedControl
                label={`Severity for ${info.title}`}
                value={rule.min_severity === "notice" ? "info" : rule.min_severity}
                onChange={(min_severity: Severity) => void save({ min_severity })}
                options={SEVERITY_OPTIONS}
              />
            </div>
          ) : null}
        </div>
      ) : null}
    </li>
  )
}

/** Which events send an alert, and where. Everything is off until you switch it on. */
export function RulesCard() {
  const { canWrite } = useAuth()
  const client = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const rules = useQuery({ queryKey: alertKeys.rules, queryFn: alertsApi.rules })
  const channels = useQuery({ queryKey: alertKeys.channels, queryFn: alertsApi.channels })
  const ready = rules.data && channels.data

  function changed() {
    setError(null)
    void client.invalidateQueries({ queryKey: alertKeys.rules })
  }

  return (
    <FindingCard
      eyebrow="What sends an alert"
      finding={ready ? rulesFinding(rules.data, channels.data) : "Checking the alert rules…"}
      detail="Every alert is off until you switch it on. IP addresses are hidden by default and links to attacker servers are made harmless."
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {rules.isPending || channels.isPending ? (
        <div className="px-4 sm:px-5">
          <SkeletonText lines={4} className="py-1" />
        </div>
      ) : !ready ? (
        <p className="px-4 pb-3 text-sm text-fg-muted sm:px-5">
          The rules are not available right now.
        </p>
      ) : (
        <>
          {channels.data.length === 0 ? (
            <p className="border-t px-4 py-3 text-sm text-fg-muted sm:px-5">
              Add a channel first in{" "}
              <Link to="/settings?tab=alerts" className="text-fg underline underline-offset-2">
                Settings, Alert channels
              </Link>
              .
            </p>
          ) : null}
          {error ? (
            <p role="alert" className="border-t px-4 py-3 text-sm text-sev-warning sm:px-5">
              {error}
            </p>
          ) : null}
          <ul aria-label="Alert rules" className="divide-y border-t">
            {RULES.map((info) => {
              const rule = rules.data.find((r) => r.kind === info.kind)
              return rule ? (
                <RuleRow
                  key={info.kind}
                  info={info}
                  rule={rule}
                  channels={channels.data}
                  writable={canWrite}
                  onChanged={changed}
                  onError={setError}
                />
              ) : null
            })}
          </ul>
        </>
      )}
    </FindingCard>
  )
}

/** CVEs the owner wants an alert for. */
export function WatchedCvesCard() {
  const { canWrite } = useAuth()
  const client = useQueryClient()
  const [value, setValue] = useState("")
  const [problem, setProblem] = useState<string | null>(null)
  const inputId = useId()
  const q = useQuery({ queryKey: alertKeys.watched, queryFn: alertsApi.watched })
  const list = q.data

  async function run(fn: () => Promise<unknown>) {
    try {
      await fn()
      setProblem(null)
      void client.invalidateQueries({ queryKey: alertKeys.watched })
    } catch (e) {
      setProblem(e instanceof Error ? e.message : "The change could not be saved.")
    }
  }

  function add(event: SyntheticEvent) {
    event.preventDefault()
    const id = value.trim().toUpperCase()
    if (!CVE_PATTERN.test(id)) {
      setProblem("Enter a CVE number such as CVE-2026-12345.")
      return
    }
    setValue("")
    void run(() => watchCve(id))
  }

  return (
    <FindingCard
      eyebrow="Watched vulnerabilities"
      finding={
        !list
          ? "Checking the watch list…"
          : list.length === 0
            ? "No vulnerability on the watch list."
            : `You are watching ${list.length} ${list.length === 1 ? "vulnerability" : "vulnerabilities"}.`
      }
      detail="When attackers try one of these against the honeypot, the “watched vulnerability” alert fires (once a day per CVE)."
    >
      {q.isPending ? (
        <SkeletonText lines={2} className="py-1" />
      ) : (
        <div className="space-y-3">
          {list && list.length > 0 ? (
            <ul aria-label="Watched CVEs" className="flex flex-wrap gap-2">
              {list.map((c) => (
                <li
                  key={c.cve_id}
                  className="inline-flex items-center gap-1 rounded-md border py-0.5 pr-0.5 pl-2 font-mono text-xs text-fg"
                >
                  <Link to={`/cves?q=${c.cve_id}`} className="hover:underline">
                    {c.cve_id}
                  </Link>
                  {canWrite ? (
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Stop watching ${c.cve_id}`}
                      onClick={() => void run(() => unwatchCve(c.cve_id))}
                    >
                      <X aria-hidden />
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : null}
          {canWrite ? (
            <form onSubmit={add} className="flex max-w-md items-start gap-2" noValidate>
              <div className="min-w-0 flex-1 space-y-1">
                <label htmlFor={inputId} className="sr-only">
                  CVE number
                </label>
                <Input
                  id={inputId}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder="CVE-2026-12345"
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                  aria-invalid={problem ? true : undefined}
                />
                {problem ? (
                  <p role="alert" className="text-xs text-sev-warning">
                    {problem}
                  </p>
                ) : null}
              </div>
              <Button type="submit" variant="outline">
                <Plus aria-hidden />
                Watch
              </Button>
            </form>
          ) : null}
        </div>
      )}
    </FindingCard>
  )
}
