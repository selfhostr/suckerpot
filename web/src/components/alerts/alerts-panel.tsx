import { useQuery } from "@tanstack/react-query"
import { Link } from "react-router"
import { OutboxCard } from "@/components/alerts/outbox-card"
import { ReportsCard } from "@/components/alerts/reports-card"
import { RulesCard, WatchedCvesCard } from "@/components/alerts/rules-card"
import { alertKeys, alertsApi } from "@/lib/alerts"
import { plural } from "@/lib/format"

/** What the tab says right now, in one sentence. */
function sentence(enabledRules: number | null, channels: number | null, off: boolean): string {
  if (off)
    return "Alerts are switched off on this server, so nothing is sent until they are enabled."
  if (enabledRules === null || channels === null)
    return "Get a message when something that matters happens, and one report every Monday."
  if (enabledRules === 0)
    return "Nothing is sent yet. Switch on the alerts you care about and choose where they go."
  return `${plural(enabledRules, "alert")} ${enabledRules === 1 ? "is" : "are"} on, sent to ${plural(channels, "channel")}.`
}

/**
 * Settings, Alerts tab (the old Alerts page): the rules, the weekly reports (each opens
 * `/reports/<week>`), the watched vulnerabilities and the recent alerts. Where they are sent is
 * the Alert channels tab beside it.
 */
export function AlertsPanel() {
  const rules = useQuery({ queryKey: alertKeys.rules, queryFn: alertsApi.rules })
  const status = useQuery({ queryKey: alertKeys.status, queryFn: alertsApi.status })
  const enabled = rules.data ? rules.data.filter((r) => r.enabled).length : null
  const used = rules.data
    ? new Set(rules.data.filter((r) => r.enabled).flatMap((r) => r.channel_ids)).size
    : null
  return (
    <div className="grid grid-cols-1 gap-4 normal-nums">
      <p className="type-lede text-pretty text-fg-muted">
        {sentence(enabled, used, status.data ? !status.data.alerts.enabled : false)} Where they go
        is set under{" "}
        <Link to="/settings?tab=alerts" className="text-fg underline underline-offset-4">
          Alert channels
        </Link>
        .
      </p>
      <RulesCard />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ReportsCard />
        <WatchedCvesCard />
      </div>
      <OutboxCard />
    </div>
  )
}
