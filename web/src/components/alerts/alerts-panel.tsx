import { useQuery } from "@tanstack/react-query"
import { Link } from "react-router"
import { OutboxCard } from "@/components/alerts/outbox-card"
import { ReportsCard } from "@/components/alerts/reports-card"
import { RulesCard, WatchedCvesCard } from "@/components/alerts/rules-card"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { alertKeys, alertsApi } from "@/lib/alerts"

/** What the tab says right now, in one sentence. */
function sentence(enabledRules: number | null, channels: number | null, off: boolean): string {
  if (off) return t("alerts_panel_off")
  if (enabledRules === null || channels === null) return t("alerts_panel_intro")
  if (enabledRules === 0) return t("alerts_panel_none")
  return t("alerts_panel_summary", { alerts: enabledRules, channels })
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
        {tNodes(
          "alerts_panel_lede",
          { summary: sentence(enabled, used, status.data ? !status.data.alerts.enabled : false) },
          {
            link: (
              <Link to="/settings?tab=alerts" className="text-fg underline underline-offset-4">
                {t("settings_tab_alert_channels")}
              </Link>
            ),
          },
        )}
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
