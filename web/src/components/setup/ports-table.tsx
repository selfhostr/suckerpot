import { useQuery } from "@tanstack/react-query"
import { CircleCheck, CircleOff, Hourglass, ShieldAlert, type LucideIcon } from "lucide-react"
import { FindingCard } from "@/components/finding-card"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SkeletonText } from "@/components/skeletons"
import {
  describePort,
  describePorts,
  PORT_STATE_LABEL,
  wizardApi,
  wizardKeys,
  type PortItem,
  type PortState,
} from "@/lib/setup-wizard"
import { cn } from "@/lib/utils"

const STATE_STYLE: Record<PortState, { icon: LucideIcon; className: string }> = {
  receiving: { icon: CircleCheck, className: "text-status-ok" },
  waiting: { icon: Hourglass, className: "text-sev-warning" },
  off: { icon: CircleOff, className: "text-fg-muted" },
}

export function PortStatus({ item }: { item: PortItem }) {
  const { icon: Icon, className } = STATE_STYLE[item.state]
  return (
    <span className={cn("inline-flex items-start gap-1.5 text-sm", className)}>
      <Icon aria-hidden className="mt-0.5 size-4 shrink-0" strokeWidth={2.25} />
      <span>
        {PORT_STATE_LABEL[item.state]}
        {item.state === "receiving" && item.last_event_at ? (
          <span className="block text-xs text-fg-muted">
            {tNodes(
              "setup_port_last_connection",
              {},
              { time: <RelativeTime iso={item.last_event_at} /> },
            )}
          </span>
        ) : null}
      </span>
    </span>
  )
}

const GRID = "grid-cols-[1fr_auto] sm:grid-cols-[8rem_1fr_1fr_1.4fr]"

/** The sensors, the router port to open, the port on this machine, and a live status. */
export function PortsTable({ items }: { items: readonly PortItem[] }) {
  return (
    <div>
      <div
        aria-hidden
        className={cn(
          "hidden gap-x-4 border-t px-4 py-2 text-xs font-medium text-fg-muted sm:grid sm:px-5",
          GRID,
        )}
      >
        <span>{t("setup_ports_col_sensor")}</span>
        <span>{t("setup_ports_col_router")}</span>
        <span>{t("setup_ports_col_forward")}</span>
        <span>{t("setup_ports_col_status")}</span>
      </div>
      <ul aria-label={t("setup_ports_list_label")} className="divide-y border-t">
        {items.map((i) => (
          <li
            key={i.sensor}
            className={cn(
              "grid items-start gap-x-4 gap-y-1 px-4 py-3 sm:px-5",
              GRID,
              !i.enabled && "text-fg-muted",
            )}
          >
            <SensorBadge sensor={i.sensor} variant="dot" className="text-sm text-fg" />
            <span className="col-start-2 row-start-1 justify-self-end sm:col-start-4 sm:row-start-1 sm:justify-self-start">
              <PortStatus item={i} />
            </span>
            <span className="col-span-2 text-sm sm:col-span-1 sm:col-start-2 sm:row-start-1">
              <span className="text-xs text-fg-muted sm:hidden">{t("setup_ports_router_inline")} </span>
              <span className="font-mono tabular-nums">{describePort(i)}</span>
            </span>
            <span className="col-span-2 text-sm sm:col-span-1 sm:col-start-3 sm:row-start-1">
              <span className="text-xs text-fg-muted sm:hidden">{t("setup_ports_forward_inline")} </span>
              <span className="font-mono tabular-nums">{i.host_port}</span>
              <span className="ml-2 font-mono text-2xs text-fg-subtle">{i.env_var}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * The one rule that must not be missed, above the table: what never to forward. Shared by the setup
 * step and Settings, so both say it the same way.
 */
export function NeverForward({ dashboardPort }: { dashboardPort: number }) {
  return (
    <div
      role="note"
      className="flex items-start gap-2.5 rounded-md border border-sev-warning/40 px-3 py-2.5 text-sm text-fg"
    >
      <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
      <p className="text-pretty">
        <span className="font-medium">
          {tNodes(
            "setup_never_forward",
            {},
            { port: <span className="font-mono tabular-nums">{dashboardPort}</span> },
          )}
        </span>{" "}
        {t("setup_never_forward_why")}
      </p>
    </div>
  )
}

/** The notes that belong under the table: CGNAT, and why a sensor may still be waiting. */
export function PortsNotes() {
  return (
    <ul className="list-disc space-y-1 pl-4 text-xs text-fg-muted">
      <li>
        {tNodes(
          "setup_ports_cgnat",
          {},
          {
            range: <span className="font-mono tabular-nums">100.64.0.0/10</span>,
            doc: <code className="font-mono">docs/deployment.md</code>,
          },
        )}
      </li>
      <li>
        {t("setup_ports_note_receiving")}
      </li>
    </ul>
  )
}

/** One card: the finding, the rule, the table, the notes. Shared by the setup step and Settings. */
export function PortsCard({ eyebrow }: { eyebrow?: string }) {
  const q = useQuery({
    queryKey: wizardKeys.ports,
    queryFn: wizardApi.ports,
    refetchInterval: 15_000,
  })
  return (
    <FindingCard
      eyebrow={eyebrow ?? t("setup_ports_card_title")}
      finding={
        q.data
          ? describePorts(q.data.items)
          : q.isError
            ? t("setup_ports_unavailable")
            : t("setup_sensors_checking")
      }
      detail={t("setup_ports_detail")}
      bodyClassName="px-0 sm:px-0 pt-4 pb-0 sm:pb-0"
      footer={q.data ? <PortsNotes /> : null}
    >
      {q.data ? (
        <div className="space-y-4">
          <div className="px-4 sm:px-5">
            <NeverForward dashboardPort={q.data.dashboard_port} />
          </div>
          <PortsTable items={q.data.items} />
        </div>
      ) : q.isPending ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <SkeletonText lines={4} />
        </div>
      ) : null}
    </FindingCard>
  )
}
