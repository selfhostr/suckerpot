import {
  Archive,
  Bell,
  ChevronRight,
  Crosshair,
  Database,
  FileCode2,
  Flag,
  Globe,
  Mail,
  MailWarning,
  Monitor,
  Play,
  ScanSearch,
  Shield,
  SquareTerminal,
  Sun,
  TrendingUp,
  UserCheck,
  Waypoints,
  type LucideIcon,
} from "lucide-react"
import { t, tk } from "@/i18n"
import { FAMILY_META, type SensorFamily } from "@/lib/sensors"
import type { TourStep } from "@/lib/tour"
import { cn } from "@/lib/utils"

interface FlowNode {
  icon: LucideIcon
  labelKey: string
  /** A sensor family colours the node; the label is always there too. */
  family?: SensorFamily
}

/** Each stage is one column of nodes; arrows join the stages. */
type Stages = readonly (readonly FlowNode[])[]

function Node({ node }: { node: FlowNode }) {
  const Icon = node.icon
  const fam = node.family ? FAMILY_META[node.family] : null
  return (
    <span
      className={cn(
        "inline-flex min-h-8 items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium",
        fam ? [fam.text, fam.tint] : "bg-bg text-fg",
      )}
    >
      <Icon aria-hidden className="size-3.5 shrink-0" strokeWidth={2} />
      <span className={fam ? "text-fg" : undefined}>{t(node.labelKey)}</span>
    </span>
  )
}

function Flow({
  stages,
  labelKey,
  className,
}: {
  stages: Stages
  labelKey: string
  className?: string
}) {
  return (
    <div
      role="img"
      aria-label={t(labelKey)}
      className={cn(
        "flex flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed bg-surface px-3 py-4 sm:flex-row sm:flex-wrap sm:gap-2",
        className,
      )}
    >
      {stages.map((stage, i) => (
        <span key={i} className="flex flex-col items-center gap-1.5 sm:flex-row sm:gap-2">
          {i > 0 ? (
            <ChevronRight
              aria-hidden
              className="size-4 shrink-0 rotate-90 text-fg-subtle sm:rotate-0"
            />
          ) : null}
          <span className="flex flex-col items-stretch gap-1.5">
            {stage.map((n) => (
              <Node key={n.labelKey} node={n} />
            ))}
          </span>
        </span>
      ))}
    </div>
  )
}

const SENSOR_STAGE: readonly FlowNode[] = [
  { icon: SquareTerminal, labelKey: tk("tour_node_remote_shells"), family: "shell" },
  { icon: Globe, labelKey: tk("tour_node_web_and_apis"), family: "web" },
  { icon: Database, labelKey: tk("tour_node_databases"), family: "data" },
  { icon: Monitor, labelKey: tk("tour_node_windows_and_voip"), family: "windows" },
]

const FLOWS: Record<TourStep["id"], { labelKey: string; stages: Stages }> = {
  what: {
    labelKey: tk("tour_flow_what"),
    stages: [
      [{ icon: Globe, labelKey: tk("tour_node_internet") }],
      SENSOR_STAGE,
      [{ icon: Database, labelKey: tk("tour_node_events_and_sessions") }],
    ],
  },
  daily: {
    labelKey: tk("tour_flow_daily"),
    stages: [
      [{ icon: Sun, labelKey: tk("nav_today") }],
      [{ icon: Crosshair, labelKey: tk("nav_attacks") }],
      [{ icon: Play, labelKey: tk("tour_node_session_and_replay") }],
    ],
  },
  group: {
    labelKey: tk("tour_flow_group"),
    stages: [
      [{ icon: Crosshair, labelKey: tk("nav_sessions") }],
      [
        { icon: Flag, labelKey: tk("nav_campaigns") },
        { icon: FileCode2, labelKey: tk("nav_payloads") },
        { icon: TrendingUp, labelKey: tk("nav_patterns") },
      ],
    ],
  },
  payloads: {
    labelKey: tk("tour_flow_payloads"),
    stages: [
      [{ icon: Waypoints, labelKey: tk("tour_node_recorded_url") }],
      [{ icon: Shield, labelKey: tk("tour_node_collector_vpn") }],
      [{ icon: Archive, labelKey: tk("tour_node_quarantine") }],
      [{ icon: ScanSearch, labelKey: tk("tour_node_analyzer_offline") }],
    ],
  },
  egress: {
    labelKey: tk("tour_flow_egress"),
    stages: [
      [{ icon: Database, labelKey: tk("tour_node_ingest_collector") }],
      [{ icon: Shield, labelKey: tk("tour_node_gate") }],
      [{ icon: Waypoints, labelKey: tk("tour_node_vpn_kill_switch") }],
      [{ icon: Globe, labelKey: tk("tour_node_internet") }],
    ],
  },
  abuse: {
    labelKey: tk("tour_flow_abuse"),
    stages: [
      [{ icon: ScanSearch, labelKey: tk("tour_node_rdap_lookup") }],
      [{ icon: MailWarning, labelKey: tk("tour_node_draft") }],
      [{ icon: UserCheck, labelKey: tk("tour_node_you_review") }],
      [{ icon: Mail, labelKey: tk("tour_node_your_mailbox") }],
    ],
  },
  alerts: {
    labelKey: tk("tour_flow_alerts"),
    stages: [
      [{ icon: Bell, labelKey: tk("tour_node_rules") }],
      [{ icon: Mail, labelKey: tk("tour_node_discord_teams_email") }],
      [{ icon: UserCheck, labelKey: tk("tour_node_you") }],
    ],
  },
}

/** The small picture of one tour step, built from boxes and arrows only. */
export function TourIllustration({
  step,
  className,
}: {
  step: TourStep["id"]
  className?: string
}) {
  const f = FLOWS[step]
  return <Flow stages={f.stages} labelKey={f.labelKey} className={className} />
}
