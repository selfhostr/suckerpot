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
import { FAMILY_META, type SensorFamily } from "@/lib/sensors"
import type { TourStep } from "@/lib/tour"
import { cn } from "@/lib/utils"

interface FlowNode {
  icon: LucideIcon
  label: string
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
      <span className={fam ? "text-fg" : undefined}>{node.label}</span>
    </span>
  )
}

function Flow({ stages, label, className }: { stages: Stages; label: string; className?: string }) {
  return (
    <div
      role="img"
      aria-label={label}
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
              <Node key={n.label} node={n} />
            ))}
          </span>
        </span>
      ))}
    </div>
  )
}

const SENSOR_STAGE: readonly FlowNode[] = [
  { icon: SquareTerminal, label: "Remote shells", family: "shell" },
  { icon: Globe, label: "Web and APIs", family: "web" },
  { icon: Database, label: "Databases", family: "data" },
  { icon: Monitor, label: "Windows and VoIP", family: "windows" },
]

const FLOWS: Record<TourStep["id"], { label: string; stages: Stages }> = {
  what: {
    label: "Attackers on the internet reach fake sensors, which record events.",
    stages: [
      [{ icon: Globe, label: "Internet" }],
      SENSOR_STAGE,
      [{ icon: Database, label: "Events and sessions" }],
    ],
  },
  daily: {
    label: "Today leads to Attacks, then to one session with its replay.",
    stages: [
      [{ icon: Sun, label: "Today" }],
      [{ icon: Crosshair, label: "Attacks" }],
      [{ icon: Play, label: "Session and replay" }],
    ],
  },
  group: {
    label: "Sessions are grouped into campaigns, payloads and patterns.",
    stages: [
      [{ icon: Crosshair, label: "Sessions" }],
      [
        { icon: Flag, label: "Campaigns" },
        { icon: FileCode2, label: "Payloads" },
        { icon: TrendingUp, label: "Patterns" },
      ],
    ],
  },
  payloads: {
    label:
      "A recorded URL is fetched by the collector through the VPN into quarantine, then read by the analyzer with no network.",
    stages: [
      [{ icon: Waypoints, label: "Recorded URL" }],
      [{ icon: Shield, label: "Collector (VPN)" }],
      [{ icon: Archive, label: "Quarantine" }],
      [{ icon: ScanSearch, label: "Analyzer (offline)" }],
    ],
  },
  egress: {
    label: "The stack has no route out except the vpn service, behind a gate and a kill switch.",
    stages: [
      [{ icon: Database, label: "Ingest + collector" }],
      [{ icon: Shield, label: "Gate" }],
      [{ icon: Waypoints, label: "VPN + kill switch" }],
      [{ icon: Globe, label: "Internet" }],
    ],
  },
  abuse: {
    label: "A contact is found, a draft is built, you review it and send it from your own mailbox.",
    stages: [
      [{ icon: ScanSearch, label: "RDAP lookup" }],
      [{ icon: MailWarning, label: "Draft" }],
      [{ icon: UserCheck, label: "You review" }],
      [{ icon: Mail, label: "Your mailbox" }],
    ],
  },
  alerts: {
    label: "Rules send messages to your channels, and a weekly report summarises the week.",
    stages: [
      [{ icon: Bell, label: "Rules" }],
      [{ icon: Mail, label: "Discord, Teams, email" }],
      [{ icon: UserCheck, label: "You" }],
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
  return <Flow stages={f.stages} label={f.label} className={className} />
}
