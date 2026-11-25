import {
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleHelp,
  CircleX,
  MailX,
  Repeat2,
  Ticket,
  TriangleAlert,
  UserRound,
  Bot,
  type LucideIcon,
} from "lucide-react"
import { OUTCOME_LABEL, type Outcome } from "@/lib/replies"
import type { TargetRole, TargetState } from "@/lib/results"
import { cn } from "@/lib/utils"

interface Meta {
  label: string
  icon: LucideIcon
  className: string
  iconClass?: string
}

const NEUTRAL = "text-fg-muted"
const WARN = "text-sev-warning tint-warning"

const OUTCOME_META: Record<Outcome, Meta> = {
  none: { label: OUTCOME_LABEL.none, icon: CircleDashed, className: NEUTRAL },
  unknown: { label: OUTCOME_LABEL.unknown, icon: CircleHelp, className: NEUTRAL },
  bounce: { label: OUTCOME_LABEL.bounce, icon: MailX, className: WARN },
  auto_ack: { label: OUTCOME_LABEL.auto_ack, icon: Bot, className: NEUTRAL },
  human_reply: { label: OUTCOME_LABEL.human_reply, icon: UserRound, className: "text-fg" },
  ticket_opened: { label: OUTCOME_LABEL.ticket_opened, icon: Ticket, className: "text-fg" },
  rejected: { label: OUTCOME_LABEL.rejected, icon: CircleX, className: WARN },
  resolved: {
    label: OUTCOME_LABEL.resolved,
    icon: CircleCheck,
    className: "text-fg",
    iconClass: "text-status-ok",
  },
}

interface OutcomeBadgeProps {
  outcome: Outcome
  /** Show "No answer" for an old unanswered report. */
  noAnswer?: boolean
  className?: string
}

/** What a report led to, as icon plus word. Warning tone for rejected and bounced, never red. */
export function OutcomeBadge({ outcome, noAnswer = false, className }: OutcomeBadgeProps) {
  const m = OUTCOME_META[outcome]
  const label = noAnswer && outcome === "none" ? "No answer" : m.label
  return (
    <span
      className={cn(
        "inline-flex h-(--chip) shrink-0 items-center gap-1.5 rounded-sm px-1 text-xs font-medium whitespace-nowrap",
        m.className,
        className,
      )}
    >
      <m.icon aria-hidden className={cn("size-3.5", m.iconClass)} strokeWidth={2.25} />
      {label}
    </span>
  )
}

const PAYLOAD_WORD: Record<TargetState, string> = {
  up: "Still serving",
  down: "Down",
  changed: "Serving a new file",
  unknown: "Unknown",
}
const ADDRESS_WORD: Record<TargetState, string> = {
  up: "Active",
  down: "Quiet",
  changed: "Changed",
  unknown: "Unknown",
}

interface StateBadgeProps {
  state: TargetState
  role: TargetRole
  className?: string
}

/**
 * State of a tracked target, icon plus word. Red only for a payload still being served or replaced by a new file (severe);
 * attacking addresses and C2 servers never use red. Changed is the warning tone, down the ok tone.
 */
export function TargetStateBadge({ state, role, className }: StateBadgeProps) {
  const address = role === "attack_source" || role === "c2"
  const word = (address ? ADDRESS_WORD : PAYLOAD_WORD)[state]
  const severe = (state === "up" || state === "changed") && !address
  const Icon: LucideIcon =
    state === "down"
      ? CircleCheck
      : state === "changed"
        ? Repeat2
        : state === "up"
          ? severe
            ? CircleAlert
            : TriangleAlert
          : CircleHelp
  const tone =
    state === "down"
      ? "text-fg"
      : severe
        ? "text-sev-severe"
        : state === "changed"
          ? "text-sev-warning"
          : "text-fg-muted"
  return (
    <span
      className={cn(
        "inline-flex h-(--chip) shrink-0 items-center gap-1.5 rounded-sm px-1 text-xs font-medium whitespace-nowrap text-fg",
        className,
      )}
    >
      <Icon
        aria-hidden
        className={cn("size-3.5", tone, state === "down" && "text-status-ok")}
        strokeWidth={2.25}
      />
      {word}
      {severe ? <span className="sr-only"> (severe: malware is still served)</span> : null}
    </span>
  )
}
