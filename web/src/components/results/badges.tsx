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
import { t, tk } from "@/i18n"
import { OUTCOME_LABEL, type Outcome } from "@/lib/replies"
import type { TargetRole, TargetState } from "@/lib/results"
import { cn } from "@/lib/utils"

interface Meta {
  icon: LucideIcon
  className: string
  iconClass?: string
}

const NEUTRAL = "text-fg-muted"
const WARN = "text-sev-warning tint-warning"

const OUTCOME_META: Record<Outcome, Meta> = {
  none: { icon: CircleDashed, className: NEUTRAL },
  unknown: { icon: CircleHelp, className: NEUTRAL },
  bounce: { icon: MailX, className: WARN },
  auto_ack: { icon: Bot, className: NEUTRAL },
  human_reply: { icon: UserRound, className: "text-fg" },
  ticket_opened: { icon: Ticket, className: "text-fg" },
  rejected: { icon: CircleX, className: WARN },
  resolved: {
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
  const label =
    noAnswer && outcome === "none" ? t("results_outcome_no_answer") : OUTCOME_LABEL[outcome]
  return (
    <span
      className={cn(
        "inline-flex min-h-(--chip) items-center gap-1.5 rounded-sm px-1 text-xs font-medium",
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
  up: tk("results_state_payload_up"),
  down: tk("results_state_payload_down"),
  changed: tk("results_state_payload_changed"),
  unknown: tk("common_unknown"),
}
const ADDRESS_WORD: Record<TargetState, string> = {
  up: tk("results_state_address_up"),
  down: tk("results_state_address_down"),
  changed: tk("results_state_address_changed"),
  unknown: tk("common_unknown"),
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
  const word = t((address ? ADDRESS_WORD : PAYLOAD_WORD)[state])
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
        "inline-flex min-h-(--chip) items-center gap-1.5 rounded-sm px-1 text-xs font-medium text-fg",
        className,
      )}
    >
      <Icon
        aria-hidden
        className={cn("size-3.5", tone, state === "down" && "text-status-ok")}
        strokeWidth={2.25}
      />
      {word}
      {severe ? <span className="sr-only"> {t("results_state_severe")}</span> : null}
    </span>
  )
}
