import { STAGE_ICON } from "@/components/campaigns/stage-icons"
import { t } from "@/i18n"
import { STAGES, STAGE_META, stageReach, stageTrailText, type Stage } from "@/lib/campaigns"
import { cn } from "@/lib/utils"

interface StageTrailProps {
  /** Stage ids the campaign went through (any order; the trail is always in story order). */
  stages: readonly string[]
  /**
   * `compact` (lists): six small slots, an icon where the stage was seen, a dot where it was not,
   * and one line of words under it. `steps` (detail pages): the six stages as a stepper with
   * their names.
   */
  variant?: "compact" | "steps"
  className?: string
}

function stageState(stage: Stage, seen: boolean): string {
  return t(seen ? "campaign_stage_seen" : "campaign_stage_not_seen", {
    stage: STAGE_META[stage].label,
  })
}

/**
 * The playbook at a glance, always in story order, so rows line up and can be compared. Seen and
 * not seen differ by shape (an icon in a box against a dot or a dashed ring) and by words, never
 * by colour, and stages never get a hue. Slots fade in one after the other.
 */
export function StageTrail({ stages, variant = "compact", className }: StageTrailProps) {
  const label = t("campaign_stages_label", { stages: stageTrailText(stages) })
  if (variant === "steps") {
    return (
      <ol aria-label={label} className={cn("relative grid grid-cols-6 gap-1", className)}>
        {/* The rail behind the rings, from the first centre to the last. */}
        <span
          aria-hidden
          className="absolute top-4 right-[calc(100%/12)] left-[calc(100%/12)] h-px bg-border"
        />
        {STAGES.map((stage, i) => {
          const on = stages.includes(stage)
          const Icon = STAGE_ICON[stage]
          return (
            <li
              key={stage}
              style={{ animationDelay: `${i * 60}ms` }}
              className="relative flex min-w-0 animate-fade-in flex-col items-center gap-1.5 text-center"
            >
              <span
                aria-hidden
                className={cn(
                  "flex size-8 items-center justify-center rounded-full border",
                  on
                    ? "border-fg-subtle bg-surface-raised text-fg shadow-sm"
                    : "border-dashed border-border-strong bg-surface text-fg-subtle",
                )}
              >
                <Icon className="size-4" strokeWidth={on ? 2 : 1.5} />
              </span>
              <span
                className={cn(
                  "text-2xs leading-tight text-balance",
                  on ? "font-medium text-fg" : "text-fg-subtle",
                )}
              >
                <span aria-hidden>{STAGE_META[stage].label}</span>
                <span className="sr-only">{stageState(stage, on)}</span>
              </span>
            </li>
          )
        })}
      </ol>
    )
  }
  return (
    <div className={cn("min-w-0 space-y-1", className)}>
      <ol aria-label={label} className="flex items-center gap-1">
        {STAGES.map((stage, i) => {
          const on = stages.includes(stage)
          const Icon = STAGE_ICON[stage]
          return (
            <li
              key={stage}
              title={on ? STAGE_META[stage].label : stageState(stage, false)}
              style={{ animationDelay: `${i * 45}ms` }}
              className={cn(
                "flex size-5 shrink-0 animate-fade-in items-center justify-center rounded-sm",
                on && "border border-border-strong bg-surface-raised text-fg",
              )}
            >
              {on ? (
                <Icon aria-hidden className="size-3" strokeWidth={2} />
              ) : (
                <span aria-hidden className="size-1 rounded-full bg-fg-subtle" />
              )}
              <span className="sr-only">
                {stageState(stage, on)}
              </span>
            </li>
          )
        })}
      </ol>
      <p aria-hidden className="truncate text-2xs text-fg-muted">
        {stageReach(stages)}
      </p>
    </div>
  )
}
