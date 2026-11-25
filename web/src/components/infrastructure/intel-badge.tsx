import { CircleDashed, CircleHelp, OctagonAlert } from "lucide-react"
import { INTEL_LABELS, intelState, type IndicatorItem, type IntelState } from "@/lib/infrastructure"
import { cn } from "@/lib/utils"

const STYLE: Record<IntelState, { icon: typeof OctagonAlert; className: string }> = {
  // Red is for severe: a payload host that threat intelligence knows as malicious.
  known: { icon: OctagonAlert, className: "tint-severe border-sev-severe/30 text-sev-severe" },
  "listed-none": { icon: CircleHelp, className: "border-border text-fg-muted" },
  unchecked: { icon: CircleDashed, className: "border-dashed border-border-strong text-fg-subtle" },
}

/** Icon, word and tone together, so the meaning never rests on colour alone. */
export function IntelBadge({
  item,
  className,
}: {
  item: Pick<IndicatorItem, "checked" | "known">
  className?: string
}) {
  const state = intelState(item)
  const { icon: Icon, className: tone } = STYLE[state]
  return (
    <span
      className={cn(
        "inline-flex min-h-(--chip) items-center gap-1.5 rounded-sm border px-2 text-xs font-medium",
        tone,
        className,
      )}
    >
      <Icon aria-hidden className="size-3.5" strokeWidth={2} />
      {INTEL_LABELS[state]}
    </span>
  )
}
