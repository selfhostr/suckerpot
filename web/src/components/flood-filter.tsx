import { SegmentedControl, type SegmentedOption } from "@/components/segmented-control"
import { useUrlParam } from "@/hooks/use-url-param"
import { FLOOD_PARAM, floodParamFor, floodViewFromParam, type FloodView } from "@/lib/floods"
import { cn } from "@/lib/utils"

const OPTIONS: readonly SegmentedOption<FloodView>[] = [
  { value: "all", label: "All", ariaLabel: "Show everything, floods included" },
  { value: "hide", label: "Hide", ariaLabel: "Hide floods" },
  { value: "only", label: "Only", ariaLabel: "Show only floods" },
]

/**
 * Floods: All, Hide or Only. Writes `?kind=` (`session` hides the flood groups, `burst` keeps
 * only them), so the choice is part of the link.
 */
export function FloodFilter({ className }: { className?: string }) {
  const [param, setParam] = useUrlParam(FLOOD_PARAM)
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <span aria-hidden className="text-xs text-fg-muted">
        Floods
      </span>
      <SegmentedControl
        label="Floods"
        value={floodViewFromParam(param)}
        onChange={(next) => setParam(floodParamFor(next))}
        options={OPTIONS}
      />
    </div>
  )
}
