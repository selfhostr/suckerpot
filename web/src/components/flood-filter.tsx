import { SegmentedControl, type SegmentedOption } from "@/components/segmented-control"
import { useUrlParam } from "@/hooks/use-url-param"
import { t } from "@/i18n"
import { FLOOD_PARAM, floodParamFor, floodViewFromParam, type FloodView } from "@/lib/floods"
import { cn } from "@/lib/utils"

/** Built on render, so the labels follow the language. */
function options(): readonly SegmentedOption<FloodView>[] {
  return [
    { value: "all", label: t("flood_filter_all"), ariaLabel: t("flood_filter_all_aria") },
    { value: "hide", label: t("flood_filter_hide"), ariaLabel: t("flood_filter_hide_aria") },
    { value: "only", label: t("flood_filter_only"), ariaLabel: t("flood_filter_only_aria") },
  ]
}

/**
 * Floods: All, Hide or Only. Writes `?kind=` (`session` hides the flood groups, `burst` keeps
 * only them), so the choice is part of the link.
 */
export function FloodFilter({ className }: { className?: string }) {
  const [param, setParam] = useUrlParam(FLOOD_PARAM)
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <span aria-hidden className="text-xs text-fg-muted">
        {t("flood_filter_label")}
      </span>
      <SegmentedControl
        label={t("flood_filter_label")}
        value={floodViewFromParam(param)}
        onChange={(next) => setParam(floodParamFor(next))}
        options={options()}
      />
    </div>
  )
}
