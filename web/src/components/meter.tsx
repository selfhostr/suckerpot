import { BarFill } from "@/components/bar-fill"
import { cn } from "@/lib/utils"

export type MeterTone = "neutral" | "warning" | "severe"

interface MeterProps {
  value: number
  max: number
  /** Accessible name, e.g. "AbuseIPDB checks used today". */
  label: string
  /** Human-readable value, e.g. "312 of 1,000". */
  valueText: string
  tone?: MeterTone
  className?: string
}

const FILL: Record<MeterTone, string> = {
  neutral: "bg-fg-muted",
  warning: "bg-sev-warning",
  severe: "bg-sev-severe",
}

/**
 * How much of a budget is used (quota, disk ceiling). Neutral until it matters:
 * warning from 80 %, severe only when the caller says so (e.g. disk guard critical).
 * A `meter`, not a progress bar: nothing is loading.
 */
export function Meter({ value, max, label, valueText, tone = "neutral", className }: MeterProps) {
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={value}
      aria-valuetext={valueText}
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-surface-hover", className)}
    >
      <BarFill ratio={ratio} className={FILL[tone]} />
    </div>
  )
}
