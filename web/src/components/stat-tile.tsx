import { ArrowDownRight, ArrowRight, ArrowUpRight } from "lucide-react"
import { Link } from "react-router"
import { AnimatedNumber } from "@/components/animated-number"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber, formatPercent } from "@/lib/format"
import { sensorMeta } from "@/lib/sensors"
import { cn } from "@/lib/utils"

interface StatTileProps {
  label: string
  value: number | null | undefined
  /** Relative change vs the previous window, as a ratio (0.12 = +12%). */
  delta?: number | null
  deltaLabel?: string
  hint?: string
  sparkline?: React.ReactNode
  loading?: boolean
  format?: (n: number) => string
  /** Tie the tile to a sensor: the label takes the sensor's hue and icon. */
  sensor?: string
  /** Unit after the value, e.g. "events / min". Shortened on mobile via `unitShort`. */
  unit?: string
  unitShort?: string
  /** Makes the whole tile a link (e.g. to the filtered list). */
  href?: string
  /**
   * `card` (default) is the bordered KPI tile. `figure` drops the card: no border or fill and a
   * larger value, for the few headline numbers that open a page (Today, Results), so they read
   * before the cards around them.
   */
  variant?: "card" | "figure"
  className?: string
}

/**
 * One KPI. Deltas stay neutral: for a honeypot "more" is neither good nor bad,
 * so we use an arrow and words, never green/red.
 */
export function StatTile({
  label,
  value,
  delta,
  deltaLabel = "vs prev. 24 h",
  hint,
  sparkline,
  loading = false,
  format = formatNumber,
  sensor,
  unit,
  unitShort,
  href,
  variant = "card",
  className,
}: StatTileProps) {
  const figure = variant === "figure"
  const meta = sensor ? sensorMeta(sensor) : null
  const SensorIcon = meta?.icon
  const DeltaIcon =
    delta == null || Math.abs(delta) < 0.005
      ? ArrowRight
      : delta > 0
        ? ArrowUpRight
        : ArrowDownRight

  const body = (
    <>
      <div
        className={cn(
          "inline-flex items-center gap-1.5 type-eyebrow",
          meta ? meta.text : "text-fg-muted",
        )}
      >
        {SensorIcon ? <SensorIcon aria-hidden className="size-3.5" strokeWidth={2} /> : null}
        {label}
      </div>
      {loading || value == null ? (
        <Skeleton className={cn("w-24", figure ? "h-8.5 sm:h-10.5" : "h-8.5")} />
      ) : (
        <span className="flex items-baseline gap-1.5">
          <AnimatedNumber
            value={value}
            format={format}
            className={cn("text-fg", figure ? "type-figure" : "type-kpi")}
          />
          {unit ? (
            <span className="text-xs text-fg-muted">
              <span className={cn(unitShort && "hidden sm:inline")}>{unit}</span>
              {unitShort ? (
                <span aria-hidden className="sm:hidden">
                  {unitShort}
                </span>
              ) : null}
            </span>
          ) : null}
        </span>
      )}
      {sparkline ? <div className="-mx-1 text-fg-subtle">{sparkline}</div> : null}
      {delta != null || hint ? (
        <div className="mt-auto flex min-h-4 flex-wrap items-center gap-x-1 text-xs text-fg-muted">
          {delta != null ? (
            <>
              <DeltaIcon aria-hidden className="size-3.5 text-fg-subtle" />
              <span className="font-medium text-fg">
                {delta > 0 ? "+" : ""}
                {formatPercent(delta)}
              </span>
              <span>{deltaLabel}</span>
            </>
          ) : (
            <span>{hint}</span>
          )}
        </div>
      ) : null}
    </>
  )

  const classes = cn(
    figure
      ? // A little inner room, so a linked figure's hover fill does not touch the text.
        "-mx-2 flex min-w-0 flex-col gap-1.5 rounded-md px-2 py-1.5"
      : "flex min-w-0 flex-col gap-3 rounded-lg border bg-surface p-4 shadow-sm sm:p-5",
    href && "transition-colors duration-150 hover:bg-surface-hover/50",
    className,
  )
  return href ? (
    <Link to={href} className={classes}>
      {body}
    </Link>
  ) : (
    <div className={classes}>{body}</div>
  )
}
