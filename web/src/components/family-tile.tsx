import { Link } from "react-router"
import { AnimatedNumber } from "@/components/animated-number"
import { Skeleton } from "@/components/ui/skeleton"
import { t } from "@/i18n"
import type { SensorCounts } from "@/lib/api"
import { formatNumber } from "@/lib/format"
import { FAMILY_META, SENSOR_META, sensorsHref, type SensorFamily } from "@/lib/sensors"
import { cn } from "@/lib/utils"

interface FamilyTileProps {
  family: SensorFamily
  /** Counts per sensor name (e.g. LiveStats.by_sensor). */
  bySensor: Record<string, SensorCounts> | undefined
  /** Which count is the headline number. */
  metric?: "events" | "sessions"
  /** Unit after the value, shortened on mobile via `unitShort`. */
  unit?: string
  unitShort?: string
  loading?: boolean
  className?: string
}

/**
 * One sensor family as a KPI: the family total in its hue, then one line per
 * sensor (icon, name, count). The tile opens the family's filtered Attacks
 * view; each sensor line opens that sensor's.
 */
export function FamilyTile({
  family,
  bySensor,
  metric = "events",
  unit,
  unitShort,
  loading = false,
  className,
}: FamilyTileProps) {
  const fam = FAMILY_META[family]
  const rows = fam.sensors.map((s) => ({ id: s, n: bySensor?.[s]?.[metric] ?? 0 }))
  const total = rows.reduce((n, r) => n + r.n, 0)

  return (
    <div
      className={cn(
        "group/tile relative flex min-w-0 flex-col gap-3 rounded-lg border bg-surface p-4 shadow-sm transition-colors duration-150 hover:bg-surface-hover/50 sm:p-5",
        className,
      )}
    >
      <Link
        to={sensorsHref(fam.sensors)}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
        aria-label={t("family_tile_aria", {
          label: fam.label,
          total: formatNumber(total),
          unit: unit ?? (metric === "events" ? t("family_tile_events") : t("family_tile_sessions")),
        })}
      />
      <div className={cn("inline-flex items-center gap-2 type-eyebrow", fam.text)}>
        <span aria-hidden className={cn("size-2 rounded-full", fam.fill)} />
        {fam.label}
      </div>
      {loading || !bySensor ? (
        <Skeleton className="h-8 w-24" />
      ) : (
        <span className="flex items-baseline gap-1.5">
          <AnimatedNumber value={total} className="type-kpi text-fg" />
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
      <ul className="-mx-1.5 mt-auto space-y-px border-t pt-2" aria-label={t("family_tile_sensors_aria", { label: fam.label })}>
        {rows.map(({ id, n }) => {
          const m = SENSOR_META[id]
          return (
            <li key={id}>
              <Link
                to={sensorsHref([id])}
                className={cn(
                  "relative z-10 flex h-6 items-center gap-2 rounded-sm px-1.5 text-xs transition-colors duration-150 hover:bg-surface-hover",
                  n > 0 ? "text-fg-muted hover:text-fg" : "text-fg-subtle",
                )}
              >
                <m.icon aria-hidden className={cn("size-3.5 shrink-0", m.text)} strokeWidth={2} />
                <span className="min-w-0 flex-1 truncate">{m.label}</span>
                <span className={cn("tabular-nums", n > 0 && "font-medium text-fg")}>
                  {loading || !bySensor ? "–" : formatNumber(n)}
                </span>
              </Link>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
