import { AnimatedNumber } from "@/components/animated-number"
import { useSensorFilter } from "@/hooks/use-sensor-filter"
import { t } from "@/i18n"
import type { SensorCounts } from "@/lib/api"
import { formatNumber } from "@/lib/format"
import {
  FAMILY_META,
  SENSOR_FAMILIES,
  exactFamily,
  type Sensor,
  type SensorFamily,
} from "@/lib/sensors"
import { cn } from "@/lib/utils"

interface FamilyStripProps {
  /** Counts per sensor name for the last minute (LiveStats.by_sensor). */
  bySensor: Record<string, SensorCounts> | undefined
  /**
   * `overlay`: one glassy row for the top-left corner of the map.
   * `grid`: a 2 x 2 (4 on wide screens) grid under the map, for narrow cards.
   */
  layout?: "overlay" | "grid"
  className?: string
}

function familyTotal(f: SensorFamily, bySensor: Record<string, SensorCounts> | undefined): number {
  return FAMILY_META[f].sensors.reduce((n, s) => n + (bySensor?.[s]?.events ?? 0), 0)
}

/**
 * The Live KPIs, compact enough to sit on the map: events per minute in total,
 * then one toggle per sensor family. The swatch is the family's arc colour, so
 * the strip doubles as the map legend; a toggle filters the whole page to that
 * family (`?sensor=`), a second press shows every sensor again.
 */
export function FamilyStrip({ bySensor, layout = "overlay", className }: FamilyStripProps) {
  const [sensors, setSensors] = useSensorFilter()
  const selected = new Set<Sensor>(sensors)
  const only = sensors.length > 1 ? exactFamily(sensors) : null
  const inSelection = (f: SensorFamily) =>
    sensors.length === 0 || FAMILY_META[f].sensors.some((s) => selected.has(s))
  const total = SENSOR_FAMILIES.filter(inSelection).reduce(
    (n, f) => n + familyTotal(f, bySensor),
    0,
  )
  const toggle = (f: SensorFamily) => setSensors(only === f ? [] : [...FAMILY_META[f].sensors])

  const overlay = layout === "overlay"
  return (
    <section
      aria-label={t("family_strip_aria")}
      className={cn(
        overlay
          ? "flex h-9 items-center gap-1 rounded-md border bg-surface-raised/90 p-0.5 shadow-sm backdrop-blur-sm"
          : "grid grid-cols-2 gap-x-2 gap-y-1 sm:grid-cols-[auto_repeat(4,minmax(0,1fr))]",
        className,
      )}
    >
      <p
        className={cn(
          "flex items-baseline gap-1.5 px-2",
          overlay ? "border-r pr-3" : "col-span-2 pb-1 sm:col-span-1 sm:pb-0",
        )}
      >
        {bySensor ? (
          <AnimatedNumber
            value={total}
            className={cn("font-semibold tracking-tight text-fg", overlay ? "text-md" : "text-lg")}
          />
        ) : (
          <span className="font-semibold text-fg-subtle">–</span>
        )}
        <span className="text-xs whitespace-nowrap text-fg-muted">{t("family_strip_unit")}</span>
      </p>
      <ul className="contents">
        {SENSOR_FAMILIES.map((f) => {
          const fam = FAMILY_META[f]
          const n = familyTotal(f, bySensor)
          const on = inSelection(f)
          return (
            <li key={f} className="min-w-0">
              <button
                type="button"
                aria-pressed={only === f}
                title={fam.label}
                aria-label={t("family_strip_button_aria", {
                  label: fam.label,
                  count: n,
                  only: only === f ? "yes" : "no",
                })}
                onClick={() => toggle(f)}
                className={cn(
                  "flex h-7 w-full min-w-0 items-center gap-2 rounded-sm px-2 text-xs transition-colors duration-150 hover:bg-surface-hover",
                  only === f && "bg-surface-hover",
                  on ? "text-fg-muted hover:text-fg" : "text-fg-subtle opacity-60",
                )}
              >
                <span aria-hidden className={cn("h-[3px] w-3.5 shrink-0 rounded-full", fam.fill)} />
                <span className={cn("min-w-0 truncate", overlay && "hidden @5xl:inline")}>{fam.label}</span>
                <span
                  className={cn(
                    "ml-auto font-medium tabular-nums",
                    on && n > 0 ? "text-fg" : "text-fg-subtle",
                  )}
                >
                  {bySensor ? formatNumber(n) : "–"}
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
