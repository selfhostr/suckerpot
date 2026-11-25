import type { CSSProperties } from "react"
import { Link } from "react-router"
import { t } from "@/i18n"
import type { Sensor } from "@/lib/api"
import { formatNumber, formatPercent } from "@/lib/format"
import {
  FAMILY_META,
  SENSOR_FAMILIES,
  SENSOR_META,
  listPlain,
  sensorsHref,
  type SensorFamily,
} from "@/lib/sensors"
import { cn } from "@/lib/utils"

interface SensorShareProps {
  shares: readonly { id: Sensor; value: number }[]
  className?: string
}

/** Where each family's segment starts and how much of the bar it takes (0..1). */
function segments(families: readonly { id: SensorFamily; value: number }[], total: number) {
  let start = 0
  return families
    .filter((f) => f.value > 0)
    .map((f) => {
      const share = f.value / total
      const segment = { id: f.id, start, share }
      start += share
      return segment
    })
}

/**
 * A single stacked bar by family plus a labelled legend: each family's total
 * and share, then its busiest sensors by name. The legend carries the numbers,
 * so colour is never the only way to read it. Every entry links to the filtered list.
 */
export function SensorShare({ shares, className }: SensorShareProps) {
  const value = (s: Sensor) => shares.find((x) => x.id === s)?.value ?? 0
  const total = shares.reduce((n, s) => n + s.value, 0)
  const families = SENSOR_FAMILIES.map((f) => ({
    id: f,
    value: FAMILY_META[f].sensors.reduce((n, s) => n + value(s), 0),
  }))

  return (
    <div className={cn("space-y-4", className)}>
      {/* Each segment is the whole track, moved to its start and scaled to its share, so a new
        split glides on the compositor; a thin gap marks every start but the first. */}
      <div
        className="relative h-2.5 w-full overflow-hidden rounded-full bg-surface-hover"
        role="img"
        aria-label={listPlain(
          families.map((f) =>
            t("sensorshare_item", { label: FAMILY_META[f.id].label, value: formatNumber(f.value) }),
          ),
        )}
      >
        {total
          ? segments(families, total).map(({ id, start, share }) => (
              <span key={id} aria-hidden>
                <span
                  className={cn("bar-fill absolute inset-0", FAMILY_META[id].fill)}
                  style={
                    { "--bar": share.toFixed(4), translate: `${start * 100}% 0` } as CSSProperties
                  }
                />
                {start > 0 ? (
                  <span
                    className="bar-gap absolute inset-0"
                    style={{ translate: `${start * 100}% 0` }}
                  />
                ) : null}
              </span>
            ))
          : null}
      </div>
      <ul className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
        {families.map((f) => {
          const fam = FAMILY_META[f.id]
          const active = fam.sensors.filter((s) => value(s) > 0)
          return (
            <li key={f.id}>
              <Link
                to={sensorsHref(fam.sensors)}
                className="-mx-2 flex flex-col rounded-md px-2 py-1.5 transition-colors hover:bg-surface-hover"
              >
                <span className={cn("flex items-center gap-1.5 text-xs font-medium", fam.text)}>
                  <span aria-hidden className={cn("size-2 rounded-full", fam.fill)} />
                  {fam.label}
                </span>
                <span className="mt-0.5 flex items-baseline gap-1.5">
                  <span className="text-md font-semibold text-fg">{formatNumber(f.value)}</span>
                  <span className="text-xs text-fg-subtle">
                    {total ? formatPercent(f.value / total) : "–"}
                  </span>
                </span>
                <span className="mt-0.5 truncate text-2xs text-fg-subtle">
                  {active.length
                    ? active.map((s) => SENSOR_META[s].label).join(" · ")
                    : t("sensorshare_no_traffic")}
                </span>
              </Link>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
