import { useMemo, useRef, useState } from "react"
import { Link } from "react-router"
import { SegmentedControl } from "@/components/segmented-control"
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { formatCompact, formatNumber } from "@/lib/format"
import { FAMILY_META, SENSOR_FAMILIES, SENSOR_META, SENSORS } from "@/lib/sensors"
import { bucketMs, hhmm, withWindow, type TimelineBucket } from "@/lib/story"
import { cn } from "@/lib/utils"

/** A label under every sixth hour: four or five on a day, never crowded. */
const LABEL_EVERY = 6

/** Stack by family (one hue each, as on the map) or by sensor (shades of the family hue). */
export type HourSplit = "family" | "sensor"

const SPLITS = [
  { value: "family", labelKey: tk("charts_hourly_families") },
  { value: "sensor", labelKey: tk("charts_hourly_sensors") },
] as const

interface Series {
  key: string
  label: string
  /** A CSS colour (a token variable). */
  fill: string
}

/** Stack order and colours, bottom to top, in registry order so a family stays one block. */
function seriesFor(split: HourSplit): Series[] {
  return split === "family"
    ? SENSOR_FAMILIES.map((f) => ({
        key: f,
        label: FAMILY_META[f].label,
        fill: FAMILY_META[f].cssVar,
      }))
    : SENSORS.map((s) => ({ key: s, label: SENSOR_META[s].label, fill: SENSOR_META[s].shadeVar }))
}

export interface Column {
  start: string
  end: string
  total: number
  /** Visits per series key (family or sensor). */
  values: Record<string, number>
  href: string
}

/** The smallest round step (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6 or 8 times a power of ten) >= `n`. */
export function niceMax(n: number): number {
  if (n <= 0) return 1
  const p = 10 ** Math.floor(Math.log10(n))
  for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= n) return m * p
  return 10 * p
}

/** Buckets as columns, keeping only the doors (sensors) in `sensors` when it is not empty. */
export function toColumns(
  timeline: readonly TimelineBucket[],
  split: HourSplit,
  sensors: readonly string[] = [],
): Column[] {
  const ms = bucketMs(timeline)
  const wanted = sensors.length ? new Set(sensors) : null
  return timeline.map((b) => {
    const values: Record<string, number> = {}
    let counted = 0
    for (const s of SENSORS) {
      const v = wanted && !wanted.has(s) ? 0 : (b.by_door[s] ?? 0)
      const key = split === "family" ? SENSOR_META[s].family : s
      values[key] = (values[key] ?? 0) + v
      counted += v
    }
    const end = new Date(Date.parse(b.start) + ms).toISOString()
    let href = withWindow("/attacks", b.start, end)
    if (sensors.length) href += `&sensor=${sensors.join(",")}`
    // Unfiltered, the bucket total wins: it also counts doors the registry does not know yet.
    const total = wanted ? counted : Math.max(b.sessions, counted)
    return { start: b.start, end, total, values, href }
  })
}

interface HourlyActivityProps {
  timeline: readonly TimelineBucket[]
  /** The page's `?sensor=` filter: only these doors are counted. */
  sensors?: readonly string[]
  /** Size of the plot; by default it fills what its parent leaves (a flex column). */
  plotClassName?: string
  className?: string
}

/**
 * The hour strip: visits per hour over the last day, one column per hour, stacked by sensor
 * family (the hues of the map arcs) or, with the switch, by sensor. Hairline grid at zero, half
 * and the top, round values, a time label every six hours. Hover or focus a column for its
 * numbers; click it, or press Enter, to open those visits. The arrow keys move between hours (the
 * chart is one tab stop).
 */
export function HourlyActivity({
  timeline,
  sensors = [],
  plotClassName,
  className,
}: HourlyActivityProps) {
  const [split, setSplit] = useState<HourSplit>("family")
  const columns = useMemo(() => toColumns(timeline, split, sensors), [timeline, split, sensors])
  const max = niceMax(Math.max(0, ...columns.map((c) => c.total)))
  const busiest = columns.reduce(
    (best, c, i) => (c.total >= (columns[best]?.total ?? -1) ? i : best),
    0,
  )
  const [active, setActive] = useState<number | null>(null)
  const links = useRef<(HTMLAnchorElement | null)[]>([])
  // Only the series that saw something: a key of twelve sensors with eight zeros says nothing.
  const series = useMemo(
    () => seriesFor(split).filter((s) => columns.some((c) => (c.values[s.key] ?? 0) > 0)),
    [split, columns],
  )
  const n = columns.length
  const focusable = active ?? busiest

  const move = (i: number) => {
    const next = Math.min(n - 1, Math.max(0, i))
    setActive(next)
    links.current[next]?.focus()
  }

  const shownCol = active !== null ? columns[active] : undefined

  return (
    <figure className={cn("flex min-h-0 flex-col", className)}>
      <figcaption className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <span className="flex items-center gap-3">
          <span className="type-eyebrow text-fg-muted">{t("charts_hourly_title")}</span>
          <SegmentedControl
            label={t("charts_hourly_stack_by")}
            value={split}
            onChange={setSplit}
            options={SPLITS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
          />
        </span>
        {/* The key: in family mode, the same swatches as the map's stats strip. */}
        <ul aria-label={t("charts_hourly_key")} className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {series.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5 text-xs text-fg-muted">
              <span aria-hidden className="size-2 rounded-xs" style={{ backgroundColor: s.fill }} />
              {s.label}
            </li>
          ))}
        </ul>
      </figcaption>

      <div className={cn("relative mt-3 min-h-16 flex-1 pl-9", plotClassName)}>
        {/* Grid: zero, half and the top, hairlines behind the columns. */}
        {[1, 0.5, 0].map((frac) => (
          <div
            key={frac}
            aria-hidden
            className="pointer-events-none absolute inset-x-0 flex translate-y-1/2 items-center"
            style={{ bottom: `${frac * 100}%` }}
          >
            <span className="w-9 pr-2 text-right text-2xs leading-none text-fg-subtle tabular-nums">
              {frac === 0 ? "0" : formatCompact(max * frac)}
            </span>
            <span className={cn("h-px flex-1", frac === 0 ? "bg-border-strong" : "bg-border")} />
          </div>
        ))}

        <div
          role="group"
          aria-label={t("charts_hourly_aria")}
          className="relative flex h-full items-stretch"
          onPointerLeave={() => setActive(null)}
        >
          {columns.map((c, i) => (
            <Link
              key={c.start}
              ref={(el) => {
                links.current[i] = el
              }}
              to={c.href}
              tabIndex={i === focusable ? 0 : -1}
              aria-label={t("charts_hourly_column_aria", {
                from: hhmm(c.start),
                to: hhmm(c.end),
                count: c.total,
              })}
              onPointerEnter={() => setActive(i)}
              onFocus={() => setActive(i)}
              onKeyDown={(e) => {
                if (e.key === "ArrowRight") move(i + 1)
                else if (e.key === "ArrowLeft") move(i - 1)
                else if (e.key === "Home") move(0)
                else if (e.key === "End") move(n - 1)
                else return
                e.preventDefault()
              }}
              className={cn(
                "relative flex h-full min-w-0 flex-1 items-end justify-center rounded-xs transition-colors duration-150 focus-visible:outline-offset-0",
                active === i && "bg-surface-hover/70",
              )}
            >
              {/* Segments bottom to top, a 2 px gap between them, a 4 px round top only. */}
              <span
                aria-hidden
                className="flex w-[min(24px,64%)] flex-col-reverse gap-0.5 overflow-hidden rounded-t-xs"
                style={{ height: `${(c.total / max) * 100}%` }}
              >
                {series.map((s) =>
                  (c.values[s.key] ?? 0) > 0 ? (
                    <span
                      key={s.key}
                      className="min-h-px"
                      style={{ flex: `${c.values[s.key]} 1 0`, backgroundColor: s.fill }}
                    />
                  ) : null,
                )}
              </span>
            </Link>
          ))}
        </div>

        {/* The readout, beside the column and anchored to the baseline, so it stays in the card. */}
        {shownCol && active !== null ? (
          <div
            aria-hidden
            className="pointer-events-none absolute bottom-0 z-10 w-48 rounded-md border bg-surface-raised p-2.5 text-xs shadow-md"
            style={
              active < n / 2
                ? { left: `calc(2.25rem + (100% - 2.25rem) * ${(active + 1) / n} + 6px)` }
                : { right: `calc((100% - 2.25rem) * ${(n - active) / n} + 6px)` }
            }
          >
            <p className="font-medium text-fg">
              {t("charts_hourly_range", { from: hhmm(shownCol.start), to: hhmm(shownCol.end) })}
            </p>
            <p className="mt-0.5 text-fg-muted">
              {tNodes(
                "charts_hourly_visits",
                { count: shownCol.total },
                {
                  total: (
                    <span className="font-medium text-fg tabular-nums">
                      {formatNumber(shownCol.total)}
                    </span>
                  ),
                },
              )}
            </p>
            <ul className="mt-1.5 space-y-0.5">
              {series
                .filter((s) => (shownCol.values[s.key] ?? 0) > 0)
                .map((s) => (
                  <li key={s.key} className="flex items-center gap-1.5 text-fg-muted">
                    <span
                      aria-hidden
                      className="size-2 rounded-xs"
                      style={{ backgroundColor: s.fill }}
                    />
                    <span className="min-w-0 flex-1 truncate">{s.label}</span>
                    <span className="text-fg tabular-nums">
                      {formatNumber(shownCol.values[s.key] ?? 0)}
                    </span>
                  </li>
                ))}
            </ul>
          </div>
        ) : null}
      </div>

      {/* Time labels, centred under their hour. */}
      <div aria-hidden className="relative mt-1.5 ml-9 h-4">
        {columns.map((c, i) =>
          i % LABEL_EVERY === 0 ? (
            <span
              key={c.start}
              className="absolute top-0 -translate-x-1/2 text-2xs text-fg-subtle tabular-nums"
              style={{ left: `${((i + 0.5) / n) * 100}%` }}
            >
              {hhmm(c.start)}
            </span>
          ) : null,
        )}
      </div>

      {/* A table's height ignores `height: 1px`, so the visually hidden box wraps it. */}
      <div className="sr-only">
        <table>
          <caption>{t("charts_hourly_aria")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("charts_hourly_col_hour")}</th>
              <th scope="col">{t("charts_hourly_col_all")}</th>
              {series.map((s) => (
                <th key={s.key} scope="col">
                  {s.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {columns.map((c) => (
              <tr key={c.start}>
                <th scope="row">
                  {t("charts_hourly_range", { from: hhmm(c.start), to: hhmm(c.end) })}
                </th>
                <td>{formatNumber(c.total)}</td>
                {series.map((s) => (
                  <td key={s.key}>{formatNumber(c.values[s.key] ?? 0)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </figure>
  )
}
