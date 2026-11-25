import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis } from "recharts"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { intlLocale, t } from "@/i18n"
import { fillDays, type DayPoint } from "@/lib/chart-time"
import { formatNumber } from "@/lib/format"

const dayFormats = new Map<string, Intl.DateTimeFormat>()

/** "Nov 12" in the active language (days are UTC dates, so the zone is fixed). */
const label = (day: string) => {
  const locale = intlLocale()
  let f = dayFormats.get(locale)
  if (!f) {
    f = new Intl.DateTimeFormat(locale, { month: "short", day: "numeric", timeZone: "UTC" })
    dayFormats.set(locale, f)
  }
  return f.format(new Date(`${day}T00:00:00Z`))
}

const capitalise = (word: string) => word.charAt(0).toLocaleUpperCase(intlLocale()) + word.slice(1)

function Tip({
  active,
  payload,
  unit,
}: {
  active?: boolean
  payload?: readonly { payload?: DayPoint }[]
  unit: string
}) {
  const p = payload?.[0]?.payload
  if (!active || !p) return null
  return (
    <div className="rounded-md border bg-surface-raised px-3 py-2 text-xs shadow-md">
      <span className="text-fg-muted">{label(p.day)}</span>{" "}
      <span className="font-medium text-fg tabular-nums">
        {formatNumber(p.events)} {unit}
      </span>
    </div>
  )
}

/** One neutral bar per day (the attacker may span several sensors, so no sensor hue). */
export function DayBars({
  points,
  className,
  unit,
  days = 30,
}: {
  points: readonly DayPoint[]
  className?: string
  /** What a bar counts, for the tooltip and the text alternative ("sessions"). Default: events. */
  unit?: string
  /** Number of days drawn, ending today (UTC). */
  days?: number
}) {
  const reduced = useReducedMotion()
  const data = fillDays(points, days)
  const noun = unit ?? t("charts_unit_events")
  return (
    <div className={className}>
      <div
        role="img"
        aria-label={t("charts_day_bars_aria", { unit: capitalise(noun), count: data.length })}
        className="h-32 w-full"
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            margin={{ top: 4, right: 0, bottom: 0, left: 0 }}
            barCategoryGap={2}
          >
            <XAxis
              dataKey="day"
              tickFormatter={label}
              tick={{ fill: "var(--fg-subtle)", fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: "var(--border-strong)" }}
              interval="preserveStartEnd"
              minTickGap={48}
            />
            <Tooltip
              content={<Tip unit={noun} />}
              cursor={{ fill: "var(--surface-hover)" }}
              isAnimationActive={false}
            />
            <Bar
              dataKey="events"
              fill="var(--fg-muted)"
              radius={[2, 2, 0, 0]}
              isAnimationActive={!reduced}
              animationDuration={400}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only">
        <caption>{t("charts_day_bars_caption", { unit: capitalise(noun) })}</caption>
        <thead>
          <tr>
            <th scope="col">{t("charts_day_bars_day")}</th>
            <th scope="col">{capitalise(noun)}</th>
          </tr>
        </thead>
        <tbody>
          {data.map((p) => (
            <tr key={p.day}>
              <th scope="row">{label(p.day)}</th>
              <td>{p.events}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
