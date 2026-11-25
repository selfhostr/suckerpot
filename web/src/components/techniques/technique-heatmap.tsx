import { ExternalLink } from "lucide-react"
import { useMemo, useState } from "react"
import { Link } from "react-router"
import { STAGE_ICON } from "@/components/campaigns/stage-icons"
import { formatDay, groupByStage, heatColour, heatStep, type Matrix } from "@/lib/campaigns"
import { formatNumber, plural } from "@/lib/format"
import { cn } from "@/lib/utils"

interface TechniqueHeatmapProps {
  matrix: Matrix
  /** Extra query string for the row links, e.g. "&sensor=ssh". */
  linkSuffix?: string
  className?: string
}

const ROW_GRID =
  "md:grid-cols-[15rem_minmax(0,1fr)_4.5rem] lg:grid-cols-[19rem_minmax(0,1fr)_4.5rem] md:gap-x-4"

/**
 * Techniques (rows, grouped by stage) against days (columns). The darkness of a cell is a
 * neutral scale; the exact count is in the readout (hover, tap or focus a row) and in the table
 * that screen readers get. A row opens the sessions that used the technique.
 */
export function TechniqueHeatmap({ matrix, linkSuffix = "", className }: TechniqueHeatmapProps) {
  const groups = useMemo(() => groupByStage(matrix), [matrix])
  const max = useMemo(() => Math.max(1, ...matrix.rows.flatMap((r) => r.counts)), [matrix])
  const [active, setActive] = useState<{ id: string; day: number } | null>(null)
  const days = matrix.days.length
  const columns = { gridTemplateColumns: `repeat(${days}, minmax(0, 1fr))` }

  const row = active ? matrix.rows.find((r) => r.id === active.id) : undefined
  const readout =
    row && active
      ? `${row.id} ${row.name} · ${formatDay(matrix.days[active.day] ?? "")}: ${plural(
          row.counts[active.day] ?? 0,
          "session",
        )}`
      : "Hover or tap a cell for the exact count."
  const first = matrix.days[0]
  const last = matrix.days.at(-1)

  return (
    <div className={className}>
      <div className={cn("hidden items-end pb-2 type-column text-fg-subtle md:grid", ROW_GRID)}>
        <span>Technique</span>
        <span className="flex justify-between normal-case">
          <span>{first ? formatDay(first) : ""}</span>
          <span>{last ? formatDay(last) : ""}</span>
        </span>
        <span className="text-right">Sessions</span>
      </div>

      <div
        role="img"
        aria-label={`Heatmap of sessions per ATT&CK technique and day over the last ${days} days. The same numbers are in the table below.`}
        className="space-y-5"
        onMouseLeave={() => setActive(null)}
      >
        {groups.map((g) => {
          const Icon = STAGE_ICON[g.stage]
          return (
            <section key={g.stage} aria-label={g.label}>
              <h4 className="mb-1.5 flex items-center justify-between gap-3 border-b pb-1.5">
                <span className="inline-flex items-center gap-2 text-sm font-medium text-fg">
                  <Icon aria-hidden className="size-3.5 text-fg-muted" strokeWidth={2} />
                  {g.label}
                </span>
                <span className="text-xs text-fg-subtle tabular-nums">
                  {plural(g.rows.length, "technique")} · {plural(g.total, "session")}
                </span>
              </h4>
              <ul>
                {g.rows.map((r) => (
                  <li
                    key={r.id}
                    className={cn("grid grid-cols-1 items-center gap-y-1 py-1.5 md:py-1", ROW_GRID)}
                    onFocusCapture={() => setActive({ id: r.id, day: days - 1 })}
                  >
                    <div className="flex min-w-0 items-baseline justify-between gap-2 md:justify-start">
                      <Link
                        to={`/attacks?technique=${encodeURIComponent(r.id)}${linkSuffix}`}
                        title={`${r.name}. Show the sessions that used it.`}
                        className="min-w-0 truncate rounded-sm text-sm text-fg hover:underline hover:underline-offset-4"
                      >
                        <span className="mr-2 font-mono text-2xs text-fg-subtle">{r.id}</span>{" "}
                        {r.name}
                      </Link>
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="hidden size-5 shrink-0 items-center justify-center rounded-sm text-fg-subtle hover:text-fg md:inline-flex"
                        aria-label={`Read about ${r.id} on attack.mitre.org (opens in a new tab)`}
                      >
                        <ExternalLink aria-hidden className="size-3" />
                      </a>
                      <span className="text-xs text-fg-muted tabular-nums md:hidden">
                        {formatNumber(r.total_sessions)}
                      </span>
                    </div>
                    <div className="grid gap-[2px]" style={columns}>
                      {r.counts.map((n, d) => {
                        const on = active?.id === r.id && active.day === d
                        return (
                          <span
                            key={matrix.days[d]}
                            title={`${formatDay(matrix.days[d] ?? "")}: ${formatNumber(n)}`}
                            onMouseEnter={() => setActive({ id: r.id, day: d })}
                            onClick={() => setActive({ id: r.id, day: d })}
                            className={cn(
                              "h-5 rounded-[3px] transition-[box-shadow] duration-150",
                              on && "ring-2 ring-fg ring-offset-1 ring-offset-surface",
                            )}
                            style={{ background: heatColour(heatStep(n, max)) }}
                          />
                        )
                      })}
                    </div>
                    <span className="hidden text-right text-sm text-fg tabular-nums md:block">
                      {formatNumber(r.total_sessions)}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 text-xs text-fg-muted">
        <p aria-live="polite" className="min-h-4 tabular-nums">
          {readout}
        </p>
        <div className="flex items-center gap-2">
          <span>Fewer</span>
          <span aria-hidden className="flex gap-[2px]">
            {[0, 1, 2, 3, 4, 5].map((s) => (
              <span
                key={s}
                className="size-3 rounded-[3px]"
                style={{ background: heatColour(s) }}
              />
            ))}
          </span>
          <span>More</span>
        </div>
      </div>
      <p className="mt-1 text-2xs text-fg-subtle">
        Days are in UTC, oldest on the left. Techniques are labelled by MITRE ATT&CK®.
      </p>

      <div className="sr-only">
        <table>
          <caption>Sessions per technique and day, in UTC</caption>
          <thead>
            <tr>
              <th scope="col">Technique</th>
              {matrix.days.map((d) => (
                <th key={d} scope="col">
                  {formatDay(d)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.rows.map((r) => (
              <tr key={r.id}>
                <th scope="row">
                  {r.id} {r.name}
                </th>
                {r.counts.map((n, i) => (
                  <td key={matrix.days[i]}>{n}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
