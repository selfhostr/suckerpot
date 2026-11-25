import { ExternalLink } from "lucide-react"
import { useMemo } from "react"
import { Link } from "react-router"
import { STAGE_ICON } from "@/components/campaigns/stage-icons"
import { Sparkline } from "@/components/sparkline"
import { formatDay, STAGE_META, type Matrix } from "@/lib/campaigns"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

interface TechniqueTableProps {
  matrix: Matrix
  /** Extra query string for the row links, e.g. "&sensor=ssh". */
  linkSuffix?: string
  className?: string
}

const GRID =
  "md:grid-cols-[minmax(0,1fr)_9rem_8rem_5.5rem_5.5rem] md:gap-x-4 lg:grid-cols-[minmax(0,1fr)_10rem_10rem_6rem_6rem]"

/**
 * Techniques, busiest first: the stage, a sparkline of the days, the day it first showed up in
 * the window and how many sessions used it. A row opens those sessions. Colourless: a count is
 * a number, and the order carries the ranking.
 */
export function TechniqueTable({ matrix, linkSuffix = "", className }: TechniqueTableProps) {
  const rows = useMemo(
    () => [...matrix.rows].sort((a, b) => b.total_sessions - a.total_sessions),
    [matrix],
  )
  const days = matrix.days.length
  return (
    <div className={className}>
      <div className={cn("hidden border-b pb-2 type-column text-fg-subtle md:grid", GRID)}>
        <span>Technique</span>
        <span>Stage</span>
        <span>Last {days} days</span>
        <span>First seen</span>
        <span className="text-right">Sessions</span>
      </div>
      <ul aria-label="Techniques, most sessions first">
        {rows.map((r, i) => {
          const Icon = STAGE_ICON[r.stage]
          const firstDay = matrix.days[r.counts.findIndex((n) => n > 0)]
          return (
            <li
              key={r.id}
              className={cn(
                "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 py-2.5",
                GRID,
                i > 0 && "border-t",
              )}
            >
              <div className="flex min-w-0 items-baseline gap-2">
                <Link
                  to={`/attacks?technique=${encodeURIComponent(r.id)}${linkSuffix}`}
                  title={`${r.name}. Show the sessions that used it.`}
                  className="min-w-0 truncate rounded-sm text-sm text-fg hover:underline hover:underline-offset-4"
                >
                  <span className="mr-2 font-mono text-2xs text-fg-subtle">{r.id}</span>
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
              </div>
              <span className="text-right text-sm text-fg tabular-nums md:order-last">
                {formatNumber(r.total_sessions)}
              </span>
              <span className="col-span-2 inline-flex items-center gap-1.5 text-xs text-fg-muted md:col-span-1">
                <Icon aria-hidden className="size-3.5 shrink-0" strokeWidth={2} />
                {STAGE_META[r.stage].label}
              </span>
              <span className="hidden md:block">
                <Sparkline
                  values={r.counts}
                  color="var(--fg-muted)"
                  label={`${r.id} sessions per day`}
                  className="h-6"
                />
              </span>
              <span className="hidden text-xs text-fg-muted tabular-nums md:block">
                {firstDay ? formatDay(firstDay) : "None"}
              </span>
            </li>
          )
        })}
      </ul>
      <p className="mt-3 text-2xs text-fg-subtle">
        Days are in UTC. Techniques are labelled by MITRE ATT&CK®.
      </p>
    </div>
  )
}
