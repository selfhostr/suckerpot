import { Link } from "react-router"
import { t } from "@/i18n"
import { Sparkline } from "@/components/sparkline"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber } from "@/lib/format"
import { isSevereTag, tagChange, tagTotals, type TagPoint } from "@/lib/trends"
import { cn } from "@/lib/utils"

const GRID = "grid-cols-[minmax(0,1fr)_5rem_5rem] sm:grid-cols-[minmax(0,1fr)_9rem_5.5rem_5.5rem]"
const MAX_ROWS = 10

/** "+120%", "-45%", "New" (nothing in the first half) or "No change". Never coloured. */
export function describeChange(first: number, second: number): string {
  if (first === 0 && second === 0) return t("trends_change_none")
  if (first === 0) return t("trends_change_new")
  const pct = Math.round(((second - first) / first) * 100)
  if (pct === 0) return t("trends_change_same")
  return t("trends_change_pct", { direction: pct > 0 ? "up" : "down", value: Math.abs(pct) })
}

interface TagTableProps {
  points: readonly TagPoint[] | undefined
  loading?: boolean
  className?: string
}

/**
 * Tags over the period as a table: how many events, a sparkline of the days, and the change of
 * the second half against the first. The leading payload tag is the only red mark, as in the
 * old chart; every other line is neutral.
 */
export function TagTable({ points, loading, className }: TagTableProps) {
  if (loading) return <Skeleton className={cn("h-56 w-full", className)} />
  const pts = points ?? []
  const totals = tagTotals(pts)
  if (totals.length === 0)
    return (
      <p className="py-8 text-center text-sm text-fg-muted">{t("trends_tags_empty")}</p>
    )
  // "other" always last.
  const named = totals.filter(([name]) => name !== "other").slice(0, MAX_ROWS)
  const other = totals.find(([name]) => name === "other")
  const rows = other ? [...named, other] : named
  const highlight = named.find(([name]) => isSevereTag(name))?.[0] ?? null
  return (
    <div className={cn("-mx-1", className)}>
      <div
        className={cn(
          "grid gap-x-4 border-b px-1 pb-2 type-column text-fg-subtle",
          GRID,
        )}
      >
        <span>{t("filters_tag_label")}</span>
        <span className="hidden sm:block">{t("trends_tags_col_per_day")}</span>
        <span className="text-right">{t("trends_tags_col_events")}</span>
        <span className="text-right" title={t("trends_tags_col_change_title")}>
          {t("trends_tags_col_change")}
        </span>
      </div>
      <ul aria-label={t("trends_tags_list_label")}>
        {rows.map(([tag, total], i) => {
          const { first, second } = tagChange(pts, tag)
          const severe = isSevereTag(tag)
          const body = (
            <>
              <span className="flex min-w-0 items-center gap-2">
                <span
                  aria-hidden
                  className={cn(
                    "size-2.5 shrink-0 rounded-[2px] bg-fg-subtle",
                    severe && "rotate-45 bg-transparent ring-1 ring-sev-severe",
                    tag === highlight && "bg-sev-severe ring-0",
                  )}
                />
                <span className="truncate font-mono text-xs text-fg">{tag}</span>
                {severe ? <span className="sr-only">{t("tag_level", { level: "severe" })}</span> : null}
              </span>
              <span className="hidden sm:block">
                <Sparkline
                  values={pts.map((p) => p.tags[tag] ?? 0)}
                  color={tag === highlight ? "var(--sev-severe)" : "var(--fg-muted)"}
                  label={t("trends_tag_per_day", { tag })}
                  className="h-6"
                />
              </span>
              <span className="text-right text-sm text-fg tabular-nums">{formatNumber(total)}</span>
              <span className="text-right text-xs text-fg-muted tabular-nums">
                {describeChange(first, second)}
              </span>
            </>
          )
          const cls = cn("grid items-center gap-x-4 px-1 py-2", GRID)
          return (
            <li key={tag} className={cn(i > 0 && "border-t")}>
              {tag === "other" ? (
                <div className={cls}>{body}</div>
              ) : (
                <Link
                  to={`/attacks?tag=${encodeURIComponent(tag)}`}
                  className={cn(cls, "rounded-sm transition-colors hover:bg-surface-hover/50")}
                >
                  {body}
                </Link>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
