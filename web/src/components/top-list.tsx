import { Link } from "react-router"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber, formatPercent } from "@/lib/format"
import { cn } from "@/lib/utils"

export interface TopListItem {
  key: string
  /** What the row says (flag + name, or a mono credential). */
  label: React.ReactNode
  count: number
  /** 0..1, drawn as the bar and printed as a number. */
  share: number
  /** Filtered view this row opens. */
  href?: string
  /** Plain-text name for screen readers. */
  name: string
}

interface TopListProps {
  items: readonly TopListItem[]
  loading?: boolean
  rows?: number
  empty?: string
  /**
   * What a full bar means. `max` (the default) stretches the bars against the busiest row, so
   * small shares still show their differences. `total` draws each share as it is printed: use it
   * when the rows can all be tied (every password of a spray tried once), where `max` would draw
   * a row of full bars next to "<1%".
   */
  scale?: "max" | "total"
  className?: string
}

/** The printed share: a share that is not zero never reads as "0%". */
function shareLabel(share: number): string {
  return share > 0 && share < 0.005 ? "<1%" : formatPercent(share)
}

/**
 * A ranked list with share bars. The bar is decoration: the count and the
 * percentage are always printed, so no meaning rests on the bar or its colour.
 */
export function TopList({
  items,
  loading,
  rows = 5,
  empty = "Nothing yet.",
  scale = "max",
  className,
}: TopListProps) {
  if (loading) {
    return (
      <div role="status" aria-label="Loading" className={cn("space-y-3", className)}>
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    )
  }
  if (items.length === 0)
    return <p className={cn("py-4 text-sm text-fg-muted", className)}>{empty}</p>
  const max = scale === "total" ? 1 : Math.max(...items.map((i) => i.share), 0.0001)
  return (
    <ol className={cn("space-y-1", className)}>
      {items.map((item, idx) => {
        const row = (
          <>
            <span
              aria-hidden
              className="w-4 shrink-0 text-right text-2xs text-fg-subtle tabular-nums"
            >
              {idx + 1}
            </span>
            <span className="min-w-0 flex-1 truncate text-sm text-fg">{item.label}</span>
            <span className="text-sm text-fg tabular-nums">{formatNumber(item.count)}</span>
            <span className="w-10 text-right text-xs text-fg-muted tabular-nums">
              {shareLabel(item.share)}
            </span>
            <span
              aria-hidden
              className="absolute inset-x-2 bottom-0.5 h-0.5 rounded-full bg-border-strong/30"
            >
              <span
                className="block h-full rounded-full bg-fg-subtle/60 transition-[width] duration-300"
                style={{ width: `${(item.share / max) * 100}%` }}
              />
            </span>
          </>
        )
        const cls =
          "relative flex items-center gap-3 rounded-md px-2 pt-1.5 pb-2.5 transition-colors duration-150"
        return (
          <li key={item.key}>
            {item.href ? (
              <Link
                to={item.href}
                aria-label={`${item.name}: ${formatNumber(item.count)}, ${shareLabel(item.share)}. Open filtered view`}
                className={cn(cls, "hover:bg-surface-hover")}
              >
                {row}
              </Link>
            ) : (
              <div className={cls}>{row}</div>
            )}
          </li>
        )
      })}
    </ol>
  )
}
