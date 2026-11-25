import { useInfiniteQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import { ArrowRight } from "lucide-react"
import { useMemo } from "react"
import { Link } from "react-router"
import { FindingCard } from "@/components/finding-card"
import { SkeletonText } from "@/components/skeletons"
import { alertKeys, alertsApi, reportsFinding, weekLabel } from "@/lib/alerts"
import { formatNumber } from "@/lib/format"

/** The weekly reports, newest first. Each opens the report page. */
export function ReportsCard() {
  const q = useInfiniteQuery({
    queryKey: alertKeys.reports,
    queryFn: ({ pageParam }) => alertsApi.reports(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const items = useMemo(() => (q.data?.pages ?? []).flatMap((p) => p.items), [q.data])
  return (
    <FindingCard
      eyebrow="Weekly reports"
      finding={q.isPending ? "Checking the weekly reports…" : reportsFinding(items)}
      detail="One page every Monday morning: what happened, what changed, what to do. Print it to PDF to share with your team."
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {q.isPending ? (
        <div className="px-4 sm:px-5">
          <SkeletonText lines={3} className="py-1" />
        </div>
      ) : items.length === 0 ? (
        <p className="border-t px-4 py-6 text-sm text-fg-muted sm:px-5">
          The first report appears here after the next Monday morning.
        </p>
      ) : (
        <>
          <ul aria-label="Weekly reports" className="divide-y border-t">
            {items.map((r) => (
              <li key={r.week_start}>
                <Link
                  to={`/reports/${r.week_start}`}
                  className="group grid grid-cols-[1fr_auto] items-center gap-x-3 px-4 py-3 transition-colors hover:bg-surface-hover focus-visible:bg-surface-hover focus-visible:outline-none sm:px-5"
                >
                  <span className="min-w-0 space-y-0.5">
                    <span className="block text-sm font-medium text-fg">
                      Week of {weekLabel(r.week_start, r.week_end)}
                    </span>
                    <span className="block text-xs text-fg-muted">
                      {formatNumber(r.sessions)} sessions from {formatNumber(r.sources)} addresses
                      {r.malware > 0 ? ` · ${formatNumber(r.malware)} dropped malware` : ""}
                      {r.change_pct !== null && Math.abs(r.change_pct) >= 5
                        ? ` · ${r.change_pct > 0 ? "up" : "down"} ${Math.abs(r.change_pct)}% on the week before`
                        : ""}
                    </span>
                  </span>
                  <ArrowRight
                    aria-hidden
                    className="size-4 text-fg-subtle transition-transform group-hover:translate-x-0.5"
                  />
                </Link>
              </li>
            ))}
          </ul>
          <LoadMore
            hasNextPage={q.hasNextPage}
            isFetchingNextPage={q.isFetchingNextPage}
            fetchNextPage={q.fetchNextPage}
            label="Show older reports"
            className="border-t"
          />
        </>
      )}
    </FindingCard>
  )
}
