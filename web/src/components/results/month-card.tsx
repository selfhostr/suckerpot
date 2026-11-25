import { useQuery } from "@tanstack/react-query"
import { FindingCard } from "@/components/finding-card"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber } from "@/lib/format"
import { resultKeys, resultsApi } from "@/lib/results"
import { describeSentOverTime, monthComparison } from "@/lib/results-sentences"
import { t } from "@/i18n"

/**
 * "This month against last month": one figure for how many reports went out, in place of a bar
 * per week. The comparison is words and numbers; the bars only said it less clearly.
 */
export function MonthCard() {
  const q = useQuery({
    queryKey: resultKeys.timeline("month"),
    queryFn: () => resultsApi.timeline("month"),
  })
  const points = q.data?.points ?? []
  const now = new Date()
  const m = monthComparison(points, now)
  return (
    <FindingCard
      eyebrow={t("results_month_eyebrow")}
      finding={q.data ? describeSentOverTime(points, now) : t("results_month_loading")}
    >
      {q.isPending ? (
        <Skeleton className="h-16 w-full" />
      ) : (
        <dl className="flex items-end gap-x-8 gap-y-2">
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">
              {m.running ? t("results_month_so_far", { month: m.month }) : m.month}
            </dt>
            <dd className="type-kpi text-fg tabular-nums">{formatNumber(m.sent)}</dd>
          </div>
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">{m.previousMonth}</dt>
            <dd className="text-xl font-medium text-fg-muted tabular-nums">
              {formatNumber(m.previous)}
            </dd>
          </div>
        </dl>
      )}
    </FindingCard>
  )
}
