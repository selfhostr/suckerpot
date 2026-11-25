import { FindingCard } from "@/components/finding-card"
import { BarFill } from "@/components/bar-fill"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber, formatPercent } from "@/lib/format"
import { outcomeIsWarning } from "@/lib/replies"
import { ANSWER_ROWS, type OutcomesResponse } from "@/lib/results"
import { describeAnswers } from "@/lib/results-sentences"
import { OutcomeBadge } from "./badges"
import { t } from "@/i18n"

/** "Did anyone answer?": one bar per outcome. Rejected and bounced take the warning tone. */
export function AnswersCard({ data }: { data: OutcomesResponse | undefined }) {
  const totals = data?.totals
  const max = Math.max(1, ...ANSWER_ROWS.map((o) => totals?.by_outcome[o] ?? 0))
  return (
    <FindingCard
      eyebrow={t("results_answers_eyebrow")}
      finding={data ? describeAnswers(data.totals, data.groups) : t("results_answers_loading")}
      detail={
        totals && totals.eligible > 0
          ? t("results_answers_detail", {
              answered: totals.answered,
              count: totals.eligible,
              percent: formatPercent(totals.answered / totals.eligible),
            })
          : undefined
      }
    >
      {!totals ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <ul className="space-y-2">
          {ANSWER_ROWS.map((o) => {
            const n = totals.by_outcome[o] ?? 0
            return (
              <li
                key={o}
                className="grid grid-cols-[minmax(8.5rem,11rem)_1fr_2.5rem] items-center gap-3"
              >
                <OutcomeBadge outcome={o} noAnswer />
                <div className="h-2 overflow-hidden rounded-full bg-surface-hover" aria-hidden>
                  <BarFill
                    ratio={n / max}
                    className={outcomeIsWarning(o) ? "bg-sev-warning" : "bg-fg-muted"}
                  />
                </div>
                <span className="text-right text-sm text-fg tabular-nums">{formatNumber(n)}</span>
              </li>
            )
          })}
        </ul>
      )}
    </FindingCard>
  )
}
