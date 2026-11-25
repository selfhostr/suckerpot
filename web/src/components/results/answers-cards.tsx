import { FindingCard } from "@/components/finding-card"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber, formatPercent } from "@/lib/format"
import { outcomeIsWarning } from "@/lib/replies"
import { ANSWER_ROWS, type OutcomesResponse } from "@/lib/results"
import { describeAnswers, describeDelay, longDelay } from "@/lib/results-sentences"
import { OutcomeBadge } from "./badges"

/** "Did anyone answer?": one bar per outcome. Rejected and bounced take the warning tone. */
export function AnswersCard({ data }: { data: OutcomesResponse | undefined }) {
  const totals = data?.totals
  const max = Math.max(1, ...ANSWER_ROWS.map((o) => totals?.by_outcome[o] ?? 0))
  return (
    <FindingCard
      eyebrow="Did anyone answer?"
      finding={
        data ? describeAnswers(data.totals, data.groups) : "Reading the answers to your reports…"
      }
      detail={
        totals && totals.eligible > 0
          ? `${formatNumber(totals.answered)} of ${formatNumber(totals.eligible)} reports sent at least 3 days ago got an answer (${formatPercent(
              totals.answered / totals.eligible,
            )}). Younger reports are not counted yet.`
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
                <div className="h-2 rounded-full bg-surface-hover" aria-hidden>
                  <div
                    className={
                      outcomeIsWarning(o)
                        ? "h-full rounded-full bg-sev-warning"
                        : "h-full rounded-full bg-fg-muted"
                    }
                    style={{ width: `${(n / max) * 100}%` }}
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

function Figure({ label, seconds }: { label: string; seconds: number | null }) {
  return (
    <div className="flex items-baseline justify-between gap-3 rounded-lg border bg-bg p-4 sm:block sm:space-y-1">
      <p className="type-eyebrow text-fg-muted sm:min-h-[2lh]">{label}</p>
      <p className="type-kpi text-fg tabular-nums">
        {seconds == null ? "none yet" : longDelay(seconds)}
      </p>
    </div>
  )
}

/** "How fast they answer": the median and the slowest-tenth delay to the first answer. */
export function DelayCard({ data }: { data: OutcomesResponse | undefined }) {
  const t = data?.totals
  return (
    <FindingCard
      eyebrow="How fast they answer"
      finding={data ? describeDelay(data.totals) : "Measuring how long answers take…"}
      detail="Measured from the time you sent the report to the first answer."
    >
      {!t ? (
        <Skeleton className="h-24 w-full" />
      ) : (
        <div className="grid grid-cols-1 items-start gap-3 sm:grid-cols-3">
          <Figure label="Half answered within" seconds={t.first_reply_p50_s} />
          <Figure label="Nine in ten within" seconds={t.first_reply_p90_s} />
          <Figure label="Median time to resolve" seconds={t.resolved_p50_s} />
        </div>
      )}
    </FindingCard>
  )
}
