import { ChevronRight } from "lucide-react"
import { BarFill } from "@/components/bar-fill"
import { FindingCard } from "@/components/finding-card"
import { Meter } from "@/components/meter"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber, plural } from "@/lib/format"
import {
  wholePercent,
  type ReportEffect,
  type ReportEffectMethod,
  type ReportEffectResponse,
} from "@/lib/results"

const TIER_LABEL = {
  H: "random holdout",
  A: "same network (ASN)",
  B: "same provider size and country",
  C: "same provider size",
} as const

const UNMATCHED_LABEL = {
  no_control: "no similar unreported source",
  no_activity: "no activity in the week before",
  network_reported: "reported by the network",
} as const

/** Two neutral bars: never red or green, this is not a score. */
function ShareBar({ label, share }: { label: string; share: number }) {
  return (
    <li className="grid grid-cols-[minmax(8rem,12rem)_1fr_3rem] items-center gap-3">
      <span className="text-sm text-fg-muted">{label}</span>
      <div className="h-2 overflow-hidden rounded-full bg-surface-hover" aria-hidden>
        <BarFill ratio={share} className="bg-fg-muted" />
      </div>
      <span className="text-right text-sm text-fg tabular-nums">{wholePercent(share)}</span>
    </li>
  )
}

/** Progress below the minimum: a meter of pairs, then of discordant pairs. No percentage. */
function Progress({ effect }: { effect: ReportEffect }) {
  const pairsDone = effect.pairs >= effect.needed
  const value = pairsDone ? effect.discordant : effect.pairs
  const max = pairsDone ? effect.needed_discordant : effect.needed
  const text = `${formatNumber(value)} of ${formatNumber(max)} ${pairsDone ? "pairs that differ" : "pairs"}`
  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className="text-fg">
          {pairsDone ? "Pairs where only one source was seen" : "Comparable pairs"}
        </span>
        <span className="text-xs text-fg-muted tabular-nums">{text}</span>
      </div>
      <Meter value={value} max={max} label="Pairs measured so far" valueText={text} />
    </div>
  )
}

function Measured({ effect, label }: { effect: ReportEffect; label?: string }) {
  if (effect.seen_reported == null || effect.seen_control == null) return null
  return (
    <div className="space-y-2">
      {label ? <p className="text-xs font-medium text-fg-muted">{label}</p> : null}
      <ul className="space-y-2">
        <ShareBar label="Reported" share={effect.seen_reported} />
        <ShareBar label="Similar, not reported" share={effect.seen_control} />
      </ul>
      <p className="text-xs text-fg-muted">
        Still seen attacking in the week after day {effect.horizon}, {plural(effect.pairs, "pair")}.
        {effect.interval ? ` The difference is ${effect.interval} (95 % interval).` : null}
      </p>
    </div>
  )
}

function Method({ method, running }: { method: ReportEffectMethod; running: boolean }) {
  const tiers = (Object.keys(TIER_LABEL) as (keyof typeof TIER_LABEL)[]).filter(
    (t) => (method.tiers[t] ?? 0) > 0,
  )
  const unmatched = (Object.keys(UNMATCHED_LABEL) as (keyof typeof UNMATCHED_LABEL)[]).filter(
    (r) => (method.unmatched_reasons[r] ?? 0) > 0,
  )
  return (
    <details className="group/details">
      <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-sm text-xs text-fg-muted hover:text-fg [&::-webkit-details-marker]:hidden">
        <ChevronRight
          aria-hidden
          className="size-3.5 transition-transform duration-150 group-open/details:rotate-90"
        />
        How this is measured
      </summary>
      <div className="mt-2 space-y-2 pl-4 text-xs text-fg-muted">
        <p>
          Each reported attacking address is paired with one address that passed the same report
          rules in the same days but was not reported, with the same kind of activity, the same
          volume and the same last sighting in the week before. &ldquo;Still seen&rdquo; means any
          session on your sensors in the week from day 7 (or day 30) after the report. Only weeks
          when your sensors were up count.
        </p>
        <p>
          This compares two groups. A source that was not reported may differ in ways the pairing
          cannot see, so a difference does not show why it happened.
        </p>
        {!running ? (
          <p>Abuse reporting is off (ABUSE_REPORTS_ENABLED), so nothing is measured.</p>
        ) : null}
        <ul className="space-y-1">
          <li>
            Pairs made: {formatNumber(method.pairs_made)}
            {tiers.length > 0
              ? ` (${tiers.map((t) => `${formatNumber(method.tiers[t] ?? 0)} ${TIER_LABEL[t]}`).join(", ")})`
              : null}
          </li>
          <li>Waiting for their week to end: {formatNumber(method.waiting)}</li>
          <li>
            Left out: {formatNumber(method.not_observed)} sensors down,{" "}
            {formatNumber(method.control_reported)} similar source reported later,{" "}
            {formatNumber(method.network_reported)} reported by the network
          </li>
          <li>
            Reported sources with no comparable source: {formatNumber(method.unmatched)}
            {unmatched.length > 0
              ? ` (${unmatched.map((r) => `${formatNumber(method.unmatched_reasons[r] ?? 0)} ${UNMATCHED_LABEL[r]}`).join(", ")})`
              : null}
          </li>
          <li>
            Random holdout:{" "}
            {method.holdout_pct > 0
              ? `on, ${method.holdout_pct} % of new sources wait 21 days (${formatNumber(method.held_now)} waiting now)`
              : "off"}
          </li>
        </ul>
      </div>
    </details>
  )
}

/** "Do reports make a difference?" (M38): the verdict, then the evidence or the progress. */
export function EffectCard({
  week,
  month,
}: {
  week: ReportEffectResponse | undefined
  month?: ReportEffectResponse | undefined
}) {
  const e = week?.effect
  const enough = e !== undefined && e.verdict !== "not_enough_data"
  const monthEnough = month !== undefined && month.effect.verdict !== "not_enough_data"
  return (
    <FindingCard
      eyebrow="Do reports make a difference?"
      finding={e ? e.sentence : "Comparing reported sources with similar ones…"}
    >
      {!week || !e ? (
        <Skeleton className="h-24 w-full" />
      ) : (
        <div className="space-y-4">
          {enough ? (
            <Measured effect={e} label={monthEnough ? "After a week" : undefined} />
          ) : (
            <Progress effect={e} />
          )}
          {enough && monthEnough ? <Measured effect={month.effect} label="After a month" /> : null}
          <Method method={week.method} running={week.running} />
        </div>
      )}
    </FindingCard>
  )
}
