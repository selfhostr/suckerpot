import { ChevronRight } from "lucide-react"
import { BarFill } from "@/components/bar-fill"
import { FindingCard } from "@/components/finding-card"
import { Meter } from "@/components/meter"
import { Skeleton } from "@/components/ui/skeleton"
import { intlLocale, t, tk } from "@/i18n"
import {
  wholePercent,
  type ReportEffect,
  type ReportEffectMethod,
  type ReportEffectResponse,
} from "@/lib/results"

const TIER_LABEL = {
  H: tk("results_effect_tier_h"),
  A: tk("results_effect_tier_a"),
  B: tk("results_effect_tier_b"),
  C: tk("results_effect_tier_c"),
} as const

const UNMATCHED_LABEL = {
  no_control: tk("results_effect_unmatched_no_control"),
  no_activity: tk("results_effect_unmatched_no_activity"),
  network_reported: tk("results_effect_unmatched_network_reported"),
} as const

const list = (parts: string[]): string =>
  new Intl.ListFormat(intlLocale(), { style: "long", type: "unit" }).format(parts)

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
  const text = t("results_effect_progress_text", {
    value,
    max,
    differ: pairsDone ? "yes" : "no",
  })
  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className="text-fg">
          {pairsDone ? t("results_effect_pairs_differ") : t("results_effect_pairs")}
        </span>
        <span className="text-xs text-fg-muted tabular-nums">{text}</span>
      </div>
      <Meter value={value} max={max} label={t("results_effect_progress_label")} valueText={text} />
    </div>
  )
}

function Measured({ effect, label }: { effect: ReportEffect; label?: string }) {
  if (effect.seen_reported == null || effect.seen_control == null) return null
  return (
    <div className="space-y-2">
      {label ? <p className="text-xs font-medium text-fg-muted">{label}</p> : null}
      <ul className="space-y-2">
        <ShareBar label={t("results_effect_reported")} share={effect.seen_reported} />
        <ShareBar label={t("results_effect_similar")} share={effect.seen_control} />
      </ul>
      <p className="text-xs text-fg-muted">
        {t("results_effect_measured", {
          horizon: effect.horizon,
          count: effect.pairs,
          hasInterval: effect.interval ? "yes" : "no",
          interval: effect.interval ?? "",
        })}
      </p>
    </div>
  )
}

function Method({ method, running }: { method: ReportEffectMethod; running: boolean }) {
  const tiers = (Object.keys(TIER_LABEL) as (keyof typeof TIER_LABEL)[]).filter(
    (k) => (method.tiers[k] ?? 0) > 0,
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
        {t("results_effect_method_title")}
      </summary>
      <div className="mt-2 space-y-2 pl-4 text-xs text-fg-muted">
        <p>
          {t("results_effect_method_pairing")}
        </p>
        <p>
          {t("results_effect_method_caveat")}
        </p>
        {!running ? (
          <p>{t("results_effect_method_off")}</p>
        ) : null}
        <ul className="space-y-1">
          <li>
            {t("results_effect_method_pairs_made", {
              count: method.pairs_made,
              hasTiers: tiers.length > 0 ? "yes" : "no",
              tiers: list(tiers.map((k) => t(TIER_LABEL[k], { count: method.tiers[k] ?? 0 }))),
            })}
          </li>
          <li>{t("results_effect_method_waiting", { count: method.waiting })}</li>
          <li>
            {t("results_effect_method_left_out", {
              notObserved: method.not_observed,
              controlReported: method.control_reported,
              networkReported: method.network_reported,
            })}
          </li>
          <li>
            {t("results_effect_method_unmatched", {
              count: method.unmatched,
              hasReasons: unmatched.length > 0 ? "yes" : "no",
              reasons: list(
                unmatched.map((r) =>
                  t(UNMATCHED_LABEL[r], { count: method.unmatched_reasons[r] ?? 0 }),
                ),
              ),
            })}
          </li>
          <li>
            {t("results_effect_method_holdout", {
              state: method.holdout_pct > 0 ? "on" : "off",
              pct: method.holdout_pct,
              held: method.held_now,
            })}
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
      eyebrow={t("results_effect_eyebrow")}
      finding={e ? e.sentence : t("results_effect_loading")}
    >
      {!week || !e ? (
        <Skeleton className="h-24 w-full" />
      ) : (
        <div className="space-y-4">
          {enough ? (
            <Measured effect={e} label={monthEnough ? t("results_effect_after_week") : undefined} />
          ) : (
            <Progress effect={e} />
          )}
          {enough && monthEnough ? (
            <Measured effect={month.effect} label={t("results_effect_after_month")} />
          ) : null}
          <Method method={week.method} running={week.running} />
        </div>
      )}
    </FindingCard>
  )
}
