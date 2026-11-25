import { useQuery } from "@tanstack/react-query"
import { ChartNoAxesCombined } from "lucide-react"
import { useMemo } from "react"
import { Link, useSearchParams } from "react-router"
import { AnswersCard } from "@/components/results/answers-cards"
import { EffectCard } from "@/components/results/effect-card"
import { MonthCard } from "@/components/results/month-card"
import { ProvidersCard } from "@/components/results/providers-card"
import { TargetsCard } from "@/components/results/targets-card"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, type FilterChipDef } from "@/components/filter-bar"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { StatTile } from "@/components/stat-tile"
import { Button } from "@/components/ui/button"
import { t, tk } from "@/i18n"
import { formatPercent } from "@/lib/format"
import {
  CHANNEL_LABEL,
  resultKeys,
  resultsApi,
  type Channel,
  type OutcomeGroup,
  type ResultFilters,
} from "@/lib/results"
import { describeTakedownHeader, describeTtd, longDelay, shortDelay } from "@/lib/results-sentences"
import { cn } from "@/lib/utils"

/** Filters that arrive from links elsewhere (a target page, the takedown tiles). */
const filterChips = (): FilterChipDef[] => [
  {
    param: "kind",
    label: t("results_filter_kind"),
    render: (v) =>
      v === "url"
        ? t("results_targets_role_urls")
        : v === "host"
          ? t("results_targets_role_hosts")
          : v,
  },
  { param: "provider", label: t("results_filter_provider") },
  {
    param: "channel",
    label: t("results_filter_channel"),
    render: (v) => (v in CHANNEL_LABEL ? CHANNEL_LABEL[v as Channel] : v),
  },
]

const PERIODS = [
  { value: "30", labelKey: tk("results_period_30") },
  { value: "90", labelKey: tk("results_period_90") },
  { value: "365", labelKey: tk("results_period_365") },
] as const

const DEFAULT_DAYS = 90
const GROUPS: readonly OutcomeGroup[] = ["asn", "recipient", "country", "kind"]

/** YYYY-MM-DD, `days` ago, in UTC. */
function daysAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10)
}

/** The days an explicit `since` stands for, if it matches a preset. */
function presetOf(since: string | null): string {
  if (!since) return String(DEFAULT_DAYS)
  const hit = PERIODS.find((p) => daysAgo(Number(p.value)) === since)
  return hit?.value ?? ""
}

const CHANNELS: readonly Channel[] = ["mail", "form", "urlhaus", "threatfox"]

export function ResultsPage() {
  const [params, setParams] = useSearchParams()
  const sinceParam = params.get("since")
  const since = sinceParam ?? daysAgo(DEFAULT_DAYS)
  const groupParam = params.get("group")
  const group: OutcomeGroup = GROUPS.find((g) => g === groupParam) ?? "asn"
  const channelParam = params.get("channel")
  const filters: ResultFilters = useMemo(
    () => ({
      since,
      kind: params.get("kind") ?? undefined,
      provider: params.get("provider") ?? undefined,
      channel: CHANNELS.find((c) => c === channelParam),
    }),
    [since, params, channelParam],
  )

  const setParam = (key: string, value: string | null) =>
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev)
        if (value === null) p.delete(key)
        else p.set(key, value)
        return p
      },
      { preventScrollReset: true },
    )

  const summary = useQuery({
    queryKey: resultKeys.summary(filters),
    queryFn: () => resultsApi.summary(filters),
  })
  const byAsn = useQuery({
    queryKey: resultKeys.outcomes({ since, group: "asn" }),
    queryFn: () => resultsApi.outcomes({ since, group: "asn" }),
  })
  const grouped = useQuery({
    queryKey: resultKeys.outcomes({ since, group }),
    queryFn: () => resultsApi.outcomes({ since, group }),
    enabled: group !== "asn",
  })
  const providers = useQuery({
    queryKey: resultKeys.providers(filters),
    queryFn: () => resultsApi.providers(filters),
    enabled: summary.data !== undefined && summary.data.enabled !== false,
  })

  const effectWeek = useQuery({
    queryKey: resultKeys.effect({ since, horizon: 7 }),
    queryFn: () => resultsApi.effect({ since, horizon: 7 }),
  })
  const effectMonth = useQuery({
    queryKey: resultKeys.effect({ since, horizon: 30 }),
    queryFn: () => resultsApi.effect({ since, horizon: 30 }),
    enabled: effectWeek.data !== undefined && effectWeek.data.effect.verdict !== "not_enough_data",
  })

  const s = summary.data
  const totals = byAsn.data?.totals
  const tracking = s !== undefined && s.enabled !== false
  const nothing = totals?.sent === 0 && (!tracking || s.urls.tracked + s.hosts.tracked === 0)
  const active = [
    ["kind", params.get("kind")],
    ["provider", params.get("provider")],
    ["channel", params.get("channel")],
  ].filter((x): x is [string, string] => x[1] !== null)

  return (
    <>
      <PageHeader
        help="abuse-results"
        title={t("results_title")}
        description={
          <span className="normal-nums">
            {summary.isError ? t("results_load_error") : describeTakedownHeader(s, since)}
          </span>
        }
        actions={
          <SegmentedControl
            label={t("results_period_label")}
            value={presetOf(sinceParam)}
            onChange={(v) =>
              setParam("since", v === String(DEFAULT_DAYS) ? null : daysAgo(Number(v)))
            }
            options={PERIODS.map((p) => ({ value: p.value, label: t(p.labelKey) }))}
            className="scroll-fade-x max-w-full overflow-x-auto"
          />
        }
      />

      {active.length > 0 ? <FilterBar className="mb-4" chips={filterChips()} /> : null}

      {nothing ? (
        <EmptyState
          icon={ChartNoAxesCombined}
          title={t("results_empty_title")}
          description={t("results_empty_description")}
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/defend/abuse">{t("results_open_reports")}</Link>
            </Button>
          }
        />
      ) : (
        <div className="space-y-4 normal-nums">
          {/*
           * The headline numbers are figures on a ruled band, not more cards: how many reports,
           * how many got an answer, how fast, and (with tracking) what happened to the targets.
           */}
          <div
            className={cn(
              "grid grid-cols-2 gap-x-6 gap-y-3 border-y py-3 sm:py-4 lg:grid-cols-4",
              tracking ? "2xl:grid-cols-7" : "2xl:grid-cols-5",
            )}
          >
            <StatTile
              variant="figure"
              label={t("results_tile_sent")}
              value={totals?.sent}
              loading={!totals}
              hint={totals ? t("results_tile_sent_hint", { count: totals.no_answer }) : undefined}
              href="/defend/abuse?status=sent"
            />
            <StatTile
              variant="figure"
              label={t("results_tile_answered")}
              value={totals?.answered}
              loading={!totals}
              hint={
                totals && totals.eligible > 0
                  ? t("results_tile_answered_hint", {
                      percent: formatPercent(totals.answered / totals.eligible),
                    })
                  : t("results_tile_answered_hint_none")
              }
            />
            <StatTile
              variant="figure"
              label={t("results_tile_half")}
              value={totals?.first_reply_p50_s ?? 0}
              loading={!totals}
              format={(n) =>
                totals?.first_reply_p50_s == null ? t("results_none_yet") : longDelay(n)
              }
              hint={t("results_tile_half_hint")}
            />
            <StatTile
              variant="figure"
              label={t("results_tile_nine")}
              value={totals?.first_reply_p90_s ?? 0}
              loading={!totals}
              format={(n) =>
                totals?.first_reply_p90_s == null ? t("results_none_yet") : longDelay(n)
              }
              hint={t("results_tile_nine_hint")}
            />
            <StatTile
              variant="figure"
              label={t("results_tile_resolve")}
              value={totals?.resolved_p50_s ?? 0}
              loading={!totals}
              format={(n) =>
                totals?.resolved_p50_s == null ? t("results_none_yet") : longDelay(n)
              }
              hint={t("results_tile_resolve_hint", { count: totals?.by_outcome.resolved ?? 0 })}
            />
            {tracking ? (
              <>
                <StatTile
                  variant="figure"
                  label={t("results_tile_down")}
                  value={s.urls.down_48h}
                  hint={t("results_tile_down_hint", { count: s.urls.eligible_48h })}
                />
                <StatTile
                  variant="figure"
                  label={t("results_tile_ttd")}
                  value={s.urls.ttd_p50_s != null && s.urls.ttd_n >= 5 ? s.urls.ttd_p50_s : 0}
                  format={(n) =>
                    s.urls.ttd_p50_s != null && s.urls.ttd_n >= 5 ? shortDelay(n) : t("results_na")
                  }
                  hint={describeTtd(s.urls)}
                />
              </>
            ) : null}
          </div>

          {/* Who answered, how many went out this month, and whether the reports helped. */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3 [&>*]:grid [&>*]:min-w-0">
            <div>
              <AnswersCard data={byAsn.data} />
            </div>
            <div>
              <MonthCard />
            </div>
            {effectWeek.isError ? null : (
              <div className="lg:col-span-2 2xl:col-span-1">
                <EffectCard week={effectWeek.data} month={effectMonth.data} />
              </div>
            )}
          </div>
          <ProvidersCard
            groups={(group === "asn" ? byAsn.data : grouped.data)?.groups}
            group={group}
            takedown={providers.data?.items}
          />
          {tracking ? <TargetsCard filters={filters} /> : null}
        </div>
      )}
    </>
  )
}
