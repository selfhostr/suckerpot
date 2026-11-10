import { useQuery } from "@tanstack/react-query"
import { ChartNoAxesCombined } from "lucide-react"
import { useMemo } from "react"
import { Link, useSearchParams } from "react-router"
import { AnswersCard, DelayCard } from "@/components/results/answers-cards"
import { CurveCard } from "@/components/results/curve-card"
import { OverTimeCard } from "@/components/results/over-time-card"
import { ProvidersCard } from "@/components/results/providers-card"
import { TargetsCard } from "@/components/results/targets-card"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, type FilterChipDef } from "@/components/filter-bar"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { StatTile } from "@/components/stat-tile"
import { Button } from "@/components/ui/button"
import { formatNumber, formatPercent } from "@/lib/format"
import {
  CHANNEL_LABEL,
  resultKeys,
  resultsApi,
  type Channel,
  type OutcomeGroup,
  type ResultFilters,
} from "@/lib/results"
import { describeTakedownHeader, describeTtd, shortDelay } from "@/lib/results-sentences"

/** Filters that arrive from links elsewhere (a target page, the takedown tiles). */
const FILTER_CHIPS: FilterChipDef[] = [
  {
    param: "kind",
    label: "Kind",
    render: (v) => (v === "url" ? "URLs" : v === "host" ? "Hosts" : v),
  },
  { param: "provider", label: "Provider" },
  {
    param: "channel",
    label: "Channel",
    render: (v) => (v in CHANNEL_LABEL ? CHANNEL_LABEL[v as Channel] : v),
  },
]

const PERIODS = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
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

const CHANNELS: readonly Channel[] = ["mail", "urlhaus", "threatfox"]

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
        title="Results"
        description={
          <span className="normal-nums">
            {summary.isError
              ? "The results could not be loaded."
              : describeTakedownHeader(s, since)}
          </span>
        }
        actions={
          <SegmentedControl
            label="Period"
            value={presetOf(sinceParam)}
            onChange={(v) =>
              setParam("since", v === String(DEFAULT_DAYS) ? null : daysAgo(Number(v)))
            }
            options={PERIODS}
            className="scroll-fade-x max-w-full overflow-x-auto"
          />
        }
      />

      {active.length > 0 ? <FilterBar className="mb-4" chips={FILTER_CHIPS} /> : null}

      {nothing ? (
        <EmptyState
          icon={ChartNoAxesCombined}
          title="No report sent yet"
          description="Results appear here once you send one."
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/defend/abuse">Open the reports</Link>
            </Button>
          }
        />
      ) : (
        <div className="space-y-4 normal-nums">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Reports sent"
              value={totals?.sent}
              loading={!totals}
              hint={totals ? `${formatNumber(totals.no_answer)} without an answer` : undefined}
              href="/defend/abuse?status=sent"
            />
            <StatTile
              label="Answered"
              value={totals?.answered}
              loading={!totals}
              hint={
                totals && totals.eligible > 0
                  ? `${formatPercent(totals.answered / totals.eligible)} of reports sent 3+ days ago`
                  : "Reports are counted after 3 days"
              }
            />
            {tracking ? (
              <>
                <StatTile
                  label="Taken down within 48 h"
                  value={s.urls.down_48h}
                  hint={`of ${formatNumber(s.urls.eligible_48h)} reported URLs`}
                />
                <StatTile
                  label="Median time to takedown"
                  value={s.urls.ttd_p50_s != null && s.urls.ttd_n >= 5 ? s.urls.ttd_p50_s : 0}
                  format={(n) =>
                    s.urls.ttd_p50_s != null && s.urls.ttd_n >= 5 ? shortDelay(n) : "n/a"
                  }
                  hint={describeTtd(s.urls)}
                />
              </>
            ) : (
              <>
                <StatTile
                  label="Median first reply"
                  value={totals?.first_reply_p50_s ?? 0}
                  loading={!totals}
                  format={(n) => (totals?.first_reply_p50_s == null ? "n/a" : shortDelay(n))}
                  hint="From the sending time"
                />
                <StatTile
                  label="Resolved"
                  value={totals?.by_outcome.resolved ?? 0}
                  loading={!totals}
                  hint="Providers that said they acted"
                />
              </>
            )}
          </div>

          <OverTimeCard />
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <AnswersCard data={byAsn.data} />
            <DelayCard data={byAsn.data} />
          </div>
          {tracking ? <CurveCard summary={s} filters={filters} /> : null}
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
