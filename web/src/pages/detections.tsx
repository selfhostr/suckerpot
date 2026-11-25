import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { Download, FileSearch, SearchX } from "lucide-react"
import { GuidanceCard } from "@/components/defend/guidance-card"
import { PeriodSwitch } from "@/components/defend/period-switch"
import { ReviewNotice } from "@/components/defend/review-notice"
import { RuleCard } from "@/components/defend/rule-card"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonCard, SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { usePeriod } from "@/hooks/use-period"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  defendApi,
  defendKeys,
  detectionsExportUrl,
  detectionsSentence,
  RULE_KIND_META,
  RULE_KINDS,
  type RuleKind,
} from "@/lib/defend"
import { formatNumber, plural } from "@/lib/format"

const PAGE_SIZE = 10

function parseKind(raw: string | null): RuleKind {
  return raw === "suricata" ? "suricata" : "sigma"
}

export function DetectionsPage() {
  const [kindParam, setKindParam] = useUrlParam("kind")
  const kind = parseKind(kindParam)
  const [days, setDays] = usePeriod()

  const rules = useInfiniteQuery({
    queryKey: defendKeys.detections(kind, days),
    queryFn: ({ pageParam }) => defendApi.detections(kind, days, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const list = rules.data?.pages.flatMap((p) => p.items) ?? []
  const total = rules.data?.pages[0]?.total

  const guidance = useQuery({
    queryKey: defendKeys.guidance(days),
    queryFn: () => defendApi.guidance(days),
    staleTime: 60_000,
  })

  const meta = RULE_KIND_META[kind]
  return (
    <>
      <PageHeader
        help="detections"
        title="Detections"
        description={detectionsSentence(total, days)}
      />
      <ReviewNotice />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SegmentedControl
          label="Rule format"
          value={kind}
          onChange={(v) => setKindParam(v === "sigma" ? null : v)}
          options={RULE_KINDS.map((k) => ({ value: k, label: RULE_KIND_META[k].label }))}
        />
        <PeriodSwitch days={days} onChange={setDays} />
        <p className="text-xs text-fg-muted">{meta.hint}</p>
        <Button asChild variant="outline" size="sm" className="sm:ml-auto">
          <a href={detectionsExportUrl(kind, days)} download>
            <Download aria-hidden />
            Download all as {meta.ext}
          </a>
        </Button>
      </div>

      {rules.isPending ? (
        <SkeletonList rows={4} />
      ) : rules.isError ? (
        <EmptyState
          icon={SearchX}
          title="Could not load the rules"
          description={rules.error.message}
          action={
            <Button variant="outline" size="sm" onClick={() => void rules.refetch()}>
              Try again
            </Button>
          }
        />
      ) : list.length === 0 ? (
        <EmptyState
          icon={FileSearch}
          title="No rules for this period"
          description="A rule is written only when several different sources did the same thing. Try a longer period."
        />
      ) : (
        <>
          <ul aria-label={`${meta.label} rules`} className="flex flex-col gap-3">
            {list.map((rule) => (
              <RuleCard key={rule.id} rule={rule} />
            ))}
          </ul>
          <div className="mt-4 flex flex-col items-center gap-2">
            {rules.hasNextPage ? (
              <Button
                variant="outline"
                size="sm"
                disabled={rules.isFetchingNextPage}
                onClick={() => void rules.fetchNextPage()}
              >
                {rules.isFetchingNextPage ? "Loading…" : "Load more rules"}
              </Button>
            ) : null}
            <p className="text-xs text-fg-subtle">
              Showing {formatNumber(list.length)} of {plural(total ?? list.length, "rule")}
            </p>
          </div>
        </>
      )}

      <section aria-labelledby="company-check" className="mt-12">
        <h2 id="company-check" className="type-section-title text-fg">
          Check this at your company
        </h2>
        <p className="mt-1.5 max-w-2xl type-lede text-fg-muted">
          {guidance.data
            ? guidance.data.items.length === 0
              ? `Nothing in the last ${plural(days, "day")} calls for a check yet.`
              : `${plural(guidance.data.items.length, "behaviour")} seen in the last ${plural(days, "day")}, with what to look for in your own logs and how to fix it.`
            : "What attackers did to our decoys, and what to look for in your own logs."}
        </p>
        <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
          {guidance.isPending ? (
            <>
              <SkeletonCard />
              <SkeletonCard />
            </>
          ) : (
            guidance.data?.items.map((item) => <GuidanceCard key={item.tag} item={item} />)
          )}
        </div>
      </section>
    </>
  )
}
