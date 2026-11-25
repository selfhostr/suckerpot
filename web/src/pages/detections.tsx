import { CardHelp } from "@/components/page-help"
import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
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
import { t } from "@/i18n"
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
        title={t("detections_title")}
        description={detectionsSentence(total, days)}
      />
      <ReviewNotice />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SegmentedControl
          label={t("detections_format_label")}
          value={kind}
          onChange={(v) => setKindParam(v === "sigma" ? null : v)}
          options={RULE_KINDS.map((k) => ({ value: k, label: RULE_KIND_META[k].label }))}
        />
        <PeriodSwitch days={days} onChange={setDays} />
        <p className="text-xs text-fg-muted">{meta.hint}</p>
        <Button asChild variant="outline" size="sm" className="sm:ml-auto">
          <a href={detectionsExportUrl(kind, days)} download>
            <Download aria-hidden />
            {t("detections_download", { ext: meta.ext })}
          </a>
        </Button>
      </div>

      {rules.isPending ? (
        <SkeletonList rows={4} />
      ) : rules.isError ? (
        <EmptyState
          icon={SearchX}
          title={t("detections_error_title")}
          description={rules.error.message}
          action={
            <Button variant="outline" size="sm" onClick={() => void rules.refetch()}>
              {t("common_try_again")}
            </Button>
          }
        />
      ) : list.length === 0 ? (
        <EmptyState
          icon={FileSearch}
          title={t("detections_empty_title")}
          description={t("detections_empty_description")}
        />
      ) : (
        <>
          <ul aria-label={t("detections_list_label", { format: meta.label })} className="flex flex-col gap-3">
            {list.map((rule) => (
              <RuleCard key={rule.id} rule={rule} />
            ))}
          </ul>
          <div className="mt-4 flex flex-col items-center gap-2">
            <LoadMore
              hasNextPage={rules.hasNextPage}
              isFetchingNextPage={rules.isFetchingNextPage}
              fetchNextPage={rules.fetchNextPage}
              label={t("detections_load_more")}
            />
            <p className="text-xs text-fg-subtle">
              {t("detections_showing", { shown: list.length, total: total ?? list.length })}
            </p>
          </div>
        </>
      )}

      <section aria-labelledby="company-check" className="mt-12">
        <div className="flex items-center gap-1.5">
          <h2 id="company-check" className="type-section-title text-fg">
            {t("detections_company_title")}
          </h2>
          <CardHelp id="company" />
        </div>
        <p className="mt-1.5 max-w-2xl type-lede text-fg-muted">
          {guidance.data
            ? guidance.data.items.length === 0
              ? t("detections_company_none", { days })
              : t("detections_company_seen", { count: guidance.data.items.length, days })
            : t("detections_company_intro")}
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
