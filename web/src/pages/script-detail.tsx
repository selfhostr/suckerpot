import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import { ArrowLeft, FileCode2, Lightbulb } from "lucide-react"
import { Link, useParams } from "react-router"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { ExplainedLines } from "@/components/scripts/explained-lines"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionRow } from "@/components/session-row"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonCard, SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { ApiError } from "@/lib/api"
import { t } from "@/i18n"
import { formatNumber } from "@/lib/format"
import { describeScript, nextStep, scriptKeys, scriptsApi } from "@/lib/scripts"

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="type-column text-fg-subtle">{label}</dt>
      <dd className="text-sm text-fg tabular-nums">{children}</dd>
    </div>
  )
}

function SessionsCard({ id }: { id: number }) {
  const query = useInfiniteQuery({
    queryKey: scriptKeys.sessions(id),
    queryFn: ({ pageParam }) => scriptsApi.sessions(id, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  return (
    <FindingCard
      eyebrow={t("scripts_sessions_eyebrow")}
      finding={
        query.isPending
          ? t("scripts_sessions_loading")
          : rows.length === 0
            ? t("scripts_sessions_none")
            : t("scripts_sessions_recent", {
                count: rows.length,
                more: query.hasNextPage ? "yes" : "no",
              })
      }
      bodyClassName="px-0 pt-3 sm:px-0 pb-0 sm:pb-0"
    >
      {query.isPending ? (
        <SkeletonList rows={3} />
      ) : (
        <div
          role="list"
          aria-label={t("scripts_sessions_list_label")}
          className="divide-y border-t"
        >
          {rows.map((s) => (
            <div key={s.session_id} role="listitem">
              <SessionRow session={s} />
            </div>
          ))}
        </div>
      )}
      <LoadMore
        hasNextPage={query.hasNextPage}
        isFetchingNextPage={query.isFetchingNextPage}
        fetchNextPage={query.fetchNextPage}
        label={t("scripts_sessions_more")}
      />
    </FindingCard>
  )
}

export function ScriptDetailPage() {
  const { id: raw } = useParams()
  const id = Number(raw)
  const valid = Number.isInteger(id) && id > 0
  const query = useQuery({
    queryKey: scriptKeys.detail(id),
    queryFn: () => scriptsApi.detail(id),
    enabled: valid,
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 2,
  })
  const back = (
    <Link to="/scripts" className="inline-flex items-center gap-1 hover:text-fg">
      <ArrowLeft aria-hidden className="size-3.5" />
      {t("scripts_all")}
    </Link>
  )

  if (!valid || (query.isError && query.error instanceof ApiError && query.error.status === 404)) {
    return (
      <>
        <PageHeader help="script" title={t("scripts_detail_title")} eyebrow={back} />
        <EmptyState
          icon={FileCode2}
          title={t("scripts_not_found_title")}
          description={t("scripts_not_found_hint")}
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/scripts">{t("scripts_back_to_library")}</Link>
            </Button>
          }
        />
      </>
    )
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader help="script" title={t("scripts_detail_title")} eyebrow={back} />
        <div className="space-y-4" aria-busy>
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </>
    )
  }
  if (query.isError) {
    return (
      <>
        <PageHeader help="script" title={t("scripts_detail_title")} eyebrow={back} />
        <EmptyState
          icon={FileCode2}
          title={t("scripts_detail_error_title")}
          description={query.error.message}
          action={
            <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
              {t("common_try_again")}
            </Button>
          }
        />
      </>
    )
  }

  const d = query.data
  const item = d.item
  return (
    <>
      <PageHeader
        help="script"
        title={t("scripts_detail_heading", { id: item.id })}
        eyebrow={back}
        description={<span className="normal-nums">{describeScript(item, item.summary)}</span>}
      />

      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-fg-muted">
          {item.risk ? <SeverityBadge severity={item.risk} /> : null}
          {item.sensors.map((s) => (
            <Link
              key={s}
              to={`/scripts?sensor=${encodeURIComponent(s)}`}
              className="rounded-sm hover:opacity-80"
            >
              <SensorBadge sensor={s} />
            </Link>
          ))}
          {d.campaign ? (
            <Link
              to={`/campaigns/${d.campaign.id}`}
              className="rounded-sm border border-border-strong px-2 py-1 text-fg-muted normal-nums transition-colors hover:border-fg-subtle hover:text-fg"
            >
              {t("scripts_row_campaign", { name: d.campaign.name })}
            </Link>
          ) : null}
        </div>

        <FindingCard
          eyebrow={t("scripts_lines_eyebrow")}
          className="normal-nums"
          finding={d.lines.length === 0 ? t("scripts_lines_none") : t("scripts_lines_finding")}
          detail={
            d.unexplained > 0 ? t("scripts_lines_unexplained", { count: d.unexplained }) : undefined
          }
        >
          {d.lines.length > 0 ? (
            <>
              <ExplainedLines lines={d.lines} />
              <p className="mt-4 flex items-start gap-2 rounded-md bg-surface-hover/50 px-3 py-2.5 text-sm text-fg-muted">
                <Lightbulb aria-hidden className="mt-0.5 size-4 shrink-0" />
                <span>
                  <span className="font-medium text-fg">{t("scripts_what_to_do")} </span>
                  {nextStep(d.lines)}
                </span>
              </p>
            </>
          ) : null}
        </FindingCard>

        {d.techniques_detail.length > 0 ? (
          <FindingCard
            eyebrow={t("campaign_techniques_label")}
            className="normal-nums"
            finding={t("scripts_techniques_finding", { count: d.techniques_detail.length })}
            detail={t("scripts_techniques_detail")}
          >
            <ul className="flex flex-wrap gap-2" aria-label={t("campaign_techniques_label")}>
              {d.techniques_detail.map((tech) => (
                <li key={tech.id}>
                  <Link
                    to={`/scripts?technique=${encodeURIComponent(tech.id)}`}
                    className="inline-flex items-center gap-1.5 rounded-sm border border-border-strong px-2 py-1 text-xs text-fg-muted transition-colors hover:border-fg-subtle hover:text-fg"
                  >
                    <span className="font-mono">{tech.id}</span>
                    {tech.name}
                  </Link>
                </li>
              ))}
            </ul>
          </FindingCard>
        ) : null}

        <FindingCard eyebrow={t("scripts_facts_eyebrow")} finding={t("scripts_facts_finding")}>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
            <Fact label={t("campaign_meta_first_seen")}>
              <RelativeTime iso={item.first_seen} className="text-sm text-fg" />
            </Fact>
            <Fact label={t("campaign_meta_last_seen")}>
              <RelativeTime iso={item.last_seen} className="text-sm text-fg" />
            </Fact>
            <Fact label={t("campaign_meta_sessions")}>{formatNumber(item.sessions)}</Fact>
            <Fact label={t("campaign_meta_addresses")}>{formatNumber(item.sources)}</Fact>
            <Fact label={t("scripts_fact_fingerprint")}>
              <span className="font-mono text-xs" title={item.fingerprint}>
                {item.fingerprint.slice(0, 12)}
              </span>
            </Fact>
          </dl>
        </FindingCard>

        <SessionsCard id={item.id} />
      </div>
    </>
  )
}
