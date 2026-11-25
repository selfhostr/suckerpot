import { PageHelp } from "@/components/page-help"
import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, ArrowRight, FileQuestion, GitMerge, ShieldCheck } from "lucide-react"
import { Link, useParams } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { subjectProps } from "@/app/view-transitions"
import { ExportMenu } from "@/components/abuse/export-menu"
import { ExcerptBlock } from "@/components/campaigns/excerpt-block"
import { IndicatorList } from "@/components/campaigns/indicator-list"
import { StageTrail } from "@/components/campaigns/stage-trail"
import { TechniqueChips } from "@/components/campaigns/technique-chips"
import { DayBars } from "@/components/charts/day-bars"
import { CountryFlag } from "@/components/country-flag"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionRow } from "@/components/session-row"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonList, SkeletonText } from "@/components/skeletons"
import { TagBadge } from "@/components/tag-badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, api, queryKeys } from "@/lib/api"
import {
  dailyFromHourly,
  describeScale,
  formatDay,
  stageTrailText,
  statusLabel,
  type Campaign,
  type CampaignTimeline,
} from "@/lib/campaigns"
import { t } from "@/i18n"
import { formatNumber, maskDefangedText } from "@/lib/format"
import { cn } from "@/lib/utils"

const TIMELINE_DAYS = 7
const SESSIONS_SHOWN = 8

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="text-sm font-medium break-words text-fg">{children}</dd>
    </div>
  )
}

function activityFinding(tl: CampaignTimeline): string {
  if (tl.linked === 0) return t("campaign_activity_none", { days: TIMELINE_DAYS })
  const days = dailyFromHourly(tl.points, TIMELINE_DAYS)
  const busiest = days.reduce(
    (best, d) => (d.events > best.events ? d : best),
    days[0] ?? { day: "", events: 0 },
  )
  const active = days.filter((d) => d.events > 0).length
  const values = {
    sessions: tl.linked,
    days: TIMELINE_DAYS,
    busiest: formatDay(busiest.day),
  }
  if (active <= 1) return t("campaign_activity_one_day", values)
  return t("campaign_activity_many_days", { ...values, active, events: busiest.events })
}

function sessionsFinding(total: number, shown: number | null): string {
  if (shown === 0) return t("campaign_sessions_none_stored", { count: total })
  if (shown !== null && total > shown) return t("campaign_sessions_latest", { shown, total })
  return t("campaign_sessions_newest", { count: total })
}

/** The advice, first sentence as the finding and the rest as an ordered checklist. */
function WhatToDo({
  tips,
  className,
}: {
  tips: readonly string[] | undefined
  className?: string
}) {
  const { masked } = useIpMask()
  const shown = (tip: string) => (masked ? maskDefangedText(tip) : tip)
  return (
    <FindingCard
      className={className}
      eyebrow={t("campaign_todo_eyebrow")}
      finding={tips?.[0] ? shown(tips[0]) : t("campaign_todo_working")}
      detail={tips && tips.length > 1 ? t("campaign_todo_then") : undefined}
    >
      {tips && tips.length > 1 ? (
        <ol className="space-y-2.5">
          {tips.slice(1).map((tip) => (
            <li key={tip} className="flex gap-2.5 text-sm text-fg">
              <ShieldCheck
                aria-hidden
                className="mt-0.5 size-4 shrink-0 text-fg-subtle"
                strokeWidth={1.75}
              />
              <span className="text-pretty">{shown(tip)}</span>
            </li>
          ))}
        </ol>
      ) : null}
    </FindingCard>
  )
}

function Back() {
  return (
    <Link
      to="/campaigns"
      className="inline-flex items-center gap-1.5 text-xs text-fg-muted transition-colors hover:text-fg"
    >
      <ArrowLeft aria-hidden className="size-3.5" /> {t("campaigns_page_title")}
    </Link>
  )
}

export function CampaignDetailPage() {
  const params = useParams()
  const id = /^\d{1,15}$/.test(params.id ?? "") ? Number(params.id) : null
  const { masked } = useIpMask()
  const campaign = useQuery({
    queryKey: queryKeys.campaign(id ?? 0),
    queryFn: () => api.campaign(id ?? 0),
    enabled: id !== null,
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  })
  const ready = campaign.isSuccess
  const story = useQuery({
    queryKey: queryKeys.campaignStory(id ?? 0),
    queryFn: () => api.campaignStory(id ?? 0),
    enabled: ready,
  })
  const timeline = useQuery({
    queryKey: queryKeys.campaignTimeline(id ?? 0, TIMELINE_DAYS),
    queryFn: () => api.campaignTimeline(id ?? 0, TIMELINE_DAYS),
    enabled: ready,
  })
  const sessions = useQuery({
    queryKey: queryKeys.campaignSessions(id ?? 0),
    queryFn: () => api.campaignSessions(id ?? 0, null, SESSIONS_SHOWN),
    enabled: ready,
  })
  const indicators = useQuery({
    queryKey: queryKeys.campaignIndicators(id ?? 0),
    queryFn: () => api.campaignIndicators(id ?? 0),
    enabled: ready,
  })

  if (id === null || campaign.isError) {
    const notFound =
      id === null || (campaign.error instanceof ApiError && campaign.error.status === 404)
    return (
      <>
        <div className="pb-6">
          <Back />
        </div>
        <EmptyState
          icon={FileQuestion}
          title={notFound ? t("campaign_not_found_title") : t("campaign_error_title")}
          description={
            notFound
              ? t("campaign_not_found_hint")
              : campaign.error?.message
          }
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/campaigns">{t("campaign_back_to_list")}</Link>
            </Button>
          }
        />
      </>
    )
  }

  const c: Campaign | undefined = campaign.data
  const st = story.data
  const sessionItems = sessions.data?.items ?? []

  return (
    <>
      <header className="space-y-4 pb-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <Back />
          {c ? <ExportMenu scope={{ campaign: id }} /> : null}
        </div>
        {c ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={c.severity} />
              <span className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
                <span
                  aria-hidden
                  className={cn(
                    "size-1.5 rounded-full",
                    c.status === "active" ? "bg-fg" : "border border-fg-subtle",
                  )}
                />
                {statusLabel(c.status)}
              </span>
              {c.sensors.map((s) => (
                <SensorBadge key={s} sensor={s} />
              ))}
              {c.families.map((f) => (
                <TagBadge key={f} tag={f} href={`/campaigns?family=${encodeURIComponent(f)}`} />
              ))}
            </div>
            <div className="flex items-start gap-1.5">
              <h1
                {...subjectProps(`campaign:${c.id}`)}
                className="type-page-title text-pretty text-fg"
              >
                {c.name}
              </h1>
              <PageHelp id="campaign" className="mt-0.5" />
            </div>
            <p className="max-w-2xl type-lede text-pretty text-fg-muted">
              {st?.headline ?? t("campaign_scale_sentence", { scale: describeScale(c) })}
            </p>
            {c.status === "merged" && c.merged_into ? (
              <p className="inline-flex items-center gap-2 rounded-md border border-dashed border-border-strong px-3 py-2 text-sm text-fg-muted">
                <GitMerge aria-hidden className="size-4" />
                {t("campaign_merged_note")}
                <Link
                  className="font-medium text-fg underline underline-offset-4"
                  to={`/campaigns/${c.merged_into}`}
                >
                  {t("campaign_merged_open")}
                </Link>
              </p>
            ) : null}
          </>
        ) : (
          <div className="space-y-3">
            <Skeleton className="h-6 w-64" />
            <Skeleton className="h-7 w-96 max-w-full" />
            <SkeletonText lines={2} className="max-w-xl" />
          </div>
        )}
      </header>

      {c ? (
        <dl className="mb-6 grid grid-cols-2 gap-x-6 gap-y-4 rounded-lg border bg-surface p-4 shadow-sm sm:grid-cols-3 sm:p-5 lg:grid-cols-6">
          <Meta label={t("campaign_meta_sessions")}>{formatNumber(c.sessions)}</Meta>
          <Meta label={t("campaign_meta_addresses")}>{formatNumber(c.sources)}</Meta>
          <Meta label={t("campaign_meta_countries")}>
            {c.countries.length === 0 ? (
              "–"
            ) : (
              <span className="inline-flex flex-wrap items-center gap-1.5">
                {c.countries.slice(0, 5).map((code) => (
                  <CountryFlag key={code} code={code} />
                ))}
                {c.countries.length > 5 ? (
                  <span className="text-xs text-fg-muted">+{c.countries.length - 5}</span>
                ) : null}
              </span>
            )}
          </Meta>
          <Meta label={t("campaign_meta_networks")}>{formatNumber(c.asns.length)}</Meta>
          <Meta label={t("campaign_meta_first_seen")}>
            <RelativeTime iso={c.first_seen} className="text-sm font-medium text-fg" />
          </Meta>
          <Meta label={t("campaign_meta_last_seen")}>
            <RelativeTime iso={c.last_seen} className="text-sm font-medium text-fg" />
          </Meta>
        </dl>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <FindingCard
            eyebrow={t("campaign_story_eyebrow")}
            finding={
              c
                ? t("campaign_story_finding", {
                    count: c.stages.length,
                    stages: stageTrailText(c.stages),
                  })
                : t("campaign_story_reading")
            }
            detail={t("campaign_story_detail")}
          >
            {c ? <StageTrail stages={c.stages} variant="steps" className="mb-6" /> : null}
            {story.isPending ? (
              <div role="status" aria-label={t("common_loading")} className="space-y-4">
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
              </div>
            ) : story.isError ? (
              <p className="text-sm text-fg-muted">{t("campaign_story_error")}</p>
            ) : st && st.stages.length > 0 ? (
              <TechniqueChips stages={st.stages} campaignId={id} className="border-t pt-5" />
            ) : (
              <EmptyState
                variant="bare"
                icon={FileQuestion}
                title={t("campaign_no_techniques_title")}
                description={t("campaign_no_techniques_hint")}
                className="py-8"
              />
            )}
          </FindingCard>

          {/* Phones and tablets: what to do comes right after the story, not after every card. */}
          <WhatToDo tips={st?.what_to_do} className="lg:hidden" />

          {st?.excerpt ? (
            <FindingCard
              eyebrow={t("campaign_excerpt_eyebrow")}
              finding={t("campaign_excerpt_finding", { count: st.counts.sessions })}
              footer={
                <Link
                  className="inline-flex items-center gap-1.5 font-medium text-fg hover:underline hover:underline-offset-4"
                  to={`/attacks/${encodeURIComponent(st.excerpt.session_id)}`}
                >
                  {t("campaign_open_session")} <ArrowRight aria-hidden className="size-3.5" />
                </Link>
              }
            >
              <ExcerptBlock excerpt={st.excerpt} />
            </FindingCard>
          ) : null}

          <FindingCard
            eyebrow={t("campaign_activity_eyebrow")}
            finding={
              timeline.data ? activityFinding(timeline.data) : t("campaign_activity_reading")
            }
          >
            {timeline.isPending ? (
              <Skeleton className="h-32 w-full" />
            ) : timeline.isError ? (
              <p className="text-sm text-fg-muted">{t("campaign_activity_error")}</p>
            ) : (
              <DayBars
                points={dailyFromHourly(timeline.data.points, TIMELINE_DAYS)}
                unit={t("campaign_chart_unit")}
                days={TIMELINE_DAYS}
              />
            )}
          </FindingCard>
        </div>

        <div className="space-y-4 self-start">
          <WhatToDo tips={st?.what_to_do} className="hidden lg:block" />

          <FindingCard
            eyebrow={t("campaign_ties_eyebrow")}
            finding={
              indicators.data
                ? indicators.data.items.length
                  ? t("campaign_ties_finding")
                  : t("campaign_ties_none")
                : t("campaign_ties_reading")
            }
            detail={t("campaign_ties_detail")}
          >
            {indicators.isPending ? (
              <SkeletonText lines={4} />
            ) : indicators.data && indicators.data.items.length > 0 ? (
              <IndicatorList items={indicators.data.items} />
            ) : null}
          </FindingCard>
        </div>

        {/* Full width, so each session keeps its one-line story instead of a truncated stub. */}
        <FindingCard
          className="lg:col-span-3"
          eyebrow={t("campaign_sessions_eyebrow")}
          finding={
            c ? sessionsFinding(c.sessions, sessions.isSuccess ? sessionItems.length : null) : "…"
          }
          bodyClassName="px-0 sm:px-0 pt-2 pb-0 sm:pb-0"
          footer={
            sessionItems.length > 0 ? (
              <Link
                className="inline-flex items-center gap-1.5 font-medium text-fg hover:underline hover:underline-offset-4"
                to={`/attacks?campaign_id=${id}`}
              >
                {t("campaign_see_all_sessions")} <ArrowRight aria-hidden className="size-3.5" />
              </Link>
            ) : undefined
          }
        >
          {sessions.isPending ? (
            <SkeletonList rows={4} />
          ) : sessionItems.length === 0 ? (
            <EmptyState
              variant="bare"
              icon={FileQuestion}
              title={t("campaign_sessions_aged_title")}
              description={t("campaign_sessions_aged_hint")}
              className="py-8"
            />
          ) : (
            <ul aria-label={t("campaign_sessions_eyebrow")} className="divide-y border-t">
              {sessionItems.map((s) => (
                <li key={s.session_id}>
                  <SessionRow session={s} masked={masked} />
                </li>
              ))}
            </ul>
          )}
        </FindingCard>
      </div>
    </>
  )
}
