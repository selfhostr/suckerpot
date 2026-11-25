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
import { StoryStages } from "@/components/campaigns/story-stages"
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
import { formatNumber, maskDefangedText, plural } from "@/lib/format"
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

function activityFinding(t: CampaignTimeline): string {
  if (t.linked === 0) return `No sessions in the last ${TIMELINE_DAYS} days.`
  const days = dailyFromHourly(t.points, TIMELINE_DAYS)
  const busiest = days.reduce(
    (best, d) => (d.events > best.events ? d : best),
    days[0] ?? { day: "", events: 0 },
  )
  const active = days.filter((d) => d.events > 0).length
  const lead = `${plural(t.linked, "session")} in the last ${TIMELINE_DAYS} days`
  if (active <= 1) return `${lead}, all on ${formatDay(busiest.day)}.`
  return `${lead}, on ${active} different days. The busiest was ${formatDay(busiest.day)} with ${plural(busiest.events, "session")}.`
}

function sessionsFinding(total: number, shown: number | null): string {
  if (shown === 0) return `None of the ${plural(total, "session")} is still stored.`
  if (shown !== null && total > shown)
    return `The latest ${shown} of ${formatNumber(total)} sessions.`
  return `${plural(total, "session")}, newest first.`
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
      eyebrow="What to do"
      finding={tips?.[0] ? shown(tips[0]) : "Working out what to do…"}
      detail={tips && tips.length > 1 ? "Then, in this order:" : undefined}
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
      <ArrowLeft aria-hidden className="size-3.5" /> Campaigns
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
          title={notFound ? "Campaign not found" : "Could not load this campaign"}
          description={
            notFound
              ? "It may have been merged into another one, or removed to keep the database small."
              : campaign.error?.message
          }
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/campaigns">Back to campaigns</Link>
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
              {st?.headline ?? `${describeScale(c)}.`}
            </p>
            {c.status === "merged" && c.merged_into ? (
              <p className="inline-flex items-center gap-2 rounded-md border border-dashed border-border-strong px-3 py-2 text-sm text-fg-muted">
                <GitMerge aria-hidden className="size-4" />
                This campaign was found to be part of another one.
                <Link
                  className="font-medium text-fg underline underline-offset-4"
                  to={`/campaigns/${c.merged_into}`}
                >
                  Open the combined campaign
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
          <Meta label="Sessions">{formatNumber(c.sessions)}</Meta>
          <Meta label="Addresses">{formatNumber(c.sources)}</Meta>
          <Meta label="Countries">
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
          <Meta label="Networks">{formatNumber(c.asns.length)}</Meta>
          <Meta label="First seen">
            <RelativeTime iso={c.first_seen} className="text-sm font-medium text-fg" />
          </Meta>
          <Meta label="Last seen">
            <RelativeTime iso={c.last_seen} className="text-sm font-medium text-fg" />
          </Meta>
        </dl>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <FindingCard
            eyebrow="How the attack unfolded"
            finding={
              c
                ? `${plural(c.stages.length, "stage")}: ${stageTrailText(c.stages)}.`
                : "Reading the story…"
            }
            detail="Each step in plain English, with the MITRE ATT&CK techniques behind it."
          >
            {c ? <StageTrail stages={c.stages} variant="steps" className="mb-6" /> : null}
            {story.isPending ? (
              <div role="status" aria-label="Loading" className="space-y-4">
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
              </div>
            ) : story.isError ? (
              <p className="text-sm text-fg-muted">Could not load the story.</p>
            ) : st && st.stages.length > 0 ? (
              <StoryStages stages={st.stages} campaignId={id} className="border-t pt-5" />
            ) : (
              <EmptyState
                variant="bare"
                icon={FileQuestion}
                title="No techniques recorded"
                description="ATT&CK labelling was off when these sessions arrived, so there is no story to tell yet."
                className="py-8"
              />
            )}
          </FindingCard>

          {/* Phones and tablets: what to do comes right after the story, not after every card. */}
          <WhatToDo tips={st?.what_to_do} className="lg:hidden" />

          {st?.excerpt ? (
            <FindingCard
              eyebrow="From a real session"
              finding={`This is what one of the ${formatNumber(st.counts.sessions)} sessions did.`}
              footer={
                <Link
                  className="inline-flex items-center gap-1.5 font-medium text-fg hover:underline hover:underline-offset-4"
                  to={`/attacks/${encodeURIComponent(st.excerpt.session_id)}`}
                >
                  Open the full session <ArrowRight aria-hidden className="size-3.5" />
                </Link>
              }
            >
              <ExcerptBlock excerpt={st.excerpt} />
            </FindingCard>
          ) : null}

          <FindingCard
            eyebrow="Activity"
            finding={timeline.data ? activityFinding(timeline.data) : "Reading the activity…"}
          >
            {timeline.isPending ? (
              <Skeleton className="h-32 w-full" />
            ) : timeline.isError ? (
              <p className="text-sm text-fg-muted">Could not load the activity.</p>
            ) : (
              <DayBars
                points={dailyFromHourly(timeline.data.points, TIMELINE_DAYS)}
                unit="sessions"
                days={TIMELINE_DAYS}
              />
            )}
          </FindingCard>
        </div>

        <div className="space-y-4 self-start">
          <WhatToDo tips={st?.what_to_do} className="hidden lg:block" />

          <FindingCard
            eyebrow="What ties it together"
            finding={
              indicators.data
                ? indicators.data.items.length
                  ? "These are the clues that made ingest group these sessions."
                  : "No shared servers or files yet."
                : "Reading the clues…"
            }
            detail="Hosts are shown defanged so they cannot be clicked by mistake."
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
          eyebrow="Sessions"
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
                See every session in Attacks <ArrowRight aria-hidden className="size-3.5" />
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
              title="The raw sessions have aged out"
              description="Sessions are kept for a limited time. The counters above stay."
              className="py-8"
            />
          ) : (
            <ul aria-label="Sessions" className="divide-y border-t">
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
