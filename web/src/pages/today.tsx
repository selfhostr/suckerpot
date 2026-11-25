import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { Radar, SearchX } from "lucide-react"
import { useScannerFilter } from "@/app/scanner-filter"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { StageLegend } from "@/components/story/stage-legend"
import { StoryCard, StoryCardSkeleton } from "@/components/story/story-card"
import { StoryFlow } from "@/components/story/story-flow"
import { TimelineScrubber } from "@/components/story/timeline-scrubber"
import { StatTile } from "@/components/stat-tile"
import { Term, TermText } from "@/components/term"
import { FormQueueNotice } from "@/components/today/form-queue-notice"
import { TodayCard, TodayCardSkeleton } from "@/components/today/today-card"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { plural } from "@/lib/format"
import {
  flowFinding,
  scopeFlow,
  storyApi,
  storyKeys,
  windowSince,
  withWindow,
  type StoryResponse,
} from "@/lib/story"
import { todayApi, todayKeys } from "@/lib/today"
import { cn } from "@/lib/utils"

const HOURS = 24

const time = new Intl.DateTimeFormat("en-US", {
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
})

function Section({
  id,
  title,
  finding,
  children,
  className,
}: {
  id: string
  title: string
  finding: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <section aria-labelledby={id} className={cn("mt-8", className)}>
      <h2 id={id} className="type-eyebrow text-fg-muted">
        {title}
      </h2>
      <p className="mt-1 mb-3 max-w-3xl type-card-title text-pretty text-fg">{finding}</p>
      {children}
    </section>
  )
}

/** The five headline numbers: a ruled band of figures, so they read before any card. */
const FIGURES =
  "grid grid-cols-2 gap-x-6 gap-y-3 border-y py-3 sm:grid-cols-3 sm:py-4 lg:grid-cols-5"

/**
 * Cards of uneven height (stories, to-do cards) flow in columns instead of rows, so a short card
 * never leaves a hole beside a tall one. Reading order runs down each column.
 */
const FLOW_COLUMNS = "-mb-4 gap-4 [&>*]:mb-4 [&>*]:break-inside-avoid"

function Numbers({ story }: { story: StoryResponse }) {
  const t = story.totals
  const hrefOf = (key: string) => story.flow.nodes.find((n) => n.id === `stage:${key}`)?.href
  return (
    <div className={FIGURES}>
      <StatTile
        variant="figure"
        label="Visits"
        value={t.sessions}
        href={withWindow("/attacks", windowSince(story.as_of, story.hours))}
        hint="Doors knocked on"
      />
      <StatTile
        variant="figure"
        label="Machines"
        value={t.sources}
        href="/attackers"
        hint="Different senders"
      />
      <StatTile variant="figure" label="Countries" value={t.countries} hint="They came from" />
      <StatTile
        variant="figure"
        label="Got in"
        value={t.got_in}
        href={hrefOf("got_in")}
        hint="A password worked"
      />
      <StatTile
        variant="figure"
        label="Tried to install"
        value={t.downloads}
        href={hrefOf("download")}
        hint="A program, usually malware"
        className="col-span-2 sm:col-span-1"
      />
    </div>
  )
}

function StoryLoading() {
  return (
    <div role="status" aria-label="Loading" className="space-y-8">
      <Skeleton className="h-6 w-3/4" />
      <div className={FIGURES}>
        {Array.from({ length: 5 }, (_, i) => (
          <Skeleton key={i} className="h-16" />
        ))}
      </div>
      <Skeleton className="h-80 w-full" />
      <Skeleton className="h-36 w-full" />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <StoryCardSkeleton />
        <StoryCardSkeleton />
      </div>
    </div>
  )
}

/** GET /today, shared by the to-do cards and the form queue notice (one request). */
function useToday() {
  return useQuery({
    queryKey: todayKeys.today,
    queryFn: todayApi.today,
    refetchInterval: 120_000,
  })
}

/** What to do about it: the cards of GET /today that are about action, not about the past. */
function ToDo({ className }: { className?: string }) {
  const query = useToday()
  if (query.isError) return null
  const cards = query.data?.cards.filter((c) => c.id !== "happened") ?? []
  if (query.data && cards.length === 0) return null
  return (
    <Section
      id="todo"
      title="What you can do about it"
      finding="The short list: what to block, what is new, and what you expose."
      className={className}
    >
      {query.isPending ? (
        <div
          role="status"
          aria-label="Loading"
          className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-1"
        >
          <TodayCardSkeleton />
          <TodayCardSkeleton />
        </div>
      ) : (
        <div className={cn("lg:columns-2 2xl:columns-1", FLOW_COLUMNS)}>
          {cards.map((card, i) => (
            <TodayCard key={card.id} card={card} index={i} />
          ))}
        </div>
      )}
    </Section>
  )
}

/**
 * Today: the last 24 hours as a story. A plain sentence first, then the numbers, the flow from
 * country to door to how far they got, an hour-by-hour strip, a few stories, and what to do.
 * Each technical detail is one click away.
 */
export function TodayPage() {
  const { hide, setHide } = useScannerFilter()
  const todo = useToday()
  const query = useQuery({
    queryKey: [...storyKeys.story(HOURS), hide],
    queryFn: () => storyApi.story(HOURS),
    refetchInterval: 120_000,
  })
  const raw = query.data
  const story = useMemo(
    () =>
      raw ? { ...raw, flow: scopeFlow(raw.flow, windowSince(raw.as_of, raw.hours)) } : undefined,
    [raw],
  )

  return (
    <>
      <PageHeader
        help="today"
        title="Today"
        description="The last 24 hours on your decoy servers, in plain words. Click anything to dig deeper."
      />

      <FormQueueNotice count={todo.data?.form_queue} className="mb-6" />

      {query.isPending || !story ? (
        <StoryLoading />
      ) : query.isError ? (
        <EmptyState
          icon={SearchX}
          title="Could not load Today"
          description={query.error.message}
          action={
            <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
              Try again
            </Button>
          }
        />
      ) : story.totals.sessions === 0 ? (
        <>
          <EmptyState
            icon={Radar}
            title="A quiet day"
            description="Nobody knocked on your decoy servers in the last 24 hours."
          />
          <ToDo />
        </>
      ) : (
        <>
          <p className="max-w-3xl text-lg font-medium text-pretty text-fg">
            <TermText
              text={story.headline}
              terms={["botnet", "brute-force", "exploit", "malware", "research-scanner"]}
            />
          </p>
          <p className="mt-2 text-xs text-fg-muted">
            Updated <time dateTime={story.as_of}>{time.format(new Date(story.as_of))}</time>
            {hide ? (
              <>
                <span aria-hidden className="px-1.5 text-fg-subtle">
                  ·
                </span>
                <Term id="research-scanner">Research scanners</Term> are left out.{" "}
                <button
                  type="button"
                  onClick={() => setHide(false)}
                  className="rounded-xs text-fg underline underline-offset-4 hover:text-fg-muted"
                >
                  Show them
                </button>
              </>
            ) : null}
          </p>
          <div className="mt-5">
            <Numbers story={story} />
          </div>

          {/* From 2xl the page has three columns: the story in two, what to do in the third. */}
          <div className="2xl:grid 2xl:grid-cols-3 2xl:gap-x-6">
            <div className="min-w-0 2xl:col-span-2">
              <Section
                id="flow"
                title="Where they come from, which door they knock on, how far they got"
                finding={flowFinding(story.totals)}
              >
                <div className="rounded-lg border bg-surface p-4 shadow-sm sm:p-5">
                  <StoryFlow flow={story.flow} />
                  <div className="mt-6 border-t pt-4">
                    <StageLegend />
                  </div>
                </div>
              </Section>

              <Section
                id="hours"
                title="Hour by hour"
                finding={`The busiest hour is picked below. Drag, click or use the arrow keys to look at another one.`}
              >
                <div className="rounded-lg border bg-surface p-4 shadow-sm sm:p-5">
                  <TimelineScrubber timeline={story.timeline} />
                </div>
              </Section>

              {story.stories.length > 0 ? (
                <Section
                  id="stories"
                  title="Stories of the day"
                  finding={`${plural(story.stories.length, "visit")} worth a closer look, the most serious first.`}
                >
                  <div className={cn("lg:columns-2", FLOW_COLUMNS)}>
                    {story.stories.map((s, i) => (
                      <StoryCard key={s.session_id} story={s} index={i} />
                    ))}
                  </div>
                </Section>
              ) : null}
            </div>

            <ToDo className="min-w-0" />
          </div>
        </>
      )}
    </>
  )
}
