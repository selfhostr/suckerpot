import { useQuery } from "@tanstack/react-query"
import { Pause, Play, Radio, SearchX, WifiOff } from "lucide-react"
import { Link } from "react-router"
import { intlLocale, t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { useScannerFilter } from "@/app/scanner-filter"
import { AnimatedNumber } from "@/components/animated-number"
import { HourlyActivity } from "@/components/charts/hourly-activity"
import { SensorFilter } from "@/components/filter-bar"
import { LiveLeaders } from "@/components/live-leaders"
import { LiveTicker } from "@/components/live-ticker"
import { LiveMap } from "@/components/map/live-map"
import { PageHeader } from "@/components/page-header"
import { TermText } from "@/components/term"
import { TodoList } from "@/components/today/todo-list"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useLivePicture } from "@/hooks/use-live-picture"
import { sensorSetPhrase } from "@/lib/sensors"
import { storyApi, storyKeys, windowSince, withWindow, type StoryResponse } from "@/lib/story"
import { todayApi, todayKeys } from "@/lib/today"
import { cn } from "@/lib/utils"

const HOURS = 24

const timeFormats = new Map<string, Intl.DateTimeFormat>()

/** "14:02" in the browser's time zone, in the active language. */
function formatTime(iso: string): string {
  const locale = intlLocale()
  let f = timeFormats.get(locale)
  if (!f) {
    f = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" })
    timeFormats.set(locale, f)
  }
  return f.format(new Date(iso))
}

/**
 * On desktop the page fills the window and never scrolls: the shell's header (3.5 rem) and top
 * padding (1.75 rem) above; below, 1 rem of air, then the version line (1.75 rem) where the
 * shell's 2.5 rem bottom padding would be (pulled up by 1.5 rem). Under the header, two rows: now
 * (the map, and who is behind it) and the day (five numbers and the hour strip, and what to do).
 * The right column has one width in both rows, so the cards line up on both edges. Below 40 rem
 * of height the page scrolls rather than crush the map.
 */
const BOARD =
  "grid grid-cols-1 gap-4 lg:-mb-6 lg:h-[calc(100dvh-8rem)] lg:min-h-[40rem] lg:grid-cols-[minmax(0,1fr)_clamp(20rem,26%,26rem)] lg:grid-rows-[auto_minmax(0,1fr)_clamp(16.5rem,30dvh,20rem)]"

/** One number of the day: label above, value below, a link to the matching list. */
function Figure({ label, value, href }: { label: string; value: number; href?: string }) {
  const body = (
    <>
      <span className="type-eyebrow text-fg-muted">{label}</span>
      <AnimatedNumber value={value} className="type-kpi text-fg" />
    </>
  )
  const classes = "-mx-2 flex min-w-0 flex-col gap-0.5 rounded-md px-2 py-1"
  return href ? (
    <Link
      to={href}
      className={cn(classes, "transition-colors duration-150 hover:bg-surface-hover/50")}
    >
      {body}
    </Link>
  ) : (
    <div className={classes}>{body}</div>
  )
}

/** The last 24 hours: five numbers, then visits per hour by sensor family. */
function DayCard({
  story,
  error,
  onRetry,
  sensors,
  className,
}: {
  story: StoryResponse | undefined
  error: boolean
  onRetry: () => void
  sensors: readonly string[]
  className?: string
}) {
  const totals = story?.totals
  const hrefOf = (key: string) => story?.flow.nodes.find((n) => n.id === `stage:${key}`)?.href
  return (
    <Card
      role="region"
      aria-label={t("today_day_aria")}
      className={cn("min-h-0 gap-4 overflow-hidden p-4 sm:p-5", className)}
    >
      {error ? (
        <div className="flex h-full flex-col items-start justify-center gap-3">
          <p className="text-sm text-fg-muted">{t("today_day_error")}</p>
          <Button variant="outline" size="sm" onClick={onRetry}>
            {t("common_try_again")}
          </Button>
        </div>
      ) : !story || !totals ? (
        <div role="status" aria-label={t("common_loading")} className="flex h-full flex-col gap-4">
          <div className="grid grid-cols-3 gap-4 sm:grid-cols-5">
            {Array.from({ length: 5 }, (_, i) => (
              <Skeleton key={i} className="h-13" />
            ))}
          </div>
          <Skeleton className="min-h-24 flex-1" />
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-start gap-x-4 gap-y-2">
            <div className="grid flex-1 grid-cols-3 gap-x-4 gap-y-2 sm:grid-cols-5">
              <Figure
                label={t("today_figure_visits")}
                value={totals.sessions}
                href={withWindow("/attacks", windowSince(story.as_of, story.hours))}
              />
              <Figure label={t("today_figure_machines")} value={totals.sources} href="/attackers" />
              <Figure label={t("today_figure_countries")} value={totals.countries} />
              <Figure
                label={t("today_figure_got_in")}
                value={totals.got_in}
                href={hrefOf("got_in")}
              />
              <Figure
                label={t("today_figure_tried_install")}
                value={totals.downloads}
                href={hrefOf("download")}
              />
            </div>
            <p className="pt-1 text-xs text-fg-subtle max-sm:w-full">
              {tNodes(
                "today_updated",
                {},
                { time: <time dateTime={story.as_of}>{formatTime(story.as_of)}</time> },
              )}
            </p>
          </div>
          <HourlyActivity
            timeline={story.timeline}
            sensors={sensors}
            className="flex-1 border-t pt-4"
            plotClassName="max-lg:h-36 max-lg:flex-none"
          />
        </>
      )}
    </Card>
  )
}

function TickerNote({
  icon: Icon,
  children,
}: {
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>
  children: React.ReactNode
}) {
  return (
    <p className="flex min-w-0 items-center gap-2 text-xs text-fg-muted max-sm:px-4 max-sm:pt-1 max-sm:pb-4">
      <Icon aria-hidden className="size-3.5 shrink-0 text-fg-subtle" />
      <span className="min-w-0">{children}</span>
    </p>
  )
}

/**
 * Today: the screen to glance at, and to leave running. Under one plain sentence about the day,
 * the live map of the last 15 minutes is the hero, with the newest events as a ticker under it and
 * who is behind them beside it; below, the day in five numbers and one chart, and the few things
 * that need the operator. Everything else is one click away: every number, row and column opens
 * its list.
 */
export function TodayPage() {
  const { hide } = useScannerFilter()
  const live = useLivePicture()
  const todo = useQuery({
    queryKey: todayKeys.today,
    queryFn: todayApi.today,
    refetchInterval: 120_000,
  })
  const story = useQuery({
    queryKey: [...storyKeys.story(HOURS), hide],
    queryFn: () => storyApi.story(HOURS),
    refetchInterval: 120_000,
  })
  const { sensors, paused, setPaused } = live

  const placeholder = live.connecting ? (
    <div
      role="status"
      aria-label={t("common_loading")}
      className="flex gap-2 max-sm:flex-col max-sm:p-4"
    >
      {Array.from({ length: 4 }, (_, i) => (
        <Skeleton key={i} className="h-9 w-[300px] max-w-full shrink-0 rounded-md" />
      ))}
    </div>
  ) : live.down ? (
    <TickerNote icon={WifiOff}>{t("today_ticker_down")}</TickerNote>
  ) : live.waiting ? (
    <TickerNote icon={Radio}>{t("today_ticker_waiting")}</TickerNote>
  ) : live.ticker.length === 0 ? (
    <TickerNote icon={SearchX}>
      {sensors.length === 1 ? t("today_ticker_empty_one") : t("today_ticker_empty_many")}{" "}
      <span className="max-sm:hidden">
        {t("today_ticker_buffer", { sensors: sensorSetPhrase(sensors) })}
      </span>{" "}
      <Link to="/" className="font-medium text-fg underline-offset-4 hover:underline">
        {t("today_ticker_show_all")}
      </Link>
    </TickerNote>
  ) : undefined

  const headline = story.data
    ? story.data.totals.sessions === 0
      ? t("today_quiet_day")
      : story.data.headline
    : null

  return (
    <div className={BOARD}>
      <PageHeader
        help="today"
        title={t("today_title")}
        className="pb-0 lg:col-span-2"
        description={
          headline ? (
            <TermText
              text={headline}
              terms={["botnet", "brute-force", "exploit", "malware", "research-scanner"]}
            />
          ) : story.isError ? (
            t("today_summary_error")
          ) : (
            <span aria-hidden className="skeleton block h-5 w-[min(36rem,80vw)] rounded-md" />
          )
        }
        actions={
          <>
            <SensorFilter align="end" />
            <Button
              variant="outline"
              size="sm"
              aria-pressed={paused}
              onClick={() => setPaused((p) => !p)}
            >
              {paused ? <Play aria-hidden /> : <Pause aria-hidden />}
              {paused ? t("today_resume") : t("today_pause")}
            </Button>
          </>
        }
      />

      <LiveMap
        events={live.shown}
        activity={live.activity}
        now={live.now}
        paused={paused}
        bySensor={live.stats?.by_sensor}
        focus={live.focus}
        onFocusChange={live.setFocus}
        className="min-h-0 lg:col-start-1 lg:row-start-2"
        // Phones: the bar (region switch) plus a map area about as tall as the whole world is wide.
        mapClassName="h-[16rem] sm:h-[28rem] lg:h-auto lg:flex-1"
        footer={
          <LiveTicker
            events={live.ticker}
            pending={live.pending}
            held={live.tickerHeld}
            freshAbove={live.freshAbove}
            focus={live.focus}
            onFocusChange={live.setFocus}
            onHoverChange={live.setHovering}
            onResume={live.resume}
            polling={live.polling}
            placeholder={placeholder}
          />
        }
      />

      <TodoList
        cards={todo.data?.cards}
        error={todo.isError}
        className="lg:col-start-2 lg:row-start-3"
      />

      <DayCard
        story={story.data}
        error={story.isError}
        onRetry={() => void story.refetch()}
        sensors={sensors}
        className="lg:col-start-1 lg:row-start-3"
      />

      <LiveLeaders
        leaders={live.leaders}
        focus={live.focus}
        onFocusChange={live.setFocus}
        className="lg:col-start-2 lg:row-start-2"
      />
    </div>
  )
}
