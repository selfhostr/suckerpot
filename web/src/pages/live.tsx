import { useQuery } from "@tanstack/react-query"
import { Pause, Play, Radio, SearchX, WifiOff } from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { useLiveFeed } from "@/app/use-live-feed"
import { SensorFilter } from "@/components/filter-bar"
import { LiveLeaders } from "@/components/live-leaders"
import { LiveTicker } from "@/components/live-ticker"
import {
  ACTIVITY_WINDOW_MS,
  MAX_SOURCES,
  aggregateSources,
  rankLeaders,
} from "@/components/map/activity"
import { LiveMap } from "@/components/map/live-map"
import { PageHeader } from "@/components/page-header"
import { Skeleton } from "@/components/ui/skeleton"
import { Button } from "@/components/ui/button"
import { useSensorFilter } from "@/hooks/use-sensor-filter"
import { api, getIncludeBenign } from "@/lib/api"
import { maskIpsInText } from "@/lib/format"
import { deriveStats, liveHeadline, statsFromWindow } from "@/lib/live-stats"
import { sensorSetPhrase } from "@/lib/sensors"

/** How long a freshly arrived event keeps its fade-in marker. */
const FRESH_MS = 1_000
/** How often the window aggregate is refetched; live events fill the gaps in between. */
const WINDOW_REFRESH_MS = 30_000

/** A clock for fading and windows: ticks every few seconds, not every frame. */
function useTick(ms: number) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(t)
  }, [ms])
  return now
}

/**
 * Live: the screen to leave running. A full-width map of the last 15 minutes
 * is the hero, with the events-per-minute strip on it; the newest events run
 * as a ticker under the map, and the busiest addresses, countries and
 * networks follow below. Pause freezes the whole picture.
 */
export function LivePage() {
  const feed = useLiveFeed()
  const [sensors] = useSensorFilter()
  const { masked } = useIpMask()

  // --- Hold: Pause freezes everything; hovering the ticker holds only the ticker.
  const [paused, setPaused] = useState(false)

  // The whole last 15 minutes, aggregated by the API; the WebSocket buffer adds only what is newer.
  const windowQuery = useQuery({
    queryKey: ["live-window", sensors, getIncludeBenign()],
    queryFn: () => api.liveWindow(sensors),
    refetchInterval: paused ? false : WINDOW_REFRESH_MS,
  })
  const base = windowQuery.data ?? null

  const stats = useMemo(
    () =>
      feed.stats ??
      (base ? statsFromWindow(base) : feed.events.length ? deriveStats(feed.events) : null),
    [feed.stats, feed.events, base],
  )

  const [hovering, setHovering] = useState(false)
  const newest = feed.events[0]?.id ?? 0
  const [pauseAt, setPauseAt] = useState<number | null>(null)
  if (paused && pauseAt === null) setPauseAt(newest)
  if (!paused && pauseAt !== null) setPauseAt(null)
  const tickerHeld = paused || hovering
  const [holdAt, setHoldAt] = useState<number | null>(null)
  if (tickerHeld && holdAt === null) setHoldAt(newest)
  if (!tickerHeld && holdAt !== null) setHoldAt(null)

  // --- Mark events that just arrived, for a calm fade-in.
  const [prevNewest, setPrevNewest] = useState<number | null>(null)
  const [freshAbove, setFreshAbove] = useState<number | null>(null)
  if (newest !== prevNewest) {
    setPrevNewest(newest)
    if (prevNewest !== null && prevNewest > 0) setFreshAbove(prevNewest)
  }
  useEffect(() => {
    if (freshAbove === null) return
    const t = setTimeout(() => setFreshAbove(null), FRESH_MS)
    return () => clearTimeout(t)
  }, [freshAbove])

  const matching = useMemo(() => {
    if (!sensors.length) return feed.events
    const wanted = new Set<string>(sensors)
    return feed.events.filter((e) => wanted.has(e.sensor))
  }, [feed.events, sensors])
  const shown = useMemo(
    () => (pauseAt === null ? matching : matching.filter((e) => e.id <= pauseAt)),
    [matching, pauseAt],
  )
  const ticker = useMemo(
    () => (holdAt === null ? shown : matching.filter((e) => e.id <= holdAt)),
    [shown, matching, holdAt],
  )
  const pending = matching.length - ticker.length

  // --- The last 15 minutes: map sources and rankings, recomputed on new events and on the tick.
  const tick = useTick(5_000)
  const now = Math.max(tick, Date.parse(shown[0]?.ts ?? "") || 0)
  const activity = useMemo(
    () => aggregateSources(shown, now, ACTIVITY_WINDOW_MS, MAX_SOURCES, base),
    [shown, now, base],
  )
  const leaders = useMemo(
    () => rankLeaders(shown, now, ACTIVITY_WINDOW_MS, 8, base),
    [shown, now, base],
  )

  // Hovering a row, a chip or a dot lights that country everywhere.
  const [focus, setFocus] = useState<string | null>(null)
  // Stable, so the memoized ticker re-renders only when what it shows changes.
  const resume = useCallback(() => {
    setPaused(false)
    setHovering(false)
  }, [])

  const waiting = feed.events.length === 0
  const connecting = waiting && (feed.status === "connecting" || feed.status === "reconnecting")
  const down = waiting && feed.status === "offline"
  // The headline speaks about the selected sensors only.
  const selectedStats = useMemo(() => {
    if (!stats || !sensors.length) return stats
    const wanted = new Set<string>(sensors)
    const by_sensor = Object.fromEntries(
      Object.entries(stats.by_sensor).filter(([s]) => wanted.has(s)),
    )
    return { ...stats, by_sensor }
  }, [stats, sensors])
  const headline = liveHeadline(selectedStats, activity.sources[0], activity.events)

  const placeholder = connecting ? (
    <div role="status" aria-label="Loading" className="flex gap-2 max-sm:flex-col max-sm:p-4">
      {Array.from({ length: 4 }, (_, i) => (
        <Skeleton key={i} className="h-9 w-[300px] max-w-full shrink-0 rounded-md" />
      ))}
    </div>
  ) : down ? (
    <TickerNote icon={WifiOff}>
      The live feed is unreachable. The dashboard keeps trying in the background.
    </TickerNote>
  ) : waiting ? (
    <TickerNote icon={Radio}>
      Nothing has arrived yet. New events appear here the moment a sensor records them.
    </TickerNote>
  ) : ticker.length === 0 ? (
    <TickerNote icon={SearchX}>
      {sensors.length === 1
        ? "No events from this sensor yet."
        : "No events from these sensors yet."}{" "}
      <span className="max-sm:hidden">
        Nothing from {sensorSetPhrase(sensors)} is in the live buffer.
      </span>{" "}
      <Link to="/live" className="font-medium text-fg underline-offset-4 hover:underline">
        Show all sensors
      </Link>
    </TickerNote>
  ) : undefined

  return (
    <>
      <PageHeader
        help="live"
        title="Live"
        description={masked ? maskIpsInText(headline) : headline}
        className="pb-5"
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
              {paused ? "Resume" : "Pause"}
            </Button>
          </>
        }
      />

      <LiveMap
        events={shown}
        activity={activity}
        now={now}
        paused={paused}
        bySensor={stats?.by_sensor}
        focus={focus}
        onFocusChange={setFocus}
        // Phones: the World preset's own shape (11:8), so it fills the card with no empty band.
        mapClassName="aspect-[11/8] sm:aspect-auto sm:h-[26rem] lg:h-[clamp(26rem,calc(100dvh-19.5rem),72rem)]"
        footer={
          <LiveTicker
            events={ticker}
            pending={pending}
            held={tickerHeld}
            freshAbove={freshAbove}
            focus={focus}
            onFocusChange={setFocus}
            onHoverChange={setHovering}
            onResume={resume}
            polling={feed.transport === "polling"}
            placeholder={placeholder}
          />
        }
      />

      <LiveLeaders
        leaders={leaders}
        sources={activity.sources}
        windowEvents={activity.events}
        unlocated={activity.unlocated}
        focus={focus}
        onFocusChange={setFocus}
        className="mt-4"
      />
    </>
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
