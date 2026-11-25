import { useQuery } from "@tanstack/react-query"
import { useCallback, useEffect, useMemo, useState } from "react"
import { useLiveFeed } from "@/app/use-live-feed"
import {
  ACTIVITY_WINDOW_MS,
  MAX_SOURCES,
  aggregateSources,
  rankLeaders,
} from "@/components/map/activity"
import { useSensorFilter } from "@/hooks/use-sensor-filter"
import { api, getIncludeBenign } from "@/lib/api"
import { deriveStats, statsFromWindow } from "@/lib/live-stats"

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
 * The live picture behind the map, the ticker and the rankings: the last 15 minutes from the API
 * window, topped up by the WebSocket feed, filtered by `?sensor=`. Pause freezes all of it at the
 * newest event; hovering the ticker holds only the ticker. Hovering a row, a chip or a dot sets
 * `focus`, which lights that country everywhere.
 */
export function useLivePicture() {
  const feed = useLiveFeed()
  const [sensors] = useSensorFilter()
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
    () => rankLeaders(shown, now, ACTIVITY_WINDOW_MS, 10, base),
    [shown, now, base],
  )

  const [focus, setFocus] = useState<string | null>(null)
  // Stable, so the memoized ticker re-renders only when what it shows changes.
  const resume = useCallback(() => {
    setPaused(false)
    setHovering(false)
  }, [])

  const waiting = feed.events.length === 0
  return {
    sensors,
    paused,
    setPaused,
    stats,
    shown,
    ticker,
    pending,
    tickerHeld,
    freshAbove,
    setHovering,
    resume,
    now,
    activity,
    leaders,
    focus,
    setFocus,
    polling: feed.transport === "polling",
    connecting: waiting && (feed.status === "connecting" || feed.status === "reconnecting"),
    down: waiting && feed.status === "offline",
    waiting,
  }
}
