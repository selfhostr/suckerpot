import { useMemo } from "react"
import { FamilyStrip } from "@/components/family-strip"
import type { LiveEvent, SensorCounts } from "@/lib/api"
import { cn } from "@/lib/utils"
import type { Activity } from "./activity"
import { useSiteHome } from "./use-site"
import { WorldMap } from "./world-map"

interface LiveMapProps {
  /** Newest first, already filtered (and held while paused) by the page. */
  events: readonly LiveEvent[]
  activity: Activity
  now: number
  paused: boolean
  /** Last-minute counts per sensor, for the stats strip. */
  bySensor: Record<string, SensorCounts> | undefined
  focus: string | null
  onFocusChange: (country: string | null) => void
  /** Under the map, inside the card (the live ticker). */
  footer?: React.ReactNode
  /** Height of the map area (the card grows by the strip and footer). */
  mapClassName?: string
  className?: string
}

/**
 * The Live hero: a flat world map filling the card, the last 15 minutes of
 * sources as arcs to home. On wide cards the events-per-minute strip floats in
 * the top-left corner and doubles as the colour key; on narrow ones it sits
 * under the map so it never hides a source.
 */
export function LiveMap({
  events,
  activity,
  now,
  paused,
  bySensor,
  focus,
  onFocusChange,
  footer,
  mapClassName,
  className,
}: LiveMapProps) {
  const site = useSiteHome()
  const lat = site.data?.lat
  const lon = site.data?.lon
  // Stable props, so the (memoized) map skips renders that change nothing it draws.
  const home = useMemo(
    () => (lat !== undefined && lon !== undefined ? { lat, lon } : null),
    [lat, lon],
  )
  const strip = useMemo(
    () => <FamilyStrip bySensor={bySensor} className="hidden @4xl:flex" />,
    [bySensor],
  )

  return (
    <div
      className={cn(
        "@container flex flex-col overflow-hidden rounded-lg border bg-surface shadow-sm",
        className,
      )}
    >
      <div className={cn("relative min-h-0", mapClassName)}>
        {!home ? (
          <div className="flex size-full items-center justify-center" aria-hidden>
            <div className="h-2/3 w-5/6 animate-pulse rounded-lg bg-accent" />
          </div>
        ) : (
          <WorldMap
            activity={activity}
            events={events}
            home={home}
            homeLabel={site.data?.label}
            paused={paused}
            now={now}
            focus={focus}
            onFocusChange={onFocusChange}
            topLeft={strip}
          />
        )}
      </div>
      <FamilyStrip bySensor={bySensor} layout="grid" className="border-t p-2 @4xl:hidden" />
      {footer}
    </div>
  )
}
