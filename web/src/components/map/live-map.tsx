import { useCallback, useMemo, useRef, useState } from "react"
import { FamilyStrip } from "@/components/family-strip"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog"
import { t } from "@/i18n"
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
 * sources as arcs to home. On wide cards the events-per-minute strip sits in
 * the bar above the map (never over it) and doubles as the colour key; on
 * narrow ones it sits under the map. The expand button opens the same map at
 * viewport size in a dialog.
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
    () => <FamilyStrip bySensor={bySensor} className="hidden @3xl:flex" />,
    [bySensor],
  )
  const [expanded, setExpanded] = useState(false)
  // Radix hands focus back to its own trigger, and there is none here: keep the opener ourselves.
  const opener = useRef<HTMLElement | null>(null)
  const expand = useCallback((button: HTMLElement) => {
    opener.current = button
    setExpanded(true)
  }, [])
  const collapse = useCallback(() => setExpanded(false), [])

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
            <div className="skeleton h-2/3 w-5/6 rounded-lg" />
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
            onExpand={expand}
            dormant={expanded}
          />
        )}
      </div>
      <FamilyStrip bySensor={bySensor} layout="grid" className="border-t p-2 @3xl:hidden" />
      {footer}
      {home ? (
        <Dialog open={expanded} onOpenChange={setExpanded}>
          {/* The whole viewport; Esc and the close button hand focus back to "Expand". */}
          <DialogContent
            showCloseButton={false}
            onCloseAutoFocus={(e) => {
              e.preventDefault()
              opener.current?.focus()
            }}
            className="@container top-0 left-0 flex h-dvh max-w-none translate-x-0 translate-y-0 flex-col gap-0 rounded-none border-0 bg-surface p-0 sm:max-w-none"
          >
            <DialogTitle className="sr-only">{t("map_expanded_title")}</DialogTitle>
            <DialogDescription className="sr-only">
              {t("map_expanded_description")}
            </DialogDescription>
            <div className="min-h-0 flex-1">
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
                onClose={collapse}
              />
            </div>
            <FamilyStrip bySensor={bySensor} layout="grid" className="border-t p-2 @3xl:hidden" />
          </DialogContent>
        </Dialog>
      ) : null}
    </div>
  )
}
