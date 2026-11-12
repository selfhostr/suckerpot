import { Link } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { eventTypeMeta } from "@/lib/event-type"
import { IPChip } from "@/components/ip-chip"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { TagBadge } from "@/components/tag-badge"
import type { LiveEvent } from "@/lib/api"
import { useIpMask } from "@/app/ip-mask"
import { maskIp, maskIpsInText } from "@/lib/format"
import { isSevereEvent } from "@/lib/severity"
import { sessionHref } from "@/lib/floods"
import { sensorMeta } from "@/lib/sensors"
import { cn } from "@/lib/utils"

interface LiveEventRowProps {
  event: LiveEvent
  /** Slides in once. Ignored (no motion) under prefers-reduced-motion. */
  isNew?: boolean
  /** Compact variant for small cards: no IP column, no tags. */
  compact?: boolean
  /** Always use the two-line layout, for narrow columns on wide screens. */
  stacked?: boolean
  className?: string
}

/**
 * One event of the live feed as one line (two on mobile). The whole row opens
 * the session; the IP, flag and tags stay independently clickable above it.
 * `summary` comes from the server as plain text and is rendered as text only.
 */
export function LiveEventRow({
  event,
  isNew = false,
  compact = false,
  stacked = false,
  className,
}: LiveEventRowProps) {
  const type = eventTypeMeta(event.type)
  const Icon = type.icon
  const severe = isSevereEvent(event.type, event.tags)
  const { masked } = useIpMask()
  const summary = masked ? maskIpsInText(event.summary) : event.summary
  const shownIp = masked ? maskIp(event.src_ip) : event.src_ip
  const label = sensorMeta(event.sensor)?.label ?? event.sensor
  const to = sessionHref(event.session_id, event.ts)

  const icon = (
    <span
      className={cn(
        "flex size-7 shrink-0 items-center justify-center rounded-md border",
        severe ? "tint-severe border-sev-severe/30 text-sev-severe" : "text-fg-muted",
      )}
    >
      <Icon aria-hidden className="size-3.5" strokeWidth={2} />
      <span className="sr-only">{severe ? `${type.label} (severe)` : type.label}</span>
    </span>
  )

  return (
    <div
      className={cn(
        "group/row relative px-4 py-2 text-sm transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
        isNew && "animate-slide-in",
        className,
      )}
    >
      <Link
        to={to}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
        aria-label={`${label}: ${summary}, from ${shownIp}. Open session`}
      />

      {/* Mobile: address line, then the summary. */}
      <div className={cn("flex min-w-0 flex-col gap-1", !stacked && "md:hidden")}>
        <div className="flex min-w-0 items-center gap-2.5">
          <SensorBadge sensor={event.sensor} />
          <IPChip ip={event.src_ip} variant="ghost" className="relative z-10 ml-0" />
          {event.country ? <CountryFlag code={event.country} className="relative z-10" /> : null}
          <RelativeTime iso={event.ts} className="relative z-10 ml-auto text-xs" />
        </div>
        <div className="flex min-w-0 items-center gap-2.5">
          {icon}
          <span className="min-w-0 flex-1 truncate text-fg">{summary}</span>
        </div>
      </div>

      {/* Desktop: one line. */}
      <div className={cn("hidden min-h-9 min-w-0 items-center gap-3", !stacked && "md:flex")}>
        <SensorBadge sensor={event.sensor} className="w-[4.75rem] shrink-0 justify-start" />
        {icon}
        <span className="min-w-0 flex-1 truncate text-fg">{summary}</span>
        {!compact ? (
          <>
            <span className="flex shrink-0 items-center gap-1.5">
              {event.tags.slice(0, 2).map((t) => (
                <TagBadge key={t} tag={t} className="relative z-10" />
              ))}
            </span>
            <IPChip ip={event.src_ip} variant="ghost" className="relative z-10 w-36 shrink-0" />
          </>
        ) : null}
        <span className="flex w-[18px] shrink-0 justify-center">
          {event.country ? <CountryFlag code={event.country} className="relative z-10" /> : null}
        </span>
        <RelativeTime iso={event.ts} className="relative z-10 w-20 shrink-0 text-right text-xs" />
      </div>
    </div>
  )
}
