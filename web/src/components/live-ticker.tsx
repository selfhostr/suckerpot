import { ArrowRight, Play } from "lucide-react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { CountryFlag } from "@/components/country-flag"
import { LiveEventRow } from "@/components/live-event-row"
import { useMediaQuery } from "@/hooks/use-media-query"
import type { LiveEvent } from "@/lib/api"
import { eventTypeMeta } from "@/lib/event-type"
import { countryName, maskIp, maskIpsInText, plural } from "@/lib/format"
import { isSevereEvent } from "@/lib/severity"
import { sessionHref } from "@/lib/floods"
import { sensorMeta } from "@/lib/sensors"
import { cn } from "@/lib/utils"

/** Width and gap of one chip, in px: chips sit on a fixed grid so they can glide, not jump. */
const CHIP_W = 300
const CHIP_GAP = 8
/** Chips kept in the row: enough to fill a 4K wall, the rest is history in Attacks. */
const ROW_CHIPS = 10
/** Rows kept in the stacked (phone) layout. */
const STACK_ROWS = 5

interface LiveTickerProps {
  /** Newest first, already filtered and held by the page. */
  events: readonly LiveEvent[]
  /** Events held back while paused or hovered. */
  pending: number
  held: boolean
  /** Ids above this one arrived a moment ago (fade in). */
  freshAbove: number | null
  /** Country highlighted on the map: its chips get a ring. */
  focus: string | null
  onFocusChange: (country: string | null) => void
  /** The pointer is over the ticker (the page holds it while it is read). */
  onHoverChange: (hovering: boolean) => void
  onResume: () => void
  /** "Refreshing every 10 s" when the socket is unavailable. */
  polling: boolean
  /** Shown instead of the chips (connecting, offline, nothing yet). */
  placeholder?: React.ReactNode
  className?: string
}

/**
 * The newest events as a calm ticker under the map. On wide screens, one row
 * of fixed-width chips: a new event fades in on the left while the others
 * glide right. On phones, the latest five as stacked rows. Each chip opens its
 * session; hovering one lights its source on the map.
 */
export function LiveTicker({
  events,
  pending,
  held,
  freshAbove,
  focus,
  onFocusChange,
  onHoverChange,
  onResume,
  polling,
  placeholder,
  className,
}: LiveTickerProps) {
  const narrow = useMediaQuery("(max-width: 639px)")

  const label = (
    <div className="flex shrink-0 items-center gap-2">
      {held && pending > 0 ? (
        <button
          type="button"
          onClick={onResume}
          className="inline-flex h-7 items-center gap-1.5 rounded-full border bg-surface-raised px-2.5 text-xs font-medium text-fg shadow-sm transition-colors duration-150 hover:bg-surface-hover"
        >
          <Play aria-hidden className="size-3" />
          {plural(pending, "new event")}
        </button>
      ) : (
        <span className="text-xs font-medium text-fg-muted">
          Latest
          {polling ? <span className="font-normal text-fg-subtle"> · every 10 s</span> : null}
        </span>
      )}
    </div>
  )

  const allLink = (
    <Link
      to="/attacks"
      className="inline-flex shrink-0 items-center gap-1 rounded-sm text-xs text-fg-muted transition-colors duration-150 hover:text-fg"
    >
      All attacks
      <ArrowRight aria-hidden className="size-3" />
    </Link>
  )

  if (narrow) {
    return (
      <div className={cn("border-t", className)}>
        <div className="flex items-center justify-between gap-3 px-4 pt-3 pb-1">
          {label}
          {allLink}
        </div>
        {placeholder ?? (
          <div
            role="list"
            aria-label="Latest events"
            onFocus={() => onHoverChange(true)}
            onBlur={() => onHoverChange(false)}
          >
            {events.slice(0, STACK_ROWS).map((e) => (
              <div
                key={e.id}
                role="listitem"
                className={cn(
                  "border-b last:border-b-0",
                  focus && e.country?.toUpperCase() === focus && "bg-surface-hover/60",
                )}
              >
                <LiveEventRow event={e} stacked isNew={freshAbove !== null && e.id > freshAbove} />
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div
      className={cn("flex h-13 items-center gap-3 border-t px-3 sm:px-4", className)}
      onPointerEnter={(e) => e.pointerType === "mouse" && onHoverChange(true)}
      onPointerLeave={() => onHoverChange(false)}
      onFocus={() => onHoverChange(true)}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget)) onHoverChange(false)
      }}
    >
      {label}
      <div className="relative h-9 min-w-0 flex-1 overflow-clip [mask-image:linear-gradient(to_right,black_calc(100%-48px),transparent)]">
        {placeholder ? (
          <div className="flex h-full items-center">{placeholder}</div>
        ) : (
          <ol aria-label="Latest events" className="h-full">
            {events.slice(0, ROW_CHIPS).map((e, i) => (
              <li
                key={e.id}
                className="absolute top-0 left-0 transition-transform duration-500 ease-out"
                style={{ transform: `translateX(${i * (CHIP_W + CHIP_GAP)}px)`, width: CHIP_W }}
              >
                <TickerChip
                  event={e}
                  isNew={freshAbove !== null && e.id > freshAbove}
                  lit={!!focus && e.country?.toUpperCase() === focus}
                  onFocusChange={onFocusChange}
                />
              </li>
            ))}
          </ol>
        )}
      </div>
      {allLink}
    </div>
  )
}

function TickerChip({
  event,
  isNew,
  lit,
  onFocusChange,
}: {
  event: LiveEvent
  isNew: boolean
  lit: boolean
  onFocusChange: (country: string | null) => void
}) {
  const { masked } = useIpMask()
  const meta = sensorMeta(event.sensor)
  const SensorIcon = meta?.icon
  const type = eventTypeMeta(event.type)
  const severe = isSevereEvent(event.type, event.tags)
  const summary = masked ? maskIpsInText(event.summary) : event.summary
  const ip = masked ? maskIp(event.src_ip) : event.src_ip
  const country = event.country?.toUpperCase() ?? null
  const label = meta?.label ?? event.sensor
  return (
    <Link
      to={sessionHref(event.session_id, event.ts)}
      aria-label={`${label}${severe ? " (severe)" : ""}: ${summary}, from ${ip}${country ? ` (${countryName(country) ?? country})` : ""}. Open session`}
      onPointerEnter={() => country && onFocusChange(country)}
      onPointerLeave={() => onFocusChange(null)}
      onFocus={() => country && onFocusChange(country)}
      onBlur={() => onFocusChange(null)}
      className={cn(
        "flex h-9 items-center gap-2 rounded-md border bg-surface px-2.5 text-xs transition-colors duration-150 hover:bg-surface-hover focus-visible:outline-offset-[-2px]",
        severe && "border-sev-severe/40",
        lit && "border-border-strong bg-surface-hover",
        isNew && "animate-fade-in [animation-duration:600ms]",
      )}
    >
      {SensorIcon ? (
        <SensorIcon aria-hidden className={cn("size-3.5 shrink-0", meta.text)} strokeWidth={2} />
      ) : null}
      <CountryFlag code={event.country} decorative />
      <span className="shrink-0 font-mono text-fg">{ip}</span>
      {severe ? (
        <type.icon aria-hidden className="size-3.5 shrink-0 text-sev-severe" strokeWidth={2} />
      ) : null}
      <span className="min-w-0 flex-1 truncate text-fg-muted">{summary}</span>
    </Link>
  )
}
