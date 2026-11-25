import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { useLayoutEffect, useRef, useState } from "react"
import { CountryFlag } from "@/components/country-flag"
import { formatNumber } from "@/lib/format"
import { formatMonth, memberName, TIER_LABEL, type NetworkMember } from "@/lib/network"
import { cn } from "@/lib/utils"

const ROW_H = 60
const COLS = "sm:grid-cols-[minmax(0,1.4fr)_9rem_6rem_8rem_minmax(0,1.2fr)]"

/** Seven dots, one per day of the last full week; filled when the sensor sent a batch. */
function ActiveDots({ days }: { days: number }) {
  return (
    <span
      className="inline-flex items-center gap-1"
      role="img"
      aria-label={`Active ${days} of 7 days last week`}
    >
      {Array.from({ length: 7 }, (_, i) => (
        <span
          key={i}
          aria-hidden
          className={cn(
            "size-2 rounded-full border border-fg-subtle",
            i < days ? "bg-fg-muted" : "bg-transparent",
          )}
        />
      ))}
      <span aria-hidden className="ml-1 text-xs text-fg-muted tabular-nums">
        {days}/7
      </span>
    </span>
  )
}

/** Five steps for the tier, plus its label in words: never the bar alone. */
function TierMeter({ tier }: { tier: NetworkMember["tier"] }) {
  return (
    <span className="flex min-w-0 items-center gap-2">
      <span
        role="meter"
        aria-label="Items sent last week"
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={tier}
        aria-valuetext={TIER_LABEL[tier]}
        className="flex shrink-0 items-center gap-0.5"
      >
        {Array.from({ length: 4 }, (_, i) => (
          <span
            key={i}
            aria-hidden
            className={cn("h-3 w-1.5 rounded-[2px]", i < tier ? "bg-fg-muted" : "bg-surface-hover")}
          />
        ))}
      </span>
      <span className="truncate text-xs text-fg-muted">{TIER_LABEL[tier]}</span>
    </span>
  )
}

export function MemberRow({ m, self = false }: { m: NetworkMember; self?: boolean }) {
  return (
    <div
      className={cn(
        "grid h-full grid-cols-[1fr_auto] items-center gap-x-4 gap-y-0.5 px-4 sm:px-5",
        COLS,
      )}
    >
      <span className="min-w-0 truncate text-sm font-medium text-fg">
        {memberName(m)}
        {m.pseudonym ? (
          <span className="ml-2 font-mono text-2xs font-normal text-fg-subtle">
            {m.fingerprint}
          </span>
        ) : null}
        {self ? (
          <span className="ml-2 rounded-sm border px-1.5 py-px text-2xs font-medium text-fg-muted">
            You
          </span>
        ) : null}
      </span>
      <span className="justify-self-end text-xs sm:justify-self-start">
        {m.country ? (
          <CountryFlag code={m.country} showName />
        ) : (
          <span className="text-fg-muted">
            <span aria-hidden>—</span>
            <span className="sr-only">Country not shown</span>
          </span>
        )}
      </span>
      <span className="hidden text-xs text-fg-muted sm:block">{formatMonth(m.member_since)}</span>
      <span className="hidden sm:block">
        <ActiveDots days={m.active_days} />
      </span>
      <span className="hidden sm:block">
        <TierMeter tier={m.tier} />
      </span>
      <span className="col-span-2 flex items-center justify-between gap-3 sm:hidden">
        <ActiveDots days={m.active_days} />
        <span className="text-xs text-fg-muted">{TIER_LABEL[m.tier]}</span>
      </span>
    </div>
  )
}

/**
 * The members, sorted by name (never by activity: there is no ranking). Virtualised: the list
 * can grow to hundreds without slowing the page.
 */
export function MembersList({
  members,
  self,
}: {
  members: readonly NetworkMember[]
  /** This node's fingerprint, so its own row says "You". */
  self?: string | null
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [scrollMargin, setScrollMargin] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const measure = () => setScrollMargin(el.getBoundingClientRect().top + window.scrollY)
    measure()
    if (typeof ResizeObserver === "undefined") return
    const ro = new ResizeObserver(measure)
    ro.observe(document.body)
    return () => ro.disconnect()
  }, [])
  const v = useWindowVirtualizer({
    count: members.length,
    estimateSize: () => ROW_H,
    overscan: 8,
    scrollMargin,
  })
  return (
    <div>
      <div
        aria-hidden
        className={cn(
          "sticky top-14 z-10 hidden border-t bg-surface px-5 py-2 text-xs font-medium text-fg-muted sm:grid",
          COLS,
        )}
      >
        <span>Member</span>
        <span>Country</span>
        <span>Since</span>
        <span>Active last week</span>
        <span>Items sent last week</span>
      </div>
      <div
        ref={ref}
        role="list"
        aria-label={`Members, ${formatNumber(members.length)} shown`}
        className="border-t"
      >
        <div className="relative w-full" style={{ height: v.getTotalSize() }}>
          {v.getVirtualItems().map((item) => {
            const m = members[item.index]
            if (!m) return null
            return (
              <div
                key={m.fingerprint}
                role="listitem"
                className="absolute top-0 left-0 w-full border-b"
                style={{
                  height: item.size,
                  transform: `translateY(${item.start - scrollMargin}px)`,
                }}
              >
                <MemberRow m={m} self={!!self && m.fingerprint === self} />
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
