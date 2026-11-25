import { memo, useEffect, useRef, useState } from "react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { BarFill } from "@/components/bar-fill"
import { CountryFlag } from "@/components/country-flag"
import type { Leader, Leaders } from "@/components/map/activity"
import { SegmentedControl } from "@/components/segmented-control"
import { Card } from "@/components/ui/card"
import { useMediaQuery } from "@/hooks/use-media-query"
import { useReorderMotion } from "@/hooks/use-reorder-motion"
import { t, tk } from "@/i18n"
import { countryName, formatNumber, formatPercent, maskIp } from "@/lib/format"
import { addressFinding, networkFinding } from "@/lib/live-stats"
import { SENSOR_META, listPlain, type Sensor } from "@/lib/sensors"
import { cn } from "@/lib/utils"

/** Rows per ranking: short enough to read from across the room, and to fit beside the map. */
const ROWS = 6

interface Row {
  key: string
  /** Country used for the map highlight. */
  country: string | null
  href: string
  /** Plain-text name for the link label. */
  name: string
  main: React.ReactNode
  /** Secondary text (network, addresses), hidden first when space runs out. */
  aside?: React.ReactNode
  sensors: readonly Sensor[]
  events: number
  share: number
}

function SensorIcons({ sensors }: { sensors: readonly Sensor[] }) {
  return (
    <span className="hidden shrink-0 items-center gap-1 @[22rem]:flex">
      {sensors.slice(0, 3).map((s) => {
        const m = SENSOR_META[s]
        return <m.icon key={s} aria-hidden className={cn("size-3.5", m.text)} strokeWidth={2} />
      })}
    </span>
  )
}

function RankList({
  label,
  rows,
  focus,
  onFocusChange,
  empty,
}: {
  label: string
  rows: readonly Row[]
  focus: string | null
  onFocusChange: (country: string | null) => void
  empty: string
}) {
  // A new ranking glides into place instead of reshuffling at once.
  const listRef = useRef<HTMLOListElement>(null)
  useReorderMotion(
    listRef,
    rows.map((r) => r.key),
  )
  if (!rows.length) return <p className="py-6 text-sm text-fg-muted">{empty}</p>
  const max = Math.max(...rows.map((r) => r.share), 0.0001)
  return (
    <ol ref={listRef} aria-label={label} className="@container -mx-2 space-y-0.5">
      {rows.map((r, i) => {
        const sensorNames = listPlain(r.sensors.map((s) => SENSOR_META[s].label))
        return (
          <li key={r.key} data-flip={r.key}>
            <Link
              to={r.href}
              aria-label={t("live_leaders_row_aria", {
                name: r.name,
                count: r.events,
                share: formatPercent(r.share),
                hasSensors: sensorNames ? "yes" : "no",
                sensors: sensorNames,
              })}
              onPointerEnter={() => onFocusChange(r.country)}
              onPointerLeave={() => onFocusChange(null)}
              onFocus={() => onFocusChange(r.country)}
              onBlur={() => onFocusChange(null)}
              className={cn(
                "relative flex h-10 items-center gap-2.5 rounded-md px-2 text-sm transition-colors duration-150 hover:bg-surface-hover",
                focus && r.country === focus && "bg-surface-hover",
              )}
            >
              <span
                aria-hidden
                className="w-3 shrink-0 text-right text-2xs text-fg-subtle tabular-nums"
              >
                {i + 1}
              </span>
              <span className="flex min-w-0 flex-1 items-center gap-2">
                {r.main}
                {r.aside ? (
                  <span className="hidden min-w-0 truncate text-xs text-fg-subtle @[22rem]:inline">
                    {r.aside}
                  </span>
                ) : null}
              </span>
              <SensorIcons sensors={r.sensors} />
              <span className="w-10 shrink-0 text-right font-medium text-fg tabular-nums">
                {formatNumber(r.events)}
              </span>
              <span className="w-9 shrink-0 text-right text-xs text-fg-muted tabular-nums">
                {formatPercent(r.share)}
              </span>
              <span
                aria-hidden
                className="absolute inset-x-2 bottom-0.5 h-0.5 overflow-hidden rounded-full bg-border-strong/30"
              >
                <BarFill ratio={r.share / max} className="bg-fg-subtle/60" />
              </span>
            </Link>
          </li>
        )
      })}
    </ol>
  )
}

export type LeaderBoard = "addresses" | "networks"

const BOARDS = [
  { value: "addresses", labelKey: tk("live_leaders_addresses") },
  { value: "networks", labelKey: tk("live_leaders_networks") },
] as const

/** One row (40 px) and the 2 px between rows. */
const ROW_PX = 42
const MAX_ROWS = 10

/**
 * As many rows as the card has room for on desktop, where the page fits the window and the card
 * takes the height of its grid row; a fixed six on phones and tablets, where the page scrolls.
 */
function useFitRows(ref: React.RefObject<HTMLDivElement | null>, fit: boolean): number {
  const [rows, setRows] = useState(ROWS)
  useEffect(() => {
    const el = ref.current
    if (!fit || !el || typeof ResizeObserver === "undefined") return
    // The observer reports once on observe, then on every resize. 8 px: the list's top padding.
    const ro = new ResizeObserver(() =>
      setRows(Math.max(3, Math.min(MAX_ROWS, Math.floor((el.clientHeight - 8 + 2) / ROW_PX)))),
    )
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref, fit])
  return fit ? rows : ROWS
}

interface LiveLeadersProps {
  leaders: Leaders
  focus: string | null
  onFocusChange: (country: string | null) => void
  className?: string
}

/**
 * "Who is behind it right now", in one card beside the map: the busiest addresses or networks of
 * the last 15 minutes (a switch picks one; the countries are on the map itself), opening with its
 * finding. Every row opens the filtered Attacks view; hovering one lights its country on the map.
 */
export const LiveLeaders = memo(function LiveLeaders({
  leaders,
  focus,
  onFocusChange,
  className,
}: LiveLeadersProps) {
  const { masked } = useIpMask()
  const [board, setBoard] = useState<LeaderBoard>("addresses")
  const body = useRef<HTMLDivElement>(null)
  const desktop = useMediaQuery("(min-width: 64rem)")
  const count = useFitRows(body, desktop)

  const flag = (code: string | null) => <CountryFlag code={code} decorative />
  const rows: Row[] =
    board === "addresses"
      ? leaders.addresses.slice(0, count).map((l: Leader) => {
          const ip = masked ? maskIp(l.key) : l.key
          return {
            key: l.key,
            country: l.country,
            href: `/attacks?src_ip=${encodeURIComponent(l.key)}`,
            name: t("live_leaders_address_name", {
              ip,
              hasCountry: l.country ? "yes" : "no",
              country: l.country ? (countryName(l.country) ?? l.country) : "",
            }),
            main: (
              <>
                {flag(l.country)}
                <span className="shrink-0 font-mono text-xs text-fg">{ip}</span>
              </>
            ),
            aside: l.org,
            sensors: l.sensors,
            events: l.events,
            share: l.share,
          }
        })
      : leaders.networks.slice(0, count).map((l) => ({
          key: l.key,
          country: l.country,
          href: `/attacks?asn=${l.key}`,
          name: t("live_leaders_network_name", {
            org: l.org ?? t("live_leaders_unknown_network"),
            asn: l.key,
          }),
          main: (
            <>
              {flag(l.country)}
              <span className="min-w-0 truncate text-fg">
                {l.org ?? t("live_leaders_unknown_network")}
              </span>
            </>
          ),
          aside: <span className="font-mono">AS{l.key}</span>,
          sensors: l.sensors,
          events: l.events,
          share: l.share,
        }))

  return (
    <Card
      role="region"
      aria-labelledby="live-leaders-title"
      className={cn("min-h-0 overflow-hidden", className)}
    >
      <header className="space-y-1.5 px-4 pt-4 sm:px-5 sm:pt-5">
        <p className="type-eyebrow text-fg-muted">{t("live_leaders_window")}</p>
        <h2 id="live-leaders-title" className="type-card-title text-pretty text-fg">
          {board === "addresses"
            ? addressFinding(leaders.addresses[0], masked)
            : networkFinding(leaders.networks[0])}
        </h2>
      </header>
      <div className="px-4 pt-3 sm:px-5">
        <SegmentedControl
          label={t("live_leaders_rank_by")}
          value={board}
          onChange={setBoard}
          options={BOARDS.map((b) => ({ value: b.value, label: t(b.labelKey) }))}
          className="grid w-full grid-cols-2"
        />
      </div>
      <div ref={body} className="min-h-0 flex-1 overflow-hidden px-4 pt-2 sm:px-5">
        <RankList
          label={
            board === "addresses" ? t("live_leaders_top_addresses") : t("live_leaders_top_networks")
          }
          rows={rows}
          empty={
            board === "addresses"
              ? t("live_leaders_empty_addresses")
              : t("live_leaders_empty_networks")
          }
          focus={focus}
          onFocusChange={onFocusChange}
        />
      </div>
      <div className="pb-4 sm:pb-5" />
    </Card>
  )
})
