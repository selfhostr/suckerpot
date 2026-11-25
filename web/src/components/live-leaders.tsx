import { memo } from "react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { CountryFlag } from "@/components/country-flag"
import { FindingCard } from "@/components/finding-card"
import type { Leader, Leaders, Source } from "@/components/map/activity"
import { countryName, formatNumber, formatPercent, maskIp, plural } from "@/lib/format"
import { addressFinding, countryFinding, networkFinding } from "@/lib/live-stats"
import { SENSOR_META, type Sensor } from "@/lib/sensors"
import { cn } from "@/lib/utils"

/** Rows per ranking: short enough to read from across the room. */
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
    <span className="hidden shrink-0 items-center gap-1 min-[400px]:flex">
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
  if (!rows.length) return <p className="py-6 text-sm text-fg-muted">{empty}</p>
  const max = Math.max(...rows.map((r) => r.share), 0.0001)
  return (
    <ol aria-label={label} className="-mx-2 space-y-0.5">
      {rows.map((r, i) => {
        const sensorNames = r.sensors.map((s) => SENSOR_META[s].label).join(", ")
        return (
          <li key={r.key}>
            <Link
              to={r.href}
              aria-label={`${r.name}: ${plural(r.events, "event")}, ${formatPercent(r.share)}${sensorNames ? `, on ${sensorNames}` : ""}. Open these attacks`}
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
                  <span className="hidden min-w-0 truncate text-xs text-fg-subtle min-[1800px]:inline sm:inline lg:hidden">
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
                className="absolute inset-x-2 bottom-0.5 h-0.5 rounded-full bg-border-strong/30"
              >
                <span
                  className="block h-full rounded-full bg-fg-subtle/60 transition-[width] duration-300"
                  style={{ width: `${(r.share / max) * 100}%` }}
                />
              </span>
            </Link>
          </li>
        )
      })}
    </ol>
  )
}

interface LiveLeadersProps {
  leaders: Leaders
  /** Located sources (countries), busiest first. */
  sources: readonly Source[]
  /** Events in the window, located or not. */
  windowEvents: number
  unlocated: number
  focus: string | null
  onFocusChange: (country: string | null) => void
  className?: string
}

/**
 * "Who is hitting us right now": the busiest addresses, countries and networks
 * of the last 15 minutes, each card opening with its finding. Every row opens
 * the filtered Attacks view; hovering one lights its country on the map.
 */
export const LiveLeaders = memo(function LiveLeaders({
  leaders,
  sources,
  windowEvents,
  unlocated,
  focus,
  onFocusChange,
  className,
}: LiveLeadersProps) {
  const { masked } = useIpMask()

  const flag = (code: string | null) => <CountryFlag code={code} decorative />
  const addresses: Row[] = leaders.addresses.slice(0, ROWS).map((l: Leader) => {
    const ip = masked ? maskIp(l.key) : l.key
    return {
      key: l.key,
      country: l.country,
      href: `/attacks?src_ip=${encodeURIComponent(l.key)}`,
      name: `${ip}${l.country ? ` (${countryName(l.country) ?? l.country})` : ""}`,
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
  const countries: Row[] = sources.slice(0, ROWS).map((s) => {
    const name = countryName(s.country) ?? s.country
    return {
      key: s.country,
      country: s.country,
      href: `/attacks?country=${s.country}`,
      name,
      main: (
        <>
          {flag(s.country)}
          <span className="min-w-0 truncate text-fg">{name}</span>
        </>
      ),
      aside: plural(s.ips, "address", "addresses"),
      sensors: s.sensors,
      events: s.events,
      share: windowEvents ? s.events / windowEvents : 0,
    }
  })
  const networks: Row[] = leaders.networks.slice(0, ROWS).map((l) => ({
    key: l.key,
    country: l.country,
    href: `/attacks?asn=${l.key}`,
    name: `${l.org ?? "Unknown network"} (AS${l.key})`,
    main: (
      <>
        {flag(l.country)}
        <span className="min-w-0 truncate text-fg">{l.org ?? "Unknown network"}</span>
      </>
    ),
    aside: <span className="font-mono">AS{l.key}</span>,
    sensors: l.sensors,
    events: l.events,
    share: l.share,
  }))

  const common = { focus, onFocusChange }
  return (
    <section
      aria-label="Top attackers in the last 15 minutes"
      className={cn("grid gap-4 lg:grid-cols-3", className)}
    >
      <FindingCard
        eyebrow="Top addresses · 15 min"
        className="min-w-0"
        finding={addressFinding(leaders.addresses[0], masked)}
        bodyClassName="pt-3"
      >
        <RankList
          label="Top addresses"
          rows={addresses}
          empty="No events in the last 15 minutes."
          {...common}
        />
      </FindingCard>
      <FindingCard
        eyebrow="Top countries · 15 min"
        className="min-w-0"
        finding={countryFinding(sources[0], windowEvents)}
        bodyClassName="pt-3"
      >
        <RankList
          label="Top countries"
          rows={countries}
          empty="No located events in the last 15 minutes."
          {...common}
        />
        {unlocated ? (
          <p className="mt-2 text-xs text-fg-subtle">
            Plus {plural(unlocated, "event")} without a known country.
          </p>
        ) : null}
      </FindingCard>
      <FindingCard
        eyebrow="Top networks · 15 min"
        className="min-w-0"
        finding={networkFinding(leaders.networks[0])}
        bodyClassName="pt-3"
      >
        <RankList
          label="Top networks"
          rows={networks}
          empty="No known network in the last 15 minutes."
          {...common}
        />
      </FindingCard>
    </section>
  )
})
