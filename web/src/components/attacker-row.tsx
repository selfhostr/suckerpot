import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { CountryFlag } from "@/components/country-flag"
import { IPChip } from "@/components/ip-chip"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SeverityBadge } from "@/components/severity-badge"
import { TagBadge } from "@/components/tag-badge"
import type { Attacker } from "@/lib/api"
import {
  attackerOrigin,
  attackerSeverity,
  describeAttacker,
  describeAttackerText,
} from "@/lib/describe-attacker"
import { countryName, formatNumber, maskIpsInText } from "@/lib/format"
import { cn } from "@/lib/utils"

/**
 * Desktop columns: IP address, country, what it did, tags, sessions, last seen; from xl the
 * network and the event count join in.
 */
export const ATTACKER_GRID =
  "md:grid-cols-[9.5rem_9rem_minmax(14rem,1fr)_minmax(0,auto)_4.5rem_6rem] md:gap-x-4 xl:grid-cols-[9.5rem_9rem_12rem_minmax(18rem,1fr)_minmax(0,auto)_4.5rem_4.5rem_6rem]"

/** One attacker as one line. The row opens the profile; chips and flags open filtered lists. */
export function AttackerRow({
  attacker: a,
  className,
}: {
  attacker: Attacker
  className?: string
}) {
  const { masked } = useIpMask()
  const severity = attackerSeverity(a)
  const flagged = severity === "warning" || severity === "severe"
  const origin = attackerOrigin(a)
  const label = describeAttackerText(a)

  const flag = a.country ? (
    <Link
      to={`/attackers?country=${encodeURIComponent(a.country)}`}
      className="relative z-10 inline-flex"
    >
      <CountryFlag code={a.country} />
    </Link>
  ) : null

  return (
    <div
      className={cn(
        "group/row relative grid grid-cols-1 items-center gap-y-1.5 px-4 py-3 transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
        ATTACKER_GRID,
        className,
      )}
    >
      <Link
        to={`/attackers/${encodeURIComponent(a.ip)}`}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
        aria-label={masked ? maskIpsInText(label) : label}
      />
      <div className="flex min-w-0 items-center gap-2 md:contents">
        <div className="flex min-w-0 items-center gap-2">
          <IPChip ip={a.ip} variant="ghost" className="relative z-10 ml-0 md:-ml-1.5" />
          <span className="md:hidden">{flag}</span>
        </div>
        <span className="ml-auto flex shrink-0 items-center gap-2 md:hidden">
          {flagged ? <SeverityBadge severity={severity} iconOnly /> : null}
          <RelativeTime iso={a.last_seen} className="relative z-10 text-xs" />
        </span>
      </div>

      <div className="hidden min-w-0 items-center gap-1.5 text-xs text-fg-muted md:flex">
        {flag ? (
          <>
            {flag}
            <span>{countryName(a.country) ?? a.country}</span>
          </>
        ) : (
          <>
            <CountryFlag code={null} />
            <span>Unknown</span>
          </>
        )}
      </div>

      <div className="hidden min-w-0 text-xs text-fg-muted xl:block">
        {a.asn !== null ? (
          <Link
            to={`/attackers?asn=${a.asn}`}
            className="relative z-10 block hover:text-fg"
            title={`AS${a.asn}`}
          >
            <span className="block font-mono text-2xs text-fg-subtle">AS{a.asn}</span>
            {a.org ?? "Unknown network"}
          </Link>
        ) : (
          "Unknown network"
        )}
      </div>

      <div className="flex min-w-0 items-start gap-2.5 md:items-center">
        <p className="min-w-0 text-sm text-fg">
          {origin ? <span className="text-fg-muted md:hidden">{origin} — </span> : null}
          <span className="md:first-letter:uppercase">{describeAttacker(a)}</span>
        </p>
      </div>

      <div className="flex min-w-0 flex-wrap items-center gap-1.5 md:flex-nowrap md:justify-end md:overflow-hidden">
        {a.sensors.slice(0, 3).map((s) => (
          <SensorBadge key={s} sensor={s} variant="dot" className="shrink-0" />
        ))}
        {a.sensors.length > 3 ? (
          <span
            className="shrink-0 text-xs text-fg-subtle tabular-nums"
            title={a.sensors.slice(3).join(", ")}
          >
            +{a.sensors.length - 3}
          </span>
        ) : null}
        {a.tags.slice(0, 2).map((t) => (
          <TagBadge
            key={t}
            tag={t}
            href={`/attackers?tag=${encodeURIComponent(t)}`}
            className="z-10"
          />
        ))}
        {flagged ? (
          <SeverityBadge severity={severity} iconOnly className="z-10 hidden md:inline-flex" />
        ) : null}
      </div>

      <span className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatNumber(a.sessions)}
      </span>
      <span className="hidden text-right text-sm text-fg tabular-nums xl:block">
        {formatNumber(a.events)}
      </span>

      <div className="hidden justify-self-end md:block">
        <RelativeTime iso={a.last_seen} className="relative z-10 text-xs" />
      </div>
    </div>
  )
}
