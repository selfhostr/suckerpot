import { Link } from "react-router"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SeverityBadge } from "@/components/severity-badge"
import { StageTrail } from "@/components/campaigns/stage-trail"
import { CountryFlag } from "@/components/country-flag"
import { describeScale, statusLabel, type Campaign } from "@/lib/campaigns"
import { cn } from "@/lib/utils"

/** The grid shared by the list header and its rows (desktop). */
export const CAMPAIGN_GRID = "md:grid-cols-[minmax(0,1.6fr)_10.5rem_minmax(0,1fr)_6rem] md:gap-x-5"

function StatusChip({ status }: { status: Campaign["status"] }) {
  const active = status === "active"
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
      <span
        aria-hidden
        className={cn(
          "size-1.5 rounded-full",
          active ? "bg-fg" : "border border-fg-subtle bg-transparent",
        )}
      />
      {statusLabel(status)}
    </span>
  )
}

/**
 * One campaign as one story line: severity and name, the playbook trail, the scale in words,
 * where it hit and when it was last seen. The whole row opens the campaign.
 */
export function CampaignRow({
  campaign: c,
  className,
}: {
  campaign: Campaign
  className?: string
}) {
  return (
    <div
      className={cn(
        "group/row relative grid grid-cols-1 items-center gap-y-2 px-4 py-3.5 transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
        CAMPAIGN_GRID,
        className,
      )}
    >
      <Link
        to={`/campaigns/${c.id}`}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
        aria-label={`${c.name}: ${describeScale(c)}`}
      />
      <div className="min-w-0 space-y-1">
        <div className="flex min-w-0 items-center gap-2">
          <SeverityBadge severity={c.severity} iconOnly />
          <h3 className="truncate type-subtitle text-fg">{c.name}</h3>
        </div>
        <p className="line-clamp-2 text-xs text-fg-muted md:truncate">
          {describeScale(c)}
          {c.countries.length > 0 ? (
            <span className="ml-2 inline-flex items-center gap-1 align-middle">
              {c.countries.slice(0, 4).map((code) => (
                <CountryFlag key={code} code={code} />
              ))}
            </span>
          ) : null}
        </p>
      </div>

      <StageTrail stages={c.stages} className="pointer-events-none md:justify-self-start" />

      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {c.sensors.slice(0, 3).map((s) => (
          <SensorBadge key={s} sensor={s} />
        ))}
        {c.sensors.length > 3 ? (
          <span className="text-xs text-fg-subtle">+{c.sensors.length - 3}</span>
        ) : null}
      </div>

      <div className="flex items-center justify-between gap-3 md:flex-col md:items-end md:gap-1">
        <StatusChip status={c.status} />
        <RelativeTime iso={c.last_seen} className="relative z-10 text-xs" />
      </div>
    </div>
  )
}
