import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SeverityBadge } from "@/components/severity-badge"
import { formatNumber, maskIpsInText, plural } from "@/lib/format"
import type { ScriptItem } from "@/lib/scripts"
import { cn } from "@/lib/utils"

export const SCRIPT_GRID = "md:grid-cols-[minmax(0,1fr)_5rem_5rem_6rem] md:gap-x-4"

function NewPill() {
  return (
    <span className="inline-flex h-(--chip) items-center rounded-sm border border-border-strong px-2 text-xs font-medium text-fg">
      New this week
    </span>
  )
}

/** One script as one story: what it does, a glimpse of the commands, who ran it and when. */
export function ScriptRow({ item }: { item: ScriptItem }) {
  const { masked } = useIpMask()
  const summary = item.summary ?? "No built-in explanation for this script yet."
  return (
    <div
      className={cn(
        "group/row relative grid grid-cols-1 items-center gap-y-2 px-4 py-3.5 transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
        SCRIPT_GRID,
      )}
    >
      <Link
        to={`/scripts/${item.id}`}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
        aria-label={`Script ${item.id}: ${summary}`}
      />
      <div className="min-w-0 space-y-1.5">
        <p
          className={cn(
            "text-sm text-pretty normal-nums",
            item.summary ? "text-fg" : "text-fg-muted",
          )}
        >
          {summary}
        </p>
        <pre
          aria-label="First commands"
          className="max-w-full overflow-hidden font-mono text-xs leading-5 text-ellipsis whitespace-pre text-fg-subtle"
        >
          {item.preview
            .map((l) => (masked ? maskIpsInText(l) : l))
            .map((l) => (l.length > 90 ? `${l.slice(0, 89)}…` : l))
            .join("\n")}
        </pre>
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-fg-muted">
          {item.risk ? <SeverityBadge severity={item.risk} /> : null}
          {item.is_new ? <NewPill /> : null}
          {item.sensors.map((s) => (
            <SensorBadge key={s} sensor={s} variant="dot" />
          ))}
          <span>{plural(item.line_count, "step")}</span>
          {item.campaign_name ? (
            <Link
              to={`/campaigns/${item.campaign_id}`}
              className="relative z-10 rounded-sm border border-border-strong px-1.5 py-0.5 text-2xs text-fg-muted normal-nums transition-colors hover:border-fg-subtle hover:text-fg"
            >
              Campaign: {item.campaign_name}
            </Link>
          ) : null}
        </p>
      </div>
      <p className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatNumber(item.sessions)}
      </p>
      <p className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatNumber(item.sources)}
      </p>
      <RelativeTime iso={item.last_seen} className="hidden text-right text-xs md:block" />
      <p className="flex items-center gap-4 text-xs text-fg-muted tabular-nums md:hidden">
        <span>
          <span className="text-fg">{formatNumber(item.sessions)}</span> sessions
        </span>
        <span>
          <span className="text-fg">{formatNumber(item.sources)}</span> addresses
        </span>
        <RelativeTime iso={item.last_seen} className="relative z-10 ml-auto text-xs" />
      </p>
    </div>
  )
}
