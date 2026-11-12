import { Globe } from "lucide-react"
import type { ReactNode } from "react"
import { Link } from "react-router"
import { RelativeTime } from "@/components/relative-time"
import { Badge } from "@/components/ui/badge"
import { SeverityBadge } from "@/components/severity-badge"
import { TagBadge } from "@/components/tag-badge"
import { formatBytes, formatNumber } from "@/lib/format"
import {
  describeKind,
  familyLabel,
  isPlainWeb,
  NETWORK_CHECK,
  shortHash,
  type SampleItem,
} from "@/lib/samples"
import { cn } from "@/lib/utils"

export const SAMPLE_GRID = "md:grid-cols-[minmax(0,1fr)_6rem_5rem_5rem_6rem] md:gap-x-4"
/** The same grid with a narrow last column for a row action (the bundle toggle). */
export const SAMPLE_GRID_ACTION = "md:grid-cols-[minmax(0,1fr)_6rem_5rem_5rem_6rem_2rem] md:gap-x-4"

/**
 * One collected file. The row opens the sample page; the family and the rule names stay
 * independently clickable and open the filtered list.
 */
export function SampleRow({ item, action }: { item: SampleItem; action?: ReactNode }) {
  const to = `/malware/samples/${item.sha256}`
  const family = familyLabel(item.family, item.kind)
  // A plain web page is named once ("Web page"), not "Unknown" plus the kind.
  const plain = isPlainWeb(item)
  const what = plain ? describeKind(item) : `${family}, ${describeKind(item)}`
  return (
    <div
      className={cn(
        "group/row relative grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 px-4 py-3 transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
        action ? SAMPLE_GRID_ACTION : SAMPLE_GRID,
      )}
    >
      <Link
        to={to}
        aria-label={`${what}, ${formatBytes(item.size)}, hash ${shortHash(item.sha256)}`}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
      />
      <div className="min-w-0 space-y-1">
        <p className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1 text-sm text-fg">
          {item.severity === "severe" ? <SeverityBadge severity="severe" /> : null}
          {item.family ? (
            <Link
              to={`/malware?view=samples&family=${encodeURIComponent(item.family)}`}
              className="relative z-10 font-medium hover:underline"
            >
              {family}
            </Link>
          ) : (
            <span className="font-medium text-fg-muted">{family}</span>
          )}
          {plain ? null : <span className="text-fg-muted">{describeKind(item)}</span>}
          {item.origin === "network_verify" ? (
            <Badge
              variant="outline"
              title={NETWORK_CHECK.explain}
              className="font-sans text-fg-muted"
            >
              <Globe aria-hidden="true" />
              {NETWORK_CHECK.label} · {NETWORK_CHECK.qualifier}
              <span className="sr-only">. {NETWORK_CHECK.explain}</span>
            </Badge>
          ) : null}
        </p>
        <p className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-fg-muted">
          <span className="font-mono text-2xs" title={item.sha256}>
            {shortHash(item.sha256)}…
          </span>
          {item.yara.slice(0, 3).map((r) => (
            <span key={r} className="relative z-10">
              <TagBadge tag={r} href={`/malware?view=samples&yara=${encodeURIComponent(r)}`} />
            </span>
          ))}
        </p>
      </div>

      <RelativeTime iso={item.last_seen} className="relative z-10 text-xs md:hidden" />
      <p className="col-span-2 flex items-center gap-4 text-xs text-fg-muted tabular-nums md:hidden">
        <span>{formatBytes(item.size)}</span>
        <span>
          <span className="text-fg">{formatNumber(item.sources)}</span>{" "}
          {item.sources === 1 ? "URL" : "URLs"}
        </span>
        <span>
          <span className="text-fg">{formatNumber(item.sessions)}</span>{" "}
          {item.sessions === 1 ? "session" : "sessions"}
        </span>
        {action ? <span className="relative z-10 -my-1.5 ml-auto">{action}</span> : null}
      </p>

      <span className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatBytes(item.size)}
      </span>
      <span className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatNumber(item.sources)}
      </span>
      <span className="hidden text-right text-sm text-fg tabular-nums md:block">
        {formatNumber(item.sessions)}
      </span>
      <span className="relative z-10 hidden justify-self-end md:block">
        <RelativeTime iso={item.last_seen} className="text-xs" />
      </span>
      {action ? (
        <span className="relative z-10 hidden justify-self-end md:block">{action}</span>
      ) : null}
    </div>
  )
}
