import { Waves } from "lucide-react"
import { formatNumber, plural } from "@/lib/format"
import { cn } from "@/lib/utils"

/**
 * Marks a flood group: one row for many plain connections of one address in one hour. Neutral on
 * purpose (a flood is volume, not a payload, so it never uses red), and it says it three ways:
 * an icon, the word "flood" and the count ("x812"), so no meaning rests on colour.
 */
export function FloodBadge({
  connections,
  className,
}: {
  connections: number
  className?: string
}) {
  return (
    <span
      title={`${plural(connections, "connection")} from one address in one hour, shown as one row`}
      className={cn(
        "inline-flex h-6 shrink-0 items-center gap-1.5 rounded-sm border border-border-strong px-2 text-2xs font-medium text-fg-muted",
        className,
      )}
    >
      <Waves aria-hidden className="size-3" strokeWidth={2} />
      <span>flood</span>
      <span aria-hidden className="font-mono text-fg tabular-nums">
        x{formatNumber(connections)}
      </span>
      <span className="sr-only">of {plural(connections, "connection")}</span>
    </span>
  )
}
