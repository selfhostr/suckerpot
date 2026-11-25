import { Waves } from "lucide-react"
import { t } from "@/i18n"
import { formatNumber } from "@/lib/format"
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
      title={t("flood_badge_title", { count: connections })}
      className={cn(
        "inline-flex h-(--chip) shrink-0 items-center gap-1.5 rounded-sm border border-border-strong px-2 text-xs font-medium text-fg-muted",
        className,
      )}
    >
      <Waves aria-hidden className="size-3.5" strokeWidth={2} />
      <span>{t("flood_badge_word")}</span>
      <span aria-hidden className="font-mono text-fg tabular-nums">
        x{formatNumber(connections)}
      </span>
      <span className="sr-only">{t("flood_badge_sr", { count: connections })}</span>
    </span>
  )
}
