import { Check, Globe, Hash, Link2, Network, type LucideIcon } from "lucide-react"
import { t } from "@/i18n"
import { AnimatedNumber } from "@/components/animated-number"
import { Skeleton } from "@/components/ui/skeleton"
import {
  BLOCK_KINDS,
  HIGH_SCORE,
  KIND_META,
  LISTED_SCORE,
  type BlockKind,
  type DefendSummary,
} from "@/lib/defend"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

const ICONS: Record<BlockKind, LucideIcon> = {
  ip: Network,
  domain: Globe,
  url: Link2,
  hash: Hash,
}

/** One tile per kind. Each is also the kind filter: press it to narrow the list, again to clear. */
export function KindTiles({
  summary,
  kind,
  onSelect,
}: {
  summary: DefendSummary | undefined
  kind: BlockKind | null
  onSelect: (kind: BlockKind | null) => void
}) {
  return (
    <div role="group" aria-label={t("defend_tiles_filter")}
      className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {BLOCK_KINDS.map((k) => {
        const s = summary?.kinds.find((x) => x.kind === k)
        const Icon = ICONS[k]
        const selected = kind === k
        return (
          <button
            key={k}
            type="button"
            aria-pressed={selected}
            onClick={() => onSelect(selected ? null : k)}
            className={cn(
              "flex min-w-0 flex-col gap-3 rounded-lg border bg-surface p-4 text-left shadow-sm transition-colors duration-150 hover:bg-surface-hover/50 sm:p-5",
              selected && "border-border-strong bg-surface-raised ring-1 ring-border-strong",
            )}
          >
            <span className="flex items-center justify-between gap-2 type-eyebrow text-fg-muted">
              <span className="inline-flex items-center gap-1.5">
                <Icon aria-hidden className="size-3.5" strokeWidth={2} />
                {KIND_META[k].label}
              </span>
              {selected ? <Check aria-hidden className="size-3.5 text-fg" /> : null}
            </span>
            {s ? (
              <AnimatedNumber value={s.listed} format={formatNumber} className="type-kpi text-fg" />
            ) : (
              <Skeleton className="h-8 w-16" />
            )}
            <span className="text-xs text-fg-muted">
              {s ? (
                <>
                  {t("defend_tiles_scored", {
                    listedScore: LISTED_SCORE,
                    high: s.high,
                    highScore: HIGH_SCORE,
                  })}
                  <span className="block text-fg-subtle">
                    {t("defend_tiles_total", { total: s.total })}
                  </span>
                </>
              ) : (
                <span className="block h-8" />
              )}
            </span>
          </button>
        )
      })}
    </div>
  )
}
