import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { t } from "@/i18n"
import { RelativeTime } from "@/components/relative-time"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber, maskIpsInText } from "@/lib/format"
import type { NewField, NewItem } from "@/lib/trends"

const LINKS: Partial<Record<NewField, (v: string) => string>> = {
  asn: (v) => `/attackers?asn=${encodeURIComponent(v)}`,
}

interface NewListProps {
  field: NewField
  items: readonly NewItem[]
  loading?: boolean
  empty: string
}

/** Values never seen before the window, with when they first showed up. */
export function NewList({ field, items, loading, empty }: NewListProps) {
  const { masked } = useIpMask()
  if (loading)
    return (
      <div role="status" aria-label={t("common_loading")} className="space-y-3">
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    )
  if (items.length === 0) return <p className="py-4 text-sm text-fg-muted">{empty}</p>
  const link = LINKS[field]
  return (
    <>
      <div aria-hidden className="flex gap-3 border-b pb-2 type-column text-fg-subtle">
        <span className="flex-1">{t("trends_new_col_value")}</span>
        <span>{t("trends_new_col_seen")}</span>
        <span className="w-24 text-right">{t("trends_new_col_first_seen")}</span>
      </div>
      <ul aria-label={t("trends_new_list_label")} className="divide-y">
        {items.map((i) => {
          const shown = masked ? maskIpsInText(i.value) : i.value
          const label = (
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={shown}>
              {field === "asn" ? `AS${shown}` : shown}
            </span>
          )
          return (
            <li key={i.value} className="flex items-center gap-3 py-2">
              {link ? (
                <Link to={link(i.value)} className="min-w-0 flex-1 hover:underline">
                  {label}
                </Link>
              ) : (
                label
              )}
              <span className="text-sm text-fg tabular-nums">{formatNumber(i.count)}</span>
              <span className="w-24 shrink-0 text-right text-xs">
                <span className="sr-only">{t("trends_new_col_first_seen")} </span>
                <RelativeTime iso={i.first_seen} />
              </span>
            </li>
          )
        })}
      </ul>
    </>
  )
}
