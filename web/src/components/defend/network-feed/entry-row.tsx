import { Eye, HandHelping } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { t } from "@/i18n"
import { CopyButton } from "@/components/defend/copy-button"
import { IPChip } from "@/components/ip-chip"
import { TagBadge } from "@/components/tag-badge"
import { Badge } from "@/components/ui/badge"
import { maskIpsInText } from "@/lib/format"
import { formatDay } from "@/lib/network"
import { categoryLabel, SEVERE_CATEGORIES, type FeedEntry } from "@/lib/network-feed"

export const FEED_GRID =
  "md:grid md:grid-cols-[minmax(0,2fr)_minmax(0,2.2fr)_minmax(0,1.6fr)_11rem] md:items-center md:gap-x-4"

function Value({ entry }: { entry: FeedEntry }) {
  const { masked } = useIpMask()
  if (entry.family !== null) {
    // Only an address that also reached this sensor has a local page to open.
    return <IPChip ip={entry.value} variant="ghost" href={entry.seen_here ? undefined : null} />
  }
  const shown = masked ? maskIpsInText(entry.value) : entry.value
  return (
    <span className="group/row flex min-w-0 items-center gap-1">
      <span title={shown} className="min-w-0 truncate font-mono text-xs text-fg">
        {shown}
      </span>
      {masked ? null : (
        <CopyButton text={entry.value} label={t("defend_copy_named", { name: entry.value })} />
      )}
    </span>
  )
}

/** Malware hosts and command servers carry the severe marker: a diamond and a word, not colour. */
function CategoryBadge({ category }: { category: string }) {
  const severe = SEVERE_CATEGORIES.includes(category)
  return (
    <li
      className={
        severe
          ? "inline-flex h-(--chip) items-center gap-1.5 rounded-sm border border-sev-severe/40 px-2 text-xs font-medium text-fg"
          : "inline-flex h-(--chip) items-center rounded-sm border border-border-strong px-2 text-xs font-medium text-fg-muted"
      }
    >
      {severe ? (
        <span aria-hidden className="size-1.5 rotate-45 rounded-[1px] bg-sev-severe" />
      ) : null}
      {categoryLabel(category)}
      {severe ? <span className="sr-only"> {t("nfeed_severe")}</span> : null}
    </li>
  )
}

export function EntryRow({ entry }: { entry: FeedEntry }) {
  return (
    <div className={`flex flex-col gap-2 px-4 py-3.5 sm:px-5 md:py-3 ${FEED_GRID}`}>
      <div className="min-w-0 space-y-1">
        <Value entry={entry} />
        <p className="text-2xs text-fg-subtle">
          {entry.tier === "high" ? t("nfeed_tier_high") : t("nfeed_tier_standard")}
          {entry.family ? ` · IPv${entry.family}` : ` · ${t("nfeed_host_name")}`}
          {entry.families.length > 0 ? ` · ${entry.families.join(", ")}` : ""}
        </p>
      </div>
      <div className="min-w-0 space-y-1.5">
        <ul aria-label={t("nfeed_categories")} className="flex flex-wrap gap-1.5">
          {entry.categories.map((c) => (
            <CategoryBadge key={c} category={c} />
          ))}
        </ul>
        {entry.tags.length > 0 ? (
          <ul aria-label={t("nfeed_tags")} className="flex flex-wrap gap-1.5">
            {entry.tags.map((tag) => (
              <li key={tag}>
                <TagBadge tag={tag} />
              </li>
            ))}
          </ul>
        ) : null}
      </div>
      <dl className="grid grid-cols-3 gap-x-3 text-2xs text-fg-muted md:grid-cols-1 md:gap-y-0.5">
        <div className="md:flex md:gap-1.5">
          <dt className="text-fg-subtle md:w-14">{t("nfeed_first_seen")}</dt>
          <dd className="tabular-nums">{formatDay(entry.first_seen)}</dd>
        </div>
        <div className="md:flex md:gap-1.5">
          <dt className="text-fg-subtle md:w-14">{t("nfeed_last_seen")}</dt>
          <dd className="tabular-nums">{formatDay(entry.last_seen)}</dd>
        </div>
        <div className="md:flex md:gap-1.5">
          <dt className="text-fg-subtle md:w-14">{t("nfeed_expires")}</dt>
          <dd className="tabular-nums">{formatDay(entry.expires)}</dd>
        </div>
      </dl>
      <div className="flex flex-wrap items-start gap-1.5 md:justify-end">
        {entry.seen_here ? (
          <Badge variant="outline" className="text-fg">
            <Eye aria-hidden />
            {t("nfeed_seen_here")}
          </Badge>
        ) : null}
        {entry.helped ? (
          <Badge variant="outline" className="text-fg">
            <HandHelping aria-hidden />
            {t("nfeed_you_helped")}
          </Badge>
        ) : null}
      </div>
    </div>
  )
}
