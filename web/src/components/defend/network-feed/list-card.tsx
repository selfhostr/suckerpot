import { Check, ChevronDown, Globe, LogIn, LogOut, Star, type LucideIcon } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { t, tk } from "@/i18n"
import { StatTile } from "@/components/stat-tile"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useCopy } from "@/hooks/use-copy"
import {
  FORMAT_LABEL,
  formatsOf,
  LIST_META,
  type FeedList,
  type FeedListId,
  type FeedTier,
} from "@/lib/network-feed"

const ICON: Record<FeedListId, LucideIcon> = {
  outbound: LogOut,
  inbound: LogIn,
  "outbound-domains": Globe,
}

const TIERS: { tier: FeedTier; labelKey: string }[] = [
  { tier: "standard", labelKey: tk("nfeed_copy_every") },
  { tier: "high", labelKey: tk("nfeed_copy_high") },
]

function CopyMenu({ list, title }: { list: FeedList; title: string }) {
  const { copy } = useCopy()
  const [done, setDone] = useState<string | null>(null)
  const groups = TIERS.map((x) => ({ ...x, files: formatsOf(list, x.tier) })).filter(
    (g) => g.files.length > 0,
  )
  if (groups.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            aria-label={t("nfeed_copy_aria", { title: title.toLowerCase() })}
          >
            {t("nfeed_copy_url")}
            <ChevronDown aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="max-h-80 w-64 overflow-y-auto">
          {groups.map((g, i) => (
            <DropdownMenuGroup key={g.tier}>
              {i > 0 ? <DropdownMenuSeparator /> : null}
              <DropdownMenuLabel>{t(g.labelKey)}</DropdownMenuLabel>
              {g.files.map((f) => (
                <DropdownMenuItem
                  key={f.name}
                  onSelect={() => {
                    void copy(f.url)
                    setDone(
                      g.tier === "high"
                        ? t("nfeed_copied_high", { format: FORMAT_LABEL[f.format] })
                        : FORMAT_LABEL[f.format],
                    )
                  }}
                >
                  {FORMAT_LABEL[f.format]}
                </DropdownMenuItem>
              ))}
            </DropdownMenuGroup>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      <span role="status" className="text-xs text-fg-muted">
        {done ? (
          <span className="inline-flex items-center gap-1">
            <Check aria-hidden className="size-3.5" />
            {t("nfeed_copied", { what: done })}
          </span>
        ) : (
          t("nfeed_copy_hint")
        )}
      </span>
    </div>
  )
}

/** One community list: what it blocks, how big it is, and its addresses to copy. */
export function ListCard({
  list,
  mirrorLink,
}: {
  list: FeedList
  /** Show the link to the verified copy served by this dashboard (administrators). */
  mirrorLink: boolean
}) {
  const meta = LIST_META[list.id]
  const Icon = ICON[list.id]
  return (
    <Card role="group" aria-label={t("nfeed_list_group", { title: meta.title })} className="gap-4 p-4 sm:p-5">
      <header className="space-y-1.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="inline-flex items-center gap-2 type-card-title text-fg">
            <Icon aria-hidden className="size-4 text-fg-muted" strokeWidth={1.85} />
            {meta.title}
          </h3>
          {meta.startHere ? (
            <Badge variant="outline" className="text-fg">
              <Star aria-hidden />
              {t("nfeed_start_here")}
            </Badge>
          ) : null}
        </div>
        <p className="text-sm font-medium text-fg">{meta.directionLabel}</p>
        <p className="text-sm text-pretty text-fg-muted">{meta.purpose}</p>
      </header>
      {/* Pushed to the bottom so the figures line up across cards of different text length. */}
      <div className="mt-auto grid grid-cols-2 gap-3">
        <StatTile label={t("blocklists_entries")} value={list.entries} />
        <StatTile label={t("nfeed_tier_high")} value={list.high} />
      </div>
      <p className="text-xs text-fg-muted">
        {list.seen_here > 0 ? (
          <Link
            to={`/defend/blocklists?tab=network&list=${list.id}&seen_here=1`}
            className="text-fg underline-offset-2 hover:underline"
          >
            {t("nfeed_card_seen", { count: list.seen_here })}
          </Link>
        ) : (
          t("nfeed_card_none_seen")
        )}
        {list.helped !== null ? ` · ${t("nfeed_card_helped", { count: list.helped })}` : ""}
      </p>
      <CopyMenu list={list} title={meta.title} />
      {mirrorLink ? (
        <Link
          to="/settings?tab=feeds"
          className="text-xs text-fg-muted underline-offset-2 hover:text-fg hover:underline"
        >
          {t("nfeed_card_mirror")}
        </Link>
      ) : null}
    </Card>
  )
}
