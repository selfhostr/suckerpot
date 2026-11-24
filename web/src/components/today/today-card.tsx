import {
  Activity,
  ArrowRight,
  ChevronRight,
  ClipboardPaste,
  Crosshair,
  Flag,
  Link2,
  Network,
  Radar,
  ServerCrash,
  ShieldAlert,
  Sparkles,
  SquareTerminal,
  Tag,
  UserRound,
  type LucideIcon,
} from "lucide-react"
import type { CSSProperties } from "react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { CountryFlag } from "@/components/country-flag"
import { TermText } from "@/components/term"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber } from "@/lib/format"
import { sensorMeta } from "@/lib/sensors"
import { CARD_TITLE, type TodayCardData, type TodayCardId, type TodayItem } from "@/lib/today"
import { countUnit, isCodeLike, itemLabel, newField, visibleItems } from "@/lib/today-view"
import { cn } from "@/lib/utils"

const CARD_ICON: Record<TodayCardId, LucideIcon> = {
  happened: Activity,
  forms: ClipboardPaste,
  campaigns: Flag,
  act: ShieldAlert,
  new_week: Sparkles,
  exposure: Radar,
}

const KIND_ICON: Partial<Record<TodayItem["kind"], LucideIcon>> = {
  tag: Tag,
  campaign: Flag,
  host: ServerCrash,
  session: Crosshair,
  service: Radar,
  new: Sparkles,
}

/** First-seen items get the icon of what they are, so three rows never repeat one glyph. */
const NEW_ICON: Record<string, LucideIcon> = {
  asn: Network,
  url: Link2,
  command: SquareTerminal,
  username: UserRound,
}

function ItemMark({ item }: { item: TodayItem }) {
  if (item.kind === "country") return <CountryFlag code={item.value} decorative />
  const Icon =
    (item.kind === "sensor"
      ? sensorMeta(item.value)?.icon
      : item.kind === "new"
        ? NEW_ICON[newField(item) ?? ""]
        : KIND_ICON[item.kind]) ?? Tag
  return <Icon aria-hidden className="size-4 shrink-0 text-fg-subtle" strokeWidth={1.85} />
}

function ItemRow({ item }: { item: TodayItem }) {
  const { masked } = useIpMask()
  const unit = countUnit(item)
  return (
    <li>
      <Link
        to={item.to}
        className="group -mx-2 flex min-h-11 items-center gap-3 rounded-md px-2 py-1.5 transition-colors duration-150 hover:bg-surface-hover/70 sm:min-h-10"
      >
        <ItemMark item={item} />
        <span className="min-w-0 flex-1">
          <span
            className={cn(
              "block truncate text-sm text-fg",
              isCodeLike(item) && "font-mono text-xs",
            )}
          >
            {itemLabel(item, masked)}
          </span>
          {item.detail ? (
            <span className="block truncate text-xs text-fg-muted">{item.detail}</span>
          ) : null}
        </span>
        {unit ? (
          <span className="shrink-0 text-right text-sm text-fg tabular-nums">
            {formatNumber(item.count ?? 0)} <span className="text-xs text-fg-subtle">{unit}</span>
          </span>
        ) : null}
        <ChevronRight
          aria-hidden
          className="size-4 shrink-0 text-fg-subtle opacity-0 transition-opacity duration-150 group-hover:opacity-100 group-focus-visible:opacity-100"
        />
      </Link>
    </li>
  )
}

interface TodayCardProps {
  card: TodayCardData
  /** Position on the page: cards enter one after another. */
  index?: number
  className?: string
}

/**
 * One Today card: a sentence, up to three items, one action. Every item opens a filtered view.
 * An empty card keeps its place and says so in its sentence.
 */
export function TodayCard({ card, index = 0, className }: TodayCardProps) {
  const Icon = CARD_ICON[card.id]
  const items = visibleItems(card.items)
  const title = CARD_TITLE[card.id]
  // Servers that hand out malware are the one severe thing on this page: the only red here.
  const urgent = card.id === "act" && items.length > 0
  return (
    <Card
      data-card={card.id}
      role="group"
      aria-labelledby={`today-${card.id}`}
      style={{ "--motion-i": index } as CSSProperties}
      className={cn(
        "motion-stagger h-full animate-card-in gap-0 rounded-lg py-0 shadow-sm",
        className,
      )}
    >
      <header className="px-4 pt-4 sm:px-5 sm:pt-5">
        <p className="flex items-center gap-2 text-xs font-medium text-fg-muted">
          <Icon
            aria-hidden
            className={cn("size-3.5", urgent && "text-sev-severe")}
            strokeWidth={1.85}
          />
          {title}
        </p>
        <h2
          id={`today-${card.id}`}
          className={cn(
            "mt-2 text-base font-medium text-pretty",
            card.empty ? "text-fg-muted" : "text-fg",
          )}
        >
          <TermText text={card.sentence} />
        </h2>
      </header>
      {items.length > 0 ? (
        <ul aria-label={title} className="px-4 pt-3 sm:px-5">
          {items.map((item) => (
            <ItemRow key={`${item.kind}:${item.value}`} item={item} />
          ))}
        </ul>
      ) : null}
      <footer className="mt-auto px-4 pt-4 pb-4 sm:px-5 sm:pb-5">
        <Button asChild variant="outline" size="sm">
          <Link to={card.action.to}>
            {card.action.label}
            <ArrowRight aria-hidden />
          </Link>
        </Button>
      </footer>
    </Card>
  )
}

/** Same footprint as a card with three items, so nothing jumps when data arrives. */
export function TodayCardSkeleton() {
  return (
    <div aria-hidden className="h-full space-y-4 rounded-lg border bg-surface p-5">
      <div className="space-y-2.5">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-4 w-11/12" />
        <Skeleton className="h-4 w-2/3" />
      </div>
      <div className="space-y-3">
        {Array.from({ length: 3 }, (_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
      <Skeleton className="h-8 w-32" />
    </div>
  )
}
