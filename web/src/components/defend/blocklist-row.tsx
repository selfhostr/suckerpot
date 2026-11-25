import { Ban, CircleCheck, Ellipsis, FlaskConical, Radar } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { t } from "@/i18n"
import { CopyButton } from "@/components/defend/copy-button"
import { IPChip } from "@/components/ip-chip"
import { Meter } from "@/components/meter"
import { RelativeTime } from "@/components/relative-time"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { maskIpsInText } from "@/lib/format"
import {
  BAND_LABEL,
  reasonLabel,
  reasonSentence,
  scoreBand,
  type BlockEntry,
  type OverrideAction,
} from "@/lib/defend"
import { cn } from "@/lib/utils"

export const BLOCKLIST_GRID =
  "md:grid md:grid-cols-[minmax(0,2.4fr)_8.5rem_minmax(0,2fr)_9rem_2rem] md:items-center md:gap-x-4"

const MAX_REASONS = 3

function ValueCell({ entry }: { entry: BlockEntry }) {
  const { masked } = useIpMask()
  if (entry.kind === "ip") return <IPChip ip={entry.value} variant="ghost" />
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

function Reasons({ reasons }: { reasons: string[] }) {
  const shown = reasons.slice(0, MAX_REASONS)
  const rest = reasons.slice(MAX_REASONS)
  return (
    <ul aria-label={t("blocklists_why")} className="flex flex-wrap gap-1.5">
      {shown.map((r) => (
        <li
          key={r}
          title={reasonSentence(r)}
          className="inline-flex h-(--chip) items-center rounded-sm border border-border-strong px-2 text-xs font-medium text-fg-muted"
        >
          {reasonLabel(r)}
        </li>
      ))}
      {rest.length > 0 ? (
        <li
          title={rest.map(reasonSentence).join(" ")}
          className="inline-flex h-(--chip) items-center rounded-sm px-1.5 text-xs text-fg-subtle"
        >
          {t("blocklists_row_more", { count: rest.length })}
        </li>
      ) : null}
    </ul>
  )
}

function OverrideBadge({ action }: { action: OverrideAction }) {
  const Icon = action === "allow" ? CircleCheck : Ban
  return (
    <Badge variant="outline" className="text-fg">
      <Icon aria-hidden />
      {action === "allow" ? t("blocklists_row_allowed") : t("blocklists_row_blocked")}
    </Badge>
  )
}

/** One listed value: what it is, how sure we are, why, and when it was last seen. */
export function BlocklistRow({
  entry,
  canWrite,
  onOverride,
  onRemoveOverride,
}: {
  entry: BlockEntry
  canWrite: boolean
  onOverride: (entry: BlockEntry, action: OverrideAction) => void
  onRemoveOverride: (entry: BlockEntry) => void
}) {
  const band = scoreBand(entry.score)
  return (
    <div className={cn("flex flex-col gap-2.5 px-4 py-3.5 sm:px-5 md:py-3", BLOCKLIST_GRID)}>
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1.5">
        <ValueCell entry={entry} />
        {entry.override ? <OverrideBadge action={entry.override} /> : null}
        {entry.demo ? (
          <Badge variant="outline" className="text-fg-muted">
            <FlaskConical aria-hidden />
            {t("blocklists_row_demo")}
          </Badge>
        ) : null}
        {entry.benign ? (
          <Badge variant="outline" className="text-fg-muted">
            <Radar aria-hidden />
            {t("blocklists_row_scanner")}
          </Badge>
        ) : null}
      </div>

      <div className="flex items-center gap-2.5">
        <Meter
          value={entry.score}
          max={100}
          label={t("blocklists_col_score")}
          valueText={t("blocklists_row_score_text", { score: entry.score, band: BAND_LABEL[band] })}
          tone={band === "high" ? "warning" : "neutral"}
          className="w-16 shrink-0"
        />
        <span className="text-sm font-medium text-fg">{entry.score}</span>
        <span className="text-xs text-fg-muted">{BAND_LABEL[band]}</span>
      </div>

      <Reasons reasons={entry.reasons} />

      <div className="flex flex-wrap items-center justify-between gap-x-3 text-xs text-fg-muted md:block">
        <span>
          {t("blocklists_row_seen", { sessions: entry.sessions, sources: entry.sources })}
        </span>
        <span className="md:block">
          <RelativeTime iso={entry.last_seen} className="text-xs" />
        </span>
      </div>

      <div className="md:justify-self-end">
        {canWrite ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={t("blocklists_row_actions", { kind: entry.kind, value: entry.value })}
              >
                <Ellipsis aria-hidden />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => onOverride(entry, "allow")}>
                <CircleCheck aria-hidden />
                {t("blocklists_row_always_allow")}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => onOverride(entry, "block")}>
                <Ban aria-hidden />
                {t("blocklists_row_always_block")}
              </DropdownMenuItem>
              {entry.override ? (
                <DropdownMenuItem onSelect={() => onRemoveOverride(entry)}>
                  {t("blocklists_row_remove_override")}
                </DropdownMenuItem>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}
      </div>
    </div>
  )
}
