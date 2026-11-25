import { ChevronDown, ChevronUp } from "lucide-react"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

/** The "Expand / Collapse" button under a capped box of raw text (see `useExpandable`). */
export function ExpandToggle({
  expanded,
  overflowing,
  onToggle,
  label,
  className,
}: {
  expanded: boolean
  overflowing: boolean
  onToggle: () => void
  /** What is being expanded, for the accessible name, e.g. "message body". */
  label: string
  className?: string
}) {
  if (!overflowing && !expanded) return null
  const Icon = expanded ? ChevronUp : ChevronDown
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={onToggle}
      aria-expanded={expanded}
      aria-label={
        expanded ? t("ui_collapse_named", { label }) : t("ui_expand_named", { label })
      }
      className={cn("text-fg-muted", className)}
    >
      <Icon aria-hidden />
      {expanded ? t("ui_collapse") : t("ui_expand")}
    </Button>
  )
}
