import { Eye } from "lucide-react"
import { useAuth } from "@/app/auth"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

/** Shown to viewers only: everything can be read, nothing can be changed. */
export function ReadOnlyBadge({
  className,
  short = false,
}: {
  className?: string
  /** "Read-only" alone, for the narrow mobile top bar; the full label stays for screen readers. */
  short?: boolean
}) {
  const { user } = useAuth()
  if (user?.role !== "viewer") return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            "inline-flex h-(--chip) items-center gap-1.5 rounded-sm border px-2 text-xs font-medium whitespace-nowrap text-fg-muted",
            className,
          )}
        >
          <Eye aria-hidden className="size-3.5" />
          {short ? (
            <>
              {t("ui_read_only_short")}
              <span className="sr-only"> {t("ui_read_only_short_sr")}</span>
            </>
          ) : (
            t("ui_read_only_full")
          )}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{t("ui_read_only_tip")}</TooltipContent>
    </Tooltip>
  )
}
