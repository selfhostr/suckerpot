import { useQuery } from "@tanstack/react-query"
import { useId } from "react"
import { useScannerFilter } from "@/app/scanner-filter"
import { Term } from "@/components/term"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { scannerCaption } from "@/lib/scanner-caption"
import { todayApi, todayKeys } from "@/lib/today"
import { cn } from "@/lib/utils"

/**
 * "Hide research scanners" switch, with the number of sessions it hides. The count is always
 * there, so hiding never feels like data going missing. `inline` is the one-row form for the
 * desktop header (the count in the switch's tooltip); the stacked form, with the count printed
 * under it, is for the phone navigation drawer.
 */
export function ScannerToggle({
  className,
  inline = false,
}: {
  className?: string
  inline?: boolean
}) {
  const { hide, setHide } = useScannerFilter()
  const id = useId()
  const captionId = useId()
  const count = useQuery({
    queryKey: todayKeys.benign,
    queryFn: todayApi.benignCount,
    refetchInterval: 60_000,
  })
  const caption = scannerCaption(hide, count.data?.sessions)
  const hideLabel = tNodes(
    "scanner_toggle_label",
    {},
    { term: <Term id="research-scanner">{t("scanner_toggle_term")}</Term> },
  )
  if (inline) {
    // The header form: label and switch only. The count sits in the switch's tooltip and its
    // accessible description, so the header stays quiet; the phone drawer prints it in full.
    return (
      <div className={cn("flex items-center gap-2.5", className)}>
        <label htmlFor={id} className="text-xs text-fg-muted">
          {hideLabel}
        </label>
        <Tooltip>
          {/* A wrapper as the trigger: the tooltip's own data-state must not replace the switch's. */}
          <TooltipTrigger asChild>
            <span className="inline-flex">
              <Switch
                id={id}
                size="sm"
                checked={hide}
                onCheckedChange={setHide}
                aria-describedby={captionId}
              />
            </span>
          </TooltipTrigger>
          <TooltipContent side="bottom" sideOffset={6}>
            {caption}
          </TooltipContent>
        </Tooltip>
        <span id={captionId} className="sr-only">
          {caption}
        </span>
      </div>
    )
  }
  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={id} className="text-xs text-fg-muted">
          {hideLabel}
        </label>
        <Switch
          id={id}
          size="sm"
          checked={hide}
          onCheckedChange={setHide}
          aria-describedby={captionId}
        />
      </div>
      <p id={captionId} className="min-h-4 text-2xs text-fg-subtle">
        {caption}
      </p>
    </div>
  )
}
