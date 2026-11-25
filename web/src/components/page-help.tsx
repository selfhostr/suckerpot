import { CircleHelp } from "lucide-react"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { HELP, type HelpId } from "@/lib/help"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

/** The "?" next to a page title: what the page shows, where its data comes from, what to try. */
export function PageHelp({ id, className }: { id: HelpId; className?: string }) {
  const text = HELP[id]
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={t("page_help_about", { title: text.title })}
          className={cn(
            "inline-grid size-6 shrink-0 place-items-center rounded-md text-fg-subtle transition-colors duration-150 hover:bg-surface-hover/60 hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
            className,
          )}
        >
          <CircleHelp aria-hidden className="size-4" strokeWidth={1.85} />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 max-w-[calc(100vw-2rem)] space-y-1.5 p-4">
        <p className="text-sm font-medium text-fg">{text.title}</p>
        <p className="text-sm text-pretty text-fg-muted">{text.body}</p>
      </PopoverContent>
    </Popover>
  )
}
