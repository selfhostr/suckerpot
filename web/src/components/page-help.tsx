import { CircleHelp } from "lucide-react"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { CARD_HELP, HELP, type CardHelpId, type HelpId, type HelpText } from "@/lib/help"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

function HelpPopover({
  text,
  card,
  className,
}: {
  text: HelpText
  card: boolean
  className?: string | undefined
}) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={t(card ? "help_more_about" : "page_help_about", { title: text.title })}
          className={cn(
            "inline-grid shrink-0 place-items-center rounded-md text-fg-subtle transition-colors duration-150 hover:bg-surface-hover/60 hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
            card ? "size-5" : "size-6",
            className,
          )}
        >
          <CircleHelp aria-hidden className={card ? "size-3.5" : "size-4"} strokeWidth={1.85} />
        </button>
      </PopoverTrigger>
      <PopoverContent
        align={card ? "start" : "end"}
        collisionPadding={8}
        className="w-80 max-w-[calc(100vw-2rem)] space-y-1.5 p-4"
      >
        <p className="text-sm font-medium text-fg">{text.title}</p>
        <p className="text-sm text-pretty text-fg-muted">{text.body}</p>
      </PopoverContent>
    </Popover>
  )
}

/**
 * The "?" of a page: what it shows, where its data comes from, what to try. It sits at the end of
 * the page switch, or after the page's intro line when the page has no switch.
 */
export function PageHelp({ id, className }: { id: HelpId; className?: string }) {
  return <HelpPopover text={HELP[id]} card={false} className={className} />
}

/** The same popover, smaller, beside the title of a card, a section or a column. */
export function CardHelp({ id, className }: { id: CardHelpId; className?: string }) {
  return <HelpPopover text={CARD_HELP[id]} card className={className} />
}
