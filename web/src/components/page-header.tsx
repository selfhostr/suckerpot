import { useContext } from "react"
import { createPortal } from "react-dom"
import { HelpSlotContext } from "@/app/help-slot"
import { PageHelp } from "@/components/page-help"
import type { HelpId } from "@/lib/help"
import { cn } from "@/lib/utils"

interface PageHeaderProps {
  /** The page's name. Visible only on a detail page (see `showTitle`); a screen reader always gets it. */
  title: React.ReactNode
  /** One sentence that says what this page shows right now. */
  description?: React.ReactNode
  actions?: React.ReactNode
  /** Back link above the title: this is a detail page, which shows its own title. */
  eyebrow?: React.ReactNode
  /**
   * Draw the title. One rule for the whole app: a page already named by the breadcrumb and, in a
   * group, by its tab does not say its name a second time. A detail page (it has a back link) is
   * the exception: its title is the thing being looked at (an address, a script, a report).
   */
  showTitle?: boolean
  /** Which text the "?" popover shows (src/lib/help.ts). */
  help?: HelpId
  className?: string
}

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
  showTitle,
  help,
  className,
}: PageHeaderProps) {
  const { node: switchSlot } = useContext(HelpSlotContext)
  if (showTitle ?? !!eyebrow) {
    return (
      <header
        className={cn(
          "flex flex-col gap-4 pb-6 sm:flex-row sm:items-end sm:justify-between sm:gap-6",
          className,
        )}
      >
        <div className="min-w-0 space-y-1.5">
          {eyebrow ? <div className="type-eyebrow text-fg-muted">{eyebrow}</div> : null}
          <div className="flex items-center gap-1.5">
            <h1 className="min-w-0 type-page-title text-fg">{title}</h1>
            {help ? <PageHelp id={help} /> : null}
          </div>
          {description ? (
            <p className="max-w-2xl type-lede text-pretty text-fg-muted">{description}</p>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </header>
    )
  }
  // The page's "?" goes to the end of the switch row when there is one, else after the intro line.
  const helpHere =
    help && !switchSlot ? <PageHelp id={help} className="-my-0.5 ml-1 align-middle" /> : null
  const empty = !description && !actions && !helpHere
  return (
    <header
      className={cn(
        empty
          ? "pb-0"
          : "flex flex-col gap-3 pb-6 sm:flex-row sm:items-start sm:justify-between sm:gap-6",
        className,
      )}
    >
      <h1 className="sr-only">{title}</h1>
      {help && switchSlot ? createPortal(<PageHelp id={help} />, switchSlot) : null}
      {description || helpHere ? (
        <p className="max-w-2xl min-w-0 type-lede text-pretty text-fg-muted">
          {description}
          {helpHere}
        </p>
      ) : null}
      {actions ? (
        <div className="flex shrink-0 items-center gap-2 sm:ml-auto">{actions}</div>
      ) : null}
    </header>
  )
}
