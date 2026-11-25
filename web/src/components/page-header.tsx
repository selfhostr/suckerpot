import { PageHelp } from "@/components/page-help"
import type { HelpId } from "@/lib/help"
import { cn } from "@/lib/utils"

interface PageHeaderProps {
  title: React.ReactNode
  /** One sentence that says what this page shows right now. */
  description?: React.ReactNode
  actions?: React.ReactNode
  /** Breadcrumb or back link above the title. */
  eyebrow?: React.ReactNode
  /** Which text the "?" popover shows (src/lib/help.ts). */
  help?: HelpId
  className?: string
}

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
  help,
  className,
}: PageHeaderProps) {
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
