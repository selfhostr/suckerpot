import { CardHelp } from "@/components/page-help"
import { Card } from "@/components/ui/card"
import type { CardHelpId } from "@/lib/help"
import { cn } from "@/lib/utils"

interface FindingCardProps {
  /** Small label naming the chart, e.g. "Activity by sensor". */
  eyebrow: string
  /** The plain-English finding the chart proves. Mandatory: no chart without a sentence. */
  finding: React.ReactNode
  /** What the card shows and where its figures come from: a "?" beside the label. */
  help?: CardHelpId
  /** Optional supporting line under the finding. */
  detail?: React.ReactNode
  /** Right-aligned controls (period switch, "View all" link…). */
  action?: React.ReactNode
  footer?: React.ReactNode
  children?: React.ReactNode
  className?: string
  bodyClassName?: string
}

/** The base Card: a finding sentence first, then the evidence. */
export function FindingCard({
  eyebrow,
  finding,
  help,
  detail,
  action,
  footer,
  children,
  className,
  bodyClassName,
}: FindingCardProps) {
  return (
    <Card className={className}>
      {/* The action wraps under the sentence when both cannot sit side by side (wide segmented
          controls on phones), so the finding never shrinks into a narrow column. */}
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3 px-4 pt-4 sm:px-5 sm:pt-5">
        <div className="min-w-0 flex-[1_1_16rem] space-y-1.5">
          {help ? (
            <div className="-my-0.5 flex items-center gap-1">
              <p className="type-eyebrow text-fg-muted">{eyebrow}</p>
              <CardHelp id={help} />
            </div>
          ) : (
            <p className="type-eyebrow text-fg-muted">{eyebrow}</p>
          )}
          <h3 className="type-card-title text-pretty text-fg">{finding}</h3>
          {detail ? <p className="text-sm text-fg-muted">{detail}</p> : null}
        </div>
        {action ? <div className="max-w-full shrink-0">{action}</div> : null}
      </header>
      {children ? (
        <div className={cn("px-4 pt-4 pb-4 sm:px-5 sm:pb-5", bodyClassName)}>{children}</div>
      ) : (
        <div className="pb-4 sm:pb-5" />
      )}
      {footer ? (
        <footer className="border-t px-4 py-3 text-xs text-fg-muted sm:px-5">{footer}</footer>
      ) : null}
    </Card>
  )
}
