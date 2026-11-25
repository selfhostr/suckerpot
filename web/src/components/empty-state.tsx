import type { LucideIcon } from "lucide-react"
import { cn } from "@/lib/utils"

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description?: React.ReactNode
  action?: React.ReactNode
  /** Small pill above the title, e.g. "Coming in M5". */
  badge?: string
  className?: string
  /** `card` draws its own dashed frame; `bare` sits inside an existing card. */
  variant?: "card" | "bare"
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  badge,
  className,
  variant = "card",
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center px-6 py-12 text-center",
        variant === "card" && "rounded-lg border border-dashed border-border-strong bg-surface/40",
        className,
      )}
    >
      <div className="mb-4 flex size-10 items-center justify-center rounded-md border bg-surface text-fg-muted shadow-sm">
        <Icon aria-hidden className="size-5" strokeWidth={1.75} />
      </div>
      {badge ? (
        <span className="mb-2 inline-flex h-(--chip) items-center rounded-sm border px-2 text-xs font-medium text-fg-muted">
          {badge}
        </span>
      ) : null}
      <h3 className="type-card-title text-fg">{title}</h3>
      {description ? (
        <p className="mt-1.5 max-w-sm text-sm text-pretty text-fg-muted">{description}</p>
      ) : null}
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  )
}
