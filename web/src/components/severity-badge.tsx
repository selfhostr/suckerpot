import { CircleDot, Info, OctagonAlert, TriangleAlert, type LucideIcon } from "lucide-react"
import { t, tk } from "@/i18n"
import type { Severity } from "@/lib/severity"
import { cn } from "@/lib/utils"

const META: Record<Severity, { label: string; icon: LucideIcon; className: string }> = {
  info: { label: tk("severity_info"), icon: Info, className: "text-sev-info tint-info" },
  notice: {
    label: tk("severity_notice"),
    icon: CircleDot,
    className: "text-sev-notice tint-notice",
  },
  warning: {
    label: tk("severity_warning"),
    icon: TriangleAlert,
    className: "text-sev-warning tint-warning",
  },
  severe: {
    label: tk("severity_severe"),
    icon: OctagonAlert,
    className: "text-sev-severe tint-severe",
  },
}

interface SeverityBadgeProps {
  severity: Severity
  /** Hide the label visually (kept for screen readers). */
  iconOnly?: boolean
  className?: string
}

export function SeverityBadge({ severity, iconOnly = false, className }: SeverityBadgeProps) {
  const { label: labelKey, icon: Icon, className: tone } = META[severity]
  const label = t(labelKey)
  return (
    <span
      className={cn(
        "inline-flex h-(--chip) shrink-0 items-center gap-1.5 rounded-sm text-xs font-medium",
        iconOnly ? "w-6 justify-center" : "px-2",
        severity === "severe" && "font-semibold",
        tone,
        className,
      )}
      title={iconOnly ? label : undefined}
    >
      <Icon aria-hidden className="size-3.5" strokeWidth={2.25} />
      <span className={cn(iconOnly && "sr-only")}>{label}</span>
    </span>
  )
}
