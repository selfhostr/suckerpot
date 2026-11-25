import { cn } from "@/lib/utils"
import { sensorMeta } from "@/lib/sensors"

interface SensorBadgeProps {
  sensor: string
  /** `badge`: tinted pill with icon. `dot`: coloured dot + muted label, for dense rows. */
  variant?: "badge" | "dot"
  className?: string
}

/** Sensor identity: hue + icon + label, so meaning never rests on colour alone. */
export function SensorBadge({ sensor, variant = "badge", className }: SensorBadgeProps) {
  const meta = sensorMeta(sensor)
  const label = meta?.label ?? sensor.toUpperCase()

  if (variant === "dot") {
    return (
      <span className={cn("inline-flex items-center gap-1.5 text-xs text-fg-muted", className)}>
        <span aria-hidden className={cn("size-2 rounded-full", meta?.fill ?? "bg-fg-subtle")} />
        {label}
      </span>
    )
  }

  const Icon = meta?.icon
  return (
    <span
      className={cn(
        "inline-flex h-(--chip) shrink-0 items-center gap-1.5 rounded-sm px-2 text-xs font-medium",
        meta ? [meta.text, meta.tint] : "bg-surface-hover text-fg-muted",
        className,
      )}
    >
      {Icon ? <Icon aria-hidden className="size-3.5" strokeWidth={2} /> : null}
      {label}
    </span>
  )
}
