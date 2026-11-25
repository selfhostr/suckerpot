import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { cn } from "@/lib/utils"

export interface SegmentedOption<T extends string> {
  value: T
  label: React.ReactNode
  /** Accessible name when the label is an icon or abbreviated. */
  ariaLabel?: string
  disabled?: boolean
}

interface SegmentedControlProps<T extends string> {
  value: T
  onChange: (value: T) => void
  options: readonly SegmentedOption<T>[]
  /** Accessible name of the whole group, e.g. "Sensor". */
  label: string
  /**
   * `md` for filters and sorts: the whole track is a `sm` control (32 px, 40 on touch), so it
   * lines up with the buttons, inputs and chips of a filter row. `form` beside form fields: a
   * default control (36 px) with 13 px labels. `icon` for icon-only switches.
   */
  size?: "md" | "form" | "icon"
  className?: string
}

const ITEM = {
  md: "h-full min-w-9 gap-1.5 px-2.5 text-xs font-medium",
  form: "h-full min-w-9 gap-1.5 px-3 text-sm font-medium",
  icon: "h-full w-7 min-w-0 px-0",
} as const

/**
 * One choice among a few, always visible: sensor filter, sort order, playback
 * speed, theme. A track on --bg with the selected segment raised.
 */
export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  label,
  size = "md",
  className,
}: SegmentedControlProps<T>) {
  return (
    <ToggleGroup
      type="single"
      value={value}
      onValueChange={(v) => {
        const next = options.find((o) => o.value === v)
        if (next) onChange(next.value)
      }}
      aria-label={label}
      className={cn(
        "rounded-md border bg-bg p-0.5",
        size === "form" ? "h-(--control-md)" : "h-(--control-sm)",
        className,
      )}
    >
      {options.map((o) => (
        <ToggleGroupItem
          key={o.value}
          value={o.value}
          aria-label={o.ariaLabel}
          disabled={o.disabled}
          title={size === "icon" ? o.ariaLabel : undefined}
          className={cn(
            "rounded-sm border-0 text-fg-muted shadow-none hover:bg-transparent hover:text-fg",
            "data-[state=on]:bg-surface-raised data-[state=on]:text-fg data-[state=on]:shadow-sm data-[state=on]:ring-1 data-[state=on]:ring-border",
            ITEM[size],
          )}
        >
          {o.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  )
}
