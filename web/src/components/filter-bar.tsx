import { X } from "lucide-react"
import { useSearchParams } from "react-router"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export interface FilterChipDef {
  /** URL search param name. */
  param: string
  /** Human label shown before the value, e.g. "IP". */
  label: string
  /** Render the value (mono for IPs, flag for countries…). */
  render?: (value: string) => React.ReactNode
  /** Other params removed together with this one (a period is `since` and `until`). */
  alsoRemove?: string[]
}

export { SensorFilter } from "@/components/sensor-filter"

interface FilterBarProps {
  /** Controls on the left (e.g. <SensorFilter />). */
  children?: React.ReactNode
  /** Controls pushed to the right end, after the chips (e.g. a sort). */
  trailing?: React.ReactNode
  /** Params shown as removable chips when present in the URL. */
  chips: FilterChipDef[]
  /** Extra params cleared by "Clear all" (besides the chips). */
  alsoClears?: string[]
  className?: string
}

/** Every filter lives in the URL, so any view can be shared as a link. */
export function FilterBar({
  children,
  trailing,
  chips,
  alsoClears = [],
  className,
}: FilterBarProps) {
  const [params, setParams] = useSearchParams()
  const active = chips.flatMap((c) => {
    const v = params.get(c.param)
    return v ? [{ ...c, value: v }] : []
  })
  const anyActive = active.length > 0 || alsoClears.some((p) => params.has(p))

  const remove = (names: string[]) =>
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev)
        names.forEach((n) => p.delete(n))
        return p
      },
      { preventScrollReset: true },
    )

  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      {/* One row that scrolls sideways on a phone; plain flex items from md up. */}
      <div className="-mx-4 flex w-[calc(100%+2rem)] items-center gap-2 overflow-x-auto px-4 pb-1 md:contents">
        {children}
      </div>
      {active.map((c) => (
        <span
          key={c.param}
          className="inline-flex h-8 animate-fade-in items-center gap-1.5 rounded-md border border-border-strong bg-surface pr-1 pl-2.5 text-xs shadow-sm"
        >
          <span className="text-fg-muted">{c.label}</span>
          <span className="font-medium text-fg">{c.render ? c.render(c.value) : c.value}</span>
          <button
            type="button"
            onClick={() => remove([c.param, ...(c.alsoRemove ?? [])])}
            className="ml-0.5 inline-flex size-6 items-center justify-center rounded-sm text-fg-subtle transition-colors hover:bg-surface-hover hover:text-fg"
            aria-label={`Remove ${c.label} filter`}
          >
            <X aria-hidden className="size-3.5" />
          </button>
        </span>
      ))}
      {anyActive ? (
        <Button
          variant="ghost"
          size="sm"
          className="h-8 text-xs text-fg-muted"
          onClick={() =>
            remove([...chips.flatMap((c) => [c.param, ...(c.alsoRemove ?? [])]), ...alsoClears])
          }
        >
          Clear all
        </Button>
      ) : null}
      {trailing ? <div className="sm:ml-auto">{trailing}</div> : null}
    </div>
  )
}
