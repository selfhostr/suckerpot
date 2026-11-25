import { useLayoutEffect, useRef } from "react"
import { cn } from "@/lib/utils"

/**
 * A list page's filter bar that stays in view under the app header while the rows scroll. It
 * publishes its height as `--filters-h` on its wrapper, so the list's column header (sticky
 * `top-[calc(3.5rem+var(--filters-h,0px))]`) sits right under it instead of behind it.
 */
export function StickyFilters({
  filters,
  children,
  className,
}: {
  filters: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  const scope = useRef<HTMLDivElement>(null)
  const bar = useRef<HTMLDivElement>(null)
  useLayoutEffect(() => {
    const s = scope.current
    const b = bar.current
    if (!s || !b) return
    const measure = () => s.style.setProperty("--filters-h", `${b.offsetHeight}px`)
    measure()
    if (typeof ResizeObserver === "undefined") return
    const ro = new ResizeObserver(measure)
    ro.observe(b)
    return () => ro.disconnect()
  }, [])
  return (
    <div ref={scope} className={className}>
      <div ref={bar} className={cn("bg-bg pb-3 md:sticky md:top-14 md:z-10 md:pt-1")}>
        {filters}
      </div>
      {children}
    </div>
  )
}
