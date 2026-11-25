import { useVirtualizer, useWindowVirtualizer } from "@tanstack/react-virtual"
import { useLayoutEffect, useRef, useState } from "react"
import { ExpandToggle } from "@/components/expand-toggle"

const ROW_H = 24
/** Rows shown before the box needs its own scrollbar (320 px). */
const CAP_ROWS = 13

function StringRow({ index, text, top }: { index: number; text: string | undefined; top: number }) {
  return (
    <div
      role="listitem"
      className="absolute top-0 left-0 flex h-6 w-full items-center gap-3 px-3 font-mono text-xs"
      style={{ transform: `translateY(${top}px)` }}
    >
      <span aria-hidden className="w-8 shrink-0 text-right text-fg-subtle tabular-nums">
        {index + 1}
      </span>
      <span className="truncate text-fg" title={text}>
        {text}
      </span>
    </div>
  )
}

/** Capped: the list scrolls inside its own box, faded at the edge that hides more. */
function CappedStrings({ strings }: { strings: readonly string[] }) {
  const ref = useRef<HTMLDivElement>(null)
  // The virtualizer is used as intended; the compiler just cannot memoize its return value.
  // eslint-disable-next-line react-hooks/incompatible-library
  const v = useVirtualizer({
    count: strings.length,
    getScrollElement: () => ref.current,
    estimateSize: () => ROW_H,
    overscan: 12,
  })
  return (
    <div
      ref={ref}
      tabIndex={0}
      role="list"
      aria-label="Strings found in the file"
      className="scroll-fade-y max-h-80 overflow-auto outline-none"
    >
      <div className="relative w-full" style={{ height: v.getTotalSize() }}>
        {v.getVirtualItems().map((item) => (
          <StringRow
            key={item.key}
            index={item.index}
            text={strings[item.index]}
            top={item.start}
          />
        ))}
      </div>
    </div>
  )
}

/** Expanded: every string, scrolled with the window like any other list. */
function FullStrings({ strings }: { strings: readonly string[] }) {
  const ref = useRef<HTMLDivElement>(null)
  const [scrollMargin, setScrollMargin] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const measure = () => setScrollMargin(el.getBoundingClientRect().top + window.scrollY)
    measure()
    if (typeof ResizeObserver === "undefined") return
    const ro = new ResizeObserver(measure)
    ro.observe(document.body)
    return () => ro.disconnect()
  }, [])
  const v = useWindowVirtualizer({
    count: strings.length,
    estimateSize: () => ROW_H,
    overscan: 12,
    scrollMargin,
  })
  return (
    <div
      ref={ref}
      tabIndex={0}
      role="list"
      aria-label="Strings found in the file"
      className="outline-none"
    >
      <div className="relative w-full" style={{ height: v.getTotalSize() }}>
        {v.getVirtualItems().map((item) => (
          <StringRow
            key={item.key}
            index={item.index}
            text={strings[item.index]}
            top={item.start - scrollMargin}
          />
        ))}
      </div>
    </div>
  )
}

/**
 * Printable strings found in the file: plain text, virtualised. Capped at about 13 rows with an
 * Expand toggle that shows them all and hands the scrolling back to the window.
 */
export function StringsList({ strings }: { strings: readonly string[] }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className="space-y-1">
      <div className="overflow-hidden rounded-md border bg-bg has-[[role=list]:focus-visible]:ring-2 has-[[role=list]:focus-visible]:ring-ring">
        {expanded ? <FullStrings strings={strings} /> : <CappedStrings strings={strings} />}
      </div>
      <ExpandToggle
        expanded={expanded}
        overflowing={strings.length > CAP_ROWS}
        onToggle={() => setExpanded((v) => !v)}
        label="strings"
      />
    </div>
  )
}
