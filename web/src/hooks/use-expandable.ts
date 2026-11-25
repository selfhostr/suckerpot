import { useLayoutEffect, useRef, useState } from "react"

/**
 * A capped box of raw text that can show everything. The box keeps its own scroll while
 * collapsed (the caller adds the max-height class only when `expanded` is false); `overflowing`
 * says whether there is anything more to show, so the toggle only appears when it matters.
 */
export function useExpandable<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [expanded, setExpanded] = useState(false)
  const [overflowing, setOverflowing] = useState(false)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el || expanded) return
    const measure = () => setOverflowing(el.scrollHeight > el.clientHeight + 1)
    measure()
    if (typeof ResizeObserver === "undefined") return
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [expanded])
  return { ref, expanded, overflowing, toggle: () => setExpanded((v) => !v) }
}
