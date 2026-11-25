import { useLayoutEffect, useRef } from "react"
import { formatNumber } from "@/lib/format"
import { calmMotion } from "@/lib/motion"
import { cn } from "@/lib/utils"

interface AnimatedNumberProps {
  value: number
  format?: (n: number) => string
  className?: string
  /** How long a change takes. */
  durationMs?: number
}

const easeOut = (t: number) => 1 - (1 - t) ** 3

/**
 * A number that counts to its new value (ease-out, 600 ms). The first value is shown at once;
 * only changes count. The digits are written straight into the text node from an animation frame,
 * so a count costs no React render. Jumps under reduced motion, frozen motion and on phones.
 * Screen readers get the final value only.
 */
export function AnimatedNumber({
  value,
  format = formatNumber,
  className,
  durationMs = 600,
}: AnimatedNumberProps) {
  const ref = useRef<HTMLSpanElement>(null)
  const shown = useRef(value)
  const fmt = useRef(format)
  useLayoutEffect(() => {
    fmt.current = format
  })

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const from = shown.current
    const write = (n: number) => {
      shown.current = n
      el.textContent = fmt.current(Math.round(n))
    }
    if (from === value || durationMs <= 0 || calmMotion()) {
      write(value)
      return
    }
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs)
      write(from + (value - from) * easeOut(t))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value, durationMs])

  return (
    <span className={cn("tabular-nums", className)}>
      <span aria-hidden ref={ref} />
      <span className="sr-only">{format(value)}</span>
    </span>
  )
}
