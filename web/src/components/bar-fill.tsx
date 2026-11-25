import { cn } from "@/lib/utils"

interface BarFillProps {
  /** 0..1 of the track. Clamped. */
  ratio: number
  /** Colour and height of the fill (`h-full` by default). */
  className?: string
}

/**
 * The filled part of a bar. Drawn full width and scaled (`transform: scaleX`), so a new value,
 * after a filter change for example, glides on the compositor instead of resizing the layout.
 * Put it in a track that clips (`overflow-hidden`) and carries the radius.
 */
export function BarFill({ ratio, className }: BarFillProps) {
  const r = Number.isFinite(ratio) ? Math.min(1, Math.max(0, ratio)) : 0
  return (
    <span
      aria-hidden
      className={cn("bar-fill block h-full", className)}
      style={{ "--bar": r.toFixed(4) } as React.CSSProperties}
    />
  )
}
