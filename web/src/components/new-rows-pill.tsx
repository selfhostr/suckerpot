import { ArrowUp } from "lucide-react"
import { plural } from "@/lib/format"
import { cn } from "@/lib/utils"

interface NewRowsPillProps {
  /** Rows held back while the reader is further down. Nothing shows at 0. */
  count: number
  /** "session" -> "3 new sessions". */
  noun: string
  /** The count is a floor ("20+ new sessions"). */
  more?: boolean
  onShow: () => void
  className?: string
}

/**
 * "N new sessions": rows arrived at the top of a list the reader has scrolled down, and were held
 * so the list does not jump. It sits in a zero-height sticky slot under the top bar, so showing
 * it moves nothing; clicking it brings the rows in and scrolls back up.
 */
export function NewRowsPill({ count, noun, more = false, onShow, className }: NewRowsPillProps) {
  return (
    <div
      className={cn("pointer-events-none sticky top-18 z-20 flex h-0 justify-center", className)}
    >
      <div aria-live="polite">
        {count > 0 ? (
          <button
            type="button"
            onClick={onShow}
            className="pointer-events-auto inline-flex h-8 animate-slide-in items-center gap-1.5 rounded-full border bg-surface-raised px-3 text-xs font-medium text-fg shadow-md transition-colors hover:bg-surface-hover"
          >
            <ArrowUp aria-hidden className="size-3.5" />
            {more ? `${count}+ new ${noun}s` : plural(count, `new ${noun}`)}
          </button>
        ) : null}
      </div>
    </div>
  )
}
