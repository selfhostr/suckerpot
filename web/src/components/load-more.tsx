import { useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface LoadMoreProps {
  hasNextPage: boolean
  isFetchingNextPage: boolean
  fetchNextPage: () => unknown
  /** Button text while idle, e.g. "Show older reports". */
  label: string
  className?: string
}

/**
 * The end of a paged list that is not virtualized: the next page loads by itself when this
 * row gets within a screen of the viewport, and the button stays as the keyboard and
 * no-IntersectionObserver fallback (see the scroll model in DESIGN.md).
 */
export function LoadMore({
  hasNextPage,
  isFetchingNextPage,
  fetchNextPage,
  label,
  className,
}: LoadMoreProps) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el || !hasNextPage || isFetchingNextPage || typeof IntersectionObserver === "undefined")
      return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) void fetchNextPage()
      },
      { rootMargin: "0px 0px 600px 0px" },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [hasNextPage, isFetchingNextPage, fetchNextPage])
  if (!hasNextPage) return null
  return (
    <div ref={ref} className={cn("flex justify-center px-4 py-3 sm:px-5", className)}>
      <Button
        variant="outline"
        size="sm"
        disabled={isFetchingNextPage}
        onClick={() => void fetchNextPage()}
      >
        {isFetchingNextPage ? "Loading…" : label}
      </Button>
    </div>
  )
}
