import { Skeleton } from "@/components/ui/skeleton"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

/** Placeholder lines for text blocks. */
export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)} aria-hidden>
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className={cn("h-3.5", i === lines - 1 ? "w-3/5" : "w-full")} />
      ))}
    </div>
  )
}

/** Same footprint as a SessionRow, so nothing jumps when data arrives. */
export function SkeletonRow({ className }: { className?: string }) {
  return (
    <div
      aria-hidden
      className={cn(
        "flex items-center gap-4 border-b px-4 py-3.5 last:border-b-0 sm:px-5",
        className,
      )}
    >
      <Skeleton className="h-6 w-16 shrink-0" />
      <div className="flex min-w-0 flex-1 items-center gap-2">
        <Skeleton className="h-6 w-28 shrink-0" />
        <Skeleton className="h-3.5 w-full max-w-md" />
      </div>
      <Skeleton className="hidden h-3.5 w-14 shrink-0 sm:block" />
    </div>
  )
}

export function SkeletonList({ rows = 8, className }: { rows?: number; className?: string }) {
  return (
    <div className={className} role="status" aria-label={t("common_loading")}>
      {Array.from({ length: rows }, (_, i) => (
        <SkeletonRow key={i} />
      ))}
    </div>
  )
}

export function SkeletonTile({ className }: { className?: string }) {
  return (
    <div
      aria-hidden
      className={cn("space-y-3 rounded-lg border bg-surface p-4 shadow-sm sm:p-5", className)}
    >
      <Skeleton className="h-3 w-20" />
      <Skeleton className="h-8.5 w-28" />
      <Skeleton className="h-3 w-32" />
    </div>
  )
}

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div
      aria-hidden
      className={cn("space-y-4 rounded-lg border bg-surface p-4 shadow-sm sm:p-5", className)}
    >
      <div className="space-y-2">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-4 w-3/4" />
      </div>
      <Skeleton className="h-36 w-full" />
    </div>
  )
}

/** Placeholder for a whole page while its code loads: header, KPI row, two cards. */
export function PageSkeleton() {
  return (
    <div role="status" aria-label={t("ui_loading_page")} className="animate-fade-in">
      <div className="space-y-2.5 pb-6">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-4 w-full max-w-md" />
      </div>
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <SkeletonTile key={i} />
        ))}
      </div>
      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    </div>
  )
}
