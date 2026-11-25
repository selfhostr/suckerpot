import { Radio } from "lucide-react"
import { useRef } from "react"
import { Link } from "react-router"
import { useLiveFeed } from "@/app/use-live-feed"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { LiveEventRow } from "@/components/live-event-row"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { useReorderMotion } from "@/hooks/use-reorder-motion"
import { LATEST_ROWS } from "@/lib/latest"
import { deriveStats, liveFinding } from "@/lib/live-stats"

/** The newest events from the shared live feed, opened by a finding about the last minute. */
export function LatestEventsCard({ className }: { className?: string }) {
  const { events, stats, status } = useLiveFeed()
  const latest = events.slice(0, LATEST_ROWS)
  const finding = liveFinding(stats ?? (events.length ? deriveStats(events) : null))
  // A new event fades in at the top while the others glide down one row.
  const listRef = useRef<HTMLDivElement>(null)
  useReorderMotion(
    listRef,
    latest.map((e) => String(e.id)),
  )

  return (
    <FindingCard
      className={className}
      eyebrow="Latest events"
      finding={finding}
      action={
        <Button asChild variant="ghost" size="sm">
          <Link to="/">See all</Link>
        </Button>
      }
      bodyClassName="p-0 sm:p-0 pt-4 sm:pt-4"
    >
      {latest.length > 0 ? (
        <div ref={listRef} role="list" aria-label="Latest events" className="border-t">
          {latest.map((e) => (
            <div key={e.id} role="listitem" data-flip={e.id} className="border-b last:border-b-0">
              <LiveEventRow event={e} compact />
            </div>
          ))}
        </div>
      ) : status === "connecting" || status === "reconnecting" ? (
        <SkeletonList rows={4} className="border-t" />
      ) : (
        <EmptyState
          variant="bare"
          icon={Radio}
          title="Nothing has arrived yet"
          description="New events appear here the moment a sensor records them."
          className="border-t py-8"
        />
      )}
    </FindingCard>
  )
}
