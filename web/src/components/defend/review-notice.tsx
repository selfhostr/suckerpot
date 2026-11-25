import { TriangleAlert } from "lucide-react"

/** Always visible on the Detections page: these rules are a starting point, not a verdict. */
export function ReviewNotice() {
  return (
    <aside
      aria-labelledby="review-notice-title"
      className="mb-6 flex items-start gap-3 rounded-lg border border-border-strong bg-surface-raised px-4 py-3.5 shadow-sm"
    >
      <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
      <div className="space-y-1">
        <h2 id="review-notice-title" className="type-subtitle text-fg">
          Review before deploying
        </h2>
        <p className="text-sm text-fg-muted">
          These rules come from traffic aimed at our decoys, not from your network. They can match
          harmless activity, such as your own scanners or tests. Try each one in log-only mode
          first, and read what it catches before you let it block anything.
        </p>
      </div>
    </aside>
  )
}
