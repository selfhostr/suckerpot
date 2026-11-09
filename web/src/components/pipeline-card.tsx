import { CircleCheck, CircleHelp, OctagonAlert } from "lucide-react"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { usePipeline } from "@/hooks/use-pipeline"
import { formatNumber } from "@/lib/format"
import { pipelineFinding } from "@/lib/pipeline"

const STATE = {
  ok: { label: "Storing events", icon: CircleCheck, className: "text-status-ok" },
  stalled: { label: "Stalled", icon: OctagonAlert, className: "text-sev-severe" },
  unknown: { label: "Unknown", icon: CircleHelp, className: "text-fg-muted" },
} as const

/** Settings, General tab: is the service that stores events working, and when did it last write. */
export function PipelineCard() {
  const { pipeline: p, loading } = usePipeline()
  const state = STATE[p.status]
  const Icon = state.icon
  return (
    <FindingCard
      eyebrow="Pipeline"
      finding={loading ? "Checking the pipeline…" : pipelineFinding(p)}
      detail="Sensors hand events to the ingest service, which stores them. If it stops, events wait in a short queue, then the oldest are lost. Ingest checks in every 30 seconds while every stream is healthy."
    >
      {loading ? (
        <SkeletonText lines={2} className="py-1" />
      ) : (
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">Status</dt>
            <dd>
              <span
                className={`inline-flex items-center gap-1.5 text-sm font-medium ${state.className}`}
              >
                <Icon aria-hidden className="size-3.5" strokeWidth={2.25} />
                {state.label}
              </span>
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">Last healthy check</dt>
            <dd className="text-sm text-fg">
              {p.last_ok_at ? <RelativeTime iso={p.last_ok_at} className="text-sm" /> : "Not known"}
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">Events set aside</dt>
            <dd className="text-sm text-fg tabular-nums">{formatNumber(p.parked_events)}</dd>
          </div>
        </dl>
      )}
    </FindingCard>
  )
}
