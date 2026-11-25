import { CircleCheck, CircleHelp, OctagonAlert } from "lucide-react"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { usePipeline } from "@/hooks/use-pipeline"
import { t, tk } from "@/i18n"
import { formatNumber } from "@/lib/format"
import { pipelineFinding } from "@/lib/pipeline"

const STATE = {
  ok: { label: tk("pipeline_state_ok"), icon: CircleCheck, className: "text-status-ok" },
  stalled: {
    label: tk("pipeline_state_stalled"),
    icon: OctagonAlert,
    className: "text-sev-severe",
  },
  unknown: { label: tk("pipeline_state_unknown"), icon: CircleHelp, className: "text-fg-muted" },
} as const

/** Settings, General tab: is the service that stores events working, and when did it last write. */
export function PipelineCard() {
  const { pipeline: p, loading } = usePipeline()
  const state = STATE[p.status]
  const Icon = state.icon
  return (
    <FindingCard
      eyebrow={t("pipeline_title")}
      help="pipeline"
      finding={loading ? t("pipeline_checking") : pipelineFinding(p)}
      detail={t("pipeline_detail")}
    >
      {loading ? (
        <SkeletonText lines={2} className="py-1" />
      ) : (
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">{t("pipeline_status")}</dt>
            <dd>
              <span
                className={`inline-flex items-center gap-1.5 text-sm font-medium ${state.className}`}
              >
                <Icon aria-hidden className="size-3.5" strokeWidth={2.25} />
                {t(state.label)}
              </span>
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">{t("pipeline_last_ok")}</dt>
            <dd className="text-sm text-fg">
              {p.last_ok_at ? (
                <RelativeTime iso={p.last_ok_at} className="text-sm" />
              ) : (
                t("pipeline_not_known")
              )}
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="text-xs text-fg-muted">{t("pipeline_set_aside")}</dt>
            <dd className="text-sm text-fg tabular-nums">{formatNumber(p.parked_events)}</dd>
          </div>
        </dl>
      )}
    </FindingCard>
  )
}
