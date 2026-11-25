import { useQuery } from "@tanstack/react-query"
import { ArrowUpRight, Sparkles } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { SeverityBadge } from "@/components/severity-badge"
import { Skeleton } from "@/components/ui/skeleton"
import { t } from "@/i18n"
import { api, queryKeys } from "@/lib/api"
import { maskIpsInText } from "@/lib/format"
import { INSIGHT_KIND_LABEL, type Insight } from "@/lib/trends"
import { cn } from "@/lib/utils"

const HOUR = 3_600_000
const WINDOW_DAYS = 7

/** The auto-written insights: one sentence each, a severity icon, a link to the proof. */
export function InsightsCard({ className }: { className?: string }) {
  const [end] = useState(() => Math.ceil(Date.now() / HOUR) * HOUR)
  const range = {
    since: new Date(end - WINDOW_DAYS * 24 * HOUR).toISOString(),
    until: new Date(end).toISOString(),
  }
  const q = useQuery({ queryKey: queryKeys.insights(range), queryFn: () => api.insights(range) })
  const items = q.data?.items ?? []

  const finding = q.isPending
    ? t("insights_reading")
    : q.isError
      ? t("insights_unavailable")
      : items.length === 0
        ? t("insights_none")
        : t("insights_stand_out", { count: items.length })

  return (
    <FindingCard
      className={className}
      eyebrow={t("insights_title")}
      finding={finding}
      detail={items.length > 0 ? t("insights_detail") : undefined}
    >
      {q.isPending ? (
        <div role="status" aria-label={t("common_loading")} className="space-y-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : q.isError ? (
        <EmptyState
          variant="bare"
          icon={Sparkles}
          title={t("insights_error_title")}
          description={q.error.message}
          className="py-6"
        />
      ) : items.length === 0 ? (
        <EmptyState
          variant="bare"
          icon={Sparkles}
          title={t("insights_empty_title")}
          description={t("insights_empty_description")}
          className="py-6"
        />
      ) : (
        <ul aria-label={t("insights_title")} className="-mx-2 space-y-1">
          {items.map((i) => (
            <li key={i.id}>
              <InsightRow insight={i} />
            </li>
          ))}
        </ul>
      )}
    </FindingCard>
  )
}

export function InsightRow({ insight, className }: { insight: Insight; className?: string }) {
  const { masked } = useIpMask()
  const text = masked ? maskIpsInText(insight.sentence) : insight.sentence
  return (
    <Link
      to={insight.link}
      className={cn(
        "group/insight flex items-start gap-3 rounded-md px-2 py-2.5 transition-colors duration-150 hover:bg-surface-hover",
        className,
      )}
    >
      <SeverityBadge severity={insight.severity} iconOnly className="mt-px" />
      <span className="min-w-0 flex-1 text-sm text-pretty text-fg">
        <span className="sr-only">
          {t("insights_row_prefix", {
            kind:
              (INSIGHT_KIND_LABEL as Partial<Record<string, string>>)[insight.kind] ??
              t("insights_kind_fallback"),
          })}{" "}
        </span>
        {text}
      </span>
      <ArrowUpRight
        aria-hidden
        className="mt-1 size-3.5 shrink-0 text-fg-subtle transition-colors group-hover/insight:text-fg"
      />
    </Link>
  )
}
