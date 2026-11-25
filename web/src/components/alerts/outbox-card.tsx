import { useInfiniteQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import { CircleAlert, CircleCheck, CircleDashed, CircleSlash, type LucideIcon } from "lucide-react"
import { useMemo } from "react"
import { FindingCard } from "@/components/finding-card"
import { t } from "@/i18n"
import { RelativeTime } from "@/components/relative-time"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonText } from "@/components/skeletons"
import {
  alertKeys,
  alertsApi,
  describeError,
  outboxFinding,
  RULE_TITLE,
  STATE_LABEL,
  type OutboxItem,
  type OutboxState,
} from "@/lib/alerts"
import { cn } from "@/lib/utils"

const STATE_STYLE: Record<OutboxState, { icon: LucideIcon; className: string }> = {
  sent: { icon: CircleCheck, className: "text-status-ok" },
  pending: { icon: CircleDashed, className: "text-fg-muted" },
  failed: { icon: CircleAlert, className: "text-sev-warning" },
  suppressed: { icon: CircleSlash, className: "text-fg-muted" },
}

/** One queued, sent or held-back alert: severity, title, summary, destination, state and time. */
export function OutboxRow({ item }: { item: OutboxItem }) {
  const { icon: Icon, className } = STATE_STYLE[item.state]
  const reason = describeError(item.error_code)
  return (
    <li className="grid grid-cols-[1fr_auto] items-start gap-x-3 gap-y-1 px-4 py-3 sm:px-5">
      <div className="min-w-0 space-y-1">
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium text-fg">
          {item.severity ? <SeverityBadge severity={item.severity} /> : null}
          <span className="min-w-0 text-pretty">{item.title ?? RULE_TITLE[item.rule_kind]}</span>
        </p>
        {item.summary ? <p className="text-xs text-fg-muted">{item.summary}</p> : null}
        <p className="text-xs text-fg-muted">
          {item.channel_name
            ? t("outbox_to", { channel: item.channel_name })
            : t("outbox_to_deleted")}
          {reason ? <> · {reason}</> : null}
        </p>
      </div>
      <div className="flex flex-col items-end gap-1 text-right">
        <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", className)}>
          <Icon aria-hidden className="size-3.5" strokeWidth={2.25} />
          {STATE_LABEL[item.state]}
        </span>
        <RelativeTime iso={item.sent_at ?? item.created_at} className="text-xs" />
      </div>
    </li>
  )
}

/** The last alerts that were queued, sent or held back. */
export function OutboxCard() {
  const q = useInfiniteQuery({
    queryKey: alertKeys.outbox,
    queryFn: ({ pageParam }) => alertsApi.outbox(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    refetchInterval: 30_000,
  })
  const items = useMemo(() => (q.data?.pages ?? []).flatMap((p) => p.items), [q.data])
  return (
    <FindingCard
      eyebrow={t("outbox_title")}
      finding={q.isPending ? t("outbox_checking") : outboxFinding(items)}
      detail={t("outbox_detail")}
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {q.isPending ? (
        <div className="px-4 sm:px-5">
          <SkeletonText lines={3} className="py-1" />
        </div>
      ) : items.length === 0 ? (
        <p className="border-t px-4 py-6 text-sm text-fg-muted sm:px-5">
          {t("outbox_empty")}
        </p>
      ) : (
        <>
          <ul aria-label={t("outbox_title")} className="divide-y border-t">
            {items.map((item) => (
              <OutboxRow key={item.id} item={item} />
            ))}
          </ul>
          <LoadMore
            hasNextPage={q.hasNextPage}
            isFetchingNextPage={q.isFetchingNextPage}
            fetchNextPage={q.fetchNextPage}
            label={t("outbox_older")}
            className="border-t"
          />
        </>
      )}
    </FindingCard>
  )
}
