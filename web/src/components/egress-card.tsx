import { useQuery } from "@tanstack/react-query"
import { CircleCheck, Eye, EyeOff, TriangleAlert } from "lucide-react"
import { useState } from "react"
import { FindingCard } from "@/components/finding-card"
import { Meter } from "@/components/meter"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { formatBytes, formatNumber } from "@/lib/format"
import { describeEgress, egressOpen, egressReason, sampleKeys, samplesApi } from "@/lib/samples"
import { usageTone } from "@/lib/settings"
import { t } from "@/i18n"

/** Settings, General tab: is outbound traffic leaving through the VPN, and what the collector uses. */
export function EgressCard() {
  const q = useQuery({
    queryKey: sampleKeys.egress,
    queryFn: samplesApi.egress,
    refetchInterval: 30_000,
  })
  const [reveal, setReveal] = useState(false)
  const e = q.data
  const open = e ? egressOpen(e) : false
  const closed = e ? (e.ingest.state === "closed" ? e.ingest : e.collector) : null
  const checked = e
    ? [e.ingest.checked_at, e.collector.checked_at]
        .filter((x): x is string => x !== null)
        .sort()
        .at(-1)
    : undefined
  return (
    <FindingCard
      eyebrow={t("egress_eyebrow")}
      help="egress"
      finding={
        e
          ? describeEgress(e)
          : q.isError
            ? t("egress_unavailable")
            : t("egress_checking")
      }
      detail={t("egress_detail")}
    >
      {!e ? (
        q.isPending ? (
          <SkeletonText lines={3} className="py-1" />
        ) : (
          <p className="text-sm text-fg-muted">{t("egress_unavailable_detail")}</p>
        )
      ) : (
        <div className="space-y-5">
          <dl className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <dt className="text-xs text-fg-muted">{t("egress_gate")}</dt>
              <dd className="text-sm text-fg">
                {open ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-status-ok">
                    <CircleCheck aria-hidden className="size-3.5" strokeWidth={2.25} />
                    {t("egress_open")}
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-sev-warning">
                    <TriangleAlert aria-hidden className="size-3.5" strokeWidth={2.25} />
                    {t("egress_closed", { reason: egressReason(closed?.reason ?? null) })}
                  </span>
                )}
              </dd>
            </div>
            <div className="space-y-1">
              <dt className="text-xs text-fg-muted">{t("egress_last_check")}</dt>
              <dd className="text-sm text-fg">
                {checked ? <RelativeTime iso={checked} className="text-sm" /> : t("egress_not_yet")}
              </dd>
            </div>
            <div className="col-span-2 space-y-1">
              <dt className="text-xs text-fg-muted">{t("egress_exit_address")}</dt>
              <dd className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg">
                <span>
                  {e.exit_ip_allowed === null
                    ? t("egress_exit_unchecked")
                    : e.exit_ip_allowed
                      ? t("egress_exit_allowed")
                      : t("egress_exit_not_allowed")}
                </span>
                {e.exit_ip ? (
                  <>
                    <span className="font-mono text-xs" data-testid="exit-ip">
                      {reveal ? e.exit_ip : "•••.•••.•••.•••"}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-pressed={reveal}
                      onClick={() => setReveal((v) => !v)}
                    >
                      {reveal ? (
                        <EyeOff aria-hidden className="size-3.5" />
                      ) : (
                        <Eye aria-hidden className="size-3.5" />
                      )}
                      {reveal ? t("egress_hide") : t("egress_show")}
                    </Button>
                  </>
                ) : null}
              </dd>
            </div>
          </dl>

          <div className="space-y-2 border-t pt-5">
            <div className="flex items-baseline justify-between gap-3 text-sm">
              <span className="min-w-0 text-fg">{t("egress_collector_today")}</span>
              <span className="text-xs text-fg-muted">
                <span className="text-sm font-medium text-fg">
                  {formatNumber(e.collector_quota.used)}
                </span>{" "}
                {t("egress_of", { limit: formatNumber(e.collector_quota.limit) })}
              </span>
            </div>
            <Meter
              value={e.collector_quota.used}
              max={e.collector_quota.limit}
              label={t("egress_collector_meter")}
              valueText={t("egress_used_of", {
                used: formatNumber(e.collector_quota.used),
                limit: formatNumber(e.collector_quota.limit),
              })}
              tone={usageTone(e.collector_quota.used / Math.max(1, e.collector_quota.limit))}
            />
          </div>
          <div className="space-y-2">
            <div className="flex items-baseline justify-between gap-3 text-sm">
              <span className="min-w-0 text-fg">{t("egress_quarantine")}</span>
              <span className="text-xs text-fg-muted">
                <span className="text-sm font-medium text-fg">
                  {formatBytes(e.quarantine.used_bytes)}
                </span>{" "}
                {t("egress_of", { limit: formatBytes(e.quarantine.max_bytes) })}
              </span>
            </div>
            <Meter
              value={e.quarantine.used_bytes}
              max={e.quarantine.max_bytes}
              label={t("egress_quarantine_meter")}
              valueText={t("egress_used_of", {
                used: formatBytes(e.quarantine.used_bytes),
                limit: formatBytes(e.quarantine.max_bytes),
              })}
              tone={usageTone(e.quarantine.used_bytes / Math.max(1, e.quarantine.max_bytes))}
            />
          </div>
        </div>
      )}
    </FindingCard>
  )
}
