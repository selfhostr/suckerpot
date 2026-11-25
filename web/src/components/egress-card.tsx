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
        .filter((t): t is string => t !== null)
        .sort()
        .at(-1)
    : undefined
  return (
    <FindingCard
      eyebrow="Outbound traffic"
      finding={
        e
          ? describeEgress(e)
          : q.isError
            ? "The egress status is not available."
            : "Checking the VPN…"
      }
      detail="Enrichment and the sample collector only talk to the internet while the tunnel is up and its exit address is allowed."
    >
      {!e ? (
        q.isPending ? (
          <SkeletonText lines={3} className="py-1" />
        ) : (
          <p className="text-sm text-fg-muted">This status is not available right now.</p>
        )
      ) : (
        <div className="space-y-5">
          <dl className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <dt className="text-xs text-fg-muted">Gate</dt>
              <dd className="text-sm text-fg">
                {open ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-status-ok">
                    <CircleCheck aria-hidden className="size-3.5" strokeWidth={2.25} />
                    Open
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-sev-warning">
                    <TriangleAlert aria-hidden className="size-3.5" strokeWidth={2.25} />
                    Closed: {egressReason(closed?.reason ?? null)}
                  </span>
                )}
              </dd>
            </div>
            <div className="space-y-1">
              <dt className="text-xs text-fg-muted">Last check</dt>
              <dd className="text-sm text-fg">
                {checked ? <RelativeTime iso={checked} className="text-sm" /> : "Not yet"}
              </dd>
            </div>
            <div className="col-span-2 space-y-1">
              <dt className="text-xs text-fg-muted">Exit address</dt>
              <dd className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg">
                <span>
                  {e.exit_ip_allowed === null
                    ? "Not checked yet"
                    : e.exit_ip_allowed
                      ? "On the allow-list"
                      : "Not on the allow-list"}
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
                      {reveal ? "Hide" : "Show"}
                    </Button>
                  </>
                ) : null}
              </dd>
            </div>
          </dl>

          <div className="space-y-2 border-t pt-5">
            <div className="flex items-baseline justify-between gap-3 text-sm">
              <span className="text-fg">Collector fetches today</span>
              <span className="text-xs text-fg-muted">
                <span className="text-sm font-medium text-fg">
                  {formatNumber(e.collector_quota.used)}
                </span>{" "}
                of {formatNumber(e.collector_quota.limit)}
              </span>
            </div>
            <Meter
              value={e.collector_quota.used}
              max={e.collector_quota.limit}
              label="Collector fetches used today"
              valueText={`${formatNumber(e.collector_quota.used)} of ${formatNumber(e.collector_quota.limit)}`}
              tone={usageTone(e.collector_quota.used / Math.max(1, e.collector_quota.limit))}
            />
          </div>
          <div className="space-y-2">
            <div className="flex items-baseline justify-between gap-3 text-sm">
              <span className="text-fg">Quarantine</span>
              <span className="text-xs text-fg-muted">
                <span className="text-sm font-medium text-fg">
                  {formatBytes(e.quarantine.used_bytes)}
                </span>{" "}
                of {formatBytes(e.quarantine.max_bytes)}
              </span>
            </div>
            <Meter
              value={e.quarantine.used_bytes}
              max={e.quarantine.max_bytes}
              label="Quarantine space used"
              valueText={`${formatBytes(e.quarantine.used_bytes)} of ${formatBytes(e.quarantine.max_bytes)}`}
              tone={usageTone(e.quarantine.used_bytes / Math.max(1, e.quarantine.max_bytes))}
            />
          </div>
        </div>
      )}
    </FindingCard>
  )
}
