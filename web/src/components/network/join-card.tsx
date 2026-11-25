import { LoaderCircle, Share2, TriangleAlert } from "lucide-react"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { describeNetworkError, describeStatus, type NetworkStatus } from "@/lib/network"
import { JoinDialog } from "./join-dialog"
import { hasLeft, useNetworkStatus } from "./use-network"
import { t } from "@/i18n"

function Notice({ children, busy = false }: { children: React.ReactNode; busy?: boolean }) {
  const Icon = busy ? LoaderCircle : TriangleAlert
  return (
    <p
      role="status"
      className="flex items-start gap-2 rounded-md border bg-bg px-3 py-2 text-sm text-fg-muted"
    >
      <Icon
        aria-hidden
        className={busy ? "mt-0.5 size-4 shrink-0 animate-spin" : "mt-0.5 size-4 shrink-0"}
      />
      <span className="min-w-0">{children}</span>
    </p>
  )
}

/** Why joining is not possible right now, or null when it is. */
function blockedBy(s: NetworkStatus): React.ReactNode {
  if (!s.enabled_env)
    return t("network_join_blocked_env")
  if (!s.hub_configured)
    return t("network_join_blocked_hub")
  return null
}

/**
 * The card shown while this system is NOT a member: it says so, and offers to join. Joining is
 * always an explicit choice; staying out needs no action.
 */
export function JoinCard({ onJoined }: { onJoined?: () => void }) {
  const { canWrite } = useAuth()
  const q = useNetworkStatus()
  const [open, setOpen] = useState(false)
  const s = q.data
  if (q.isPending) {
    return (
      <FindingCard
        eyebrow={t("network_join_eyebrow")}
        finding={t("network_join_checking")}
      >
        <SkeletonText lines={2} />
      </FindingCard>
    )
  }
  if (!s) {
    return (
      <FindingCard
        eyebrow={t("network_join_eyebrow")}
        finding={t("network_join_status_unavailable")}
      >
        <p className="text-sm text-fg-muted">{t("network_join_status_unavailable_detail")}</p>
      </FindingCard>
    )
  }
  const blocked = blockedBy(s)
  const busy = s.state === "enrolling" || s.state === "leaving"
  const error = s.state === "error" ? describeNetworkError(s.last_error_code) : null
  return (
    <FindingCard
      eyebrow={t("network_join_eyebrow")}
      finding={describeStatus(s)}
      detail={
        s.state === "off"
          ? t("network_join_detail_off")
          : undefined
      }
    >
      <div className="space-y-4">
        {blocked ? <Notice>{blocked}</Notice> : null}
        {busy ? (
          <Notice busy>
            {s.state === "enrolling"
              ? t("network_join_busy_enrolling")
              : t("network_join_busy_leaving")}
          </Notice>
        ) : null}
        {error ? <Notice>{error}</Notice> : null}
        {s.state === "off" || s.state === "error" ? (
          canWrite ? (
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={() => setOpen(true)} disabled={!!blocked}>
                <Share2 aria-hidden />
                {hasLeft() ? t("network_join_again") : t("network_join_button")}
              </Button>
              <span className="text-xs text-fg-muted">
                {t("network_join_hint")}
              </span>
            </div>
          ) : (
            <p className="text-sm text-fg-muted">
              {t("network_join_admin_only")}
            </p>
          )
        ) : null}
      </div>
      <JoinDialog open={open} onOpenChange={setOpen} {...(onJoined ? { onJoined } : {})} />
    </FindingCard>
  )
}
