import { CircleCheck, Share2 } from "lucide-react"
import { useState, type ReactNode } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { JoinDialog } from "@/components/network/join-dialog"
import { WhatYouShare } from "@/components/network/what-you-share"
import { useNetworkStatus } from "@/components/network/use-network"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { benefitText } from "@/lib/network"

/**
 * The optional "Join the SuckerPot network" step of the setup flow. Standalone: the setup flow
 * decides where it goes and what "next" means.
 *
 * Joining is recommended but never automatic: it needs the join button and the password. "Not now"
 * does nothing and sends nothing, and the step says so. When sharing is switched off in .env and no hub is configured
 * there is nothing to offer: the step shows `fallback` (nothing by default). A member sees a done
 * state.
 *
 * - `onDone` is called after joining.
 * - `onSkip` is called when the person chooses "Not now". Without it there is no "Not now"
 *   button: the setup wizard has its own "Skip for now".
 */
export function NetworkStep({
  onDone,
  onSkip,
  fallback = null,
}: {
  onDone?: () => void
  onSkip?: () => void
  fallback?: ReactNode
}) {
  const { canWrite } = useAuth()
  const q = useNetworkStatus()
  const [open, setOpen] = useState(false)
  const s = q.data
  if (q.isPending) return <SkeletonText lines={4} />
  if (!s || (!s.enabled_env && !s.hub_configured)) return <>{fallback}</>

  if (s.state === "member" || s.state === "enrolling") {
    return (
      <div className="space-y-3">
        <h3 className="flex items-center gap-2 type-card-title text-fg">
          <CircleCheck aria-hidden className="size-4 text-status-ok" strokeWidth={2.25} />
          {s.state === "member"
            ? s.pseudonym
              ? t("setup_network_member_as", { name: s.pseudonym })
              : t("setup_network_member")
            : t("setup_network_joining")}
        </h3>
        <p className="text-sm text-fg-muted">
          {tNodes(
            "setup_network_manage",
            {},
            {
              link: (
                <Link to="/settings?tab=network" className="text-fg underline underline-offset-4">
                  {t("setup_network_manage_link")}
                </Link>
              ),
            },
          )}
        </p>
      </div>
    )
  }

  const blocked = !s.enabled_env
    ? t("setup_network_sharing_off")
    : !s.hub_configured
      ? t("setup_network_no_hub")
      : null

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <h3 className="type-card-title text-fg">
          {t("setup_network_join_title")}{" "}
          <span className="font-normal text-fg-muted">{t("setup_network_recommended")}</span>
        </h3>
        <p className="max-w-3xl text-sm text-fg-muted">{benefitText()}</p>
        <p className="max-w-3xl text-sm text-fg">
          {t("setup_network_join_note")}
        </p>
      </div>
      <WhatYouShare />
      {blocked ? (
        <p
          role="status"
          className="rounded-md border border-dashed px-3 py-2 text-sm text-fg-muted"
        >
          {blocked}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-3">
        {canWrite ? (
          <Button onClick={() => setOpen(true)} disabled={!!blocked}>
            <Share2 aria-hidden />
            {t("setup_network_join")}
          </Button>
        ) : null}
        {onSkip ? (
          <Button variant="outline" onClick={onSkip}>
            {t("setup_network_not_now")}
          </Button>
        ) : null}
      </div>
      <JoinDialog open={open} onOpenChange={setOpen} {...(onDone ? { onJoined: onDone } : {})} />
    </div>
  )
}
