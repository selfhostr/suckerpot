import { CircleCheck, Share2 } from "lucide-react"
import { useState, type ReactNode } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { JoinDialog } from "@/components/network/join-dialog"
import { WhatYouShare } from "@/components/network/what-you-share"
import { useNetworkStatus } from "@/components/network/use-network"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { BENEFIT } from "@/lib/network"

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
              ? `You are part of the SuckerPot network as ${s.pseudonym}.`
              : "You are part of the SuckerPot network."
            : "Joining the SuckerPot network…"}
        </h3>
        <p className="text-sm text-fg-muted">
          You can read everything that was sent, change your pseudonym or leave with one button in{" "}
          <Link to="/settings?tab=network" className="text-fg underline underline-offset-4">
            Settings, Network
          </Link>
          .
        </p>
      </div>
    )
  }

  const blocked = !s.enabled_env
    ? "Sharing is switched off in this system's settings (NETWORK_ENABLED=false)."
    : !s.hub_configured
      ? "No network hub is configured yet, so there is nothing to join."
      : null

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <h3 className="type-card-title text-fg">
          Join the SuckerPot network{" "}
          <span className="font-normal text-fg-muted">(recommended)</span>
        </h3>
        <p className="max-w-3xl text-sm text-fg-muted">{BENEFIT}</p>
        <p className="max-w-3xl text-sm text-fg">
          One button and your password. Until you join, nothing leaves this system. You can skip
          this, and join or leave later in Settings.
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
            Join the network
          </Button>
        ) : null}
        {onSkip ? (
          <Button variant="outline" onClick={onSkip}>
            Not now
          </Button>
        ) : null}
      </div>
      <JoinDialog open={open} onOpenChange={setOpen} {...(onDone ? { onJoined: onDone } : {})} />
    </div>
  )
}
