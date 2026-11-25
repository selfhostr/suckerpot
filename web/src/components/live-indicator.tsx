import { t, tk } from "@/i18n"
import { cn } from "@/lib/utils"

export type LiveStatus = "live" | "connecting" | "reconnecting" | "offline"

const LABEL: Record<LiveStatus, string> = {
  live: tk("live_status_live"),
  connecting: tk("live_status_connecting"),
  reconnecting: tk("live_status_reconnecting"),
  offline: tk("live_status_offline"),
}

/** A small, calm status dot. The ring pulses slowly only while live. */
export function LiveIndicator({
  status,
  detail,
  className,
}: {
  status: LiveStatus
  detail?: string
  className?: string
}) {
  return (
    <span
      className={cn("inline-flex items-center gap-2 text-xs text-fg-muted", className)}
      role="status"
    >
      <span className="relative flex size-2">
        {status === "live" ? (
          <span
            aria-hidden
            className="absolute inset-0 animate-live-pulse rounded-full bg-status-ok"
          />
        ) : null}
        <span
          aria-hidden
          className={cn(
            "relative size-2 rounded-full",
            status === "live" && "bg-status-ok",
            (status === "connecting" || status === "reconnecting") && "bg-status-off opacity-60",
            status === "offline" && "border border-status-off",
          )}
        />
      </span>
      <span className="font-medium text-fg">{t(LABEL[status])}</span>
      {detail ? <span className="truncate">{detail}</span> : null}
    </span>
  )
}
