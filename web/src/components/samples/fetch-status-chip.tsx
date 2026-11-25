import {
  CircleCheck,
  CircleDashed,
  CircleOff,
  CircleSlash,
  CircleX,
  Clock,
  HardDrive,
  Ruler,
  type LucideIcon,
} from "lucide-react"
import { fetchStatusLabel, FETCH_STATUS } from "@/lib/samples"
import type { FetchStatus } from "@/lib/trends"
import { cn } from "@/lib/utils"

const ICON: Record<FetchStatus, LucideIcon> = {
  fetched: CircleCheck,
  pending: Clock,
  failed: CircleX,
  gone: CircleOff,
  refused: CircleSlash,
  too_large: Ruler,
  unsupported: CircleDashed,
  quarantine_full: HardDrive,
}

/**
 * Whether the collector fetched a download URL. Always a word plus an icon; neutral tones only,
 * because a failed fetch is not a severe event (red stays for malware that was dropped).
 */
export function FetchStatusChip({
  status,
  url,
  className,
}: {
  status: FetchStatus
  url?: string
  className?: string
}) {
  const Icon = ICON[status]
  return (
    <span
      title={FETCH_STATUS[status].explain}
      className={cn(
        "inline-flex h-(--chip) items-center gap-1 rounded-sm border border-border-strong px-2 text-xs font-medium",
        status === "fetched" ? "text-fg" : "text-fg-muted",
        className,
      )}
    >
      <Icon aria-hidden className="size-3.5" strokeWidth={2.25} />
      {fetchStatusLabel(status, url)}
    </span>
  )
}
