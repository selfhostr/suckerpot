import { useQuery } from "@tanstack/react-query"
import { Flag } from "lucide-react"
import { Link } from "react-router"
import { Skeleton } from "@/components/ui/skeleton"
import { api, queryKeys } from "@/lib/api"
import { cn } from "@/lib/utils"

/**
 * "Part of campaign <name>" on the session page: the bridge from one session to the bigger story.
 * A campaign that was merged into another points at the one that absorbed it. If the campaign
 * cannot be read the chip is simply not shown: it never gets in the way of the session.
 */
export function CampaignChip({ id, className }: { id: number; className?: string }) {
  const first = useQuery({
    queryKey: queryKeys.campaign(id),
    queryFn: () => api.campaign(id),
    staleTime: 60_000,
  })
  const targetId = first.data?.merged_into ?? null
  const merged = useQuery({
    queryKey: queryKeys.campaign(targetId ?? 0),
    queryFn: () => api.campaign(targetId ?? 0),
    enabled: targetId !== null,
    staleTime: 60_000,
  })
  const campaign = targetId !== null ? merged.data : first.data

  if (first.isPending || (targetId !== null && merged.isPending)) {
    return <Skeleton className={cn("h-6 w-56 max-w-full", className)} />
  }
  if (!campaign) return null
  return (
    <Link
      to={`/campaigns/${campaign.id}`}
      className={cn(
        "inline-flex h-(--chip) max-w-full animate-fade-in items-center gap-1.5 rounded-sm border border-border-strong px-2 text-xs text-fg-muted transition-colors duration-150 hover:border-fg-subtle hover:text-fg",
        className,
      )}
    >
      <Flag aria-hidden className="size-3.5 shrink-0" strokeWidth={2} />
      <span className="shrink-0">Part of campaign</span>
      <span className="truncate font-medium text-fg">{campaign.name}</span>
    </Link>
  )
}
