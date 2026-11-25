import { useQuery } from "@tanstack/react-query"
import { Ban, CircleCheck, Plus, Trash2 } from "lucide-react"
import { useState } from "react"
import { useIpMask } from "@/app/ip-mask"
import { FindingCard } from "@/components/finding-card"
import { OverrideDialog } from "@/components/defend/override-dialog"
import {
  RemoveOverrideDialog,
  type RemovingOverride,
} from "@/components/defend/remove-override-dialog"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { defendApi, defendKeys, KIND_META, type OverrideItem } from "@/lib/defend"
import { maskIpsInText, plural } from "@/lib/format"

function Row({
  item,
  canWrite,
  onRemove,
}: {
  item: OverrideItem
  canWrite: boolean
  onRemove: (target: RemovingOverride) => void
}) {
  const { masked } = useIpMask()
  const allow = item.action === "allow"
  const Icon = allow ? CircleCheck : Ban
  const value = masked ? maskIpsInText(item.value) : item.value
  return (
    <li className="flex items-start gap-3 px-4 py-3 sm:px-5">
      <Icon aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
      <div className="min-w-0 flex-1 space-y-0.5">
        <p className="text-sm text-fg">
          <span className="font-medium">{allow ? "Always allow" : "Always block"}</span>{" "}
          <span className="font-mono text-xs break-all">{value}</span>
        </p>
        <p className="text-xs text-fg-muted">
          {KIND_META[item.kind].singular}
          {item.note ? ` · ${item.note}` : ""}
          {" · "}
          {item.expires_at ? (
            <>
              ends <RelativeTime iso={item.expires_at} className="text-xs" />
            </>
          ) : (
            "no end date"
          )}
        </p>
      </div>
      {canWrite ? (
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label={`Remove the override for ${value}`}
          onClick={() => onRemove({ id: item.id, label: value })}
        >
          <Trash2 aria-hidden />
        </Button>
      ) : null}
    </li>
  )
}

/** What you decided by hand: values that are always allowed or always blocked. */
export function OverridesCard({ canWrite }: { canWrite: boolean }) {
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<RemovingOverride | null>(null)
  const q = useQuery({ queryKey: defendKeys.overrides, queryFn: defendApi.overrides })
  const items = q.data?.items ?? []
  const allowed = items.filter((i) => i.action === "allow").length
  const finding = !q.data
    ? "Checking your overrides…"
    : items.length === 0
      ? "You have not overridden anything. The scores decide."
      : `You always allow ${plural(allowed, "value")} and always block ${plural(items.length - allowed, "value")}.`
  return (
    <FindingCard
      eyebrow="Your overrides"
      finding={finding}
      detail="An override beats the score. Use it for your own scanners and partners, or for something you want blocked today."
      action={
        canWrite ? (
          <Button variant="outline" size="sm" onClick={() => setAdding(true)}>
            <Plus aria-hidden />
            Add
          </Button>
        ) : null
      }
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {q.isPending ? (
        <div className="px-4 sm:px-5">
          <SkeletonText lines={2} />
        </div>
      ) : items.length > 0 ? (
        <ul aria-label="Overrides" className="divide-y border-t">
          {items.map((item) => (
            <Row key={item.id} item={item} canWrite={canWrite} onRemove={setRemoving} />
          ))}
        </ul>
      ) : null}
      {canWrite ? (
        <RemoveOverrideDialog target={removing} onClose={() => setRemoving(null)} />
      ) : null}
      {canWrite ? (
        <OverrideDialog open={adding} onOpenChange={setAdding} target={null} action="allow" />
      ) : null}
    </FindingCard>
  )
}
